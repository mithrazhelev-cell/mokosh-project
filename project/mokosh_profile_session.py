"""Explicit protected-profile session and fail-closed capability registry."""

from __future__ import annotations

import enum
import hmac
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from mokosh_profile_storage import (
    ProfileSnapshot,
    ProfileValidationError,
    normalize_nickname,
    normalize_password,
)
from mokosh_vault_format import VaultSession, VaultSessionState
from mokosh_vault_keyring import (
    active_key_record,
    encode_keyring,
    key_record_for_decryption,
    parse_keyring,
)
from mokosh_v2_operation_lifecycle import CancellationToken
from mokosh_v2_slot_orchestration import (
    EnvelopeKeyPlan,
    KeySlotPlanBuilder,
    VaultCredential,
)
from mokosh_v2_key_slots import KeyVaultSlot


DEFAULT_PROFILE_INACTIVITY_TIMEOUT = 15.0 * 60.0
DEFAULT_SUSPEND_GAP = 30.0
DEFAULT_CLOCK_SKEW_TOLERANCE = 5.0


class ProfileSessionError(RuntimeError):
    """Base class for protected-profile session failures."""


class ProfileOperationBusyError(ProfileSessionError):
    """A previous local operation still owns the sole session key lease."""


class ProfileAuthenticationError(ProfileSessionError):
    """A generic credential refusal that does not identify which field failed."""


class ProfileSessionState(str, enum.Enum):
    LOCKED = "locked"
    UNLOCKING = "unlocking"
    UNLOCKED = "unlocked"
    LOCKING = "locking"
    FAILED = "failed"
    CLOSED = "closed"


class ProfileLockReason(str, enum.Enum):
    USER = "user"
    PANIC = "panic"
    INACTIVITY = "inactivity"
    SUSPEND_OR_CLOCK = "suspend_or_clock"
    WINDOW_CLOSED = "window_closed"
    INTERNAL_FAILURE = "internal_failure"


class ProfileCapability(str, enum.Enum):
    LEGACY_MOK1_DECRYPT = "legacy_mok1_decrypt"
    V2_LOCAL_ENCRYPT = "v2_local_encrypt"
    V2_LOCAL_DECRYPT = "v2_local_decrypt"
    CLEAN_ORIGINALS = "clean_originals"
    CONTACTS = "contacts"
    CONTACT_CRYPTO = "contact_crypto"
    SANDBOX = "sandbox"
    NETWORK = "network"
    RECOVERY_PHRASE = "recovery_phrase"


@dataclass(frozen=True, slots=True)
class LoginResult:
    unlocked: bool
    clear_password: bool
    clear_nickname: bool


@dataclass(frozen=True, slots=True)
class SessionCheckResult:
    locked: bool
    reason: ProfileLockReason | None = None


def _zeroize(value: bytearray | None) -> None:
    if value is not None:
        for index in range(len(value)):
            value[index] = 0


class _LocalV2OperationLease:
    """One non-copyable keyring lease bound to one profile operation."""

    __slots__ = (
        "_session",
        "_operation_id",
        "_cancellation",
        "_keyring_data",
        "_closed",
        "_guard",
    )

    def __init__(
        self,
        owner: "SecureProfileSession",
        operation_id: int,
        cancellation: CancellationToken,
        keyring_data: bytes,
    ) -> None:
        self._session = owner
        self._operation_id = operation_id
        self._cancellation = cancellation
        self._keyring_data = bytearray(keyring_data)
        self._closed = False
        self._guard = threading.RLock()

    def __repr__(self) -> str:
        return f"_LocalV2OperationLease(closed={self._closed!r})"

    def __copy__(self) -> None:
        raise TypeError("local operation lease cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("local operation lease cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("local operation lease cannot be pickled")

    @property
    def cancellation(self) -> CancellationToken:
        return self._cancellation

    @property
    def closed(self) -> bool:
        with self._guard:
            return self._closed

    def _keyring(self):
        with self._guard:
            if self._closed:
                raise ProfileSessionError("local operation lease is closed")
            self._cancellation.checkpoint()
            return parse_keyring(bytes(self._keyring_data))

    def encryption_plan(self) -> tuple[EnvelopeKeyPlan, KeyVaultSlot]:
        """Build exactly one active KEY_VAULT slot for a new local file."""

        keyring = self._keyring()
        record = active_key_record(keyring)
        builder = KeySlotPlanBuilder()
        slot = builder.add_vault(record.wrapping_key, record.key_version)
        plan = builder.finish()
        self._cancellation.checkpoint()
        return plan, slot

    def credential_for_version(self, key_version: int) -> VaultCredential:
        """Select one exact active or retired Vault version without fallback."""

        keyring = self._keyring()
        record = key_record_for_decryption(keyring, key_version)
        credential = VaultCredential(record.wrapping_key)
        self._cancellation.checkpoint()
        return credential

    def close(self) -> None:
        with self._guard:
            if self._closed:
                return
            _zeroize(self._keyring_data)
            self._keyring_data = bytearray()
            self._closed = True
        self._session._finish_local_v2_operation(self._operation_id)

    def __enter__(self) -> "_LocalV2OperationLease":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.close()
        return False


class _LocalV2CleanupLease:
    """One keyless cleanup lease sharing the local-operation exclusion gate."""

    __slots__ = (
        "_session",
        "_operation_id",
        "_cancellation",
        "_closed",
        "_guard",
    )

    def __init__(
        self,
        owner: "SecureProfileSession",
        operation_id: int,
        cancellation: CancellationToken,
    ) -> None:
        self._session = owner
        self._operation_id = operation_id
        self._cancellation = cancellation
        self._closed = False
        self._guard = threading.RLock()

    def __repr__(self) -> str:
        return f"_LocalV2CleanupLease(closed={self._closed!r})"

    def __copy__(self) -> None:
        raise TypeError("local cleanup lease cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("local cleanup lease cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("local cleanup lease cannot be pickled")

    @property
    def cancellation(self) -> CancellationToken:
        return self._cancellation

    @property
    def closed(self) -> bool:
        with self._guard:
            return self._closed

    def close(self) -> None:
        with self._guard:
            if self._closed:
                return
            self._closed = True
        self._session._finish_local_v2_operation(self._operation_id)

    def __enter__(self) -> "_LocalV2CleanupLease":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.close()
        return False


def _positive_finite(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileSessionError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ProfileSessionError(f"{field} must be positive and finite")
    return result


def _clock_value(clock: Callable[[], float], field: str) -> float:
    try:
        value = clock()
    except BaseException as exc:
        raise ProfileSessionError(f"{field} clock failed") from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileSessionError(f"{field} clock returned an invalid value")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ProfileSessionError(f"{field} clock returned an invalid value")
    return result


def capability_registry(state: ProfileSessionState) -> dict[ProfileCapability, bool]:
    """Return the complete Stage 2.48 action gate."""

    unlocked = state is ProfileSessionState.UNLOCKED
    return {
        ProfileCapability.LEGACY_MOK1_DECRYPT: unlocked,
        ProfileCapability.V2_LOCAL_ENCRYPT: unlocked,
        ProfileCapability.V2_LOCAL_DECRYPT: unlocked,
        ProfileCapability.CLEAN_ORIGINALS: False,
        ProfileCapability.CONTACTS: False,
        ProfileCapability.CONTACT_CRYPTO: False,
        ProfileCapability.SANDBOX: False,
        ProfileCapability.NETWORK: False,
        # Setup exposes the live Vault keyring and therefore requires an
        # explicitly unlocked profile.  The separate forgotten-password entry
        # route is gated by a READY profile while the session remains locked.
        ProfileCapability.RECOVERY_PHRASE: unlocked,
    }


class SecureProfileSession:
    """Own one in-memory Key Vault session without retaining a password."""

    __slots__ = (
        "_snapshot",
        "_vault",
        "_state",
        "_timeout",
        "_suspend_gap",
        "_skew_tolerance",
        "_monotonic",
        "_wall_clock",
        "_last_activity_mono",
        "_last_check_mono",
        "_last_check_wall",
        "_last_lock_reason",
        "_guard",
        "_operation_counter",
        "_active_operation_id",
        "_active_cancellation",
    )

    def __init__(
        self,
        snapshot: ProfileSnapshot,
        *,
        inactivity_timeout: float = DEFAULT_PROFILE_INACTIVITY_TIMEOUT,
        suspend_gap: float = DEFAULT_SUSPEND_GAP,
        clock_skew_tolerance: float = DEFAULT_CLOCK_SKEW_TOLERANCE,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(snapshot, ProfileSnapshot):
            raise ProfileSessionError("snapshot must be a protected profile")
        if not callable(monotonic) or not callable(wall_clock):
            raise ProfileSessionError("session clocks must be callable")
        timeout = _positive_finite(inactivity_timeout, "inactivity timeout")
        gap = _positive_finite(suspend_gap, "suspend gap")
        tolerance = _positive_finite(clock_skew_tolerance, "clock tolerance")
        self._snapshot = snapshot
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._timeout = timeout
        self._suspend_gap = gap
        self._skew_tolerance = tolerance
        self._vault = VaultSession(
            snapshot.vault_bytes,
            inactivity_timeout=timeout,
            clock=monotonic,
            minimum_revision=snapshot.receipt.revision,
        )
        self._state = ProfileSessionState.LOCKED
        self._last_activity_mono: float | None = None
        self._last_check_mono: float | None = None
        self._last_check_wall: float | None = None
        self._last_lock_reason: ProfileLockReason | None = None
        self._guard = threading.RLock()
        self._operation_counter = 0
        self._active_operation_id: int | None = None
        self._active_cancellation: CancellationToken | None = None

    def __repr__(self) -> str:
        with self._guard:
            return f"SecureProfileSession(state={self._state.value!r})"

    def __copy__(self) -> None:
        raise TypeError("SecureProfileSession cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("SecureProfileSession cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("SecureProfileSession cannot be pickled")

    @property
    def state(self) -> ProfileSessionState:
        with self._guard:
            return self._state

    @property
    def nickname(self) -> str:
        with self._guard:
            return self._snapshot.descriptor.nickname

    @property
    def last_lock_reason(self) -> ProfileLockReason | None:
        with self._guard:
            return self._last_lock_reason

    @property
    def capabilities(self) -> dict[ProfileCapability, bool]:
        with self._guard:
            return capability_registry(self._state)

    def _read_clocks(self) -> tuple[float, float]:
        return (
            _clock_value(self._monotonic, "monotonic"),
            _clock_value(self._wall_clock, "wall"),
        )

    def _cancel_active_operation(self) -> None:
        if self._active_cancellation is not None:
            self._active_cancellation.cancel()

    def _begin_local_v2_operation(
        self,
        cancellation: CancellationToken | None = None,
    ) -> _LocalV2OperationLease:
        """Acquire the sole trusted local-v2 key lease for this session."""

        if cancellation is not None and type(cancellation) is not CancellationToken:
            raise ProfileSessionError("operation cancellation token is invalid")
        token = cancellation or CancellationToken()
        with self._guard:
            checked = self.check()
            if checked.locked or self._state is not ProfileSessionState.UNLOCKED:
                raise ProfileSessionError("local operation requires an unlocked profile")
            if self._active_operation_id is not None:
                raise ProfileOperationBusyError(
                    "another local operation is still active"
                )
            self.touch()
            if self._state is not ProfileSessionState.UNLOCKED:
                raise ProfileSessionError("local operation requires an unlocked profile")
            token.checkpoint()
            try:
                keyring_data = encode_keyring(self._vault.keyring_copy())
            except Exception as exc:
                self.lock(ProfileLockReason.INTERNAL_FAILURE)
                raise ProfileSessionError("Vault keyring is unavailable") from exc
            self._operation_counter += 1
            operation_id = self._operation_counter
            try:
                lease = _LocalV2OperationLease(
                    self,
                    operation_id,
                    token,
                    keyring_data,
                )
            finally:
                del keyring_data
            self._active_operation_id = operation_id
            self._active_cancellation = token
            return lease

    def _begin_local_v2_cleanup_operation(
        self,
        cancellation: CancellationToken | None = None,
    ) -> _LocalV2CleanupLease:
        """Acquire the sole local-operation slot without copying Vault keys."""

        if cancellation is not None and type(cancellation) is not CancellationToken:
            raise ProfileSessionError("operation cancellation token is invalid")
        token = cancellation or CancellationToken()
        with self._guard:
            checked = self.check()
            if checked.locked or self._state is not ProfileSessionState.UNLOCKED:
                raise ProfileSessionError("local cleanup requires an unlocked profile")
            if self._active_operation_id is not None:
                raise ProfileOperationBusyError(
                    "another local operation is still active"
                )
            self.touch()
            if self._state is not ProfileSessionState.UNLOCKED:
                raise ProfileSessionError("local cleanup requires an unlocked profile")
            token.checkpoint()
            self._operation_counter += 1
            operation_id = self._operation_counter
            lease = _LocalV2CleanupLease(self, operation_id, token)
            self._active_operation_id = operation_id
            self._active_cancellation = token
            return lease

    def _finish_local_v2_operation(self, operation_id: int) -> None:
        with self._guard:
            if self._active_operation_id == operation_id:
                self._active_operation_id = None
                self._active_cancellation = None

    def unlock(self, nickname: Any, password: Any) -> LoginResult:
        with self._guard:
            if self._state is ProfileSessionState.CLOSED:
                raise ProfileSessionError("closed profile session cannot unlock")
            if self._state is not ProfileSessionState.LOCKED:
                raise ProfileSessionError("unlock requires the locked state")
            if self._active_operation_id is not None:
                raise ProfileOperationBusyError(
                    "previous local operation is still stopping"
                )
            self._state = ProfileSessionState.UNLOCKING
            try:
                try:
                    exact_nickname = normalize_nickname(nickname)
                    exact_password = normalize_password(password)
                except ProfileValidationError as exc:
                    raise ProfileAuthenticationError(
                        "profile credentials are invalid"
                    ) from exc
                expected = self._snapshot.descriptor.nickname.encode("utf-8")
                supplied = exact_nickname.encode("utf-8")
                if not hmac.compare_digest(expected, supplied):
                    raise ProfileAuthenticationError("profile credentials are invalid")
                try:
                    self._vault.unlock(exact_password)
                    self._vault.keyring_copy()
                    now_mono, now_wall = self._read_clocks()
                except Exception as exc:
                    if self._vault.state is VaultSessionState.FAILED:
                        self._vault.reset_failure()
                    elif self._vault.state is VaultSessionState.UNLOCKED:
                        self._vault.lock()
                    raise ProfileAuthenticationError(
                        "profile credentials are invalid"
                    ) from exc
                self._last_activity_mono = now_mono
                self._last_check_mono = now_mono
                self._last_check_wall = now_wall
                self._last_lock_reason = None
                self._state = ProfileSessionState.UNLOCKED
                return LoginResult(True, True, True)
            except ProfileAuthenticationError:
                self._last_activity_mono = None
                self._last_check_mono = None
                self._last_check_wall = None
                self._state = ProfileSessionState.LOCKED
                return LoginResult(False, True, False)
            finally:
                try:
                    del exact_password
                except UnboundLocalError:
                    pass

    def _lock_vault(self) -> None:
        if self._vault.state is VaultSessionState.UNLOCKED:
            self._vault.lock()
        elif self._vault.state is VaultSessionState.FAILED:
            self._vault.reset_failure()

    def lock(self, reason: ProfileLockReason = ProfileLockReason.USER) -> None:
        with self._guard:
            if not isinstance(reason, ProfileLockReason):
                raise ProfileSessionError("lock reason is invalid")
            if self._state is ProfileSessionState.CLOSED:
                self._cancel_active_operation()
                return
            if self._state is ProfileSessionState.LOCKED:
                self._cancel_active_operation()
                self._last_lock_reason = reason
                return
            if self._state is not ProfileSessionState.UNLOCKED:
                self._cancel_active_operation()
                self._state = ProfileSessionState.FAILED
                self._lock_vault()
                raise ProfileSessionError("profile cannot lock from its current state")
            self._state = ProfileSessionState.LOCKING
            self._cancel_active_operation()
            try:
                self._lock_vault()
            except Exception as exc:
                self._state = ProfileSessionState.FAILED
                raise ProfileSessionError("profile lock failed") from exc
            self._last_activity_mono = None
            self._last_check_mono = None
            self._last_check_wall = None
            self._last_lock_reason = reason
            self._state = ProfileSessionState.LOCKED

    def panic_lock(self) -> None:
        self.lock(ProfileLockReason.PANIC)

    def touch(self) -> None:
        with self._guard:
            if self._state is not ProfileSessionState.UNLOCKED:
                return
            try:
                now_mono, now_wall = self._read_clocks()
                assert self._last_check_mono is not None
                assert self._last_check_wall is not None
                mono_delta = now_mono - self._last_check_mono
                wall_delta = now_wall - self._last_check_wall
                if (
                    mono_delta < 0
                    or wall_delta < -self._skew_tolerance
                    or abs(wall_delta - mono_delta) > self._skew_tolerance
                    or mono_delta >= self._suspend_gap
                ):
                    self.lock(ProfileLockReason.SUSPEND_OR_CLOCK)
                    return
                self._vault.touch()
                self._last_activity_mono = now_mono
                self._last_check_mono = now_mono
                self._last_check_wall = now_wall
            except ProfileSessionError:
                self.lock(ProfileLockReason.INTERNAL_FAILURE)
                raise
            except Exception as exc:
                self.lock(ProfileLockReason.INTERNAL_FAILURE)
                raise ProfileSessionError("profile activity check failed") from exc

    def check(self) -> SessionCheckResult:
        with self._guard:
            if self._state is not ProfileSessionState.UNLOCKED:
                return SessionCheckResult(False)
            try:
                now_mono, now_wall = self._read_clocks()
                assert self._last_activity_mono is not None
                assert self._last_check_mono is not None
                assert self._last_check_wall is not None
                mono_delta = now_mono - self._last_check_mono
                wall_delta = now_wall - self._last_check_wall
                if (
                    mono_delta < 0
                    or wall_delta < -self._skew_tolerance
                    or abs(wall_delta - mono_delta) > self._skew_tolerance
                    or mono_delta >= self._suspend_gap
                ):
                    self.lock(ProfileLockReason.SUSPEND_OR_CLOCK)
                    return SessionCheckResult(True, ProfileLockReason.SUSPEND_OR_CLOCK)
                if now_mono - self._last_activity_mono >= self._timeout:
                    self.lock(ProfileLockReason.INACTIVITY)
                    return SessionCheckResult(True, ProfileLockReason.INACTIVITY)
                self._last_check_mono = now_mono
                self._last_check_wall = now_wall
                return SessionCheckResult(False)
            except ProfileSessionError:
                self.lock(ProfileLockReason.INTERNAL_FAILURE)
                return SessionCheckResult(True, ProfileLockReason.INTERNAL_FAILURE)

    def close(self) -> None:
        with self._guard:
            if self._state is ProfileSessionState.CLOSED:
                self._cancel_active_operation()
                return
            self._cancel_active_operation()
            if self._state is ProfileSessionState.UNLOCKED:
                self.lock(ProfileLockReason.WINDOW_CLOSED)
            self._vault.close()
            self._last_activity_mono = None
            self._last_check_mono = None
            self._last_check_wall = None
            self._state = ProfileSessionState.CLOSED


__all__ = [
    "DEFAULT_CLOCK_SKEW_TOLERANCE",
    "DEFAULT_PROFILE_INACTIVITY_TIMEOUT",
    "DEFAULT_SUSPEND_GAP",
    "LoginResult",
    "ProfileAuthenticationError",
    "ProfileCapability",
    "ProfileLockReason",
    "ProfileOperationBusyError",
    "ProfileSessionError",
    "ProfileSessionState",
    "SecureProfileSession",
    "SessionCheckResult",
    "capability_registry",
]
