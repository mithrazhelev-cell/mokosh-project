"""Normal-profile orchestration for optional MOKOSH-RP1 password recovery.

This layer composes the frozen Vault recovery primitives.  Setup requires the
current profile password, writes the encrypted ``.mokr`` record first, and
accepts either a fully re-entered paper phrase or a verified phrase sheet on a
different filesystem device.  Password recovery prepares a verified in-memory
candidate before one explicit immutable publish.  It never overwrites or
deletes a Vault generation, recovery record, phrase sheet, or user file.
"""

from __future__ import annotations

import enum
import hmac
import os
import stat
from dataclasses import dataclass
from typing import Any

from mokosh_profile_storage import (
    PROFILE_VAULT_DIRECTORY_NAME,
    ProfileState,
    default_profile_root,
    inspect_profile,
    load_profile,
    normalize_password,
)
from mokosh_profile_recovery_state import (
    ProfileRecoveryStateError as ProfileRecoveryReceiptError,
    publish_current_profile_recovery_state,
)
from mokosh_recovery_phrase import (
    RecoveryPhraseError,
    decode_recovery_phrase,
    encode_recovery_phrase,
)
from mokosh_recovery_phrase_storage import (
    ParsedRecoveryPhraseSheet,
    RecoveryMaterialKind,
    RecoveryPhraseExportUncertainError,
    RecoveryPhraseExportUnsupportedError,
    RecoveryPhraseExportReceipt,
    RecoveryPhraseSeparationError,
    RecoveryPhraseStorageError,
    RecoveryPrivateDirectoryReceipt,
    create_private_recovery_directory,
    export_recovery_phrase_sheet,
    read_recovery_phrase_sheet,
    remove_empty_private_recovery_directory,
    recovery_phrase_file_name,
)
from mokosh_vault_format import (
    DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    VaultSession,
    VaultSessionState,
)
from mokosh_vault_recovery import VaultRecoverySetup
from mokosh_vault_recovery_candidate import (
    PreparedVaultRecoveryCandidate,
    RecoveryCandidateDecision,
    VaultRecoveryCandidateError,
    prepare_recovery_candidate,
)
from mokosh_vault_recovery_publish import (
    RecoveryPublishDecision,
    VaultRecoveryPublishError,
    VaultRecoveryPublishResult,
    VaultRecoveryPublishUncertainError,
    publish_recovery_candidate,
)
from mokosh_vault_recovery_reconciliation import (
    RecoveryPublishClassification,
    VaultRecoveryReconciliationError,
    VaultRecoveryReconciliationResult,
    reconcile_recovery_publish,
)
from mokosh_vault_recovery_storage import (
    VaultRecoveryExportReceipt,
    RecoveryExportUncertainError,
    RecoveryExportUnsupportedError,
    VaultRecoveryStorageError,
    export_recovery_record,
    prepare_recovery_export,
    recovery_record_name,
    rehearse_recovery_file,
)
from mokosh_vault_storage import VaultGenerationReceipt, VaultStorage


class ProfileRecoveryError(RuntimeError):
    """Base class for normal protected-profile recovery failures."""


class ProfileRecoveryInputError(ProfileRecoveryError, ValueError):
    """An explicit password, path, phrase, or decision is invalid."""


class ProfileRecoveryAuthenticationError(ProfileRecoveryError):
    """Current profile reauthentication failed without credential detail."""


class ProfileRecoveryStateError(ProfileRecoveryError):
    """The profile, Vault, recovery source, or one-shot plan is unsafe."""


class ProfileRecoveryLifecyclePublishError(ProfileRecoveryStateError):
    """External copies exist, but current recovery availability is unproven."""


class ProfileRecoveryBackupError(ProfileRecoveryError):
    """The required separate phrase backup has not been verified."""


class ProfileRecoverySeparationError(ProfileRecoveryBackupError):
    """The phrase and protected recovery material are on one device."""


class ProfileRecoveryExportUncertainError(ProfileRecoveryError):
    """A setup export may remain visible and must not be retried blindly."""


class ProfileRecoveryStorageUnsupportedError(ProfileRecoveryError):
    """The selected platform or filesystem cannot meet the storage contract."""


class ProfileRecoveryPublishUncertainError(ProfileRecoveryError):
    """Read-only reconciliation could not prove one safe final outcome."""

    def __init__(
        self,
        message: str,
        reconciliation: VaultRecoveryReconciliationResult | None = None,
    ) -> None:
        super().__init__(message)
        self.reconciliation = reconciliation


class ProfileRecoveryDecision(str, enum.Enum):
    PRESERVE = "preserve"
    AUTHORIZE = "authorize"


class ProfileRecoveryBackupKind(str, enum.Enum):
    PAPER = "paper"
    SEPARATE_FILE = "separate_file"


@dataclass(frozen=True, slots=True)
class ProfileRecoverySetupResult:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    record_path: str
    phrase_path: str | None
    backup_kind: ProfileRecoveryBackupKind
    record_sha256: bytes
    phrase_sha256: bytes | None
    exact_rehearsal_verified: bool = True
    phrase_retained_by_application: bool = False
    vault_publish_performed: bool = False


@dataclass(frozen=True, slots=True)
class ProfilePasswordRecoveryPreview:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    updated_utc: str
    time_cost: int
    memory_kib: int
    parallelism: int
    active_key_version: int
    key_count: int
    source_preserved: bool = True
    publish_performed: bool = False


@dataclass(frozen=True, slots=True)
class ProfilePasswordRecoveryResult:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    reconciled_after_uncertain_publish: bool
    profile_locked_after_publish: bool = True
    source_generation_preserved: bool = True
    recovery_record_preserved: bool = True
    recovery_record_now_stale: bool = True
    user_file_mutation_performed: bool = False


def _profile_root(value: Any | None) -> str:
    target = default_profile_root() if value is None else value
    try:
        raw = os.fspath(target)
    except TypeError as exc:
        raise ProfileRecoveryInputError("profile root must be a path") from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ProfileRecoveryInputError("profile root must be non-empty text")
    absolute = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(absolute) != absolute:
        raise ProfileRecoveryStateError("profile root must not contain symlinks")
    return absolute


def _vault_path(root: str) -> str:
    return os.path.join(root, PROFILE_VAULT_DIRECTORY_NAME)


def _ready_snapshot(root: str):
    inspection = inspect_profile(root)
    if inspection.state is not ProfileState.READY:
        raise ProfileRecoveryStateError("protected profile is not ready")
    try:
        return load_profile(root)
    except Exception as exc:
        raise ProfileRecoveryStateError(
            "protected profile cannot be loaded exactly"
        ) from exc


def _authorize(value: Any, label: str) -> None:
    if not isinstance(value, ProfileRecoveryDecision):
        raise ProfileRecoveryInputError(f"{label} decision is invalid")
    if value is not ProfileRecoveryDecision.AUTHORIZE:
        raise ProfileRecoveryInputError(f"{label} was not explicitly authorized")


def _unique_devices(*values: int) -> tuple[int, ...]:
    result: list[int] = []
    for value in values:
        if type(value) is not int or value < 0:
            raise ProfileRecoveryStateError("filesystem device identity is invalid")
        if value not in result:
            result.append(value)
    return tuple(result)


def _selected_parent_outside_profile(parent: Any, root: str) -> str:
    try:
        raw = os.fspath(parent)
    except TypeError as exc:
        raise ProfileRecoveryInputError(
            "recovery destination parent must be a path"
        ) from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ProfileRecoveryInputError(
            "recovery destination parent must be non-empty text"
        )
    exact = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(exact) != exact:
        raise ProfileRecoveryStateError(
            "recovery destination must not contain symlinks"
        )
    try:
        inside = os.path.commonpath((root, exact)) == root
    except ValueError as exc:
        raise ProfileRecoveryInputError(
            "recovery destination path is invalid"
        ) from exc
    if inside:
        raise ProfileRecoveryStateError(
            "recovery material cannot be stored inside the profile"
        )
    return exact


def _regular_file_device(path: Any, label: str) -> int:
    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise ProfileRecoveryInputError(f"{label} must be a path") from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ProfileRecoveryInputError(f"{label} must be non-empty text")
    exact = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(exact) != exact:
        raise ProfileRecoveryStateError(f"{label} must not contain symlinks")
    try:
        info = os.lstat(exact)
    except OSError as exc:
        raise ProfileRecoveryStateError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ProfileRecoveryStateError(f"{label} must be a regular file")
    return info.st_dev


def _rollback_new_empty_directory(
    directory: RecoveryPrivateDirectoryReceipt | None,
) -> None:
    """Remove only our exact empty directory or report uncertain cleanup."""

    if directory is None:
        return
    try:
        removed = remove_empty_private_recovery_directory(directory)
    except RecoveryPhraseStorageError as exc:
        raise ProfileRecoveryExportUncertainError(
            "new recovery directory cleanup is uncertain; inspect it manually"
        ) from exc
    if not removed:
        raise ProfileRecoveryExportUncertainError(
            "new recovery directory is not empty; inspect it manually"
        )


class PreparedProfileRecoverySetup:
    """Hold one process-local recovery root until both backups are verified."""

    __slots__ = (
        "_root",
        "_latest",
        "_setup",
        "_record_directory",
        "_record_receipt",
        "_record_path",
        "_phrase_directory",
        "_phrase_receipt",
        "_phrase_path",
        "_paper_confirmed",
        "_completed",
        "_closed",
    )

    def __init__(
        self,
        root: str,
        latest: VaultGenerationReceipt,
        setup: VaultRecoverySetup,
    ) -> None:
        self._root = root
        self._latest = latest
        self._setup = setup
        self._record_directory: RecoveryPrivateDirectoryReceipt | None = None
        self._record_receipt: VaultRecoveryExportReceipt | None = None
        self._record_path: str | None = None
        self._phrase_directory: RecoveryPrivateDirectoryReceipt | None = None
        self._phrase_receipt: RecoveryPhraseExportReceipt | None = None
        self._phrase_path: str | None = None
        self._paper_confirmed = False
        self._completed = False
        self._closed = False

    def __repr__(self) -> str:
        return (
            "PreparedProfileRecoverySetup("
            f"record_exported={self._record_receipt is not None}, "
            f"backup_verified={self.backup_verified}, completed={self._completed})"
        )

    def __copy__(self) -> None:
        raise TypeError("profile recovery setup cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("profile recovery setup cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("profile recovery setup cannot be serialized")

    def _require_open(self) -> None:
        if self._closed or self._completed:
            raise ProfileRecoveryStateError("profile recovery setup is closed")

    @property
    def recovery_id(self) -> bytes:
        return self._setup.recovery_id

    @property
    def phrase_words(self) -> tuple[str, ...]:
        self._require_open()
        return encode_recovery_phrase(self._setup.recovery_key)

    @property
    def record_exported(self) -> bool:
        return self._record_receipt is not None

    @property
    def backup_verified(self) -> bool:
        return self._phrase_receipt is not None or self._paper_confirmed

    @property
    def record_path(self) -> str | None:
        return self._record_path

    @property
    def phrase_path(self) -> str | None:
        return self._phrase_path

    def export_record(self, selected_parent: Any) -> VaultRecoveryExportReceipt:
        self._require_open()
        if self._record_receipt is not None:
            raise ProfileRecoveryStateError("recovery record was already exported")
        parent = _selected_parent_outside_profile(selected_parent, self._root)
        directory: RecoveryPrivateDirectoryReceipt | None = None
        try:
            directory = create_private_recovery_directory(
                parent,
                RecoveryMaterialKind.RECORD,
                self._setup.recovery_id,
            )
            with VaultStorage(_vault_path(self._root)) as storage:
                receipt = export_recovery_record(
                    self._setup,
                    storage,
                    self._latest,
                    directory.path,
                )
        except (
            RecoveryPhraseExportUncertainError,
            RecoveryExportUncertainError,
        ) as exc:
            raise ProfileRecoveryExportUncertainError(
                "recovery record export is uncertain; inspect it before any retry"
            ) from exc
        except (
            RecoveryPhraseExportUnsupportedError,
            RecoveryExportUnsupportedError,
        ) as exc:
            _rollback_new_empty_directory(directory)
            raise ProfileRecoveryStorageUnsupportedError(
                "selected recovery storage cannot enforce the required guarantees"
            ) from exc
        except (RecoveryPhraseStorageError, VaultRecoveryStorageError) as exc:
            _rollback_new_empty_directory(directory)
            raise ProfileRecoveryStateError(
                "recovery record could not be exported safely"
            ) from exc
        assert directory is not None
        path = os.path.join(
            directory.path,
            recovery_record_name(self._setup.recovery_id),
        )
        self._record_directory = directory
        self._record_receipt = receipt
        self._record_path = path
        return receipt

    def export_phrase(self, selected_parent: Any) -> RecoveryPhraseExportReceipt:
        self._require_open()
        if self._record_receipt is None:
            raise ProfileRecoveryStateError(
                "export the encrypted recovery record first"
            )
        if self.backup_verified:
            raise ProfileRecoveryStateError("recovery phrase backup is already verified")
        parent = _selected_parent_outside_profile(selected_parent, self._root)
        forbidden = _unique_devices(
            self._latest.directory_device,
            self._record_receipt.directory_device,
        )
        directory: RecoveryPrivateDirectoryReceipt | None = None
        try:
            directory = create_private_recovery_directory(
                parent,
                RecoveryMaterialKind.PHRASE,
                self._setup.recovery_id,
                forbidden_devices=forbidden,
            )
            receipt = export_recovery_phrase_sheet(
                self._setup.recovery_id,
                self.phrase_words,
                directory.path,
                forbidden_devices=forbidden,
            )
        except RecoveryPhraseSeparationError as exc:
            _rollback_new_empty_directory(directory)
            raise ProfileRecoverySeparationError(
                "recovery phrase must be stored on a separate device"
            ) from exc
        except RecoveryPhraseExportUncertainError as exc:
            raise ProfileRecoveryExportUncertainError(
                "recovery phrase export is uncertain; inspect it before any retry"
            ) from exc
        except RecoveryPhraseExportUnsupportedError as exc:
            _rollback_new_empty_directory(directory)
            raise ProfileRecoveryStorageUnsupportedError(
                "selected phrase storage cannot enforce the required guarantees"
            ) from exc
        except RecoveryPhraseStorageError as exc:
            _rollback_new_empty_directory(directory)
            raise ProfileRecoveryBackupError(
                "recovery phrase sheet could not be exported safely"
            ) from exc
        assert directory is not None
        self._phrase_directory = directory
        self._phrase_receipt = receipt
        self._phrase_path = os.path.join(
            directory.path,
            recovery_phrase_file_name(self._setup.recovery_id),
        )
        return receipt

    def confirm_paper_backup(self, entered_phrase: Any) -> None:
        self._require_open()
        if self._record_receipt is None:
            raise ProfileRecoveryStateError(
                "export the encrypted recovery record first"
            )
        if self.backup_verified:
            raise ProfileRecoveryStateError("recovery phrase backup is already verified")
        try:
            key = decode_recovery_phrase(entered_phrase)
        except RecoveryPhraseError as exc:
            raise ProfileRecoveryBackupError(
                "the complete recovery phrase is invalid"
            ) from exc
        if not hmac.compare_digest(key, self._setup.recovery_key):
            raise ProfileRecoveryBackupError(
                "the complete recovery phrase does not match"
            )
        self._paper_confirmed = True

    def complete(
        self,
        decision: ProfileRecoveryDecision,
    ) -> ProfileRecoverySetupResult:
        self._require_open()
        _authorize(decision, "recovery setup completion")
        if self._record_receipt is None or self._record_path is None:
            raise ProfileRecoveryStateError("recovery record is not exported")
        if not self.backup_verified:
            raise ProfileRecoveryBackupError(
                "a separate recovery phrase backup is not verified"
            )
        try:
            with VaultStorage(_vault_path(self._root)) as storage:
                rehearsal = rehearse_recovery_file(
                    self._record_path,
                    self._setup.recovery_key,
                    storage,
                    self._latest,
                )
            if self._phrase_path is not None:
                assert self._phrase_receipt is not None
                forbidden = _unique_devices(
                    self._latest.directory_device,
                    self._record_receipt.directory_device,
                )
                phrase = read_recovery_phrase_sheet(
                    self._phrase_path,
                    expected_recovery_id=self._setup.recovery_id,
                    forbidden_devices=forbidden,
                )
                if not hmac.compare_digest(
                    phrase.recovery_key, self._setup.recovery_key
                ):
                    raise ProfileRecoveryBackupError(
                        "saved recovery phrase no longer matches"
                    )
            if (
                not hmac.compare_digest(rehearsal.recovery_id, self._setup.recovery_id)
                or not hmac.compare_digest(rehearsal.vault_id, self._setup.vault_id)
                or rehearsal.source_revision != self._setup.source_revision
            ):
                raise ProfileRecoveryStateError(
                    "final recovery rehearsal differs from setup"
                )
        except (
            RecoveryPhraseExportUnsupportedError,
            RecoveryExportUnsupportedError,
        ) as exc:
            raise ProfileRecoveryStorageUnsupportedError(
                "saved recovery storage cannot be verified safely"
            ) from exc
        except (VaultRecoveryStorageError, RecoveryPhraseStorageError) as exc:
            raise ProfileRecoveryStateError(
                "recovery materials could not be reverified"
            ) from exc
        try:
            publish_current_profile_recovery_state(
                self._root,
                self._setup.recovery_id,
                self._latest,
            )
        except ProfileRecoveryReceiptError as exc:
            # A receipt failure can occur after atomic replacement.  Close the
            # one-shot setup so Finish cannot blindly retry an uncertain state;
            # exported standalone copies are deliberately left untouched.
            self.close()
            raise ProfileRecoveryLifecyclePublishError(
                "recovery availability state could not be published safely"
            ) from exc
        self._completed = True
        result = ProfileRecoverySetupResult(
            recovery_id=self._setup.recovery_id,
            vault_id=self._setup.vault_id,
            source_revision=self._setup.source_revision,
            record_path=self._record_path,
            phrase_path=self._phrase_path,
            backup_kind=(
                ProfileRecoveryBackupKind.SEPARATE_FILE
                if self._phrase_path is not None
                else ProfileRecoveryBackupKind.PAPER
            ),
            record_sha256=self._record_receipt.record_sha256,
            phrase_sha256=(
                None
                if self._phrase_receipt is None
                else self._phrase_receipt.sha256
            ),
        )
        self.close()
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._setup = VaultRecoverySetup(
            record=b"",
            recovery_key=b"",
            recovery_id=self._setup.recovery_id,
            vault_id=self._setup.vault_id,
            source_revision=self._setup.source_revision,
            source_vault_sha256=self._setup.source_vault_sha256,
        )


def begin_profile_recovery_setup(
    profile_root: Any | None,
    current_password: Any,
    decision: ProfileRecoveryDecision,
    *,
    created_utc: str | None = None,
) -> PreparedProfileRecoverySetup:
    """Reauthenticate and prepare one in-memory optional recovery setup."""

    _authorize(decision, "recovery setup")
    root = _profile_root(profile_root)
    snapshot = _ready_snapshot(root)
    try:
        password = normalize_password(current_password)
    except Exception as exc:
        raise ProfileRecoveryAuthenticationError(
            "profile credentials are invalid"
        ) from exc
    session = VaultSession(snapshot.vault_bytes, minimum_revision=snapshot.receipt.revision)
    try:
        try:
            session.unlock(password)
            session.keyring_copy()
        except Exception as exc:
            raise ProfileRecoveryAuthenticationError(
                "profile credentials are invalid"
            ) from exc
        if session.state is not VaultSessionState.UNLOCKED:
            raise ProfileRecoveryAuthenticationError(
                "profile credentials are invalid"
            )
        with VaultStorage(_vault_path(root)) as storage:
            setup = prepare_recovery_export(
                storage,
                snapshot.receipt,
                session,
                created_utc=created_utc,
            )
    except ProfileRecoveryError:
        raise
    except Exception as exc:
        raise ProfileRecoveryStateError(
            "recovery setup could not be prepared safely"
        ) from exc
    finally:
        session.close()
        password = ""
    return PreparedProfileRecoverySetup(root, snapshot.receipt, setup)


class PreparedProfilePasswordRecovery:
    """Hold one verified in-memory password candidate until explicit publish."""

    __slots__ = (
        "_root",
        "_latest",
        "_recovery_path",
        "_recovery_key",
        "_new_password",
        "_prepared",
        "_closed",
    )

    def __init__(
        self,
        root: str,
        latest: VaultGenerationReceipt,
        recovery_path: str,
        recovery_key: bytes,
        new_password: str,
        prepared: PreparedVaultRecoveryCandidate,
    ) -> None:
        self._root = root
        self._latest = latest
        self._recovery_path = recovery_path
        self._recovery_key = recovery_key
        self._new_password = new_password
        self._prepared: PreparedVaultRecoveryCandidate | None = prepared
        self._closed = False

    def __repr__(self) -> str:
        return f"PreparedProfilePasswordRecovery(closed={self._closed})"

    def __copy__(self) -> None:
        raise TypeError("profile password recovery cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("profile password recovery cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("profile password recovery cannot be serialized")

    def _require_open(self) -> PreparedVaultRecoveryCandidate:
        if self._closed or self._prepared is None:
            raise ProfileRecoveryStateError("profile password recovery is closed")
        return self._prepared

    @property
    def preview(self) -> ProfilePasswordRecoveryPreview:
        evidence = self._require_open().evidence
        return ProfilePasswordRecoveryPreview(
            recovery_id=evidence.recovery_id,
            vault_id=evidence.vault_id,
            source_revision=evidence.source_revision,
            target_revision=evidence.target_revision,
            updated_utc=evidence.updated_utc,
            time_cost=evidence.time_cost,
            memory_kib=evidence.memory_kib,
            parallelism=evidence.parallelism,
            active_key_version=evidence.active_key_version,
            key_count=evidence.key_count,
        )

    def publish(
        self,
        decision: ProfileRecoveryDecision,
    ) -> ProfilePasswordRecoveryResult:
        prepared = self._require_open()
        _authorize(decision, "password recovery publish")
        evidence = prepared.evidence
        reconciled = False
        try:
            try:
                with VaultStorage(_vault_path(self._root)) as storage:
                    published = publish_recovery_candidate(
                        prepared,
                        self._recovery_path,
                        self._recovery_key,
                        storage,
                        self._latest,
                        self._new_password,
                        RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
                    )
            except VaultRecoveryPublishUncertainError as uncertain:
                reconciliation: VaultRecoveryReconciliationResult | None = None
                try:
                    with VaultStorage(_vault_path(self._root)) as storage:
                        reconciliation = reconcile_recovery_publish(
                            self._recovery_path,
                            self._recovery_key,
                            storage,
                            self._latest,
                            evidence.target_revision,
                            self._new_password,
                        )
                except VaultRecoveryReconciliationError as exc:
                    raise ProfileRecoveryPublishUncertainError(
                        "password recovery publish is uncertain; stop for manual review"
                    ) from exc
                if (
                    reconciliation.classification
                    is not RecoveryPublishClassification.TARGET_EXACT_DURABLE
                ):
                    raise ProfileRecoveryPublishUncertainError(
                        "password recovery publish is not proven durable; do not retry blindly",
                        reconciliation,
                    ) from uncertain
                reconciled = True
                published = None
            if published is not None:
                _validate_publish_result(published, evidence.target_revision)
            final = _ready_snapshot(self._root)
            if (
                final.receipt.revision != evidence.target_revision
                or not hmac.compare_digest(final.receipt.vault_id, evidence.vault_id)
            ):
                raise ProfileRecoveryPublishUncertainError(
                    "published profile state cannot be confirmed"
                )
            return ProfilePasswordRecoveryResult(
                recovery_id=evidence.recovery_id,
                vault_id=evidence.vault_id,
                source_revision=evidence.source_revision,
                target_revision=evidence.target_revision,
                reconciled_after_uncertain_publish=reconciled,
            )
        except ProfileRecoveryError:
            raise
        except VaultRecoveryPublishError as exc:
            raise ProfileRecoveryStateError(
                "password recovery could not be published safely"
            ) from exc
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._recovery_key = b""
        self._new_password = ""
        self._prepared = None


def _validate_publish_result(
    value: VaultRecoveryPublishResult,
    target_revision: int,
) -> None:
    if (
        not isinstance(value, VaultRecoveryPublishResult)
        or value.target_revision != target_revision
        or value.source_generation_preserved is not True
        or value.recovery_record_preserved is not True
        or value.recovery_record_now_stale is not True
        or value.user_file_mutation_performed is not False
    ):
        raise ProfileRecoveryPublishUncertainError(
            "password recovery result is inconsistent"
        )


def _prepare_profile_password_recovery(
    profile_root: Any | None,
    recovery_path: Any,
    recovery_key: bytes,
    new_password: Any,
    confirmation: Any,
    decision: ProfileRecoveryDecision,
    *,
    expected_recovery_id: bytes | None = None,
    phrase_directory_device: int | None = None,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
) -> PreparedProfilePasswordRecovery:
    _authorize(decision, "password recovery preparation")
    root = _profile_root(profile_root)
    snapshot = _ready_snapshot(root)
    try:
        exact_password = normalize_password(new_password)
        exact_confirmation = normalize_password(confirmation)
    except Exception as exc:
        raise ProfileRecoveryInputError("new password is outside policy") from exc
    if not hmac.compare_digest(
        exact_password.encode("utf-8"), exact_confirmation.encode("utf-8")
    ):
        raise ProfileRecoveryInputError("new password confirmation differs")
    try:
        exact_recovery_path = os.path.abspath(
            os.path.expanduser(os.fspath(recovery_path))
        )
    except TypeError as exc:
        raise ProfileRecoveryInputError("recovery record must be a path") from exc
    if os.path.realpath(exact_recovery_path) != exact_recovery_path:
        raise ProfileRecoveryStateError(
            "recovery record path must not contain symlinks"
        )
    try:
        with VaultStorage(_vault_path(root)) as storage:
            prepared = prepare_recovery_candidate(
                exact_recovery_path,
                recovery_key,
                storage,
                snapshot.receipt,
                exact_password,
                RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
                updated_utc=updated_utc,
                time_cost=time_cost,
                memory_kib=memory_kib,
                parallelism=parallelism,
            )
    except (VaultRecoveryCandidateError, VaultRecoveryStorageError) as exc:
        raise ProfileRecoveryStateError(
            "recovery record, phrase, or current Vault does not match"
        ) from exc
    evidence = prepared.evidence
    if expected_recovery_id is not None and not hmac.compare_digest(
        evidence.recovery_id, expected_recovery_id
    ):
        raise ProfileRecoveryStateError(
            "recovery phrase sheet and recovery record do not match"
        )
    if phrase_directory_device is not None and phrase_directory_device in (
        snapshot.receipt.directory_device,
        evidence.directory_device,
    ):
        raise ProfileRecoverySeparationError(
            "recovery phrase sheet is not separate from protected material"
        )
    return PreparedProfilePasswordRecovery(
        root,
        snapshot.receipt,
        exact_recovery_path,
        recovery_key,
        exact_password,
        prepared,
    )


def prepare_profile_password_recovery_from_words(
    profile_root: Any | None,
    recovery_path: Any,
    phrase: Any,
    new_password: Any,
    confirmation: Any,
    decision: ProfileRecoveryDecision,
    **options: Any,
) -> PreparedProfilePasswordRecovery:
    """Prepare a read-only candidate from 25 manually supplied full words."""

    try:
        key = decode_recovery_phrase(phrase)
    except RecoveryPhraseError as exc:
        raise ProfileRecoveryInputError("recovery phrase is invalid") from exc
    return _prepare_profile_password_recovery(
        profile_root,
        recovery_path,
        key,
        new_password,
        confirmation,
        decision,
        **options,
    )


def prepare_profile_password_recovery_from_sheet(
    profile_root: Any | None,
    recovery_path: Any,
    phrase_path: Any,
    new_password: Any,
    confirmation: Any,
    decision: ProfileRecoveryDecision,
    **options: Any,
) -> PreparedProfilePasswordRecovery:
    """Prepare a read-only candidate from a verified separate phrase sheet."""

    root = _profile_root(profile_root)
    snapshot = _ready_snapshot(root)
    record_device = _regular_file_device(recovery_path, "recovery record")
    forbidden = _unique_devices(snapshot.receipt.directory_device, record_device)
    try:
        sheet: ParsedRecoveryPhraseSheet = read_recovery_phrase_sheet(
            phrase_path,
            forbidden_devices=forbidden,
        )
    except RecoveryPhraseSeparationError as exc:
        raise ProfileRecoverySeparationError(
            "recovery phrase sheet is not on a separate device"
        ) from exc
    except RecoveryPhraseExportUnsupportedError as exc:
        raise ProfileRecoveryStorageUnsupportedError(
            "phrase sheet storage cannot be read with the required guarantees"
        ) from exc
    except RecoveryPhraseStorageError as exc:
        raise ProfileRecoveryInputError(
            "recovery phrase sheet is invalid or not separate"
        ) from exc
    return _prepare_profile_password_recovery(
        root,
        recovery_path,
        sheet.recovery_key,
        new_password,
        confirmation,
        decision,
        expected_recovery_id=sheet.recovery_id,
        phrase_directory_device=sheet.directory_device,
        **options,
    )


__all__ = [
    "PreparedProfilePasswordRecovery",
    "PreparedProfileRecoverySetup",
    "ProfilePasswordRecoveryPreview",
    "ProfilePasswordRecoveryResult",
    "ProfileRecoveryAuthenticationError",
    "ProfileRecoveryBackupError",
    "ProfileRecoveryBackupKind",
    "ProfileRecoveryDecision",
    "ProfileRecoveryError",
    "ProfileRecoveryExportUncertainError",
    "ProfileRecoveryInputError",
    "ProfileRecoveryLifecyclePublishError",
    "ProfileRecoveryPublishUncertainError",
    "ProfileRecoverySeparationError",
    "ProfileRecoverySetupResult",
    "ProfileRecoveryStateError",
    "ProfileRecoveryStorageUnsupportedError",
    "begin_profile_recovery_setup",
    "prepare_profile_password_recovery_from_sheet",
    "prepare_profile_password_recovery_from_words",
]
