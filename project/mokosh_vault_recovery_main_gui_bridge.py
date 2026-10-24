"""Inactive Stage 2.17 handoff from the main GUI to recovery review.

The bridge accepts only an already prepared Stage 2.16 review session whose
locale is bound exactly.  It has no source-input, recovery, filesystem, or
operation API.  Normal MOKOSH startup creates no binding and therefore cannot
activate this handoff.
"""

from __future__ import annotations

from dataclasses import replace as _replace
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_localization import RecoveryLocalizationLocale
from mokosh_vault_recovery_review_controller import (
    PreparedVaultRecoveryReviewSession,
    RecoveryReviewControllerState,
    VaultRecoveryReviewControllerError,
)
from mokosh_vault_recovery_review_window import VaultRecoveryReviewWindowOutcome


class VaultRecoveryMainGUIBridgeError(ValueError):
    """The bounded Stage 2.17 main-GUI handoff failed safely."""


class VaultRecoveryMainGUIBridgeSourceError(VaultRecoveryMainGUIBridgeError):
    """The supplied prepared session or locale is invalid or mismatched."""


class VaultRecoveryMainGUIBridgeDisplayError(VaultRecoveryMainGUIBridgeError):
    """The one permitted review display attempt failed safely."""


class VaultRecoveryMainGUIBridgeOutcomeError(VaultRecoveryMainGUIBridgeError):
    """The result returned through the handoff is invalid or replayed."""


class RecoveryMainGUIBridgeState(str, Enum):
    """One-shot process-local Stage 2.17 handoff lifecycle."""

    READY = "ready"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


_LOCALE_BY_ID = {
    "bg-BG": RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    "en-GB": RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
}


class PreparedMainGUIRecoveryReviewBinding:
    """An exact locale-bound, one-shot handoff containing no source state."""

    __slots__ = (
        "_session",
        "_locale",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        session: PreparedVaultRecoveryReviewSession,
        locale_id: str,
    ) -> None:
        if (
            type(session) is not PreparedVaultRecoveryReviewSession
            or type(locale_id) is not str
        ):
            raise VaultRecoveryMainGUIBridgeSourceError(
                "main-GUI recovery review sources use invalid types"
            )
        locale = _LOCALE_BY_ID.get(locale_id)
        if (
            locale is None
            or session.current_state is not RecoveryReviewControllerState.PREPARED
            or session.locale is not locale
        ):
            raise VaultRecoveryMainGUIBridgeSourceError(
                "main-GUI recovery review sources are not fresh or do not match"
            )
        self._session: PreparedVaultRecoveryReviewSession | None = session
        self._locale = locale
        self._state = RecoveryMainGUIBridgeState.READY
        self._outcome: VaultRecoveryReviewWindowOutcome | None = None
        self._lock = _Lock()

    @property
    def current_state(self) -> RecoveryMainGUIBridgeState:
        return self._state

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def outcome(self) -> VaultRecoveryReviewWindowOutcome | None:
        return self._outcome

    def show_once(self, parent: _Any) -> VaultRecoveryReviewWindowOutcome:
        """Use the exact prepared session once and return a bounded outcome."""

        with self._lock:
            if self._state is not RecoveryMainGUIBridgeState.READY:
                raise VaultRecoveryMainGUIBridgeOutcomeError(
                    "main-GUI recovery review binding is not fresh"
                )
            session = self._session
            if type(session) is not PreparedVaultRecoveryReviewSession:
                self._state = RecoveryMainGUIBridgeState.FAILED
                self._session = None
                raise VaultRecoveryMainGUIBridgeSourceError(
                    "main-GUI recovery review session is unavailable"
                )
            self._state = RecoveryMainGUIBridgeState.DISPLAYING

        try:
            outcome = session.show_once(parent)
            validated = self._validate_exact_outcome(outcome)
        except VaultRecoveryReviewControllerError as exc:
            self._fail()
            raise VaultRecoveryMainGUIBridgeDisplayError(
                "main-GUI recovery review display failed safely"
            ) from exc
        except VaultRecoveryMainGUIBridgeError:
            self._fail()
            raise
        except BaseException:
            self._fail()
            raise

        with self._lock:
            self._outcome = validated
            self._state = RecoveryMainGUIBridgeState.COMPLETED
            self._session = None
        return validated

    def _validate_exact_outcome(
        self,
        outcome: _Any,
    ) -> VaultRecoveryReviewWindowOutcome:
        if type(outcome) is not VaultRecoveryReviewWindowOutcome:
            raise VaultRecoveryMainGUIBridgeOutcomeError(
                "main-GUI recovery review outcome type is invalid"
            )
        try:
            validated = _replace(outcome)
        except (TypeError, ValueError) as exc:
            raise VaultRecoveryMainGUIBridgeOutcomeError(
                "main-GUI recovery review outcome is invalid"
            ) from exc
        if validated.locale is not self._locale:
            raise VaultRecoveryMainGUIBridgeOutcomeError(
                "main-GUI recovery review outcome locale differs"
            )
        return validated

    def _fail(self) -> None:
        with self._lock:
            self._state = RecoveryMainGUIBridgeState.FAILED
            self._session = None

    def __repr__(self) -> str:
        return (
            "PreparedMainGUIRecoveryReviewBinding("
            f"locale={self._locale.value!r}, state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryMainGUIBridgeOutcomeError(
            "main-GUI recovery review binding cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        raise VaultRecoveryMainGUIBridgeOutcomeError(
            "main-GUI recovery review binding cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryMainGUIBridgeOutcomeError(
            "main-GUI recovery review binding cannot be serialized"
        )


def prepare_main_gui_recovery_review_binding(
    prepared_session: PreparedVaultRecoveryReviewSession,
    locale_id: str,
) -> PreparedMainGUIRecoveryReviewBinding:
    """Prepare the inactive exact Stage 2.17 handoff for a future GUI event."""

    return PreparedMainGUIRecoveryReviewBinding(prepared_session, locale_id)
