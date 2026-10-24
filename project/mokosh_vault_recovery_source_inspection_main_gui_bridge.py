"""Inactive Stage 2.40 handoff from the main GUI to source-inspection review.

The bridge accepts only an exact fresh Stage 2.39 review session.  Locale is
inherited from that session; there is no caller-controlled locale, source,
path, password, secret, callback, executor, or operation input.  Normal MOKOSH
startup creates no binding and cannot activate this handoff.
"""

from __future__ import annotations

from dataclasses import replace as _replace
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_review_controller import (
    PreparedVaultRecoverySourceInspectionReviewSession,
    RecoverySourceInspectionReviewControllerState,
    VaultRecoverySourceInspectionReviewControllerError,
)
from mokosh_vault_recovery_source_inspection_review_window import (
    VaultRecoverySourceInspectionReviewWindowOutcome,
)


class VaultRecoverySourceInspectionMainGUIBridgeError(ValueError):
    """The bounded Stage 2.40 main-GUI handoff failed safely."""


class VaultRecoverySourceInspectionMainGUIBridgeSourceError(
    VaultRecoverySourceInspectionMainGUIBridgeError
):
    """The supplied exact prepared session is invalid or no longer fresh."""


class VaultRecoverySourceInspectionMainGUIBridgeDisplayError(
    VaultRecoverySourceInspectionMainGUIBridgeError
):
    """The one permitted source-inspection review display failed safely."""


class VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
    VaultRecoverySourceInspectionMainGUIBridgeError
):
    """The source-inspection result is invalid, foreign, or replayed."""


class RecoverySourceInspectionMainGUIBridgeState(str, Enum):
    """One-shot process-local Stage 2.40 handoff lifecycle."""

    READY = "ready"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


class PreparedMainGUIRecoverySourceInspectionReviewBinding:
    """One exact, locale-bound handoff retaining no source or parent."""

    __slots__ = (
        "_session",
        "_session_identity",
        "_locale",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        session: PreparedVaultRecoverySourceInspectionReviewSession,
    ) -> None:
        if type(session) is not PreparedVaultRecoverySourceInspectionReviewSession:
            raise VaultRecoverySourceInspectionMainGUIBridgeSourceError(
                "source inspection main-GUI review session type is invalid"
            )
        if (
            session.current_state
            is not RecoverySourceInspectionReviewControllerState.PREPARED
            or type(session.locale) is not RecoveryLocalizationLocale
        ):
            raise VaultRecoverySourceInspectionMainGUIBridgeSourceError(
                "source inspection main-GUI review session is not fresh"
            )
        self._session: (
            PreparedVaultRecoverySourceInspectionReviewSession | None
        ) = session
        self._session_identity: int | None = id(session)
        self._locale = session.locale
        self._state = RecoverySourceInspectionMainGUIBridgeState.READY
        self._outcome: VaultRecoverySourceInspectionReviewWindowOutcome | None = None
        self._lock = _Lock()

    @property
    def current_state(self) -> RecoverySourceInspectionMainGUIBridgeState:
        return self._state

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def outcome(self) -> VaultRecoverySourceInspectionReviewWindowOutcome | None:
        return self._outcome

    def show_once(
        self,
        parent: _Any,
    ) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        """Use the exact prepared session once and return its bounded outcome."""

        with self._lock:
            if self._state is not RecoverySourceInspectionMainGUIBridgeState.READY:
                raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
                    "source inspection main-GUI review binding is not fresh"
                )
            session = self._session
            if (
                type(session)
                is not PreparedVaultRecoverySourceInspectionReviewSession
                or self._session_identity is None
                or id(session) != self._session_identity
                or session.current_state
                is not RecoverySourceInspectionReviewControllerState.PREPARED
                or session.locale is not self._locale
            ):
                self._state = RecoverySourceInspectionMainGUIBridgeState.FAILED
                self._session = None
                self._session_identity = None
                raise VaultRecoverySourceInspectionMainGUIBridgeSourceError(
                    "source inspection main-GUI review session is unavailable"
                )
            self._state = RecoverySourceInspectionMainGUIBridgeState.DISPLAYING

        try:
            outcome = session.show_once(parent)
            validated = self._validate_exact_session_outcome(session, outcome)
        except VaultRecoverySourceInspectionReviewControllerError as exc:
            self._fail()
            raise VaultRecoverySourceInspectionMainGUIBridgeDisplayError(
                "source inspection main-GUI review display failed safely"
            ) from exc
        except VaultRecoverySourceInspectionMainGUIBridgeError:
            self._fail()
            raise
        except BaseException:
            self._fail()
            raise

        with self._lock:
            self._outcome = validated
            self._state = RecoverySourceInspectionMainGUIBridgeState.COMPLETED
            self._session = None
            self._session_identity = None
        return validated

    def _validate_exact_session_outcome(
        self,
        session: PreparedVaultRecoverySourceInspectionReviewSession,
        outcome: _Any,
    ) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        if (
            type(outcome) is not VaultRecoverySourceInspectionReviewWindowOutcome
            or session.current_state
            is not RecoverySourceInspectionReviewControllerState.COMPLETED
            or session.outcome is not outcome
        ):
            raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
                "source inspection main-GUI outcome is not the session result"
            )
        try:
            validated = _replace(outcome)
        except (TypeError, ValueError) as exc:
            raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
                "source inspection main-GUI outcome is invalid"
            ) from exc
        if validated.locale is not self._locale:
            raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
                "source inspection main-GUI outcome locale differs"
            )
        return validated

    def _fail(self) -> None:
        with self._lock:
            self._state = RecoverySourceInspectionMainGUIBridgeState.FAILED
            self._session = None
            self._session_identity = None

    def __repr__(self) -> str:
        return (
            "PreparedMainGUIRecoverySourceInspectionReviewBinding("
            f"locale={self._locale.value!r}, state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
            "source inspection main-GUI review binding cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
            "source inspection main-GUI review binding cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionMainGUIBridgeOutcomeError(
            "source inspection main-GUI review binding cannot be serialized"
        )


def prepare_main_gui_recovery_source_inspection_review_binding(
    prepared_session: PreparedVaultRecoverySourceInspectionReviewSession,
) -> PreparedMainGUIRecoverySourceInspectionReviewBinding:
    """Prepare the inactive exact Stage 2.40 handoff for a future GUI event."""

    return PreparedMainGUIRecoverySourceInspectionReviewBinding(prepared_session)
