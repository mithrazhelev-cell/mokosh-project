"""One-shot Stage 2.39 application boundary for source-inspection review.

The controller composes only the already bounded Stage 2.33 presentation,
Stage 2.35 UI adapter, Stage 2.36 localization through Stage 2.37, and the
Stage 2.37/2.38 review-window display path.  It accepts one exact Stage 2.32
in-memory execution outcome and an existing GUI parent only at display time.
It does not accept a locale, path, source descriptor, password, recovery
secret, callback, executor, or operation capability, and it cannot authorize
or perform recovery.
"""

from __future__ import annotations

import hmac
from dataclasses import replace as _replace
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_execution import (
    VaultRecoverySourceInspectionExecutionOutcome,
)
from mokosh_vault_recovery_source_inspection_presentation import (
    VaultRecoverySourceInspectionPresentation,
    VaultRecoverySourceInspectionPresentationError,
    prepare_recovery_source_inspection_presentation,
)
from mokosh_vault_recovery_source_inspection_review_window import (
    VaultRecoverySourceInspectionReviewWindowDisplayError,
    VaultRecoverySourceInspectionReviewWindowError,
    VaultRecoverySourceInspectionReviewWindowOutcome,
    prepare_recovery_source_inspection_review_window,
    show_recovery_source_inspection_review_window as _show_recovery_source_inspection_review_window,
)
from mokosh_vault_recovery_source_inspection_ui_adapter import (
    PreparedVaultRecoverySourceInspectionUIAdapter,
    VaultRecoverySourceInspectionUIAdapterError,
    prepare_recovery_source_inspection_ui_adapter,
)


class VaultRecoverySourceInspectionReviewControllerError(ValueError):
    """The bounded Stage 2.39 review session failed safely."""


class VaultRecoverySourceInspectionReviewControllerSourceError(
    VaultRecoverySourceInspectionReviewControllerError
):
    """The supplied Stage 2.32 source or prepared layers are invalid."""


class VaultRecoverySourceInspectionReviewControllerDisplayError(
    VaultRecoverySourceInspectionReviewControllerError
):
    """The local review could not be displayed and the session was consumed."""


class VaultRecoverySourceInspectionReviewControllerOutcomeError(
    VaultRecoverySourceInspectionReviewControllerError
):
    """The returned Stage 2.37/2.38 outcome did not match the session."""


class RecoverySourceInspectionReviewControllerState(str, Enum):
    """One-shot process-local Stage 2.39 lifecycle."""

    PREPARED = "prepared"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


class PreparedVaultRecoverySourceInspectionReviewSession:
    """Fresh one-shot display session retaining no Stage 2.32 source outcome."""

    __slots__ = (
        "_presentation",
        "_adapter",
        "_expected_locale",
        "_expected_presentation_sha256",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        presentation: VaultRecoverySourceInspectionPresentation,
        adapter: PreparedVaultRecoverySourceInspectionUIAdapter,
    ) -> None:
        if (
            type(presentation) is not VaultRecoverySourceInspectionPresentation
            or type(adapter) is not PreparedVaultRecoverySourceInspectionUIAdapter
        ):
            raise VaultRecoverySourceInspectionReviewControllerSourceError(
                "source inspection review session sources use invalid types"
            )
        try:
            prepared_window = prepare_recovery_source_inspection_review_window(
                presentation,
                adapter,
            )
        except VaultRecoverySourceInspectionReviewWindowError as exc:
            raise VaultRecoverySourceInspectionReviewControllerSourceError(
                "source inspection review session sources do not match"
            ) from exc
        self._presentation: VaultRecoverySourceInspectionPresentation | None = (
            presentation
        )
        self._adapter: PreparedVaultRecoverySourceInspectionUIAdapter | None = adapter
        self._expected_locale = prepared_window.localized_view.locale
        self._expected_presentation_sha256 = (
            prepared_window.localized_view.presentation_sha256
        )
        self._state = RecoverySourceInspectionReviewControllerState.PREPARED
        self._outcome: VaultRecoverySourceInspectionReviewWindowOutcome | None = None
        self._lock = _Lock()

    @property
    def current_state(self) -> RecoverySourceInspectionReviewControllerState:
        return self._state

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._expected_locale

    @property
    def outcome(self) -> VaultRecoverySourceInspectionReviewWindowOutcome | None:
        return self._outcome

    def show_once(self, parent: _Any) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        """Display exactly once and return only a revalidated bounded outcome."""

        with self._lock:
            if self._state is not RecoverySourceInspectionReviewControllerState.PREPARED:
                raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                    "source inspection review session is not fresh"
                )
            presentation = self._presentation
            adapter = self._adapter
            if (
                type(presentation) is not VaultRecoverySourceInspectionPresentation
                or type(adapter) is not PreparedVaultRecoverySourceInspectionUIAdapter
            ):
                self._state = RecoverySourceInspectionReviewControllerState.FAILED
                self._clear_sources()
                raise VaultRecoverySourceInspectionReviewControllerSourceError(
                    "source inspection review session sources are unavailable"
                )
            self._state = RecoverySourceInspectionReviewControllerState.DISPLAYING

        try:
            outcome = _show_recovery_source_inspection_review_window(
                parent,
                presentation,
                adapter,
            )
            validated = self._validate_exact_outcome(outcome)
        except VaultRecoverySourceInspectionReviewWindowDisplayError as exc:
            self._fail()
            raise VaultRecoverySourceInspectionReviewControllerDisplayError(
                "local source inspection review display failed safely"
            ) from exc
        except VaultRecoverySourceInspectionReviewWindowError as exc:
            self._fail()
            raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                "local source inspection review interaction failed safely"
            ) from exc
        except VaultRecoverySourceInspectionReviewControllerError:
            self._fail()
            raise
        except BaseException:
            self._fail()
            raise

        with self._lock:
            self._outcome = validated
            self._state = RecoverySourceInspectionReviewControllerState.COMPLETED
            self._clear_sources()
        return validated

    def _validate_exact_outcome(
        self,
        outcome: _Any,
    ) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        if type(outcome) is not VaultRecoverySourceInspectionReviewWindowOutcome:
            raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                "source inspection review outcome type is invalid"
            )
        try:
            validated = _replace(outcome)
        except (TypeError, ValueError) as exc:
            raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                "source inspection review outcome is invalid"
            ) from exc
        if (
            validated.locale is not self._expected_locale
            or not hmac.compare_digest(
                validated.presentation_sha256,
                self._expected_presentation_sha256,
            )
        ):
            raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                "source inspection review outcome differs from the prepared session"
            )
        receipt = validated.acknowledgement_receipt
        if receipt is not None and (
            receipt.locale is not self._expected_locale
            or not hmac.compare_digest(
                receipt.presentation_sha256,
                self._expected_presentation_sha256,
            )
        ):
            raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
                "source inspection acknowledgement differs from the prepared session"
            )
        return validated

    def _fail(self) -> None:
        with self._lock:
            self._state = RecoverySourceInspectionReviewControllerState.FAILED
            self._clear_sources()

    def _clear_sources(self) -> None:
        self._presentation = None
        self._adapter = None

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionReviewSession("
            f"locale={self._expected_locale.value!r}, "
            f"state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
            "source inspection review session cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
            "source inspection review session cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionReviewControllerOutcomeError(
            "source inspection review session cannot be serialized"
        )


def prepare_recovery_source_inspection_review_session(
    execution_outcome: VaultRecoverySourceInspectionExecutionOutcome,
) -> PreparedVaultRecoverySourceInspectionReviewSession:
    """Prepare one exact no-authority Stage 2.39 source-inspection review."""

    if type(execution_outcome) is not VaultRecoverySourceInspectionExecutionOutcome:
        raise VaultRecoverySourceInspectionReviewControllerSourceError(
            "execution outcome must use the exact Stage 2.32 type"
        )
    try:
        presentation = prepare_recovery_source_inspection_presentation(
            execution_outcome
        )
        adapter = prepare_recovery_source_inspection_ui_adapter(presentation)
    except (
        VaultRecoverySourceInspectionPresentationError,
        VaultRecoverySourceInspectionUIAdapterError,
        VaultRecoverySourceInspectionReviewWindowError,
    ) as exc:
        raise VaultRecoverySourceInspectionReviewControllerSourceError(
            "source inspection execution outcome is invalid or unsupported"
        ) from exc
    return PreparedVaultRecoverySourceInspectionReviewSession(
        presentation,
        adapter,
    )
