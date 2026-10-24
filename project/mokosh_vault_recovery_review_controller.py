"""One-shot Stage 2.16 application boundary for recovery review display.

The controller composes only the already bounded Stage 2.10 presentation,
Stage 2.12 UI adapter, Stage 2.13 localization, and Stage 2.14 review window.
It accepts one exact Stage 2.9 in-memory state and an existing GUI parent.  It
does not accept a password, recovery root, keyring, path, callback, executor,
or operation capability, and it cannot authorize or perform recovery.
"""

from __future__ import annotations

import hmac
from dataclasses import replace as _replace
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_localization import RecoveryLocalizationLocale
from mokosh_vault_recovery_presentation import (
    VaultRecoveryPresentationError,
    VaultRecoveryWorkflowPresentation,
    prepare_recovery_workflow_presentation,
)
from mokosh_vault_recovery_review_window import (
    VaultRecoveryReviewWindowDisplayError,
    VaultRecoveryReviewWindowError,
    VaultRecoveryReviewWindowOutcome,
    prepare_recovery_review_window,
    show_recovery_review_window as _show_recovery_review_window,
)
from mokosh_vault_recovery_ui_adapter import (
    PreparedVaultRecoveryUIAdapter,
    VaultRecoveryUIAdapterError,
    prepare_recovery_ui_adapter,
)
from mokosh_vault_recovery_workflow import VaultRecoveryWorkflowState


class VaultRecoveryReviewControllerError(ValueError):
    """The bounded Stage 2.16 review session failed safely."""


class VaultRecoveryReviewControllerSourceError(VaultRecoveryReviewControllerError):
    """The supplied state or locale is not an exact supported source."""


class VaultRecoveryReviewControllerDisplayError(VaultRecoveryReviewControllerError):
    """The local review could not be displayed and the session was consumed."""


class VaultRecoveryReviewControllerOutcomeError(VaultRecoveryReviewControllerError):
    """The returned Stage 2.14 outcome did not match the prepared session."""


class RecoveryReviewControllerState(str, Enum):
    """One-shot process-local controller lifecycle."""

    PREPARED = "prepared"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


class PreparedVaultRecoveryReviewSession:
    """A fresh one-shot display session retaining no Stage 2.9 source state."""

    __slots__ = (
        "_presentation",
        "_adapter",
        "_locale_id",
        "_expected_locale",
        "_expected_presentation_sha256",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        presentation: VaultRecoveryWorkflowPresentation,
        adapter: PreparedVaultRecoveryUIAdapter,
        locale_id: str,
    ) -> None:
        if (
            type(presentation) is not VaultRecoveryWorkflowPresentation
            or type(adapter) is not PreparedVaultRecoveryUIAdapter
            or type(locale_id) is not str
        ):
            raise VaultRecoveryReviewControllerSourceError(
                "recovery review session sources use invalid types"
            )
        try:
            prepared_window = prepare_recovery_review_window(
                presentation,
                adapter,
                locale_id,
            )
        except VaultRecoveryReviewWindowError as exc:
            raise VaultRecoveryReviewControllerSourceError(
                "recovery review session sources do not match"
            ) from exc
        self._presentation: VaultRecoveryWorkflowPresentation | None = presentation
        self._adapter: PreparedVaultRecoveryUIAdapter | None = adapter
        self._locale_id = locale_id
        self._expected_locale = prepared_window.localized_view.locale
        self._expected_presentation_sha256 = (
            prepared_window.localized_view.presentation_sha256
        )
        self._state = RecoveryReviewControllerState.PREPARED
        self._outcome: VaultRecoveryReviewWindowOutcome | None = None
        self._lock = _Lock()

    @property
    def current_state(self) -> RecoveryReviewControllerState:
        return self._state

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._expected_locale

    @property
    def outcome(self) -> VaultRecoveryReviewWindowOutcome | None:
        return self._outcome

    def show_once(self, parent: _Any) -> VaultRecoveryReviewWindowOutcome:
        """Display exactly once and return only a revalidated bounded outcome."""

        with self._lock:
            if self._state is not RecoveryReviewControllerState.PREPARED:
                raise VaultRecoveryReviewControllerOutcomeError(
                    "recovery review session is not fresh"
                )
            presentation = self._presentation
            adapter = self._adapter
            if (
                type(presentation) is not VaultRecoveryWorkflowPresentation
                or type(adapter) is not PreparedVaultRecoveryUIAdapter
            ):
                self._state = RecoveryReviewControllerState.FAILED
                self._clear_sources()
                raise VaultRecoveryReviewControllerSourceError(
                    "recovery review session sources are unavailable"
                )
            self._state = RecoveryReviewControllerState.DISPLAYING

        try:
            outcome = _show_recovery_review_window(
                parent,
                presentation,
                adapter,
                self._locale_id,
            )
            validated = self._validate_exact_outcome(outcome)
        except VaultRecoveryReviewWindowDisplayError as exc:
            self._fail()
            raise VaultRecoveryReviewControllerDisplayError(
                "local recovery review display failed safely"
            ) from exc
        except VaultRecoveryReviewWindowError as exc:
            self._fail()
            raise VaultRecoveryReviewControllerOutcomeError(
                "local recovery review source or interaction failed safely"
            ) from exc
        except VaultRecoveryReviewControllerError:
            self._fail()
            raise
        except BaseException:
            self._fail()
            raise

        with self._lock:
            self._outcome = validated
            self._state = RecoveryReviewControllerState.COMPLETED
            self._clear_sources()
        return validated

    def _validate_exact_outcome(
        self,
        outcome: _Any,
    ) -> VaultRecoveryReviewWindowOutcome:
        if type(outcome) is not VaultRecoveryReviewWindowOutcome:
            raise VaultRecoveryReviewControllerOutcomeError(
                "review outcome type is invalid"
            )
        try:
            validated = _replace(outcome)
        except (TypeError, ValueError) as exc:
            raise VaultRecoveryReviewControllerOutcomeError(
                "review outcome is invalid"
            ) from exc
        if (
            validated.locale is not self._expected_locale
            or not hmac.compare_digest(
                validated.presentation_sha256,
                self._expected_presentation_sha256,
            )
        ):
            raise VaultRecoveryReviewControllerOutcomeError(
                "review outcome differs from the prepared session"
            )
        return validated

    def _fail(self) -> None:
        with self._lock:
            self._state = RecoveryReviewControllerState.FAILED
            self._clear_sources()

    def _clear_sources(self) -> None:
        self._presentation = None
        self._adapter = None

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryReviewSession("
            f"locale={self._expected_locale.value!r}, "
            f"state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryReviewControllerOutcomeError(
            "recovery review session cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        raise VaultRecoveryReviewControllerOutcomeError(
            "recovery review session cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryReviewControllerOutcomeError(
            "recovery review session cannot be serialized"
        )


def prepare_recovery_review_session(
    workflow_state: VaultRecoveryWorkflowState,
    locale_id: str,
) -> PreparedVaultRecoveryReviewSession:
    """Prepare one exact no-authority Stage 2.16 review display session."""

    if type(workflow_state) is not VaultRecoveryWorkflowState or type(locale_id) is not str:
        raise VaultRecoveryReviewControllerSourceError(
            "workflow state and locale must use exact supported types"
        )
    try:
        presentation = prepare_recovery_workflow_presentation(workflow_state)
        adapter = prepare_recovery_ui_adapter(presentation)
    except (
        VaultRecoveryPresentationError,
        VaultRecoveryUIAdapterError,
        VaultRecoveryReviewWindowError,
    ) as exc:
        raise VaultRecoveryReviewControllerSourceError(
            "recovery review source is invalid or unsupported"
        ) from exc
    return PreparedVaultRecoveryReviewSession(
        presentation,
        adapter,
        locale_id,
    )
