"""Bounded human-observation contract for the Stage 2.48 local V2 GUI."""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, fields
from typing import Any


LOCAL_V2_GUI_VISUAL_VERSION = 1
LOCAL_V2_GUI_VISUAL_MAX_JSON_BYTES = 4096
LOCAL_V2_GUI_VISUAL_SCALES = (100, 125, 150, 200)
LOCAL_V2_GUI_VISUAL_LOCALES = ("en", "bg")
LOCAL_V2_GUI_VISUAL_MODES = ("encrypt", "decrypt")


class LocalV2GUIVisualHarnessError(ValueError):
    """A visual case or bounded observation is invalid."""


class VisualObservation(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True, slots=True)
class LocalV2GUIVisualCase:
    case_number: int
    locale: str
    scale_percent: int
    mode: str


@dataclass(frozen=True, slots=True)
class LocalV2GUIVisualObservations:
    text_readable_and_unclipped: VisualObservation
    text_reflows_at_narrow_width: VisualObservation
    source_and_new_output_are_explicit: VisualObservation
    proposed_names_are_generic: VisualObservation
    originals_and_no_overwrite_warning_visible: VisualObservation
    encrypt_mok2_or_decrypt_magic_policy_visible: VisualObservation
    progress_and_cancel_state_are_clear: VisualObservation
    cleanable_residue_requires_explicit_action: VisualObservation
    ambiguous_residue_is_preserved_and_blocking: VisualObservation
    published_warning_says_do_not_retry: VisualObservation
    historical_mok1_route_is_separate: VisualObservation
    keyboard_focus_reaches_every_control: VisualObservation
    resize_scroll_and_window_controls_work: VisualObservation


@dataclass(frozen=True, slots=True)
class LocalV2GUIVisualReport:
    version: int
    case_number: int
    locale: str
    scale_percent: int
    mode: str
    observations: LocalV2GUIVisualObservations
    synthetic_non_secret: bool = True
    filesystem_mutation_performed: bool = False
    cryptographic_operation_performed: bool = False


LOCAL_V2_GUI_VISUAL_MATRIX = tuple(
    LocalV2GUIVisualCase(index + 1, locale, scale, mode)
    for index, (locale, scale, mode) in enumerate(
        (locale, scale, mode)
        for locale in LOCAL_V2_GUI_VISUAL_LOCALES
        for scale in LOCAL_V2_GUI_VISUAL_SCALES
        for mode in LOCAL_V2_GUI_VISUAL_MODES
    )
)


def prepare_local_v2_gui_visual_case(case_number: Any) -> LocalV2GUIVisualCase:
    if type(case_number) is not int or not 1 <= case_number <= len(
        LOCAL_V2_GUI_VISUAL_MATRIX
    ):
        raise LocalV2GUIVisualHarnessError("visual case number is invalid")
    return LOCAL_V2_GUI_VISUAL_MATRIX[case_number - 1]


def _validate_observations(value: Any) -> None:
    if not isinstance(value, LocalV2GUIVisualObservations):
        raise LocalV2GUIVisualHarnessError("visual observations are invalid")
    if any(not isinstance(item, VisualObservation) for item in asdict(value).values()):
        raise LocalV2GUIVisualHarnessError("visual observation value is invalid")


def build_local_v2_gui_visual_report(
    case: Any,
    observations: Any,
) -> LocalV2GUIVisualReport:
    if (
        not isinstance(case, LocalV2GUIVisualCase)
        or case not in LOCAL_V2_GUI_VISUAL_MATRIX
    ):
        raise LocalV2GUIVisualHarnessError("visual case is invalid")
    _validate_observations(observations)
    return LocalV2GUIVisualReport(
        version=LOCAL_V2_GUI_VISUAL_VERSION,
        case_number=case.case_number,
        locale=case.locale,
        scale_percent=case.scale_percent,
        mode=case.mode,
        observations=observations,
    )


def local_v2_gui_visual_report_json(report: Any) -> str:
    if not isinstance(report, LocalV2GUIVisualReport):
        raise LocalV2GUIVisualHarnessError("visual report is invalid")
    _validate_observations(report.observations)
    mapping = asdict(report)
    mapping["observations"] = {
        field.name: getattr(report.observations, field.name).value
        for field in fields(LocalV2GUIVisualObservations)
    }
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > LOCAL_V2_GUI_VISUAL_MAX_JSON_BYTES:
        raise LocalV2GUIVisualHarnessError("visual report exceeds its bound")
    return encoded


def local_v2_gui_visual_observations_pass(value: Any) -> bool:
    _validate_observations(value)
    return all(
        getattr(value, field.name) is VisualObservation.PASS
        for field in fields(LocalV2GUIVisualObservations)
    )


__all__ = [
    "LOCAL_V2_GUI_VISUAL_LOCALES",
    "LOCAL_V2_GUI_VISUAL_MATRIX",
    "LOCAL_V2_GUI_VISUAL_MAX_JSON_BYTES",
    "LOCAL_V2_GUI_VISUAL_MODES",
    "LOCAL_V2_GUI_VISUAL_SCALES",
    "LOCAL_V2_GUI_VISUAL_VERSION",
    "LocalV2GUIVisualCase",
    "LocalV2GUIVisualHarnessError",
    "LocalV2GUIVisualObservations",
    "LocalV2GUIVisualReport",
    "VisualObservation",
    "build_local_v2_gui_visual_report",
    "local_v2_gui_visual_observations_pass",
    "local_v2_gui_visual_report_json",
    "prepare_local_v2_gui_visual_case",
]
