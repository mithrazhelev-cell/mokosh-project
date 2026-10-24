#!/usr/bin/env python3
"""Launch the fixed Stage 2.38 manual Linux visual validation matrix."""

from __future__ import annotations

import argparse
import math
import sys
import tkinter as tk
from tkinter import messagebox, ttk

from mokosh_vault_recovery_source_inspection_review_window import (
    RecoverySourceInspectionReviewWindowCancelReason,
    RecoverySourceInspectionReviewWindowDecision,
    VaultRecoverySourceInspectionReviewWindowError,
    show_recovery_source_inspection_review_window,
)
from mokosh_vault_recovery_source_inspection_visual_harness import (
    RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX,
    RecoverySourceInspectionVisualHarnessObservation,
    RecoverySourceInspectionVisualHarnessObservations,
    VaultRecoverySourceInspectionVisualHarnessError,
    build_recovery_source_inspection_visual_harness_report,
    prepare_synthetic_recovery_source_inspection_visual_case,
    recovery_source_inspection_visual_harness_report_json,
    visual_observations_pass,
)


_MAP_POLL_MILLISECONDS = 25
_MAP_MAX_POLLS = 80
_WRAP_MIN = 240
_WRAP_MAX = 960
_MIN_MIDDLE_HEIGHT = 80

_ACTION_LABELS = {
    "escape_key": "КЛАВИША ESCAPE (ESC)",
    "cancel_button": "БУТОНА CANCEL / ОТКАЗ",
    "window_close": "СИСТЕМНОТО X",
    "acknowledge": "БУТОНА CONFIRM / ПОТВЪРДИ",
}


class _VisualHarnessLaunchError(RuntimeError):
    """The visible child could not satisfy the bounded launcher contract."""


def _widget_rect(widget: object) -> tuple[int, int, int, int] | None:
    try:
        if not bool(widget.winfo_ismapped()):
            return None
        width = int(widget.winfo_width())
        height = int(widget.winfo_height())
        left = int(widget.winfo_rootx())
        top = int(widget.winfo_rooty())
    except (AttributeError, TypeError, ValueError, tk.TclError):
        return None
    if width <= 0 or height <= 0:
        return None
    return left, top, left + width, top + height


def _layout_regions_visible(
    container: object,
    regions: tuple[object, object, object],
    required_controls: tuple[object, ...],
) -> bool:
    container_rect = _widget_rect(container)
    region_rects = tuple(_widget_rect(widget) for widget in regions)
    control_rects = tuple(_widget_rect(widget) for widget in required_controls)
    if (
        container_rect is None
        or any(rect is None for rect in region_rects)
        or any(rect is None for rect in control_rects)
    ):
        return False
    left, top, right, bottom = container_rect
    checked_regions = tuple(rect for rect in region_rects if rect is not None)
    checked_controls = tuple(rect for rect in control_rects if rect is not None)
    if checked_regions[1][3] - checked_regions[1][1] < _MIN_MIDDLE_HEIGHT:
        return False
    for rect in (*checked_regions, *checked_controls):
        if (
            rect[0] < left
            or rect[1] < top
            or rect[2] > right
            or rect[3] > bottom
        ):
            return False
    return (
        checked_regions[0][3] <= checked_regions[1][1]
        and checked_regions[1][3] <= checked_regions[2][1]
    )


def _require_visible_layout(
    root: tk.Tk,
    regions: tuple[object, object, object],
    required_controls: tuple[object, ...],
    *,
    phase: str,
    case: object,
) -> None:
    root.update_idletasks()
    if _layout_regions_visible(root, regions, required_controls):
        return
    print(
        "STAGE2_38_LAYOUT_VISIBILITY_FAILED "
        f"PHASE={phase} CASE={case.case_number} "
        f"SCALE={case.scale_percent} PROFILE={case.window_profile.value}",
        file=sys.stderr,
        flush=True,
    )
    raise _VisualHarnessLaunchError(
        f"{phase} has a hidden or unusable required layout region"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open the fixed eight-case Stage 2.38 synthetic Linux visual "
            "validation matrix using the real Stage 2.37 Toplevel."
        )
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help=(
            "Record all six observations as not_checked. The validation "
            "matrix then fails with a nonzero status."
        ),
    )
    return parser


def _not_checked_observations() -> RecoverySourceInspectionVisualHarnessObservations:
    value = RecoverySourceInspectionVisualHarnessObservation.NOT_CHECKED
    return RecoverySourceInspectionVisualHarnessObservations(
        value, value, value, value, value, value
    )


def _configure_child_until_mapped(
    root: tk.Tk,
    width: int,
    height: int,
    mapping_state: dict[str, bool],
    polls_remaining: int,
) -> None:
    if mapping_state["mapped"] or mapping_state["timed_out"]:
        return
    child = next(
        (item for item in root.winfo_children() if isinstance(item, tk.Toplevel)),
        None,
    )
    if child is not None:
        try:
            child.geometry(f"{width}x{height}")
            child.update_idletasks()
            if bool(child.winfo_ismapped()):
                mapping_state["mapped"] = True
                return
        except tk.TclError:
            pass
    if polls_remaining <= 0:
        mapping_state["timed_out"] = True
        if child is not None:
            try:
                child.destroy()
            except tk.TclError:
                pass
        return
    root.after(
        _MAP_POLL_MILLISECONDS,
        _configure_child_until_mapped,
        root,
        width,
        height,
        mapping_state,
        polls_remaining - 1,
    )


def _action_instruction(action: str) -> str:
    return {
        "escape_key": (
            "Накрая натиснете клавиша Escape — не натискайте бутона "
            "за потвърждение."
        ),
        "cancel_button": (
            "Накрая натиснете видимия бутон за отказ — не натискайте "
            "бутона за потвърждение."
        ),
        "window_close": (
            "Накрая затворете прозореца чрез системния контрол X — не "
            "натискайте бутона за потвърждение."
        ),
        "acknowledge": "Накрая натиснете бутона за потвърждение.",
    }[action]


def _instruction_text(case: object, action: str) -> str:
    return (
        "Това е инструкция на тестовата програма, а не част от "
        "проверявания продукт.\n\n"
        "Cases 1–8 са задължителна последователност, а не избор според "
        "резултата. Текущият Case се изпълнява докрай с предварително "
        "зададеното действие. PASS или FAIL се отбелязва едва в следващия "
        "формуляр.\n\n"
        f"Последователен синтетичен Case {case.case_number}/8\n"
        f"Език на проверявания прозорец: {case.locale.value}\n"
        f"Мащаб: {case.scale_percent}%\n"
        f"Профил: {case.window_profile.value} "
        f"({case.width}×{case.height})\n\n"
        "Изпълнете точно следните стъпки:\n"
        "1. Натиснете „Започни случая“ и прочетете проверявания "
        "прозорец от началото.\n"
        "2. Проверете, че текстът е четлив, пренася се правилно и "
        "нищо не се застъпва.\n"
        "3. Превъртете до края с мишка и с клавиатура; всеки "
        "фокусиран контрол трябва да остава видим.\n"
        "4. Проверете, че и трите квадратчета първоначално не са "
        "отметнати.\n"
        "5. Отметнете и трите; бутонът за потвърждение трябва да "
        "се активира.\n"
        "6. Махнете една отметка; бутонът трябва отново да се "
        "деактивира.\n"
        "7. Поставете отметката отново.\n"
        "8. Разтеглете прозореца от ръб или ъгъл и проверете, че "
        "текстът се пренарежда ясно; после може да го върнете към "
        "началния размер.\n"
        f"9. {_action_instruction(action)}\n\n"
        "Въпросите се отварят автоматично след правилното крайно действие. "
        "Escape не е общ клавиш за продължаване. Използвайте само ръчни "
        "действия с мишка и клавиатура."
    )


def _action_banner_text(case_number: int, action: str) -> str:
    return (
        f"CASE {case_number}/8 — КРАЙНО ДЕЙСТВИЕ: {_ACTION_LABELS[action]}\n"
        "Това действие е зададено предварително и не зависи от PASS/FAIL. "
        "След него въпросите се отварят автоматично."
    )


def _show_matrix_overview(root: tk.Tk, case: object) -> None:
    _clear_root(root)
    root.title("MOKOSH Stage 2.38 — как се изпълнява матрицата")
    root.geometry("700x560")
    root.minsize(560, 440)
    root.resizable(True, True)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    outer = ttk.Frame(root, padding=16)
    outer.grid(row=0, column=0, sticky="nsew")
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(1, weight=1)
    header = ttk.Label(
        outer,
        text="MOKOSH Stage 2.38 — последователни Cases 1 → 8",
        justify="left",
        anchor="w",
        wraplength=640,
    )
    header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    body = ttk.Frame(outer)
    body.grid(row=1, column=0, sticky="nsew")
    canvas = tk.Canvas(body, highlightthickness=0, takefocus=True)
    scrollbar = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    content = ttk.Frame(canvas, padding=(4, 4, 12, 4))
    content_id = canvas.create_window((0, 0), window=content, anchor="nw")
    overview = ttk.Label(
        content,
        text=(
            "ВАЖНО: това са осем последователни теста — 1 → 2 → 3 → 4 → "
            "5 → 6 → 7 → 8. Не избирате Case според резултата.\n\n"
            "Във всеки Case първо изпълнявате общите проверки. После "
            "използвате точно предварително зададеното крайно действие. "
            "То служи за проверка на различен route и не означава PASS или "
            "FAIL.\n\n"
            "След правилното крайно действие въпросите се отварят "
            "автоматично. В тях отбелязвате действителния PASS/FAIL.\n\n"
            "Последователност на крайните действия:\n"
            "Case 1 — Escape; Case 2 — Cancel; Case 3 — X; "
            "Case 4 — Confirm; Case 5 — Cancel; Case 6 — Escape; "
            "Case 7 — Confirm; Case 8 — X."
        ),
        justify="left",
        anchor="nw",
        wraplength=640,
    )
    overview.pack(fill="x")
    content.bind(
        "<Configure>",
        lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
    )
    accepted = tk.BooleanVar(master=root, value=False)
    finished = tk.BooleanVar(master=root, value=False)
    cancelled = {"value": False}
    footer = ttk.Frame(outer)
    footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
    footer.columnconfigure(0, weight=1)
    start = ttk.Button(
        footer,
        text="Разбрах последователността — продължи",
        state="disabled",
        command=lambda: finished.set(1),
    )
    acknowledgement = tk.Checkbutton(
        footer,
        text="Разбирам: Case 1 → 8 са последователни.",
        variable=accepted,
        anchor="w",
        justify="left",
        wraplength=640,
        command=lambda: start.configure(
            state="normal" if accepted.get() else "disabled"
        ),
    )
    acknowledgement.grid(row=0, column=0, sticky="ew")
    start.grid(row=1, column=0, sticky="e", pady=(8, 0))

    def resize(event: tk.Event) -> None:
        width = max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
        canvas.itemconfigure(content_id, width=event.width)
        overview.configure(wraplength=width)
        header.configure(wraplength=width)
        acknowledgement.configure(wraplength=width)

    canvas.bind("<Configure>", resize)
    root.bind(
        "<MouseWheel>",
        lambda event: canvas.yview_scroll(
            -1 if event.delta > 0 else 1, "units"
        ),
    )
    root.bind("<Button-4>", lambda event: canvas.yview_scroll(-1, "units"))
    root.bind("<Button-5>", lambda event: canvas.yview_scroll(1, "units"))
    def cancel() -> None:
        cancelled["value"] = True
        finished.set(1)

    root.protocol("WM_DELETE_WINDOW", cancel)
    root.update_idletasks()
    root.deiconify()
    root.lift()
    root.wait_visibility()
    _require_visible_layout(
        root,
        (header, canvas, footer),
        (acknowledgement, start),
        phase="matrix_overview",
        case=case,
    )
    acknowledgement.focus_set()
    root.wait_variable(finished)
    if cancelled["value"] or not accepted.get():
        raise KeyboardInterrupt


def _clear_root(root: tk.Tk) -> None:
    for sequence in (
        "<Configure>",
        "<MouseWheel>",
        "<Button-4>",
        "<Button-5>",
        "<Prior>",
        "<Next>",
        "<Home>",
        "<End>",
    ):
        root.unbind(sequence)
    for child in root.winfo_children():
        child.destroy()


def _show_case_instructions(root: tk.Tk, case: object, action: str) -> None:
    _clear_root(root)
    root.title("MOKOSH Stage 2.38 — инструкция преди случая")
    root.geometry("680x560")
    root.minsize(560, 440)
    root.resizable(True, True)

    outer = ttk.Frame(root, padding=16)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    outer.grid(row=0, column=0, sticky="nsew")
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(1, weight=1)
    style = ttk.Style(root)
    style.configure(
        "HarnessAction.TLabel",
        font=("TkDefaultFont", 14, "bold"),
    )
    action_banner = ttk.Label(
        outer,
        text=_action_banner_text(case.case_number, action),
        style="HarnessAction.TLabel",
        justify="left",
        anchor="w",
        wraplength=620,
    )
    action_banner.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    body = ttk.Frame(outer)
    body.grid(row=1, column=0, sticky="nsew")
    canvas = tk.Canvas(body, highlightthickness=0, takefocus=True)
    scrollbar = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    content = ttk.Frame(canvas, padding=(4, 4, 12, 4))
    content_id = canvas.create_window((0, 0), window=content, anchor="nw")
    text = ttk.Label(
        content,
        text=_instruction_text(case, action),
        justify="left",
        anchor="nw",
        wraplength=620,
    )
    text.pack(fill="x", expand=True)
    content.bind(
        "<Configure>",
        lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
    )
    started = tk.BooleanVar(master=root, value=False)
    action_understood = tk.BooleanVar(master=root, value=False)
    cancelled = {"value": False}

    def cancel() -> None:
        cancelled["value"] = True
        started.set(1)

    footer = ttk.Frame(outer)
    footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
    footer.columnconfigure(0, weight=1)
    button = ttk.Button(
        footer,
        text="Разбрах — започни случая",
        state="disabled",
        command=lambda: started.set(1),
    )
    action_acknowledgement = tk.Checkbutton(
        footer,
        text=(
            f"Разбирам точното действие: {_ACTION_LABELS[action]}."
        ),
        variable=action_understood,
        anchor="w",
        justify="left",
        wraplength=620,
        command=lambda: button.configure(
            state="normal" if action_understood.get() else "disabled"
        ),
    )
    action_acknowledgement.grid(row=0, column=0, sticky="ew")
    button.grid(row=1, column=0, sticky="e", pady=(8, 0))

    def resize_content(event: tk.Event) -> None:
        canvas.itemconfigure(content_id, width=event.width)
        text.configure(
            wraplength=max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
        )
        action_banner.configure(
            wraplength=max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
        )
        action_acknowledgement.configure(
            wraplength=max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
        )

    canvas.bind("<Configure>", resize_content)
    root.bind(
        "<MouseWheel>",
        lambda event: canvas.yview_scroll(
            -1 if event.delta > 0 else 1, "units"
        ),
    )
    root.bind(
        "<Button-4>", lambda event: canvas.yview_scroll(-1, "units")
    )
    root.bind(
        "<Button-5>", lambda event: canvas.yview_scroll(1, "units")
    )
    root.bind("<Prior>", lambda event: canvas.yview_scroll(-1, "pages"))
    root.bind("<Next>", lambda event: canvas.yview_scroll(1, "pages"))
    root.bind("<Home>", lambda event: canvas.yview_moveto(0.0))
    root.bind("<End>", lambda event: canvas.yview_moveto(1.0))
    root.protocol("WM_DELETE_WINDOW", cancel)
    root.update_idletasks()
    root.deiconify()
    root.lift()
    root.wait_visibility()
    _require_visible_layout(
        root,
        (action_banner, canvas, footer),
        (action_acknowledgement, button),
        phase="case_instruction",
        case=case,
    )
    action_acknowledgement.focus_set()
    root.wait_variable(started)
    if cancelled["value"] or not action_understood.get():
        raise KeyboardInterrupt


_OBSERVATION_ROWS = (
    (
        "content_reachability_and_scrolling",
        "Във всички показани фази header/footer действията бяха видими "
        "първоначално без scroll, resize или maximize; цялото средно "
        "съдържание беше достижимо чрез превъртане.",
    ),
    (
        "text_wrapping_no_clipping_or_overlap",
        "Текстът се пренасяше без изрязване, съкращаване или застъпване.",
    ),
    (
        "focus_order_visible_unobscured",
        "Клавиатурният фокус беше логичен, видим и незакрит.",
    ),
    (
        "keyboard_only_no_trap",
        "Tab, Shift+Tab, Space, превъртането и Escape работеха без "
        "клавиатурен капан.",
    ),
    (
        "default_false_and_enable_redisable",
        "Квадратчетата започнаха празни; махането на отметка "
        "деактивира потвърждението.",
    ),
    (
        "locale_title_and_labels",
        "Заглавието и всички видими текстове бяха ясни и на "
        "очаквания език.",
    ),
)


def _observation_dialog(
    root: tk.Tk,
    case: object,
) -> RecoverySourceInspectionVisualHarnessObservations:
    _clear_root(root)
    root.title("MOKOSH Stage 2.38 — наблюдения след случая")
    root.geometry("760x640")
    root.minsize(560, 440)
    root.resizable(True, True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    outer = ttk.Frame(root, padding=16)
    outer.grid(row=0, column=0, sticky="nsew")
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(1, weight=1)
    heading = ttk.Label(
        outer,
        text=f"Case {case.case_number}/8 — запишете наблюденията",
        justify="left",
        anchor="w",
        wraplength=700,
    )
    heading.grid(row=0, column=0, sticky="ew", pady=(0, 12))

    body = ttk.Frame(outer)
    body.grid(row=1, column=0, sticky="nsew")
    canvas = tk.Canvas(body, highlightthickness=0, takefocus=True)
    scrollbar = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    content = ttk.Frame(canvas, padding=(4, 4, 12, 4))
    content_id = canvas.create_window((0, 0), window=content, anchor="nw")
    content.bind(
        "<Configure>",
        lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
    )

    variables: dict[str, tk.StringVar] = {}
    form_intro = ttk.Label(
        content,
        text=(
            "Изберете изрично по един отговор за всяко наблюдение. "
            "Няма предварително избран PASS. Оценявайте всички показани "
            "фази, включително видимостта на постоянните долни действия."
        ),
        justify="left",
        anchor="w",
        wraplength=640,
    )
    form_intro.pack(fill="x", pady=(0, 14))
    labels: list[ttk.Label] = [heading, form_intro]
    finished = tk.BooleanVar(master=root, value=False)
    cancelled = {"value": False}
    footer = ttk.Frame(outer)
    footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
    submit = ttk.Button(
        footer,
        text="Запиши наблюденията",
        state="disabled",
        command=lambda: finished.set(1),
    )
    submit.pack(side="right")

    def cancel() -> None:
        cancelled["value"] = True
        finished.set(1)

    abort = ttk.Button(
        footer,
        text="Прекрати матрицата",
        command=cancel,
    )
    abort.pack(side="right", padx=(0, 8))
    root.protocol("WM_DELETE_WINDOW", cancel)

    def update_submit() -> None:
        state = (
            "normal"
            if all(value.get() for value in variables.values())
            else "disabled"
        )
        submit.configure(state=state)

    for name, label_text in _OBSERVATION_ROWS:
        row = ttk.Frame(content)
        row.pack(fill="x", pady=(0, 14))
        label = ttk.Label(
            row,
            text=label_text,
            justify="left",
            anchor="w",
            wraplength=640,
        )
        label.pack(fill="x", pady=(0, 6))
        labels.append(label)
        variable = tk.StringVar(master=root, value="")
        variables[name] = variable
        choices = ttk.Frame(row)
        choices.pack(fill="x")
        for choice_text, value in (
            ("PASS — изпълнено", "pass"),
            ("FAIL — неизпълнено", "fail"),
            ("Не е проверено", "not_checked"),
        ):
            radio = ttk.Radiobutton(
                choices,
                text=choice_text,
                value=value,
                variable=variable,
                command=update_submit,
            )
            radio.pack(anchor="w", pady=(0, 4))
            radio.bind(
                "<FocusIn>",
                lambda event, widget=row: root.after_idle(
                    _reveal_canvas_widget,
                    canvas,
                    content,
                    widget,
                ),
            )

    def resize_content(event: tk.Event) -> None:
        canvas.itemconfigure(content_id, width=event.width)
        wrap = max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
        for label in labels:
            label.configure(wraplength=wrap)

    canvas.bind("<Configure>", resize_content)
    root.bind(
        "<MouseWheel>",
        lambda event: canvas.yview_scroll(
            -1 if event.delta > 0 else 1, "units"
        ),
    )
    root.bind(
        "<Button-4>", lambda event: canvas.yview_scroll(-1, "units")
    )
    root.bind(
        "<Button-5>", lambda event: canvas.yview_scroll(1, "units")
    )
    canvas.bind(
        "<Prior>", lambda event: canvas.yview_scroll(-1, "pages")
    )
    canvas.bind("<Next>", lambda event: canvas.yview_scroll(1, "pages"))
    canvas.bind("<Home>", lambda event: canvas.yview_moveto(0.0))
    canvas.bind("<End>", lambda event: canvas.yview_moveto(1.0))
    root.update_idletasks()
    root.deiconify()
    root.lift()
    root.wait_visibility()
    _require_visible_layout(
        root,
        (heading, canvas, footer),
        (abort, submit),
        phase="observations",
        case=case,
    )
    canvas.focus_set()
    root.wait_variable(finished)
    if cancelled["value"]:
        raise KeyboardInterrupt

    values = {
        name: RecoverySourceInspectionVisualHarnessObservation(variable.get())
        for name, variable in variables.items()
    }
    return RecoverySourceInspectionVisualHarnessObservations(**values)


def _reveal_canvas_widget(
    canvas: tk.Canvas,
    content: ttk.Frame,
    widget: ttk.Frame,
) -> None:
    canvas.update_idletasks()
    content_height = max(1, int(content.winfo_reqheight()))
    viewport_height = max(1, int(canvas.winfo_height()))
    visible_top = float(canvas.canvasy(0))
    visible_bottom = visible_top + viewport_height
    widget_top = float(widget.winfo_y())
    widget_bottom = widget_top + float(widget.winfo_height())
    if widget_top < visible_top:
        target = widget_top
    elif widget_bottom > visible_bottom:
        target = widget_bottom - viewport_height
    else:
        return
    maximum = max(0.0, float(content_height - viewport_height))
    canvas.yview_moveto(max(0.0, min(maximum, target)) / content_height)


def _observed_terminal_action(outcome: object) -> str:
    if (
        outcome.decision
        is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED
        and outcome.cancel_reason is None
    ):
        return "acknowledge"
    reasons = {
        RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY: (
            "escape_key"
        ),
        RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON: (
            "cancel_button"
        ),
        RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE: (
            "window_close"
        ),
    }
    return reasons.get(outcome.cancel_reason, "invalid_outcome")


def _run_case(case_number: int, skip_observations: bool) -> bool:
    case = prepare_synthetic_recovery_source_inspection_visual_case(case_number)
    root = tk.Tk()
    mapping_state = {"mapped": False, "timed_out": False}
    try:
        base_scaling = float(root.tk.call("tk", "scaling"))
        if not math.isfinite(base_scaling) or base_scaling <= 0.0:
            raise _VisualHarnessLaunchError("initial Tk scaling is invalid")
        relative_scaling = base_scaling * case.scale_percent / 100.0
        root.tk.call("tk", "scaling", relative_scaling)

        action = case.required_terminal_action.value
        if case.case_number == 1:
            _show_matrix_overview(root, case)
        _show_case_instructions(root, case, action)
        _clear_root(root)
        root.title(
            f"MOKOSH Stage 2.38 — случай {case.case_number}/8 се изпълнява"
        )
        root.geometry("560x440")
        status_label = ttk.Label(
            root,
            text=(
                f"Случай {case.case_number}/8 е отворен. Следвайте вече "
                f"прочетените стъпки.\n\nКрайно действие: "
                f"{_action_instruction(action)}"
            ),
            justify="left",
            anchor="center",
            wraplength=500,
            padding=24,
        )
        status_label.pack(fill="both", expand=True)
        root.bind(
            "<Configure>",
            lambda event: status_label.configure(
                wraplength=max(_WRAP_MIN, min(_WRAP_MAX, event.width - 48))
            ),
        )
        root.after(
            _MAP_POLL_MILLISECONDS,
            _configure_child_until_mapped,
            root,
            case.width,
            case.height,
            mapping_state,
            _MAP_MAX_POLLS,
        )
        outcome = show_recovery_source_inspection_review_window(
            root,
            case.presentation,
            case.adapter,
        )
        if mapping_state["timed_out"] or not mapping_state["mapped"]:
            raise _VisualHarnessLaunchError(
                "Stage 2.37 child did not map before the fixed timeout"
            )

        observed_action = _observed_terminal_action(outcome)
        if observed_action != action:
            diagnostic = (
                f"CASE={case.case_number} EXPECTED={action} "
                f"OBSERVED={observed_action}"
            )
            print(
                f"STAGE2_38_VISUAL_ACTION_MISMATCH {diagnostic}",
                file=sys.stderr,
                flush=True,
            )
            messagebox.showerror(
                "Stage 2.38 — грешно крайно действие",
                (
                    f"Case {case.case_number}/8 спира преди въпросите.\n\n"
                    f"Очаквано: {_ACTION_LABELS[action]}\n"
                    f"Използвано: {_ACTION_LABELS.get(observed_action, observed_action)}\n\n"
                    "Крайното действие е предварително зададен тестов route, "
                    "а не отговор PASS/FAIL."
                ),
                parent=root,
            )
            raise VaultRecoverySourceInspectionVisualHarnessError(diagnostic)

        try:
            build_recovery_source_inspection_visual_harness_report(
                case,
                outcome,
                _not_checked_observations(),
            )
        except VaultRecoverySourceInspectionVisualHarnessError:
            print(
                "STAGE2_38_MATCHING_ACTION_CONTRACT_VALIDATION_FAILED "
                f"CASE={case.case_number} ACTION={action}",
                file=sys.stderr,
                flush=True,
            )
            messagebox.showerror(
                "Stage 2.38 — вътрешна contract грешка",
                (
                    f"Case {case.case_number}/8 използва правилното действие, "
                    "но вътрешната contract validation отказа резултата. "
                    "Матрицата спира fail-closed."
                ),
                parent=root,
            )
            raise

        recorded = (
            _not_checked_observations()
            if skip_observations
            else _observation_dialog(root, case)
        )
        report = build_recovery_source_inspection_visual_harness_report(
            case,
            outcome,
            recorded,
        )
        print(
            recovery_source_inspection_visual_harness_report_json(report),
            flush=True,
        )
        return visual_observations_pass(recorded)
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        for case_number in range(
            1, len(RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX) + 1
        ):
            if not _run_case(case_number, args.no_observations):
                print(
                    "The fixed Stage 2.38 visual validation matrix did not pass.",
                    file=sys.stderr,
                )
                return 2
    except (
        tk.TclError,
        VaultRecoverySourceInspectionReviewWindowError,
        VaultRecoverySourceInspectionVisualHarnessError,
        _VisualHarnessLaunchError,
    ) as exc:
        print(
            "The Stage 2.38 synthetic visual harness failed safely: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print(
            "The Stage 2.38 synthetic visual harness was cancelled.",
            file=sys.stderr,
        )
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
