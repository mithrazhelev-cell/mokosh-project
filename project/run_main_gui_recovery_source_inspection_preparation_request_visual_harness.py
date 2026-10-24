#!/usr/bin/env python3
"""Run the guided Stage 2.43 fifth-action human observation matrix."""

from __future__ import annotations

import argparse
import math
import os
import stat
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

import mokosh_gui
from mokosh_vault_recovery_source_inspection_preparation_request_main_gui_visual_harness import (
    RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_MATRIX,
    RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError,
    RecoverySourceInspectionPreparationRequestMainGUIVisualObservation,
    RecoverySourceInspectionPreparationRequestMainGUIVisualObservations,
    RecoverySourceInspectionPreparationRequestMainGUIVisualProfile,
    RecoverySourceInspectionPreparationRequestMainGUIVisualRoute,
    build_recovery_source_inspection_preparation_request_main_gui_visual_report,
    prepare_recovery_source_inspection_preparation_request_main_gui_visual_case,
    recovery_source_inspection_preparation_request_main_gui_observations_pass,
    recovery_source_inspection_preparation_request_main_gui_visual_report_json,
)


_FIXTURE_NAME = "MOKOSH_STAGE2_43_SYNTHETIC_NON_SECRET_EMPTY.mokr"
_OBSERVATION_FIELDS_AND_TEXT = (
    (
        "parallel_step_guide_visible_and_usable",
        "Остана ли отделният пътеводител видим през целия case и показваше ли ясна инструкция за всяка извършена стъпка?",
    ),
    (
        "five_staged_actions_reachable",
        "Виждаха ли се и бяха ли достижими всичките пет последователни действия?",
    ),
    (
        "fifth_action_locked_until_positive_fourth_action",
        "Остана ли петото действие заключено до положителното четвърто действие?",
    ),
    (
        "confirmation_opened_only_after_fifth_action",
        "Появи ли се потвърждението за подготовка само след отделно натискане на петото действие?",
    ),
    (
        "request_or_preserve_result_was_generic",
        "Беше ли крайното съобщение общо и без показване на path/име на файла?",
    ),
    (
        "no_source_content_secret_or_authority_observed",
        "Не беше ли поискано съдържание, тайна, capability или право за достъп?",
    ),
    (
        "all_five_actions_one_shot",
        "Останаха ли използваните пет действия еднократни и изключени след употреба?",
    ),
    (
        "picker_metadata_disclosure_visible",
        "Виждаше ли се предупреждението, че native picker може да чете filesystem metadata?",
    ),
    (
        "preparation_no_access_disclosure_visible",
        "Беше ли ясно, че искането за подготовка не разрешава достъп до source?",
    ),
    (
        "path_retention_and_no_zeroisation_disclosure_visible",
        "Виждаха ли се process-local path retention и липсата на доказуемо Python zeroisation?",
    ),
    (
        "adaptive_keyboard_reachability_observed",
        "Достигна ли keyboard focus петото действие с Tab и върна ли се с Shift+Tab без trap?",
    ),
    (
        "safety_controls_visible",
        "Останаха ли видими и изключени защитените controls за криптиране, почистване и Contacts?",
    ),
)


class _PreparationRequestMainGUIVisualLaunchError(RuntimeError):
    """The bounded guided visual matrix could not run safely."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise _PreparationRequestMainGUIVisualLaunchError(message)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the exact guided four-case Stage 2.43 human matrix."
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help="Record not_checked values and fail the human gate.",
    )
    return parser


class _SyntheticMokrFixture:
    """Own one empty non-secret .mokr fixture and remove the exact inode."""

    def __init__(self, downloads: Path | None = None) -> None:
        if downloads is not None and not isinstance(downloads, Path):
            raise TypeError("exact pathlib Downloads directory is required")
        directory = Path.home() / "Downloads" if downloads is None else downloads
        self.path = directory / _FIXTURE_NAME
        self._identity: tuple[int, int] | None = None

    def create(self) -> Path:
        directory_info = self.path.parent.lstat()
        _require(
            stat.S_ISDIR(directory_info.st_mode)
            and not self.path.parent.is_symlink(),
            "Downloads is not an exact physical directory",
        )
        _require(
            directory_info.st_uid == os.getuid()
            and directory_info.st_gid == os.getgid(),
            "Downloads owner/group differs from the current user",
        )
        _require(
            not self.path.exists() and not self.path.is_symlink(),
            "the exact synthetic .mokr fixture already exists",
        )
        descriptor = os.open(
            self.path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        self._identity = (info.st_dev, info.st_ino)
        valid = (
            stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid()
            and info.st_gid == os.getgid()
            and info.st_size == 0
        )
        if not valid:
            try:
                current = self.path.lstat()
                if (
                    stat.S_ISREG(current.st_mode)
                    and not self.path.is_symlink()
                    and (current.st_dev, current.st_ino) == self._identity
                ):
                    self.path.unlink()
            finally:
                self._identity = None
            raise _PreparationRequestMainGUIVisualLaunchError(
                "synthetic .mokr fixture attributes are invalid"
            )
        return self.path

    def remove(self) -> None:
        _require(self._identity is not None, "synthetic fixture was not created")
        info = self.path.lstat()
        _require(
            stat.S_ISREG(info.st_mode)
            and not self.path.is_symlink()
            and (info.st_dev, info.st_ino) == self._identity
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid()
            and info.st_gid == os.getgid()
            and info.st_size == 0,
            "synthetic .mokr fixture changed before cleanup",
        )
        self.path.unlink()
        directory_descriptor = os.open(
            self.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        _require(
            not self.path.exists() and not self.path.is_symlink(),
            "synthetic .mokr fixture cleanup failed",
        )
        self._identity = None


def _action_labels(case) -> tuple[str, str, str, str, str]:
    if case.locale == "bg-BG":
        return (
            "Заяви преглед за възстановяване...",
            "Продължи заявката за възстановяване...",
            "Избери локален recovery record...",
            "Заяви бъдеща сигурна инспекция...",
            "Заяви бъдеща подготовка за сигурна инспекция...",
        )
    return (
        "Request recovery review...",
        "Continue recovery request...",
        "Choose local recovery record...",
        "Request future secure inspection...",
        "Request future secure-inspection preparation...",
    )


def _guide_steps(case, fixture: Path) -> tuple[str, ...]:
    first, second, third, fourth, fifth = _action_labels(case)
    yes = "Да / Yes"
    no = "Не / No"
    fifth_choice = (
        yes
        if case.route
        is RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST
        else no
    )
    resize = (
        "Увеличете главния прозорец, после го върнете до началния му размер. "
        "Проверете отново, че текстовете и петте действия остават достижими."
        if case.profile
        is RecoverySourceInspectionPreparationRequestMainGUIVisualProfile.RESIZE_RESTORE_KEYBOARD
        else "Не променяйте началния размер на главния прозорец в този case."
    )
    return (
        (
            "НАЧАЛНА ПРОВЕРКА И ДЕЙСТВИЕ 1\n\n"
            "Работете само с петте зелени recovery действия. Не въвеждайте "
            "парола, не избирайте Vault и не използвайте crypto/Contacts controls.\n\n"
            "Проверете, че действия 2–5 и защитените controls започват изключени.\n\n"
            f"Натиснете „{first}“, изберете {yes}, после натиснете OK.\n\n"
            "Пътеводителят ще премине автоматично след успешното отключване на действие 2."
        ),
        (
            f"ДЕЙСТВИЕ 2\n\nНатиснете „{second}“.\n"
            f"В confirmation диалога изберете {yes}, после натиснете OK.\n\n"
            "Пътеводителят ще премине автоматично след отключването на действие 3."
        ),
        (
            f"ДЕЙСТВИЕ 3 — САМО СИНТЕТИЧНИЯТ ФАЙЛ\n\nНатиснете „{third}“.\n\n"
            "В picker-а използвайте горното поле Directory и въведете:\n"
            f"{fixture.parent}\n\n"
            "Натиснете Enter и изберете само:\n"
            f"{fixture.name}\n\n"
            "Натиснете Open, после OK. Никога не избирайте реален recovery record. "
            "Пътеводителят ще премине автоматично след отключването на действие 4."
        ),
        (
            f"ДЕЙСТВИЕ 4\n\nНатиснете „{fourth}“.\n"
            f"Изберете {yes}, после натиснете OK.\n\n"
            "Петото действие трябва да се отключи без автоматично стартиране; "
            "пътеводителят тогава ще премине сам."
        ),
        (
            f"KEYBOARD ПРОВЕРКА И ДЕЙСТВИЕ 5 — ROUTE: {case.route.value.upper()}\n\n"
            "Използвайте Tab до петото действие, Shift+Tab поне веднъж назад и "
            "Tab отново до петото действие. Не трябва да има keyboard trap.\n\n"
            f"Когато keyboard focus е отново върху „{fifth}“, натиснете Space, "
            "за да задействате петото действие чрез клавиатурата. "
            f"В confirmation диалога изберете {fifth_choice}, "
            "после натиснете OK. Крайното съобщение не трябва да показва path/име."
        ),
        (
            f"ФИНАЛНА ПРОВЕРКА\n\n{resize}\n\n"
            "Проверете, че използваните пет действия са изключени и защитените "
            "controls остават видими и изключени.\n\n"
            "Затворете само главния прозорец MOKOSH Agent със системното X. "
            "След това формулярът с 12 проверки трябва автоматично да излезе отпред."
        ),
    )


def _next_guide_progress(
    current_index: int,
    action_states: tuple[str, str, str, str, str],
    fifth_seen_enabled: bool,
) -> tuple[int, bool]:
    """Advance only from passively observed enable/disable state transitions."""

    if type(current_index) is not int or not 0 <= current_index <= 5:
        raise _PreparationRequestMainGUIVisualLaunchError(
            "guide progress index is invalid"
        )
    if (
        type(action_states) is not tuple
        or len(action_states) != 5
        or any(state not in {"normal", "active", "disabled"} for state in action_states)
        or type(fifth_seen_enabled) is not bool
    ):
        raise _PreparationRequestMainGUIVisualLaunchError(
            "guide action states are invalid"
        )
    next_index = current_index
    enabled_indices = tuple(
        index
        for index, state in enumerate(action_states)
        if state in {"normal", "active"}
    )
    if enabled_indices:
        furthest_enabled = max(enabled_indices)
        if current_index < 4 and furthest_enabled > current_index:
            next_index = min(furthest_enabled, 4)
    fifth_seen_enabled = fifth_seen_enabled or action_states[4] in {
        "normal",
        "active",
    }
    if current_index == 4 and fifth_seen_enabled and action_states[4] == "disabled":
        next_index = 5
    return next_index, fifth_seen_enabled


def _descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from _descendants(child)


def _exact_action_buttons(root, case) -> tuple[tk.Button, ...]:
    """Resolve the five normal-GUI buttons without changing their callbacks."""

    buttons = tuple(
        item for item in _descendants(root) if isinstance(item, tk.Button)
    )
    resolved = []
    for label in _action_labels(case):
        matches = tuple(item for item in buttons if str(item.cget("text")) == label)
        _require(len(matches) == 1, "exact guided action button was not found")
        resolved.append(matches[0])
    return tuple(resolved)


def _complete_guide_text(steps: tuple[str, ...], current_index: int) -> str:
    """Render the current instruction plus a permanent six-phase fallback."""

    if (
        type(steps) is not tuple
        or len(steps) != 6
        or any(type(step) is not str or not step for step in steps)
        or type(current_index) is not int
        or not 0 <= current_index < len(steps)
    ):
        raise _PreparationRequestMainGUIVisualLaunchError(
            "guide text inputs are invalid"
        )
    complete_plan = "\n\n".join(
        (
            f"{'→' if index == current_index else ' '} "
            f"ФАЗА {index + 1}/{len(steps)}\n{step}"
        )
        for index, step in enumerate(steps)
    )
    return (
        "ТЕКУЩА ИНСТРУКЦИЯ\n\n"
        f"{steps[current_index]}\n\n"
        "ПОСТОЯНЕН ПЪЛЕН ПЛАН — използвайте го, дори ако маркерът "
        "изостане:\n\n"
        f"{complete_plan}"
    )


class _StepGuide:
    """A visible, passive, non-authoritative guide beside the real GUI."""

    def __init__(self, root, case, fixture: Path) -> None:
        self._root = root
        self._case = case
        self._steps = _guide_steps(case, fixture)
        self._index = 0
        self._fifth_seen_enabled = False
        self._observer_id = None
        self.error = None
        self._buttons = _exact_action_buttons(root, case)
        self.window = tk.Toplevel(root)
        self.window.title(f"Stage 2.43 ПЪТЕВОДИТЕЛ — Case {case.case_number}/4")
        self.window.protocol("WM_DELETE_WINDOW", self._keep_open)

        header = tk.Label(
            self.window,
            text=(
                f"CASE {case.case_number}/4  |  MOKOSH {case.locale}  |  "
                f"Scale {case.scale_percent}%  |  Fifth route: {case.route.value.upper()}"
            ),
            bg="#17324d",
            fg="white",
            font=("TkDefaultFont", 11, "bold"),
            padx=10,
            pady=10,
            wraplength=610,
        )
        header.pack(fill="x")
        safety = tk.Label(
            self.window,
            text=(
                "САМО СИНТЕТИЧЕН ТЕСТ. Пътеводителят не натиска MOKOSH "
                "вместо Вас и не удостоверява резултат автоматично. Той само "
                "наблюдава disabled/normal състоянията и преминава сам."
            ),
            bg="#fff3cd",
            fg="#6b3a00",
            font=("TkDefaultFont", 10, "bold"),
            padx=10,
            pady=8,
            justify="left",
            anchor="w",
            wraplength=610,
        )
        safety.pack(fill="x", padx=8, pady=(8, 4))
        self._counter = tk.Label(
            self.window,
            font=("TkDefaultFont", 11, "bold"),
            anchor="w",
            padx=10,
            pady=6,
        )
        self._counter.pack(fill="x")

        text_frame = tk.Frame(self.window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=4)
        scrollbar = tk.Scrollbar(text_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")
        self._text = tk.Text(
            text_frame,
            wrap="word",
            font=("TkDefaultFont", 11),
            padx=12,
            pady=12,
            spacing1=3,
            spacing3=5,
            yscrollcommand=scrollbar.set,
            state="disabled",
        )
        self._text.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self._text.yview)

        self._render()
        self._position_beside_main()
        self._observer_id = self._root.after(150, self._observe_actions)

    def _keep_open(self) -> None:
        messagebox.showwarning(
            "Stage 2.43 Пътеводител",
            "Пътеводителят трябва да остане отворен до края на текущия case.",
            parent=self.window,
        )

    def _position_beside_main(self) -> None:
        try:
            self._root.update_idletasks()
            self.window.update_idletasks()
            screen_width = self._root.winfo_screenwidth()
            screen_height = self._root.winfo_screenheight()
            guide_width = min(650, max(480, screen_width // 2 - 40))
            guide_height = min(690, max(430, screen_height - 120))
            self._root.geometry("+20+20")
            guide_x = max(20, screen_width - guide_width - 20)
            self.window.geometry(
                f"{guide_width}x{guide_height}+{guide_x}+20"
            )
            self.window.minsize(min(430, guide_width), min(430, guide_height))
            self.window.transient(self._root)
            self.window.attributes("-topmost", True)
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
        except tk.TclError:
            return

    def _observe_actions(self) -> None:
        """Passively advance after exact normal-GUI button-state changes."""

        try:
            states = tuple(str(button.cget("state")) for button in self._buttons)
            next_index, self._fifth_seen_enabled = _next_guide_progress(
                self._index,
                states,
                self._fifth_seen_enabled,
            )
            if next_index != self._index:
                self._index = next_index
                self._render()
            self._observer_id = self._root.after(150, self._observe_actions)
        except _PreparationRequestMainGUIVisualLaunchError as exc:
            self.error = exc
            self._observer_id = None
            try:
                self._root.after_idle(self._root.destroy)
            except tk.TclError:
                pass
        except tk.TclError:
            self._observer_id = None

    def close(self) -> None:
        """Cancel the one passive observer before either Tk window is released."""

        if self._observer_id is not None:
            try:
                self._root.after_cancel(self._observer_id)
            except tk.TclError:
                pass
            self._observer_id = None
        try:
            if self.window.winfo_exists():
                self.window.destroy()
        except tk.TclError:
            pass

    def _render(self) -> None:
        self._counter.config(
            text=f"Инструкция {self._index + 1} от {len(self._steps)}"
        )
        self._text.config(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", _complete_guide_text(self._steps, self._index))
        self._text.config(state="disabled")
        self._text.yview_moveto(0.0)


def _not_checked_observations():
    value = RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.NOT_CHECKED
    return RecoverySourceInspectionPreparationRequestMainGUIVisualObservations(
        value,
        value,
        value,
        value,
        value,
        value,
        value,
        value,
        value,
        value,
        value,
        value,
    )


class _ObservationWizard:
    """Collect twelve explicit human judgments; default never means PASS."""

    def __init__(self, case) -> None:
        self._case = case
        self._index = 0
        self._values = [
            RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.NOT_CHECKED.value
            for _ in _OBSERVATION_FIELDS_AND_TEXT
        ]
        self._touched = [False for _ in _OBSERVATION_FIELDS_AND_TEXT]
        self.result = None
        self.root = tk.Tk()
        self.root.title(f"Stage 2.43 НАБЛЮДЕНИЯ — Case {case.case_number}/4")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(900, max(640, screen_width - 80))
        height = min(700, max(480, screen_height - 140))
        self.root.geometry(f"{width}x{height}+20+20")
        self.root.minsize(min(600, width), min(460, height))
        self.root.protocol("WM_DELETE_WINDOW", self._cancel)

        self._header = tk.Label(
            self.root,
            text=f"CASE {case.case_number}/4 — графична проверка 1/12",
            bg="#17324d",
            fg="white",
            font=("TkDefaultFont", 12, "bold"),
            padx=12,
            pady=12,
        )
        self._header.pack(fill="x")
        tk.Label(
            self.root,
            text=(
                "Отбележете само лично наблюдаваното. PASS не е избран "
                "предварително. FAIL или НЕПРОВЕРЕНО безопасно блокира live apply."
            ),
            bg="#fff3cd",
            fg="#6b3a00",
            justify="left",
            anchor="w",
            wraplength=770,
            padx=12,
            pady=10,
            font=("TkDefaultFont", 10, "bold"),
        ).pack(fill="x", padx=10, pady=10)

        cancel_row = tk.Frame(self.root)
        cancel_row.pack(fill="x", padx=18, pady=(0, 6))
        tk.Button(
            cancel_row,
            text="Откажи теста безопасно",
            command=self._cancel,
        ).pack(fill="x")

        navigation = tk.Frame(self.root)
        navigation.pack(fill="x", padx=18, pady=(0, 8))
        self._previous = tk.Button(
            navigation,
            text="← Предишна проверка",
            command=self._previous_question,
        )
        self._previous.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self._next = tk.Button(
            navigation,
            command=self._next_question,
        )
        self._next.pack(side="right", fill="x", expand=True, padx=(5, 0))

        body = tk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._body_canvas = tk.Canvas(body, highlightthickness=0)
        body_scrollbar = tk.Scrollbar(
            body,
            orient="vertical",
            command=self._body_canvas.yview,
        )
        body_scrollbar.pack(side="right", fill="y")
        self._body_canvas.pack(side="left", fill="both", expand=True)
        self._body_canvas.configure(yscrollcommand=body_scrollbar.set)
        body_content = tk.Frame(self._body_canvas)
        body_window = self._body_canvas.create_window(
            (0, 0),
            window=body_content,
            anchor="nw",
        )
        body_content.bind(
            "<Configure>",
            lambda _event: self._body_canvas.configure(
                scrollregion=self._body_canvas.bbox("all")
            ),
        )
        self._body_canvas.bind(
            "<Configure>",
            lambda event: self._body_canvas.itemconfigure(
                body_window,
                width=event.width,
            ),
        )

        self._counter = tk.Label(
            body_content,
            font=("TkDefaultFont", 12, "bold"),
            padx=12,
            pady=8,
        )
        self._counter.pack(fill="x")
        self._question = tk.Label(
            body_content,
            font=("TkDefaultFont", 12),
            justify="left",
            anchor="nw",
            wraplength=760,
            padx=18,
            pady=18,
        )
        self._question.pack(fill="both", expand=True)

        self._selection = tk.StringVar(
            value=RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.NOT_CHECKED.value
        )
        choices = tk.Frame(body_content)
        choices.pack(fill="x", padx=18, pady=8)
        for label, value in (
            ("PASS — наблюдавано успешно", "pass"),
            ("FAIL — наблюдаван е проблем", "fail"),
            ("НЕПРОВЕРЕНО — блокира apply", "not_checked"),
        ):
            tk.Radiobutton(
                choices,
                text=label,
                value=value,
                variable=self._selection,
                command=self._mark_touched,
                anchor="w",
                font=("TkDefaultFont", 11),
            ).pack(fill="x", pady=3)
        self._render()
        self.root.after_idle(self._present_above_all)

    def _present_above_all(self) -> None:
        """Map the observation form in front after the previous Tk root closes."""

        try:
            if not self.root.winfo_exists():
                return
            if self.root.state() in {"iconic", "withdrawn"}:
                self.root.deiconify()
            self.root.attributes("-topmost", True)
            self.root.lift()
            self.root.focus_force()
        except tk.TclError:
            return

    def _mark_touched(self) -> None:
        self._values[self._index] = self._selection.get()
        self._touched[self._index] = True
        self._render_buttons()

    def _previous_question(self) -> None:
        if self._index > 0:
            self._index -= 1
            self._render()

    def _next_question(self) -> None:
        if not self._touched[self._index]:
            return
        if self._index < len(_OBSERVATION_FIELDS_AND_TEXT) - 1:
            self._index += 1
            self._render()
            return
        self.result = RecoverySourceInspectionPreparationRequestMainGUIVisualObservations(
            *(
                RecoverySourceInspectionPreparationRequestMainGUIVisualObservation(value)
                for value in self._values
            )
        )
        self.root.destroy()

    def _cancel(self) -> None:
        if messagebox.askyesno(
            "Безопасно прекратяване",
            "Да се прекрати ли human matrix? Live apply няма да започне.",
            parent=self.root,
        ):
            self.result = None
            self.root.destroy()

    def _render_buttons(self) -> None:
        self._previous.config(state=tk.NORMAL if self._index else tk.DISABLED)
        self._next.config(
            text=(
                "Запиши Case-а"
                if self._index == len(_OBSERVATION_FIELDS_AND_TEXT) - 1
                else "Следваща проверка →"
            ),
            state=tk.NORMAL if self._touched[self._index] else tk.DISABLED,
        )

    def _render(self) -> None:
        self._header.config(
            text=(
                f"CASE {self._case.case_number}/4 — графична проверка "
                f"{self._index + 1}/{len(_OBSERVATION_FIELDS_AND_TEXT)}"
            )
        )
        self._counter.config(
            text=f"Проверка {self._index + 1} от {len(_OBSERVATION_FIELDS_AND_TEXT)}"
        )
        self._question.config(text=_OBSERVATION_FIELDS_AND_TEXT[self._index][1])
        self._selection.set(self._values[self._index])
        self._render_buttons()
        self._body_canvas.yview_moveto(0.0)

    def run(self):
        self.root.mainloop()
        return self.result


def _graphical_observations(case):
    return _ObservationWizard(case).run()


def _run_case(case_number: int, skip_observations: bool) -> bool:
    case = prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
        case_number
    )
    root = tk.Tk()
    original_tk = mokosh_gui.tk.Tk
    original_lang = mokosh_gui.current_lang
    fixture = _SyntheticMokrFixture()
    fixture_path = fixture.create()
    try:
        base_scaling = float(root.tk.call("tk", "scaling"))
        if not math.isfinite(base_scaling) or base_scaling <= 0.0:
            raise _PreparationRequestMainGUIVisualLaunchError(
                "initial Tk scaling is invalid"
            )
        root.tk.call(
            "tk",
            "scaling",
            base_scaling * case.scale_percent / 100.0,
        )
        mokosh_gui.current_lang = "bg" if case.locale == "bg-BG" else "en"
        guide_holder = []

        def open_guide_after_main_is_built() -> None:
            guide_holder.append(_StepGuide(root, case, fixture_path))

        root.after_idle(open_guide_after_main_is_built)
        print(
            f"CASE {case.case_number}/4 GUIDED_GUI_STARTED "
            f"locale={case.locale} scale={case.scale_percent}% "
            f"route={case.route.value}",
            flush=True,
        )
        print("Never choose a real recovery record.", flush=True)
        mokosh_gui.tk.Tk = lambda: root
        mokosh_gui.main()
        _require(len(guide_holder) == 1, "parallel step guide did not open")
        _require(
            guide_holder[0].error is None,
            "passive guide observer failed",
        )
    finally:
        if "guide_holder" in locals() and guide_holder:
            guide_holder[0].close()
            guide_holder.clear()
        mokosh_gui.tk.Tk = original_tk
        mokosh_gui.current_lang = original_lang
        try:
            root.destroy()
        except tk.TclError:
            pass
        fixture.remove()

    observations = (
        _not_checked_observations()
        if skip_observations
        else _graphical_observations(case)
    )
    if observations is None:
        raise KeyboardInterrupt
    report = build_recovery_source_inspection_preparation_request_main_gui_visual_report(
        case,
        observations,
    )
    print(
        recovery_source_inspection_preparation_request_main_gui_visual_report_json(
            report
        ),
        flush=True,
    )
    return recovery_source_inspection_preparation_request_main_gui_observations_pass(
        observations
    )


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = _parser().parse_args(argv)
    try:
        for case_number in range(
            1,
            len(RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_MATRIX) + 1,
        ):
            if not _run_case(case_number, args.no_observations):
                print(
                    "The Stage 2.43 human matrix did not pass; "
                    "live apply remains blocked.",
                    file=sys.stderr,
                )
                return 2
    except (
        OSError,
        tk.TclError,
        RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError,
        _PreparationRequestMainGUIVisualLaunchError,
    ) as exc:
        print(
            "The Stage 2.43 guided visual matrix failed safely: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print("The Stage 2.43 guided visual matrix was cancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
