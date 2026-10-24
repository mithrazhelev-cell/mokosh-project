import inspect
import unittest
from types import SimpleNamespace
from unittest import mock

import mokosh_profile_ui as ui


WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo "
    "lima mike november oscar papa quebec romeo sierra tango uniform "
    "victor whiskey xray yankee"
)
VALID_PASSWORD = "fifteen chars ok"


class ProfileUIValidationTests(unittest.TestCase):
    def validate(self, **changes):
        values = {
            "record_path": "/synthetic/record.mokr",
            "source_mode": "words",
            "sheet_path": "",
            "words": WORDS,
            "new_password": VALID_PASSWORD,
            "confirmation": VALID_PASSWORD,
        }
        values.update(changes)
        return ui.validate_password_recovery_form(**values)

    def assert_issue(self, issue, **changes):
        finding = self.validate(**changes)
        self.assertIsNotNone(finding)
        self.assertIs(finding.issue, issue)
        self.assertNotIn(VALID_PASSWORD, repr(finding))
        return finding

    def test_complete_manual_and_sheet_forms_are_valid(self):
        self.assertIsNone(self.validate())
        self.assertIsNone(
            self.validate(
                source_mode="sheet",
                sheet_path="/synthetic/phrase.txt",
                words="",
            )
        )

    def test_each_missing_input_has_a_distinct_result_and_focus_target(self):
        cases = (
            (ui.RecoveryFormIssue.MISSING_RECORD, {"record_path": ""}),
            (
                ui.RecoveryFormIssue.INVALID_SOURCE_MODE,
                {"source_mode": "invalid"},
            ),
            (
                ui.RecoveryFormIssue.MISSING_SHEET,
                {"source_mode": "sheet", "sheet_path": ""},
            ),
            (ui.RecoveryFormIssue.MISSING_WORDS, {"words": ""}),
            (
                ui.RecoveryFormIssue.MISSING_NEW_PASSWORD,
                {"new_password": ""},
            ),
            (
                ui.RecoveryFormIssue.MISSING_CONFIRMATION,
                {"confirmation": ""},
            ),
        )
        keys = set()
        focuses = set()
        for expected, changes in cases:
            with self.subTest(expected=expected):
                finding = self.assert_issue(expected, **changes)
                keys.add(finding.message_key)
                focuses.add(finding.focus_target)
        self.assertEqual(len(keys), len(cases))
        self.assertGreaterEqual(len(focuses), 5)

    def test_manual_phrase_counts_are_independent_and_exact(self):
        for count in (1, 24, 26):
            with self.subTest(count=count):
                finding = self.assert_issue(
                    ui.RecoveryFormIssue.WORD_COUNT,
                    words=" ".join("word" for _ in range(count)),
                )
                self.assertEqual(finding.word_count, count)
        self.assertIsNone(ui.validate_paper_phrase("  " + WORDS + "\n"))

    def test_case_punctuation_non_ascii_and_large_phrase_are_specific(self):
        cases = (
            WORDS.replace("alpha", "Alpha"),
            WORDS.replace("alpha", "alpha,"),
            WORDS.replace("alpha", "дума"),
        )
        for words in cases:
            with self.subTest(words=words[:10]):
                self.assert_issue(ui.RecoveryFormIssue.WORD_FORMAT, words=words)
        finding = self.validate(words="a" * 513)
        self.assertIs(finding.issue, ui.RecoveryFormIssue.WORD_TEXT_TOO_LONG)

    def test_password_boundaries_spaces_unicode_and_nfc_are_exact(self):
        fourteen = "x" * 14
        fifteen = "x" * 15
        max_bytes = "x" * 1024
        too_many_bytes = "x" * 1025
        self.assert_issue(
            ui.RecoveryFormIssue.PASSWORD_TOO_SHORT,
            new_password=fourteen,
            confirmation=fourteen,
        )
        self.assertIsNone(
            self.validate(new_password=fifteen, confirmation=fifteen)
        )
        self.assertIsNone(
            self.validate(new_password=max_bytes, confirmation=max_bytes)
        )
        self.assert_issue(
            ui.RecoveryFormIssue.PASSWORD_TOO_LONG,
            new_password=too_many_bytes,
            confirmation=too_many_bytes,
        )
        spaced = "  exactly spaced  "
        self.assertIsNone(
            self.validate(new_password=spaced, confirmation=spaced)
        )
        unicode_password = "🔐" * 15
        self.assertIsNone(
            self.validate(
                new_password=unicode_password,
                confirmation=unicode_password,
            )
        )
        self.assertIsNone(
            self.validate(
                new_password="e\N{COMBINING ACUTE ACCENT}" * 15,
                confirmation="é" * 15,
            )
        )

    def test_password_mismatch_has_its_own_message(self):
        finding = self.assert_issue(
            ui.RecoveryFormIssue.PASSWORD_MISMATCH,
            confirmation="different password value",
        )
        self.assertEqual(
            finding.message_key,
            "password_recovery_password_mismatch",
        )
        self.assertEqual(finding.focus_target, "confirmation")


class ProfileUILayoutTests(unittest.TestCase):
    def test_wraplength_is_bounded_and_reacts_to_width(self):
        self.assertEqual(ui.responsive_wraplength("bad"), 180)
        self.assertEqual(ui.responsive_wraplength(100), 180)
        self.assertEqual(ui.responsive_wraplength(640), 600)
        self.assertEqual(ui.responsive_wraplength(4000), 1040)

    def test_responsive_label_measures_its_own_actual_width(self):
        bindings = {}

        class Label:
            def __init__(self, parent, **options):
                self.parent = parent
                self.options = options

            def bind(self, name, callback, **_options):
                bindings[name] = callback

            def configure(self, **options):
                self.options.update(options)

        parent = SimpleNamespace(
            bind=mock.Mock(
                side_effect=AssertionError(
                    "responsive labels must not measure the padded parent"
                )
            )
        )
        with mock.patch.object(ui.tk, "Label", Label):
            label = ui.create_responsive_label(
                parent,
                text="Synthetic responsive warning",
                horizontal_inset=40,
            )

        self.assertIn("<Configure>", bindings)
        bindings["<Configure>"](SimpleNamespace(width=620))
        self.assertEqual(label.options["wraplength"], 580)
        parent.bind.assert_not_called()

    def test_common_window_contract_enables_resize_and_escape_close(self):
        events = []
        bindings = {}
        window = SimpleNamespace(
            geometry=lambda value: events.append(("geometry", value)),
            minsize=lambda *value: events.append(("minsize", value)),
            resizable=lambda *value: events.append(("resizable", value)),
            protocol=lambda *value: events.append(("protocol", value[0])),
            bind=lambda name, callback, **_options: bindings.setdefault(
                name, callback
            ),
        )
        closed = []
        ui.configure_resizable_window(
            window,
            geometry="700x500",
            minimum=(500, 400),
            close=lambda: closed.append(True),
        )
        self.assertIn(("resizable", (True, True)), events)
        self.assertIn(("protocol", "WM_DELETE_WINDOW"), events)
        self.assertEqual(bindings["<Escape>"](object()), "break")
        self.assertEqual(closed, [True])

    def test_scroll_chrome_is_not_in_tab_order_and_page_keys_still_scroll(self):
        created = {}

        class Widget:
            def __init__(self, parent=None, **options):
                self.parent = parent
                self.options = options
                self.bindings = {}

            def pack(self, **_options):
                return None

            def bind(self, name, callback, **_options):
                self.bindings[name] = callback

            def configure(self, **options):
                self.options.update(options)

        class Frame(Widget):
            pass

        class Canvas(Widget):
            def __init__(self, parent=None, **options):
                super().__init__(parent, **options)
                self.scrolls = []
                created["canvas"] = self

            def create_window(self, *_args, **_options):
                return 1

            def itemconfigure(self, *_args, **_options):
                return None

            def bbox(self, *_args):
                return (0, 0, 100, 200)

            def yview(self, *_args):
                return None

            def yview_scroll(self, units, kind):
                self.scrolls.append((units, kind))

            def yview_moveto(self, _fraction):
                return None

        class Scrollbar(Widget):
            def __init__(self, parent=None, **options):
                super().__init__(parent, **options)
                created["scrollbar"] = self

            def set(self, *_args):
                return None

        window = Widget()
        with (
            mock.patch.object(ui.tk, "Frame", Frame),
            mock.patch.object(ui.tk, "Canvas", Canvas),
            mock.patch.object(ui.tk, "Scrollbar", Scrollbar),
        ):
            ui.create_scrollable_region(window)

        self.assertIs(created["canvas"].options["takefocus"], False)
        self.assertIs(created["scrollbar"].options["takefocus"], False)
        self.assertIn("<Prior>", window.bindings)
        self.assertIn("<Next>", window.bindings)
        self.assertIn("<FocusIn>", window.bindings)
        self.assertEqual(
            window.bindings["<Next>"](SimpleNamespace(widget=object())),
            "break",
        )
        self.assertEqual(created["canvas"].scrolls[-1], (1, "pages"))

    def test_focus_reveal_is_idle_minimal_and_limited_to_descendants(self):
        class Canvas:
            def __init__(self):
                self.movements = []
                self.cancelled = []
                self.callbacks = {}
                self.next_after = 0
                self.focused = None

            def after_idle(self, callback):
                self.next_after += 1
                identifier = f"after-{self.next_after}"
                self.callbacks[identifier] = callback
                return identifier

            def after_cancel(self, identifier):
                self.cancelled.append(identifier)
                self.callbacks.pop(identifier, None)

            def run_idle(self):
                callbacks = tuple(self.callbacks.values())
                self.callbacks.clear()
                for callback in callbacks:
                    callback()

            def focus_get(self):
                return self.focused

            def bbox(self, _item):
                return (0, 0, 100, 200)

            def yview(self):
                return (0.0, 0.5)

            def yview_moveto(self, fraction):
                self.movements.append(fraction)

            def winfo_rooty(self):
                return 100

            def winfo_height(self):
                return 100

        class Widget:
            def __init__(self, master, root_y, height=20):
                self.master = master
                self.root_y = root_y
                self.height = height

            def focus_get(self):
                return canvas.focused

            def winfo_exists(self):
                return True

            def winfo_ismapped(self):
                return True

            def winfo_rooty(self):
                return self.root_y

            def winfo_height(self):
                return self.height

        canvas = Canvas()
        content = object()
        region = ui.ScrollableRegion(object(), canvas, content, object(), 1)

        offscreen = Widget(content, 230)
        canvas.focused = offscreen
        region.focus_in(SimpleNamespace(widget=offscreen))
        self.assertEqual(len(canvas.callbacks), 1)
        canvas.run_idle()
        self.assertEqual(canvas.movements, [0.25])
        self.assertIs(region.last_focus_widget, offscreen)

        intermediate = Widget(content, 120)
        region.focus_in(SimpleNamespace(widget=intermediate))
        region.focus_in(SimpleNamespace(widget=offscreen))
        self.assertEqual(len(canvas.callbacks), 1)
        self.assertEqual(canvas.cancelled, ["after-2"])
        canvas.run_idle()
        self.assertEqual(
            canvas.movements,
            [0.25],
            "window reactivation must not reveal the same stable focus target",
        )
        self.assertIs(region.last_focus_widget, offscreen)

        visible = Widget(content, 130)
        canvas.focused = visible
        region.focus_in(SimpleNamespace(widget=visible))
        canvas.run_idle()
        self.assertEqual(canvas.movements, [0.25])
        self.assertIs(region.last_focus_widget, visible)

        next_offscreen = Widget(content, 230)
        canvas.focused = next_offscreen
        region.focus_in(SimpleNamespace(widget=next_offscreen))
        canvas.run_idle()
        self.assertEqual(canvas.movements, [0.25, 0.25])
        self.assertIs(region.last_focus_widget, next_offscreen)

        unrelated = Widget(object(), 230)
        canvas.focused = unrelated
        region.focus_in(SimpleNamespace(widget=unrelated))
        self.assertEqual(canvas.callbacks, {})
        self.assertEqual(canvas.movements, [0.25, 0.25])
        self.assertIs(region.last_focus_widget, next_offscreen)

    def test_responsive_grid_changes_between_three_two_and_one_columns(self):
        class Container:
            def __init__(self):
                self.bindings = {}
                self.columns = {}

            def bind(self, name, callback, **_options):
                self.bindings[name] = callback

            def grid_columnconfigure(self, column, **options):
                self.columns[column] = options

        class Widget:
            def __init__(self):
                self.positions = []

            def grid_forget(self):
                return None

            def grid(self, **options):
                self.positions.append(options)

        container = Container()
        widgets = [Widget() for _ in range(6)]
        grid = ui.ResponsiveGrid(
            container,
            widgets,
            column_rules=((700, 3), (460, 2), (0, 1)),
        )
        self.assertEqual(grid.columns, 1)
        container.bindings["<Configure>"](SimpleNamespace(width=520))
        self.assertEqual(grid.columns, 2)
        self.assertEqual(widgets[2].positions[-1]["row"], 1)
        self.assertEqual(widgets[2].positions[-1]["column"], 0)
        container.bindings["<Configure>"](SimpleNamespace(width=900))
        self.assertEqual(grid.columns, 3)
        self.assertEqual(widgets[5].positions[-1]["row"], 1)
        self.assertEqual(widgets[5].positions[-1]["column"], 2)

    def test_responsive_pair_stacks_before_controls_can_be_clipped(self):
        class Container:
            def __init__(self):
                self.bindings = {}
                self.columns = {}

            def bind(self, name, callback, **_options):
                self.bindings[name] = callback

            def grid_columnconfigure(self, column, **options):
                self.columns[column] = options

        class Widget:
            def __init__(self):
                self.positions = []

            def grid_forget(self):
                return None

            def grid(self, **options):
                self.positions.append(options)

        container = Container()
        primary = Widget()
        controls = Widget()
        pair = ui.ResponsivePair(
            container,
            primary,
            controls,
            breakpoint=760,
        )
        self.assertTrue(pair.stacked)
        self.assertEqual(controls.positions[-1]["row"], 1)
        self.assertEqual(controls.positions[-1]["column"], 0)
        self.assertEqual(controls.positions[-1]["sticky"], "ew")

        container.bindings["<Configure>"](SimpleNamespace(width=820))
        self.assertFalse(pair.stacked)
        self.assertEqual(primary.positions[-1]["row"], 0)
        self.assertEqual(controls.positions[-1]["row"], 0)
        self.assertEqual(controls.positions[-1]["column"], 1)
        self.assertEqual(container.columns[0]["weight"], 1)

        container.bindings["<Configure>"](SimpleNamespace(width=620))
        self.assertTrue(pair.stacked)
        self.assertEqual(controls.positions[-1]["row"], 1)
        self.assertEqual(controls.positions[-1]["column"], 0)

    def test_responsive_pair_rejects_invalid_breakpoint_and_layout(self):
        container = SimpleNamespace(
            bind=lambda *_args, **_kwargs: None,
            grid_columnconfigure=lambda *_args, **_kwargs: None,
        )
        widget = SimpleNamespace(
            grid_forget=lambda: None,
            grid=lambda **_values: None,
        )
        for breakpoint in (0, True, 1.5):
            with self.subTest(breakpoint=breakpoint):
                with self.assertRaises(ValueError):
                    ui.ResponsivePair(
                        container,
                        widget,
                        widget,
                        breakpoint=breakpoint,
                    )
        pair = ui.ResponsivePair(container, widget, widget)
        with self.assertRaises(ValueError):
            pair.relayout(1)
        with self.assertRaises(ValueError):
            ui.ResponsivePair(
                container,
                widget,
                widget,
                fit_requested_widths=1,
            )

    def test_responsive_pair_uses_real_requested_widths_when_enabled(self):
        class Container:
            def __init__(self):
                self.bindings = {}

            def bind(self, name, callback, **_options):
                self.bindings[name] = callback

            def grid_columnconfigure(self, *_args, **_options):
                return None

        class Widget:
            def __init__(self, requested_width):
                self.requested_width = requested_width

            def winfo_reqwidth(self):
                return self.requested_width

            def grid_forget(self):
                return None

            def grid(self, **_options):
                return None

        container = Container()
        primary = Widget(400)
        controls = Widget(389)
        pair = ui.ResponsivePair(
            container,
            primary,
            controls,
            breakpoint=760,
            padx=5,
            fit_requested_widths=True,
        )

        self.assertFalse(pair.stacked_for_width(820))
        self.assertTrue(pair.stacked_for_width(800))
        self.assertTrue(pair.stacked_for_width(759))

    def test_action_dialog_releases_grab_when_minimized_and_restores_it(self):
        callbacks = []
        events = []
        dialog = ui.ActionDialog.__new__(ui.ActionDialog)
        dialog._closed = False
        dialog._grab_active = True
        dialog._default_index = 1
        dialog.buttons = [mock.Mock(), mock.Mock()]
        dialog.window = SimpleNamespace(
            grab_release=lambda: events.append("release"),
            after_idle=lambda callback: callbacks.append(callback),
            winfo_exists=lambda: True,
            winfo_viewable=lambda: True,
            grab_set=lambda: events.append("grab"),
        )
        dialog._on_unmap(SimpleNamespace(widget=dialog.window))
        self.assertEqual(events, ["release"])
        self.assertFalse(dialog._grab_active)
        dialog._on_map(SimpleNamespace(widget=dialog.window))
        self.assertEqual(len(callbacks), 1)
        callbacks.pop()()
        self.assertEqual(events, ["release", "grab"])
        self.assertTrue(dialog._grab_active)
        dialog.buttons[1].focus_set.assert_called_once_with()

    def test_action_dialog_layout_reserves_a_non_shrinking_action_row(self):
        source = inspect.getsource(ui.ActionDialog.__init__)
        self.assertIn("body.grid_rowconfigure(0, weight=1)", source)
        self.assertIn("body.grid_columnconfigure(0, weight=1)", source)
        self.assertIn("text_frame.grid(row=0, column=0, sticky=\"nsew\")", source)
        self.assertIn("buttons.grid(row=1, column=0, sticky=\"ew\"", source)

    def test_action_dialog_close_restores_parent_after_destroy(self):
        callbacks = []
        events = []
        parent = SimpleNamespace(
            after_idle=lambda callback: callbacks.append(callback),
            winfo_exists=lambda: True,
            deiconify=lambda: events.append("deiconify"),
            lift=lambda: events.append("lift"),
            focus_force=lambda: events.append("focus"),
        )
        dialog = ui.ActionDialog.__new__(ui.ActionDialog)
        dialog.parent = parent
        dialog._closed = False
        dialog._grab_active = True
        dialog.window = SimpleNamespace(
            grab_release=lambda: events.append("release"),
            destroy=lambda: events.append("destroy"),
        )

        dialog.close()

        self.assertEqual(events, ["release", "destroy"])
        self.assertEqual(len(callbacks), 1)
        callbacks.pop()()
        self.assertEqual(
            events,
            ["release", "destroy", "deiconify", "lift", "focus"],
        )

    def test_destructive_decision_uses_cancel_as_keyboard_default(self):
        source = (__import__("pathlib").Path(ui.__file__)).read_text(encoding="utf-8")
        self.assertIn("default_index=1", source)
        self.assertNotIn("messagebox", source)
        self.assertNotIn(".transient(", source)


if __name__ == "__main__":
    unittest.main()
