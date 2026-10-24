"""Measured reflow for the six synthetic state buttons, without action changes.

Only the supplied existing widgets are laid out. No font, text, command, focus,
bindings for input, root geometry, worker, file or cryptographic state is changed.
The existing ScrollableRegion keeps its own viewport policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk


STATES = ('ready', 'working', 'cleanable', 'blocked', 'published', 'not_v2')
_reporter = None


class LabelLayoutError(RuntimeError):
    pass


def set_reporter(reporter):
    global _reporter
    _reporter = reporter


def report(event, **fields):
    if _reporter is not None:
        _reporter(event, **fields)


@dataclass(frozen=True)
class LayoutPlan:
    columns: int
    rows: int
    text_widths: tuple[int, ...]
    minimum_cell: int


def plan_layout(width, longest_words, insets, *, gap=6, maximum_columns=3):
    """Use the real longest-word widths; never force a word into a smaller cell."""
    if type(width) is not int or width <= 0 or len(longest_words) != 6 or len(insets) != 6:
        raise LabelLayoutError('Invalid state-label geometry inventory')
    if any(type(v) is not int or v <= 0 for v in longest_words) or any(
            type(v) is not int or v < 0 for v in insets):
        raise LabelLayoutError('Invalid state-label font or inset measurements')
    minimum = max(word + 2 * inset + gap + 4 for word, inset in zip(longest_words, insets))
    if width < minimum:
        raise LabelLayoutError('Available width cannot hold one complete state-label word')
    columns = next(n for n in range(maximum_columns, 0, -1) if width // n >= minimum)
    widths = tuple(width // columns - gap - 2 * inset - 4 for inset in insets)
    return LayoutPlan(columns, (6 + columns - 1) // columns, widths, minimum)


def _pixels(widget, option):
    return int(widget.winfo_pixels(widget.cget(option)))


def _inset(widget):
    return sum(_pixels(widget, name) for name in ('padx', 'borderwidth', 'highlightthickness'))


def longest_word(widget, text=None):
    text = str(widget.cget('text')) if text is None else text
    words = text.split()
    if not words:
        raise LabelLayoutError('Empty state-label text')
    font = widget.cget('font')
    widths = [int(widget.tk.call('font', 'measure', font, '-displayof', str(widget), word))
              for word in words]
    if any(width <= 0 for width in widths):
        raise LabelLayoutError('State-label word metrics are invalid')
    return max(widths)


class StateLabelReflow:
    """One coalesced idle relayout, owned bindings and deterministic teardown."""
    def __init__(self, container, buttons, *, heading, displayed, viewport, on_error):
        if tuple(buttons) != STATES:
            raise LabelLayoutError('State-button order/inventory differs')
        self.container = container
        self.buttons = tuple(buttons.values())
        self.heading, self.displayed = heading, displayed
        self.viewport, self.on_error = viewport, on_error
        self.after_id = None
        self.closed = False
        self.failure = None
        self.last_plan = None
        self.layout_count = 0
        self.bindings = []
        try:
            for widget in (container, *self.buttons, heading, displayed):
                self.bindings.append((widget, '<Configure>', widget.bind('<Configure>', self.request, add='+')))
            self.bindings.append((container, '<Map>', container.bind('<Map>', self.request, add='+')))
            self.bindings.append((container, '<Destroy>', container.bind('<Destroy>', self.destroyed, add='+')))
            self.request()
        except Exception:
            self.close()
            raise

    def request(self, event=None):
        if not self.closed and self.after_id is None:
            self.after_id = self.container.after_idle(self._scheduled)

    def _scheduled(self):
        self.after_id = None
        if self.closed:
            return
        try:
            self.reflow()
        except Exception as error:
            self.failure = error
            self.close()
            report('STATE_LABEL_LAYOUT_FAILED', error_type=type(error).__name__)
            self.on_error(error)

    def reflow(self):
        if self.closed or not self.container.winfo_exists():
            return
        outer_width = int(self.container.winfo_width())
        if outer_width <= 1:
            return  # Initial withdrawn construction; Map/Configure will schedule.
        width = outer_width - 2 * _inset(self.container)
        words = tuple(longest_word(button) for button in self.buttons)
        insets = tuple(_inset(button) for button in self.buttons)
        plan = plan_layout(width, words, insets)
        signature = (plan, width, _inset(self.displayed))
        if signature == self.last_plan:
            return
        self.viewport._begin_relayout()
        try:
            for column in range(3):
                self.container.grid_columnconfigure(column, weight=1 if column < plan.columns else 0,
                    minsize=0, uniform='mokosh-state-labels' if column < plan.columns else '')
            self.heading.grid_configure(columnspan=plan.columns)
            for index, (button, wrap) in enumerate(zip(self.buttons, plan.text_widths)):
                button.configure(wraplength=wrap)
                button.grid_configure(row=1 + index // plan.columns, column=index % plan.columns)
            self.displayed.grid_configure(row=plan.rows + 1, column=0, columnspan=plan.columns)
            self.displayed.configure(wraplength=max(1, width - 2 * _inset(self.displayed) - 4))
            self.last_plan = signature
            self.layout_count += 1
        finally:
            self.viewport._schedule_viewport_restore()
        report('STATE_LABEL_LAYOUT_MEASURED', columns=plan.columns, rows=plan.rows,
               available_pixels=width, minimum_cell_pixels=plan.minimum_cell,
               longest_word_pixels=list(words), wrap_pixels=list(plan.text_widths),
               font_sizes_changed=False, labels_changed=False, actions_changed=False,
               physical_acceptance='PENDING_REQUIRED')

    def destroyed(self, event):
        if getattr(event, 'widget', None) is self.container:
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.after_id is not None:
            try:
                self.container.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None
        for widget, sequence, identifier in self.bindings:
            if identifier:
                try:
                    widget.unbind(sequence, identifier)
                except tk.TclError:
                    pass
        self.bindings.clear()
