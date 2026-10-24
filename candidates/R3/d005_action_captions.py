"""Word-preserving wrap for one existing action caption.

The caller owns the existing Button and ScrollableRegion.  This controller
changes only wraplength; it never rewrites text/font/commands or focus.  Native
input/window-manager acceptance is deliberately outside this layout helper.
"""
from __future__ import annotations

import tkinter as tk


class CaptionLayoutError(RuntimeError):
    pass


def _pixels(widget, option):
    return int(widget.winfo_pixels(widget.cget(option)))


def text_budget(button):
    """Available text pixels after actual per-side padding and focus borders."""
    inset = sum(_pixels(button, option) for option in
                ('padx', 'borderwidth', 'highlightthickness'))
    return int(button.winfo_width()) - 2 * inset - 4


def measured_longest_word(button):
    words = str(button.cget('text')).split()
    if not words:
        raise CaptionLayoutError('Action caption is empty')
    font = button.cget('font')
    widths = [int(button.tk.call('font', 'measure', font,
                                '-displayof', str(button), word)) for word in words]
    if min(widths) <= 0:
        raise CaptionLayoutError('Action caption font metrics are invalid')
    return max(widths)


class ActionCaptionReflow:
    """One owned idle callback and widget-local bindings; deterministic teardown."""

    def __init__(self, button, *, viewport, on_error=None):
        self.button, self.viewport, self.on_error = button, viewport, on_error
        self.after_id = None
        self.closed = False
        self.failure = None
        self.layout_count = 0
        self.bindings = []
        try:
            for event in ('<Configure>', '<Map>'):
                self.bindings.append((event, button.bind(event, self.request, add='+')))
            self.bindings.append(('<Destroy>', button.bind('<Destroy>', self.destroyed, add='+')))
            self.request()
        except Exception:
            self.close()
            raise

    def request(self, _event=None):
        if not self.closed and self.after_id is None:
            self.after_id = self.button.after_idle(self._scheduled)

    def _scheduled(self):
        self.after_id = None
        if self.closed:
            return
        try:
            self.reflow()
        except Exception as error:
            self.failure = error
            self.close()
            if self.on_error is None:
                raise
            self.on_error(error)

    def reflow(self):
        if self.closed or not self.button.winfo_exists():
            return
        if int(self.button.winfo_width()) <= 1:
            return  # Construction before Map/Configure is not a measured width.
        wrap = text_budget(self.button)
        if wrap < measured_longest_word(self.button):
            raise CaptionLayoutError('Available action width cannot hold a whole word')
        if int(self.button.cget('wraplength')) == wrap:
            return
        self.viewport._begin_relayout()
        try:
            self.button.configure(wraplength=wrap)
            self.layout_count += 1
        finally:
            self.viewport._schedule_viewport_restore()

    def destroyed(self, event):
        if getattr(event, 'widget', None) is self.button:
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.after_id is not None:
            try:
                self.button.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None
        for event, identifier in self.bindings:
            if identifier:
                try:
                    self.button.unbind(event, identifier)
                except tk.TclError:
                    pass
        self.bindings.clear()
