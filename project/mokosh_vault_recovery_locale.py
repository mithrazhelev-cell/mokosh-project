"""Leaf locale identity for bounded MOKOSH recovery contracts.

This module intentionally depends only on the Python standard-library enum
type.  Importing a non-secret recovery entry contract must not transitively
load Vault storage, reconciliation, workflow, GUI, or cryptographic backends.
"""

from __future__ import annotations

from enum import Enum as _Enum


class RecoveryLocalizationLocale(str, _Enum):
    """Exact supported recovery locale identifiers."""

    BULGARIAN_BULGARIA = "bg-BG"
    ENGLISH_UNITED_KINGDOM = "en-GB"


__all__ = ("RecoveryLocalizationLocale",)
