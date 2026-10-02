"""Output-encoding helpers.

Every attacker-controlled (log-derived) value rendered in HTML must pass
through escape_html. Every value exported to CSV must pass through csv_safe
to neutralize spreadsheet formula injection.
"""
from __future__ import annotations

from html import escape

_FORMULA_PREFIXES = ("=", "+", "-", "@")


def escape_html(value: object) -> str:
    """HTML-encode an untrusted value for safe rendering."""
    return escape("" if value is None else str(value), quote=True)


def csv_safe(value: object) -> str:
    """Neutralize CSV formula injection (=, +, -, @ and control-char prefixes)."""
    s = "" if value is None else str(value)
    if s.startswith(_FORMULA_PREFIXES):
        return "'" + s
    return s
