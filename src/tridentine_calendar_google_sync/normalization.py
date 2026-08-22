"""Transport decoding helpers with deliberately absent semantic normalization.

RFC line unfolding and iCalendar escape decoding are performed by
``icalendar`` before these helpers are called.  Phase 1 preserves the resulting
Unicode value exactly: it does not trim, collapse whitespace, normalize
Unicode, rewrite HTML, decode HTML entities, or rewrite URLs.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any


def transport_decoded_text(value: object) -> str:
    """Return the parser-decoded Unicode text without semantic normalization."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    return str(value)


def semantic_text_identity(value: str) -> str:
    """Return ``value`` unchanged; Phase 1 has no semantic normalization."""

    return value


def ical_value_text(value: Any) -> str:
    """Serialize a non-text iCalendar property for internal structural storage.

    This helper is used for recurrence metadata, not SUMMARY or DESCRIPTION.
    The third-party objects expose ``to_ical`` dynamically, so a narrow ``Any``
    boundary is intentional here.
    """

    to_ical = getattr(value, "to_ical", None)
    if callable(to_ical):
        encoded = to_ical()
        if isinstance(encoded, bytes):
            return encoded.decode("utf-8", errors="strict")
        return str(encoded)
    return transport_decoded_text(value)


def decoded_date_or_datetime(value: Any) -> date | datetime | None:
    """Extract the ``.dt`` payload exposed by an icalendar date property."""

    decoded = getattr(value, "dt", None)
    if isinstance(decoded, datetime):
        return decoded
    if isinstance(decoded, date):
        return decoded
    return None


__all__ = [
    "decoded_date_or_datetime",
    "ical_value_text",
    "semantic_text_identity",
    "transport_decoded_text",
]
