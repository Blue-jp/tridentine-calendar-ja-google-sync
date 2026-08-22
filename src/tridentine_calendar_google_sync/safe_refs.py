"""Stable redacted references for values that must not appear in reports."""

from __future__ import annotations

import hashlib

_UID_REFERENCE_DOMAIN = b"tridentine-calendar-google-sync:uid-reference:v1\x00"
_GOOGLE_EVENT_REFERENCE_DOMAIN = b"tridentine-calendar-google-sync:google-event-reference:v1\x00"


def safe_uid_ref(uid: str) -> str:
    """Return a deterministic non-reversible display reference for an exact UID.

    The domain separator prevents this digest prefix from being confused with
    hashes produced for reports, canonical content, or future Google objects.
    No trimming or Unicode normalization is applied to ``uid``.
    """

    digest = hashlib.sha256(_UID_REFERENCE_DOMAIN + uid.encode("utf-8")).hexdigest()
    return f"U-{digest[:12]}"


def safe_google_event_ref(event_id: str) -> str:
    """Return a deterministic display reference for an opaque Google event ID."""

    digest = hashlib.sha256(_GOOGLE_EVENT_REFERENCE_DOMAIN + event_id.encode("utf-8")).hexdigest()
    return f"G-{digest[:12]}"


__all__ = ["safe_google_event_ref", "safe_uid_ref"]
