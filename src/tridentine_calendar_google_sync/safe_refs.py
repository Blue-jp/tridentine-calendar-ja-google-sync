"""Stable redacted references for values that must not appear in reports."""

from __future__ import annotations

import hashlib

_UID_REFERENCE_DOMAIN = b"tridentine-calendar-google-sync:uid-reference:v1\x00"


def safe_uid_ref(uid: str) -> str:
    """Return a deterministic non-reversible display reference for an exact UID.

    The domain separator prevents this digest prefix from being confused with
    hashes produced for reports, canonical content, or future Google objects.
    No trimming or Unicode normalization is applied to ``uid``.
    """

    digest = hashlib.sha256(_UID_REFERENCE_DOMAIN + uid.encode("utf-8")).hexdigest()
    return f"U-{digest[:12]}"


__all__ = ["safe_uid_ref"]
