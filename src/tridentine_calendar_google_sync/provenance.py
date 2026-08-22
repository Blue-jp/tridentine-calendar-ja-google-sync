"""Deterministic hashes and public tool provenance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime

from tridentine_calendar_google_sync import __version__
from tridentine_calendar_google_sync.models import CanonicalSourceEvent

_CONTENT_HASH_DOMAIN = b"tridentine-calendar-google-sync:source-content:v1\x00"
_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:inspection-report:v1\x00"
_UNPARSED_HASH_DOMAIN = b"tridentine-calendar-google-sync:unparsed-source:v1\x00"


def tool_version() -> str:
    """Return the package version included in reports."""

    return __version__


def sha256_bytes(raw_bytes: bytes) -> str:
    """Return the lowercase SHA-256 digest of exact source bytes."""

    return hashlib.sha256(raw_bytes).hexdigest()


def _temporal_text(value: date | datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _event_hash_payload(event: CanonicalSourceEvent) -> dict[str, object]:
    """Build an internal exact payload; callers must never serialize it as a report."""

    return {
        "source_index": event.source_index,
        "uid": event.uid,
        "summary": event.summary,
        "description": event.description,
        "dtstart_present": event.dtstart_present,
        "start_date": _temporal_text(event.start_date),
        "start_datetime": _temporal_text(event.start_datetime),
        "all_day": event.all_day,
        "dtend_present": event.dtend_present,
        "explicit_end_date": _temporal_text(event.explicit_end_date),
        "explicit_end_datetime": _temporal_text(event.explicit_end_datetime),
        "effective_end_date": _temporal_text(event.effective_end_date),
        "effective_end_datetime": _temporal_text(event.effective_end_datetime),
        "dtstamp_present": event.dtstamp_present,
        "status_present": event.status_present,
        "status": event.status,
        "sequence_present": event.sequence_present,
        "sequence": event.sequence,
        "rrule_present": event.rrule_present,
        "rrule_values": list(event.rrule_values),
        "recurrence_id_present": event.recurrence_id_present,
        "recurrence_id_value": event.recurrence_id_value,
        "optional_property_names": list(event.optional_property_names),
        "event_x_property_names": list(event.event_x_property_names),
        "parser_issue_codes": list(event.parser_issue_codes),
    }


def canonical_content_hash(
    *,
    vcalendar_count: int,
    events: Sequence[CanonicalSourceEvent],
) -> str:
    """Hash exact canonical content without volatile timestamps or local paths."""

    payload = {
        "schema_version": "1.0",
        "vcalendar_count": vcalendar_count,
        "events": [_event_hash_payload(event) for event in events],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_CONTENT_HASH_DOMAIN + encoded).hexdigest()


def deterministic_report_hash(report_without_hash: Mapping[str, object]) -> str:
    """Hash a redacted report using stable JSON serialization."""

    encoded = json.dumps(
        report_without_hash,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest()


def unparsed_content_hash(*, raw_sha256: str, reason_code: str) -> str:
    """Return a deterministic placeholder hash when parsing is intentionally skipped."""

    encoded = f"{reason_code}\x00{raw_sha256}".encode("ascii", errors="strict")
    return hashlib.sha256(_UNPARSED_HASH_DOMAIN + encoded).hexdigest()


__all__ = [
    "canonical_content_hash",
    "deterministic_report_hash",
    "sha256_bytes",
    "tool_version",
    "unparsed_content_hash",
]
