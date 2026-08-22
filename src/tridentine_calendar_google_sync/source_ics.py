"""Safe local byte loading and RFC-aware Accepted ICS parsing."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from icalendar import Calendar  # type: ignore[import-untyped]

from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    ParsedSourceCalendar,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.normalization import (
    decoded_date_or_datetime,
    ical_value_text,
    semantic_text_identity,
    transport_decoded_text,
)
from tridentine_calendar_google_sync.provenance import sha256_bytes
from tridentine_calendar_google_sync.safe_refs import safe_uid_ref
from tridentine_calendar_google_sync.validation import (
    unparsed_fatal_inspection,
    validate_source_events,
)

MAX_SOURCE_BYTES = 64 * 1024 * 1024

_OPTIONAL_PROPERTY_NAMES = frozenset(
    {
        "ATTACH",
        "ATTENDEE",
        "CATEGORIES",
        "CLASS",
        "COMMENT",
        "CONTACT",
        "CREATED",
        "GEO",
        "LAST-MODIFIED",
        "LOCATION",
        "ORGANIZER",
        "PRIORITY",
        "RELATED-TO",
        "REQUEST-STATUS",
        "RESOURCES",
        "TRANSP",
        "URL",
    }
)


class SourceInputError(ValueError):
    """A local source input error with privacy-safe public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class SourceParseError(ValueError):
    """A parser failure whose message never contains source content."""

    def __init__(self) -> None:
        super().__init__("source is not a well-formed iCalendar document")


@dataclass(frozen=True, slots=True)
class LoadedSourceBytes:
    """Bounded exact bytes and their pre-parse digest."""

    raw_bytes: bytes = field(repr=False)
    sha256: str
    sha256_matches_expected: bool | None
    size: int


def _reject_nonlocal_source_text(value: str) -> None:
    lowered = value.casefold()
    if "://" in value or lowered.startswith("file:") or value.startswith(("\\\\", "//")):
        raise SourceInputError("nonlocal_source", "source must be a local filesystem path")
    if "\x00" in value:
        raise SourceInputError("invalid_source_path", "source path is invalid")


def _checked_source_path(source: str | Path) -> Path:
    if isinstance(source, str):
        _reject_nonlocal_source_text(source)
    path = Path(source)
    try:
        if path.is_symlink():
            raise SourceInputError("source_symlink", "symbolic-link source files are not accepted")
        if not path.is_file():
            raise SourceInputError("source_not_file", "source is not a regular local file")
    except SourceInputError:
        raise
    except OSError as exc:
        raise SourceInputError("source_unavailable", "source file is unavailable") from exc
    return path


def load_source_bytes(
    source: str | Path,
    expected_sha256: str | None = None,
    *,
    max_size: int = MAX_SOURCE_BYTES,
) -> LoadedSourceBytes:
    """Read a bounded regular local file and hash its exact bytes before parsing.

    URL strings, ``file://`` strings, UNC paths, and source-file symlinks are
    rejected.  The file is never copied into the repository.  Errors contain
    neither the attempted path nor file content.
    """

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    path = _checked_source_path(source)
    try:
        with path.open("rb") as source_file:
            stat_result = os.fstat(source_file.fileno())
            if stat_result.st_size > max_size:
                raise SourceInputError("source_too_large", "source exceeds the size limit")
            raw_bytes = source_file.read(max_size + 1)
    except SourceInputError:
        raise
    except OSError as exc:
        raise SourceInputError("source_unavailable", "source file is unavailable") from exc
    if len(raw_bytes) > max_size:
        raise SourceInputError("source_too_large", "source exceeds the size limit")
    digest = sha256_bytes(raw_bytes)
    sha_matches = None if expected_sha256 is None else digest == expected_sha256
    return LoadedSourceBytes(
        raw_bytes=raw_bytes,
        sha256=digest,
        sha256_matches_expected=sha_matches,
        size=len(raw_bytes),
    )


def _validate_component_boundaries(raw_bytes: bytes) -> None:
    stack: list[bytes] = []
    for raw_line in raw_bytes.splitlines():
        if raw_line.startswith((b" ", b"\t")):
            continue
        upper_line = raw_line.upper()
        if upper_line.startswith(b"BEGIN:"):
            component_name = upper_line.removeprefix(b"BEGIN:")
            if not component_name:
                raise SourceParseError
            stack.append(component_name)
        elif upper_line.startswith(b"END:"):
            component_name = upper_line.removeprefix(b"END:")
            if not stack or stack.pop() != component_name:
                raise SourceParseError
    if stack:
        raise SourceParseError


def _property_values(component: Any, property_name: str) -> list[Any]:
    value = component.get(property_name)
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text_property(
    component: Any,
    property_name: str,
    issue_prefix: str,
    issues: list[str],
) -> str | None:
    values = _property_values(component, property_name)
    if not values:
        issues.append(f"missing_{issue_prefix}")
        return None
    if len(values) != 1:
        issues.append(f"multiple_{issue_prefix}")
    try:
        decoded = semantic_text_identity(transport_decoded_text(values[0]))
    except (UnicodeDecodeError, ValueError, TypeError):
        issues.append(f"invalid_{issue_prefix}")
        return None
    if decoded == "":
        issues.append(f"empty_{issue_prefix}")
    return decoded


def _date_property(
    component: Any,
    property_name: str,
    issue_prefix: str,
    issues: list[str],
) -> date | datetime | None:
    values = _property_values(component, property_name)
    if not values:
        if property_name == "DTSTART":
            issues.append("missing_dtstart")
        return None
    if len(values) != 1:
        issues.append(f"multiple_{issue_prefix}")
    decoded = decoded_date_or_datetime(values[0])
    if decoded is None:
        issues.append(f"invalid_{issue_prefix}")
    return decoded


def _recurrence_values(component: Any, issues: list[str]) -> tuple[str, ...]:
    values = _property_values(component, "RRULE")
    if len(values) > 1:
        issues.append("multiple_rrule")
    rendered: list[str] = []
    for value in values:
        try:
            rendered.append(ical_value_text(value))
        except (UnicodeDecodeError, ValueError, TypeError):
            issues.append("invalid_rrule")
    return tuple(rendered)


def _recurrence_id_value(component: Any, issues: list[str]) -> str | None:
    values = _property_values(component, "RECURRENCE-ID")
    if not values:
        return None
    if len(values) > 1:
        issues.append("multiple_recurrence_id")
    try:
        return ical_value_text(values[0])
    except (UnicodeDecodeError, ValueError, TypeError):
        issues.append("invalid_recurrence_id")
        return None


def _sequence_value(component: Any, issues: list[str]) -> int | None:
    values = _property_values(component, "SEQUENCE")
    if not values:
        return None
    if len(values) > 1:
        issues.append("multiple_sequence")
    try:
        return int(values[0])
    except (TypeError, ValueError):
        issues.append("invalid_sequence")
        return None


def _status_value(component: Any, issues: list[str]) -> str | None:
    values = _property_values(component, "STATUS")
    if not values:
        return None
    if len(values) > 1:
        issues.append("multiple_status")
    try:
        return transport_decoded_text(values[0])
    except (UnicodeDecodeError, ValueError, TypeError):
        issues.append("invalid_status")
        return None


def _property_names(component: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    optional: list[str] = []
    x_properties: list[str] = []
    for raw_name, raw_value in component.items():
        name = str(raw_name).upper()
        occurrence_count = len(raw_value) if isinstance(raw_value, list) else 1
        if name in _OPTIONAL_PROPERTY_NAMES:
            optional.extend([name] * occurrence_count)
        if name.startswith("X-"):
            x_properties.extend([name] * occurrence_count)
    return tuple(sorted(optional)), tuple(sorted(x_properties))


def _canonical_event(component: Any, source_index: int) -> CanonicalSourceEvent:
    issues: list[str] = []
    uid = _text_property(component, "UID", "uid", issues)
    summary = _text_property(component, "SUMMARY", "summary", issues)
    description = _text_property(component, "DESCRIPTION", "description", issues)
    start = _date_property(component, "DTSTART", "dtstart", issues)
    end = _date_property(component, "DTEND", "dtend", issues)

    start_date: date | None = None
    start_datetime: datetime | None = None
    explicit_end_date: date | None = None
    explicit_end_datetime: datetime | None = None
    effective_end_date: date | None = None
    effective_end_datetime: datetime | None = None

    if isinstance(start, datetime):
        start_datetime = start
    elif isinstance(start, date):
        start_date = start

    if isinstance(end, datetime):
        explicit_end_datetime = end
    elif isinstance(end, date):
        explicit_end_date = end

    dtend_present = bool(_property_values(component, "DTEND"))
    if start_date is not None:
        if not dtend_present:
            effective_end_date = start_date + timedelta(days=1)
        elif explicit_end_date is None:
            issues.append("mixed_dtend_type")
        else:
            effective_end_date = explicit_end_date
            if explicit_end_date <= start_date:
                issues.append("dtend_not_after_start")
    elif start_datetime is not None and dtend_present:
        if explicit_end_datetime is None:
            issues.append("mixed_dtend_type")
        else:
            effective_end_datetime = explicit_end_datetime
            try:
                if explicit_end_datetime <= start_datetime:
                    issues.append("dtend_not_after_start")
            except TypeError:
                issues.append("mixed_dtend_type")

    status_values = _property_values(component, "STATUS")
    sequence_values = _property_values(component, "SEQUENCE")
    rrule_values = _recurrence_values(component, issues)
    recurrence_id_values = _property_values(component, "RECURRENCE-ID")
    optional_names, x_property_names = _property_names(component)

    return CanonicalSourceEvent(
        source_index=source_index,
        uid=uid,
        safe_uid_reference=safe_uid_ref(uid) if uid is not None else None,
        summary=summary,
        description=description,
        dtstart_present=start is not None,
        start_date=start_date,
        start_datetime=start_datetime,
        all_day=start_date is not None,
        dtend_present=dtend_present,
        explicit_end_date=explicit_end_date,
        explicit_end_datetime=explicit_end_datetime,
        effective_end_date=effective_end_date,
        effective_end_datetime=effective_end_datetime,
        dtstamp_present=bool(_property_values(component, "DTSTAMP")),
        status_present=bool(status_values),
        status=_status_value(component, issues),
        sequence_present=bool(sequence_values),
        sequence=_sequence_value(component, issues),
        rrule_present=bool(rrule_values),
        rrule_values=rrule_values,
        recurrence_id_present=bool(recurrence_id_values),
        recurrence_id_value=_recurrence_id_value(component, issues),
        optional_property_names=optional_names,
        event_x_property_names=x_property_names,
        parser_issue_codes=tuple(sorted(set(issues))),
    )


def parse_source_bytes(raw_bytes: bytes) -> ParsedSourceCalendar:
    """Parse exact ICS bytes into canonical events using ``icalendar``.

    Parsing performs RFC transport decoding only.  Any exception is replaced by
    ``SourceParseError`` so parser diagnostics cannot echo source text.
    """

    try:
        _validate_component_boundaries(raw_bytes)
        parsed_value = Calendar.from_ical(raw_bytes, multiple=True)
        parsed_components = parsed_value if isinstance(parsed_value, list) else [parsed_value]
        calendars = [
            component
            for component in parsed_components
            if str(getattr(component, "name", "")).upper() == "VCALENDAR"
        ]
        if not calendars:
            raise SourceParseError
        raw_events = [component for calendar in calendars for component in calendar.walk("VEVENT")]
        events = tuple(
            _canonical_event(component, source_index)
            for source_index, component in enumerate(raw_events)
        )
        return ParsedSourceCalendar(
            vcalendar_count=len(calendars),
            vevent_count=len(raw_events),
            events=events,
        )
    except SourceParseError:
        raise
    except Exception as exc:
        raise SourceParseError from exc


def inspect_source(
    source: str | Path,
    profile: AcceptedSourceProfile,
) -> SourceCalendarInspection:
    """Load, hash, parse, aggregate, and strictly validate one local source file."""

    loaded = load_source_bytes(source, expected_sha256=profile.html_sha256)
    if loaded.sha256_matches_expected is not True:
        return unparsed_fatal_inspection(
            profile=profile,
            raw_sha256=loaded.sha256,
            source_sha_matches=False,
            code="source_sha256_mismatch",
            message="source SHA-256 does not match the accepted profile",
            field="sha256",
        )
    try:
        parsed = parse_source_bytes(loaded.raw_bytes)
    except SourceParseError:
        return unparsed_fatal_inspection(
            profile=profile,
            raw_sha256=loaded.sha256,
            source_sha_matches=True,
            code="malformed_ics",
            message="source is not a well-formed iCalendar document",
            field="calendar",
        )
    return validate_source_events(
        parsed=parsed,
        profile=profile,
        raw_sha256=loaded.sha256,
    )


__all__ = [
    "MAX_SOURCE_BYTES",
    "LoadedSourceBytes",
    "SourceInputError",
    "SourceParseError",
    "inspect_source",
    "load_source_bytes",
    "parse_source_bytes",
]
