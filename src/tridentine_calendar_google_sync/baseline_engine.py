"""Deterministic candidate construction and explicit baseline trust transition."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from tridentine_calendar_google_sync.baseline_models import (
    BaselineCandidate,
    BaselineState,
    TrustedBaseline,
)
from tridentine_calendar_google_sync.diff_models import CalendarDiff, DiffClassification
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.provenance import tool_version

_BASELINE_HASH_DOMAIN = b"tridentine-calendar-google-sync:trusted-baseline:v1\x00"


class BaselineError(ValueError):
    """Base baseline failure with content- and path-free public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class BaselineInputError(BaselineError):
    """Unsafe or unavailable local baseline input/output."""


class BaselineValidationError(BaselineError):
    """Malformed, unsupported, or tampered baseline content."""


class BaselineGuardError(BaselineError):
    """Candidate construction or state transition failed a fatal guard."""


class BaselineConfirmationError(BaselineError):
    """The exact explicit trust phrase was not supplied."""


def _hash_payload(
    *,
    state: BaselineState,
    version: str,
    target_fingerprint: str,
    source_profile: str,
    accepted_tag: str,
    accepted_commit: str,
    source_sha256: str,
    source_event_count: int,
    snapshot_content_hash: str,
    snapshot_event_count: int,
    diff_content_hash: str,
    managed_uids: tuple[str, ...],
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "state": state.value,
        "tool_version": version,
        "target_fingerprint": target_fingerprint,
        "source_profile": source_profile,
        "accepted_tag": accepted_tag,
        "accepted_commit": accepted_commit,
        "source_sha256": source_sha256,
        "source_event_count": source_event_count,
        "snapshot_content_hash": snapshot_content_hash,
        "snapshot_event_count": snapshot_event_count,
        "diff_content_hash": diff_content_hash,
        "managed_uid_count": len(managed_uids),
        "managed_uids": list(managed_uids),
    }


def _hash_mapping(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_BASELINE_HASH_DOMAIN + encoded).hexdigest()


def calculate_baseline_content_hash(baseline: TrustedBaseline) -> str:
    """Recalculate the exact domain-separated baseline hash."""

    return _hash_mapping(
        _hash_payload(
            state=baseline.state,
            version=baseline.tool_version,
            target_fingerprint=baseline.target_fingerprint,
            source_profile=baseline.source_profile,
            accepted_tag=baseline.accepted_tag,
            accepted_commit=baseline.accepted_commit,
            source_sha256=baseline.source_sha256,
            source_event_count=baseline.source_event_count,
            snapshot_content_hash=baseline.snapshot_content_hash,
            snapshot_event_count=baseline.snapshot_event_count,
            diff_content_hash=baseline.diff_content_hash,
            managed_uids=baseline.managed_uids,
        )
    )


def verify_baseline_content_hash(baseline: TrustedBaseline) -> None:
    """Reject a baseline whose content no longer matches its stored digest."""

    calculated = calculate_baseline_content_hash(baseline)
    if not hmac.compare_digest(calculated, baseline.baseline_content_hash):
        raise BaselineValidationError(
            "baseline_content_hash_mismatch",
            "baseline content hash verification failed",
        )


def _guard(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BaselineGuardError(code, message)


def _validate_candidate_inputs(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    diff: CalendarDiff,
) -> tuple[str, ...]:
    _guard(
        source.profile_id == profile.profile_id,
        "baseline_profile_mismatch",
        "source profile mismatch",
    )
    _guard(
        source.raw_sha256 == profile.html_sha256 and source.source_sha_matches,
        "baseline_source_hash_mismatch",
        "source hash does not match the accepted profile",
    )
    _guard(
        source.source_valid and not source.fatal and not source.findings,
        "baseline_source_invalid",
        "source validation is not exactly clean",
    )
    _guard(
        source.vevent_count == profile.expected.vevent_count == len(source.events),
        "baseline_source_count_mismatch",
        "source event count does not match the accepted profile",
    )
    _guard(snapshot.complete, "baseline_snapshot_incomplete", "snapshot is incomplete")
    _guard(
        snapshot.event_count == len(snapshot.events) == source.vevent_count,
        "baseline_snapshot_count_mismatch",
        "snapshot event count does not exactly match the source",
    )
    _guard(
        all(
            value == 0
            for value in (
                snapshot.cancelled_event_count,
                snapshot.unknown_event_type_count,
                snapshot.dropped_private_extended_property_count,
                snapshot.dropped_shared_extended_property_count,
                snapshot.forbidden_field_count,
            )
        ),
        "baseline_snapshot_guard_nonzero",
        "snapshot safety counters are not exactly zero",
    )
    _guard(
        diff.source_profile_id == profile.profile_id
        and diff.source_sha256 == source.raw_sha256
        and diff.source_sha_matches
        and diff.snapshot_sha256 == snapshot.content_hash
        and diff.target_fingerprint == snapshot.target_fingerprint,
        "baseline_diff_provenance_mismatch",
        "diff provenance does not match its source and snapshot",
    )
    _guard(
        diff.source_event_count == source.vevent_count
        and diff.google_event_count == snapshot.event_count
        and diff.snapshot_complete,
        "baseline_diff_count_mismatch",
        "diff counts do not match its source and snapshot",
    )
    _guard(not diff.fatal, "baseline_diff_fatal", "diff contains a fatal guard")
    non_unchanged = (
        diff.counts.add,
        diff.counts.update,
        diff.counts.delete_candidate,
        diff.counts.duplicate_source_uid,
        diff.counts.duplicate_google_icaluid,
        diff.counts.ambiguous,
        diff.counts.unmanaged_google_event,
        diff.counts.invalid_source,
        diff.counts.fatal_guard,
    )
    _guard(
        all(value == 0 for value in non_unchanged),
        "baseline_diff_not_exact",
        "diff classifications are not exactly unchanged",
    )
    _guard(
        diff.counts.unchanged == source.vevent_count == len(diff.events)
        and all(event.classification is DiffClassification.UNCHANGED for event in diff.events),
        "baseline_unchanged_count_mismatch",
        "unchanged diff count does not exactly match the source",
    )
    _guard(not diff.warnings, "baseline_diff_warning", "diff contains a warning")

    source_uids = tuple(event.uid for event in source.events if event.uid is not None)
    _guard(
        len(source_uids) == len(source.events),
        "baseline_source_uid_missing",
        "source contains an event without a UID",
    )
    managed_uids = tuple(sorted(set(source_uids)))
    _guard(
        len(managed_uids) == len(source_uids) == profile.expected.uid_unique_count,
        "baseline_source_uid_not_unique",
        "source UID inventory is not exactly unique",
    )
    return managed_uids


def _new_baseline(
    *,
    state: BaselineState,
    version: str,
    target_fingerprint: str,
    source_profile: str,
    accepted_tag: str,
    accepted_commit: str,
    source_sha256: str,
    source_event_count: int,
    snapshot_content_hash: str,
    snapshot_event_count: int,
    diff_content_hash: str,
    managed_uids: tuple[str, ...],
) -> TrustedBaseline:
    payload = _hash_payload(
        state=state,
        version=version,
        target_fingerprint=target_fingerprint,
        source_profile=source_profile,
        accepted_tag=accepted_tag,
        accepted_commit=accepted_commit,
        source_sha256=source_sha256,
        source_event_count=source_event_count,
        snapshot_content_hash=snapshot_content_hash,
        snapshot_event_count=snapshot_event_count,
        diff_content_hash=diff_content_hash,
        managed_uids=managed_uids,
    )
    return TrustedBaseline(
        schema_version="1.0",
        state=state,
        tool_version=version,
        target_fingerprint=target_fingerprint,
        source_profile=source_profile,
        accepted_tag=accepted_tag,
        accepted_commit=accepted_commit,
        source_sha256=source_sha256,
        source_event_count=source_event_count,
        snapshot_content_hash=snapshot_content_hash,
        snapshot_event_count=snapshot_event_count,
        diff_content_hash=diff_content_hash,
        managed_uid_count=len(managed_uids),
        managed_uids=managed_uids,
        baseline_content_hash=_hash_mapping(payload),
    )


def build_baseline_candidate(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    diff: CalendarDiff,
) -> BaselineCandidate:
    """Build a candidate only from an exact, zero-difference offline audit."""

    managed_uids = _validate_candidate_inputs(profile, source, snapshot, diff)
    return _new_baseline(
        state=BaselineState.CANDIDATE,
        version=tool_version(),
        target_fingerprint=snapshot.target_fingerprint,
        source_profile=profile.profile_id,
        accepted_tag=profile.accepted_tag,
        accepted_commit=profile.accepted_commit,
        source_sha256=source.raw_sha256,
        source_event_count=source.vevent_count,
        snapshot_content_hash=snapshot.content_hash,
        snapshot_event_count=snapshot.event_count,
        diff_content_hash=diff.content_hash,
        managed_uids=managed_uids,
    )


def baseline_confirmation_phrase(candidate: BaselineCandidate) -> str:
    """Return the exact phrase required for the candidate trust transition."""

    _guard(
        candidate.state is BaselineState.CANDIDATE,
        "baseline_not_candidate",
        "only a candidate baseline can be trusted",
    )
    verify_baseline_content_hash(candidate)
    return (
        f"TRUST BASELINE T-{candidate.target_fingerprint[:12]} "
        f"{candidate.baseline_content_hash[:12]}"
    )


def trust_baseline(
    candidate: BaselineCandidate,
    confirmation: str,
) -> TrustedBaseline:
    """Return a newly hashed trusted object after exact explicit confirmation."""

    expected = baseline_confirmation_phrase(candidate)
    if not hmac.compare_digest(
        confirmation.encode("utf-8", errors="strict"),
        expected.encode("utf-8", errors="strict"),
    ):
        raise BaselineConfirmationError(
            "baseline_confirmation_mismatch",
            "baseline trust confirmation did not exactly match",
        )
    return _new_baseline(
        state=BaselineState.TRUSTED,
        version=candidate.tool_version,
        target_fingerprint=candidate.target_fingerprint,
        source_profile=candidate.source_profile,
        accepted_tag=candidate.accepted_tag,
        accepted_commit=candidate.accepted_commit,
        source_sha256=candidate.source_sha256,
        source_event_count=candidate.source_event_count,
        snapshot_content_hash=candidate.snapshot_content_hash,
        snapshot_event_count=candidate.snapshot_event_count,
        diff_content_hash=candidate.diff_content_hash,
        managed_uids=candidate.managed_uids,
    )


def baseline_inspection_data(baseline: TrustedBaseline) -> dict[str, object]:
    """Build safe inspection data without raw UIDs or the full target fingerprint."""

    verify_baseline_content_hash(baseline)
    return {
        "schema_version": baseline.schema_version,
        "state": baseline.state.value,
        "tool_version": baseline.tool_version,
        "target_reference": f"T-{baseline.target_fingerprint[:12]}",
        "source_profile": baseline.source_profile,
        "accepted_tag": baseline.accepted_tag,
        "accepted_commit": baseline.accepted_commit,
        "source_sha256": baseline.source_sha256,
        "source_event_count": baseline.source_event_count,
        "snapshot_content_hash": baseline.snapshot_content_hash,
        "snapshot_event_count": baseline.snapshot_event_count,
        "diff_content_hash": baseline.diff_content_hash,
        "managed_uid_count": baseline.managed_uid_count,
        "baseline_content_hash": baseline.baseline_content_hash,
    }


def render_baseline_inspection_json(baseline: TrustedBaseline) -> str:
    """Render deterministic privacy-safe inspection JSON."""

    return (
        json.dumps(
            baseline_inspection_data(baseline),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_baseline_text(baseline: TrustedBaseline) -> str:
    """Render a compact privacy-safe baseline summary."""

    data = baseline_inspection_data(baseline)
    return "\n".join(f"{key}: {value}" for key, value in data.items()) + "\n"


__all__ = [
    "BaselineConfirmationError",
    "BaselineError",
    "BaselineGuardError",
    "BaselineInputError",
    "BaselineValidationError",
    "baseline_confirmation_phrase",
    "baseline_inspection_data",
    "build_baseline_candidate",
    "calculate_baseline_content_hash",
    "render_baseline_inspection_json",
    "render_baseline_text",
    "trust_baseline",
    "verify_baseline_content_hash",
]
