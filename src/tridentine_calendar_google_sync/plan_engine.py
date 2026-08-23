"""Trusted-baseline ownership and deterministic non-executable plan construction."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import date
from typing import cast

from tridentine_calendar_google_sync.baseline_engine import verify_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import (
    CalendarDiff,
    DiffClassification,
    ManagedScope,
)
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.plan_models import (
    BaselinePlanProvenance,
    ChangedFieldCounts,
    ChangedFieldName,
    DiffSummary,
    FindingCode,
    OwnershipEvidence,
    PlanAction,
    PlanActionKind,
    PlanGuard,
    PlanSourceProvenance,
    PlanState,
    PlanThresholds,
    SyncPlan,
)
from tridentine_calendar_google_sync.provenance import tool_version

_PLAN_HASH_DOMAIN = b"tridentine-calendar-google-sync:non-executable-plan:v1\x00"
_FIELD_ORDER = {
    name: index for index, name in enumerate(("summary", "description", "start_date", "end_date"))
}
_ACTION_ORDER = {
    PlanActionKind.ADD: 0,
    PlanActionKind.UPDATE: 1,
    PlanActionKind.DELETE_CANDIDATE: 2,
}


class PlanError(ValueError):
    """A content- and identifier-free planning failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class PlanInputError(PlanError):
    """Input objects cannot safely produce any plan."""


def _reject_untrusted_baseline(baseline: TrustedBaseline) -> None:
    if not isinstance(baseline, TrustedBaseline):
        raise PlanInputError(
            "trusted_baseline_required",
            "a trusted baseline is required",
        )
    if baseline.schema_version != "1.0":
        raise PlanInputError(
            "unsupported_baseline_schema",
            "trusted baseline schema is unsupported",
        )
    if baseline.state is not BaselineState.TRUSTED:
        raise PlanInputError(
            "baseline_not_trusted",
            "a trusted baseline is required",
        )
    verify_baseline_content_hash(baseline)
    if baseline.managed_uid_count == 0 or not baseline.managed_uids:
        raise PlanInputError(
            "trusted_baseline_empty",
            "trusted baseline UID inventory is empty",
        )


def baseline_to_managed_scope(baseline: TrustedBaseline) -> ManagedScope:
    """Convert only a verified trusted baseline into isolated ownership evidence."""

    _reject_untrusted_baseline(baseline)
    return ManagedScope(trusted_baseline_uids=frozenset(baseline.managed_uids))


def diff_with_trusted_baseline(
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    baseline: TrustedBaseline,
) -> CalendarDiff:
    """Diff with baseline ownership after strict state/hash/target guards."""

    scope = baseline_to_managed_scope(baseline)
    if not hmac.compare_digest(snapshot.target_fingerprint, baseline.target_fingerprint):
        raise PlanInputError(
            "baseline_target_mismatch",
            "snapshot target does not match the trusted baseline",
        )
    return diff_source_to_snapshot(source, snapshot, scope)


def summarize_diff(diff: CalendarDiff) -> DiffSummary:
    """Return a redacted aggregate without retaining the EventDiff array."""

    changed = {
        name: sum(
            difference.field == name for event in diff.events for difference in event.differences
        )
        for name in _FIELD_ORDER
    }
    proposed_count = diff.counts.add + diff.counts.update + diff.counts.delete_candidate
    return DiffSummary(
        counts=diff.counts,
        changed_fields=ChangedFieldCounts(**changed),
        source_event_count=diff.source_event_count,
        google_event_count=diff.google_event_count,
        warning_count=len(diff.warnings),
        fatal_event_count=sum(event.fatal for event in diff.events),
        proposed_action_count=proposed_count,
        fatal=diff.fatal,
        has_changes=diff.has_changes,
        has_ambiguous=diff.has_ambiguous,
        diff_content_hash=diff.content_hash,
    )


def _baseline_source_provenance(baseline: TrustedBaseline) -> PlanSourceProvenance:
    return PlanSourceProvenance(
        profile_id=baseline.source_profile,
        accepted_tag=baseline.accepted_tag,
        accepted_commit=baseline.accepted_commit,
        source_sha256=baseline.source_sha256,
        source_content_hash=None,
        event_count=baseline.source_event_count,
        first_date=None,
        last_date=None,
    )


def _current_source_provenance(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> PlanSourceProvenance:
    return PlanSourceProvenance(
        profile_id=profile.profile_id,
        accepted_tag=profile.accepted_tag,
        accepted_commit=profile.accepted_commit,
        source_sha256=source.raw_sha256,
        source_content_hash=source.content_hash,
        event_count=source.vevent_count,
        first_date=source.first_date,
        last_date=source.last_date,
    )


def _baseline_provenance(baseline: TrustedBaseline) -> BaselinePlanProvenance:
    return BaselinePlanProvenance(
        schema_version=baseline.schema_version,
        baseline_content_hash=baseline.baseline_content_hash,
        target_fingerprint=baseline.target_fingerprint,
        snapshot_content_hash=baseline.snapshot_content_hash,
        managed_uid_count=baseline.managed_uid_count,
        source=_baseline_source_provenance(baseline),
    )


def _validate_current_inputs(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    diff: CalendarDiff,
) -> None:
    valid = (
        profile.profile_id == source.profile_id == diff.source_profile_id
        and source.raw_sha256 == diff.source_sha256
        and source.source_sha_matches == diff.source_sha_matches
        and snapshot.content_hash == diff.snapshot_sha256
        and snapshot.target_fingerprint == diff.target_fingerprint
        and snapshot.event_count == diff.google_event_count
        and source.vevent_count == diff.source_event_count
        and snapshot.complete == diff.snapshot_complete
    )
    if not valid:
        raise PlanInputError(
            "plan_input_provenance_mismatch",
            "plan inputs do not share identical provenance",
        )


def _action_from_event(event: object) -> PlanAction | None:
    from tridentine_calendar_google_sync.diff_models import EventDiff

    if not isinstance(event, EventDiff):
        raise PlanInputError("invalid_diff_event", "diff event is invalid")
    if event.classification is DiffClassification.ADD:
        action = PlanActionKind.ADD
        destructive = False
        separate_approval = False
    elif event.classification is DiffClassification.UPDATE:
        action = PlanActionKind.UPDATE
        destructive = False
        separate_approval = False
    elif event.classification is DiffClassification.DELETE_CANDIDATE:
        action = PlanActionKind.DELETE_CANDIDATE
        destructive = True
        separate_approval = True
    else:
        return None
    changed_fields = cast(
        tuple[ChangedFieldName, ...],
        tuple(
            sorted(
                {difference.field for difference in event.differences},
                key=_FIELD_ORDER.__getitem__,
            )
        ),
    )
    finding_codes = cast(
        tuple[FindingCode, ...],
        tuple(sorted(set((*event.reason_codes, *event.warnings)))),
    )
    ownership_evidence = cast(
        tuple[OwnershipEvidence, ...],
        tuple(sorted(event.ownership_evidence)),
    )
    return PlanAction(
        action=action,
        source_ref=event.source_ref,
        google_refs=tuple(sorted(event.google_refs)),
        source_date=event.source_date,
        google_date=event.google_date,
        changed_fields=changed_fields,
        ownership_evidence=ownership_evidence,
        finding_codes=finding_codes,
        destructive=destructive,
        separate_approval_required=separate_approval,
    )


def _action_sort_key(action: PlanAction) -> tuple[int, date, str, tuple[str, ...]]:
    return (
        _ACTION_ORDER[action.action],
        action.source_date or action.google_date or date.max,
        action.source_ref or "",
        action.google_refs,
    )


def _guard(
    code: str,
    message: str,
    *,
    observed_count: int | None = None,
    limit: int | None = None,
    severity: str = "fatal",
) -> PlanGuard:
    return PlanGuard(
        severity="fatal" if severity == "fatal" else "warning",
        code=code,
        message=message,
        observed_count=observed_count,
        limit=limit,
    )


def _build_guards(
    summary: DiffSummary,
    actions: tuple[PlanAction, ...],
    thresholds: PlanThresholds,
) -> tuple[PlanGuard, ...]:
    counts = summary.counts
    guards: list[PlanGuard] = []
    if summary.source_event_count == 0:
        guards.append(_guard("zero_source_event_count", "source event count is zero"))
    if summary.google_event_count == 0:
        guards.append(_guard("zero_google_event_count", "Google event count is zero"))
    total_classified = sum(
        counts.for_classification(classification) for classification in DiffClassification
    )
    if total_classified == 0:
        guards.append(_guard("zero_diff_event_count", "diff contains no classified events"))
    if summary.source_event_count > 0 and counts.add == summary.source_event_count:
        guards.append(_guard("all_events_add", "all source events are classified as add"))
    if summary.source_event_count > 0 and counts.update == summary.source_event_count:
        guards.append(_guard("all_events_update", "all source events are classified as update"))
    if summary.google_event_count > 0 and counts.delete_candidate == summary.google_event_count:
        guards.append(
            _guard("all_events_delete_candidate", "all Google events are delete candidates")
        )
    guarded_counts = (
        ("ambiguous_events_present", counts.ambiguous, "ambiguous events are present"),
        (
            "duplicate_source_uid_present",
            counts.duplicate_source_uid,
            "duplicate source UIDs are present",
        ),
        (
            "duplicate_google_icaluid_present",
            counts.duplicate_google_icaluid,
            "duplicate Google iCalUIDs are present",
        ),
        ("invalid_source_present", counts.invalid_source, "invalid source events are present"),
        ("fatal_guard_present", counts.fatal_guard, "fatal diff guards are present"),
        (
            "unmanaged_google_event_present",
            counts.unmanaged_google_event,
            "unmanaged Google events are present",
        ),
    )
    guards.extend(
        _guard(code, message, observed_count=count)
        for code, count, message in guarded_counts
        if count > 0
    )
    if summary.fatal:
        guards.append(_guard("diff_marked_fatal", "diff is marked fatal"))
    threshold_values = (
        ("add_threshold_exceeded", counts.add, thresholds.max_add, "add threshold exceeded"),
        (
            "update_threshold_exceeded",
            counts.update,
            thresholds.max_update,
            "update threshold exceeded",
        ),
        (
            "delete_threshold_exceeded",
            counts.delete_candidate,
            thresholds.max_delete,
            "delete threshold exceeded",
        ),
    )
    guards.extend(
        _guard(code, message, observed_count=count, limit=limit)
        for code, count, limit, message in threshold_values
        if count > limit
    )
    changed_count = counts.add + counts.update + counts.delete_candidate
    exceeds_percent = (
        summary.source_event_count > 0 and changed_count * 100 > summary.source_event_count
    )
    if changed_count > 50 or exceeds_percent:
        guards.append(
            _guard(
                "mass_change_guard",
                "changed event count exceeds the hard mass-change limit",
                observed_count=changed_count,
                limit=50,
            )
        )
    delete_actions = [
        action for action in actions if action.action is PlanActionKind.DELETE_CANDIDATE
    ]
    if any("trusted_baseline" not in action.ownership_evidence for action in delete_actions):
        guards.append(
            _guard(
                "delete_missing_trusted_baseline",
                "delete candidate lacks trusted baseline ownership evidence",
                observed_count=len(delete_actions),
            )
        )
    if delete_actions:
        guards.append(
            _guard(
                "delete_requires_separate_approval",
                "delete candidates always require separate explicit approval",
                observed_count=len(delete_actions),
                severity="warning",
            )
        )
    return tuple(
        sorted(
            guards,
            key=lambda guard: (
                0 if guard.severity == "fatal" else 1,
                guard.code,
                guard.observed_count if guard.observed_count is not None else -1,
                guard.limit if guard.limit is not None else -1,
            ),
        )
    )


def _hash_mapping(data: Mapping[str, object]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_PLAN_HASH_DOMAIN + encoded).hexdigest()


def _plan_hash_data(
    *,
    state: PlanState,
    baseline: BaselinePlanProvenance,
    current_source: PlanSourceProvenance,
    target_fingerprint: str,
    snapshot_content_hash: str,
    summary: DiffSummary,
    thresholds: PlanThresholds,
    actions: tuple[PlanAction, ...],
    guards: tuple[PlanGuard, ...],
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "plan_type": "non-executable-sync-plan-v1",
        "tool_version": tool_version(),
        "state": state.value,
        "executable": False,
        "approval_required": state is not PlanState.DRAFT,
        "baseline": baseline.model_dump(mode="json"),
        "current_source": current_source.model_dump(mode="json"),
        "target_fingerprint": target_fingerprint,
        "snapshot_content_hash": snapshot_content_hash,
        "diff_summary": summary.model_dump(mode="json"),
        "thresholds": thresholds.model_dump(mode="json"),
        "proposed_actions": [action.model_dump(mode="json") for action in actions],
        "safety_guards": [guard.model_dump(mode="json") for guard in guards],
    }


def calculate_sync_plan_content_hash(plan: SyncPlan) -> str:
    """Recalculate the exact deterministic plan hash."""

    hash_data = _plan_hash_data(
        state=plan.state,
        baseline=plan.baseline,
        current_source=plan.current_source,
        target_fingerprint=plan.target_fingerprint,
        snapshot_content_hash=plan.snapshot_content_hash,
        summary=plan.diff_summary,
        thresholds=plan.thresholds,
        actions=plan.proposed_actions,
        guards=plan.safety_guards,
    )
    return _hash_mapping(hash_data)


def verify_sync_plan_content_hash(plan: SyncPlan) -> None:
    """Reject a plan whose stored digest no longer matches its content."""

    if not hmac.compare_digest(
        calculate_sync_plan_content_hash(plan),
        plan.plan_content_hash,
    ):
        raise PlanInputError(
            "sync_plan_content_hash_mismatch",
            "sync plan content hash verification failed",
        )


def build_sync_plan(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    baseline: TrustedBaseline,
    *,
    thresholds: PlanThresholds | None = None,
    diff: CalendarDiff | None = None,
) -> SyncPlan:
    """Build a deterministic plan that is structurally incapable of execution."""

    expected_diff = diff_with_trusted_baseline(source, snapshot, baseline)
    if diff is not None and not hmac.compare_digest(diff.content_hash, expected_diff.content_hash):
        raise PlanInputError(
            "plan_diff_mismatch",
            "provided diff does not match trusted-baseline inputs",
        )
    resolved_diff = expected_diff if diff is None else diff
    _validate_current_inputs(profile, source, snapshot, resolved_diff)
    resolved_thresholds = thresholds or PlanThresholds()
    actions = tuple(
        sorted(
            filter(
                None,
                (_action_from_event(event) for event in resolved_diff.events),
            ),
            key=_action_sort_key,
        )
    )
    summary = summarize_diff(resolved_diff)
    guards = _build_guards(summary, actions, resolved_thresholds)
    if any(guard.severity == "fatal" for guard in guards):
        state = PlanState.BLOCKED
    elif actions:
        state = PlanState.REVIEW_REQUIRED
    else:
        state = PlanState.DRAFT
    baseline_provenance = _baseline_provenance(baseline)
    current_provenance = _current_source_provenance(profile, source)
    hash_data = _plan_hash_data(
        state=state,
        baseline=baseline_provenance,
        current_source=current_provenance,
        target_fingerprint=snapshot.target_fingerprint,
        snapshot_content_hash=snapshot.content_hash,
        summary=summary,
        thresholds=resolved_thresholds,
        actions=actions,
        guards=guards,
    )
    return SyncPlan(
        schema_version="1.0",
        plan_type="non-executable-sync-plan-v1",
        tool_version=tool_version(),
        state=state,
        executable=False,
        approval_required=state is not PlanState.DRAFT,
        baseline=baseline_provenance,
        current_source=current_provenance,
        target_fingerprint=snapshot.target_fingerprint,
        snapshot_content_hash=snapshot.content_hash,
        diff_summary=summary,
        thresholds=resolved_thresholds,
        proposed_actions=actions,
        safety_guards=guards,
        plan_content_hash=_hash_mapping(hash_data),
    )


__all__ = [
    "PlanError",
    "PlanInputError",
    "baseline_to_managed_scope",
    "build_sync_plan",
    "calculate_sync_plan_content_hash",
    "diff_with_trusted_baseline",
    "summarize_diff",
    "verify_sync_plan_content_hash",
]
