"""Deterministic redacted reports for non-executable synchronization plans."""

from __future__ import annotations

import json

from tridentine_calendar_google_sync.diff_models import CLASSIFICATION_ORDER
from tridentine_calendar_google_sync.plan_engine import verify_sync_plan_content_hash
from tridentine_calendar_google_sync.plan_models import (
    PlanAction,
    PlanSourceProvenance,
    SyncPlan,
)


def _source_data(source: PlanSourceProvenance) -> dict[str, object]:
    return {
        "profile_id": source.profile_id,
        "accepted_tag": source.accepted_tag,
        "accepted_commit": source.accepted_commit,
        "source_sha256": source.source_sha256,
        "source_content_hash": source.source_content_hash,
        "event_count": source.event_count,
        "first_date": source.first_date.isoformat() if source.first_date else None,
        "last_date": source.last_date.isoformat() if source.last_date else None,
    }


def _action_data(action: PlanAction) -> dict[str, object]:
    return {
        "action": action.action.value,
        "source_ref": action.source_ref,
        "google_refs": list(action.google_refs),
        "source_date": action.source_date.isoformat() if action.source_date else None,
        "google_date": action.google_date.isoformat() if action.google_date else None,
        "changed_fields": list(action.changed_fields),
        "ownership_evidence": list(action.ownership_evidence),
        "finding_codes": list(action.finding_codes),
        "destructive": action.destructive,
        "separate_approval_required": action.separate_approval_required,
    }


def build_plan_json_report(plan: SyncPlan) -> dict[str, object]:
    """Build a closed redacted document with no raw identity or request body."""

    verify_sync_plan_content_hash(plan)
    summary = plan.diff_summary
    return {
        "schema_version": plan.schema_version,
        "plan_type": plan.plan_type,
        "tool_version": plan.tool_version,
        "state": plan.state.value,
        "executable": False,
        "approval_required": plan.approval_required,
        "baseline": {
            "schema_version": plan.baseline.schema_version,
            "baseline_content_hash": plan.baseline.baseline_content_hash,
            "target_reference": f"T-{plan.baseline.target_fingerprint[:12]}",
            "snapshot_content_hash": plan.baseline.snapshot_content_hash,
            "managed_uid_count": plan.baseline.managed_uid_count,
            "source": _source_data(plan.baseline.source),
        },
        "current_source": _source_data(plan.current_source),
        "target_fingerprint": plan.target_fingerprint,
        "snapshot_content_hash": plan.snapshot_content_hash,
        "diff_summary": {
            "counts": {
                classification.value: summary.counts.for_classification(classification)
                for classification in CLASSIFICATION_ORDER
            },
            "changed_fields": summary.changed_fields.model_dump(mode="json"),
            "source_event_count": summary.source_event_count,
            "google_event_count": summary.google_event_count,
            "warning_count": summary.warning_count,
            "fatal_event_count": summary.fatal_event_count,
            "proposed_action_count": summary.proposed_action_count,
            "fatal": summary.fatal,
            "has_changes": summary.has_changes,
            "has_ambiguous": summary.has_ambiguous,
            "diff_content_hash": summary.diff_content_hash,
        },
        "thresholds": plan.thresholds.model_dump(mode="json"),
        "proposed_actions": [_action_data(action) for action in plan.proposed_actions],
        "safety_guards": [guard.model_dump(mode="json") for guard in plan.safety_guards],
        "plan_content_hash": plan.plan_content_hash,
    }


def render_plan_json_report(plan: SyncPlan) -> str:
    """Render stable UTF-8 JSON with a final newline."""

    return (
        json.dumps(
            build_plan_json_report(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_plan_text_report(plan: SyncPlan) -> str:
    """Render a compact safe report suitable for human review."""

    verify_sync_plan_content_hash(plan)
    summary = plan.diff_summary
    lines = [
        "Non-executable Google Calendar synchronization plan",
        f"tool version: {plan.tool_version}",
        f"state: {plan.state.value}",
        "executable: no",
        f"approval required: {'yes' if plan.approval_required else 'no'}",
        f"target reference: T-{plan.target_fingerprint[:12]}",
        f"baseline hash: {plan.baseline.baseline_content_hash}",
        f"baseline accepted tag: {plan.baseline.source.accepted_tag}",
        f"current accepted tag: {plan.current_source.accepted_tag}",
        f"snapshot content hash: {plan.snapshot_content_hash}",
        f"diff content hash: {summary.diff_content_hash}",
    ]
    lines.extend(
        f"{classification.value}: {summary.counts.for_classification(classification)}"
        for classification in CLASSIFICATION_ORDER
    )
    lines.extend(
        (
            f"changed field summary: {summary.changed_fields.summary}",
            f"changed field description: {summary.changed_fields.description}",
            f"changed field start_date: {summary.changed_fields.start_date}",
            f"changed field end_date: {summary.changed_fields.end_date}",
            f"max add: {plan.thresholds.max_add}",
            f"max update: {plan.thresholds.max_update}",
            f"max delete: {plan.thresholds.max_delete}",
            f"action count: {len(plan.proposed_actions)}",
            f"guard count: {len(plan.safety_guards)}",
        )
    )
    if plan.proposed_actions:
        lines.append("actions:")
        for action in plan.proposed_actions:
            references = ",".join(
                value for value in (action.source_ref, *action.google_refs) if value
            )
            fields = ",".join(action.changed_fields)
            evidence = ",".join(action.ownership_evidence)
            details = "; ".join(
                value
                for value in (
                    f"refs={references}" if references else "",
                    f"fields={fields}" if fields else "",
                    f"ownership={evidence}" if evidence else "",
                    "destructive=yes" if action.destructive else "destructive=no",
                    "separate-approval=yes"
                    if action.separate_approval_required
                    else "separate-approval=no",
                )
                if value
            )
            lines.append(f"- {action.action.value} ({details})")
    if plan.safety_guards:
        lines.append("guards:")
        lines.extend(
            f"- {guard.severity} {guard.code}: {guard.message}" for guard in plan.safety_guards
        )
    lines.append(f"plan content hash: {plan.plan_content_hash}")
    return "\n".join(lines) + "\n"


__all__ = [
    "build_plan_json_report",
    "render_plan_json_report",
    "render_plan_text_report",
]
