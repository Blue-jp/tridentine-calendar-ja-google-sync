"""Strict canonical loading of safe JSON synchronization plan reports."""

from __future__ import annotations

import hmac
import json
from datetime import date
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.diff_models import DiffCounts
from tridentine_calendar_google_sync.plan_engine import (
    PlanError,
    verify_sync_plan_content_hash,
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
    SafeGoogleReference,
    SyncPlan,
)
from tridentine_calendar_google_sync.plan_report import render_plan_json_report
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    read_sensitive_bytes,
)

MAX_SYNC_PLAN_REPORT_BYTES = 64 * 1024 * 1024


class PlanReportError(PlanError):
    """A plan report path, structure, canonical form, or hash is invalid."""


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _closed_object(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise TypeError
    return cast(dict[str, Any], value)


def _optional_date(value: object) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError
    return date.fromisoformat(value)


def _source_provenance(value: object) -> PlanSourceProvenance:
    data = _closed_object(
        value,
        {
            "profile_id",
            "accepted_tag",
            "accepted_commit",
            "source_sha256",
            "source_content_hash",
            "event_count",
            "first_date",
            "last_date",
        },
    )
    return PlanSourceProvenance(
        profile_id=data["profile_id"],
        accepted_tag=data["accepted_tag"],
        accepted_commit=data["accepted_commit"],
        source_sha256=data["source_sha256"],
        source_content_hash=data["source_content_hash"],
        event_count=data["event_count"],
        first_date=_optional_date(data["first_date"]),
        last_date=_optional_date(data["last_date"]),
    )


def _baseline_provenance(
    value: object,
    *,
    target_fingerprint: str,
) -> BaselinePlanProvenance:
    data = _closed_object(
        value,
        {
            "schema_version",
            "baseline_content_hash",
            "target_reference",
            "snapshot_content_hash",
            "managed_uid_count",
            "source",
        },
    )
    if data["target_reference"] != f"T-{target_fingerprint[:12]}":
        raise ValueError
    return BaselinePlanProvenance(
        schema_version=data["schema_version"],
        baseline_content_hash=data["baseline_content_hash"],
        target_fingerprint=target_fingerprint,
        snapshot_content_hash=data["snapshot_content_hash"],
        managed_uid_count=data["managed_uid_count"],
        source=_source_provenance(data["source"]),
    )


def _diff_summary(value: object) -> DiffSummary:
    data = _closed_object(
        value,
        {
            "counts",
            "changed_fields",
            "source_event_count",
            "google_event_count",
            "warning_count",
            "fatal_event_count",
            "proposed_action_count",
            "fatal",
            "has_changes",
            "has_ambiguous",
            "diff_content_hash",
        },
    )
    counts = DiffCounts.model_validate(data["counts"], strict=True)
    changed_fields = ChangedFieldCounts.model_validate(data["changed_fields"], strict=True)
    return DiffSummary(
        counts=counts,
        changed_fields=changed_fields,
        source_event_count=data["source_event_count"],
        google_event_count=data["google_event_count"],
        warning_count=data["warning_count"],
        fatal_event_count=data["fatal_event_count"],
        proposed_action_count=data["proposed_action_count"],
        fatal=data["fatal"],
        has_changes=data["has_changes"],
        has_ambiguous=data["has_ambiguous"],
        diff_content_hash=data["diff_content_hash"],
    )


def _plan_action(value: object) -> PlanAction:
    data = _closed_object(
        value,
        {
            "action",
            "source_ref",
            "google_refs",
            "source_date",
            "google_date",
            "changed_fields",
            "ownership_evidence",
            "finding_codes",
            "destructive",
            "separate_approval_required",
        },
    )
    for key in ("google_refs", "changed_fields", "ownership_evidence", "finding_codes"):
        if not isinstance(data[key], list):
            raise TypeError
    return PlanAction(
        action=PlanActionKind(data["action"]),
        source_ref=data["source_ref"],
        google_refs=cast(tuple[SafeGoogleReference, ...], tuple(data["google_refs"])),
        source_date=_optional_date(data["source_date"]),
        google_date=_optional_date(data["google_date"]),
        changed_fields=cast(tuple[ChangedFieldName, ...], tuple(data["changed_fields"])),
        ownership_evidence=cast(tuple[OwnershipEvidence, ...], tuple(data["ownership_evidence"])),
        finding_codes=cast(tuple[FindingCode, ...], tuple(data["finding_codes"])),
        destructive=data["destructive"],
        separate_approval_required=data["separate_approval_required"],
    )


def _plan_guard(value: object) -> PlanGuard:
    data = _closed_object(
        value,
        {"severity", "code", "message", "observed_count", "limit"},
    )
    return PlanGuard.model_validate(data, strict=True)


def _parse_sync_plan_document(value: object) -> SyncPlan:
    data = _closed_object(
        value,
        {
            "schema_version",
            "plan_type",
            "tool_version",
            "state",
            "executable",
            "approval_required",
            "baseline",
            "current_source",
            "target_fingerprint",
            "snapshot_content_hash",
            "diff_summary",
            "thresholds",
            "proposed_actions",
            "safety_guards",
            "plan_content_hash",
        },
    )
    raw_actions = data["proposed_actions"]
    raw_guards = data["safety_guards"]
    if not isinstance(raw_actions, list) or not isinstance(raw_guards, list):
        raise TypeError
    target_fingerprint = data["target_fingerprint"]
    if not isinstance(target_fingerprint, str):
        raise TypeError
    plan = SyncPlan(
        schema_version=data["schema_version"],
        plan_type=data["plan_type"],
        tool_version=data["tool_version"],
        state=PlanState(data["state"]),
        executable=data["executable"],
        approval_required=data["approval_required"],
        baseline=_baseline_provenance(
            data["baseline"],
            target_fingerprint=target_fingerprint,
        ),
        current_source=_source_provenance(data["current_source"]),
        target_fingerprint=target_fingerprint,
        snapshot_content_hash=data["snapshot_content_hash"],
        diff_summary=_diff_summary(data["diff_summary"]),
        thresholds=PlanThresholds.model_validate(data["thresholds"], strict=True),
        proposed_actions=tuple(_plan_action(item) for item in raw_actions),
        safety_guards=tuple(_plan_guard(item) for item in raw_guards),
        plan_content_hash=data["plan_content_hash"],
    )
    verify_sync_plan_content_hash(plan)
    return plan


def parse_sync_plan_report_bytes(raw_bytes: bytes) -> SyncPlan:
    """Parse, integrity-check, and require exact canonical plan-report bytes."""

    if len(raw_bytes) > MAX_SYNC_PLAN_REPORT_BYTES:
        raise PlanReportError("plan_report_too_large", "sync plan report is too large")
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        plan = _parse_sync_plan_document(value)
        canonical = render_plan_json_report(plan).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return plan
    except PlanReportError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
        PlanError,
    ) as exc:
        raise PlanReportError(
            "invalid_sync_plan_report",
            "sync plan report is invalid or noncanonical",
        ) from exc


def load_sync_plan_report(path: str | Path) -> SyncPlan:
    """Load one repository-external canonical JSON plan report."""

    try:
        return parse_sync_plan_report_bytes(
            read_sensitive_bytes(path, max_size=MAX_SYNC_PLAN_REPORT_BYTES)
        )
    except PlanReportError:
        raise
    except SensitivePathError as exc:
        raise PlanReportError(
            "unsafe_sync_plan_report_path",
            "sync plan report path is unsafe or unavailable",
        ) from exc


__all__ = [
    "MAX_SYNC_PLAN_REPORT_BYTES",
    "PlanReportError",
    "load_sync_plan_report",
    "parse_sync_plan_report_bytes",
]
