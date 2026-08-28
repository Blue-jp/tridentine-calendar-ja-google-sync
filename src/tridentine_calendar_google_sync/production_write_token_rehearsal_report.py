"""Deterministic redacted Phase 6D.0 rehearsal snapshot and reports."""

from __future__ import annotations

import hashlib
import hmac
import json

from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenRehearsalEventEvidence,
    ProductionWriteTokenRehearsalReport,
    ProductionWriteTokenRehearsalSnapshot,
)

_SNAPSHOT_EVIDENCE_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-rehearsal-snapshot:v1\x00"
)
_REPORT_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-rehearsal-report:v1\x00"
)
_EVENT_EVIDENCE_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-rehearsal-event:v1\x00"
)


class ProductionWriteTokenRehearsalReportError(ValueError):
    """Content-free report integrity or binding failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash(domain: bytes, data: dict[str, object]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def calculate_production_write_token_rehearsal_snapshot_hash(
    snapshot: ProductionWriteTokenRehearsalSnapshot,
) -> str:
    data = snapshot.model_dump(mode="json")
    del data["snapshot_evidence_hash"]
    return _hash(_SNAPSHOT_EVIDENCE_HASH_DOMAIN, data)


def build_production_write_token_rehearsal_event_evidence(
    event: CanonicalGoogleEvent,
) -> ProductionWriteTokenRehearsalEventEvidence:
    """Cover one managed event without persisting raw identity or content."""

    if event.safe_ical_uid_reference is None:
        raise ProductionWriteTokenRehearsalReportError(
            "production_rehearsal_event_evidence_invalid",
            "Production rehearsal event evidence cannot be created",
        )
    managed_data: dict[str, object] = {
        "safe_event_ref": event.safe_event_reference,
        "safe_uid_ref": event.safe_ical_uid_reference,
        "summary": event.summary,
        "description": event.description,
        "start": event.start.model_dump(mode="json") if event.start is not None else None,
        "end": event.end.model_dump(mode="json") if event.end is not None else None,
        "all_day": event.all_day,
        "status": event.status,
        "event_type": event.event_type,
        "recurrence": list(event.recurrence),
    }
    return ProductionWriteTokenRehearsalEventEvidence(
        safe_event_ref=event.safe_event_reference,
        safe_uid_ref=event.safe_ical_uid_reference,
        managed_content_hash=_hash(_EVENT_EVIDENCE_HASH_DOMAIN, managed_data),
    )


def finalize_production_write_token_rehearsal_snapshot(
    snapshot: ProductionWriteTokenRehearsalSnapshot,
) -> ProductionWriteTokenRehearsalSnapshot:
    return snapshot.model_copy(
        update={
            "snapshot_evidence_hash": calculate_production_write_token_rehearsal_snapshot_hash(
                snapshot
            )
        }
    )


def verify_production_write_token_rehearsal_snapshot(
    snapshot: ProductionWriteTokenRehearsalSnapshot,
) -> None:
    if not hmac.compare_digest(
        calculate_production_write_token_rehearsal_snapshot_hash(snapshot),
        snapshot.snapshot_evidence_hash,
    ):
        raise ProductionWriteTokenRehearsalReportError(
            "production_rehearsal_snapshot_hash_mismatch",
            "Production rehearsal snapshot evidence integrity verification failed",
        )


def calculate_production_write_token_rehearsal_report_hash(
    report: ProductionWriteTokenRehearsalReport,
) -> str:
    data = report.model_dump(mode="json")
    del data["report_content_hash"]
    return _hash(_REPORT_HASH_DOMAIN, data)


def finalize_production_write_token_rehearsal_report(
    report: ProductionWriteTokenRehearsalReport,
) -> ProductionWriteTokenRehearsalReport:
    return report.model_copy(
        update={
            "report_content_hash": calculate_production_write_token_rehearsal_report_hash(report)
        }
    )


def verify_production_write_token_rehearsal_report(
    report: ProductionWriteTokenRehearsalReport,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None = None,
) -> None:
    if not hmac.compare_digest(
        calculate_production_write_token_rehearsal_report_hash(report),
        report.report_content_hash,
    ):
        raise ProductionWriteTokenRehearsalReportError(
            "production_rehearsal_report_hash_mismatch",
            "Production rehearsal report integrity verification failed",
        )
    if snapshot is None:
        if report.snapshot_evidence_hash is not None:
            raise ProductionWriteTokenRehearsalReportError(
                "production_rehearsal_report_snapshot_binding_mismatch",
                "Production rehearsal report snapshot binding does not match",
            )
        return
    verify_production_write_token_rehearsal_snapshot(snapshot)
    if (
        report.snapshot_evidence_hash is None
        or not hmac.compare_digest(report.snapshot_evidence_hash, snapshot.snapshot_evidence_hash)
        or report.snapshot_content_hash != snapshot.snapshot_content_hash
        or report.target_safe_ref != snapshot.target_safe_ref
        or report.event_count != snapshot.event_count
        or report.page_count != snapshot.page_count
    ):
        raise ProductionWriteTokenRehearsalReportError(
            "production_rehearsal_report_snapshot_binding_mismatch",
            "Production rehearsal report snapshot binding does not match",
        )


def production_write_token_rehearsal_snapshot_data(
    snapshot: ProductionWriteTokenRehearsalSnapshot,
) -> dict[str, object]:
    verify_production_write_token_rehearsal_snapshot(snapshot)
    return snapshot.model_dump(mode="json")


def production_write_token_rehearsal_report_data(
    report: ProductionWriteTokenRehearsalReport,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None = None,
) -> dict[str, object]:
    verify_production_write_token_rehearsal_report(report, snapshot)
    return report.model_dump(mode="json")


def render_production_write_token_rehearsal_snapshot_json(
    snapshot: ProductionWriteTokenRehearsalSnapshot,
) -> str:
    return (
        json.dumps(
            production_write_token_rehearsal_snapshot_data(snapshot),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_production_write_token_rehearsal_report_json(
    report: ProductionWriteTokenRehearsalReport,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None = None,
) -> str:
    return (
        json.dumps(
            production_write_token_rehearsal_report_data(report, snapshot),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_production_write_token_rehearsal_report_text(
    report: ProductionWriteTokenRehearsalReport,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None = None,
) -> str:
    data = production_write_token_rehearsal_report_data(report, snapshot)
    privacy_findings = data["privacy_findings"]
    assert isinstance(privacy_findings, list)
    return "\n".join(
        (
            "Production write-token read-only rehearsal report",
            "Phase 6D.0 foundation only: yes",
            "live execution: no",
            f"target reference: {data['target_safe_ref']}",
            f"token role: {data['token_role']}",
            f"token generation: {data['token_generation']}",
            f"scope exact: {'yes' if data['scope_exact'] else 'no'}",
            f"scope count: {data['scope_count']}",
            f"token refreshes: {data['token_refresh_count']}",
            f"browser launches: {data['browser_launch_count']}",
            f"rehearsal clients constructed: {data['rehearsal_client_construction_count']}",
            f"Calendar API calls: {data['calendar_api_call_count']}",
            f"list calls: {data['list_call_count']}",
            f"get calls: {data['get_call_count']}",
            f"read retries: {data['read_retry_count']}",
            f"mutation calls: {data['mutation_call_count']}",
            f"target metadata verified: {'yes' if data['target_metadata_verified'] else 'no'}",
            f"snapshot complete: {'yes' if data['snapshot_complete'] else 'no'}",
            f"snapshot pages: {data['page_count']}",
            f"snapshot events: {data['event_count']}",
            f"snapshot hash: {data['snapshot_content_hash'] or 'none'}",
            f"Baseline cross-binding: {'yes' if data['baseline_cross_binding'] else 'no'}",
            f"Source unchanged: {data['source_unchanged_count']}",
            (
                "Source add/update/delete: "
                f"{data['source_add_count']}/{data['source_update_count']}/"
                f"{data['source_delete_candidate_count']}"
            ),
            f"Source zero-diff: {'yes' if data['source_zero_diff'] else 'no'}",
            f"get performed: {'yes' if data['get_performed'] else 'no'}",
            f"get verified: {'yes' if data['get_verified'] else 'no'}",
            (
                "Event ID present internally: "
                f"{'yes' if data['event_id_present_internally'] else 'no'}"
            ),
            f"ETag present internally: {'yes' if data['etag_present_internally'] else 'no'}",
            f"privacy findings: {len(privacy_findings)}",
            f"result state: {data['result_state']}",
            f"safe code: {data['safe_code'] or 'none'}",
            f"report hash: {data['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "ProductionWriteTokenRehearsalReportError",
    "build_production_write_token_rehearsal_event_evidence",
    "calculate_production_write_token_rehearsal_report_hash",
    "calculate_production_write_token_rehearsal_snapshot_hash",
    "finalize_production_write_token_rehearsal_report",
    "finalize_production_write_token_rehearsal_snapshot",
    "production_write_token_rehearsal_report_data",
    "production_write_token_rehearsal_snapshot_data",
    "render_production_write_token_rehearsal_report_json",
    "render_production_write_token_rehearsal_report_text",
    "render_production_write_token_rehearsal_snapshot_json",
    "verify_production_write_token_rehearsal_report",
    "verify_production_write_token_rehearsal_snapshot",
]
