"""Deterministic public-safe report for mock Production update execution."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_execution_journal import (
    PRODUCTION_EXECUTION_SAFE_CODES,
    ProductionExecutionJournal,
    ProductionExecutionJournalEntryStatus,
    ProductionExecutionJournalPhase,
    ProductionExecutionJournalState,
    verify_production_execution_journal,
)
from tridentine_calendar_google_sync.production_transport_models import (
    ProductionMockExecutionResult,
)

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-execution-report:v1\x00"


class ProductionExecutionReport(StrictFrozenModel):
    """Safe aggregate report with a one-way binding to the journal hash."""

    schema_version: Literal["1.0"] = "1.0"
    report_type: Literal["production-single-update-execution-report-v1"] = (
        "production-single-update-execution-report-v1"
    )
    mock_only: Literal[True] = True
    live_execution: Literal[False] = False
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    plan_ref: str = Field(pattern=r"^P-[0-9a-f]{12}$")
    approval_state: Literal["validated", "rejected"]
    permit_consumed: bool
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...]
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    api_call_count: int = Field(ge=0, le=10)
    read_retry_count: int = Field(ge=0, le=10)
    mutation_attempt_count: int = Field(ge=0, le=1)
    mutation_retry_count: Literal[0] = 0
    pre_snapshot_verified: bool
    pre_image_verified: bool
    read_back_verified: bool
    post_snapshot_verified: bool
    zero_diff_verified: bool
    baseline_renewal_required: bool
    automatic_rollback_count: Literal[0] = 0
    safe_findings: tuple[str, ...]
    journal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_state: ProductionExecutionJournalState
    success: bool
    report_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_public_shape(self) -> Self:
        if self.changed_fields != ("description",):
            raise ValueError("Production execution report field set is invalid")
        if self.permit_consumed and self.approval_state != "validated":
            raise ValueError("Production execution report approval state is invalid")
        if len(set(self.safe_findings)) != len(self.safe_findings) or any(
            not _is_safe_code(item) for item in self.safe_findings
        ):
            raise ValueError("Production execution report findings are invalid")
        expected_success = self.result_state is ProductionExecutionJournalState.SUCCEEDED
        if self.success != expected_success:
            raise ValueError("Production execution report success state is invalid")
        if self.success:
            if not all(
                (
                    self.permit_consumed,
                    self.pre_snapshot_verified,
                    self.pre_image_verified,
                    self.read_back_verified,
                    self.post_snapshot_verified,
                    self.zero_diff_verified,
                    self.baseline_renewal_required,
                )
            ):
                raise ValueError("successful Production execution report is incomplete")
            if self.mutation_attempt_count != 1 or self.safe_findings:
                raise ValueError("successful Production execution report counts are invalid")
        return self


class ProductionExecutionReportError(ValueError):
    """Content-free report verification failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _is_safe_code(value: str) -> bool:
    return value in PRODUCTION_EXECUTION_SAFE_CODES


def _report_hash_data(report: ProductionExecutionReport) -> dict[str, object]:
    return {
        key: value
        for key, value in report.model_dump(mode="json").items()
        if key != "report_content_hash"
    }


def calculate_production_execution_report_hash(
    report: ProductionExecutionReport,
) -> str:
    """Recalculate the deterministic public report hash."""

    encoded = json.dumps(
        _report_hash_data(report),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest()


def _phase_verified(
    journal: ProductionExecutionJournal,
    phase: ProductionExecutionJournalPhase,
) -> bool:
    accepted = {
        ProductionExecutionJournalEntryStatus.VALIDATED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
        ProductionExecutionJournalEntryStatus.SUCCEEDED,
        ProductionExecutionJournalEntryStatus.RECOVERED,
    }
    return any(entry.phase is phase and entry.status in accepted for entry in journal.entries)


def build_production_execution_report_from_journal(
    journal: ProductionExecutionJournal,
    *,
    safe_findings: tuple[str, ...] | None = None,
) -> ProductionExecutionReport:
    """Build a report whose identities, counters, and states derive from the journal."""

    verify_production_execution_journal(journal)
    terminal_code = journal.entries[-1].safe_code
    expected_findings = () if terminal_code is None else (terminal_code,)
    if safe_findings is None:
        safe_findings = expected_findings
    elif safe_findings != expected_findings:
        raise ProductionExecutionReportError(
            "production_execution_report_findings_mismatch",
            "Production execution report findings do not match the journal",
        )
    report = ProductionExecutionReport(
        target_safe_ref=journal.target_safe_ref,
        run_spec_ref=journal.run_spec_ref,
        plan_ref=journal.plan_ref,
        approval_state=(
            "validated"
            if any(
                entry.phase is ProductionExecutionJournalPhase.APPROVAL_VALIDATED
                and entry.status is ProductionExecutionJournalEntryStatus.VALIDATED
                for entry in journal.entries
            )
            else "rejected"
        ),
        permit_consumed=journal.approval_consumed,
        changed_fields=("description",),
        patch_hash=journal.patch_hash,
        api_call_count=journal.api_call_count,
        read_retry_count=journal.read_retry_count,
        mutation_attempt_count=journal.mutation_attempt_count,
        pre_snapshot_verified=_phase_verified(
            journal, ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED
        ),
        pre_image_verified=_phase_verified(
            journal, ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED
        ),
        read_back_verified=_phase_verified(
            journal, ProductionExecutionJournalPhase.READBACK_VERIFIED
        ),
        post_snapshot_verified=_phase_verified(
            journal, ProductionExecutionJournalPhase.POST_SNAPSHOT_VERIFIED
        ),
        zero_diff_verified=_phase_verified(
            journal, ProductionExecutionJournalPhase.ZERO_DIFF_VERIFIED
        ),
        baseline_renewal_required=(journal.state is ProductionExecutionJournalState.SUCCEEDED),
        safe_findings=safe_findings,
        journal_hash=journal.journal_content_hash,
        result_state=journal.state,
        success=journal.state is ProductionExecutionJournalState.SUCCEEDED,
        report_content_hash="0" * 64,
    )
    return report.model_copy(
        update={"report_content_hash": calculate_production_execution_report_hash(report)}
    )


def build_production_execution_report(
    result: ProductionMockExecutionResult,
) -> ProductionExecutionReport:
    """Build and cross-check a report from the mock orchestrator result."""

    journal = result.journal
    verify_production_execution_journal(journal)
    expected_state = ProductionExecutionJournalState(result.result_state.value)
    derived = build_production_execution_report_from_journal(
        journal,
        safe_findings=result.safe_findings,
    )
    expected_values = (
        result.mock_only,
        result.live_execution,
        result.target_safe_ref,
        result.run_spec_ref,
        result.plan_ref,
        result.approval_state,
        result.permit_consumed,
        result.operation_count,
        result.changed_fields,
        result.patch_hash,
        result.api_call_count,
        result.read_retry_count,
        result.mutation_attempt_count,
        result.mutation_retry_count,
        result.pre_snapshot_verified,
        result.pre_image_verified,
        result.read_back_verified,
        result.post_snapshot_verified,
        result.zero_diff_verified,
        result.baseline_renewal_required,
        expected_state,
    )
    derived_values = (
        derived.mock_only,
        derived.live_execution,
        derived.target_safe_ref,
        derived.run_spec_ref,
        derived.plan_ref,
        derived.approval_state,
        derived.permit_consumed,
        derived.operation_count,
        derived.changed_fields,
        derived.patch_hash,
        derived.api_call_count,
        derived.read_retry_count,
        derived.mutation_attempt_count,
        derived.mutation_retry_count,
        derived.pre_snapshot_verified,
        derived.pre_image_verified,
        derived.read_back_verified,
        derived.post_snapshot_verified,
        derived.zero_diff_verified,
        derived.baseline_renewal_required,
        derived.result_state,
    )
    if expected_values != derived_values:
        raise ProductionExecutionReportError(
            "production_execution_result_journal_mismatch",
            "Production execution result does not match its journal",
        )
    return derived


def verify_production_execution_report(
    report: ProductionExecutionReport,
    journal: ProductionExecutionJournal,
) -> None:
    """Verify report integrity and exact one-way binding to its source journal."""

    verify_production_execution_journal(journal)
    if not hmac.compare_digest(
        calculate_production_execution_report_hash(report), report.report_content_hash
    ):
        raise ProductionExecutionReportError(
            "production_execution_report_hash_mismatch",
            "Production execution report integrity verification failed",
        )
    try:
        expected = build_production_execution_report_from_journal(
            journal,
            safe_findings=report.safe_findings,
        )
    except ProductionExecutionReportError as exc:
        raise ProductionExecutionReportError(
            "production_execution_report_binding_mismatch",
            "Production execution report journal binding verification failed",
        ) from exc
    if not hmac.compare_digest(expected.report_content_hash, report.report_content_hash):
        raise ProductionExecutionReportError(
            "production_execution_report_binding_mismatch",
            "Production execution report journal binding verification failed",
        )


def production_execution_report_data(
    report: ProductionExecutionReport,
    journal: ProductionExecutionJournal,
) -> dict[str, object]:
    """Return a verified canonical public report document."""

    verify_production_execution_report(report, journal)
    return report.model_dump(mode="json")


def render_production_execution_report_json(
    report: ProductionExecutionReport,
    journal: ProductionExecutionJournal,
) -> str:
    """Render deterministic public-safe JSON."""

    return (
        json.dumps(
            production_execution_report_data(report, journal),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_production_execution_report_text(
    report: ProductionExecutionReport,
    journal: ProductionExecutionJournal,
) -> str:
    """Render a content-free human report."""

    data = production_execution_report_data(report, journal)
    findings = data["safe_findings"]
    assert isinstance(findings, list)
    fields = data["changed_fields"]
    assert isinstance(fields, list)
    return "\n".join(
        (
            "Production Calendar single-update mock execution report",
            "mock only: yes",
            "live execution: no",
            f"target reference: {data['target_safe_ref']}",
            f"Run Spec reference: {data['run_spec_ref']}",
            f"Plan reference: {data['plan_ref']}",
            f"approval state: {data['approval_state']}",
            f"permit consumed: {'yes' if data['permit_consumed'] else 'no'}",
            f"operations: {data['operation_count']}",
            f"changed fields: {', '.join(str(field) for field in fields)}",
            f"API calls: {data['api_call_count']}",
            f"read retries: {data['read_retry_count']}",
            f"mutation attempts: {data['mutation_attempt_count']}",
            f"mutation retries: {data['mutation_retry_count']}",
            f"pre-snapshot verified: {'yes' if data['pre_snapshot_verified'] else 'no'}",
            f"pre-image verified: {'yes' if data['pre_image_verified'] else 'no'}",
            f"read-back verified: {'yes' if data['read_back_verified'] else 'no'}",
            f"post-snapshot verified: {'yes' if data['post_snapshot_verified'] else 'no'}",
            f"zero-diff verified: {'yes' if data['zero_diff_verified'] else 'no'}",
            (f"baseline renewal required: {'yes' if data['baseline_renewal_required'] else 'no'}"),
            f"automatic rollback: {data['automatic_rollback_count']}",
            f"safe findings: {','.join(findings) if findings else 'none'}",
            f"state: {data['result_state']}",
            f"success: {'yes' if data['success'] else 'no'}",
            f"journal hash: {data['journal_hash']}",
            f"report hash: {data['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "ProductionExecutionReport",
    "ProductionExecutionReportError",
    "build_production_execution_report",
    "build_production_execution_report_from_journal",
    "calculate_production_execution_report_hash",
    "production_execution_report_data",
    "render_production_execution_report_json",
    "render_production_execution_report_text",
    "verify_production_execution_report",
]
