"""Public-safe reports for mock Production write-token authorization state."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Literal

from pydantic import Field

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_write_token import (
    verify_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionTokenRole,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteTokenAuthorizationResult,
    ProductionWriteTokenGenerationState,
)

_REPORT_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-authorization-report:v1\x00"
)


class ProductionWriteTokenAuthorizationReport(StrictFrozenModel):
    """Aggregate-only report with no token, credential, path, or raw target data."""

    schema_version: Literal["1.0"] = "1.0"
    report_type: Literal["production-write-token-authorization-report-v1"] = (
        "production-write-token-authorization-report-v1"
    )
    mock_only: Literal[True] = True
    live_oauth: Literal[False] = False
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    token_role: Literal[ProductionTokenRole.PRODUCTION_WRITE] = ProductionTokenRole.PRODUCTION_WRITE
    scope_count: Literal[1] = 1
    scope_exact: Literal[True] = True
    generation: int = Field(ge=1)
    browser_launch_count: Literal[1] = 1
    oauth_attempt_count: Literal[1] = 1
    calendar_api_call_count: Literal[0] = 0
    token_written: Literal[True] = True
    generation_state_written: Literal[True] = True
    result_state: Literal["mock_authorized"] = "mock_authorized"
    report_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProductionWriteTokenReportError(ValueError):
    """Content-free authorization-report failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash_data(report: ProductionWriteTokenAuthorizationReport) -> dict[str, object]:
    return {
        key: value
        for key, value in report.model_dump(mode="json").items()
        if key != "report_content_hash"
    }


def calculate_production_write_token_authorization_report_hash(
    report: ProductionWriteTokenAuthorizationReport,
) -> str:
    encoded = json.dumps(
        _hash_data(report),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest()


def build_production_write_token_authorization_report(
    result: ProductionWriteTokenAuthorizationResult,
) -> ProductionWriteTokenAuthorizationReport:
    """Build a safe report from a verified fake-only authorization result."""

    state = result.generation_state
    token = result.token
    verify_production_write_token_generation_state(
        state,
        required_generation=token.generation,
    )
    if not (
        token.role is ProductionTokenRole.PRODUCTION_WRITE
        and token.scopes == PRODUCTION_WRITE_SCOPES
        and token.granted_scopes == PRODUCTION_WRITE_SCOPES
        and token.grant_evidence.origin
        is ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE
        and hmac.compare_digest(token.target_safe_ref, state.target_safe_ref)
        and hmac.compare_digest(token.target_config_hash, state.target_config_hash)
    ):
        raise ProductionWriteTokenReportError(
            "production_write_token_report_binding_mismatch",
            "Production write-token report source binding did not match",
        )
    provisional = ProductionWriteTokenAuthorizationReport(
        target_safe_ref=state.target_safe_ref,
        generation=state.generation,
        browser_launch_count=result.browser_launch_count,
        oauth_attempt_count=result.oauth_attempt_count,
        calendar_api_call_count=result.calendar_api_call_count,
        token_written=result.token_written,
        generation_state_written=result.generation_state_written,
        report_content_hash="0" * 64,
    )
    return provisional.model_copy(
        update={
            "report_content_hash": calculate_production_write_token_authorization_report_hash(
                provisional
            )
        }
    )


def verify_production_write_token_authorization_report(
    report: ProductionWriteTokenAuthorizationReport,
) -> None:
    if not hmac.compare_digest(
        calculate_production_write_token_authorization_report_hash(report),
        report.report_content_hash,
    ):
        raise ProductionWriteTokenReportError(
            "production_write_token_report_hash_mismatch",
            "Production write-token report integrity verification failed",
        )


def render_production_write_token_authorization_report_json(
    report: ProductionWriteTokenAuthorizationReport,
) -> str:
    verify_production_write_token_authorization_report(report)
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_production_write_token_authorization_report_text(
    report: ProductionWriteTokenAuthorizationReport,
) -> str:
    verify_production_write_token_authorization_report(report)
    return "\n".join(
        (
            "Production write-token mock authorization report",
            "mock only: yes",
            "live OAuth: no",
            f"target reference: {report.target_safe_ref}",
            f"token role: {report.token_role.value}",
            f"scope count: {report.scope_count}",
            "scope exact: yes",
            f"token generation: {report.generation}",
            f"browser launches: {report.browser_launch_count}",
            f"OAuth attempts: {report.oauth_attempt_count}",
            f"Calendar API calls: {report.calendar_api_call_count}",
            f"state: {report.result_state}",
            f"report hash: {report.report_content_hash}",
            "",
        )
    )


def build_production_write_token_generation_inspection(
    state: ProductionWriteTokenGenerationState,
) -> dict[str, object]:
    """Return only safe metadata; no token-content or credential hash exists."""

    verify_production_write_token_generation_state(state)
    return {
        "schema_version": state.schema_version,
        "state_type": state.state_type,
        "token_role": state.role.value,
        "target_safe_ref": state.target_safe_ref,
        "generation": state.generation,
        "issued_at": state.issued_at.isoformat(),
        "predecessor_present": state.predecessor_state_hash is not None,
        "integrity": "verified",
        "content_hash": state.content_hash,
    }


__all__ = [
    "ProductionWriteTokenAuthorizationReport",
    "ProductionWriteTokenReportError",
    "build_production_write_token_authorization_report",
    "build_production_write_token_generation_inspection",
    "calculate_production_write_token_authorization_report_hash",
    "render_production_write_token_authorization_report_json",
    "render_production_write_token_authorization_report_text",
    "verify_production_write_token_authorization_report",
]
