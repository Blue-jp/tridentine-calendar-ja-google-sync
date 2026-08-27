"""Redacted inspection reports for Accepted Production source manifests."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:accepted-production-source-report:v1\x00"
_REPOSITORY_REFERENCE_DOMAIN = (
    b"tridentine-calendar-google-sync:accepted-source-repository-reference:v1\x00"
)
_TAG_REFERENCE_DOMAIN = b"tridentine-calendar-google-sync:accepted-source-tag-reference:v1\x00"
_PROFILE_REFERENCE_DOMAIN = (
    b"tridentine-calendar-google-sync:accepted-source-profile-reference:v1\x00"
)


def _text_reference(prefix: str, domain: bytes, value: str) -> str:
    digest = hashlib.sha256(domain + value.encode("utf-8", errors="strict")).hexdigest()
    return f"{prefix}-{digest[:12]}"


def build_accepted_production_source_manifest_inspection(
    manifest: AcceptedProductionSourceManifest,
) -> dict[str, object]:
    """Return safe aggregate metadata without raw provenance or source content."""

    verify_accepted_production_source_manifest(manifest)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "accepted-production-source-manifest-inspection-v1",
        "manifest_type": manifest.manifest_type,
        "production": manifest.production,
        "acceptance_state": manifest.acceptance_state,
        "synthetic": manifest.synthetic,
        "repository_reference": _text_reference(
            "R",
            _REPOSITORY_REFERENCE_DOMAIN,
            manifest.repository_identity,
        ),
        "tag_reference": _text_reference(
            "A",
            _TAG_REFERENCE_DOMAIN,
            manifest.repository_tag,
        ),
        "commit_reference": f"C-{manifest.repository_commit[:12]}",
        "ics_reference": f"I-{manifest.ics_sha256[:12]}",
        "profile_reference": _text_reference(
            "P",
            _PROFILE_REFERENCE_DOMAIN,
            manifest.profile_id,
        ),
        "event_count": manifest.event_count,
        "first_date": manifest.first_date.isoformat(),
        "last_date": manifest.last_date.isoformat(),
        "all_day_count": manifest.all_day_count,
        "timed_count": manifest.timed_count,
        "recurring_event_count": manifest.recurring_event_count,
        "source_content_reference": f"S-{manifest.source_content_hash[:12]}",
        "manifest_reference": f"M-{manifest.manifest_content_hash[:12]}",
        "integrity": "verified",
    }
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return {
        **data,
        "report_content_hash": hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest(),
    }


def render_accepted_production_source_manifest_inspection_json(
    manifest: AcceptedProductionSourceManifest,
) -> str:
    """Render deterministic redacted inspection JSON."""

    return (
        json.dumps(
            build_accepted_production_source_manifest_inspection(manifest),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_accepted_production_source_manifest_inspection_text(
    manifest: AcceptedProductionSourceManifest,
) -> str:
    """Render deterministic text containing only safe references and aggregates."""

    report = build_accepted_production_source_manifest_inspection(manifest)
    return "\n".join(
        (
            "Accepted Production Source Manifest inspection",
            f"schema version: {report['schema_version']}",
            f"manifest type: {report['manifest_type']}",
            "Production: yes",
            f"acceptance state: {report['acceptance_state']}",
            "synthetic: no",
            f"repository reference: {report['repository_reference']}",
            f"tag reference: {report['tag_reference']}",
            f"commit reference: {report['commit_reference']}",
            f"ICS reference: {report['ics_reference']}",
            f"profile reference: {report['profile_reference']}",
            f"events: {report['event_count']}",
            f"date range: {report['first_date']} to {report['last_date']}",
            f"all-day events: {report['all_day_count']}",
            f"timed events: {report['timed_count']}",
            f"recurring events: {report['recurring_event_count']}",
            f"source content reference: {report['source_content_reference']}",
            f"manifest reference: {report['manifest_reference']}",
            "integrity: verified",
            f"report hash: {report['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "build_accepted_production_source_manifest_inspection",
    "render_accepted_production_source_manifest_inspection_json",
    "render_accepted_production_source_manifest_inspection_text",
]
