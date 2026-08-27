"""Build and verify Accepted Production source manifests without network access."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping

from pydantic import ValidationError

from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.provenance import canonical_content_hash
from tridentine_calendar_google_sync.safe_refs import safe_uid_ref

_MANIFEST_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:accepted-production-source-manifest:v1\x00"
)
_REPOSITORY_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_FORBIDDEN_MARKERS = ("test", "synthetic", "テスト")


class AcceptedProductionSourceManifestError(ValueError):
    """A content-free Accepted Production source manifest failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class AcceptedProductionSourceManifestInputError(AcceptedProductionSourceManifestError):
    """Source, profile, or repository identity cannot produce a manifest."""


class AcceptedProductionSourceManifestValidationError(AcceptedProductionSourceManifestError):
    """A manifest failed fixed-policy or integrity verification."""


def _guard(condition: bool, code: str, public_message: str) -> None:
    if not condition:
        raise AcceptedProductionSourceManifestInputError(code, public_message)


def _contains_forbidden_marker(value: str) -> bool:
    folded = value.casefold()
    return ".invalid" in folded or any(marker.casefold() in folded for marker in _FORBIDDEN_MARKERS)


def accepted_production_source_manifest_data(
    manifest: AcceptedProductionSourceManifest,
) -> dict[str, object]:
    """Return the complete canonical private manifest document."""

    return {
        "schema_version": manifest.schema_version,
        "manifest_type": manifest.manifest_type,
        "production": manifest.production,
        "acceptance_state": manifest.acceptance_state,
        "synthetic": manifest.synthetic,
        "repository_identity": manifest.repository_identity,
        "repository_tag": manifest.repository_tag,
        "repository_commit": manifest.repository_commit,
        "ics_sha256": manifest.ics_sha256,
        "profile_id": manifest.profile_id,
        "event_count": manifest.event_count,
        "first_date": manifest.first_date.isoformat(),
        "last_date": manifest.last_date.isoformat(),
        "all_day_count": manifest.all_day_count,
        "timed_count": manifest.timed_count,
        "recurring_event_count": manifest.recurring_event_count,
        "source_content_hash": manifest.source_content_hash,
        "manifest_content_hash": manifest.manifest_content_hash,
    }


def _hash_mapping(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_MANIFEST_HASH_DOMAIN + encoded).hexdigest()


def calculate_accepted_production_source_manifest_hash(
    manifest: AcceptedProductionSourceManifest,
) -> str:
    """Calculate the domain-separated manifest hash without trusting its digest."""

    data = accepted_production_source_manifest_data(manifest)
    del data["manifest_content_hash"]
    return _hash_mapping(data)


def verify_accepted_production_source_manifest(
    manifest: AcceptedProductionSourceManifest,
) -> None:
    """Revalidate the closed Production contract and its complete content hash."""

    if not isinstance(manifest, AcceptedProductionSourceManifest):
        raise AcceptedProductionSourceManifestValidationError(
            "invalid_accepted_production_source_manifest",
            "Accepted Production source manifest is invalid",
        )
    try:
        AcceptedProductionSourceManifest.model_validate(
            manifest.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as exc:
        raise AcceptedProductionSourceManifestValidationError(
            "accepted_production_source_manifest_policy_mismatch",
            "Accepted Production source manifest policy verification failed",
        ) from exc
    if not hmac.compare_digest(
        calculate_accepted_production_source_manifest_hash(manifest),
        manifest.manifest_content_hash,
    ):
        raise AcceptedProductionSourceManifestValidationError(
            "accepted_production_source_manifest_hash_mismatch",
            "Accepted Production source manifest integrity verification failed",
        )


def _validate_repository_identity(repository_identity: str) -> None:
    _guard(
        isinstance(repository_identity, str)
        and _REPOSITORY_IDENTITY_PATTERN.fullmatch(repository_identity) is not None,
        "accepted_production_source_repository_invalid",
        "Accepted Production source repository identity is invalid",
    )
    parts = repository_identity.split("/", 1)
    _guard(
        not any(part in {".", ".."} or part.casefold().endswith(".git") for part in parts),
        "accepted_production_source_repository_invalid",
        "Accepted Production source repository identity is invalid",
    )
    _guard(
        not _contains_forbidden_marker(repository_identity),
        "accepted_production_source_marker_forbidden",
        "Accepted Production source contains a Test or synthetic marker",
    )


def _validate_profile(profile: AcceptedSourceProfile) -> None:
    _guard(
        isinstance(profile, AcceptedSourceProfile),
        "accepted_production_source_profile_invalid",
        "Accepted Production source profile is invalid",
    )
    marker_values = (profile.profile_id, profile.accepted_tag, profile.project_name)
    _guard(
        all(not _contains_forbidden_marker(value) for value in marker_values),
        "accepted_production_source_marker_forbidden",
        "Accepted Production source contains a Test or synthetic marker",
    )
    _guard(
        "accepted" in profile.profile_id.casefold()
        and "accepted" in profile.accepted_tag.casefold(),
        "accepted_production_source_not_accepted",
        "Production source provenance is not explicitly Accepted",
    )
    _guard(
        profile.accepted_commit != "0" * 40 and profile.html_sha256 != "0" * 64,
        "accepted_production_source_provenance_invalid",
        "Accepted Production source provenance is invalid",
    )


def _aggregate_matches_profile(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> bool:
    expected = profile.expected
    return (
        source.vcalendar_count == expected.vcalendar_count
        and source.vevent_count == expected.vevent_count
        and len(source.events) == expected.vevent_count
        and source.uid_total_count == expected.uid_total_count
        and source.uid_unique_count == expected.uid_unique_count
        and source.uid_duplicate_count == expected.uid_duplicate_count
        and source.first_date == expected.first_date
        and source.last_date == expected.last_date
        and source.all_day_count == expected.all_day_count
        and source.timed_count == expected.timed_count
        and source.dtstart_date_count == expected.dtstart_date_count
        and source.dtend_present_count == expected.dtend_present_count
        and source.summary_present_count == expected.summary_present_count
        and source.description_present_count == expected.description_present_count
        and source.dtstamp_present_count == expected.dtstamp_present_count
        and source.rrule_count == expected.rrule_count
        and source.recurrence_id_count == expected.recurrence_id_count
        and source.event_x_property_count == expected.event_x_property_count
    )


def _validate_source(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> int:
    _guard(
        isinstance(source, SourceCalendarInspection),
        "accepted_production_source_inspection_invalid",
        "Accepted Production source inspection is invalid",
    )
    _guard(
        source.profile_id == profile.profile_id
        and source.raw_sha256 == profile.html_sha256
        and source.source_sha_matches,
        "accepted_production_source_profile_mismatch",
        "Accepted Production source does not match its profile",
    )
    _guard(
        source.source_valid
        and not source.fatal
        and not source.findings
        and source.malformed_event_count == 0,
        "accepted_production_source_not_clean",
        "Accepted Production source validation is not exactly clean",
    )
    _guard(
        _aggregate_matches_profile(profile, source)
        and source.vevent_count > 0
        and source.all_day_count + source.timed_count == source.vevent_count,
        "accepted_production_source_aggregate_mismatch",
        "Accepted Production source aggregates do not match its profile",
    )
    _guard(
        hmac.compare_digest(
            canonical_content_hash(
                vcalendar_count=source.vcalendar_count,
                events=source.events,
            ),
            source.content_hash,
        ),
        "accepted_production_source_content_hash_mismatch",
        "Accepted Production source content integrity verification failed",
    )
    for event in source.events:
        _guard(
            event.uid is not None
            and event.safe_uid_reference is not None
            and event.safe_uid_reference == safe_uid_ref(event.uid),
            "accepted_production_source_uid_invalid",
            "Accepted Production source contains an invalid UID",
        )
        assert event.uid is not None
        _guard(
            ".invalid" not in event.uid.casefold(),
            "accepted_production_source_invalid_uid_domain",
            "Accepted Production source contains a reserved invalid UID",
        )
        marker_values = (event.uid, event.summary or "")
        _guard(
            all(not _contains_forbidden_marker(value) for value in marker_values),
            "accepted_production_source_marker_forbidden",
            "Accepted Production source contains a Test or synthetic marker",
        )
    return sum(event.rrule_present or event.recurrence_id_present for event in source.events)


def build_accepted_production_source_manifest(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    *,
    repository_identity: str,
) -> AcceptedProductionSourceManifest:
    """Build one pin-agnostic manifest from an exact clean offline inspection."""

    _validate_repository_identity(repository_identity)
    _validate_profile(profile)
    recurring_event_count = _validate_source(profile, source)
    assert source.first_date is not None and source.last_date is not None
    try:
        provisional = AcceptedProductionSourceManifest(
            repository_identity=repository_identity,
            repository_tag=profile.accepted_tag,
            repository_commit=profile.accepted_commit,
            ics_sha256=source.raw_sha256,
            profile_id=profile.profile_id,
            event_count=source.vevent_count,
            first_date=source.first_date,
            last_date=source.last_date,
            all_day_count=source.all_day_count,
            timed_count=source.timed_count,
            recurring_event_count=recurring_event_count,
            source_content_hash=source.content_hash,
            manifest_content_hash="0" * 64,
        )
    except ValidationError as exc:
        raise AcceptedProductionSourceManifestInputError(
            "accepted_production_source_manifest_invalid",
            "Accepted Production source cannot produce a valid manifest",
        ) from exc
    manifest = provisional.model_copy(
        update={
            "manifest_content_hash": calculate_accepted_production_source_manifest_hash(provisional)
        }
    )
    verify_accepted_production_source_manifest(manifest)
    return manifest


__all__ = [
    "AcceptedProductionSourceManifestError",
    "AcceptedProductionSourceManifestInputError",
    "AcceptedProductionSourceManifestValidationError",
    "accepted_production_source_manifest_data",
    "build_accepted_production_source_manifest",
    "calculate_accepted_production_source_manifest_hash",
    "verify_accepted_production_source_manifest",
]
