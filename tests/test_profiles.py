from __future__ import annotations

from pathlib import Path

import pytest
from conftest import PROFILES_DIR
from pydantic import ValidationError

from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.profiles import ProfileError, load_profile


def test_load_accepted_profile_contains_pinned_public_provenance() -> None:
    profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)

    assert profile.schema_version == "1.0"
    assert profile.profile_id == "accepted-20260814"
    assert profile.source.accepted_tag == "ja-localization-accepted-20260814"
    assert profile.source.accepted_commit == "c0dedd86257df2ff1a95097bcf3824b2b95fce66"
    assert profile.source.html_sha256 == (
        "1c0ee8a19769f9ff26b1a40d03d0280afdcbde1d7d50642ad3f2123c117dd552"
    )
    assert profile.source.plain_sha256 == (
        "962725c8029993af7fc02450cb29ab6c18eaa4db0569023f53d114be1247ae62"
    )
    assert profile.expected.vevent_count == 4938
    assert profile.expected.uid_total_count == 4938
    assert profile.expected.uid_unique_count == 4938
    assert profile.expected.uid_duplicate_count == 0
    assert profile.expected.first_date.isoformat() == "2024-01-01"
    assert profile.expected.last_date.isoformat() == "2034-12-31"
    assert profile.expected.all_day_count == 4938
    assert profile.expected.timed_count == 0
    assert profile.expected.dtend_present_count == 0
    assert profile.expected.rrule_count == 0
    assert profile.expected.recurrence_id_count == 0


def test_profile_models_are_frozen() -> None:
    profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)

    with pytest.raises(ValidationError):
        profile.profile_id = "changed"  # type: ignore[misc]


def test_unknown_profile_error_does_not_expose_profiles_directory() -> None:
    secret_like_directory = Path("private-profile-location")

    with pytest.raises(ProfileError) as caught:
        load_profile("does-not-exist", profiles_dir=secret_like_directory)

    assert str(secret_like_directory) not in str(caught.value)


def test_profile_schema_rejects_unknown_fields() -> None:
    profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
    data = profile.model_dump(mode="json")
    data["calendar_id"] = "must-not-be-accepted"

    with pytest.raises(ValidationError):
        AcceptedSourceProfile.model_validate(data)
