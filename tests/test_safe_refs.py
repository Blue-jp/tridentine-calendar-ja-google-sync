from __future__ import annotations

import re

from tridentine_calendar_google_sync.safe_refs import safe_uid_ref


def test_safe_uid_reference_is_deterministic_and_redacted() -> None:
    raw_uid = "fixture-private-uid@example.invalid"

    first = safe_uid_ref(raw_uid)
    second = safe_uid_ref(raw_uid)

    assert first == second
    assert re.fullmatch(r"U-[0-9a-f]{12}", first)
    assert raw_uid not in first


def test_safe_uid_reference_uses_a_distinct_domain() -> None:
    raw_uid = "same-input@example.invalid"
    unseparated_prefix = __import__("hashlib").sha256(raw_uid.encode()).hexdigest()[:12]

    assert safe_uid_ref(raw_uid) != f"U-{unseparated_prefix}"


def test_different_uids_have_different_safe_references() -> None:
    assert safe_uid_ref("fixture-one@example.invalid") != safe_uid_ref(
        "fixture-two@example.invalid"
    )
