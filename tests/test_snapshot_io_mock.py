from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages
from tridentine_calendar_google_sync.google_sanitize import sanitize_fetched_pages
from tridentine_calendar_google_sync.google_snapshot import (
    parse_google_snapshot_bytes,
)
from tridentine_calendar_google_sync.snapshot_io import (
    SnapshotWriteError,
    write_google_snapshot,
    write_snapshot_atomic,
)

pytestmark = pytest.mark.google_read


def test_snapshot_bytes_are_written_atomically_outside_repository(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    payload = b'{"synthetic":true}\n'

    result = write_snapshot_atomic(path, payload)

    assert result == path
    assert path.read_bytes() == payload


def test_snapshot_writer_never_overwrites_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_bytes(b"synthetic existing bytes")

    with pytest.raises(SnapshotWriteError) as caught:
        write_snapshot_atomic(path, b'{"synthetic":"replacement"}\n')

    assert caught.value.code == "sensitive_output_exists"
    assert path.read_bytes() == b"synthetic existing bytes"
    assert str(path) not in str(caught.value)


def test_snapshot_output_inside_repository_is_rejected_before_write() -> None:
    path = REPOSITORY_ROOT / "must-not-create-snapshot.json"

    with pytest.raises(SnapshotWriteError) as caught:
        write_snapshot_atomic(path, b'{"synthetic":true}\n')

    assert caught.value.code == "sensitive_path_in_git_worktree"
    assert not path.exists()
    assert str(path) not in str(caught.value)


def test_snapshot_writer_rejects_relative_non_utf8_and_url_paths(tmp_path: Path) -> None:
    cases = (
        (Path("relative-snapshot.json"), b'{"synthetic":true}\n'),
        (tmp_path / "invalid.json", b"\xff\xfe"),
        ("https://example.invalid/snapshot.json", b'{"synthetic":true}\n'),
        ("file:///synthetic/snapshot.json", b'{"synthetic":true}\n'),
    )

    for path, payload in cases:
        with pytest.raises(SnapshotWriteError) as caught:
            write_snapshot_atomic(path, payload)
        assert str(path) not in str(caught.value)


def test_google_snapshot_render_write_and_parse_round_trip(
    tmp_path: Path,
    google_api_pages_dir: Path,
) -> None:
    scenario = json.loads((google_api_pages_dir / "one_page.json").read_text(encoding="utf-8"))
    responses = scenario["responses"]
    assert isinstance(responses, list)
    assert all(isinstance(page, Mapping) for page in responses)
    fetched = FetchedGooglePages(
        target_fingerprint="d" * 64,
        pages=tuple(responses),
        page_count=1,
        item_count=1,
        retry_count=0,
        refreshed_after_401=False,
        collection_metadata_hash="f" * 64,
    )
    snapshot = sanitize_fetched_pages(
        fetched,
        captured_at=datetime(2026, 8, 23, tzinfo=UTC),
    )
    path = tmp_path / "sanitized-snapshot.json"

    result = write_google_snapshot(snapshot, path)
    reparsed = parse_google_snapshot_bytes(path.read_bytes())

    assert result == path
    assert reparsed == snapshot
