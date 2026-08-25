from __future__ import annotations

import argparse

import pytest
from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.cli import build_parser

pytestmark = pytest.mark.google_test_write


def test_ci_matrix_remains_exactly_six_offline_mock_jobs() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("os: ubuntu-latest") == 3
    assert workflow.count("os: windows-latest") == 3
    assert workflow.count("layer: base") == 2
    assert workflow.count("layer: google-read") == 2
    assert workflow.count("layer: google-test-write") == 2
    assert "contents: read" in workflow
    for forbidden in (
        "workflow_dispatch",
        "inspect-test-calendar-prewrite",
        "credentials-file",
        "token-file",
        "secrets.",
    ):
        assert forbidden not in workflow


def test_all_phase5a1_test_modules_use_google_test_write_marker() -> None:
    tests = sorted((REPOSITORY_ROOT / "tests").glob("test_*phase5a1.py"))

    assert tests
    for path in tests:
        source = path.read_text(encoding="utf-8")
        assert "pytestmark = pytest.mark.google_test_write" in source


def test_cli_inventory_keeps_prewrite_and_bootstrap_commands_without_generic_aliases() -> None:
    parser = build_parser()
    action = next(item for item in parser._actions if isinstance(item, argparse._SubParsersAction))

    assert len(action.choices) == 24
    assert "inspect-test-calendar-prewrite" in action.choices
    assert {
        "build-test-bootstrap-add-plan",
        "inspect-test-bootstrap-add-plan",
        "build-test-bootstrap-add-run-spec",
    } <= set(action.choices)
    assert {
        "build-test-single-update-plan",
        "inspect-test-single-update-plan",
        "build-test-single-update-run-spec",
    } <= set(action.choices)
    assert not {"apply", "sync", "execute"} & set(action.choices)
