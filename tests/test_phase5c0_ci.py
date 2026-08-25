from __future__ import annotations

import argparse

from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.cli import build_parser


def test_ci_matrix_remains_exactly_six_jobs_and_offline_bootstrap_runs_in_base() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("os: ubuntu-latest") == 3
    assert workflow.count("os: windows-latest") == 3
    assert workflow.count("layer: base") == 2
    assert workflow.count("layer: google-read") == 2
    assert workflow.count("layer: google-test-write") == 2
    assert '-m "not google_read and not google_test_write"' in workflow
    assert "contents: read" in workflow
    for forbidden in (
        "workflow_dispatch",
        "build-test-bootstrap-add-plan",
        "credentials-file",
        "token-file",
        "secrets.",
    ):
        assert forbidden not in workflow


def test_bootstrap_base_tests_are_unmarked_and_transport_bridge_is_google_test_write() -> None:
    base_files = sorted((REPOSITORY_ROOT / "tests").glob("test_*bootstrap*phase5c0.py"))

    assert base_files
    for path in base_files:
        source = path.read_text(encoding="utf-8")
        if path.name == "test_test_bootstrap_add_transport_phase5c0.py":
            assert "pytestmark = pytest.mark.google_test_write" in source
        else:
            assert "pytestmark = pytest.mark.google_test_write" not in source


def test_cli_inventory_adds_three_commands_without_generic_aliases() -> None:
    parser = build_parser()
    action = next(item for item in parser._actions if isinstance(item, argparse._SubParsersAction))

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
    assert len(action.choices) == 24
    assert not {"apply", "sync", "execute"} & set(action.choices)
