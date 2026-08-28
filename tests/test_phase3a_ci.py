from __future__ import annotations

from conftest import REPOSITORY_ROOT


def test_ci_separates_base_and_google_read_mock_layers_on_linux_and_windows() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("os: ubuntu-latest") == 4
    assert workflow.count("os: windows-latest") == 4
    assert workflow.count("layer: base") == 2
    assert workflow.count("layer: google-read") == 2
    assert workflow.count("layer: google-test-write") == 2
    assert workflow.count("layer: google-production-write") == 2
    assert workflow.count("sync_args: --extra dev\n") == 2
    assert workflow.count("sync_args: --extra dev --extra google-read") == 2
    assert workflow.count("sync_args: --extra dev --extra google-test-write") == 2
    assert workflow.count("sync_args: --extra dev --extra google-production-write") == 2
    assert (
        '-m "not google_read and not google_test_write and not google_production_write"' in workflow
    )
    assert "-m google_read" in workflow
    assert "-m google_test_write" in workflow
    assert "-m google_production_write" in workflow
    assert "--all-extras" not in workflow


def test_ci_keeps_existing_action_versions_and_read_only_permissions() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert "actions/checkout@v4" in workflow
    assert "actions/setup-python@v5" in workflow
    assert "astral-sh/setup-uv@v6" in workflow
    assert "permissions:\n  contents: read" in workflow
    for forbidden in (
        "contents: write",
        "id-token: write",
        "workflow_dispatch",
        "secrets.",
        "TRIDENTINE_ACCEPTED_HTML_ICS_PATH:",
    ):
        assert forbidden not in workflow
