from __future__ import annotations

import ast
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT

pytestmark = pytest.mark.google_production_write


def test_phase6d0_runtime_artifacts_are_gitignored() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "production-write-tokens/",
        "production-write-token-generations/",
        "production-write-token-rehearsals/",
        "*.production-write-token.json",
        "*.production-write-token-generation.json",
        "*.production-write-token-rehearsal-snapshot.json",
        "*.production-write-token-rehearsal-report.json",
        "*.production-write-token-rehearsal-report.txt",
        "production-write-authorized-user-token.json",
        "production-write-token-generation-state.json",
        "production-write-token-readonly-rehearsal-snapshot.json",
        "production-write-token-readonly-rehearsal-report.json",
        "production-write-token-readonly-rehearsal-report.txt",
    ):
        assert pattern in ignore


def test_cli_hard_off_handlers_do_not_import_live_phase6d_runtime() -> None:
    source = (REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / "cli.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in (
        "_authorize_production_write_token_command",
        "_rehearse_production_write_token_readonly_command",
    ):
        function = functions[name]
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        called_names = {node.func.id for node in calls if isinstance(node.func, ast.Name)} | {
            node.func.attr for node in calls if isinstance(node.func, ast.Attribute)
        }
        assert called_names <= {"write"}


def test_phase6d0_modules_do_not_import_calendar_clients_or_network_stacks() -> None:
    source_root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(source_root.glob("production_write_token*.py"))
    assert paths
    forbidden_prefixes = (
        "googleapiclient",
        "requests",
        "httpx",
        "urllib",
        "socket",
    )
    forbidden_internal = {
        "tridentine_calendar_google_sync.google_client",
        "tridentine_calendar_google_sync.google_fetch",
        "tridentine_calendar_google_sync.google_test_write_client",
        "tridentine_calendar_google_sync.production_transport",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert not any(name.startswith(forbidden_prefixes) for name in imports)
        assert forbidden_internal.isdisjoint(imports)


def test_rehearsal_protocol_exposes_exactly_list_and_get() -> None:
    path = (
        REPOSITORY_ROOT
        / "src"
        / "tridentine_calendar_google_sync"
        / "production_write_token_rehearsal_models.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    protocol = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ProductionWriteTokenReadOnlyTransport"
    )
    public_methods = {
        node.name
        for node in protocol.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }

    assert public_methods == {"list_events", "get_event"}


def test_authorization_module_has_no_calendar_api_method_calls() -> None:
    path = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / "production_write_token.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert {
        "patch",
        "import_",
        "insert",
        "update",
        "delete",
        "move",
        "batch",
    }.isdisjoint(attributes)


def test_phase6d0_document_records_live_and_privacy_boundaries() -> None:
    document = (
        REPOSITORY_ROOT / "docs" / "production-write-token-readonly-rehearsal-foundation.md"
    ).read_text(encoding="utf-8")

    required = (
        "https://www.googleapis.com/auth/calendar.events.owned",
        "production_read",
        "test_write",
        "production_write",
        "AUTHORIZE PRODUCTION WRITE TOKEN ONLY T-<12>",
        "READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN T-<12>",
        "list_events",
        "get_event",
        "raw Calendar API hard maximum is 5",
        "Repository-wide Deep security scan required after merge and before Production OAuth",
    )
    assert all(value in document for value in required)
    assert "Phase 6C `patch_description` is not imported" in document


def test_no_real_production_identity_or_secret_literals_in_phase6d0_wiring_files() -> None:
    paths = (
        REPOSITORY_ROOT / "README.md",
        REPOSITORY_ROOT / "docs" / "production-write-token-readonly-rehearsal-foundation.md",
        REPOSITORY_ROOT / "tests" / "test_cli_phase6d0.py",
        REPOSITORY_ROOT / "tests" / "test_phase6d0_ci.py",
        REPOSITORY_ROOT / "tests" / "test_phase6d0_privacy.py",
    )
    content = "\n".join(Path(path).read_text(encoding="utf-8") for path in paths).casefold()
    forbidden_literals = (
        "@" + "gmail.com",
        "authorization:" + " bearer",
        "ya" + "29.",
        "1" + "//",
        "client_" + 'secret":',
        "c:" + "\\users\\jumpf",
        "t-e10f" + "0095ab8f",
    )
    for forbidden in forbidden_literals:
        assert forbidden not in content
