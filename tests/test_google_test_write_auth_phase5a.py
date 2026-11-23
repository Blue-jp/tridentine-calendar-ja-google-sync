from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from conftest import REPOSITORY_ROOT
from phase5a_helpers import make_test_target_config
from pytest_mock import MockerFixture

from tridentine_calendar_google_sync import google_test_write_auth as auth_module
from tridentine_calendar_google_sync.google_auth import READ_ONLY_GOOGLE_SCOPES
from tridentine_calendar_google_sync.google_optional import GoogleOptionalBindings
from tridentine_calendar_google_sync.google_test_write_auth import (
    GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE,
    TEST_WRITE_GOOGLE_SCOPES,
    authorize_test_google_write,
    load_test_write_authorized_user_token,
    validate_test_write_scopes,
    validate_test_write_token_separation,
)
from tridentine_calendar_google_sync.google_test_write_auth import (
    TestWriteAuthConfigError as AuthConfigError,
)
from tridentine_calendar_google_sync.google_test_write_auth import (
    TestWriteAuthorizationCancelled as AuthorizationCancelled,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    atomic_write_private_text,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)

pytestmark = pytest.mark.google_test_write


def _token_document(scopes: list[str]) -> dict[str, object]:
    return {
        "type": "authorized_user",
        "token": "fixture-access-token-never-used",
        "refresh_token": "fixture-refresh-token-never-used",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "fixture-client-id",
        "client_secret": "fixture-client-secret",
        "scopes": scopes,
    }


def _write_private_json(path: Path, document: dict[str, object]) -> None:
    """Create a synthetic token fixture using the runtime private writer."""

    atomic_write_private_text(path, json.dumps(document))


@dataclass(frozen=True)
class _SyntheticInitialAuthorization:
    client_path: Path
    token_path: Path
    production_read: Path
    production_before: bytes
    document: dict[str, object]
    flow_factory: Mock
    flow_runner: Mock
    bindings: GoogleOptionalBindings

    def authorize(self) -> object:
        return authorize_test_google_write(
            self.client_path,
            self.token_path,
            self.production_read,
            make_test_target_config(),
            bindings=self.bindings,
            flow_runner=self.flow_runner,
        )

    def expected_bytes(self) -> bytes:
        text = json.dumps(
            self.document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return (text + "\n").encode("utf-8")


@pytest.fixture
def initial_authorization(tmp_path: Path, mocker: MockerFixture) -> _SyntheticInitialAuthorization:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    client_path = tmp_path / "fixture-desktop-client.json"
    token_path = tmp_path / "fixture-new-test-write-token.json"
    production_read = tmp_path / "fixture-production-read-token.json"
    document = _token_document(list(TEST_WRITE_GOOGLE_SCOPES))
    document["token"] = "fixture-initial-\N{LATIN SMALL LETTER E WITH ACUTE}"
    _write_private_json(
        client_path,
        {
            "installed": {
                "client_id": document["client_id"],
                "client_secret": document["client_secret"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": document["token_uri"],
                "redirect_uris": ["http://localhost"],
            },
        },
    )
    _write_private_json(production_read, _token_document(list(READ_ONLY_GOOGLE_SCOPES)))
    flow_factory = mocker.Mock(return_value=object())
    flow_runner = mocker.Mock(
        return_value=SimpleNamespace(
            scopes=TEST_WRITE_GOOGLE_SCOPES,
            granted_scopes=TEST_WRITE_GOOGLE_SCOPES,
            to_json=lambda: json.dumps(document),
        ),
    )
    return _SyntheticInitialAuthorization(
        client_path=client_path,
        token_path=token_path,
        production_read=production_read,
        production_before=production_read.read_bytes(),
        document=document,
        flow_factory=flow_factory,
        flow_runner=flow_runner,
        bindings=GoogleOptionalBindings(
            credentials_class=None,
            installed_app_flow_class=SimpleNamespace(from_client_config=flow_factory),
            request_class=None,
            build_service=mocker.Mock(
                side_effect=AssertionError("unexpected service construction"),
            ),
            http_error_class=RuntimeError,
        ),
    )


@pytest.mark.skipif(os.name != "posix", reason="requires real POSIX create-only publisher")
def test_posix_initial_authorization_creates_exact_private_test_token(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
) -> None:
    auth = initial_authorization
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")

    assert auth.authorize() is auth.flow_runner.return_value

    auth.flow_factory.assert_called_once()
    assert auth.flow_factory.call_args.kwargs["scopes"] == list(TEST_WRITE_GOOGLE_SCOPES)
    auth.flow_runner.assert_called_once_with(auth.flow_factory.return_value)
    create.assert_called_once()
    legacy.assert_not_called()
    assert auth.token_path.read_bytes() == auth.expected_bytes()
    info = auth.token_path.stat()
    assert info.st_uid == os.geteuid()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_nlink == 1
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX parent mode")
def test_posix_initial_authorization_rejects_nonprivate_parent_before_flow(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
) -> None:
    auth = initial_authorization
    parent = auth.token_path.parent
    parent.chmod(0o755)
    before = set(parent.iterdir())
    create = mocker.spy(auth_module, "create_private_text")

    with pytest.raises(auth_module.TestWriteTokenPersistenceError) as caught:
        auth.authorize()

    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is False
    assert "0700" in caught.value.public_message
    auth.flow_factory.assert_not_called()
    auth.flow_runner.assert_not_called()
    create.assert_not_called()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert set(parent.iterdir()) == before
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX parent mode")
def test_posix_initial_authorization_rechecks_parent_after_flow(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
) -> None:
    auth = initial_authorization
    parent = auth.token_path.parent
    before = set(parent.iterdir())
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")
    credentials = auth.flow_runner.return_value

    def change_parent(_flow: object) -> object:
        parent.chmod(0o755)
        return credentials

    auth.flow_runner.side_effect = change_parent
    with pytest.raises(auth_module.TestWriteTokenPersistenceError) as caught:
        auth.authorize()

    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is False
    auth.flow_runner.assert_called_once_with(auth.flow_factory.return_value)
    create.assert_called_once()
    legacy.assert_not_called()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert set(parent.iterdir()) == before
    assert auth.production_read.read_bytes() == auth.production_before


def test_initial_authorization_leaves_existing_token_unchanged(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
) -> None:
    auth = initial_authorization
    _write_private_json(auth.token_path, {"synthetic": "existing"})
    before = auth.token_path.read_bytes()
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")

    with pytest.raises(AuthConfigError) as caught:
        auth.authorize()

    assert caught.value.code == "unsafe_test_write_token_path"
    auth.flow_factory.assert_not_called()
    auth.flow_runner.assert_not_called()
    create.assert_not_called()
    legacy.assert_not_called()
    assert auth.token_path.read_bytes() == before
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.parametrize("publication_possible", [False, True, None])
def test_posix_initial_authorization_preserves_publication_evidence(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
    publication_possible: bool | None,
) -> None:
    auth = initial_authorization
    error = auth_module.PrivateCreateIOError(publication_possible=publication_possible)
    error.args = (f"{auth.token_path}: {auth.document['token']}",)

    def fail_create(path: Path, text: str) -> None:
        if publication_possible is not False:
            atomic_write_private_text(path, text)
        raise error

    mocker.patch.object(auth_module, "os", SimpleNamespace(name="posix"))
    preflight = mocker.patch.object(auth_module, "preflight_posix_private_text_create")
    create = mocker.patch.object(auth_module, "create_private_text", side_effect=fail_create)
    legacy = mocker.spy(auth_module, "atomic_write_private_json")
    with pytest.raises(AuthConfigError) as caught:
        auth.authorize()

    assert isinstance(caught.value, auth_module.TestWriteTokenPersistenceError)
    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is publication_possible
    message = caught.value.public_message
    assert message.startswith("Test write credentials could not be persisted safely.")
    assert str(auth.token_path) not in message
    assert str(auth.document["token"]) not in message
    assert str(caught.value) == message
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    preflight.assert_called_once_with(auth.token_path)
    auth.flow_runner.assert_called_once_with(auth.flow_factory.return_value)
    create.assert_called_once()
    legacy.assert_not_called()
    assert auth.production_read.read_bytes() == auth.production_before
    state = {
        False: "This call did not attempt to create the final file.",
        True: "This call attempted to create the final file.",
        None: "The final file creation state is unknown.",
    }
    assert state[publication_possible] in message
    if publication_possible is False:
        assert not auth.token_path.exists()
    else:
        assert "Output may exist" in message
        assert "before reauthorizing, retrying, or deleting files" in message
        assert auth.token_path.read_bytes() == auth.expected_bytes()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows legacy writer")
def test_windows_initial_authorization_keeps_legacy_nonoverwriting_writer(
    initial_authorization: _SyntheticInitialAuthorization,
    mocker: MockerFixture,
) -> None:
    auth = initial_authorization
    preflight = mocker.spy(auth_module, "preflight_posix_private_text_create")
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")

    assert auth.authorize() is auth.flow_runner.return_value

    auth.flow_runner.assert_called_once_with(auth.flow_factory.return_value)
    preflight.assert_not_called()
    create.assert_not_called()
    legacy.assert_called_once()
    assert legacy.call_args.args[0] == auth.token_path
    assert legacy.call_args.kwargs["overwrite"] is False
    assert auth.token_path.read_bytes() == auth.expected_bytes()
    assert auth.production_read.read_bytes() == auth.production_before


def test_test_write_scope_is_exactly_one_owned_events_scope() -> None:
    assert GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE == (
        "https://www.googleapis.com/auth/calendar.events.owned"
    )
    assert TEST_WRITE_GOOGLE_SCOPES == (GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE,)
    assert validate_test_write_scopes(TEST_WRITE_GOOGLE_SCOPES) == TEST_WRITE_GOOGLE_SCOPES


@pytest.mark.parametrize(
    "scopes",
    (
        (),
        ("https://www.googleapis.com/auth/calendar.events.owned.readonly",),
        ("https://www.googleapis.com/auth/calendar.events",),
        ("https://www.googleapis.com/auth/calendar",),
        ("https://www.googleapis.com/auth/calendar.app.created",),
        (
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.owned.readonly",
        ),
        (
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.owned",
        ),
    ),
)
def test_every_missing_readonly_broad_multiple_or_duplicate_scope_is_rejected(
    scopes: tuple[str, ...],
) -> None:
    with pytest.raises(AuthConfigError) as captured:
        validate_test_write_scopes(scopes)
    assert captured.value.code == "unsafe_test_write_scope"


def test_synthetic_exact_scope_token_loads_without_exposing_secret(tmp_path: Path) -> None:
    token_path = tmp_path / "fixture-test-write-token.json"
    document = _token_document([GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE])
    _write_private_json(token_path, document)

    token = load_test_write_authorized_user_token(token_path)

    assert token.scopes == TEST_WRITE_GOOGLE_SCOPES
    rendered = repr(token)
    for value in (
        document["token"],
        document["refresh_token"],
        document["client_id"],
        document["client_secret"],
    ):
        assert str(value) not in rendered


@pytest.mark.parametrize(
    "scopes",
    (
        ["https://www.googleapis.com/auth/calendar.events.owned.readonly"],
        ["https://www.googleapis.com/auth/calendar.events"],
        ["https://www.googleapis.com/auth/calendar"],
        [
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.readonly",
        ],
    ),
)
def test_token_loader_rejects_nonexact_scope_without_secret_echo(
    tmp_path: Path,
    scopes: list[str],
) -> None:
    token_path = tmp_path / "fixture-invalid-test-write-token.json"
    document = _token_document(scopes)
    _write_private_json(token_path, document)

    with pytest.raises(AuthConfigError) as captured:
        load_test_write_authorized_user_token(token_path)
    assert document["refresh_token"] not in str(captured.value)
    assert str(token_path) not in str(captured.value)


_REFRESHED_TEST_TOKEN = "fixture-refreshed-access-token-never-used"


@dataclass(frozen=True)
class _SyntheticRefresh:
    token_path: Path
    production_read: Path
    token_before: bytes
    production_before: bytes
    credentials: SimpleNamespace
    bindings: GoogleOptionalBindings
    request: object

    def load(self) -> object:
        return auth_module.load_test_write_credentials(
            self.token_path,
            self.production_read,
            make_test_target_config(),
            bindings=self.bindings,
        )


def _synthetic_refresh(
    tmp_path: Path,
    mocker: MockerFixture,
    *,
    initially_valid: bool = False,
    refreshed_grants: tuple[str, ...] = TEST_WRITE_GOOGLE_SCOPES,
) -> _SyntheticRefresh:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    test_token = tmp_path / "fixture-test-write-token.json"
    production_read = tmp_path / "fixture-production-read-token.json"
    original = _token_document(list(TEST_WRITE_GOOGLE_SCOPES))
    _write_private_json(test_token, original)
    _write_private_json(production_read, _token_document(list(READ_ONLY_GOOGLE_SCOPES)))
    test_before = test_token.read_bytes()
    production_before = production_read.read_bytes()

    serialized = original.copy()
    credentials = SimpleNamespace(
        valid=initially_valid,
        expired=not initially_valid,
        refresh_token=original["refresh_token"],
        scopes=TEST_WRITE_GOOGLE_SCOPES,
        granted_scopes=TEST_WRITE_GOOGLE_SCOPES,
        to_json=lambda: json.dumps(serialized),
    )

    def refresh(_request: object) -> None:
        credentials.valid = True
        credentials.expired = False
        credentials.granted_scopes = refreshed_grants
        serialized["token"] = _REFRESHED_TEST_TOKEN

    credentials.refresh = mocker.Mock(side_effect=refresh)
    request = object()
    request_class = mocker.Mock(return_value=request)
    bindings = GoogleOptionalBindings(
        credentials_class=SimpleNamespace(
            from_authorized_user_info=mocker.Mock(return_value=credentials)
        ),
        installed_app_flow_class=None,
        request_class=request_class,
        build_service=mocker.Mock(side_effect=AssertionError("unexpected service construction")),
        http_error_class=RuntimeError,
    )
    return _SyntheticRefresh(
        test_token, production_read, test_before, production_before, credentials, bindings, request
    )


@pytest.mark.parametrize(
    ("initially_valid", "refreshed_grants"),
    (
        pytest.param(True, TEST_WRITE_GOOGLE_SCOPES, id="valid-no-write"),
        pytest.param(False, TEST_WRITE_GOOGLE_SCOPES, id="expired-refresh-saved"),
        pytest.param(False, READ_ONLY_GOOGLE_SCOPES, id="refresh-rejects-granted-scope"),
    ),
)
def test_load_test_write_credentials_refresh_persistence(
    tmp_path: Path,
    mocker: MockerFixture,
    initially_valid: bool,
    refreshed_grants: tuple[str, ...],
) -> None:
    auth = _synthetic_refresh(
        tmp_path, mocker, initially_valid=initially_valid, refreshed_grants=refreshed_grants
    )
    credentials = auth.credentials
    request_class = auth.bindings.request_class
    initial_preflight = mocker.spy(auth_module, "preflight_posix_private_text_create")
    refresh_preflight = mocker.spy(auth_module.posix_replace, "preflight_posix_private_replace")
    create = mocker.spy(auth_module, "create_private_text")
    replace = mocker.spy(auth_module.posix_replace, "replace_posix_private_bytes")
    write = mocker.spy(auth_module, "atomic_write_private_json")
    rejects_refresh = refreshed_grants != TEST_WRITE_GOOGLE_SCOPES

    if rejects_refresh:
        with pytest.raises(AuthConfigError) as caught:
            auth.load()
        assert caught.value.code == "unsafe_test_write_scope"
    else:
        assert auth.load() is credentials

    if initially_valid:
        request_class.assert_not_called()
        credentials.refresh.assert_not_called()
    else:
        request_class.assert_called_once_with()
        credentials.refresh.assert_called_once_with(auth.request)

    if os.name == "posix" and not initially_valid:
        refresh_preflight.assert_called_once_with(
            auth.token_path, expected_content=auth.token_before
        )
    else:
        refresh_preflight.assert_not_called()

    if initially_valid or rejects_refresh:
        write.assert_not_called()
        replace.assert_not_called()
        assert auth.token_path.read_bytes() == auth.token_before
    else:
        if os.name == "posix":
            write.assert_not_called()
            replace.assert_called_once()
            assert replace.call_args.args[0] == auth.token_path
            assert replace.call_args.kwargs["expected_content"] == auth.token_before
            # The fixture is deliberately saved with regular json.dumps whitespace and no LF.
            assert not auth.token_before.endswith(b"\n")
            assert b": " in auth.token_before
            original_keys = list(json.loads(auth.token_before))
            assert original_keys != sorted(original_keys)
            saved_stat = auth.token_path.stat()
            assert saved_stat.st_uid == os.geteuid()
            assert stat.S_IMODE(saved_stat.st_mode) == 0o600
            assert saved_stat.st_nlink == 1
        else:
            replace.assert_not_called()
            write.assert_called_once()
            assert write.call_args.args[0] == auth.token_path
            assert write.call_args.kwargs["overwrite"] is True
        saved = json.loads(auth.token_path.read_bytes())
        assert saved["token"] == _REFRESHED_TEST_TOKEN
        assert saved["token"] != json.loads(auth.token_before)["token"]
        assert saved["scopes"] == list(TEST_WRITE_GOOGLE_SCOPES)
    assert auth.production_read.read_bytes() == auth.production_before
    initial_preflight.assert_not_called()
    create.assert_not_called()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX token permissions")
@pytest.mark.parametrize(
    ("parent_mode", "token_mode"),
    [(0o755, 0o600), (0o700, 0o400)],
    ids=["nonprivate-parent", "readonly-token"],
)
def test_posix_refresh_rejects_legacy_permissions_only_when_expired(
    tmp_path: Path, mocker: MockerFixture, parent_mode: int, token_mode: int
) -> None:
    auth = _synthetic_refresh(tmp_path, mocker, initially_valid=True)
    tmp_path.chmod(parent_mode)
    auth.token_path.chmod(token_mode)
    preflight = mocker.spy(auth_module.posix_replace, "preflight_posix_private_replace")
    replace = mocker.spy(auth_module.posix_replace, "replace_posix_private_bytes")
    write = mocker.spy(auth_module, "atomic_write_private_json")

    assert auth.load() is auth.credentials
    preflight.assert_not_called()

    auth.credentials.valid = False
    auth.credentials.expired = True
    with pytest.raises(auth_module.TestWriteTokenRefreshPersistenceError) as caught:
        auth.load()

    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is False
    assert "before the Google refresh request" in caught.value.public_message
    preflight.assert_called_once_with(auth.token_path, expected_content=auth.token_before)
    auth.bindings.request_class.assert_not_called()
    auth.credentials.refresh.assert_not_called()
    replace.assert_not_called()
    write.assert_not_called()
    assert stat.S_IMODE(tmp_path.stat().st_mode) == parent_mode
    assert stat.S_IMODE(auth.token_path.stat().st_mode) == token_mode
    assert auth.token_path.read_bytes() == auth.token_before
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.skipif(os.name != "posix", reason="requires real POSIX replacement")
def test_posix_refresh_keeps_token_updated_during_refresh(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    auth = _synthetic_refresh(tmp_path, mocker)
    finish_refresh = auth.credentials.refresh.side_effect
    concurrent = _token_document(list(TEST_WRITE_GOOGLE_SCOPES))
    concurrent["token"] = "fixture-concurrent-access-token-never-used"
    concurrent_text = json.dumps(concurrent)

    def refresh_with_concurrent_save(request: object) -> None:
        finish_refresh(request)
        atomic_write_private_text(auth.token_path, concurrent_text, overwrite=True)

    auth.credentials.refresh.side_effect = refresh_with_concurrent_save
    replace = mocker.spy(auth_module.posix_replace, "replace_posix_private_bytes")
    write = mocker.spy(auth_module, "atomic_write_private_json")
    with pytest.raises(auth_module.TestWriteTokenRefreshPersistenceError) as caught:
        auth.load()

    assert caught.value.publication_possible is False
    assert "Google refresh succeeded" in caught.value.public_message
    auth.credentials.refresh.assert_called_once_with(auth.request)
    replace.assert_called_once()
    assert replace.call_args.kwargs["expected_content"] == auth.token_before
    write.assert_not_called()
    assert auth.token_path.read_bytes() == concurrent_text.encode("utf-8")
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.parametrize(
    "original_argument",
    [
        pytest.param(dict, id="omitted"),
        pytest.param(lambda: {"expected_token_bytes": "fixture-string"}, id="wrong-type"),
        pytest.param(
            lambda: {"expected_token_bytes": b" " * (MAX_SENSITIVE_FILE_BYTES + 1)},
            id="oversize",
        ),
        pytest.param(lambda: {"expected_token_bytes": b"{fixture-invalid-json"}, id="invalid-json"),
        pytest.param(
            lambda: {
                "expected_token_bytes": json.dumps(
                    _token_document(list(READ_ONLY_GOOGLE_SCOPES))
                ).encode("utf-8")
            },
            id="unsafe-scope",
        ),
    ],
)
def test_simulated_posix_direct_refresh_requires_valid_original_bytes(
    tmp_path: Path, mocker: MockerFixture, original_argument: Callable[[], dict[str, object]]
) -> None:
    auth = _synthetic_refresh(tmp_path, mocker)
    mocker.patch.object(auth_module, "os", SimpleNamespace(name="posix"))
    replace = mocker.patch.object(auth_module.posix_replace, "replace_posix_private_bytes")
    write = mocker.spy(auth_module, "atomic_write_private_json")

    with pytest.raises(AuthConfigError) as caught:
        auth_module.persist_test_write_authorized_user_credentials(
            auth.credentials,
            auth.token_path,
            auth.production_read,
            make_test_target_config(),
            overwrite_for_refresh=True,
            **original_argument(),
        )

    assert isinstance(caught.value, auth_module.TestWriteTokenRefreshPersistenceError)
    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is False
    assert "fixture-" not in caught.value.public_message
    assert "fixture-" not in repr(caught.value)
    replace.assert_not_called()
    write.assert_not_called()
    assert auth.token_path.read_bytes() == auth.token_before
    assert auth.production_read.read_bytes() == auth.production_before


@pytest.mark.parametrize("possible", [False, True, None], ids=["before", "attempted", "unknown"])
def test_simulated_posix_refresh_persistence_failure_preserves_publication_evidence(
    tmp_path: Path, mocker: MockerFixture, possible: bool | None
) -> None:
    auth = _synthetic_refresh(tmp_path, mocker)
    mocker.patch.object(auth_module, "os", SimpleNamespace(name="posix"))
    preflight = mocker.patch.object(auth_module.posix_replace, "preflight_posix_private_replace")
    private_error = "fixture-backend-private-detail"

    def fail(path: Path, content: bytes, *, expected_content: bytes) -> None:
        assert expected_content == auth.token_before
        if possible is not False:
            atomic_write_private_text(path, content.decode("utf-8"), overwrite=True)
        if possible is None:
            raise OSError(private_error)
        raise auth_module.posix_replace.PosixPrivateReplaceError(
            private_error, publication_possible=possible
        )

    replace = mocker.patch.object(
        auth_module.posix_replace, "replace_posix_private_bytes", side_effect=fail
    )
    write = mocker.spy(auth_module, "atomic_write_private_json")
    with pytest.raises(AuthConfigError) as caught:
        auth.load()

    assert isinstance(caught.value, auth_module.TestWriteTokenRefreshPersistenceError)
    assert caught.value.code == "test_write_token_persistence_failed"
    assert caught.value.publication_possible is possible
    assert "Google refresh succeeded" in caught.value.public_message
    assert private_error not in str(caught.value)
    assert private_error not in repr(caught.value)
    preflight.assert_called_once_with(auth.token_path, expected_content=auth.token_before)
    auth.credentials.refresh.assert_called_once_with(auth.request)
    replace.assert_called_once()
    assert replace.call_args.kwargs["expected_content"] == auth.token_before
    write.assert_not_called()
    assert auth.production_read.read_bytes() == auth.production_before
    if possible is False:
        assert auth.token_path.read_bytes() == auth.token_before
    else:
        assert auth.token_path.read_bytes() == replace.call_args.args[1]


def test_test_write_and_production_read_token_paths_must_be_distinct(tmp_path: Path) -> None:
    test_token = tmp_path / "fixture-test-write-token.json"
    production_read = tmp_path / "fixture-production-read-token.json"
    _write_private_json(test_token, {})
    _write_private_json(production_read, {})

    validated_test, validated_read = validate_test_write_token_separation(
        test_token,
        production_read,
        test_token_exists=True,
    )
    assert validated_test != validated_read

    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            production_read,
            production_read,
            test_token_exists=True,
        )


def test_new_test_token_refuses_existing_output_repository_path_and_symlink(
    tmp_path: Path,
) -> None:
    production_read = tmp_path / "fixture-production-read-token.json"
    _write_private_json(production_read, {})
    existing = tmp_path / "existing-test-write-token.json"
    _write_private_json(existing, {})
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            existing,
            production_read,
            test_token_exists=False,
        )
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            REPOSITORY_ROOT / "test-write-token.json",
            production_read,
            test_token_exists=False,
        )

    link = tmp_path / "linked-test-write-token.json"
    try:
        os.symlink(existing, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            link,
            production_read,
            test_token_exists=True,
        )


def test_authorization_cancellation_precedes_path_browser_flow_and_token_creation(
    tmp_path: Path,
) -> None:
    flow_calls = 0

    def forbidden_flow(_flow: object) -> object:
        nonlocal flow_calls
        flow_calls += 1
        raise AssertionError("OAuth flow must not start")

    token_path = tmp_path / "not-created-test-write-token.json"
    with pytest.raises(AuthorizationCancelled):
        authorize_test_google_write(
            tmp_path / "not-read-client.json",
            token_path,
            tmp_path / "not-read-production-token.json",
            make_test_target_config(),
            flow_runner=forbidden_flow,
            cancellation_check=lambda: True,
        )
    assert flow_calls == 0
    assert not token_path.exists()


def test_production_policy_failure_precedes_oauth_flow_and_token_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow_calls = 0

    def reject_target(_target: object) -> str:
        raise TargetPolicyError(
            "production_test_write_target_forbidden",
            "Production Calendar write access is forbidden",
        )

    def forbidden_flow(_flow: object) -> object:
        nonlocal flow_calls
        flow_calls += 1
        raise AssertionError("OAuth flow must not start")

    monkeypatch.setattr(auth_module, "validate_test_write_target_config", reject_target)
    token_path = tmp_path / "not-created-test-write-token.json"
    with pytest.raises(TargetPolicyError):
        authorize_test_google_write(
            tmp_path / "not-read-client.json",
            token_path,
            tmp_path / "not-read-production-token.json",
            make_test_target_config(),
            flow_runner=forbidden_flow,
        )
    assert flow_calls == 0
    assert not token_path.exists()
