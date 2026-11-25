from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture

from tridentine_calendar_google_sync import cli, google_auth
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    SensitivePathError,
)

pytestmark = [
    pytest.mark.google_read,
    pytest.mark.skipif(os.name != "posix", reason="requires real POSIX token I/O"),
]

_SCOPES = google_auth.READ_ONLY_GOOGLE_SCOPES
_CLIENT = {
    "installed": {
        "client_id": "synthetic-client",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": "synthetic-client-secret",
        "redirect_uris": ["http://localhost"],
    }
}
_NEW_TOKEN = {
    "type": "authorized_user",
    "token": "synthetic-new-token",
    "refresh_token": "synthetic-new-refresh-token",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "synthetic-client-\N{LATIN SMALL LETTER E WITH ACUTE}",
    "client_secret": "synthetic-client-secret",
    "scopes": list(_SCOPES),
}
_OLD = b'{"token":'
_COMPETITOR = b"synthetic-competitor"


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


@dataclass(repr=False)
class _Authorization:
    client: Path
    destination: Path
    factory: Mock
    oauth: Mock
    preflight: Mock
    replace: Mock
    create: Mock
    legacy: Mock

    def run(self) -> int:
        return cli.main(
            [
                "authorize-google-readonly",
                "--online",
                "--credentials-file",
                str(self.client),
                "--token-file",
                str(self.destination),
                "--overwrite-token",
            ]
        )

    def assert_no_fallback(self) -> None:
        self.create.assert_not_called()
        self.legacy.assert_not_called()


@pytest.fixture
def authorization(tmp_path: Path, mocker: MockerFixture) -> _Authorization:
    root = tmp_path.resolve()
    parent = root / "synthetic-private"
    parent.mkdir()
    parent.chmod(0o700)
    client = root / "synthetic-client.json"
    destination = parent / "synthetic-token.json"
    _write_private(client, json.dumps(_CLIENT).encode("utf-8"))
    _write_private(destination, _OLD)
    credentials = SimpleNamespace(
        scopes=_SCOPES,
        granted_scopes=_SCOPES,
        to_json=lambda: json.dumps(_NEW_TOKEN),
    )
    oauth = mocker.Mock(return_value=credentials)
    factory = mocker.Mock(return_value=SimpleNamespace(run_local_server=oauth))
    mocker.patch.object(
        google_auth,
        "load_google_optional_bindings",
        return_value=SimpleNamespace(
            installed_app_flow_class=SimpleNamespace(from_client_config=factory),
        ),
    )
    return _Authorization(
        client=client,
        destination=destination,
        factory=factory,
        oauth=oauth,
        preflight=mocker.spy(google_auth.posix_replace, "preflight_posix_private_replace"),
        replace=mocker.spy(google_auth.posix_replace, "replace_posix_private_bytes"),
        create=mocker.spy(google_auth, "create_private_text"),
        legacy=mocker.spy(google_auth, "persist_authorized_user_credentials"),
    )


@pytest.mark.parametrize(
    "case",
    ["invalid-json", "invalid-utf8", "empty", "exactly-4-mib"],
)
def test_posix_cli_overwrite_recovers_opaque_old_bytes(
    authorization: _Authorization, case: str
) -> None:
    if case == "exactly-4-mib":
        old = b"x" * MAX_SENSITIVE_FILE_BYTES
    else:
        old = {"invalid-json": _OLD, "invalid-utf8": b"\xff", "empty": b""}[case]
    _write_private(authorization.destination, old)
    expected = (
        json.dumps(_NEW_TOKEN, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    assert authorization.run() == cli.EXIT_VALID

    authorization.factory.assert_called_once()
    assert authorization.factory.call_args.kwargs["scopes"] == list(_SCOPES)
    authorization.oauth.assert_called_once()
    authorization.preflight.assert_called_once_with(authorization.destination, expected_content=old)
    authorization.replace.assert_called_once_with(
        authorization.destination, expected, expected_content=old
    )
    authorization.assert_no_fallback()
    assert authorization.destination.read_bytes() == expected
    published = authorization.destination.stat()
    assert stat.S_IMODE(published.st_mode) == 0o600
    assert published.st_uid == os.geteuid()
    assert published.st_nlink == 1


@pytest.mark.parametrize("case", ["parent-0755", "file-0400", "read-failed", "over-4-mib"])
def test_posix_cli_overwrite_rejects_ineligible_file_before_oauth(
    authorization: _Authorization,
    case: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = authorization.destination
    old = _OLD
    if case == "parent-0755":
        destination.parent.chmod(0o755)
    elif case == "file-0400":
        destination.chmod(0o400)
    elif case == "over-4-mib":
        old = b"x" * (MAX_SENSITIVE_FILE_BYTES + 1)
        _write_private(destination, old)
    else:
        read = google_auth.read_private_sensitive_bytes

        def read_with_failure(path: str | Path, **kwargs: object) -> bytes:
            if Path(path) == destination:
                raise SensitivePathError("read_failed", f"injected read failure: {destination}")
            return read(path, **kwargs)

        monkeypatch.setattr(google_auth, "read_private_sensitive_bytes", read_with_failure)

    assert authorization.run() == 4

    authorization.factory.assert_not_called()
    authorization.oauth.assert_not_called()
    authorization.replace.assert_not_called()
    authorization.assert_no_fallback()
    assert destination.read_bytes() == old
    output = capsys.readouterr()
    assert "before" in output.err.lower()
    assert "authorization completed" not in output.out.lower()
    assert str(destination) not in output.out + output.err
    assert "injected read failure" not in output.err


@pytest.mark.parametrize("change", ["removed", "different-content"])
def test_posix_cli_overwrite_preserves_destination_change_during_oauth(
    authorization: _Authorization, change: str, capsys: pytest.CaptureFixture[str]
) -> None:
    destination = authorization.destination

    def mutate_destination(**_kwargs: object) -> object:
        if change == "removed":
            destination.unlink()
        else:
            _write_private(destination, _COMPETITOR)
        return authorization.oauth.return_value

    authorization.oauth.side_effect = mutate_destination

    assert authorization.run() == 4

    authorization.factory.assert_called_once()
    authorization.oauth.assert_called_once()
    authorization.preflight.assert_called_once_with(
        authorization.destination, expected_content=_OLD
    )
    authorization.replace.assert_called_once()
    assert authorization.replace.call_args.kwargs["expected_content"] == _OLD
    authorization.assert_no_fallback()
    if change == "removed":
        assert not destination.exists()
        assert list(destination.parent.iterdir()) == []
    else:
        assert destination.read_bytes() == _COMPETITOR
        assert list(destination.parent.iterdir()) == [destination]
    output = capsys.readouterr()
    assert "did not attempt" in output.err.lower()
    assert "authorization completed" not in output.out.lower()
    assert str(destination) not in output.out + output.err
