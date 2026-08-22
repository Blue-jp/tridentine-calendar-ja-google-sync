"""Load strict Accepted source profiles from trusted local TOML files."""

from __future__ import annotations

import re
import tomllib
from copy import deepcopy
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.models import AcceptedSourceProfile

_PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PROFILE_SIZE_LIMIT = 1024 * 1024


class ProfileError(ValueError):
    """A configuration failure whose text is safe for normal CLI output."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _reject_nonlocal_text_path(value: str) -> None:
    lowered = value.casefold()
    if "://" in value or lowered.startswith("file:") or value.startswith(("\\\\", "//")):
        raise ProfileError("nonlocal_profile_path", "profile directory must be a local path")
    if "\x00" in value:
        raise ProfileError("invalid_profile_path", "profile directory is invalid")


def _read_profile_path(path: Path) -> bytes:
    try:
        if path.is_symlink():
            raise ProfileError("profile_symlink", "symbolic-link profiles are not accepted")
        stat_result = path.stat()
        if not path.is_file():
            raise ProfileError("profile_not_file", "profile is not a regular file")
        if stat_result.st_size > _PROFILE_SIZE_LIMIT:
            raise ProfileError("profile_too_large", "profile exceeds the size limit")
        raw = path.read_bytes()
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError("profile_unavailable", "profile is unavailable") from exc
    if len(raw) > _PROFILE_SIZE_LIMIT:
        raise ProfileError("profile_too_large", "profile exceeds the size limit")
    return raw


def _parse_profile(raw: bytes, requested_profile_id: str) -> AcceptedSourceProfile:
    try:
        text = raw.decode("utf-8", errors="strict")
        loaded = tomllib.loads(text)
        data: dict[str, Any] = deepcopy(loaded)
        expected = data.get("expected")
        if not isinstance(expected, dict):
            raise TypeError
        for field_name in ("first_date", "last_date"):
            field_value = expected.get(field_name)
            if isinstance(field_value, str):
                expected[field_name] = date.fromisoformat(field_value)
        profile = AcceptedSourceProfile.model_validate(data, strict=True)
    except (
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ProfileError("invalid_profile", "profile is not valid") from exc
    if profile.profile_id != requested_profile_id:
        raise ProfileError("profile_identity_mismatch", "profile identity does not match request")
    return profile


def _default_profile_bytes(profile_id: str) -> bytes:
    filename = f"{profile_id}.toml"
    package_candidate = resources.files("tridentine_calendar_google_sync").joinpath(
        "_profiles", filename
    )
    try:
        if package_candidate.is_file():
            return package_candidate.read_bytes()
    except OSError:
        pass

    editable_candidate = Path(__file__).resolve().parents[2] / "profiles" / filename
    if editable_candidate.is_file():
        return _read_profile_path(editable_candidate)
    raise ProfileError("profile_not_found", "requested profile is unavailable")


def load_profile(
    profile_id: str,
    profiles_dir: str | Path | None = None,
) -> AcceptedSourceProfile:
    """Load ``profile_id`` from an explicit directory or packaged defaults.

    Profile IDs are restricted before path construction to prevent traversal.
    Explicit directories must be normal local paths; URL and ``file://`` forms
    are rejected.  No attempted path is included in a raised error.
    """

    if not _PROFILE_ID_PATTERN.fullmatch(profile_id):
        raise ProfileError("invalid_profile_id", "profile identifier is invalid")
    if profiles_dir is None:
        raw = _default_profile_bytes(profile_id)
    else:
        if isinstance(profiles_dir, str):
            _reject_nonlocal_text_path(profiles_dir)
        directory = Path(profiles_dir)
        try:
            if directory.is_symlink():
                raise ProfileError(
                    "profile_directory_symlink",
                    "symbolic-link profile directories are not accepted",
                )
        except OSError as exc:
            raise ProfileError("profile_unavailable", "profile is unavailable") from exc
        raw = _read_profile_path(directory / f"{profile_id}.toml")
    return _parse_profile(raw, profile_id)


__all__ = ["ProfileError", "load_profile"]
