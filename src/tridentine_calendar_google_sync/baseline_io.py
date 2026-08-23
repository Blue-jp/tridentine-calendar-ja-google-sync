"""Strict private JSON parsing and atomic storage for trusted baselines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.baseline_engine import (
    BaselineError,
    BaselineInputError,
    BaselineValidationError,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_BASELINE_BYTES = 64 * 1024 * 1024


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _private_baseline_data(baseline: TrustedBaseline) -> dict[str, object]:
    return {
        "schema_version": baseline.schema_version,
        "state": baseline.state.value,
        "tool_version": baseline.tool_version,
        "target_fingerprint": baseline.target_fingerprint,
        "source_profile": baseline.source_profile,
        "accepted_tag": baseline.accepted_tag,
        "accepted_commit": baseline.accepted_commit,
        "source_sha256": baseline.source_sha256,
        "source_event_count": baseline.source_event_count,
        "snapshot_content_hash": baseline.snapshot_content_hash,
        "snapshot_event_count": baseline.snapshot_event_count,
        "diff_content_hash": baseline.diff_content_hash,
        "managed_uid_count": baseline.managed_uid_count,
        "managed_uids": list(baseline.managed_uids),
        "baseline_content_hash": baseline.baseline_content_hash,
    }


def render_baseline_json(baseline: TrustedBaseline) -> str:
    """Render the private baseline document, including its raw UID inventory."""

    verify_baseline_content_hash(baseline)
    return (
        json.dumps(
            _private_baseline_data(baseline),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_baseline_bytes(raw_bytes: bytes) -> TrustedBaseline:
    """Parse, strictly validate, and hash-verify one private baseline document."""

    if len(raw_bytes) > MAX_BASELINE_BYTES:
        raise BaselineInputError(
            "baseline_too_large",
            "baseline exceeds the size limit",
        )
    try:
        decoded = raw_bytes.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        schema_version = value.get("schema_version")
        if schema_version != "1.0":
            raise BaselineValidationError(
                "unsupported_baseline_schema",
                "baseline schema version is unsupported",
            )
        normalized = dict(value)
        state = normalized.get("state")
        if not isinstance(state, str):
            raise TypeError
        normalized["state"] = BaselineState(state)
        managed_uids = normalized.get("managed_uids")
        if not isinstance(managed_uids, list):
            raise TypeError
        normalized["managed_uids"] = tuple(managed_uids)
        baseline = TrustedBaseline.model_validate(normalized, strict=True)
        verify_baseline_content_hash(baseline)
        return baseline
    except BaselineError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise BaselineValidationError(
            "invalid_baseline",
            "baseline is invalid",
        ) from exc


def load_baseline(path: str | Path) -> TrustedBaseline:
    """Load one explicit repository-external baseline path."""

    try:
        raw_bytes = read_sensitive_bytes(path, max_size=MAX_BASELINE_BYTES)
        return parse_baseline_bytes(raw_bytes)
    except BaselineError:
        raise
    except SensitivePathError as exc:
        raise BaselineInputError(
            "unsafe_baseline_path",
            "baseline path is unsafe or unavailable",
        ) from exc


def write_baseline(baseline: TrustedBaseline, path: str | Path) -> Path:
    """Atomically create a private baseline without allowing overwrite."""

    try:
        rendered = render_baseline_json(baseline)
        atomic_write_private_text(
            path,
            rendered,
            overwrite=False,
            max_size=MAX_BASELINE_BYTES,
        )
        return Path(path)
    except BaselineError:
        raise
    except SensitivePathError as exc:
        raise BaselineInputError(
            "baseline_write_failed",
            "baseline could not be written safely",
        ) from exc


__all__ = [
    "MAX_BASELINE_BYTES",
    "load_baseline",
    "parse_baseline_bytes",
    "render_baseline_json",
    "write_baseline",
]
