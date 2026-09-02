"""Strict repository-external storage for Production write-token state."""

from __future__ import annotations

import hmac
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenConfigError,
    private_production_write_token_generation_state_data,
    validate_production_token_role,
    validate_production_write_scopes,
    verify_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionTokenRole,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteTokenGenerationState,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
    remove_sensitive_file_if_matches,
    sensitive_path_identity,
    validate_sensitive_input_path,
    validate_sensitive_output_path,
)

MAX_PRODUCTION_WRITE_TOKEN_BYTES = 256 * 1024
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class ProductionWriteTokenIOError(ProductionWriteTokenConfigError):
    """A path-free token or generation-state I/O failure."""


class _DuplicateJsonKey(ValueError):
    pass


def _require_private_file_mode(path: Path) -> None:
    """Reject group/other POSIX access; Windows is checked on the open handle."""

    if os.name != "posix":
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        raise SensitivePathError(
            "sensitive_path_unavailable",
            "sensitive path cannot be safely inspected",
        ) from None
    if mode & 0o077:
        raise SensitivePathError(
            "sensitive_input_permissions_unsafe",
            "sensitive input permissions are unsafe",
        )


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _decode_json(raw_bytes: bytes, fields: set[str]) -> dict[str, Any]:
    if len(raw_bytes) > MAX_PRODUCTION_WRITE_TOKEN_BYTES:
        raise ProductionWriteTokenIOError(
            "production_write_token_artifact_too_large",
            "Production write-token artifact is too large",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict) or set(value) != fields:
            raise TypeError
        return cast(dict[str, Any], value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
    ) as exc:
        raise ProductionWriteTokenIOError(
            "invalid_production_write_token_artifact",
            "Production write-token artifact is invalid or noncanonical",
        ) from exc


def _render(data: dict[str, object]) -> str:
    return (
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def _require_canonical(raw_bytes: bytes, rendered: str) -> None:
    if not hmac.compare_digest(raw_bytes, rendered.encode("utf-8")):
        raise ProductionWriteTokenIOError(
            "noncanonical_production_write_token_artifact",
            "Production write-token artifact is invalid or noncanonical",
        )


def private_production_write_authorized_user_token_data(
    token: ProductionWriteAuthorizedUserToken,
) -> dict[str, object]:
    """Return the private on-disk document; callers must never log this value."""

    return {
        "schema_version": token.schema_version,
        "token_type": token.token_type,
        "role": token.role.value,
        "target_safe_ref": token.target_safe_ref,
        "target_config_hash": token.target_config_hash,
        "generation": token.generation,
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "client_id": token.client_id,
        "client_secret": token.client_secret,
        "token_uri": token.token_uri,
        "scopes": list(token.scopes),
        "grant_evidence": {
            "schema_version": token.grant_evidence.schema_version,
            "evidence_type": token.grant_evidence.evidence_type,
            "origin": token.grant_evidence.origin.value,
            "response_scope_field_present": (token.grant_evidence.response_scope_field_present),
            "raw_scope_tokens": list(token.grant_evidence.raw_scope_tokens),
            "granted_scopes": list(token.grant_evidence.granted_scopes),
            "observed_at": token.grant_evidence.observed_at.isoformat(),
        },
        "expiry": token.expiry.isoformat(),
    }


def render_production_write_authorized_user_token_json(
    token: ProductionWriteAuthorizedUserToken,
) -> str:
    """Render the private canonical token document for secure storage only."""

    return _render(private_production_write_authorized_user_token_data(token))


_TOKEN_FIELDS = {
    "schema_version",
    "token_type",
    "role",
    "target_safe_ref",
    "target_config_hash",
    "generation",
    "access_token",
    "refresh_token",
    "client_id",
    "client_secret",
    "token_uri",
    "scopes",
    "grant_evidence",
    "expiry",
}

_GRANT_EVIDENCE_FIELDS = {
    "schema_version",
    "evidence_type",
    "origin",
    "response_scope_field_present",
    "raw_scope_tokens",
    "granted_scopes",
    "observed_at",
}


def parse_production_write_authorized_user_token_bytes(
    raw_bytes: bytes,
) -> ProductionWriteAuthorizedUserToken:
    """Parse one exact-role token without echoing secret content on failure."""

    data = _decode_json(raw_bytes, _TOKEN_FIELDS)
    try:
        scopes = data["scopes"]
        evidence_data = data["grant_evidence"]
        if not isinstance(scopes, list) or not isinstance(evidence_data, dict):
            raise TypeError
        if set(evidence_data) != _GRANT_EVIDENCE_FIELDS:
            raise TypeError
        raw_scope_tokens = evidence_data["raw_scope_tokens"]
        granted_scopes = evidence_data["granted_scopes"]
        if not isinstance(raw_scope_tokens, list) or not isinstance(granted_scopes, list):
            raise TypeError
        if ProductionTokenRole(data["role"]) is not ProductionTokenRole.PRODUCTION_WRITE:
            raise ValueError
        grant_evidence = ProductionWriteGrantedScopeEvidence(
            schema_version=evidence_data["schema_version"],
            evidence_type=evidence_data["evidence_type"],
            origin=ProductionWriteGrantEvidenceOrigin(evidence_data["origin"]),
            response_scope_field_present=evidence_data["response_scope_field_present"],
            raw_scope_tokens=tuple(raw_scope_tokens),
            granted_scopes=tuple(granted_scopes),
            observed_at=datetime.fromisoformat(evidence_data["observed_at"]),
        )
        token = ProductionWriteAuthorizedUserToken(
            schema_version=data["schema_version"],
            token_type=data["token_type"],
            role=ProductionTokenRole.PRODUCTION_WRITE,
            target_safe_ref=data["target_safe_ref"],
            target_config_hash=data["target_config_hash"],
            generation=data["generation"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            token_uri=data["token_uri"],
            scopes=tuple(scopes),
            grant_evidence=grant_evidence,
            expiry=datetime.fromisoformat(data["expiry"]),
        )
        _require_canonical(raw_bytes, render_production_write_authorized_user_token_json(token))
        return token
    except ProductionWriteTokenIOError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionWriteTokenIOError(
            "invalid_production_write_authorized_user_token",
            "Production write authorized-user token is invalid or noncanonical",
        ) from exc


def load_production_write_authorized_user_token(
    path: str | Path,
) -> ProductionWriteAuthorizedUserToken:
    """Load one explicit repository-external token path with no fallback search."""

    try:
        validated = Path(path)
        _reject_repository_parent(validated)
        _require_private_file_mode(validated)
        return parse_production_write_authorized_user_token_bytes(
            read_sensitive_bytes(
                validated,
                max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
                windows_private_acl=True,
                windows_require_protected_acl=True,
            )
        )
    except ProductionWriteTokenIOError:
        raise
    except SensitivePathError:
        raise ProductionWriteTokenIOError(
            "unsafe_production_write_token_path",
            "Production write-token path is unsafe or unavailable",
        ) from None


def write_production_write_authorized_user_token(
    token: ProductionWriteAuthorizedUserToken,
    path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Atomically persist one private token with no overwrite by default."""

    try:
        validated = validate_sensitive_output_path(
            path,
            overwrite=overwrite,
            windows_require_existing_protected_acl=True,
        )
        _reject_repository_parent(validated)
        atomic_write_private_text(
            validated,
            render_production_write_authorized_user_token_json(token),
            overwrite=overwrite,
            max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
            windows_require_existing_protected_acl=True,
        )
        return validated
    except SensitivePathError:
        raise ProductionWriteTokenIOError(
            "production_write_token_write_failed",
            "Production write token could not be persisted safely",
        ) from None


_GENERATION_FIELDS = {
    "schema_version",
    "state_type",
    "role",
    "target_safe_ref",
    "target_config_hash",
    "generation",
    "issued_at",
    "predecessor_state_hash",
    "content_hash",
}


def render_production_write_token_generation_state_json(
    state: ProductionWriteTokenGenerationState,
) -> str:
    verify_production_write_token_generation_state(state)
    return _render(private_production_write_token_generation_state_data(state))


def parse_production_write_token_generation_state_bytes(
    raw_bytes: bytes,
) -> ProductionWriteTokenGenerationState:
    data = _decode_json(raw_bytes, _GENERATION_FIELDS)
    try:
        if ProductionTokenRole(data["role"]) is not ProductionTokenRole.PRODUCTION_WRITE:
            raise ValueError
        state = ProductionWriteTokenGenerationState(
            schema_version=data["schema_version"],
            state_type=data["state_type"],
            role=ProductionTokenRole.PRODUCTION_WRITE,
            target_safe_ref=data["target_safe_ref"],
            target_config_hash=data["target_config_hash"],
            generation=data["generation"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            predecessor_state_hash=data["predecessor_state_hash"],
            content_hash=data["content_hash"],
        )
        verify_production_write_token_generation_state(state)
        _require_canonical(raw_bytes, render_production_write_token_generation_state_json(state))
        return state
    except ProductionWriteTokenIOError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionWriteTokenIOError(
            "invalid_production_write_token_generation_state",
            "Production write-token generation state is invalid or noncanonical",
        ) from exc


def load_production_write_token_generation_state(
    path: str | Path,
) -> ProductionWriteTokenGenerationState:
    try:
        validated = Path(path)
        _reject_repository_parent(validated)
        _require_private_file_mode(validated)
        return parse_production_write_token_generation_state_bytes(
            read_sensitive_bytes(
                validated,
                max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
                windows_integrity_acl=True,
            )
        )
    except ProductionWriteTokenIOError:
        raise
    except SensitivePathError:
        raise ProductionWriteTokenIOError(
            "unsafe_production_write_token_generation_path",
            "Production write-token generation path is unsafe or unavailable",
        ) from None


def write_production_write_token_generation_state(
    state: ProductionWriteTokenGenerationState,
    path: str | Path,
) -> Path:
    """Atomically create immutable generation state; overwrite is never accepted."""

    try:
        validated = validate_sensitive_output_path(path, overwrite=False)
        _reject_repository_parent(validated)
        atomic_write_private_text(
            validated,
            render_production_write_token_generation_state_json(state),
            overwrite=False,
            max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
        )
        return validated
    except SensitivePathError:
        raise ProductionWriteTokenIOError(
            "production_write_token_generation_write_failed",
            "Production write-token generation state could not be written safely",
        ) from None


def _remove_exact_new_artifact(
    path: Path,
    expected: bytes,
    *,
    private: bool,
    integrity: bool,
) -> bool:
    """Remove only a regular, non-symlink artifact matching this invocation."""

    try:
        return remove_sensitive_file_if_matches(
            path,
            expected,
            max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
            windows_private_acl=private,
            windows_integrity_acl=integrity,
            windows_require_protected_acl=private,
        )
    except (OSError, SensitivePathError):
        return False


def write_production_write_token_bundle(
    token: ProductionWriteAuthorizedUserToken,
    token_path: str | Path,
    state: ProductionWriteTokenGenerationState,
    generation_state_path: str | Path,
) -> tuple[Path, Path]:
    """Create token and generation state as a coordinated no-overwrite pair.

    Generation state is published first so a second-write failure never requires
    retaining newly issued token material.  On an ordinary exception, only exact
    artifacts absent at preflight and matching this invocation are removed.
    """

    token_output = Path(token_path)
    state_output = Path(generation_state_path)
    verify_production_write_token_generation_state(state)
    validate_production_token_role(token.role)
    validate_production_write_scopes(token.scopes)
    validate_production_write_scopes(token.granted_scopes)
    if not (
        token.generation == state.generation
        and hmac.compare_digest(token.target_safe_ref, state.target_safe_ref)
        and hmac.compare_digest(token.target_config_hash, state.target_config_hash)
    ):
        raise ProductionWriteTokenIOError(
            "production_write_token_bundle_binding_mismatch",
            "Production write token and generation state do not match",
        )
    try:
        validated_token = validate_sensitive_output_path(token_output, overwrite=False)
        validated_state = validate_sensitive_output_path(state_output, overwrite=False)
        _reject_repository_parent(validated_token)
        _reject_repository_parent(validated_state)
        if sensitive_path_identity(
            validated_token,
            exists=False,
        ) == sensitive_path_identity(
            validated_state,
            exists=False,
        ):
            raise SensitivePathError(
                "production_write_token_bundle_path_collision",
                "Production write-token bundle paths must be distinct",
            )
    except (OSError, SensitivePathError):
        raise ProductionWriteTokenIOError(
            "unsafe_production_write_token_bundle_paths",
            "Production write-token bundle paths are unsafe or unavailable",
        ) from None

    state_bytes = render_production_write_token_generation_state_json(state).encode("utf-8")
    token_bytes = render_production_write_authorized_user_token_json(token).encode("utf-8")
    state_created = False
    token_attempted = False
    try:
        write_production_write_token_generation_state(state, validated_state)
        state_created = True
        token_attempted = True
        write_production_write_authorized_user_token(
            token,
            validated_token,
            overwrite=False,
        )
    except Exception as exc:
        token_removed = (
            _remove_exact_new_artifact(
                validated_token,
                token_bytes,
                private=True,
                integrity=False,
            )
            if token_attempted
            else True
        )
        state_removed = (
            _remove_exact_new_artifact(
                validated_state,
                state_bytes,
                private=False,
                integrity=True,
            )
            if state_created
            else True
        )
        if not token_removed or not state_removed:
            raise ProductionWriteTokenIOError(
                "production_write_token_bundle_recovery_failed",
                "Production write-token bundle could not be recovered safely",
            ) from exc
        raise
    return validated_token, validated_state


def _validate_reserved_path(
    path: str | Path,
    *,
    exists: bool,
    require_private: bool = False,
    require_integrity: bool = False,
) -> Path:
    if exists:
        validated = validate_sensitive_input_path(
            path,
            max_size=MAX_PRODUCTION_WRITE_TOKEN_BYTES,
            windows_private_acl=require_private,
            windows_integrity_acl=require_integrity,
            windows_require_protected_acl=require_private,
        )
        if require_private:
            _require_private_file_mode(validated)
        return validated
    return validate_sensitive_output_path(path, overwrite=False)


def _reject_repository_parent(path: Path) -> None:
    try:
        resolved = path.resolve(strict=False)
        repository_parent = _REPOSITORY_ROOT.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise SensitivePathError(
            "sensitive_path_unavailable",
            "sensitive path cannot be safely inspected",
        ) from None
    if resolved.is_relative_to(repository_parent):
        raise SensitivePathError(
            "sensitive_path_in_repository_parent",
            "sensitive data must not be stored in the repository parent",
        )


def validate_production_write_token_path_set(
    *,
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    client_config_path: str | Path | None,
    write_token_exists: bool,
    generation_state_exists: bool,
) -> tuple[Path, Path, Path, Path, Path | None]:
    """Require explicit, repository-external, symlink-free, pairwise-distinct paths."""

    try:
        write_path = _validate_reserved_path(
            production_write_token_path,
            exists=write_token_exists,
            require_private=write_token_exists,
        )
        generation_path = _validate_reserved_path(
            generation_state_path,
            exists=generation_state_exists,
            require_private=False,
            require_integrity=generation_state_exists,
        )
        read_path = _validate_reserved_path(
            production_read_token_path,
            exists=Path(production_read_token_path).exists(),
        )
        test_path = _validate_reserved_path(
            test_write_token_path,
            exists=Path(test_write_token_path).exists(),
        )
        client_path = (
            validate_sensitive_input_path(
                client_config_path,
                windows_private_acl=True,
            )
            if client_config_path is not None
            else None
        )
        if client_path is not None:
            _require_private_file_mode(client_path)
        paths = (write_path, generation_path, read_path, test_path)
        for path in (*paths, *((client_path,) if client_path is not None else ())):
            _reject_repository_parent(path)
        identities = [
            sensitive_path_identity(
                write_path,
                exists=write_token_exists,
                windows_private_acl=write_token_exists,
                windows_require_protected_acl=write_token_exists,
            ),
            sensitive_path_identity(
                generation_path,
                exists=generation_state_exists,
                windows_integrity_acl=generation_state_exists,
            ),
            sensitive_path_identity(read_path, exists=read_path.exists()),
            sensitive_path_identity(test_path, exists=test_path.exists()),
        ]
        if client_path is not None:
            identities.append(
                sensitive_path_identity(
                    client_path,
                    exists=True,
                    windows_private_acl=True,
                )
            )
        if len(set(identities)) != len(identities):
            raise SensitivePathError(
                "production_token_paths_not_distinct",
                "Production token role and credential paths must be distinct",
            )
        return write_path, generation_path, read_path, test_path, client_path
    except ProductionWriteTokenIOError:
        raise
    except (OSError, SensitivePathError):
        raise ProductionWriteTokenIOError(
            "unsafe_production_write_token_path_set",
            "Production token role paths are unsafe or not distinct",
        ) from None


__all__ = [
    "MAX_PRODUCTION_WRITE_TOKEN_BYTES",
    "ProductionWriteTokenIOError",
    "load_production_write_authorized_user_token",
    "load_production_write_token_generation_state",
    "parse_production_write_authorized_user_token_bytes",
    "parse_production_write_token_generation_state_bytes",
    "private_production_write_authorized_user_token_data",
    "render_production_write_authorized_user_token_json",
    "render_production_write_token_generation_state_json",
    "validate_production_write_token_path_set",
    "write_production_write_authorized_user_token",
    "write_production_write_token_bundle",
    "write_production_write_token_generation_state",
]
