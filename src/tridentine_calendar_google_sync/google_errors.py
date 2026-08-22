"""Content-free Google client errors safe for logs, reports, and CLI output."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Final

ALLOWED_GOOGLE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "bad_request",
        "backend_error",
        "forbidden",
        "invalid_response",
        "not_found",
        "pagination_cycle",
        "pagination_limit",
        "quota_exceeded",
        "rate_limited",
        "retry_exhausted",
        "service_unavailable",
        "target_mismatch",
        "timeout",
        "transport_error",
        "unauthorized",
        "unknown",
    }
)

ALLOWED_GOOGLE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "client.build",
        "credentials.refresh",
        "events.list",
        "snapshot.sanitize",
        "snapshot.write",
        "target.validate",
    }
)

_RAW_REASON_MAP: Final[dict[str, str]] = {
    "backendError": "backend_error",
    "internalError": "backend_error",
    "quotaExceeded": "quota_exceeded",
    "rateLimitExceeded": "rate_limited",
    "userRateLimitExceeded": "rate_limited",
}
_MAX_ERROR_CONTENT_BYTES = 64 * 1024


class SafeGoogleError(RuntimeError):
    """A minimal allowlisted error that retains no raw exception or response.

    The class intentionally has no URI, headers, response body, request object,
    raw reason, or wrapped ``HttpError`` field.  ``str`` and ``repr`` are built
    only from validated scalar metadata.
    """

    __slots__ = ("attempt", "operation", "reason", "retryable", "status")

    def __init__(
        self,
        *,
        status: int | None,
        reason: str,
        retryable: bool,
        attempt: int,
        operation: str,
    ) -> None:
        if status is not None and not 100 <= status <= 599:
            raise ValueError("status is invalid")
        if reason not in ALLOWED_GOOGLE_REASONS:
            raise ValueError("reason is not allowlisted")
        if operation not in ALLOWED_GOOGLE_OPERATIONS:
            raise ValueError("operation is not allowlisted")
        if attempt < 1:
            raise ValueError("attempt must be positive")
        self.status = status
        self.reason = reason
        self.retryable = retryable
        self.attempt = attempt
        self.operation = operation
        super().__init__(self._safe_message())

    def _safe_message(self) -> str:
        status_text = str(self.status) if self.status is not None else "none"
        retry_text = "yes" if self.retryable else "no"
        return (
            f"Google operation failed: operation={self.operation}; reason={self.reason}; "
            f"status={status_text}; attempt={self.attempt}; retryable={retry_text}"
        )

    def __str__(self) -> str:
        return self._safe_message()

    def __repr__(self) -> str:
        return (
            "SafeGoogleError("
            f"status={self.status!r}, reason={self.reason!r}, "
            f"retryable={self.retryable!r}, attempt={self.attempt!r}, "
            f"operation={self.operation!r})"
        )


def _status_from_exception(error: BaseException) -> int | None:
    try:
        response = getattr(error, "resp", None)
        candidate = getattr(response, "status", None)
        if not isinstance(candidate, int):
            candidate = getattr(error, "status_code", None)
    except Exception:
        return None
    return candidate if isinstance(candidate, int) and 100 <= candidate <= 599 else None


def _mapped_reason(value: object) -> str | None:
    return _RAW_REASON_MAP.get(value) if isinstance(value, str) else None


def _reason_from_details(value: object) -> str | None:
    if isinstance(value, Mapping):
        mapped = _mapped_reason(value.get("reason"))
        if mapped is not None:
            return mapped
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            mapped = _reason_from_details(item)
            if mapped is not None:
                return mapped
    return None


def _reason_from_content(value: object) -> str | None:
    if isinstance(value, bytes):
        if len(value) > _MAX_ERROR_CONTENT_BYTES:
            return None
        try:
            decoded = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    elif isinstance(value, str):
        if len(value.encode("utf-8", errors="ignore")) > _MAX_ERROR_CONTENT_BYTES:
            return None
        decoded = value
    else:
        return None
    try:
        document = json.loads(decoded)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(document, Mapping):
        return None
    error_value = document.get("error")
    if not isinstance(error_value, Mapping):
        return None
    return _reason_from_details(error_value.get("errors"))


def _allowlisted_raw_reason(error: BaseException) -> str | None:
    try:
        candidate = getattr(error, "reason", None)
    except Exception:
        candidate = None
    mapped = _mapped_reason(candidate)
    if mapped is not None:
        return mapped
    try:
        details = getattr(error, "error_details", None)
    except Exception:
        details = None
    mapped = _reason_from_details(details)
    if mapped is not None:
        return mapped
    try:
        content = getattr(error, "content", None)
    except Exception:
        content = None
    return _reason_from_content(content)


def _classify_exception(error: BaseException) -> tuple[int | None, str, bool]:
    status = _status_from_exception(error)
    mapped_reason = _allowlisted_raw_reason(error)
    if mapped_reason is not None:
        return (
            status,
            mapped_reason,
            mapped_reason
            in {
                "backend_error",
                "rate_limited",
            },
        )
    if isinstance(error, TimeoutError):
        return status, "timeout", True
    if isinstance(error, ConnectionError):
        return status, "transport_error", True
    status_map: dict[int, tuple[str, bool]] = {
        400: ("bad_request", False),
        401: ("unauthorized", False),
        403: ("forbidden", False),
        404: ("not_found", False),
        408: ("timeout", True),
        429: ("rate_limited", True),
        500: ("backend_error", True),
        502: ("backend_error", True),
        503: ("service_unavailable", True),
        504: ("timeout", True),
    }
    if status in status_map:
        reason, retryable = status_map[status]
        return status, reason, retryable
    return status, "unknown", False


def safe_google_error_from_exception(
    error: BaseException,
    *,
    attempt: int,
    operation: str,
) -> SafeGoogleError:
    """Map an arbitrary exception without reading or retaining its string/body."""

    if isinstance(error, SafeGoogleError):
        return SafeGoogleError(
            status=error.status,
            reason=error.reason,
            retryable=error.retryable,
            attempt=attempt,
            operation=operation,
        )
    status, reason, retryable = _classify_exception(error)
    return SafeGoogleError(
        status=status,
        reason=reason,
        retryable=retryable,
        attempt=attempt,
        operation=operation,
    )


__all__ = [
    "ALLOWED_GOOGLE_OPERATIONS",
    "ALLOWED_GOOGLE_REASONS",
    "SafeGoogleError",
    "safe_google_error_from_exception",
]
