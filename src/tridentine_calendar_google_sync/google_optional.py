"""Completely lazy access to the optional official Google Python packages."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType
from typing import Any

ModuleImporter = Callable[[str], ModuleType]


class GoogleOptionalDependencyError(RuntimeError):
    """Missing or incompatible optional dependency without installation-path leakage."""

    def __init__(self) -> None:
        self.code = "google_optional_dependencies_unavailable"
        self.public_message = (
            "Google read-only support is unavailable; install the declared google-read extra"
        )
        super().__init__(self.public_message)


@dataclass(frozen=True, slots=True)
class GoogleOptionalBindings:
    """Injected Google entry points used by authentication and read-only fetching."""

    credentials_class: Any
    installed_app_flow_class: Any
    request_class: Any
    build_service: Callable[..., Any]
    http_error_class: type[Exception]


def _required_attribute(module: ModuleType, name: str) -> Any:
    try:
        return vars(module)[name]
    except KeyError as exc:
        raise AttributeError from exc


def _default_importer(module_name: str) -> ModuleType:
    return importlib.import_module(module_name)


def load_google_optional_bindings(
    *,
    importer: ModuleImporter = _default_importer,
) -> GoogleOptionalBindings:
    """Import official Google libraries only when an online command explicitly calls this."""

    try:
        credentials_module = importer("google.oauth2.credentials")
        flow_module = importer("google_auth_oauthlib.flow")
        transport_module = importer("google.auth.transport.requests")
        discovery_module = importer("googleapiclient.discovery")
        errors_module = importer("googleapiclient.errors")
        credentials_class = _required_attribute(credentials_module, "Credentials")
        installed_app_flow_class = _required_attribute(flow_module, "InstalledAppFlow")
        request_class = _required_attribute(transport_module, "Request")
        build_service = _required_attribute(discovery_module, "build")
        http_error_class = _required_attribute(errors_module, "HttpError")
        if not isinstance(http_error_class, type) or not issubclass(
            http_error_class,
            Exception,
        ):
            raise TypeError
        if not callable(build_service):
            raise TypeError
    except (ImportError, AttributeError, TypeError) as exc:
        raise GoogleOptionalDependencyError from exc
    return GoogleOptionalBindings(
        credentials_class=credentials_class,
        installed_app_flow_class=installed_app_flow_class,
        request_class=request_class,
        build_service=build_service,
        http_error_class=http_error_class,
    )


__all__ = [
    "GoogleOptionalBindings",
    "GoogleOptionalDependencyError",
    "ModuleImporter",
    "load_google_optional_bindings",
]
