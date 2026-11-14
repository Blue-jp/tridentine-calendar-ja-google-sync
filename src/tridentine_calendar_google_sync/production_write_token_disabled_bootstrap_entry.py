"""Bind synthetic configuration before pair-only nonauthorizing diagnosis.

Fixture ownership and setup authority are external conditions. This interface
does not authenticate deployment or prevent hostile same-process replacement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inspection import (
    DisabledBootstrapInspectionResult,
    DisabledBootstrapInspectionResultError,
)
from tridentine_calendar_google_sync.production_write_token_enrollment_descriptor import (
    SyntheticEnrollmentExpectation,
)

from .production_write_token_disabled_bootstrap_source_loading import (
    DisabledBootstrapSourceRefusal,
    DisabledBootstrapSourceResultError,
    load_synthetic_disabled_bootstrap,
)

_EXPECTATION_FIELDS = (
    "enrollment_revision",
    "administrative_state",
    "storage_ref",
    "pair_ref",
    "artifact_directory",
    "token_slot",
    "state_slot",
    "active_intent_slot",
    "descriptor_pin",
    "descriptor_slot",
    "administrative_pending_slot",
)


class DisabledBootstrapEntryState(StrEnum):
    CONFIGURATION_REQUIRED = "CONFIGURATION_REQUIRED"
    CONFIGURATION_UNVERIFIABLE = "CONFIGURATION_UNVERIFIABLE"
    REQUEST_UNVERIFIABLE = "REQUEST_UNVERIFIABLE"
    PAIR_MISMATCH = "PAIR_MISMATCH"
    LOADER_FAILED = "LOADER_FAILED"
    LOADER_RESULT_UNVERIFIABLE = "LOADER_RESULT_UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class DisabledBootstrapEntryRefusal:
    """A fixed classification, never configuration approval or a permit."""

    state: DisabledBootstrapEntryState
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not DisabledBootstrapEntryState
            or self.reuse_authorized is not False
            or not any(self.state is member for member in DisabledBootstrapEntryState)
        ):
            raise ValueError("Invalid disabled bootstrap entry refusal")


class DisabledBootstrapEntryResultError(RuntimeError):
    """Fixed terminal error when a refusal cannot be constructed."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("Disabled bootstrap entry result construction failed")

    @property
    def reuse_authorized(self) -> Literal[False]:
        return False


def _refuse(state: DisabledBootstrapEntryState) -> DisabledBootstrapEntryRefusal:
    try:
        return DisabledBootstrapEntryRefusal(state)
    except Exception:
        pass
    failure = DisabledBootstrapEntryResultError()
    try:
        raise failure from None
    except DisabledBootstrapEntryResultError:
        failure.__cause__ = None
        failure.__context__ = None
        raise


@dataclass(frozen=True, slots=True)
class _Plan:
    source_root: str = field(repr=False)
    policy_leaf: str = field(repr=False)
    expected_descriptor_leaf: str = field(repr=False)
    expectation: SyntheticEnrollmentExpectation = field(repr=False)
    expected_control_root: str = field(repr=False)


def _text(value: object, limit: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= limit:
        raise ValueError("Invalid synthetic entry configuration")
    if len(value.encode("utf-8")) > limit:
        raise ValueError("Invalid synthetic entry configuration")
    return value


def _pair_ref(value: object) -> str:
    text = _text(value, 96)
    if (
        not text.isascii()
        or not text[0].isalnum()
        or any(not (char.isalnum() or char in "._-") for char in text)
    ):
        raise ValueError("Invalid synthetic entry pair reference")
    return text


def _pin(value: object) -> str:
    text = _text(value, 64)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError("Invalid synthetic entry pin")
    return text


def _capture_plan(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    expected_control_root: object,
) -> _Plan:
    root = _text(source_root, 1024)
    policy = _text(policy_leaf, 96)
    companion = _text(expected_descriptor_leaf, 96)
    control = _text(expected_control_root, 1024)
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise ValueError("Invalid synthetic entry expectation")
    values: dict[str, object] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise ValueError("Invalid synthetic entry expectation")
    checked = {
        name: _text(value, 1024 if name == "artifact_directory" else 96)
        for name, value in values.items()
    }
    _pin(checked["descriptor_pin"])
    _pair_ref(checked["pair_ref"])
    retained = SyntheticEnrollmentExpectation(**checked)
    return _Plan(root, policy, companion, retained, control)


def _checked_plan(value: object) -> _Plan:
    if type(value) is not _Plan:
        raise ValueError("Invalid retained synthetic entry plan")
    root, policy, companion, expected, control = (
        value.source_root,
        value.policy_leaf,
        value.expected_descriptor_leaf,
        value.expectation,
        value.expected_control_root,
    )
    # Recheck the private held values, never the original setup caller's object.
    return _capture_plan(root, policy, companion, expected, control)


def _copy_diagnostic(
    value: object,
) -> DisabledBootstrapSourceRefusal | DisabledBootstrapInspectionResult:
    if type(value) is DisabledBootstrapSourceRefusal:
        stage, reason, authorized = value.stage, value.reason, value.reuse_authorized
        if authorized is not False:
            raise ValueError("Invalid synthetic entry diagnostic")
        return DisabledBootstrapSourceRefusal(stage, reason)
    if type(value) is DisabledBootstrapInspectionResult:
        state, inputs, observation, authorized = (
            value.state,
            value.input_result,
            value.inspection_result,
            value.reuse_authorized,
        )
        if authorized is not False:
            raise ValueError("Invalid synthetic entry diagnostic")
        return DisabledBootstrapInspectionResult(state, inputs, observation)
    raise ValueError("Invalid synthetic entry diagnostic")


@dataclass(frozen=True, slots=True, init=False)
class SyntheticDisabledBootstrapEntry:
    """A retained diagnostic interface, not installation or execution authority."""

    _plan: _Plan | None = field(init=False, repr=False)

    def __init__(self) -> None:
        if type(self) is not SyntheticDisabledBootstrapEntry:
            raise ValueError("Invalid synthetic disabled bootstrap entry")
        try:
            object.__getattribute__(self, "_plan")
        except AttributeError:
            object.__setattr__(self, "_plan", None)
            return
        raise ValueError("Synthetic disabled bootstrap entry is already initialized")

    @property
    def reuse_authorized(self) -> Literal[False]:
        return False

    def diagnose(
        self,
        requested_pair_ref: object,
    ) -> (
        DisabledBootstrapSourceRefusal
        | DisabledBootstrapInspectionResult
        | DisabledBootstrapEntryRefusal
    ):
        if type(self) is not SyntheticDisabledBootstrapEntry:
            return _refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)
        try:
            held: object = object.__getattribute__(self, "_plan")
        except AttributeError:
            held = None
        except Exception:
            return _refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)
        if held is None:
            return _refuse(DisabledBootstrapEntryState.CONFIGURATION_REQUIRED)
        try:
            plan = _checked_plan(held)
        except Exception:
            return _refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)
        try:
            requested = _pair_ref(requested_pair_ref)
        except Exception:
            return _refuse(DisabledBootstrapEntryState.REQUEST_UNVERIFIABLE)
        if requested != plan.expectation.pair_ref:
            return _refuse(DisabledBootstrapEntryState.PAIR_MISMATCH)
        try:
            result = load_synthetic_disabled_bootstrap(
                plan.source_root,
                plan.policy_leaf,
                plan.expected_descriptor_leaf,
                plan.expectation,
                expected_control_root=plan.expected_control_root,
            )
        except (
            DisabledBootstrapSourceResultError,
            DisabledBootstrapInspectionResultError,
        ) as error:
            if (
                type(error) is DisabledBootstrapSourceResultError
                or type(error) is DisabledBootstrapInspectionResultError
            ):
                raise
            return _refuse(DisabledBootstrapEntryState.LOADER_FAILED)
        except Exception:
            return _refuse(DisabledBootstrapEntryState.LOADER_FAILED)
        try:
            return _copy_diagnostic(result)
        except Exception:
            return _refuse(DisabledBootstrapEntryState.LOADER_RESULT_UNVERIFIABLE)


def bind_synthetic_disabled_bootstrap(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> SyntheticDisabledBootstrapEntry | DisabledBootstrapEntryRefusal:
    """Capture one complete representation; do not read sources or approve it."""
    try:
        plan = _capture_plan(
            source_root, policy_leaf, expected_descriptor_leaf, expectation, expected_control_root
        )
        entry = SyntheticDisabledBootstrapEntry()
        object.__setattr__(entry, "_plan", plan)
    except Exception:
        return _refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)
    return entry
