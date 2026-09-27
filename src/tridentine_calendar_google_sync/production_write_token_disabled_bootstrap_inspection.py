"""Handoff retained synthetic inputs to one nonauthorizing observation.

Fixture ownership and separation are caller preconditions, not facts proved by
matching inputs. This component never supplies operational or restart authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, cast

from tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inputs import (
    DisabledBootstrapInputResult,
    DisabledBootstrapInputState,
    validate_disabled_bootstrap_inputs,
)
from tridentine_calendar_google_sync.production_write_token_enrollment_descriptor import (
    SyntheticEnrollmentExpectation,
)
from tridentine_calendar_google_sync.production_write_token_enrollment_preparation import (
    LeafObservation,
    PreparationInspection,
    inspect_synthetic_enrollment_preparation,
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


class DisabledBootstrapInspectionState(StrEnum):
    CAPTURE_REFUSED = "CAPTURE_REFUSED"
    VALIDATION_REFUSED = "VALIDATION_REFUSED"
    VALIDATION_UNVERIFIABLE = "VALIDATION_UNVERIFIABLE"
    INSPECTION_FAILED = "INSPECTION_FAILED"
    INSPECTION_RESULT_UNVERIFIABLE = "INSPECTION_RESULT_UNVERIFIABLE"
    INSPECTION_OBSERVED = "INSPECTION_OBSERVED"


@dataclass(frozen=True, slots=True)
class _CapturedInputs:
    policy_raw: bytes = field(repr=False)
    expected_raw: bytes = field(repr=False)
    expectation: SyntheticEnrollmentExpectation = field(repr=False)
    expected_control_root: str = field(repr=False)


def _capture_inputs(
    policy_raw: object,
    expected_raw: object,
    expectation: object,
    expected_control_root: object,
) -> _CapturedInputs:
    if type(policy_raw) is not bytes or not 1 <= len(policy_raw) <= 8192:
        raise ValueError("Invalid synthetic handoff inputs")
    if type(expected_raw) is not bytes or not 1 <= len(expected_raw) <= 8192:
        raise ValueError("Invalid synthetic handoff inputs")
    if type(expected_control_root) is not str:
        raise ValueError("Invalid synthetic handoff inputs")
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise ValueError("Invalid synthetic handoff inputs")
    values: dict[str, object] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise ValueError("Invalid synthetic handoff inputs")
    retained = SyntheticEnrollmentExpectation(
        **{name: cast(str, value) for name, value in values.items()}
    )
    return _CapturedInputs(policy_raw, expected_raw, retained, expected_control_root)


def _require_false(value: object) -> None:
    if value is not False:
        raise ValueError("Invalid synthetic handoff diagnostic")


def _require_member(value: StrEnum) -> None:
    # Call only after an exact enum-type check or a checked public constructor.
    if not any(value is member for member in type(value)):
        raise ValueError("Invalid synthetic handoff diagnostic")


def _copy_input_result(value: object) -> DisabledBootstrapInputResult:
    if type(value) is not DisabledBootstrapInputResult:
        raise ValueError("Invalid synthetic handoff diagnostic")
    state, authorization = value.state, value.reuse_authorized
    _require_false(authorization)
    checked = DisabledBootstrapInputResult(state)
    _require_member(checked.state)
    return checked


def _copy_leaf(value: object) -> LeafObservation:
    if type(value) is not LeafObservation:
        raise ValueError("Invalid synthetic handoff diagnostic")
    presence, content, target, changed = (
        value.presence,
        value.content,
        value.target,
        value.changed,
    )
    checked = LeafObservation(presence, content, target, changed)
    _require_member(checked.presence)
    _require_member(checked.content)
    _require_member(checked.target)
    return checked


def _copy_inspection_result(value: object) -> PreparationInspection:
    if type(value) is not PreparationInspection:
        raise ValueError("Invalid synthetic handoff diagnostic")
    (
        state,
        pending,
        descriptor,
        relation,
        non_preparing,
        complete,
        first,
        exit_failure,
        authorized,
    ) = (
        value.state,
        value.pending,
        value.descriptor,
        value.target_relation,
        value.non_preparing_observed,
        value.verification_complete,
        value.first_failure,
        value.exit_failure_observed,
        value.reuse_authorized,
    )
    _require_false(authorized)
    checked = PreparationInspection(
        state,
        _copy_leaf(pending),
        _copy_leaf(descriptor),
        relation,
        non_preparing,
        complete,
        first,
        exit_failure,
    )
    _require_member(checked.state)
    _require_member(checked.target_relation)
    _require_member(checked.first_failure)
    return checked


@dataclass(frozen=True, slots=True)
class DisabledBootstrapInspectionResult:
    """Checked diagnostic copies, never a receipt authenticating call history."""

    state: DisabledBootstrapInspectionState
    input_result: DisabledBootstrapInputResult | None = None
    inspection_result: PreparationInspection | None = None
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.state) is not DisabledBootstrapInspectionState:
            raise ValueError("Invalid disabled bootstrap inspection result")
        try:
            _require_member(self.state)
            _require_false(self.reuse_authorized)
            checked_input = (
                None if self.input_result is None else _copy_input_result(self.input_result)
            )
            checked_inspection = (
                None
                if self.inspection_result is None
                else _copy_inspection_result(self.inspection_result)
            )
            matched = (
                checked_input is not None
                and checked_input.state is DisabledBootstrapInputState.INPUTS_MATCHED_UNAPPROVED
            )
            if self.state in {
                DisabledBootstrapInspectionState.CAPTURE_REFUSED,
                DisabledBootstrapInspectionState.VALIDATION_UNVERIFIABLE,
            }:
                valid = checked_input is None and checked_inspection is None
            elif self.state is DisabledBootstrapInspectionState.VALIDATION_REFUSED:
                valid = checked_input is not None and not matched and checked_inspection is None
            elif self.state in {
                DisabledBootstrapInspectionState.INSPECTION_FAILED,
                DisabledBootstrapInspectionState.INSPECTION_RESULT_UNVERIFIABLE,
            }:
                valid = matched and checked_inspection is None
            else:
                valid = matched and checked_inspection is not None
            if not valid:
                raise ValueError("Invalid disabled bootstrap inspection result")
        except Exception:
            raise ValueError("Invalid disabled bootstrap inspection result") from None
        object.__setattr__(self, "input_result", checked_input)
        object.__setattr__(self, "inspection_result", checked_inspection)


class DisabledBootstrapInspectionResultError(RuntimeError):
    """Terminal construction refusal with already checked, nonsecret diagnostics."""

    __slots__ = ("_input_result", "_inspection_result")

    def __init__(self) -> None:
        super().__init__("Disabled bootstrap inspection result construction failed")
        self._input_result: DisabledBootstrapInputResult | None = None
        self._inspection_result: PreparationInspection | None = None

    @property
    def input_result(self) -> DisabledBootstrapInputResult | None:
        return self._input_result

    @property
    def inspection_result(self) -> PreparationInspection | None:
        return self._inspection_result

    @property
    def reuse_authorized(self) -> Literal[False]:
        return False


def _finish(
    state: DisabledBootstrapInspectionState,
    input_result: DisabledBootstrapInputResult | None = None,
    inspection_result: PreparationInspection | None = None,
) -> DisabledBootstrapInspectionResult:
    # Only checked local copies reach this boundary; never rerun a failed check.
    try:
        return DisabledBootstrapInspectionResult(state, input_result, inspection_result)
    except Exception:
        pass
    failure = DisabledBootstrapInspectionResultError()
    failure._input_result = input_result
    failure._inspection_result = inspection_result
    try:
        raise failure from None
    except DisabledBootstrapInspectionResultError:
        # Clear this new exception only, including any caller-handler context.
        failure.__cause__ = None
        failure.__context__ = None
        raise


def inspect_synthetic_disabled_bootstrap(
    policy_raw: object,
    expected_raw: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInspectionResult:
    """Inspect at most once after a checked match using the same retained inputs."""
    try:
        inputs = _capture_inputs(policy_raw, expected_raw, expectation, expected_control_root)
    except Exception:
        return _finish(DisabledBootstrapInspectionState.CAPTURE_REFUSED)
    try:
        candidate = validate_disabled_bootstrap_inputs(
            inputs.policy_raw,
            inputs.expected_raw,
            inputs.expectation,
            expected_control_root=inputs.expected_control_root,
        )
        checked_input = _copy_input_result(candidate)
    except Exception:
        return _finish(DisabledBootstrapInspectionState.VALIDATION_UNVERIFIABLE)
    if checked_input.state is not DisabledBootstrapInputState.INPUTS_MATCHED_UNAPPROVED:
        return _finish(DisabledBootstrapInspectionState.VALIDATION_REFUSED, checked_input)
    try:
        observed = inspect_synthetic_enrollment_preparation(
            inputs.expected_control_root, inputs.expected_raw, inputs.expectation
        )
    except Exception:
        return _finish(DisabledBootstrapInspectionState.INSPECTION_FAILED, checked_input)
    try:
        checked_inspection = _copy_inspection_result(observed)
    except Exception:
        return _finish(
            DisabledBootstrapInspectionState.INSPECTION_RESULT_UNVERIFIABLE, checked_input
        )
    return _finish(
        DisabledBootstrapInspectionState.INSPECTION_OBSERVED,
        checked_input,
        checked_inspection,
    )
