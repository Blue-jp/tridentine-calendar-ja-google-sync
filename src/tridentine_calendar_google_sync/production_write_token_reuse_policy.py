"""Pure classification of synthetic operation history; never an execution authority.

No persistence, credential inspection, or runtime integration is provided. References
and evidence labels are caller assumptions, not authenticated facts about real files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, TypeGuard


class PolicyState(StrEnum):
    UNREGISTERED_OR_UNKNOWN = "unregistered_or_unknown"
    INPUT_UNVERIFIABLE = "input_unverifiable"
    START_RECORDED = "start_recorded"
    IN_PROGRESS = "in_progress"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    COMMIT_UNCERTAIN = "commit_uncertain"
    COMPLETION_OBSERVED = "completion_observed"


class RefusalReason(StrEnum):
    POLICY_NEVER_AUTHORIZES = "policy_never_authorizes"
    UNREGISTERED = "unregistered"
    HISTORY_ABSENT = "history_absent"
    HISTORY_MISSING = "history_missing"
    HISTORY_CORRUPT = "history_corrupt"
    HISTORY_UNREADABLE = "history_unreadable"
    INVALID_INPUT = "invalid_input"
    BINDING_MISMATCH = "binding_mismatch"
    CONFLICTING_OPERATION = "conflicting_operation"
    MISSING_CURRENT_OPERATION = "missing_current_operation"
    MISSING_PREDECESSOR = "missing_predecessor"
    INVALID_OPERATION_CHAIN = "invalid_operation_chain"
    PREDECESSOR_NOT_COMPLETED = "predecessor_not_completed"
    INVALID_EVENT_SEQUENCE = "invalid_event_sequence"
    MISSING_START = "missing_start"
    INVALID_TRANSITION = "invalid_transition"
    UNRESOLVED_FAILURE = "unresolved_failure"
    UNRESOLVED_INTERRUPTION = "unresolved_interruption"
    UNRESOLVED_COMMIT = "unresolved_commit"
    START_ONLY = "start_only"
    OPERATION_INCOMPLETE = "operation_incomplete"
    COMPLETION_NOT_AUTHORIZATION = "completion_not_authorization"


class EventKind(StrEnum):
    START_RECORDED = "start_recorded"
    PROGRESS = "progress"
    COMPLETION_EVIDENCE = "completion_evidence"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    COMMIT_UNCERTAIN = "commit_uncertain"
    SAVE_CONFIRMATION_FAILED = "save_confirmation_failed"
    FINALIZATION_FAILED = "finalization_failed"


class OperationKind(StrEnum):
    NEW_PAIR = "new_pair"
    REFRESH = "refresh"


class HistoryStatus(StrEnum):
    COMPLETE = "complete"
    ABSENT = "absent"
    MISSING = "missing"
    CORRUPT = "corrupt"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class SyntheticBinding:
    storage_ref: str = field(repr=False)
    pair_ref: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    binding: SyntheticBinding = field(repr=False)
    operation_id: str = field(repr=False)
    kind: OperationKind = field(repr=False)
    generation_ref: str = field(repr=False)
    predecessor_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class OperationEvent:
    operation: OperationDefinition = field(repr=False)
    ordinal: int = field(repr=False)
    kind: EventKind = field(repr=False)


@dataclass(frozen=True, slots=True)
class AppearanceObservations:
    """Non-authoritative hints, including writer returns and record visibility."""

    content_matches: bool = field(default=False, repr=False)
    token_unexpired: bool = field(default=False, repr=False)
    generation_matches: bool = field(default=False, repr=False)
    publication_possible: bool | None = field(default=None, repr=False)
    completed_output_count: int | None = field(default=None, repr=False)
    time_elapsed: bool = field(default=False, repr=False)
    previous_process_absent: bool = field(default=False, repr=False)
    copied_to_other_storage: bool = field(default=False, repr=False)
    completion_record_visible: bool = field(default=False, repr=False)


@dataclass(frozen=True, slots=True)
class PolicyInput:
    target: OperationDefinition = field(repr=False)
    history: tuple[OperationEvent, ...] = field(repr=False)
    history_status: HistoryStatus = field(default=HistoryStatus.COMPLETE, repr=False)
    registered: bool = field(default=True, repr=False)
    observations: AppearanceObservations = field(default_factory=AppearanceObservations, repr=False)


@dataclass(frozen=True, slots=True)
class ReusePolicyDecision:
    state: PolicyState
    reasons: tuple[RefusalReason, ...]
    unresolved_failure: bool
    unresolved_interruption: bool
    unresolved_commit: bool
    transitions_valid: bool
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not PolicyState
            or type(self.reasons) is not tuple
            or not all(type(reason) is RefusalReason for reason in self.reasons)
            or not all(
                type(flag) is bool
                for flag in (
                    self.unresolved_failure,
                    self.unresolved_interruption,
                    self.unresolved_commit,
                    self.transitions_valid,
                )
            )
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid reuse policy decision")


_UNCERTAIN_EVENTS = frozenset(
    (EventKind.COMMIT_UNCERTAIN, EventKind.SAVE_CONFIRMATION_FAILED, EventKind.FINALIZATION_FAILED)
)
_UNKNOWN_REASONS = frozenset((RefusalReason.UNREGISTERED, RefusalReason.HISTORY_ABSENT))


def _valid_ref(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 96
        and value.isascii()
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _valid_operation(value: object) -> TypeGuard[OperationDefinition]:
    return (
        type(value) is OperationDefinition
        and type(value.binding) is SyntheticBinding
        and _valid_ref(value.binding.storage_ref)
        and _valid_ref(value.binding.pair_ref)
        and _valid_ref(value.operation_id)
        and type(value.kind) is OperationKind
        and _valid_ref(value.generation_ref)
        and (value.predecessor_id is None or _valid_ref(value.predecessor_id))
    )


def _valid_observations(value: object) -> bool:
    if type(value) is not AppearanceObservations:
        return False
    return (
        all(
            type(flag) is bool
            for flag in (
                value.content_matches,
                value.token_unexpired,
                value.generation_matches,
                value.time_elapsed,
                value.previous_process_absent,
                value.copied_to_other_storage,
                value.completion_record_visible,
            )
        )
        and (value.publication_possible is None or type(value.publication_possible) is bool)
        and (
            value.completed_output_count is None
            or (
                type(value.completed_output_count) is int and 0 <= value.completed_output_count <= 2
            )
        )
    )


def _recognizable_events(history: object) -> tuple[OperationEvent, ...]:
    # A malformed built-in list is never accepted, but cannot erase a known failure.
    # Do not iterate arbitrary objects or invoke their comparison/repr hooks.
    if type(history) is not tuple and type(history) is not list:
        return ()
    return tuple(event for event in history if type(event) is OperationEvent)


def _advance(state: PolicyState, event: EventKind) -> tuple[PolicyState, bool]:
    started = state is not PolicyState.UNREGISTERED_OR_UNKNOWN
    if event in _UNCERTAIN_EVENTS:
        return PolicyState.COMMIT_UNCERTAIN, started
    if event in (EventKind.FAILED, EventKind.INTERRUPTED):
        next_state = (
            PolicyState.COMMIT_UNCERTAIN
            if state is PolicyState.COMMIT_UNCERTAIN
            else PolicyState.RECONCILIATION_REQUIRED
        )
        return next_state, started and state is not PolicyState.COMPLETION_OBSERVED
    if state is PolicyState.UNREGISTERED_OR_UNKNOWN and event is EventKind.START_RECORDED:
        return PolicyState.START_RECORDED, True
    if state is PolicyState.START_RECORDED and event is EventKind.PROGRESS:
        return PolicyState.IN_PROGRESS, True
    if state is PolicyState.IN_PROGRESS and event is EventKind.COMPLETION_EVIDENCE:
        return PolicyState.COMPLETION_OBSERVED, True
    return state, False


def _check_trace(
    events: list[OperationEvent], problems: set[RefusalReason]
) -> tuple[PolicyState, bool]:
    ordered = sorted(events, key=lambda event: event.ordinal)
    trace_valid = True
    if [event.ordinal for event in ordered] != list(range(1, len(ordered) + 1)):
        problems.add(RefusalReason.INVALID_EVENT_SEQUENCE)
        if not any(
            event.ordinal == 1 and event.kind is EventKind.START_RECORDED for event in ordered
        ):
            problems.add(RefusalReason.MISSING_START)
        return PolicyState.INPUT_UNVERIFIABLE, False
    if ordered[0].kind is not EventKind.START_RECORDED:
        problems.add(RefusalReason.MISSING_START)
        trace_valid = False
    state = PolicyState.UNREGISTERED_OR_UNKNOWN
    for event in ordered:
        state, valid_step = _advance(state, event.kind)
        if not valid_step:
            problems.add(RefusalReason.INVALID_TRANSITION)
            trace_valid = False
    return state, trace_valid


def _check_history(
    target: OperationDefinition,
    events: tuple[OperationEvent, ...],
    problems: set[RefusalReason],
) -> PolicyState:
    definitions = {target.operation_id: target}
    groups: dict[str, list[OperationEvent]] = {}
    for event in events:
        if (
            not _valid_operation(event.operation)
            or type(event.ordinal) is not int
            or event.ordinal < 1
            or type(event.kind) is not EventKind
        ):
            problems.add(RefusalReason.INVALID_INPUT)
            continue
        operation = event.operation
        if operation.binding != target.binding:
            problems.add(RefusalReason.BINDING_MISMATCH)
        previous_definition = definitions.get(operation.operation_id)
        if previous_definition is not None and previous_definition != operation:
            problems.add(RefusalReason.CONFLICTING_OPERATION)
        else:
            definitions[operation.operation_id] = operation
        groups.setdefault(operation.operation_id, []).append(event)

    if problems & {RefusalReason.CONFLICTING_OPERATION, RefusalReason.BINDING_MISMATCH}:
        # No arbitrary choice between conflicting definitions or unrelated targets.
        # Negative evidence has already been retained by the caller.
        return PolicyState.INPUT_UNVERIFIABLE

    states: dict[str, PolicyState] = {}
    completed: set[str] = set()
    for operation_id, group in groups.items():
        state, valid_trace = _check_trace(group, problems)
        states[operation_id] = state
        if valid_trace and state is PolicyState.COMPLETION_OBSERVED:
            completed.add(operation_id)
    if target.operation_id not in groups:
        problems.add(RefusalReason.MISSING_CURRENT_OPERATION)

    visited: set[str] = set()
    cursor: str | None = target.operation_id
    while cursor is not None:
        if cursor in visited:
            problems.add(RefusalReason.INVALID_OPERATION_CHAIN)
            break
        visited.add(cursor)
        definition = definitions.get(cursor)
        if definition is None or cursor not in groups:
            if cursor != target.operation_id:
                problems.add(RefusalReason.MISSING_PREDECESSOR)
            break
        predecessor = definition.predecessor_id
        if predecessor is not None and predecessor not in completed:
            problems.add(RefusalReason.PREDECESSOR_NOT_COMPLETED)
        cursor = predecessor
    if set(definitions) != visited:
        problems.add(RefusalReason.INVALID_OPERATION_CHAIN)
    return states.get(target.operation_id, PolicyState.UNREGISTERED_OR_UNKNOWN)


def evaluate_reuse_policy(request: object) -> ReusePolicyDecision:
    """Recompute from supplied history, retaining negative evidence before validation.

    Exact input types avoid arbitrary object hooks. No caller identifier is returned
    or formatted. A well-ordered failed transition can be valid without authorizing
    reuse; ``transitions_valid`` concerns only this synthetic history's structure.
    """
    problems: set[RefusalReason] = set()
    state = PolicyState.UNREGISTERED_OR_UNKNOWN
    events = _recognizable_events(request.history) if type(request) is PolicyInput else ()
    kinds = {event.kind for event in events if type(event.kind) is EventKind}
    failure = EventKind.FAILED in kinds
    interruption = EventKind.INTERRUPTED in kinds
    uncertain = bool(kinds & _UNCERTAIN_EVENTS)

    if type(request) is not PolicyInput:
        problems.add(RefusalReason.INVALID_INPUT)
    else:
        if (
            type(request.registered) is not bool
            or type(request.history_status) is not HistoryStatus
            or type(request.history) is not tuple
            or not _valid_observations(request.observations)
            or not _valid_operation(request.target)
        ):
            problems.add(RefusalReason.INVALID_INPUT)
        if request.registered is False:
            problems.add(RefusalReason.UNREGISTERED)
        if type(request.history_status) is HistoryStatus:
            status_reasons = {
                HistoryStatus.ABSENT: RefusalReason.HISTORY_ABSENT,
                HistoryStatus.MISSING: RefusalReason.HISTORY_MISSING,
                HistoryStatus.CORRUPT: RefusalReason.HISTORY_CORRUPT,
                HistoryStatus.UNREADABLE: RefusalReason.HISTORY_UNREADABLE,
            }
            status_reason = status_reasons.get(request.history_status)
            if status_reason is not None:
                problems.add(status_reason)
            if request.history_status is HistoryStatus.ABSENT and events:
                problems.add(RefusalReason.INVALID_INPUT)
        if type(request.history) is tuple:
            if not request.history:
                problems.add(RefusalReason.HISTORY_ABSENT)
            else:
                if len(events) != len(request.history):
                    problems.add(RefusalReason.INVALID_INPUT)
                if _valid_operation(request.target):
                    state = _check_history(request.target, events, problems)

    transitions_valid = not problems
    if uncertain:
        state = PolicyState.COMMIT_UNCERTAIN
    elif failure or interruption:
        state = PolicyState.RECONCILIATION_REQUIRED
    elif problems - _UNKNOWN_REASONS:
        state = PolicyState.INPUT_UNVERIFIABLE
    elif problems:
        state = PolicyState.UNREGISTERED_OR_UNKNOWN

    reasons = problems | {RefusalReason.POLICY_NEVER_AUTHORIZES}
    if failure:
        reasons.add(RefusalReason.UNRESOLVED_FAILURE)
    if interruption:
        reasons.add(RefusalReason.UNRESOLVED_INTERRUPTION)
    if uncertain:
        reasons.add(RefusalReason.UNRESOLVED_COMMIT)
    if state is PolicyState.START_RECORDED:
        reasons.add(RefusalReason.START_ONLY)
    elif state is PolicyState.IN_PROGRESS:
        reasons.add(RefusalReason.OPERATION_INCOMPLETE)
    elif state is PolicyState.COMPLETION_OBSERVED:
        reasons.add(RefusalReason.COMPLETION_NOT_AUTHORIZATION)
    return ReusePolicyDecision(
        state=state,
        reasons=tuple(reason for reason in RefusalReason if reason in reasons),
        unresolved_failure=failure,
        unresolved_interruption=interruption,
        unresolved_commit=uncertain,
        transitions_valid=transitions_valid,
    )
