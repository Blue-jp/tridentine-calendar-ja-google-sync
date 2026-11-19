"""Synthetic memory-only policy checks; no process restart or recovery proof."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, asdict, fields, replace
from itertools import permutations
from pathlib import Path
from typing import Any

import pytest

from tridentine_calendar_google_sync import production_write_token_reuse_policy as policy

S = policy.PolicyState
E = policy.EventKind
K = policy.OperationKind
H = policy.HistoryStatus
BINDING = policy.SyntheticBinding("synthetic-store", "synthetic-pair")
OPERATION = policy.OperationDefinition(BINDING, "synthetic-current", K.REFRESH, "generation-one")


def _events(
    *kinds: E, operation: policy.OperationDefinition = OPERATION
) -> tuple[policy.OperationEvent, ...]:
    return tuple(
        policy.OperationEvent(operation, ordinal, kind) for ordinal, kind in enumerate(kinds, 1)
    )


def _request(*kinds: E, **updates: Any) -> policy.PolicyInput:
    return replace(policy.PolicyInput(OPERATION, _events(*kinds)), **updates)


def _check(request: object, state: S, *, valid: bool = True) -> policy.ReusePolicyDecision:
    result = policy.evaluate_reuse_policy(request)
    assert result.state is state
    assert result.transitions_valid is valid
    assert result.reuse_authorized is False
    assert result.reasons
    assert all(type(reason) is policy.RefusalReason for reason in result.reasons)
    assert policy.RefusalReason.POLICY_NEVER_AUTHORIZES in result.reasons
    return result


@pytest.mark.parametrize(
    ("case_input", "state", "valid"),
    (
        (_request(registered=False), S.UNREGISTERED_OR_UNKNOWN, False),
        (_request(history_status=H.ABSENT), S.UNREGISTERED_OR_UNKNOWN, False),
        (_request(history_status=H.MISSING), S.INPUT_UNVERIFIABLE, False),
        (_request(E.START_RECORDED), S.START_RECORDED, True),
        (_request(E.START_RECORDED, E.PROGRESS), S.IN_PROGRESS, True),
        (_request(E.START_RECORDED, E.FAILED), S.RECONCILIATION_REQUIRED, True),
        (_request(E.START_RECORDED, E.COMMIT_UNCERTAIN), S.COMMIT_UNCERTAIN, True),
        (
            _request(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE),
            S.COMPLETION_OBSERVED,
            True,
        ),
    ),
    ids=(
        "unregistered",
        "absent",
        "unverified",
        "start",
        "progress",
        "failed",
        "uncertain",
        "done",
    ),
)
def test_every_observed_state_is_a_refusal(
    case_input: policy.PolicyInput, state: S, valid: bool
) -> None:
    _check(case_input, state, valid=valid)
    assert {state for _, state, _ in _STATE_EXAMPLES} == set(S)


_STATE_EXAMPLES = (
    ((), S.UNREGISTERED_OR_UNKNOWN, False),
    ((), S.INPUT_UNVERIFIABLE, False),
    ((E.START_RECORDED,), S.START_RECORDED, True),
    ((E.START_RECORDED, E.PROGRESS), S.IN_PROGRESS, True),
    ((E.START_RECORDED, E.FAILED), S.RECONCILIATION_REQUIRED, True),
    ((E.START_RECORDED, E.COMMIT_UNCERTAIN), S.COMMIT_UNCERTAIN, True),
    ((E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE), S.COMPLETION_OBSERVED, True),
)


@pytest.mark.parametrize("kind", tuple(K), ids=lambda value: value.name)
def test_normal_progress_finishes_without_authorization(kind: K) -> None:
    operation = replace(OPERATION, kind=kind)
    for kinds, state in (
        ((E.START_RECORDED,), S.START_RECORDED),
        ((E.START_RECORDED, E.PROGRESS), S.IN_PROGRESS),
        ((E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE), S.COMPLETION_OBSERVED),
    ):
        result = _check(policy.PolicyInput(operation, _events(*kinds, operation=operation)), state)
        assert not result.unresolved_failure
        assert not result.unresolved_interruption
        assert not result.unresolved_commit


@pytest.mark.parametrize(
    ("prefix", "before"),
    (
        ((E.START_RECORDED,), S.START_RECORDED),
        ((E.START_RECORDED, E.PROGRESS), S.IN_PROGRESS),
        ((E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE), S.COMPLETION_OBSERVED),
        ((E.START_RECORDED, E.FAILED), S.RECONCILIATION_REQUIRED),
        ((E.START_RECORDED, E.COMMIT_UNCERTAIN), S.COMMIT_UNCERTAIN),
    ),
    ids=("start", "progress", "completed", "failed", "uncertain"),
)
@pytest.mark.parametrize("event", tuple(E), ids=lambda value: value.name)
def test_exhaustive_core_event_transitions(prefix: tuple[E, ...], before: S, event: E) -> None:
    uncertain = event in {E.COMMIT_UNCERTAIN, E.SAVE_CONFIRMATION_FAILED, E.FINALIZATION_FAILED}
    failed = event in {E.FAILED, E.INTERRUPTED}
    normal = not uncertain and not failed
    if before is S.COMMIT_UNCERTAIN or uncertain:
        expected = S.COMMIT_UNCERTAIN
    elif before is S.RECONCILIATION_REQUIRED or failed:
        expected = S.RECONCILIATION_REQUIRED
    elif before is S.START_RECORDED and event is E.PROGRESS:
        expected = S.IN_PROGRESS
    elif before is S.IN_PROGRESS and event is E.COMPLETION_EVIDENCE:
        expected = S.COMPLETION_OBSERVED
    else:
        expected = S.INPUT_UNVERIFIABLE
    valid = (
        uncertain
        or (failed and before is not S.COMPLETION_OBSERVED)
        or (before is S.START_RECORDED and event is E.PROGRESS)
        or (before is S.IN_PROGRESS and event is E.COMPLETION_EVIDENCE)
    )
    if normal and before in {S.RECONCILIATION_REQUIRED, S.COMMIT_UNCERTAIN}:
        valid = False
    _check(_request(*prefix, event), expected, valid=valid)


@pytest.mark.parametrize("event", tuple(E), ids=lambda value: value.name)
def test_missing_start_never_becomes_normal_progress(event: E) -> None:
    if event is E.START_RECORDED:
        _check(_request(event), S.START_RECORDED)
    elif event in {E.COMMIT_UNCERTAIN, E.SAVE_CONFIRMATION_FAILED, E.FINALIZATION_FAILED}:
        _check(_request(event), S.COMMIT_UNCERTAIN, valid=False)
    elif event in {E.FAILED, E.INTERRUPTED}:
        _check(_request(event), S.RECONCILIATION_REQUIRED, valid=False)
    else:
        _check(_request(event), S.INPUT_UNVERIFIABLE, valid=False)


_APPEARANCES = (
    {"content_matches": True},
    {"token_unexpired": True},
    {"generation_matches": True},
    {"publication_possible": False},
    {"completed_output_count": 2},
    {"time_elapsed": True},
    {"previous_process_absent": True},
    {"copied_to_other_storage": True},
    {"completion_record_visible": True},
    {
        "content_matches": True,
        "token_unexpired": True,
        "generation_matches": True,
        "publication_possible": False,
        "completed_output_count": 2,
        "time_elapsed": True,
        "previous_process_absent": True,
        "copied_to_other_storage": True,
        "completion_record_visible": True,
    },
)


@pytest.mark.parametrize(
    "appearance",
    _APPEARANCES,
    ids=(
        "matching",
        "unexpired",
        "generation",
        "unpublished",
        "two-writers",
        "elapsed",
        "gone",
        "copied",
        "visible",
        "all",
    ),
)
@pytest.mark.parametrize(
    "negative", (E.FAILED, E.INTERRUPTED, E.COMMIT_UNCERTAIN), ids=lambda value: value.name
)
def test_normal_looking_observations_never_clear_unresolved_history(
    appearance: dict[str, object], negative: E
) -> None:
    request = _request(
        E.START_RECORDED,
        negative,
        observations=policy.AppearanceObservations(**appearance),
    )
    state = S.COMMIT_UNCERTAIN if negative is E.COMMIT_UNCERTAIN else S.RECONCILIATION_REQUIRED
    result = _check(request, state)
    assert result.unresolved_failure is (negative is E.FAILED)
    assert result.unresolved_interruption is (negative is E.INTERRUPTED)
    assert result.unresolved_commit is (negative is E.COMMIT_UNCERTAIN)


@pytest.mark.parametrize(
    "negative", (E.FAILED, E.INTERRUPTED, E.COMMIT_UNCERTAIN), ids=lambda value: value.name
)
def test_later_completion_cannot_release_negative_state(negative: E) -> None:
    state = S.COMMIT_UNCERTAIN if negative is E.COMMIT_UNCERTAIN else S.RECONCILIATION_REQUIRED
    _check(
        _request(E.START_RECORDED, E.PROGRESS, negative, E.COMPLETION_EVIDENCE), state, valid=False
    )


def test_previous_completion_and_same_generation_refresh_are_distinct_operations() -> None:
    previous = replace(OPERATION, operation_id="synthetic-previous")
    current = replace(OPERATION, predecessor_id=previous.operation_id)
    history = _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=previous)
    history += _events(E.START_RECORDED, E.FAILED, operation=current)
    assert previous.generation_ref == current.generation_ref
    assert previous.operation_id != current.operation_id
    result = _check(policy.PolicyInput(current, history), S.RECONCILIATION_REQUIRED)
    assert result.unresolved_failure


def test_old_failure_dominates_a_later_operations_completion() -> None:
    previous = replace(OPERATION, operation_id="synthetic-previous")
    current = replace(OPERATION, predecessor_id=previous.operation_id)
    history = _events(E.START_RECORDED, E.FAILED, operation=previous)
    history += _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=current)
    result = _check(policy.PolicyInput(current, history), S.RECONCILIATION_REQUIRED, valid=False)
    assert result.unresolved_failure


@pytest.mark.parametrize("part", ("storage_ref", "pair_ref"))
def test_other_target_completion_cannot_clear_failure(part: str) -> None:
    other = replace(OPERATION, binding=replace(BINDING, **{part: "synthetic-other"}))
    history = _events(E.START_RECORDED, E.FAILED)
    history += _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=other)
    result = _check(_request(history=history), S.RECONCILIATION_REQUIRED, valid=False)
    assert result.unresolved_failure


@pytest.mark.parametrize(
    "change",
    (
        {"generation_ref": "other-generation"},
        {"kind": K.NEW_PAIR},
        {"predecessor_id": "other-previous"},
    ),
    ids=("generation", "kind", "predecessor"),
)
def test_conflicting_operation_definition_is_rejected(change: dict[str, object]) -> None:
    other = replace(OPERATION, **change)
    history = (*_events(E.START_RECORDED), policy.OperationEvent(other, 2, E.PROGRESS))
    _check(_request(history=history), S.INPUT_UNVERIFIABLE, valid=False)


@pytest.mark.parametrize("defect", ("duplicate", "gap", "zero", "bool", "reversed"))
def test_explicit_ordinals_reject_duplicate_missing_or_contradictory_order(defect: str) -> None:
    history = _events(E.START_RECORDED, E.PROGRESS)
    if defect == "duplicate":
        history += (history[1],)
    elif defect == "gap":
        history = (history[0], replace(history[1], ordinal=3))
    elif defect == "zero":
        history = (replace(history[0], ordinal=0), history[1])
    elif defect == "bool":
        history = (replace(history[0], ordinal=True), history[1])
    else:
        history = (replace(history[0], ordinal=2), replace(history[1], ordinal=1))
    _check(_request(history=history), S.INPUT_UNVERIFIABLE, valid=False)


@pytest.mark.parametrize(
    "defect", ("missing", "disconnected", "cycle", "target-absent", "predecessor-incomplete")
)
def test_predecessor_chain_is_explicit_and_required(defect: str) -> None:
    previous = replace(OPERATION, operation_id="synthetic-previous")
    current = replace(OPERATION, predecessor_id=previous.operation_id)
    done = _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=previous)
    now = _events(E.START_RECORDED, E.PROGRESS, operation=current)
    if defect == "missing":
        history = now
    elif defect == "disconnected":
        current = OPERATION
        history = done + _events(E.START_RECORDED)
    elif defect == "cycle":
        previous = replace(previous, predecessor_id=current.operation_id)
        history = (
            _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=previous) + now
        )
    elif defect == "target-absent":
        history = done
    else:
        history = _events(E.START_RECORDED, operation=previous) + now
    _check(policy.PolicyInput(current, history), S.INPUT_UNVERIFIABLE, valid=False)


def test_history_permutations_preserve_unresolved_failure_and_explicit_progress() -> None:
    previous = replace(OPERATION, operation_id="synthetic-previous")
    current = replace(OPERATION, predecessor_id=previous.operation_id)
    history = _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, operation=previous)
    history += _events(E.START_RECORDED, E.FAILED, operation=current)
    expected = policy.evaluate_reuse_policy(policy.PolicyInput(current, history))
    for ordering in permutations(history):
        assert policy.evaluate_reuse_policy(policy.PolicyInput(current, ordering)) == expected
    assert expected.unresolved_failure and expected.state is S.RECONCILIATION_REQUIRED
    normal = _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE)
    for ordering in permutations(normal):
        _check(_request(history=ordering), S.COMPLETION_OBSERVED)


def test_memory_reconstruction_uses_supplied_history_not_module_global_state() -> None:
    request = _request(E.START_RECORDED, E.FAILED)
    first = policy.evaluate_reuse_policy(request)
    rebuilt_operation = replace(OPERATION, binding=replace(BINDING))
    rebuilt_events = tuple(replace(event, operation=rebuilt_operation) for event in request.history)
    rebuilt = policy.PolicyInput(rebuilt_operation, rebuilt_events)
    assert rebuilt is not request and rebuilt.target is not request.target
    assert all(new is not old for new, old in zip(rebuilt.history, request.history, strict=True))
    assert policy.evaluate_reuse_policy(rebuilt) == first
    assert first.unresolved_failure and first.reuse_authorized is False
    _check(_request(E.START_RECORDED, E.PROGRESS), S.IN_PROGRESS)
    assert policy.evaluate_reuse_policy(rebuilt) == first


@pytest.mark.parametrize(
    "failure", (E.SAVE_CONFIRMATION_FAILED, E.FINALIZATION_FAILED), ids=lambda value: value.name
)
def test_visible_completion_plus_failed_commit_confirmation_is_uncertain(failure: E) -> None:
    result = _check(
        _request(
            E.START_RECORDED,
            E.PROGRESS,
            E.COMPLETION_EVIDENCE,
            failure,
            observations=policy.AppearanceObservations(
                completion_record_visible=True, completed_output_count=2, publication_possible=False
            ),
        ),
        S.COMMIT_UNCERTAIN,
    )
    assert result.unresolved_commit


@pytest.mark.parametrize("status", tuple(H), ids=lambda value: value.name)
def test_missing_corrupt_unreadable_history_never_means_success(status: H) -> None:
    expected = (
        S.UNREGISTERED_OR_UNKNOWN if status in {H.COMPLETE, H.ABSENT} else S.INPUT_UNVERIFIABLE
    )
    _check(_request(history_status=status), expected, valid=False)
    failed = _check(
        _request(E.START_RECORDED, E.FAILED, history_status=status),
        S.RECONCILIATION_REQUIRED,
        valid=status is H.COMPLETE,
    )
    assert failed.unresolved_failure


class _Poison:
    @property
    def __class__(self) -> type[object]:
        raise AssertionError("untrusted class hook must not execute")

    def __repr__(self) -> str:
        raise AssertionError("untrusted repr must not execute")

    def __str__(self) -> str:
        raise AssertionError("untrusted str must not execute")

    def __bool__(self) -> bool:
        raise AssertionError("untrusted truth hook must not execute")

    def __eq__(self, _other: object) -> bool:
        raise AssertionError("untrusted equality hook must not execute")

    def __hash__(self) -> int:
        raise AssertionError("untrusted hash hook must not execute")


@pytest.mark.parametrize(
    "location",
    (
        "request",
        "target",
        "binding",
        "storage",
        "pair",
        "operation",
        "kind",
        "generation",
        "predecessor",
        "ordinal",
        "event-kind",
        "history",
        "status",
        "registered",
        "observations",
        "observation-field",
    ),
)
def test_unknown_objects_are_rejected_without_invoking_untrusted_hooks(location: str) -> None:
    poison: Any = _Poison()
    request: Any = _request(E.START_RECORDED, E.PROGRESS)
    if location == "request":
        request = poison
    elif location in {"target", "history", "registered", "observations"}:
        request = replace(request, **{location: poison})
    elif location == "status":
        request = replace(request, history_status=poison)
    elif location == "observation-field":
        request = replace(
            request, observations=policy.AppearanceObservations(token_unexpired=poison)
        )
    elif location in {"ordinal", "event-kind"}:
        event = replace(
            request.history[1], **{"ordinal" if location == "ordinal" else "kind": poison}
        )
        request = replace(request, history=(request.history[0], event))
    else:
        if location in {"storage", "pair"}:
            binding = replace(
                BINDING, **{"storage_ref" if location == "storage" else "pair_ref": poison}
            )
            operation = replace(OPERATION, binding=binding)
        else:
            field = {
                "binding": "binding",
                "operation": "operation_id",
                "kind": "kind",
                "generation": "generation_ref",
                "predecessor": "predecessor_id",
            }[location]
            operation = replace(OPERATION, **{field: poison})
        request = replace(request, target=operation)
    _check(request, S.INPUT_UNVERIFIABLE, valid=False)


@pytest.mark.parametrize(
    "negative", (E.FAILED, E.INTERRUPTED, E.COMMIT_UNCERTAIN), ids=lambda value: value.name
)
@pytest.mark.parametrize(
    "defect",
    (
        "operation",
        "binding",
        "ordinal",
        "list-history",
        "unknown-neighbor",
        "unregistered",
        "bad-observation",
    ),
)
def test_malformed_input_cannot_erase_recognized_negative_evidence(
    negative: E, defect: str
) -> None:
    poison: Any = _Poison()
    event = policy.OperationEvent(OPERATION, 2, negative)
    request = _request(E.START_RECORDED, negative)
    if defect == "operation":
        event = replace(event, operation=poison)
    elif defect == "binding":
        event = replace(event, operation=replace(OPERATION, binding=poison))
    elif defect == "ordinal":
        event = replace(event, ordinal=poison)
    if defect in {"operation", "binding", "ordinal"}:
        request = replace(request, history=(request.history[0], event))
    elif defect == "list-history":
        request = replace(request, history=list(request.history))
    elif defect == "unknown-neighbor":
        request = replace(request, history=(*request.history, poison))
    elif defect == "unregistered":
        request = replace(request, registered=False)
    else:
        request = replace(
            request, observations=policy.AppearanceObservations(token_unexpired=poison)
        )
    state = S.COMMIT_UNCERTAIN if negative is E.COMMIT_UNCERTAIN else S.RECONCILIATION_REQUIRED
    result = _check(request, state, valid=False)
    assert result.unresolved_failure is (negative is E.FAILED)
    assert result.unresolved_interruption is (negative is E.INTERRUPTED)
    assert result.unresolved_commit is (negative is E.COMMIT_UNCERTAIN)


def test_competing_negative_classifications_are_all_retained() -> None:
    result = _check(
        _request(E.START_RECORDED, E.FAILED, E.INTERRUPTED, E.COMMIT_UNCERTAIN),
        S.COMMIT_UNCERTAIN,
    )
    assert result.unresolved_failure and result.unresolved_interruption and result.unresolved_commit


def test_result_and_input_repr_never_expose_arbitrary_input_strings() -> None:
    canary = "SYNTHETIC_ARBITRARY_INPUT_CANARY"
    binding = policy.SyntheticBinding(canary, canary)
    operation = policy.OperationDefinition(binding, canary, K.REFRESH, canary, canary)
    event = policy.OperationEvent(operation, 1, E.FAILED)
    request = policy.PolicyInput(operation, (event,))
    result = policy.evaluate_reuse_policy(request)
    for value in (binding, operation, event, request, result, asdict(result)):
        assert canary not in repr(value)
        assert canary not in str(value)
    assert set(asdict(result)) == {
        "state",
        "reasons",
        "unresolved_failure",
        "unresolved_interruption",
        "unresolved_commit",
        "transitions_valid",
        "reuse_authorized",
    }
    assert type(result.state) is S
    assert all(type(reason) is policy.RefusalReason for reason in result.reasons)
    assert all(
        type(value) is bool
        for name, value in asdict(result).items()
        if name not in {"state", "reasons"}
    )
    for value in (binding, operation, event, request, policy.AppearanceObservations()):
        assert all(not item.repr for item in fields(value))


def test_authorization_cannot_be_enabled_by_normal_constructor_or_assignment() -> None:
    result = policy.evaluate_reuse_policy(_request(E.START_RECORDED))
    assert next(item for item in fields(result) if item.name == "reuse_authorized").init is False
    with pytest.raises(TypeError):
        policy.ReusePolicyDecision(**{**asdict(result), "reuse_authorized": True})
    with pytest.raises(ValueError):
        replace(result, reuse_authorized=True)
    with pytest.raises(FrozenInstanceError):
        result.reuse_authorized = True
    assert result.reuse_authorized is False


@pytest.mark.parametrize(
    "field_name",
    (
        "state",
        "reasons",
        "unresolved_failure",
        "unresolved_interruption",
        "unresolved_commit",
        "transitions_valid",
    ),
)
def test_invalid_result_constructor_has_a_fixed_non_secret_exception(field_name: str) -> None:
    canary = "SYNTHETIC_INVALID_RESULT_CANARY"
    values = asdict(policy.evaluate_reuse_policy(_request(E.START_RECORDED)))
    values.pop("reuse_authorized")
    values[field_name] = canary
    with pytest.raises(ValueError) as caught:
        policy.ReusePolicyDecision(**values)
    assert str(caught.value) == "Invalid reuse policy decision"
    assert canary not in repr(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "phase", ((E.START_RECORDED,), (E.START_RECORDED, E.PROGRESS)), ids=("start", "progress")
)
def test_visible_completion_without_completion_evidence_does_not_advance(
    phase: tuple[E, ...],
) -> None:
    state = S.START_RECORDED if len(phase) == 1 else S.IN_PROGRESS
    _check(
        _request(
            *phase, observations=policy.AppearanceObservations(completion_record_visible=True)
        ),
        state,
    )


@pytest.mark.parametrize(
    "reference",
    ("", "synthetic/path", "synthetic\\path", "非秘密", "a" * 97),
    ids=("empty", "slash", "backslash", "unicode", "long"),
)
@pytest.mark.parametrize(
    "field_name", ("operation_id", "generation_ref", "predecessor_id", "storage_ref", "pair_ref")
)
def test_invalid_reference_strings_are_refused_without_rendering(
    reference: str, field_name: str
) -> None:
    if field_name in {"storage_ref", "pair_ref"}:
        operation = replace(OPERATION, binding=replace(BINDING, **{field_name: reference}))
    else:
        operation = replace(OPERATION, **{field_name: reference})
    _check(_request(E.START_RECORDED, target=operation), S.INPUT_UNVERIFIABLE, valid=False)


@pytest.mark.parametrize(
    "update",
    (
        {"publication_possible": 0},
        {"publication_possible": 1},
        {"publication_possible": "false"},
        {"completed_output_count": True},
        {"completed_output_count": -1},
        {"completed_output_count": 3},
        {"content_matches": 1},
    ),
    ids=(
        "publication-zero",
        "publication-one",
        "publication-text",
        "count-bool",
        "count-negative",
        "count-three",
        "content-one",
    ),
)
def test_invalid_observation_types_and_counts_are_not_coerced(update: dict[str, Any]) -> None:
    _check(
        _request(E.START_RECORDED, observations=policy.AppearanceObservations(**update)),
        S.INPUT_UNVERIFIABLE,
        valid=False,
    )


@pytest.mark.parametrize("field_name", ("operation-kind", "event-kind", "status"))
def test_enum_value_strings_are_unknown_input_not_trusted_labels(field_name: str) -> None:
    request = _request(E.START_RECORDED)
    if field_name == "operation-kind":
        request = replace(request, target=replace(OPERATION, kind="refresh"))
    elif field_name == "event-kind":
        request = replace(request, history=(replace(request.history[0], kind="failed"),))
    else:
        request = replace(request, history_status="complete")
    result = _check(request, S.INPUT_UNVERIFIABLE, valid=False)
    assert not result.unresolved_failure


def test_invalid_prefix_and_unregistered_status_cannot_be_corrected_by_normal_events() -> None:
    _check(_request(E.PROGRESS), S.INPUT_UNVERIFIABLE, valid=False)
    _check(
        _request(E.PROGRESS, E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE),
        S.INPUT_UNVERIFIABLE,
        valid=False,
    )
    _check(
        _request(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE, registered=False),
        S.UNREGISTERED_OR_UNKNOWN,
        valid=False,
    )


@pytest.mark.parametrize("defect", ("duplicate-ordinal", "conflicting-definition"))
def test_invalid_history_permutations_have_the_same_fixed_diagnostics(defect: str) -> None:
    history = _events(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE)
    if defect == "duplicate-ordinal":
        history += (history[1],)
    else:
        other = replace(
            OPERATION, generation_ref="other-generation", predecessor_id="missing-previous"
        )
        history += (policy.OperationEvent(other, 4, E.PROGRESS),)
    results = [
        policy.evaluate_reuse_policy(_request(history=order)) for order in permutations(history)
    ]
    assert all(result == results[0] for result in results)
    assert results[0].state is S.INPUT_UNVERIFIABLE
    assert results[0].transitions_valid is False


def test_every_fixed_refusal_reason_has_corresponding_evidence() -> None:
    r = policy.RefusalReason
    other = replace(OPERATION, binding=replace(BINDING, pair_ref="synthetic-other"))
    conflict = replace(OPERATION, generation_ref="other-generation")
    previous = replace(OPERATION, operation_id="synthetic-previous")
    current = replace(OPERATION, predecessor_id=previous.operation_id)
    cases = [
        (_request(registered=False), r.UNREGISTERED),
        (_request(), r.HISTORY_ABSENT),
        (_request(history_status=H.MISSING), r.HISTORY_MISSING),
        (_request(history_status=H.CORRUPT), r.HISTORY_CORRUPT),
        (_request(history_status=H.UNREADABLE), r.HISTORY_UNREADABLE),
        (None, r.INVALID_INPUT),
        (_request(history=_events(E.START_RECORDED, operation=other)), r.BINDING_MISMATCH),
        (_request(history=_events(E.START_RECORDED, operation=conflict)), r.CONFLICTING_OPERATION),
        (
            _request(history=_events(E.START_RECORDED, operation=previous)),
            r.MISSING_CURRENT_OPERATION,
        ),
        (
            policy.PolicyInput(current, _events(E.START_RECORDED, operation=current)),
            r.MISSING_PREDECESSOR,
        ),
        (
            _request(
                history=_events(E.START_RECORDED) + _events(E.START_RECORDED, operation=previous)
            ),
            r.INVALID_OPERATION_CHAIN,
        ),
        (
            policy.PolicyInput(
                current,
                _events(E.START_RECORDED, operation=current)
                + _events(E.START_RECORDED, operation=previous),
            ),
            r.PREDECESSOR_NOT_COMPLETED,
        ),
        (
            _request(history=(policy.OperationEvent(OPERATION, 2, E.START_RECORDED),)),
            r.INVALID_EVENT_SEQUENCE,
        ),
        (_request(E.PROGRESS), r.MISSING_START),
        (_request(E.START_RECORDED, E.COMPLETION_EVIDENCE), r.INVALID_TRANSITION),
        (_request(E.START_RECORDED, E.FAILED), r.UNRESOLVED_FAILURE),
        (_request(E.START_RECORDED, E.INTERRUPTED), r.UNRESOLVED_INTERRUPTION),
        (_request(E.START_RECORDED, E.COMMIT_UNCERTAIN), r.UNRESOLVED_COMMIT),
        (_request(E.START_RECORDED), r.START_ONLY),
        (_request(E.START_RECORDED, E.PROGRESS), r.OPERATION_INCOMPLETE),
        (
            _request(E.START_RECORDED, E.PROGRESS, E.COMPLETION_EVIDENCE),
            r.COMPLETION_NOT_AUTHORIZATION,
        ),
    ]
    observed = set()
    for case_input, expected in cases:
        result = policy.evaluate_reuse_policy(case_input)
        assert expected in result.reasons
        assert r.POLICY_NEVER_AUTHORIZES in result.reasons
        observed.update(result.reasons)
    assert observed == set(r)


def test_model_has_only_pure_standard_library_dependencies_and_no_runtime_consumer() -> None:
    path = Path(policy.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imports <= {"__future__", "dataclasses", "enum", "typing"}
    assert not any(isinstance(node, ast.Import) for node in ast.walk(tree))
    assert not any(
        isinstance(node, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef))
        for node in ast.walk(tree)
    )
    names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not names & {"open", "print", "exec", "eval", "compile", "__import__", "input"}
    attrs = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not attrs & {
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "replace",
        "chmod",
        "mkdir",
        "rmdir",
        "touch",
        "open",
        "now",
        "utcnow",
        "time",
        "sleep",
        "random",
        "randint",
        "getenv",
        "refresh",
        "authorize",
        "request",
        "run",
        "Popen",
        "connect",
        "socket",
        "acquire",
        "sha256",
        "sha1",
        "dumps",
        "dump",
    }
    for module in path.parent.glob("*.py"):
        if module != path:
            assert "production_write_token_reuse_policy" not in module.read_text(encoding="utf-8")
    assert "production_write_token_pair_inspection" not in path.read_text(encoding="utf-8")
