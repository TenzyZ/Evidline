"""Pure, adapter-neutral mutation decision engine (V1 Phase 3).

Implements the accepted ADR-0011 policy over an already-evaluated
``PathEvaluation`` and a validated ``StateDocument``.  ``decide_mutation`` is
pure: it performs no filesystem, subprocess, network, clock, randomness, or
persistence work.  ``evaluate_and_decide`` is the thin wrapper that first runs
the existing path evaluation and then delegates to the pure core.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from typing import Final

from evidline import paths as _paths
from evidline import state as _state
from evidline.paths import (
    PathEvaluation,
    evaluate_mutation_path,
    has_protected_component,
)
from evidline.state import (
    Decision,
    Execution,
    Intent,
    InvariantEnforcement,
    InvariantStatus,
    StateDocument,
    StateValidationError,
    Task,
    TaskStatus,
    Verification,
    validate_state,
)


MUTATION_SCHEMA_VERSION: Final = 1


class MutationOperation(str, Enum):
    """Informational mutation verb.  It never participates in any gate."""

    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    RENAME = "RENAME"
    MOVE = "MOVE"


class MutationRisk(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MutationOutcome(str, Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    BLOCK = "BLOCK"


class MutationReason(str, Enum):
    REQUEST_INTENT_DENIED = "REQUEST_INTENT_DENIED"
    REQUEST_INTENT_INSUFFICIENT = "REQUEST_INTENT_INSUFFICIENT"
    NO_ACTIVE_TASK = "NO_ACTIVE_TASK"
    CRITICAL_RISK = "CRITICAL_RISK"
    TARGET_UNSAFE = "TARGET_UNSAFE"
    TARGET_PROTECTED = "TARGET_PROTECTED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    INSUFFICIENT_AUTHORIZATION = "INSUFFICIENT_AUTHORIZATION"
    INVARIANT_CONFLICT = "INVARIANT_CONFLICT"
    INVARIANT_UNRESOLVED = "INVARIANT_UNRESOLVED"
    HIGH_EVIDENCE_INSUFFICIENT = "HIGH_EVIDENCE_INSUFFICIENT"


class MutationInputError(ValueError):
    """A mutation request or decision input is structurally invalid."""


@dataclass(frozen=True, slots=True)
class MutationRequest:
    request_intent: Intent
    risk: MutationRisk
    operation: MutationOperation | None = None
    authorizing_ids: tuple[str, ...] = ()
    declared_scope: tuple[str, ...] = ()
    supporting_claim_ids: tuple[str, ...] = ()
    ephemeral_evidence_ids: tuple[str, ...] = ()
    asserted_conflicting_invariant_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MutationDecision:
    outcome: MutationOutcome
    risk: MutationRisk
    target: str | None
    reasons: tuple[MutationReason, ...]
    next_step: str
    conflicting_invariant_ids: tuple[str, ...]
    advisory_invariant_ids: tuple[str, ...]
    applicable_invariant_ids: tuple[str, ...]


_RISK_ORDER: Final = {
    MutationRisk.LOW: 0,
    MutationRisk.NORMAL: 1,
    MutationRisk.HIGH: 2,
    MutationRisk.CRITICAL: 3,
}

_OUTCOME_ORDER: Final = {
    MutationOutcome.ALLOW: 0,
    MutationOutcome.ASK: 1,
    MutationOutcome.BLOCK: 2,
}

_BASELINE_OUTCOME: Final = {
    MutationRisk.LOW: MutationOutcome.ALLOW,
    MutationRisk.NORMAL: MutationOutcome.ALLOW,
    MutationRisk.HIGH: MutationOutcome.ASK,
    MutationRisk.CRITICAL: MutationOutcome.BLOCK,
}

_ALLOW_NEXT_STEP: Final = ""

_NEXT_STEP_PRIORITY: Final = (
    MutationReason.TARGET_PROTECTED,
    MutationReason.TARGET_UNSAFE,
    MutationReason.REQUEST_INTENT_DENIED,
    MutationReason.CRITICAL_RISK,
    MutationReason.INVARIANT_CONFLICT,
    MutationReason.INVARIANT_UNRESOLVED,
    MutationReason.SCOPE_VIOLATION,
    MutationReason.NO_ACTIVE_TASK,
    MutationReason.INSUFFICIENT_AUTHORIZATION,
    MutationReason.HIGH_EVIDENCE_INSUFFICIENT,
    MutationReason.REQUEST_INTENT_INSUFFICIENT,
)

_NEXT_STEP_TEXT: Final = {
    MutationReason.TARGET_PROTECTED: (
        "Target is protected project metadata; choose a target outside "
        ".git and .evidline."
    ),
    MutationReason.TARGET_UNSAFE: (
        "Target is outside the project root or cannot be resolved; choose a "
        "target inside the project root."
    ),
    MutationReason.REQUEST_INTENT_DENIED: (
        "Request intent is DENIED; obtain a human decision before re-requesting."
    ),
    MutationReason.CRITICAL_RISK: (
        "Risk is CRITICAL; a human must perform this change outside Evidline."
    ),
    MutationReason.INVARIANT_CONFLICT: (
        "Resolve or supersede the conflicting invariant before re-requesting."
    ),
    MutationReason.INVARIANT_UNRESOLVED: (
        "An asserted invariant id does not resolve; supply an existing invariant id."
    ),
    MutationReason.SCOPE_VIOLATION: (
        "Target is outside the declared scope; narrow the target or declare a "
        "scope inside the project root."
    ),
    MutationReason.NO_ACTIVE_TASK: (
        "No ACTIVE task anchors this change; activate an authorized task."
    ),
    MutationReason.INSUFFICIENT_AUTHORIZATION: (
        "Supply at least one authorizing id resolving to an AUTHORIZED decision "
        "or an ACTIVE task."
    ),
    MutationReason.HIGH_EVIDENCE_INSUFFICIENT: (
        "Supply a reproducible supporting claim whose evidence ids are all "
        "covered by ephemeral verified evidence."
    ),
    MutationReason.REQUEST_INTENT_INSUFFICIENT: (
        "Request human confirmation before executing."
    ),
}


def decide_mutation(
    request: MutationRequest,
    evaluation: PathEvaluation,
    state: StateDocument,
) -> MutationDecision:
    """Return a deterministic decision without touching the filesystem."""

    _validate_request(request)
    if type(evaluation) is not PathEvaluation:
        raise MutationInputError("evaluation must be a PathEvaluation")
    if type(state) is not StateDocument:
        raise MutationInputError("state must be a StateDocument")
    try:
        validate_state(state)
    except StateValidationError as error:
        raise MutationInputError(str(error)) from error

    reasons: list[MutationReason] = []
    seen_reasons: set[MutationReason] = set()

    def escalate(reason: MutationReason) -> None:
        if reason not in seen_reasons:
            seen_reasons.add(reason)
            reasons.append(reason)

    outcome = _BASELINE_OUTCOME[request.risk]
    risk = request.risk

    # Path safety and protection.  Intent never overrides an unsafe target.
    if not evaluation.safe:
        if (
            evaluation.canonical_root is not None
            and evaluation.canonical_target is not None
            and has_protected_component(
                evaluation.canonical_root, evaluation.canonical_target
            )
        ):
            risk = _max_risk(risk, MutationRisk.CRITICAL)
            escalate(MutationReason.TARGET_PROTECTED)
        else:
            escalate(MutationReason.TARGET_UNSAFE)
        outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # Transient request intent.
    if request.request_intent is Intent.DENIED:
        escalate(MutationReason.REQUEST_INTENT_DENIED)
        outcome = _max_outcome(outcome, MutationOutcome.BLOCK)
    elif request.request_intent is Intent.PROPOSED:
        escalate(MutationReason.REQUEST_INTENT_INSUFFICIENT)
        if risk is MutationRisk.HIGH or risk is MutationRisk.CRITICAL:
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)
        else:
            outcome = _max_outcome(outcome, MutationOutcome.ASK)

    # CRITICAL risk always blocks.
    if risk is MutationRisk.CRITICAL:
        escalate(MutationReason.CRITICAL_RISK)
        outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # ACTIVE task anchoring.
    if _active_task(state) is None:
        if risk is MutationRisk.NORMAL:
            escalate(MutationReason.NO_ACTIVE_TASK)
            outcome = _max_outcome(outcome, MutationOutcome.ASK)
        elif risk is MutationRisk.HIGH:
            escalate(MutationReason.NO_ACTIVE_TASK)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # Authorization ids.  Execution never provides authorization.
    if risk is MutationRisk.NORMAL:
        if request.authorizing_ids:
            if not all(_authorizing_validity(state, request.authorizing_ids)):
                escalate(MutationReason.INSUFFICIENT_AUTHORIZATION)
                outcome = _max_outcome(outcome, MutationOutcome.BLOCK)
    elif risk is MutationRisk.HIGH:
        if not any(_authorizing_validity(state, request.authorizing_ids)):
            escalate(MutationReason.INSUFFICIENT_AUTHORIZATION)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # HIGH requires caller-supplied ephemeral current evidence support.
    if risk is MutationRisk.HIGH:
        if not _high_support_satisfied(state, request):
            escalate(MutationReason.HIGH_EVIDENCE_INSUFFICIENT)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # Declared scope may only narrow.
    if request.declared_scope:
        if not _within_declared_scope(evaluation, request.declared_scope):
            escalate(MutationReason.SCOPE_VIOLATION)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    # Invariants.
    applicable_ids, advisory_ids = _classify_invariants(state)
    advisory_set: set[str] = set(advisory_ids)
    conflicting_ids: list[str] = []
    for invariant_id in sorted(set(request.asserted_conflicting_invariant_ids)):
        invariant = _invariant_by_id(state, invariant_id)
        if invariant is None:
            escalate(MutationReason.INVARIANT_UNRESOLVED)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)
        elif invariant.status is InvariantStatus.SUPERSEDED:
            continue  # non-operative: no escalation, no reason
        elif invariant.enforcement is InvariantEnforcement.ADVISE:
            advisory_set.add(invariant_id)  # no escalation, no MutationReason
        else:
            conflicting_ids.append(invariant_id)
            escalate(MutationReason.INVARIANT_CONFLICT)
            outcome = _max_outcome(outcome, MutationOutcome.BLOCK)

    if outcome is MutationOutcome.ALLOW:
        next_step = _ALLOW_NEXT_STEP
    else:
        next_step = _select_next_step(reasons)

    target = (
        str(evaluation.canonical_target)
        if evaluation.canonical_target is not None
        else None
    )

    return MutationDecision(
        outcome=outcome,
        risk=risk,
        target=target,
        reasons=tuple(reasons),
        next_step=next_step,
        conflicting_invariant_ids=tuple(sorted(set(conflicting_ids))),
        advisory_invariant_ids=tuple(sorted(advisory_set)),
        applicable_invariant_ids=tuple(sorted(applicable_ids)),
    )


def evaluate_and_decide(
    request: MutationRequest,
    root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    state: StateDocument,
) -> MutationDecision:
    """Evaluate the target path, then apply the pure decision core."""

    evaluation = evaluate_mutation_path(root, target)
    return decide_mutation(request, evaluation, state)


def load_and_decide(
    project_root: str | os.PathLike[str],
    request: MutationRequest,
    target: str | os.PathLike[str],
) -> MutationDecision:
    """Discover and load current state before evaluating one target."""

    root = _paths.discover_project_root(project_root)
    if root is None:
        raise _state.StateNotInitializedError("project root could not be discovered")
    state = _state.load_state(root)
    return evaluate_and_decide(request, root, target, state)


def explain(decision: MutationDecision) -> str:
    """Return a deterministic human-readable rendering of a decision."""

    if type(decision) is not MutationDecision:
        raise MutationInputError("decision must be a MutationDecision")
    reasons = ", ".join(reason.value for reason in decision.reasons) or "-"
    target = decision.target if decision.target is not None else "-"
    return (
        f"outcome: {decision.outcome.value}\n"
        f"risk: {decision.risk.value}\n"
        f"target: {target}\n"
        f"reasons: {reasons}\n"
        f"conflicting_invariant_ids: {_render_ids(decision.conflicting_invariant_ids)}\n"
        f"advisory_invariant_ids: {_render_ids(decision.advisory_invariant_ids)}\n"
        f"applicable_invariant_ids: {_render_ids(decision.applicable_invariant_ids)}\n"
        f"next_step: {decision.next_step}"
    )


def render_decision_json(decision: MutationDecision) -> str:
    """Return canonical UTF-8-compatible JSON with one trailing newline."""

    if type(decision) is not MutationDecision:
        raise MutationInputError("decision must be a MutationDecision")
    payload = {
        "outcome": decision.outcome.value,
        "risk": decision.risk.value,
        "target": decision.target,
        "reasons": [reason.value for reason in decision.reasons],
        "next_step": decision.next_step,
        "conflicting_invariant_ids": list(decision.conflicting_invariant_ids),
        "advisory_invariant_ids": list(decision.advisory_invariant_ids),
        "applicable_invariant_ids": list(decision.applicable_invariant_ids),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _validate_request(request: MutationRequest) -> None:
    if type(request) is not MutationRequest:
        raise MutationInputError("request must be a MutationRequest")
    if not isinstance(request.request_intent, Intent):
        raise MutationInputError("request_intent must be a state.Intent")
    if not isinstance(request.risk, MutationRisk):
        raise MutationInputError("risk must be a MutationRisk")
    if request.operation is not None and not isinstance(
        request.operation, MutationOperation
    ):
        raise MutationInputError("operation must be a MutationOperation or None")
    for field_name, values in (
        ("authorizing_ids", request.authorizing_ids),
        ("declared_scope", request.declared_scope),
        ("supporting_claim_ids", request.supporting_claim_ids),
        ("ephemeral_evidence_ids", request.ephemeral_evidence_ids),
        ("asserted_conflicting_invariant_ids", request.asserted_conflicting_invariant_ids),
    ):
        if not isinstance(values, tuple):
            raise MutationInputError(f"{field_name} must be a tuple")
        for value in values:
            if not isinstance(value, str) or not value:
                raise MutationInputError(
                    f"{field_name} must contain non-empty strings"
                )


def _active_task(state: StateDocument) -> Task | None:
    for task in state.tasks:
        if task.status is TaskStatus.ACTIVE:
            return task
    return None


def _authorizing_validity(
    state: StateDocument, authorizing_ids: tuple[str, ...]
) -> list[bool]:
    decisions = {item.id: item for item in state.decisions}
    tasks = {item.id: item for item in state.tasks}
    result: list[bool] = []
    for authorizing_id in authorizing_ids:
        record: Decision | Task | None = decisions.get(authorizing_id)
        if record is None:
            record = tasks.get(authorizing_id)
        if record is None:
            result.append(False)
        elif isinstance(record, Decision):
            result.append(record.intent is Intent.AUTHORIZED)
        else:
            result.append(record.status is TaskStatus.ACTIVE)
    return result


def _high_support_satisfied(
    state: StateDocument, request: MutationRequest
) -> bool:
    claims = {item.id: item for item in state.claims}
    evidence = {item.id: item for item in state.evidence}
    ephemeral = set(request.ephemeral_evidence_ids)

    # Ephemeral evidence: unresolved and NOT_RUN/EXECUTED are neutral; only
    # FAILED/BLOCKED disqualify.  Execution never positively verifies.
    for evidence_id in request.ephemeral_evidence_ids:
        record = evidence.get(evidence_id)
        if record is None:
            continue
        if record.execution in (Execution.FAILED, Execution.BLOCKED):
            return False

    # Supporting claims: a disqualifying record anywhere defeats HIGH support,
    # even if another supplied claim is satisfying.
    has_satisfying = False
    for claim_id in request.supporting_claim_ids:
        claim = claims.get(claim_id)
        if claim is None:
            return False
        if claim.verification in (
            Verification.FAILED,
            Verification.STALE,
            Verification.VERIFIED,
        ):
            return False
        if not claim.reproducible:
            continue
        if not claim.evidence_ids:
            continue
        if not set(claim.evidence_ids).issubset(ephemeral):
            continue
        has_satisfying = True

    return has_satisfying


def _within_declared_scope(
    evaluation: PathEvaluation, declared_scope: tuple[str, ...]
) -> bool:
    root = evaluation.canonical_root
    target = evaluation.canonical_target
    if root is None or target is None:
        return False
    root_text = os.path.normcase(os.path.normpath(os.fspath(root)))
    target_text = os.path.normcase(os.path.normpath(os.fspath(target)))

    usable_scopes: list[str] = []
    for scope in declared_scope:
        if os.path.isabs(scope):
            scope_path = scope
        else:
            scope_path = os.path.join(os.fspath(root), scope)
        scope_text = os.path.normcase(os.path.normpath(scope_path))
        try:
            common = os.path.commonpath((scope_text, root_text))
        except ValueError:
            return False
        if common != root_text:
            return False
        usable_scopes.append(scope_text)

    for scope_text in usable_scopes:
        try:
            common = os.path.commonpath((scope_text, target_text))
        except ValueError:
            continue
        if common == scope_text:
            return True
    return False


def _classify_invariants(
    state: StateDocument,
) -> tuple[list[str], list[str]]:
    applicable: list[str] = []
    advisory: list[str] = []
    for invariant in state.invariants:
        if invariant.status is not InvariantStatus.ACTIVE:
            continue
        if invariant.enforcement is InvariantEnforcement.BLOCK:
            applicable.append(invariant.id)
        elif invariant.enforcement is InvariantEnforcement.ADVISE:
            advisory.append(invariant.id)
    return applicable, advisory


def _invariant_by_id(state: StateDocument, invariant_id: str):
    for invariant in state.invariants:
        if invariant.id == invariant_id:
            return invariant
    return None


def _max_outcome(
    left: MutationOutcome, right: MutationOutcome
) -> MutationOutcome:
    return left if _OUTCOME_ORDER[left] >= _OUTCOME_ORDER[right] else right


def _max_risk(left: MutationRisk, right: MutationRisk) -> MutationRisk:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


def _select_next_step(reasons: tuple[MutationReason, ...]) -> str:
    for reason in _NEXT_STEP_PRIORITY:
        if reason in reasons:
            return _NEXT_STEP_TEXT[reason]
    return ""


def _render_ids(ids: tuple[str, ...]) -> str:
    return "[" + ", ".join(ids) + "]"
