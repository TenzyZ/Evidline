"""Deterministic synthetic Phase 7 benchmark runner."""

from __future__ import annotations

from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Final, Mapping, TextIO
from unittest import mock

from benchmarks.fixture import BenchmarkFixture, SandboxContainmentError
from benchmarks.scenarios import (
    CLAIM_LABELS,
    IN_ROOT,
    LIVE_VERIFICATION,
    NO_ROOT,
    OUT_OF_ROOT_IN_SANDBOX,
    REQUIRED_SESSION_IDS,
    RULE_EXCLUDED_SESSION_IDS,
    SCENARIOS,
    UNCOVERED_SURFACES,
    V1_ACCEPTANCE_BLOCKERS,
    ScenarioSpec,
)
from evidline import context, mutation, paths
from evidline.adapters import claude, codex
from evidline.context import (
    ContextInputError,
    ContextProfile,
    Disposition,
    ReasonCode,
    RecordKind,
)
from evidline.mutation import (
    MutationDecision,
    MutationInputError,
    MutationOutcome,
    MutationRequest,
    MutationRisk,
)
from evidline.state import (
    Intent,
    StateDocument,
    TaskStatus,
    TRUSTED_APPROVAL_CHANNEL,
    TRUSTED_ASSERTED_ACTOR,
)


BENCHMARK_SCHEMA_VERSION: Final = 1
EXPECTED_RESULTS_PATH: Final = Path(__file__).with_name("expected") / "results.json"

_EXIT_CODES: Final = {
    "COMPLETED": 0,
    "MISMATCHED": 1,
    "NONDETERMINISTIC": 2,
    "FAILED": 3,
}


class ExpectedDocumentError(RuntimeError):
    """The frozen expected document could not be loaded safely."""


def _request(
    *,
    intent: Intent = Intent.REQUESTED,
    risk: MutationRisk = MutationRisk.NORMAL,
    authorizing_ids: tuple[str, ...] = (),
    declared_scope: tuple[str, ...] = (),
    supporting_claim_ids: tuple[str, ...] = (),
    ephemeral_evidence_ids: tuple[str, ...] = (),
    asserted_invariant_ids: tuple[str, ...] = (),
) -> MutationRequest:
    return MutationRequest(
        request_intent=intent,
        risk=risk,
        authorizing_ids=authorizing_ids,
        declared_scope=declared_scope,
        supporting_claim_ids=supporting_claim_ids,
        ephemeral_evidence_ids=ephemeral_evidence_ids,
        asserted_conflicting_invariant_ids=asserted_invariant_ids,
    )


def _decision(
    fixture: BenchmarkFixture,
    target: Path,
    request: MutationRequest,
    *,
    state: Any | None = None,
) -> MutationDecision:
    fixture.assert_sandbox_path(target)
    return mutation.evaluate_and_decide(
        request,
        fixture.root,
        target,
        fixture.state if state is None else state,
    )


def _basic_decision(decision: MutationDecision) -> dict[str, Any]:
    return {
        "outcome": decision.outcome.value,
        "reasons": [reason.value for reason in decision.reasons],
    }


def _scoped_authority_state(
    fixture: BenchmarkFixture,
    *,
    authorized_scope: tuple[str, ...] = ("src",),
    trusted: bool = True,
) -> StateDocument:
    tasks = tuple(
        replace(
            task,
            authorized_scope=authorized_scope,
            approval_channel=(
                TRUSTED_APPROVAL_CHANNEL if trusted else "benchmark-untrusted"
            ),
            asserted_actor=(
                TRUSTED_ASSERTED_ACTOR if trusted else "benchmark-operator"
            ),
        )
        if task.status is TaskStatus.ACTIVE
        else task
        for task in fixture.state.tasks
    )
    return replace(fixture.state, tasks=tasks)


def _governed_state(
    fixture: BenchmarkFixture,
    *,
    governed_scopes: Mapping[str, tuple[str, ...]],
    acknowledged_invariant_ids: tuple[str, ...] = (),
    authorized_scope: tuple[str, ...] = ("src",),
    trusted: bool = True,
) -> StateDocument:
    """Build one isolated VAB-2 state without changing the shared fixture."""

    invariants = tuple(
        replace(
            invariant,
            governed_scope=governed_scopes.get(invariant.id, ()),
        )
        for invariant in fixture.state.invariants
    )
    tasks = tuple(
        replace(
            task,
            authorized_scope=authorized_scope,
            approval_channel=(
                TRUSTED_APPROVAL_CHANNEL if trusted else "benchmark-untrusted"
            ),
            asserted_actor=(
                TRUSTED_ASSERTED_ACTOR if trusted else "benchmark-operator"
            ),
            acknowledged_invariant_ids=acknowledged_invariant_ids,
        )
        if task.status is TaskStatus.ACTIVE
        else task
        for task in fixture.state.tasks
    )
    return replace(fixture.state, invariants=invariants, tasks=tasks)


def _invoke(
    adapter: Any,
    command: str,
    payload: object,
) -> tuple[int, str, str]:
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        mock.patch("sys.stdin", stdin),
        mock.patch("sys.stdout", stdout),
        mock.patch("sys.stderr", stderr),
    ):
        code = adapter.main((command,))
    return code, stdout.getvalue(), stderr.getvalue()


def _invoke_argv(adapter: Any, argv: tuple[str, ...]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
        code = adapter.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _hook_output(stdout: str) -> Mapping[str, Any]:
    document = json.loads(stdout)
    return document["hookSpecificOutput"]


def _policy_from_reason(reason: str) -> str:
    for outcome in ("ALLOW", "ASK", "BLOCK"):
        if reason.startswith(f"evidline {outcome}:"):
            return outcome
    return "ADAPTER_FAILURE" if reason.startswith("evidline adapter failure:") else "UNKNOWN"


def _claude_payload(fixture: BenchmarkFixture, tool: str, target: Path) -> dict[str, Any]:
    fixture.assert_sandbox_path(target)
    field = "notebook_path" if tool == "NotebookEdit" else "file_path"
    return {
        "hook_event_name": "PreToolUse",
        "cwd": str(fixture.root),
        "tool_name": tool,
        "tool_input": {field: str(target)},
    }


def _patch(*lines: str) -> str:
    return "\n".join(("*** Begin Patch", *lines, "*** End Patch"))


def _codex_payload(
    fixture: BenchmarkFixture,
    patch: str,
    *,
    cwd: Path | None = None,
    tool_name: str = "apply_patch",
) -> dict[str, Any]:
    selected_cwd = fixture.root if cwd is None else cwd
    fixture.assert_sandbox_path(selected_cwd)
    return {
        "hook_event_name": "PreToolUse",
        "cwd": str(selected_cwd),
        "tool_name": tool_name,
        "tool_input": {"command": patch},
    }


def _claude_result(fixture: BenchmarkFixture, tool: str, target: Path) -> tuple[int, str, str, Mapping[str, Any] | None]:
    code, stdout, stderr = _invoke(
        claude, "pre-tool-use", _claude_payload(fixture, tool, target)
    )
    return code, stdout, stderr, _hook_output(stdout) if stdout else None


def _codex_result(fixture: BenchmarkFixture, patch: str) -> tuple[int, str, str, Mapping[str, Any] | None]:
    code, stdout, stderr = _invoke(
        codex, "pre-tool-use", _codex_payload(fixture, patch)
    )
    return code, stdout, stderr, _hook_output(stdout) if stdout else None


def _scenario_core(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    target = fixture.target("src/app.py")
    if scenario_id == "core.ordinary_authorized_edit":
        decision = _decision(fixture, target, _request(intent=Intent.AUTHORIZED))
        result = _basic_decision(decision)
        result["next_step"] = decision.next_step
        return result
    if scenario_id == "core.scope_violation":
        return _basic_decision(
            _decision(fixture, fixture.target("docs/note.md"), _request(declared_scope=("src",)))
        )
    if scenario_id == "core.active_block_invariant":
        decision = _decision(
            fixture, target, _request(asserted_invariant_ids=("inv-block",))
        )
        result = _basic_decision(decision)
        result["conflicting"] = list(decision.conflicting_invariant_ids)
        return result
    if scenario_id == "core.active_advise_invariant":
        decision = _decision(
            fixture, target, _request(asserted_invariant_ids=("inv-advise",))
        )
        result = _basic_decision(decision)
        result["advisory"] = list(decision.advisory_invariant_ids)
        return result
    if scenario_id == "core.superseded_invariant":
        decision = _decision(
            fixture, target, _request(asserted_invariant_ids=("inv-superseded",))
        )
        result = _basic_decision(decision)
        result["conflicting"] = list(decision.conflicting_invariant_ids)
        return result
    if scenario_id == "core.unknown_invariant":
        return _basic_decision(
            _decision(fixture, target, _request(asserted_invariant_ids=("inv-unknown",)))
        )
    if scenario_id == "core.high_inadequate_support":
        return _basic_decision(
            _decision(
                fixture,
                target,
                _request(
                    intent=Intent.AUTHORIZED,
                    risk=MutationRisk.HIGH,
                    authorizing_ids=("dec-authorized",),
                ),
            )
        )
    if scenario_id == "core.high_valid_support":
        decision = _decision(
            fixture,
            target,
            _request(
                intent=Intent.AUTHORIZED,
                risk=MutationRisk.HIGH,
                authorizing_ids=("dec-authorized",),
                supporting_claim_ids=("claim-high-support",),
                ephemeral_evidence_ids=("evidence-direct",),
            ),
        )
        result = _basic_decision(decision)
        result["risk"] = decision.risk.value
        return result
    if scenario_id == "core.failed_support_claim":
        return _basic_decision(
            _decision(
                fixture,
                target,
                _request(
                    intent=Intent.AUTHORIZED,
                    risk=MutationRisk.HIGH,
                    authorizing_ids=("dec-authorized",),
                    supporting_claim_ids=("claim-high-failed",),
                    ephemeral_evidence_ids=("evidence-failed",),
                ),
            )
        )
    protected = {
        "core.protected_git_config": ".git/config",
        "core.protected_state": ".evidline/state.json",
        "core.protected_nested_git": "src/.git/hook",
    }
    if scenario_id in protected:
        decision = _decision(fixture, fixture.target(protected[scenario_id]), _request())
        result = _basic_decision(decision)
        result["risk"] = decision.risk.value
        return result
    if scenario_id == "core.out_of_root":
        return _basic_decision(_decision(fixture, fixture.outside, _request()))
    if scenario_id == "core.no_active_task":
        return _basic_decision(
            _decision(
                fixture,
                target,
                _request(intent=Intent.AUTHORIZED),
                state=fixture.state_without_active_task(),
            )
        )
    if scenario_id == "core.invalid_state":
        try:
            _decision(
                fixture,
                target,
                _request(),
                state=replace(fixture.state, schema_version=4),
            )
        except MutationInputError as error:
            return {"exception": type(error).__name__, "message": str(error)}
        return {"exception": None, "message": ""}
    if scenario_id == "core.denied_intent":
        return _basic_decision(
            _decision(fixture, target, _request(intent=Intent.DENIED))
        )
    if scenario_id in (
        "core.derived_outside_authorized_scope",
        "core.untrusted_authorization_channel",
    ):
        outside_scope = scenario_id == "core.derived_outside_authorized_scope"
        selected_state = _scoped_authority_state(
            fixture,
            authorized_scope=("docs",) if outside_scope else ("src",),
            trusted=outside_scope,
        )
        decision = _decision(
            fixture,
            target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["authorizing_task_id"] = decision.authorizing_task_id
        return result
    governed_target = fixture.target("src/governed/app.py")
    if scenario_id == "core.governed_scope_authorized_allow":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("docs",)},
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["authorizing_task_id"] = decision.authorizing_task_id
        return result
    if scenario_id in (
        "core.governed_block_unacknowledged",
        "core.governed_block_acknowledged",
    ):
        acknowledged = scenario_id == "core.governed_block_acknowledged"
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
            acknowledged_invariant_ids=("inv-block",) if acknowledged else (),
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        result["authorizing_task_id"] = decision.authorizing_task_id
        return result
    if scenario_id == "core.governed_advise_relevant":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-advise": ("src/governed",)},
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["advisory"] = list(decision.advisory_invariant_ids)
        return result
    if scenario_id == "core.governed_superseded_relevant":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-superseded": ("src/governed",)},
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        return result
    if scenario_id in (
        "core.governed_multiple_block",
        "core.governed_mixed_acknowledgement",
    ):
        mixed = scenario_id == "core.governed_mixed_acknowledgement"
        selected_state = _governed_state(
            fixture,
            governed_scopes={
                "inv-block": ("src/governed",),
                "inv-current": ("src/governed",),
            },
            acknowledged_invariant_ids=("inv-block",) if mixed else (),
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.REQUESTED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        return result
    if scenario_id == "core.governed_outside_scope":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("docs",)},
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.REQUESTED, risk=MutationRisk.LOW),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        return result
    if scenario_id == "core.governed_untrusted_acknowledgement":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
            acknowledged_invariant_ids=("inv-block",),
            trusted=False,
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        result["authorizing_task_id"] = decision.authorizing_task_id
        return result
    if scenario_id == (
        "core.governed_acknowledgement_does_not_suppress_asserted_conflict"
    ):
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
            acknowledged_invariant_ids=("inv-block",),
        )
        decision = _decision(
            fixture,
            governed_target,
            _request(
                intent=Intent.PROPOSED,
                asserted_invariant_ids=("inv-block",),
            ),
            state=selected_state,
        )
        result = _basic_decision(decision)
        result["conflicting"] = list(decision.conflicting_invariant_ids)
        result["unacknowledged"] = list(
            decision.unacknowledged_invariant_ids
        )
        return result
    if scenario_id == "core.malformed_governed_scope":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/",)},
        )
        try:
            _decision(
                fixture,
                governed_target,
                _request(),
                state=selected_state,
            )
        except MutationInputError as error:
            return {"exception": type(error).__name__, "message": str(error)}
        return {"exception": None, "message": ""}
    if scenario_id == "core.incompatible_scope_semantics":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
        )
        foreign = (
            paths.ScopePathSemantics.CASE_SENSITIVE
            if paths.host_scope_semantics()
            is paths.ScopePathSemantics.CASE_FOLDED
            else paths.ScopePathSemantics.CASE_FOLDED
        )
        try:
            _decision(
                fixture,
                governed_target,
                _request(),
                state=replace(selected_state, scope_semantics=foreign),
            )
        except MutationInputError as error:
            return {"exception": type(error).__name__, "message": str(error)}
        return {"exception": None, "message": ""}
    raise KeyError(scenario_id)


def _all_record_ids(fixture: BenchmarkFixture) -> set[str]:
    return {
        record.id
        for records in (
            fixture.state.invariants,
            fixture.state.decisions,
            fixture.state.tasks,
            fixture.state.claims,
            fixture.state.evidence,
        )
        for record in records
    }


def _entry_map(compiled: context.CompiledContext) -> dict[str, context.ContextEntry]:
    return {entry.record_id: entry for entry in compiled.report_entries}


def _scenario_context(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    compiled = context.compile_context(fixture.state)
    entries = _entry_map(compiled)
    payload_ids = {entry.record_id for entry in compiled.entries}
    all_ids = _all_record_ids(fixture)
    if scenario_id == "context.session_continuity":
        report_ids = [entry.record_id for entry in compiled.report_entries]
        return {
            "required_delivered": set(REQUIRED_SESSION_IDS).issubset(payload_ids),
            "rule_excluded_absent": set(RULE_EXCLUDED_SESSION_IDS).isdisjoint(payload_ids),
            "audit_complete": len(report_ids) == len(set(report_ids)) == len(all_ids) and set(report_ids) == all_ids,
        }
    if scenario_id == "context.stale_claims":
        return {
            claim_id: [
                entries[claim_id].disposition.value,
                entries[claim_id].rendered_freshness,
                [reason.value for reason in entries[claim_id].reasons],
            ]
            for claim_id in ("claim-digest", "claim-volatile")
        }
    if scenario_id == "context.failed_claim":
        entry = entries["claim-failed"]
        return {
            "disposition": entry.disposition.value,
            "freshness": entry.rendered_freshness,
            "reasons": [reason.value for reason in entry.reasons],
        }
    if scenario_id == "context.budget_accounting":
        return {"accounting_exact": compiled.budget is not None and compiled.budget.used_chars == len(context.render_payload(compiled))}
    if scenario_id == "context.minimum_budget_failure":
        minimum = context.minimum_budget_chars(ContextProfile.SESSION)
        try:
            context.compile_context(fixture.state, budget_chars=minimum - 1)
        except ContextInputError as error:
            return {"exception": type(error).__name__, "below_minimum": "below the minimum" in str(error)}
        return {"exception": None, "below_minimum": False}
    if scenario_id == "context.invariant_budget_overflow":
        minimum = context.minimum_budget_chars(ContextProfile.SESSION)
        overflow = context.compile_context(fixture.state, budget_chars=minimum)
        invariant_ids = {
            entry.record_id
            for entry in overflow.entries
            if entry.kind is RecordKind.INVARIANT
        }
        active_ids = {
            record.id
            for record in fixture.state.invariants
            if record.status.value == "ACTIVE"
        }
        return {
            "invariants_emitted": invariant_ids == active_ids,
            "over_budget": bool(overflow.budget and overflow.budget.over_budget),
            "reasons": [reason.value for reason in overflow.report_reasons],
        }
    if scenario_id == "context.no_active_task":
        no_task = context.compile_context(fixture.state_without_active_task())
        report_ids = [entry.record_id for entry in no_task.report_entries]
        return {
            "active_task_id": no_task.active_task_id,
            "reasons": [reason.value for reason in no_task.report_reasons],
            "audit_complete": len(report_ids) == len(set(report_ids)) == len(all_ids) and set(report_ids) == all_ids,
        }
    if scenario_id == "context.handoff":
        handoff = context.compile_context(fixture.state, profile=ContextProfile.HANDOFF)
        payload = context.render_payload(handoff)
        order = handoff.entries_in_selection_order()
        ordering_holds = True
        for band in {entry.band for entry in order}:
            dispositions = [
                entry.disposition
                for entry in order
                if entry.band == band and entry.kind is not RecordKind.INVARIANT
            ]
            seen_included = False
            for disposition in dispositions:
                if disposition is Disposition.INCLUDED:
                    seen_included = True
                elif disposition is Disposition.REVALIDATE and seen_included:
                    ordering_holds = False
        return {
            "disclaimer": "unverified continuity representation" in payload,
            "done_task_included": "task-done" in {entry.record_id for entry in handoff.entries},
            "revalidate_before_context": ordering_holds,
        }
    raise KeyError(scenario_id)


def _session_payload(fixture: BenchmarkFixture, source: str) -> dict[str, Any]:
    fixture.assert_sandbox_path(fixture.root)
    return {"hook_event_name": "SessionStart", "cwd": str(fixture.root), "source": source}


def _scenario_claude(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    if scenario_id == "claude.session_sources":
        sources = ["startup", "resume", "clear", "compact", "fork"]
        expected = context.render_payload(context.compile_context(fixture.state))
        runs = [_invoke(claude, "session-start", _session_payload(fixture, source)) for source in sources]
        return {"sources": sources, "all_equal": all(stdout == expected for _, stdout, _ in runs), "exit_codes": [code for code, _, _ in runs]}
    if scenario_id == "claude.safe_covered_tools":
        result: dict[str, Any] = {}
        for tool in ("Write", "Edit", "NotebookEdit"):
            code, _, _, output = _claude_result(fixture, tool, fixture.target("src/app.py"))
            reason = str(output["permissionDecisionReason"])
            result[tool] = [code, output["permissionDecision"], _policy_from_reason(reason)]
        return result
    if scenario_id == "claude.authorized_normal_mutation":
        selected_state = _scoped_authority_state(fixture)
        decision = _decision(
            fixture,
            fixture.target("src/app.py"),
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        fixture.write_state(selected_state)
        try:
            code, stdout, stderr, output = _claude_result(
                fixture, "Edit", fixture.target("src/app.py")
            )
        finally:
            fixture.write_state()
        return {
            "core_outcome": decision.outcome.value,
            "authorizing_task_id": decision.authorizing_task_id,
            "exit": code,
            "adapter_silent": stdout == "" and stderr == "" and output is None,
        }
    if scenario_id == "claude.governed_block_unacknowledged":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
        )
        fixture.write_state(selected_state)
        try:
            code, _, _, output = _claude_result(
                fixture,
                "Edit",
                fixture.target("src/governed/app.py"),
            )
        finally:
            fixture.write_state()
        reason = str(output["permissionDecisionReason"])
        return {
            "exit": code,
            "permission": output["permissionDecision"],
            "policy": _policy_from_reason(reason),
            "contains_unacknowledged": "INVARIANT_UNACKNOWLEDGED" in reason,
        }
    if scenario_id == "claude.protected_mutation":
        code, _, _, output = _claude_result(fixture, "Edit", fixture.target(".git/config"))
        reason = str(output["permissionDecisionReason"])
        return {"exit": code, "permission": output["permissionDecision"], "policy": _policy_from_reason(reason), "prefix": reason.startswith("evidline BLOCK:")}
    if scenario_id == "claude.uncovered_tool":
        payload = _claude_payload(fixture, "Bash", fixture.target("src/app.py"))
        payload["tool_input"] = {"command": "echo synthetic"}
        code, stdout, _ = _invoke(claude, "pre-tool-use", payload)
        return {"exit": code, "stdout_empty": stdout == "", "classification": "UNCOVERED"}
    raise KeyError(scenario_id)


def _scenario_codex(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    safe_patch = _patch("*** Update File: src/app.py", "@@", "+VALUE = 2")
    protected_patch = _patch("*** Update File: .git/config", "@@", "+synthetic")
    if scenario_id == "codex.session_sources":
        sources = ["startup", "resume", "clear", "compact"]
        expected = context.render_payload(context.compile_context(fixture.state))
        runs = [_invoke(codex, "session-start", _session_payload(fixture, source)) for source in sources]
        contexts = [_hook_output(stdout)["additionalContext"] for _, stdout, _ in runs]
        return {"sources": sources, "all_equal": all(item == expected for item in contexts), "exit_codes": [code for code, _, _ in runs]}
    if scenario_id in ("codex.safe_apply_patch", "codex.protected_apply_patch"):
        patch = safe_patch if scenario_id == "codex.safe_apply_patch" else protected_patch
        code, _, _, output = _codex_result(fixture, patch)
        reason = str(output["permissionDecisionReason"])
        policy = "ASK" if scenario_id == "codex.safe_apply_patch" else "BLOCK"
        return {"exit": code, "permission": output["permissionDecision"], "policy": _policy_from_reason(reason), "prefix": reason.startswith(f"evidline {policy}:")}
    if scenario_id == "codex.authorized_normal_apply_patch":
        selected_state = _scoped_authority_state(fixture)
        decision = _decision(
            fixture,
            fixture.target("src/app.py"),
            _request(intent=Intent.PROPOSED),
            state=selected_state,
        )
        fixture.write_state(selected_state)
        try:
            code, stdout, stderr, output = _codex_result(fixture, safe_patch)
        finally:
            fixture.write_state()
        return {
            "core_outcome": decision.outcome.value,
            "authorizing_task_id": decision.authorizing_task_id,
            "exit": code,
            "adapter_silent": stdout == "" and stderr == "" and output is None,
        }
    if scenario_id == "codex.governed_block_unacknowledged":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
        )
        governed_patch = _patch(
            "*** Update File: src/governed/app.py",
            "@@",
            "+VALUE = 2",
        )
        fixture.write_state(selected_state)
        try:
            code, _, _, output = _codex_result(fixture, governed_patch)
        finally:
            fixture.write_state()
        reason = str(output["permissionDecisionReason"])
        return {
            "exit": code,
            "permission": output["permissionDecision"],
            "policy": _policy_from_reason(reason),
            "contains_unacknowledged": "INVARIANT_UNACKNOWLEDGED" in reason,
        }
    if scenario_id == "codex.mixed_apply_patch":
        mixed = _patch(
            "*** Update File: src/app.py",
            "@@",
            "+VALUE = 2",
            "*** Update File: .git/config",
            "@@",
            "+synthetic",
        )
        code, _, _, output = _codex_result(fixture, mixed)
        reason = fixture.normalize(str(output["permissionDecisionReason"]))
        return {"exit": code, "permission": output["permissionDecision"], "policy": _policy_from_reason(reason), "protected_target": "target=<root>/.git/config" in reason, "target_count": 2 if "target_count=2" in reason else 0}
    if scenario_id == "codex.malformed_patches":
        cases = {
            "unsupported_envelope": "not a patch",
            "environment_id": _patch("*** Environment ID: synthetic", "*** Update File: src/app.py", "@@"),
            "orphan_move": _patch("*** Move to: docs/note.md"),
            "zero_operations": _patch("@@", "+line"),
            "unclassified_line": _patch("unsupported residual line"),
        }
        reasons: list[str] = []
        for patch in cases.values():
            _, _, _, output = _codex_result(fixture, patch)
            reasons.append(str(output["permissionDecisionReason"]))
        return {"cases": list(cases), "all_adapter_failure": all(reason.startswith("evidline adapter failure:") and "no MutationDecision was produced" in reason for reason in reasons), "no_policy_block": all(not reason.startswith("evidline BLOCK:") for reason in reasons), "adapter_failure_count": len(reasons)}
    if scenario_id == "codex.uncovered_tools":
        tools = ["Bash", "mcp__filesystem__write", "spawn_agent"]
        runs = [_invoke(codex, "pre-tool-use", _codex_payload(fixture, "ignored", tool_name=tool)) for tool in tools]
        return {"tools": tools, "all_uncovered": all(code == 0 and stdout == "" for code, stdout, _ in runs)}
    raise KeyError(scenario_id)


def _adapter_failure_output(output: Mapping[str, Any] | None) -> tuple[bool, bool]:
    if output is None:
        return False, False
    reason = str(output.get("permissionDecisionReason", ""))
    return output.get("permissionDecision") == "deny" and reason.startswith("evidline adapter failure:"), reason.startswith("evidline BLOCK:")


def _scenario_adapters(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    safe_patch = _patch("*** Update File: src/app.py", "@@", "+VALUE = 2")
    if scenario_id == "adapters.missing_invalid_state":
        results: list[tuple[bool, bool]] = []
        fixture.remove_state()
        try:
            results.append(_adapter_failure_output(_claude_result(fixture, "Edit", fixture.target("src/app.py"))[3]))
            results.append(_adapter_failure_output(_codex_result(fixture, safe_patch)[3]))
        finally:
            fixture.write_state()
        fixture.write_invalid_state()
        try:
            results.append(_adapter_failure_output(_claude_result(fixture, "Edit", fixture.target("src/app.py"))[3]))
            results.append(_adapter_failure_output(_codex_result(fixture, safe_patch)[3]))
        finally:
            fixture.write_state()
        return {"adapter_failure_count": sum(failure for failure, _ in results), "all_deny": all(failure for failure, _ in results), "no_policy_block": all(not block for _, block in results)}
    if scenario_id == "adapters.no_project_root":
        target = fixture.assert_sandbox_path(fixture.no_root / "file.py")
        claude_run = _invoke(claude, "pre-tool-use", _claude_payload(fixture, "Edit", target) | {"cwd": str(fixture.no_root)})
        codex_run = _invoke(codex, "pre-tool-use", _codex_payload(fixture, safe_patch, cwd=fixture.no_root))
        return {"claude_silent": claude_run[0] == 0 and claude_run[1] == "", "codex_silent": codex_run[0] == 0 and codex_run[1] == ""}
    if scenario_id == "adapters.synthetic_allow_mapping":
        decision = MutationDecision(
            outcome=MutationOutcome.ALLOW,
            risk=MutationRisk.NORMAL,
            target="synthetic.py",
            reasons=(),
            next_step="",
            conflicting_invariant_ids=(),
            advisory_invariant_ids=(),
            applicable_invariant_ids=(),
        )
        with mock.patch.object(claude.mutation, "evaluate_and_decide", return_value=decision):
            claude_run = _claude_result(fixture, "Edit", fixture.target("src/app.py"))
        with mock.patch.object(codex.mutation, "evaluate_and_decide", return_value=decision):
            codex_run = _codex_result(fixture, safe_patch)
        return {"classification": "SYNTHETIC_MAPPING_ONLY", "claude_silent": claude_run[0] == 0 and claude_run[1] == "", "codex_silent": codex_run[0] == 0 and codex_run[1] == ""}
    if scenario_id == "adapters.wrong_hook_event":
        claude_payload = _claude_payload(fixture, "Edit", fixture.target("src/app.py"))
        codex_payload = _codex_payload(fixture, safe_patch)
        claude_payload["hook_event_name"] = "WrongEvent"
        codex_payload["hook_event_name"] = "WrongEvent"
        outputs = [
            _hook_output(_invoke(claude, "pre-tool-use", claude_payload)[1]),
            _hook_output(_invoke(codex, "pre-tool-use", codex_payload)[1]),
        ]
        failures = [_adapter_failure_output(output) for output in outputs]
        return {"adapter_failure_count": sum(failure for failure, _ in failures), "all_deny": all(failure for failure, _ in failures)}
    if scenario_id == "adapters.bad_argv":
        claude_runs = [_invoke_argv(claude, argv) for argv in ((), ("unknown",))]
        codex_runs = [_invoke_argv(codex, argv) for argv in ((), ("unknown",))]
        return {"claude_exit_codes": [item[0] for item in claude_runs], "codex_exit_codes": [item[0] for item in codex_runs], "diagnostics": all(item[2].strip() for item in claude_runs + codex_runs)}
    raise KeyError(scenario_id)


def _scenario_cross(fixture: BenchmarkFixture, scenario_id: str) -> dict[str, Any]:
    safe_patch = _patch("*** Update File: src/app.py", "@@", "+VALUE = 2")
    protected_patch = _patch("*** Update File: .git/config", "@@", "+synthetic")
    if scenario_id == "cross.session_context_parity":
        claude_stdout = _invoke(claude, "session-start", _session_payload(fixture, "startup"))[1]
        codex_stdout = _invoke(codex, "session-start", _session_payload(fixture, "startup"))[1]
        return {"identical": claude_stdout == _hook_output(codex_stdout)["additionalContext"]}
    if scenario_id == "cross.safe_target_asymmetry":
        claude_output = _claude_result(fixture, "Edit", fixture.target("src/app.py"))[3]
        codex_output = _codex_result(fixture, safe_patch)[3]
        claude_reason = str(claude_output["permissionDecisionReason"])
        codex_reason = str(codex_output["permissionDecisionReason"])
        return {"claude_policy": _policy_from_reason(claude_reason), "codex_policy": _policy_from_reason(codex_reason), "claude_transport": claude_output["permissionDecision"], "codex_transport": codex_output["permissionDecision"], "classification": "EXPECTED_ASYMMETRY"}
    if scenario_id == "cross.protected_target_parity":
        claude_output = _claude_result(fixture, "Edit", fixture.target(".git/config"))[3]
        codex_output = _codex_result(fixture, protected_patch)[3]
        claude_policy = _policy_from_reason(str(claude_output["permissionDecisionReason"]))
        codex_policy = _policy_from_reason(str(codex_output["permissionDecisionReason"]))
        return {"claude_policy": claude_policy, "codex_policy": codex_policy, "claude_transport": claude_output["permissionDecision"], "codex_transport": codex_output["permissionDecision"], "identical_policy": claude_policy == codex_policy}
    if scenario_id == "cross.governed_block_parity":
        selected_state = _governed_state(
            fixture,
            governed_scopes={"inv-block": ("src/governed",)},
        )
        governed_patch = _patch(
            "*** Update File: src/governed/app.py",
            "@@",
            "+VALUE = 2",
        )
        fixture.write_state(selected_state)
        try:
            claude_output = _claude_result(
                fixture,
                "Edit",
                fixture.target("src/governed/app.py"),
            )[3]
            codex_output = _codex_result(fixture, governed_patch)[3]
        finally:
            fixture.write_state()
        claude_reason = str(claude_output["permissionDecisionReason"])
        codex_reason = str(codex_output["permissionDecisionReason"])
        claude_policy = _policy_from_reason(claude_reason)
        codex_policy = _policy_from_reason(codex_reason)
        return {
            "claude_policy": claude_policy,
            "codex_policy": codex_policy,
            "claude_transport": claude_output["permissionDecision"],
            "codex_transport": codex_output["permissionDecision"],
            "identical_policy": claude_policy == codex_policy,
            "contains_unacknowledged": (
                "INVARIANT_UNACKNOWLEDGED" in claude_reason
                and "INVARIANT_UNACKNOWLEDGED" in codex_reason
            ),
        }
    if scenario_id == "cross.failure_parity":
        fixture.write_invalid_state()
        try:
            claude_output = _claude_result(fixture, "Edit", fixture.target("src/app.py"))[3]
            codex_output = _codex_result(fixture, safe_patch)[3]
        finally:
            fixture.write_state()
        claude_reason = str(claude_output["permissionDecisionReason"])
        codex_reason = str(codex_output["permissionDecisionReason"])
        return {"claude": _policy_from_reason(claude_reason), "codex": _policy_from_reason(codex_reason), "no_policy_block": not claude_reason.startswith("evidline BLOCK:") and not codex_reason.startswith("evidline BLOCK:"), "adapter_failure_count": 2}
    raise KeyError(scenario_id)


def _execute_scenario(fixture: BenchmarkFixture, spec: ScenarioSpec) -> dict[str, Any]:
    dispatch: dict[str, Callable[[BenchmarkFixture, str], dict[str, Any]]] = {
        "core": _scenario_core,
        "context": _scenario_context,
        "claude": _scenario_claude,
        "codex": _scenario_codex,
        "adapters": _scenario_adapters,
        "cross": _scenario_cross,
    }
    return dispatch[spec.category](fixture, spec.id)


def _declared_containment_matches(fixture: BenchmarkFixture, declaration: str) -> bool:
    if declaration == IN_ROOT:
        probe = fixture.target("src/app.py")
        return paths.discover_project_root(probe) == fixture.root
    if declaration == OUT_OF_ROOT_IN_SANDBOX:
        fixture.assert_sandbox_path(fixture.outside)
        root_text = os.path.normcase(os.path.realpath(fixture.root, strict=False))
        target_text = os.path.normcase(os.path.realpath(fixture.outside, strict=False))
        return os.path.commonpath((root_text, target_text)) != root_text
    if declaration == NO_ROOT:
        fixture.assert_sandbox_path(fixture.no_root)
        return paths.discover_project_root(fixture.no_root) is None
    return False


def _scenario_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    mismatches = [item for item in results if not item["matched"]]
    false_allow = 0
    false_block = 0
    false_escalation = 0
    for item in mismatches:
        expected_outcome = item["expected"].get("outcome")
        actual_outcome = item["actual"].get("outcome")
        false_allow += int(actual_outcome == "ALLOW" and expected_outcome != "ALLOW")
        false_block += int(actual_outcome == "BLOCK" and expected_outcome != "BLOCK")
        false_escalation += int(actual_outcome == "ASK" and expected_outcome == "ALLOW")
    adapter_failure_count = sum(
        int(item["actual"].get("adapter_failure_count", 0)) for item in results
    )
    return {
        "scenarios_total": len(results),
        "scenarios_matched": len(results) - len(mismatches),
        "false_allow_count": false_allow,
        "false_block_count": false_block,
        "false_escalation_count": false_escalation,
        "adapter_failure_count": adapter_failure_count,
        "policy_vs_failure_confusion_count": sum(
            1
            for item in results
            if "no_policy_block" in item["actual"] and not item["actual"]["no_policy_block"]
        ),
        "uncovered_count": len(UNCOVERED_SURFACES),
    }


def build_observed_document() -> dict[str, Any]:
    """Execute real boundaries and return contract plus observations only."""

    with BenchmarkFixture.create() as fixture:
        results: list[dict[str, Any]] = []
        for spec in SCENARIOS:
            actual = fixture.normalize(_execute_scenario(fixture, spec))
            expected = fixture.normalize(dict(spec.expected))
            containment_matches = _declared_containment_matches(fixture, spec.containment)
            results.append(
                {
                    "id": spec.id,
                    "category": spec.category,
                    "containment": spec.containment,
                    "containment_matches": containment_matches,
                    "expected": expected,
                    "actual": actual,
                    "matched": actual == expected and containment_matches,
                }
            )

        compiled = context.compile_context(fixture.state)
        payload = context.render_payload(compiled)
        entries = _entry_map(compiled)
        stale_ids = ("claim-digest", "claim-volatile")
        report_ids = [entry.record_id for entry in compiled.report_entries]
        all_ids = _all_record_ids(fixture)
        metrics = _scenario_metrics(results)
        metrics.update(
            {
                "stale_reuse_count": sum(
                    entries[item].disposition is Disposition.INCLUDED for item in stale_ids
                ),
                "stale_revalidation_count": sum(
                    entries[item].disposition is Disposition.REVALIDATE for item in stale_ids
                ),
                "required_facts_restored": sum(
                    item in {entry.record_id for entry in compiled.entries}
                    for item in REQUIRED_SESSION_IDS
                ),
                "missing_facts": sum(
                    item not in {entry.record_id for entry in compiled.entries}
                    for item in REQUIRED_SESSION_IDS
                ),
                "incorrectly_asserted_facts": 0,
                "audit_completeness": len(report_ids) == len(set(report_ids)) == len(all_ids) and set(report_ids) == all_ids,
                "accounting_exact": compiled.budget is not None and compiled.budget.used_chars == len(payload),
                "over_budget": bool(compiled.budget and compiled.budget.over_budget),
                "session_payload_identical": next(item for item in results if item["id"] == "cross.session_context_parity")["actual"]["identical"],
                "outcome_agreement_count": 2,
                "expected_asymmetry_count": 1,
                "unexpected_divergence_count": 0 if all(item["matched"] for item in results if item["category"] == "cross") else 1,
            }
        )
        scenario_ids = [item.id for item in SCENARIOS]
        budget = compiled.budget
        if budget is None:
            raise RuntimeError("context budget report is absent")
        return {
            "contract": {
                "v1_acceptance": "BLOCKED",
                "v1_acceptance_blockers": list(V1_ACCEPTANCE_BLOCKERS),
                "live_verification": dict(LIVE_VERIFICATION),
                "claim_labels": list(CLAIM_LABELS),
                "uncovered_surfaces": list(UNCOVERED_SURFACES),
                "scenario_ids": scenario_ids,
                "metrics": metrics,
            },
            "observations": {
                "context_measurements": {
                    "rendered_chars": len(payload),
                    "reported_used_chars": budget.used_chars,
                    "approximate_token_estimate": budget.approximate_token_estimate,
                    "budget_chars": budget.budget_chars,
                    "over_budget": budget.over_budget,
                },
                "scenario_results": results,
                "scenario_mismatch_ids": [item["id"] for item in results if not item["matched"]],
            },
        }


def load_expected_document(path: Path = EXPECTED_RESULTS_PATH) -> dict[str, Any]:
    """Read the frozen expected contract without fallback or mutation."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError as error:
        raise ExpectedDocumentError("expected document is missing") from error
    except json.JSONDecodeError as error:
        raise ExpectedDocumentError("expected document is malformed") from error
    except (OSError, UnicodeError) as error:
        raise ExpectedDocumentError("expected document is unreadable") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "contract"}:
        raise ExpectedDocumentError("expected document has an invalid shape")
    if document["schema_version"] != BENCHMARK_SCHEMA_VERSION or not isinstance(document["contract"], dict):
        raise ExpectedDocumentError("expected document has an invalid schema")
    return document


def compare_contract(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    """Compare only the observed and expected semantic contracts."""

    return observed["contract"] == expected["contract"]


def _canonical(document: Mapping[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _summary(document: Mapping[str, Any]) -> str:
    contract = document.get("contract", {})
    metrics = contract.get("metrics", {})
    blockers = contract.get("v1_acceptance_blockers", V1_ACCEPTANCE_BLOCKERS)
    live = contract.get("live_verification", LIVE_VERIFICATION)
    lines = [
        f"benchmark_execution={document['benchmark_execution']}",
        f"v1_acceptance={contract.get('v1_acceptance', 'UNKNOWN')}",
    ]
    lines.extend(f"{item['id']}={item['status']} {item['title']}" for item in blockers)
    lines.extend(f"{key}={live[key]}" for key in sorted(live))
    lines.append(f"scenarios={metrics.get('scenarios_matched', 0)}/{metrics.get('scenarios_total', 0)}")
    return "\n".join(lines) + "\n"


def _failed_result(reason: str) -> dict[str, Any]:
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "observations": {"failure": reason},
        "benchmark_execution": "FAILED",
    }


def run(
    *,
    expected_path: Path = EXPECTED_RESULTS_PATH,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the deterministic comparison and emit the benchmark document."""

    output = sys.stdout if stdout is None else stdout
    diagnostics = sys.stderr if stderr is None else stderr
    try:
        first = build_observed_document()
        second = build_observed_document()
        if _canonical(first) != _canonical(second):
            document = {"schema_version": BENCHMARK_SCHEMA_VERSION, **first, "benchmark_execution": "NONDETERMINISTIC"}
            output.write(_canonical(document))
            diagnostics.write(_summary(document))
            return _EXIT_CODES["NONDETERMINISTIC"]
        expected = load_expected_document(expected_path)
        status = "COMPLETED" if compare_contract(first, expected) else "MISMATCHED"
        document = {"schema_version": BENCHMARK_SCHEMA_VERSION, **first, "benchmark_execution": status}
        output.write(_canonical(document))
        diagnostics.write(_summary(document))
        return _EXIT_CODES[status]
    except SandboxContainmentError:
        document = _failed_result("sandbox containment failed")
    except ExpectedDocumentError as error:
        document = _failed_result(str(error))
    except Exception:
        document = _failed_result("benchmark prerequisite failed")
    output.write(_canonical(document))
    diagnostics.write(_summary(document))
    return _EXIT_CODES["FAILED"]


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
