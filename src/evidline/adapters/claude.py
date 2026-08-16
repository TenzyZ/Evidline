"""Thin, read-only Claude Code hook transport for Evidline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import sys
from types import MappingProxyType
from typing import Any, Final

from evidline import context, mutation, paths, state
from evidline.context import ContextProfile
from evidline.mutation import (
    MutationOutcome,
    MutationRequest,
    MutationRisk,
)
from evidline.state import Intent


_EXIT_SUCCESS: Final = 0
_EXIT_FAILURE: Final = 2

_TARGET_FIELD: Final = MappingProxyType(
    {
        "Write": "file_path",
        "Edit": "file_path",
        "NotebookEdit": "notebook_path",
    }
)

# PROPOSED is mandatory: PreToolUse proves only that Claude proposed a tool
# call, not that a human requested or authorized the mutation. ADR-0009 forbids
# agent self-authorization, and schema version 1 cannot bind authority to a
# mutation target. The adapter must not promote this to REQUESTED or AUTHORIZED.
# NORMAL is a required declared non-assessment, not a risk classification:
# schema version 1 has no deterministic per-mutation risk source. In particular,
# no filename, location, tool, content, prompt, transcript, or permission mode
# may be used to infer risk. NORMAL also surfaces NO_ACTIVE_TASK where relevant.
_REQUEST: Final = MutationRequest(
    request_intent=Intent.PROPOSED,
    risk=MutationRisk.NORMAL,
    operation=None,
    authorizing_ids=(),
    declared_scope=(),
    supporting_claim_ids=(),
    ephemeral_evidence_ids=(),
    asserted_conflicting_invariant_ids=(),
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one Claude Code adapter command."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        _diagnose("evidline claude adapter: expected session-start or pre-tool-use")
        return _EXIT_FAILURE
    if arguments[0] == "session-start":
        return _session_start()
    if arguments[0] == "pre-tool-use":
        return _pre_tool_use()
    _diagnose(f"evidline claude adapter: unknown command: {arguments[0]}")
    return _EXIT_FAILURE


def _session_start() -> int:
    try:
        payload = _read_payload()
        if payload.get("hook_event_name") != "SessionStart":
            return _EXIT_SUCCESS
        cwd = _required_text(payload, "cwd")
        root = paths.discover_project_root(cwd)
        if root is None:
            return _EXIT_SUCCESS
        compiled = context.load_and_compile(
            root,
            profile=ContextProfile.SESSION,
            budget_chars=None,
        )
        sys.stdout.write(context.render_payload(compiled))
    except Exception:
        _diagnose("evidline session-start failure: context unavailable")
    return _EXIT_SUCCESS


def _pre_tool_use() -> int:
    try:
        payload = _read_payload()
    except Exception:
        return _adapter_failure("invalid hook input")

    if payload.get("hook_event_name") != "PreToolUse":
        return _adapter_failure("unexpected hook event")

    try:
        tool_name = _required_text(payload, "tool_name")
    except (KeyError, TypeError, ValueError):
        return _adapter_failure("invalid tool name")
    target_field = _TARGET_FIELD.get(tool_name)
    if target_field is None:
        return _EXIT_SUCCESS

    try:
        cwd = _required_text(payload, "cwd")
        tool_input = payload["tool_input"]
        if not isinstance(tool_input, Mapping):
            raise TypeError("tool_input must be an object")
        raw_target = _required_text(tool_input, target_field)
    except (KeyError, TypeError, ValueError):
        return _adapter_failure("invalid supported-tool input")

    root = paths.discover_project_root(cwd)
    if root is None:
        root = paths.discover_project_root(raw_target)
    if root is None:
        return _EXIT_SUCCESS

    try:
        current_state = state.load_state(root)
    except (
        state.StateNotInitializedError,
        state.StateValidationError,
        state.StateIOError,
    ):
        return _adapter_failure("state could not be loaded")
    except Exception:
        return _adapter_failure("state loading failed unexpectedly")

    try:
        decision = mutation.evaluate_and_decide(
            _REQUEST,
            root,
            raw_target,
            current_state,
        )
    except mutation.MutationInputError:
        return _adapter_failure("mutation input was rejected")
    except Exception:
        return _adapter_failure("mutation evaluation failed unexpectedly")

    if decision.outcome is MutationOutcome.ALLOW:
        return _EXIT_SUCCESS
    if decision.outcome is MutationOutcome.ASK:
        return _emit_permission_decision("ask", _policy_reason(decision))
    if decision.outcome is MutationOutcome.BLOCK:
        return _emit_permission_decision("deny", _policy_reason(decision))
    return _adapter_failure("mutation outcome was unrecognized")


def _read_payload() -> Mapping[str, Any]:
    payload = json.load(sys.stdin)
    if not isinstance(payload, Mapping):
        raise TypeError("hook input must be an object")
    return payload


def _required_text(payload: Mapping[str, Any], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _policy_reason(decision: mutation.MutationDecision) -> str:
    outcome = decision.outcome.value
    reasons = ",".join(reason.value for reason in decision.reasons) or "none"
    return (
        f"evidline {outcome}: outcome={outcome}; reasons={reasons}; "
        f"next_step={decision.next_step}; this is an Evidline policy result "
        "and is not harness or human authorization."
    )


def _adapter_failure(reason: str) -> int:
    return _emit_permission_decision(
        "deny",
        f"evidline adapter failure: {reason}; no MutationDecision was produced.",
    )


def _emit_permission_decision(permission: str, reason: str) -> int:
    document = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }
    rendered = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        written = sys.stdout.write(rendered)
        if written is not None and written != len(rendered):
            raise OSError("incomplete stdout write")
    except Exception:
        _diagnose("evidline claude adapter: structured stdout write failed")
        return _EXIT_FAILURE
    return _EXIT_SUCCESS


def _diagnose(message: str) -> None:
    try:
        sys.stderr.write(message + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
