"""Thin, stateless Codex hook transport for Evidline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import os
import sys
from typing import Any, Final

from evidline import context, mutation, paths, state
from evidline.context import ContextProfile
from evidline.mutation import MutationOutcome, MutationRequest, MutationRisk
from evidline.state import Intent


_EXIT_SUCCESS: Final = 0
_EXIT_FAILURE: Final = 2

_BEGIN_PATCH: Final = "*** Begin Patch"
_END_PATCH: Final = "*** End Patch"
_ENVIRONMENT_ID: Final = "*** Environment ID:"
_ADD_FILE: Final = "*** Add File: "
_DELETE_FILE: Final = "*** Delete File: "
_UPDATE_FILE: Final = "*** Update File: "
_MOVE_TO: Final = "*** Move to: "
_END_OF_FILE: Final = "*** End of File"
_HEREDOC_OPENERS: Final = frozenset(("<<EOF", "<<'EOF'", '<<"EOF"'))
_OUTCOME_SEVERITY: Final = {
    MutationOutcome.ALLOW: 0,
    MutationOutcome.ASK: 1,
    MutationOutcome.BLOCK: 2,
}

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


class _PatchInputError(ValueError):
    """The patch target set cannot be established completely."""


def main(argv: Sequence[str] | None = None) -> int:
    """Run one Codex adapter command."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        _diagnose("evidline codex adapter: expected session-start or pre-tool-use")
        return _EXIT_FAILURE
    if arguments[0] == "session-start":
        return _session_start()
    if arguments[0] == "pre-tool-use":
        return _pre_tool_use()
    _diagnose(f"evidline codex adapter: unknown command: {arguments[0]}")
    return _EXIT_FAILURE


def _session_start() -> int:
    try:
        payload = _read_payload()
        if payload.get("hook_event_name") != "SessionStart":
            raise ValueError("unexpected hook event")
        cwd = _required_text(payload, "cwd")
        root = paths.discover_project_root(cwd)
        if root is None:
            return _EXIT_SUCCESS
        compiled = context.load_and_compile(
            root,
            profile=ContextProfile.SESSION,
            budget_chars=None,
        )
        rendered = context.render_payload(compiled)
    except Exception:
        _diagnose("evidline codex session-start failure: context unavailable")
        return _EXIT_SUCCESS

    return _write_json(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": rendered,
            }
        }
    )


def _pre_tool_use() -> int:
    try:
        payload = _read_payload()
    except Exception:
        return _adapter_failure("invalid hook input")

    if payload.get("hook_event_name") != "PreToolUse":
        return _adapter_failure("unexpected hook event")

    try:
        cwd = _required_text(payload, "cwd")
        tool_name = _required_text(payload, "tool_name")
    except (KeyError, TypeError, ValueError):
        return _adapter_failure("invalid hook routing input")

    if tool_name != "apply_patch":
        return _EXIT_SUCCESS

    try:
        tool_input = payload["tool_input"]
        if not isinstance(tool_input, Mapping):
            raise TypeError("tool_input must be an object")
        command = _required_text(tool_input, "command")
    except (KeyError, TypeError, ValueError):
        return _adapter_failure("invalid apply_patch input")

    try:
        root = paths.discover_project_root(cwd)
    except Exception:
        return _adapter_failure("project-root discovery failed unexpectedly")
    if root is None:
        return _EXIT_SUCCESS

    try:
        raw_targets = _extract_patch_targets(command)
        targets = _anchor_targets(cwd, raw_targets)
    except _PatchInputError as error:
        return _adapter_failure(str(error))
    except Exception:
        return _adapter_failure("patch target extraction failed unexpectedly")

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

    decisions: list[tuple[str, mutation.MutationDecision]] = []
    try:
        for target in targets:
            decision = mutation.evaluate_and_decide(
                _REQUEST,
                root,
                target,
                current_state,
            )
            if type(decision) is not mutation.MutationDecision:
                raise _PatchInputError("mutation outcome was unrecognized")
            if decision.outcome not in _OUTCOME_SEVERITY:
                raise _PatchInputError("mutation outcome was unrecognized")
            decisions.append((target, decision))
    except mutation.MutationInputError:
        return _adapter_failure("mutation input was rejected")
    except _PatchInputError as error:
        return _adapter_failure(str(error))
    except Exception:
        return _adapter_failure("mutation evaluation failed unexpectedly")

    target, decision = _collapse_decisions(decisions)
    if decision.outcome is MutationOutcome.ALLOW:
        return _EXIT_SUCCESS
    if decision.outcome is MutationOutcome.ASK:
        return _emit_denial(_policy_reason(target, decision, len(targets)))
    if decision.outcome is MutationOutcome.BLOCK:
        return _emit_denial(_policy_reason(target, decision, len(targets)))
    return _adapter_failure("mutation outcome was unrecognized")


def _extract_patch_targets(command: str) -> tuple[str, ...]:
    text = command.strip()
    if not text:
        raise _PatchInputError("patch is malformed")

    lines = text.splitlines()
    if lines and lines[0] in _HEREDOC_OPENERS:
        if len(lines) < 4 or lines[-1] != "EOF":
            raise _PatchInputError("patch envelope is unsupported")
        text = "\n".join(lines[1:-1]).strip()
        lines = text.splitlines()

    if len(lines) < 2 or lines[0] != _BEGIN_PATCH or lines[-1] != _END_PATCH:
        raise _PatchInputError("patch envelope is unsupported")
    if len(lines) > 2 and lines[1].startswith(_ENVIRONMENT_ID):
        raise _PatchInputError("patch environment id is unsupported")

    targets: list[str] = []
    previous_operation: str | None = None
    for line in lines[1:-1]:
        operation = _operation_marker(line)
        if operation is not None:
            marker, operation_name = operation
            path = line[len(marker) :].strip()
            if not path:
                raise _PatchInputError("patch target path is empty")
            targets.append(path)
            previous_operation = operation_name
            continue

        if line.startswith(_MOVE_TO):
            if previous_operation != "update":
                raise _PatchInputError("patch move target is not attached to an update")
            path = line[len(_MOVE_TO) :].strip()
            if not path:
                raise _PatchInputError("patch target path is empty")
            targets.append(path)
            previous_operation = "move"
            continue

        previous_operation = None
        if _is_non_target_patch_line(line):
            continue
        raise _PatchInputError("patch contains an unsupported line")

    if not targets:
        raise _PatchInputError("patch contains no file operations")
    return tuple(targets)


def _operation_marker(line: str) -> tuple[str, str] | None:
    for marker, operation in (
        (_ADD_FILE, "add"),
        (_DELETE_FILE, "delete"),
        (_UPDATE_FILE, "update"),
    ):
        if line.startswith(marker):
            return marker, operation
    return None


def _is_non_target_patch_line(line: str) -> bool:
    return (
        line == ""
        or line == _END_OF_FILE
        or line == "@@"
        or line.startswith("@@ ")
        or line.startswith(("+", "-", " "))
    )


def _anchor_targets(cwd: str, raw_targets: tuple[str, ...]) -> tuple[str, ...]:
    targets: list[str] = []
    seen: set[str] = set()
    for raw_target in raw_targets:
        target = raw_target if os.path.isabs(raw_target) else os.path.join(cwd, raw_target)
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return tuple(targets)


def _collapse_decisions(
    decisions: list[tuple[str, mutation.MutationDecision]],
) -> tuple[str, mutation.MutationDecision]:
    deciding_target, deciding_decision = decisions[0]
    deciding_severity = _OUTCOME_SEVERITY[deciding_decision.outcome]
    for target, decision in decisions[1:]:
        severity = _OUTCOME_SEVERITY[decision.outcome]
        if severity > deciding_severity:
            deciding_target = target
            deciding_decision = decision
            deciding_severity = severity
    return deciding_target, deciding_decision


def _read_payload() -> Mapping[str, Any]:
    payload = json.load(sys.stdin)
    if not isinstance(payload, Mapping):
        raise TypeError("hook input must be an object")
    return payload


def _required_text(payload: Mapping[str, Any], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _policy_reason(
    target: str,
    decision: mutation.MutationDecision,
    target_count: int,
) -> str:
    outcome = decision.outcome.value
    reasons = ",".join(reason.value for reason in decision.reasons) or "none"
    base = (
        f"evidline {outcome}: target={target}; reasons={reasons}; "
        f"next_step={decision.next_step}; target_count={target_count}"
    )
    if decision.outcome is MutationOutcome.ASK:
        return (
            base
            + "; stronger human authorization or evidence is required; retry only "
            "after Evidline state changes."
        )
    return base + "; this is an Evidline policy result, not harness authorization."


def _adapter_failure(reason: str) -> int:
    return _emit_denial(
        f"evidline adapter failure: {reason}; no MutationDecision was produced."
    )


def _emit_denial(reason: str) -> int:
    if not reason.strip():
        return _adapter_failure("denial reason was empty")
    return _write_json(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    )


def _write_json(document: Mapping[str, Any]) -> int:
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
        _diagnose("evidline codex adapter: structured stdout write failed")
        return _EXIT_FAILURE
    return _EXIT_SUCCESS


def _diagnose(message: str) -> None:
    try:
        sys.stderr.write(message + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
