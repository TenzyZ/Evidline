"""Transparent Claude PreToolUse transport with optional private observation."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import BinaryIO, Final


_EXIT_NO_ADAPTER_RESULT: Final = 1
_RECORD_FORMAT: Final = "evidline.phase13.claude-pretool-correlation.v1"
_RECORD_FIELDS: Final = frozenset(
    {
        "adapter_exit_code",
        "adapter_stdout_base64",
        "format",
        "hook_event_name",
        "session_sha256",
        "tool_name",
        "tool_use_sha256",
    }
)
_DECISION_FIELDS: Final = frozenset(
    {"hookEventName", "permissionDecision", "permissionDecisionReason"}
)
# The mutation core's decision is proven only by the adapter's frozen
# _policy_reason format. Adapter-failure, transport-failure, and unknown
# reason formats state or imply that no MutationDecision was produced.
_CORE_POLICY_REASON: Final = re.compile(
    r"evidline (?P<outcome>BLOCK|ASK): outcome=(?P=outcome); "
    r"reasons=(?P<reasons>[^;]+); next_step=(?P<next_step>.*); "
    r"this is an Evidline policy result and is not harness or human authorization\."
)


def _write_bytes(stream: BinaryIO, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if not isinstance(written, int) or written <= 0:
            raise OSError("binary output made no progress")
        remaining = remaining[written:]
    stream.flush()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _attempt_private_record(
    path: Path,
    hook_input: bytes,
    adapter_stdout: bytes,
    adapter_exit_code: int,
) -> None:
    payload = json.loads(hook_input)
    if not isinstance(payload, Mapping):
        return
    session_id = payload.get("session_id")
    tool_use_id = payload.get("tool_use_id")
    hook_event_name = payload.get("hook_event_name")
    tool_name = payload.get("tool_name")
    if not all(
        isinstance(value, str) and value
        for value in (session_id, tool_use_id, hook_event_name, tool_name)
    ):
        return
    if hook_event_name != "PreToolUse":
        return
    record = {
        "adapter_exit_code": adapter_exit_code,
        "adapter_stdout_base64": base64.b64encode(adapter_stdout).decode("ascii"),
        "format": _RECORD_FORMAT,
        "hook_event_name": hook_event_name,
        "session_sha256": _sha256_text(session_id),
        "tool_name": tool_name,
        "tool_use_sha256": _sha256_text(tool_use_id),
    }
    rendered = (
        json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    with path.open("xb") as stream:
        stream.write(rendered)


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _load_json_strict(value: str | bytes) -> object:
    return json.loads(value, object_pairs_hook=_object_without_duplicate_keys)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _decision_output(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    nested = value.get("hookSpecificOutput")
    if isinstance(nested, Mapping):
        return nested
    if "permissionDecision" in value:
        return value
    return None


def _core_decision_semantics(reason: object) -> tuple[str | None, tuple[str, ...]]:
    """Derive the core outcome and reason codes the adapter actually carries.

    Returns ``(None, ())`` unless *reason* matches the adapter's frozen
    policy-decision format, so a captured deny alone never proves that the
    mutation core produced a decision.
    """

    if not isinstance(reason, str):
        return (None, ())
    match = _CORE_POLICY_REASON.fullmatch(reason)
    if match is None:
        return (None, ())
    codes = match.group("reasons")
    if codes == "none":
        return (match.group("outcome"), ())
    return (match.group("outcome"), tuple(codes.split(",")))


def derive_evidence_bindings(
    path: Path,
    *,
    expected: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Derive existing Phase 13 evidence fields from one private record."""

    record = _load_json_strict(path.read_text(encoding="ascii"))
    if (
        not isinstance(record, Mapping)
        or set(record) != _RECORD_FIELDS
        or record.get("format") != _RECORD_FORMAT
    ):
        raise ValueError("invalid private correlation record")
    if not _is_sha256(record.get("session_sha256")) or not _is_sha256(
        record.get("tool_use_sha256")
    ):
        raise ValueError("invalid private correlation digest")
    if record.get("hook_event_name") != "PreToolUse":
        raise ValueError("private correlation event must be PreToolUse")
    if not isinstance(record.get("tool_name"), str) or not record["tool_name"]:
        raise ValueError("private correlation tool_name must be non-empty")
    exit_code = record.get("adapter_exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ValueError("private correlation adapter_exit_code must be an integer")
    encoded_stdout = record.get("adapter_stdout_base64")
    if not isinstance(encoded_stdout, str):
        raise ValueError("private correlation adapter stdout must be base64 text")
    adapter_stdout = base64.b64decode(record["adapter_stdout_base64"], validate=True)
    bindings: dict[str, object] = {
        "adapter_exit_code": exit_code,
        "session_sha256": record["session_sha256"],
        "tool_use_sha256": record["tool_use_sha256"],
    }
    core_outcome: str | None = None
    core_reasons: tuple[str, ...] = ()
    if adapter_stdout:
        if exit_code != 0:
            raise ValueError("structured adapter stdout requires adapter exit 0")
        decision = _load_json_strict(adapter_stdout.decode("utf-8"))
        output = _decision_output(decision)
        if (
            not isinstance(decision, Mapping)
            or set(decision) != {"hookSpecificOutput"}
            or output is None
            or set(output) != _DECISION_FIELDS
            or output.get("hookEventName") != "PreToolUse"
            or output.get("permissionDecision") not in {"ask", "deny"}
            or not isinstance(output.get("permissionDecisionReason"), str)
            or not output["permissionDecisionReason"]
        ):
            raise ValueError("adapter stdout is not an exact Evidline decision")
        core_outcome, core_reasons = _core_decision_semantics(
            output.get("permissionDecisionReason")
        )
        bindings["sanitized_hook_decision"] = dict(decision)

    source = expected or {}
    comparisons = {
        "adapter_exit_code": exit_code,
        "session_sha256": record["session_sha256"],
        "tool_use_sha256": record["tool_use_sha256"],
        "event_type": record["hook_event_name"],
        "supported_tool_path": record["tool_name"],
    }
    for field, derived in comparisons.items():
        if field in source and source.get(field) != derived:
            raise ValueError(f"private correlation {field} mismatch")
    if "core_decision" in source:
        claimed_decision = source.get("core_decision")
        if core_outcome is None:
            if claimed_decision in {"BLOCK", "ASK"}:
                raise ValueError(
                    "private correlation captured no core MutationDecision"
                )
        elif claimed_decision != core_outcome:
            raise ValueError("private correlation core_decision mismatch")
    if "block_reason" in source:
        claimed_reason = source.get("block_reason")
        if core_outcome != "BLOCK" or not core_reasons:
            raise ValueError(
                "private correlation block_reason is unsupported by "
                "captured core BLOCK evidence"
            )
        if not isinstance(claimed_reason, str) or not any(
            code in claimed_reason for code in core_reasons
        ):
            raise ValueError("private correlation block_reason mismatch")
    if "sanitized_hook_decision" in source:
        supplied = _decision_output(source.get("sanitized_hook_decision"))
        derived = _decision_output(bindings.get("sanitized_hook_decision"))
        if supplied != derived:
            raise ValueError("private correlation sanitized_hook_decision mismatch")
    if "adapter_transport" in source:
        derived = _decision_output(bindings.get("sanitized_hook_decision"))
        permission = derived.get("permissionDecision") if derived is not None else None
        if source.get("adapter_transport") != permission:
            raise ValueError("private correlation adapter_transport mismatch")
    return bindings


def main(argv: Sequence[str] | None = None) -> int:
    """Run exactly one adapter child and relay its process boundary unchanged."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    record_path: Path | None = None
    if len(arguments) >= 3 and arguments[0] == "--record" and arguments[2] == "--":
        record_path = Path(arguments[1])
        separator = 2
    elif arguments and arguments[0] == "--":
        separator = 0
    else:
        return _EXIT_NO_ADAPTER_RESULT
    child_argv = arguments[separator + 1 :]
    if not child_argv:
        return _EXIT_NO_ADAPTER_RESULT

    hook_input = sys.stdin.buffer.read()
    try:
        completed = subprocess.run(
            child_argv,
            input=hook_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return _EXIT_NO_ADAPTER_RESULT

    # The record proves byte-transparent transport for this invocation, so it
    # may be created only after both relays delivered the adapter's bytes.
    transport_intact = True
    try:
        _write_bytes(sys.stdout.buffer, completed.stdout)
    except OSError:
        transport_intact = False
    try:
        _write_bytes(sys.stderr.buffer, completed.stderr)
    except OSError:
        transport_intact = False

    if record_path is not None and transport_intact:
        try:
            _attempt_private_record(
                record_path,
                hook_input,
                completed.stdout,
                completed.returncode,
            )
        except Exception:
            pass
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
