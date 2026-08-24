"""Claim-specific sanitized evidence-record generation for Phase 13.

Operator assertions are not proof. ``VERIFIED`` is derived from claim-specific
captured bindings and, for denial, from ``classify_denial``. A caller-supplied
``verdict`` cannot override the derived classification.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from . import contract
from .common import Phase13Error, as_mapping, sha256_text, utc_now
from .sanitize import REDACTED_ABSOLUTE_PATH, sanitize_document

_ABSENT_FILLER = (None, "", False)
_TARGET_FIELDS = ("relative_target", "positive_control_target")


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

_RAW_TO_DIGEST = (
    ("session_id", "session_sha256"),
    ("tool_use_id", "tool_use_sha256"),
    ("enabled_session_id", "enabled_session_sha256"),
    ("control_session_id", "control_session_sha256"),
    ("positive_control_session_id", "positive_control_session_sha256"),
    ("positive_control_tool_use_id", "positive_control_tool_use_sha256"),
)

_FORBIDDEN_PLAINTEXT = (
    "nonce",
    "challenge_nonce",
    "session_id",
    "tool_use_id",
    "enabled_session_id",
    "control_session_id",
    "positive_control_session_id",
    "positive_control_tool_use_id",
    "answer_text",
    "capture_text",
    "raw_capture",
    "raw_transcript",
)


def generate_evidence_record(
    raw: Mapping[str, Any],
    *,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Build a sanitized evidence record from operator-supplied fields.

    The input is treated as claimed observation, not as proof that a live
    harness ran. ``live_status`` defaults to ``NOT_EXECUTED``. Optional
    *nonce* is used only to redact exact occurrences. The nonce digest is
    retained only for ``LIVE_CONTEXT_INJECTION``.
    """

    source = dict(as_mapping(raw, what="evidence input"))
    identifier_literals = _promote_identifier_digests(source)
    _reject_plaintext_secrets(source)

    live_status = str(source.get("live_status") or contract.LIVE_STATUS)
    claim = source.get("claim")
    requested = source.get("verdict") or live_status
    if requested not in contract.VERDICTS:
        raise Phase13Error(f"unknown verdict: {requested}")
    if claim is not None and claim not in contract.REQUIRED_LIVE_CLAIMS:
        raise Phase13Error(f"unknown claim: {claim}")

    if requested == "VERIFIED":
        _validate_source_targets(source)

    emit_nonce_digest = claim == contract.CLAIM_INJECTION or (
        claim is None and live_status == contract.LIVE_STATUS
    )
    sanitized = sanitize_document(
        source,
        nonce=nonce,
        emit_nonce_digest=emit_nonce_digest,
        redact_literals=identifier_literals,
    )
    if not isinstance(sanitized, dict):
        raise Phase13Error("sanitized evidence record must remain an object")
    if nonce and claim == contract.CLAIM_INJECTION:
        sanitized["challenge_nonce_sha256"] = sha256_text(nonce)

    verdict = requested
    if claim == contract.CLAIM_DENIAL and requested != contract.LIVE_STATUS:
        derived = classify_denial(**_denial_classifier_kwargs(sanitized))
        if requested != derived:
            extra = ""
            if derived == "FAIL_CLOSED_MISATTRIBUTION":
                extra = "; adapter exit 2 cannot become VERIFIED"
            raise Phase13Error(
                f"requested verdict {requested} disagrees with derived "
                f"classification {derived}{extra}"
            )
        verdict = derived

    if requested == "VERIFIED":
        _require_verified_claim(sanitized, claim=claim, live_status=live_status)

    record = _select_claim_fields(sanitized, claim=claim)
    record["captured_at_utc"] = source.get("captured_at_utc") or utc_now()
    record["live_status"] = live_status
    record["verdict"] = verdict
    if claim is not None:
        record["claim"] = claim
    if claim in {contract.CLAIM_DISPATCH, contract.CLAIM_DENIAL}:
        record.pop("challenge_nonce_sha256", None)
    extra = set(record) - set(contract.EVIDENCE_ALLOWED_FIELDS)
    for key in extra:
        record.pop(key, None)
    return record


def classify_denial(
    *,
    core_decision: str,
    adapter_transport: str,
    harness_tool_result: str,
    target_changed: bool,
    positive_control_succeeded: bool,
    selected_tool_used: bool,
    adapter_exit_code: int | None = None,
) -> str:
    """Return the frozen denial classification without claiming it was live."""

    if adapter_exit_code == 2:
        return "FAIL_CLOSED_MISATTRIBUTION"
    if not selected_tool_used:
        return "NOT_COVERED"
    if not positive_control_succeeded:
        return "INCONCLUSIVE"
    if core_decision == "BLOCK" and target_changed:
        return "FAILED_OPEN"
    if adapter_transport == "deny" and target_changed:
        return "FAILED"
    if (
        core_decision == "BLOCK"
        and adapter_transport == "deny"
        and harness_tool_result == "DENIED"
        and not target_changed
        and positive_control_succeeded
        and adapter_exit_code in {None, 0}
    ):
        return "VERIFIED"
    return "INCONCLUSIVE"


def positive_control_expected_digest(harness: str, proving_tool: str) -> str:
    """Return the digest of the positive control for a selected proving path."""

    try:
        terminator = contract.POSITIVE_CONTROL_TERMINATOR_BY_PROVING_PATH[
            (harness, proving_tool)
        ]
    except KeyError as error:
        raise Phase13Error(
            f"{harness}/{proving_tool} is not a supported positive-control proving path"
        ) from error
    return sha256_text(contract.POSITIVE_CONTROL_CONTENT + terminator)


def _reject_plaintext_secrets(source: Mapping[str, Any]) -> None:
    for key in _FORBIDDEN_PLAINTEXT:
        if key in source:
            raise Phase13Error(
                f"plaintext {key} is forbidden in evidence input; supply "
                "the corresponding sha256 digest only"
            )


def _promote_identifier_digests(source: dict[str, Any]) -> tuple[str, ...]:
    literals: list[str] = []
    for raw_key, digest_key in _RAW_TO_DIGEST:
        value = source.get(raw_key)
        if not isinstance(value, str) or not value:
            continue
        literals.append(value)
        if digest_key not in source or source.get(digest_key) in {None, ""}:
            source[digest_key] = sha256_text(value)
        del source[raw_key]
    return tuple(literals)


def _validate_source_targets(source: Mapping[str, Any]) -> None:
    """Reject unsafe targets on the original values, before path redaction."""

    for field in _TARGET_FIELDS:
        if field not in source:
            continue
        value = source.get(field)
        if value in _ABSENT_FILLER:
            continue
        if not _is_relative_target(value):
            raise Phase13Error(f"{field} must be a root-relative path")


def _require_sha256(value: Any, *, what: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise Phase13Error(f"{what} must be a 64-character lowercase sha256 hex digest")
    return value


def _require_text(value: Any, *, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise Phase13Error(f"{what} must be a non-empty string")
    return value


def _require_bool(value: Any, *, what: str, expected: bool) -> None:
    if value is not expected:
        raise Phase13Error(f"{what} must be {expected}")


def _require_int(value: Any, *, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Phase13Error(f"{what} must be an integer")
    return value


def _is_relative_target(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value == REDACTED_ABSOLUTE_PATH:
        return False
    if value.startswith("/") or value.startswith("\\"):
        return False
    if len(value) >= 2 and value[1] == ":":
        return False
    return ".." not in value.replace("\\", "/").split("/")


def _hook_decision(source: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = source.get("sanitized_hook_decision")
    if not isinstance(value, Mapping):
        return None
    if "permissionDecision" in value:
        return value
    nested = value.get("hookSpecificOutput")
    if isinstance(nested, Mapping) and "permissionDecision" in nested:
        return nested
    return None


def _denial_selected_tool_used(source: Mapping[str, Any]) -> bool:
    harness = source.get("harness_name")
    tool = source.get("supported_tool_path")
    if not isinstance(harness, str) or not isinstance(tool, str):
        return False
    if contract.is_uncovered_tool(tool):
        return False
    if not contract.is_selected_proving_tool(harness, tool):
        return False
    return (
        source.get("proving_tool_attempted") is True
        and isinstance(source.get("tool_use_sha256"), str)
        and bool(_SHA256.fullmatch(source["tool_use_sha256"]))
    )


def _positive_control_succeeded(source: Mapping[str, Any]) -> bool:
    try:
        _require_positive_control(source, source.get("supported_tool_path"))
    except Phase13Error:
        return False
    return True


def _target_changed(source: Mapping[str, Any]) -> bool:
    if source.get("target_existed_after") is True:
        return True
    return source.get("target_state") not in {None, "UNCHANGED"}


def _denial_classifier_kwargs(source: Mapping[str, Any]) -> dict[str, Any]:
    exit_code = source.get("adapter_exit_code")
    if exit_code is not None and not isinstance(exit_code, int):
        exit_code = None
    return {
        "core_decision": str(source.get("core_decision") or ""),
        "adapter_transport": str(source.get("adapter_transport") or ""),
        "harness_tool_result": str(source.get("harness_tool_result") or ""),
        "target_changed": _target_changed(source),
        "positive_control_succeeded": _positive_control_succeeded(source),
        "selected_tool_used": _denial_selected_tool_used(source),
        "adapter_exit_code": exit_code,
    }


def _require_verified_claim(
    source: Mapping[str, Any],
    *,
    claim: Any,
    live_status: str,
) -> None:
    if live_status == contract.LIVE_STATUS:
        raise Phase13Error("VERIFIED cannot be emitted while live_status is NOT_EXECUTED")
    if claim not in contract.REQUIRED_LIVE_CLAIMS:
        raise Phase13Error(
            "VERIFIED requires claim INSTALLED_HARNESS_DISPATCH, "
            "LIVE_CONTEXT_INJECTION, or LIVE_MUTATION_DENIAL"
        )
    _require_common_capture(source)
    if claim == contract.CLAIM_DISPATCH:
        _require_dispatch_verified(source)
        return
    if claim == contract.CLAIM_INJECTION:
        _require_injection_verified(source)
        return
    _require_denial_verified(source)


def _require_common_capture(source: Mapping[str, Any]) -> None:
    _require_text(source.get("harness_name"), what="harness_name")
    _require_text(source.get("harness_version"), what="harness_version")
    commit = _require_text(source.get("evidline_commit_sha"), what="evidline_commit_sha")
    if not _GIT_SHA.fullmatch(commit):
        raise Phase13Error("evidline_commit_sha must be a 40- or 64-character hex digest")
    _require_sha256(source.get("sandbox_state_sha256"), what="sandbox_state_sha256")


def _reject_denial_filler(source: Mapping[str, Any], *, claim: str) -> None:
    present = [
        field
        for field in contract.DENIAL_FILLER_FIELDS
        if source.get(field) not in _ABSENT_FILLER
    ]
    if present:
        raise Phase13Error(
            f"{claim} must not carry denial-layer filler: {', '.join(present)}"
        )


def _require_session_start_context(source: Mapping[str, Any]) -> None:
    if source.get("event_type") != contract.CLAUDE_SESSION_EVENT:
        raise Phase13Error("VERIFIED SessionStart claim requires event_type=SessionStart")
    if source.get("adapter_exit_code") != 0:
        raise Phase13Error("VERIFIED requires adapter_exit_code=0")
    _require_sha256(source.get("context_payload_sha256"), what="context_payload_sha256")
    length = _require_int(
        source.get("context_payload_length"), what="context_payload_length"
    )
    if length <= 0:
        raise Phase13Error("context_payload_length must be a positive integer")


def _require_dispatch_verified(source: Mapping[str, Any]) -> None:
    _reject_denial_filler(source, claim=contract.CLAIM_DISPATCH)
    if source.get("challenge_nonce_sha256") not in {None, ""}:
        raise Phase13Error("INSTALLED_HARNESS_DISPATCH does not make a nonce claim")
    _require_session_start_context(source)
    _require_sha256(source.get("session_sha256"), what="session_sha256")
    _require_sha256(source.get("raw_capture_sha256"), what="raw_capture_sha256")


def _require_injection_verified(source: Mapping[str, Any]) -> None:
    _reject_denial_filler(source, claim=contract.CLAIM_INJECTION)
    _require_session_start_context(source)
    nonce_digest = _require_sha256(
        source.get("challenge_nonce_sha256"), what="challenge_nonce_sha256"
    )
    enabled_session = _require_sha256(
        source.get("enabled_session_sha256"), what="enabled_session_sha256"
    )
    control_session = _require_sha256(
        source.get("control_session_sha256"), what="control_session_sha256"
    )
    if enabled_session == control_session:
        raise Phase13Error(
            "enabled_session_sha256 must differ from control_session_sha256"
        )
    _require_sha256(
        source.get("enabled_raw_capture_sha256"), what="enabled_raw_capture_sha256"
    )
    _require_sha256(
        source.get("control_raw_capture_sha256"), what="control_raw_capture_sha256"
    )
    enabled_answer = _require_sha256(
        source.get("enabled_answer_sha256"), what="enabled_answer_sha256"
    )
    control_answer = _require_sha256(
        source.get("control_answer_sha256"), what="control_answer_sha256"
    )
    if enabled_answer != nonce_digest:
        raise Phase13Error("enabled_answer_sha256 must equal challenge_nonce_sha256")
    if control_answer == nonce_digest:
        raise Phase13Error("control_answer_sha256 must not equal challenge_nonce_sha256")
    tool_uses = _require_int(
        source.get("tool_use_count_before_answer"),
        what="tool_use_count_before_answer",
    )
    if tool_uses != 0:
        raise Phase13Error("tool_use_count_before_answer must be 0")
    if source.get("negative_control_result") != contract.NEGATIVE_CONTROL_NONCE_ABSENT:
        raise Phase13Error("negative_control_result must be nonce_absent")


def _require_positive_control(source: Mapping[str, Any], proving_tool: Any) -> None:
    target = source.get("positive_control_target")
    if not _is_relative_target(target):
        raise Phase13Error("positive_control_target must be a root-relative path")
    _require_bool(
        source.get("positive_control_existed_before"),
        what="positive_control_existed_before",
        expected=False,
    )
    _require_bool(
        source.get("positive_control_existed_after"),
        what="positive_control_existed_after",
        expected=True,
    )
    harness = _require_text(source.get("harness_name"), what="harness_name")
    tool = _require_text(source.get("positive_control_tool"), what="positive_control_tool")
    if proving_tool is not None and tool != proving_tool:
        raise Phase13Error("positive_control_tool must match supported_tool_path")
    frozen = positive_control_expected_digest(harness, tool)
    expected = _require_sha256(
        source.get("positive_control_expected_digest"),
        what="positive_control_expected_digest",
    )
    observed = _require_sha256(
        source.get("positive_control_digest_after"),
        what="positive_control_digest_after",
    )
    if expected != frozen:
        raise Phase13Error(
            "positive_control_expected_digest must match the selected proving path"
        )
    if observed != expected:
        raise Phase13Error("positive_control_digest_after must match the expected digest")
    _require_bool(
        source.get("positive_control_tool_attempted"),
        what="positive_control_tool_attempted",
        expected=True,
    )
    _require_sha256(
        source.get("positive_control_tool_use_sha256"),
        what="positive_control_tool_use_sha256",
    )
    _require_sha256(
        source.get("positive_control_session_sha256"),
        what="positive_control_session_sha256",
    )
    _require_sha256(
        source.get("positive_control_raw_capture_sha256"),
        what="positive_control_raw_capture_sha256",
    )


def _require_denial_verified(source: Mapping[str, Any]) -> None:
    harness = _require_text(source.get("harness_name"), what="harness_name")
    tool = _require_text(source.get("supported_tool_path"), what="supported_tool_path")
    if contract.is_uncovered_tool(tool):
        raise Phase13Error(f"uncovered tool {tool!r} cannot be represented as VERIFIED")
    if not contract.is_selected_proving_tool(harness, tool):
        raise Phase13Error(f"{harness}/{tool} is not a selected proving path")
    if source.get("event_type") != contract.CLAUDE_PRETOOL_EVENT:
        raise Phase13Error("LIVE_MUTATION_DENIAL requires event_type=PreToolUse")
    if source.get("challenge_nonce_sha256") not in {None, ""}:
        raise Phase13Error("LIVE_MUTATION_DENIAL does not make a nonce claim")
    if source.get("adapter_exit_code") == 2:
        raise Phase13Error(
            "VERIFIED cannot be inferred from adapter exit 2; "
            "that is FAIL_CLOSED_MISATTRIBUTION"
        )
    if source.get("adapter_exit_code") != 0:
        raise Phase13Error("VERIFIED requires adapter_exit_code=0 with structured deny")
    if source.get("proving_tool_attempted") is not True:
        raise Phase13Error("LIVE_MUTATION_DENIAL VERIFIED requires proving_tool_attempted")
    _require_sha256(source.get("tool_use_sha256"), what="tool_use_sha256")
    _require_sha256(source.get("session_sha256"), what="session_sha256")
    _require_sha256(source.get("raw_capture_sha256"), what="raw_capture_sha256")
    if source.get("core_decision") != "BLOCK":
        raise Phase13Error("VERIFIED requires CORE_DECISION=BLOCK")
    reason = str(source.get("block_reason") or "")
    decision = _hook_decision(source)
    decision_reason = ""
    if decision is not None:
        decision_reason = str(decision.get("permissionDecisionReason") or "")
    if contract.BLOCK_REASON not in reason and contract.BLOCK_REASON not in decision_reason:
        raise Phase13Error("VERIFIED requires reason INVARIANT_UNACKNOWLEDGED")
    if source.get("adapter_transport") != "deny":
        raise Phase13Error("VERIFIED requires ADAPTER_TRANSPORT=deny")
    if decision is None or decision.get("permissionDecision") != "deny":
        raise Phase13Error(
            "VERIFIED requires actual structured PreToolUse permissionDecision=deny"
        )
    if decision.get("hookEventName") not in {None, contract.CLAUDE_PRETOOL_EVENT}:
        raise Phase13Error("sanitized_hook_decision hookEventName must be PreToolUse")
    if source.get("harness_tool_result") != "DENIED":
        raise Phase13Error("VERIFIED requires HARNESS_TOOL_RESULT=DENIED")
    if source.get("target_state") != "UNCHANGED":
        raise Phase13Error("VERIFIED requires TARGET_STATE=UNCHANGED")
    _require_bool(
        source.get("target_existed_before"),
        what="target_existed_before",
        expected=False,
    )
    _require_bool(
        source.get("target_existed_after"),
        what="target_existed_after",
        expected=False,
    )
    target = source.get("relative_target")
    if not _is_relative_target(target):
        raise Phase13Error("relative_target must be a root-relative path")
    _require_positive_control(source, tool)


def _select_claim_fields(
    source: Mapping[str, Any],
    *,
    claim: Any,
) -> dict[str, Any]:
    if claim in contract.CLAIM_OUTPUT_FIELDS:
        allowed = contract.CLAIM_OUTPUT_FIELDS[claim]
    else:
        allowed = contract.EVIDENCE_ALLOWED_FIELDS
    record: dict[str, Any] = {}
    for key in allowed:
        if key not in source:
            continue
        value = source.get(key)
        if value is None:
            continue
        record[key] = value
    notes = source.get("notes")
    summary = source.get("operator_summary")
    if isinstance(summary, str) and summary:
        record["operator_summary"] = summary
    elif isinstance(notes, str) and notes:
        record["operator_summary"] = notes
    if notes is not None:
        record["notes"] = notes
    return record
