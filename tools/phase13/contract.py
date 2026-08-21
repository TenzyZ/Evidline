"""Frozen Phase 13 live-verification contract constants.

These values describe the accepted contract. They do not record live results.
"""

from __future__ import annotations

import re
import secrets
from types import MappingProxyType
from typing import Final, Mapping


CONTRACT_STATUS: Final = "CONTRACT ACCEPTED"
LIVE_STATUS: Final = "NOT_EXECUTED"

NONCE_PREFIX: Final = "EVIDLINE-P13-"
NONCE_RANDOM_BYTES: Final = 16
NONCE_ENTROPY_BITS: Final = NONCE_RANDOM_BYTES * 8
NONCE_RANDOM_ENCODING: Final = "hex"
NONCE_RANDOM_CHARS: Final = NONCE_RANDOM_BYTES * 2
NONCE_TOTAL_CHARS: Final = len(NONCE_PREFIX) + NONCE_RANDOM_CHARS
NONCE_TOTAL_BYTES: Final = len(NONCE_PREFIX.encode("utf-8")) + NONCE_RANDOM_CHARS
NONCE_PATTERN: Final = re.compile(r"^EVIDLINE-P13-[0-9a-f]{32}$")
NONCE_PLACEHOLDER_FILL: Final = "0"
NONCE_PLACEHOLDER: Final = NONCE_PREFIX + (
    NONCE_PLACEHOLDER_FILL * NONCE_RANDOM_CHARS
)

VAB_7_HARNESS_DECISION: Final = "CLAUDE_AND_CODEX"

CLAUDE_HARNESS: Final = "claude"
CODEX_HARNESS: Final = "codex"

CLAUDE_SESSION_EVENT: Final = "SessionStart"
CLAUDE_PRETOOL_EVENT: Final = "PreToolUse"
CLAUDE_PROVING_TOOL: Final = "Write"
CLAUDE_MATCHER_TOOLS: Final = ("Edit", "Write", "NotebookEdit")

CODEX_SESSION_EVENT: Final = "SessionStart"
CODEX_PRETOOL_EVENT: Final = "PreToolUse"
CODEX_PROVING_TOOL: Final = "apply_patch"
CODEX_MATCHER_TOOLS: Final = ("apply_patch",)

REQUIRED_LIVE_CLAIMS: Final = (
    "INSTALLED_HARNESS_DISPATCH",
    "LIVE_CONTEXT_INJECTION",
    "LIVE_MUTATION_DENIAL",
)

DENIAL_LAYERS: Final = (
    "CORE_DECISION",
    "ADAPTER_TRANSPORT",
    "HARNESS_TOOL_RESULT",
    "TARGET_STATE",
)

ALLOWED_PROBE: Final = "allowed/probe-allow.txt"
GOVERNED_PROBE: Final = "governed/probe-deny.txt"
INVARIANT_ID: Final = "inv-p13-governed"
TASK_ID: Final = "task-p13"
BLOCK_REASON: Final = "INVARIANT_UNACKNOWLEDGED"
SANDBOX_MARKER: Final = ".phase13-sandbox"

UNCOVERED_TOOL_NAMES: Final = (
    "Bash",
    "PowerShell",
    "Monitor",
    "MCP",
    "hosted",
    "spawn_agent",
)

EXPLICIT_NON_CLAIMS: Final = (
    "complete harness-enforcement claim",
    "Bash coverage claim",
    "PowerShell coverage claim",
    "Monitor coverage claim",
    "MCP coverage claim",
    "hosted-tool coverage claim",
    "global fail-closed security-boundary claim",
)

VERDICTS: Final = (
    "VERIFIED",
    "FAILED",
    "FAILED_OPEN",
    "NOT_COVERED",
    "INCONCLUSIVE",
    "FAIL_CLOSED_MISATTRIBUTION",
    "NOT_EXECUTED",
)

CLAIM_DISPATCH: Final = "INSTALLED_HARNESS_DISPATCH"
CLAIM_INJECTION: Final = "LIVE_CONTEXT_INJECTION"
CLAIM_DENIAL: Final = "LIVE_MUTATION_DENIAL"

POSITIVE_CONTROL_CONTENT: Final = "PHASE13"
POSITIVE_CONTROL_TERMINATOR_BY_PROVING_PATH: Final[Mapping[tuple[str, str], str]] = (
    MappingProxyType(
        {
            (CLAUDE_HARNESS, CLAUDE_PROVING_TOOL): "",
            (CODEX_HARNESS, CODEX_PROVING_TOOL): "\n",
        }
    )
)
NEGATIVE_CONTROL_NONCE_ABSENT: Final = "nonce_absent"

COMMON_EVIDENCE_FIELDS: Final = (
    "captured_at_utc",
    "claim",
    "harness_name",
    "harness_version",
    "evidline_commit_sha",
    "event_type",
    "sandbox_state_sha256",
    "adapter_exit_code",
    "verdict",
    "live_status",
    "operator_summary",
    "notes",
)

DISPATCH_EVIDENCE_FIELDS: Final = (
    "session_sha256",
    "raw_capture_sha256",
    "context_payload_sha256",
    "context_payload_length",
)

INJECTION_EVIDENCE_FIELDS: Final = (
    "challenge_nonce_sha256",
    "enabled_session_sha256",
    "control_session_sha256",
    "enabled_raw_capture_sha256",
    "control_raw_capture_sha256",
    "enabled_answer_sha256",
    "control_answer_sha256",
    "context_payload_sha256",
    "context_payload_length",
    "tool_use_count_before_answer",
    "negative_control_result",
)

DENIAL_EVIDENCE_FIELDS: Final = (
    "supported_tool_path",
    "relative_target",
    "target_existed_before",
    "target_existed_after",
    "target_digest_before",
    "target_digest_after",
    "target_state",
    "core_decision",
    "block_reason",
    "adapter_transport",
    "harness_tool_result",
    "harness_blocking_result",
    "sanitized_hook_decision",
    "proving_tool_attempted",
    "session_sha256",
    "tool_use_sha256",
    "raw_capture_sha256",
    "positive_control_target",
    "positive_control_existed_before",
    "positive_control_existed_after",
    "positive_control_digest_after",
    "positive_control_expected_digest",
    "positive_control_tool",
    "positive_control_tool_attempted",
    "positive_control_tool_use_sha256",
    "positive_control_session_sha256",
    "positive_control_raw_capture_sha256",
)

EVIDENCE_ALLOWED_FIELDS: Final = tuple(
    dict.fromkeys(
        (
            *COMMON_EVIDENCE_FIELDS,
            *DISPATCH_EVIDENCE_FIELDS,
            *INJECTION_EVIDENCE_FIELDS,
            *DENIAL_EVIDENCE_FIELDS,
            "expected_decision",
            "observed_decision",
        )
    )
)

CLAIM_OUTPUT_FIELDS: Final = {
    CLAIM_DISPATCH: COMMON_EVIDENCE_FIELDS + DISPATCH_EVIDENCE_FIELDS,
    CLAIM_INJECTION: COMMON_EVIDENCE_FIELDS + INJECTION_EVIDENCE_FIELDS,
    CLAIM_DENIAL: COMMON_EVIDENCE_FIELDS + DENIAL_EVIDENCE_FIELDS,
}

DENIAL_FILLER_FIELDS: Final = (
    "core_decision",
    "adapter_transport",
    "harness_tool_result",
    "harness_blocking_result",
    "proving_tool_attempted",
    "target_state",
    "sanitized_hook_decision",
    "block_reason",
    "positive_control_result",
    "positive_control_target",
    "tool_use_sha256",
)


def generate_live_nonce() -> str:
    """Return one fresh live-format nonce candidate."""

    return NONCE_PREFIX + secrets.token_hex(NONCE_RANDOM_BYTES)


def make_nonce_placeholder() -> str:
    """Return the deterministic reserved PRELIVE nonce placeholder."""

    return NONCE_PLACEHOLDER


def is_live_nonce_candidate(value: object) -> bool:
    """Return whether *value* is a valid non-placeholder live nonce."""

    return (
        isinstance(value, str)
        and value != NONCE_PLACEHOLDER
        and NONCE_PATTERN.fullmatch(value) is not None
    )


def is_selected_proving_tool(harness: str, tool_name: str) -> bool:
    """Return whether *tool_name* is the frozen proving tool for *harness*."""

    if harness == CLAUDE_HARNESS:
        return tool_name == CLAUDE_PROVING_TOOL
    if harness == CODEX_HARNESS:
        return tool_name == CODEX_PROVING_TOOL
    return False


def is_uncovered_tool(tool_name: str) -> bool:
    """Return whether *tool_name* is explicitly outside the Phase 13 claim."""

    return tool_name in UNCOVERED_TOOL_NAMES
