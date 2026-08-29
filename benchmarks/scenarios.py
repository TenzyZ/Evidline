"""Human-authored Phase 7 scenario declarations and literal expectations."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Mapping


IN_ROOT: Final = "IN_ROOT"
OUT_OF_ROOT_IN_SANDBOX: Final = "OUT_OF_ROOT_IN_SANDBOX"
NO_ROOT: Final = "NO_ROOT"


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    id: str
    category: str
    containment: str
    expected: Mapping[str, Any]


def _spec(
    scenario_id: str,
    category: str,
    expected: Mapping[str, Any],
    containment: str = IN_ROOT,
) -> ScenarioSpec:
    return ScenarioSpec(
        id=scenario_id,
        category=category,
        containment=containment,
        expected=MappingProxyType(dict(expected)),
    )


SCENARIOS: Final = (
    _spec("core.ordinary_authorized_edit", "core", {"outcome": "ALLOW", "reasons": [], "next_step": ""}),
    _spec("core.scope_violation", "core", {"outcome": "BLOCK", "reasons": ["SCOPE_VIOLATION"]}),
    _spec("core.active_block_invariant", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_CONFLICT"], "conflicting": ["inv-block"]}),
    _spec("core.active_advise_invariant", "core", {"outcome": "ALLOW", "reasons": [], "advisory": ["inv-advise"]}),
    _spec("core.superseded_invariant", "core", {"outcome": "ALLOW", "reasons": [], "conflicting": []}),
    _spec("core.unknown_invariant", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_UNRESOLVED"]}),
    _spec("core.high_inadequate_support", "core", {"outcome": "BLOCK", "reasons": ["HIGH_EVIDENCE_INSUFFICIENT"]}),
    _spec("core.high_valid_support", "core", {"outcome": "ASK", "reasons": [], "risk": "HIGH"}),
    _spec("core.failed_support_claim", "core", {"outcome": "BLOCK", "reasons": ["HIGH_EVIDENCE_INSUFFICIENT"]}),
    _spec("core.protected_git_config", "core", {"outcome": "BLOCK", "risk": "CRITICAL", "reasons": ["TARGET_PROTECTED", "CRITICAL_RISK"]}),
    _spec("core.protected_state", "core", {"outcome": "BLOCK", "risk": "CRITICAL", "reasons": ["TARGET_PROTECTED", "CRITICAL_RISK"]}),
    _spec("core.protected_nested_git", "core", {"outcome": "BLOCK", "risk": "CRITICAL", "reasons": ["TARGET_PROTECTED", "CRITICAL_RISK"]}),
    _spec("core.out_of_root", "core", {"outcome": "BLOCK", "reasons": ["TARGET_UNSAFE"]}, OUT_OF_ROOT_IN_SANDBOX),
    _spec("core.no_active_task", "core", {"outcome": "ASK", "reasons": ["NO_ACTIVE_TASK"]}),
    _spec("core.invalid_state", "core", {"exception": "MutationInputError", "message": "unsupported schema_version: 5"}),
    _spec("core.denied_intent", "core", {"outcome": "BLOCK", "reasons": ["REQUEST_INTENT_DENIED"]}),
    _spec("core.derived_outside_authorized_scope", "core", {"outcome": "ASK", "reasons": ["REQUEST_INTENT_INSUFFICIENT"], "authorizing_task_id": None}),
    _spec("core.untrusted_authorization_channel", "core", {"outcome": "ASK", "reasons": ["REQUEST_INTENT_INSUFFICIENT"], "authorizing_task_id": None}),
    _spec("core.governed_scope_authorized_allow", "core", {"outcome": "ALLOW", "reasons": [], "authorizing_task_id": "task-active"}),
    _spec("core.governed_block_unacknowledged", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_UNACKNOWLEDGED"], "unacknowledged": ["inv-block"], "authorizing_task_id": "task-active"}),
    _spec("core.governed_block_acknowledged", "core", {"outcome": "ALLOW", "reasons": [], "unacknowledged": [], "authorizing_task_id": "task-active"}),
    _spec("core.governed_advise_relevant", "core", {"outcome": "ALLOW", "reasons": [], "advisory": ["inv-advise"]}),
    _spec("core.governed_superseded_relevant", "core", {"outcome": "ALLOW", "reasons": [], "unacknowledged": []}),
    _spec("core.governed_multiple_block", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_UNACKNOWLEDGED"], "unacknowledged": ["inv-block", "inv-current"]}),
    _spec("core.governed_mixed_acknowledgement", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_UNACKNOWLEDGED"], "unacknowledged": ["inv-current"]}),
    _spec("core.governed_outside_scope", "core", {"outcome": "ALLOW", "reasons": [], "unacknowledged": []}),
    _spec("core.governed_untrusted_acknowledgement", "core", {"outcome": "BLOCK", "reasons": ["REQUEST_INTENT_INSUFFICIENT", "INVARIANT_UNACKNOWLEDGED"], "unacknowledged": ["inv-block"], "authorizing_task_id": None}),
    _spec("core.governed_acknowledgement_does_not_suppress_asserted_conflict", "core", {"outcome": "BLOCK", "reasons": ["INVARIANT_CONFLICT"], "conflicting": ["inv-block"], "unacknowledged": []}),
    _spec("core.malformed_governed_scope", "core", {"exception": "MutationInputError", "message": "inv-block.governed_scope entries must be normalized: src/"}),
    _spec("core.incompatible_scope_semantics", "core", {"exception": "MutationInputError", "message": "scope_semantics is incompatible with non-empty persisted scopes"}),
    _spec("context.session_continuity", "context", {"required_delivered": True, "rule_excluded_absent": True, "audit_complete": True}),
    _spec("context.stale_claims", "context", {"claim-digest": ["REVALIDATE", "STALE", ["DIGEST_NOT_RECHECKED"]], "claim-volatile": ["REVALIDATE", "STALE", ["VOLATILE_MUST_REVALIDATE"]]}),
    _spec("context.failed_claim", "context", {"disposition": "REVALIDATE", "freshness": "FAILED", "reasons": ["FAILED_VERIFICATION"]}),
    _spec("context.budget_accounting", "context", {"accounting_exact": True}),
    _spec("context.minimum_budget_failure", "context", {"exception": "ContextInputError", "below_minimum": True}),
    _spec("context.invariant_budget_overflow", "context", {"invariants_emitted": True, "over_budget": True, "reasons": ["INVARIANT_BUDGET_OVERFLOW"]}),
    _spec("context.no_active_task", "context", {"active_task_id": None, "reasons": ["NO_ACTIVE_TASK"], "audit_complete": True}),
    _spec("context.handoff", "context", {"disclaimer": True, "done_task_included": True, "revalidate_before_context": True}),
    _spec("claude.session_sources", "claude", {"sources": ["startup", "resume", "clear", "compact", "fork"], "all_equal": True, "exit_codes": [0, 0, 0, 0, 0]}),
    _spec("codex.session_sources", "codex", {"sources": ["startup", "resume", "clear", "compact"], "all_equal": True, "exit_codes": [0, 0, 0, 0]}),
    _spec("claude.safe_covered_tools", "claude", {"Write": [0, "ask", "ASK"], "Edit": [0, "ask", "ASK"], "NotebookEdit": [0, "ask", "ASK"]}),
    _spec("claude.authorized_normal_mutation", "claude", {"core_outcome": "ALLOW", "authorizing_task_id": "task-active", "exit": 0, "adapter_silent": True}),
    _spec("claude.governed_block_unacknowledged", "claude", {"exit": 0, "permission": "deny", "policy": "BLOCK", "contains_unacknowledged": True}),
    _spec("claude.protected_mutation", "claude", {"exit": 0, "permission": "deny", "policy": "BLOCK", "prefix": True}),
    _spec("claude.uncovered_tool", "claude", {"exit": 0, "stdout_empty": True, "classification": "UNCOVERED"}),
    _spec("codex.safe_apply_patch", "codex", {"exit": 0, "permission": "deny", "policy": "ASK", "prefix": True}),
    _spec("codex.authorized_normal_apply_patch", "codex", {"core_outcome": "ALLOW", "authorizing_task_id": "task-active", "exit": 0, "adapter_silent": True}),
    _spec("codex.governed_block_unacknowledged", "codex", {"exit": 0, "permission": "deny", "policy": "BLOCK", "contains_unacknowledged": True}),
    _spec("codex.protected_apply_patch", "codex", {"exit": 0, "permission": "deny", "policy": "BLOCK", "prefix": True}),
    _spec("codex.mixed_apply_patch", "codex", {"exit": 0, "permission": "deny", "policy": "BLOCK", "protected_target": True, "target_count": 2}),
    _spec("codex.malformed_patches", "codex", {"cases": ["unsupported_envelope", "environment_id", "orphan_move", "zero_operations", "unclassified_line"], "all_adapter_failure": True, "no_policy_block": True, "adapter_failure_count": 5}),
    _spec("adapters.missing_invalid_state", "adapters", {"adapter_failure_count": 4, "all_deny": True, "no_policy_block": True}),
    _spec("adapters.no_project_root", "adapters", {"claude_silent": True, "codex_silent": True}, NO_ROOT),
    _spec("codex.uncovered_tools", "codex", {"tools": ["Bash", "mcp__filesystem__write", "spawn_agent"], "all_uncovered": True}),
    _spec("adapters.synthetic_allow_mapping", "adapters", {"classification": "SYNTHETIC_MAPPING_ONLY", "claude_silent": True, "codex_silent": True}),
    _spec("adapters.wrong_hook_event", "adapters", {"adapter_failure_count": 2, "all_deny": True}),
    _spec("adapters.bad_argv", "adapters", {"claude_exit_codes": [2, 2], "codex_exit_codes": [2, 2], "diagnostics": True}),
    _spec("verify.evidence_verified", "verify", {"verification": "VERIFIED", "reason": "DIGEST_MATCH"}),
    _spec("verify.evidence_digest_mismatch", "verify", {"verification": "FAILED", "reason": "DIGEST_MISMATCH"}),
    _spec("verify.evidence_missing_source", "verify", {"verification": "UNVERIFIED", "reason": "SOURCE_MISSING"}),
    _spec("verify.evidence_protected_source", "verify", {"verification": "UNVERIFIED", "reason": "SOURCE_UNSAFE"}),
    _spec("verify.claim_verified", "verify", {"verification": "VERIFIED", "reason": "ALL_EVIDENCE_VERIFIED"}),
    _spec("verify.claim_failed_precedence", "verify", {"verification": "FAILED", "reason": "EVIDENCE_FAILED"}),
    _spec("verify.claim_unverified_precedence", "verify", {"verification": "UNVERIFIED", "reason": "EVIDENCE_UNVERIFIED"}),
    _spec("verify.claim_volatile_freshness_does_not_gate", "verify", {"verification": "VERIFIED", "reason": "ALL_EVIDENCE_VERIFIED"}),
    _spec("verify.no_state_write", "verify", {"state_bytes_unchanged": True, "revision_unchanged": True}),
    _spec("handoff.matching_binding_verified_now", "handoff", {"verification": "VERIFIED", "reason": "ALL_EVIDENCE_VERIFIED", "disposition": "INCLUDED", "verified_now": True, "digest_not_rechecked": False}),
    _spec("handoff.changed_source_failed_now", "handoff", {"verification": "FAILED", "reason": "EVIDENCE_FAILED", "disposition": "REVALIDATE", "failure_marked": True}),
    _spec("handoff.missing_source_unverified", "handoff", {"verification": "UNVERIFIED", "reason": "EVIDENCE_UNVERIFIED", "disposition": "REVALIDATE", "presented_as_verified": False}),
    _spec("handoff.unsafe_source_unverified", "handoff", {"verification": "UNVERIFIED", "reason": "SOURCE_UNSAFE"}),
    _spec("handoff.persisted_provenance_is_not_current_truth", "handoff", {"current_verification": "VERIFIED", "current_reason": "ALL_EVIDENCE_VERIFIED", "disposition": "REVALIDATE", "rendered_freshness": "FAILED", "historical_failure_preserved": True, "verified_now": True}),
    _spec("handoff.persisted_verified_claim_rejected", "handoff", {"exception": "StateValidationError", "persisted_verified_rejected": True}),
    _spec("handoff.no_state_write", "handoff", {"state_bytes_unchanged": True, "revision_unchanged": True, "source_bytes_unchanged": True}),
    _spec("handoff.repeat_is_deterministic", "handoff", {"verification_equal": True, "payload_equal": True, "report_equal": True, "json_equal": True}),
    _spec("handoff.partial_verification_contract", "handoff", {"verdict_counts": {"VERIFIED": 4, "FAILED": 2, "UNVERIFIED": 4}, "all_verifiable_explicit": True, "failed_revalidate": True, "unverified_never_verified": True, "verified_eligible_included": True, "continuity_present": True, "global_success_claim": False}),
    _spec("handoff.budget_accounting_exact", "handoff", {"accounting_exact": True}),
    _spec("handoff.session_profile_unchanged", "handoff", {"identical": True, "verification_metadata_absent": True}),
    _spec("handoff.foreign_scope_semantics_fails_closed", "handoff", {"all_unverified": True, "all_scope_incompatible": True, "zero_source_reads": True}),
    _spec("authoring.task_created_unapproved", "authoring", {"exit": 0, "status": "DRAFT", "intent": "PROPOSED", "execution": "NOT_RUN", "authorized_scope": [], "acknowledged_invariant_ids": [], "approval_metadata_absent": True, "trusted_active_task": False, "revision": 1}),
    _spec("authoring.invariant_governed_scope_created", "authoring", {"exit": 0, "enforcement": "BLOCK", "status": "ACTIVE", "governed_scope": ["src", "docs"], "approval_metadata_absent": True, "revision": 1}),
    _spec("authoring.empty_governed_scope_is_not_repository_global", "authoring", {"exit": 0, "governed_scope": [], "meaning": "NO_TARGET_BINDING", "dot_scope_meaning": "WHOLE_REPOSITORY", "equal": False}),
    _spec("doctor.healthy_project", "doctor", {"overall": "HEALTHY", "all_pass": True, "exit": 0}),
    _spec("doctor.not_initialized", "doctor", {"overall": "UNHEALTHY", "reason": "PROJECT_ROOT_NOT_FOUND", "skips": 7, "exit": 20}, NO_ROOT),
    _spec("doctor.malformed_state_json", "doctor", {"reason": "STATE_JSON_INVALID", "exit": 20}),
    _spec("doctor.unsupported_schema", "doctor", {"reason": "SCHEMA_UNSUPPORTED", "exit": 20}),
    _spec("doctor.incompatible_scope_semantics", "doctor", {"reason": "SCOPE_SEMANTICS_INCOMPATIBLE", "exit": 20}),
    _spec("doctor.healthy_without_active_task", "doctor", {"overall": "HEALTHY", "exit": 0}),
    _spec("doctor.budget_below_profile_minimum", "doctor", {"overall": "DEGRADED", "reason": "BUDGET_BELOW_PROFILE_MINIMUM", "exit": 0}),
    _spec("doctor.no_state_write", "doctor", {"bytes_unchanged": True, "revision_unchanged": True, "contents_unchanged": True}),
    _spec("doctor.deterministic_output", "doctor", {"text_identical": True, "json_identical": True}),
    _spec("cross.session_context_parity", "cross", {"identical": True}),
    _spec("cross.safe_target_asymmetry", "cross", {"claude_policy": "ASK", "codex_policy": "ASK", "claude_transport": "ask", "codex_transport": "deny", "classification": "EXPECTED_ASYMMETRY"}),
    _spec("cross.protected_target_parity", "cross", {"claude_policy": "BLOCK", "codex_policy": "BLOCK", "claude_transport": "deny", "codex_transport": "deny", "identical_policy": True}),
    _spec("cross.governed_block_parity", "cross", {"claude_policy": "BLOCK", "codex_policy": "BLOCK", "claude_transport": "deny", "codex_transport": "deny", "identical_policy": True, "contains_unacknowledged": True}),
    _spec("cross.failure_parity", "cross", {"claude": "ADAPTER_FAILURE", "codex": "ADAPTER_FAILURE", "no_policy_block": True, "adapter_failure_count": 2}),
)


SCENARIOS_BY_ID: Final = MappingProxyType({item.id: item for item in SCENARIOS})

V1_ACCEPTANCE_BLOCKERS: Final = (
    {
        "id": "VAB-1",
        "title": "trusted scoped adapter ALLOW implemented and reviewed",
        "status": "CLOSED",
    },
    {
        "id": "VAB-2",
        "title": "target-to-governed-invariant binding and acknowledgement enforcement",
        "status": "CLOSED",
    },
    {
        "id": "VAB-3",
        "title": "reproducible evidence verifier implemented; verdicts remain ephemeral and persisted VERIFIED stays prohibited",
        "status": "CLOSED",
    },
    {
        "id": "VAB-4",
        "title": "explicit verified-handoff profile implemented and reviewed; per-record Evidence and Claim verdicts are derived fresh, remain ephemeral, and whole-payload certification is not claimed",
        "status": "CLOSED",
    },
    {
        "id": "VAB-5",
        "title": "read-only doctor diagnostics implemented and reviewed; deterministic local project and state health reporting performs no repair and establishes no live harness evidence",
        "status": "CLOSED",
    },
    {
        "id": "VAB-6",
        "title": "supported Task and Invariant authoring surface implemented and reviewed; authoring remains distinct from trusted authorization",
        "status": "CLOSED",
    },
    {
        "id": "VAB-7",
        "title": "Claude-only live harness evidence accepted; installed SessionStart dispatch, live context injection, and selected-path Write mutation denial verified; Codex live acceptance deferred post-V1",
        "status": "CLOSED",
    },
    {
        "id": "VAB-8",
        "title": "V1 demo acceptance contract undefined",
        "status": "UNRESOLVED",
    },
)

LIVE_VERIFICATION: Final = MappingProxyType(
    {
        "INSTALLED_HARNESS_DISPATCH": "VERIFIED_CLAUDE_ONLY",
        "LIVE_MUTATION_DENIAL": "VERIFIED_CLAUDE_ONLY",
        "LIVE_CONTEXT_INJECTION": "VERIFIED_CLAUDE_ONLY",
    }
)

CLAIM_LABELS: Final = (
    "CORE_POLICY_VERIFIED",
    "CONTEXT_COMPILATION_VERIFIED",
    "ADAPTER_TRANSPORT_VERIFIED",
    "REPRODUCIBLE_EVIDENCE_VERIFIED",
    "SYNTHETIC_CROSS_HARNESS_PARITY_VERIFIED",
    "SYNTHETIC_MAPPING_ONLY",
    "UNCOVERED",
    "NOT_MEASURABLE_V1",
)

UNCOVERED_SURFACES: Final = (
    "Claude Bash",
    "Claude PowerShell",
    "Claude MCP",
    "Codex Bash",
    "Codex MCP",
    "other Codex local functions",
    "spawn_agent",
)

REQUIRED_SESSION_IDS: Final = (
    "inv-block",
    "inv-advise",
    "inv-current",
    "task-active",
    "dec-authorized",
    "claim-durable",
    "claim-volatile",
    "claim-digest",
    "claim-failed",
    "claim-high-support",
    "claim-high-failed",
)

RULE_EXCLUDED_SESSION_IDS: Final = (
    "inv-superseded",
    "task-done",
    "task-draft",
    "dec-proposed",
)
