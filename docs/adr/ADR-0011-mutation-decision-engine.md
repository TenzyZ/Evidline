# ADR-0011 — Mutation Decision Engine (V1 Phase 3)

Status: Accepted

## Context

ADR-0006 fixed the mutation policy and ADR-0007 fixed the boundary and filesystem
safety discipline, but both deferred implementation. Phase 3 implements the
already-decided policy as a pure, adapter-neutral decision engine over the current
validated state schema. No CLI, hook, or live enforcement exists in this phase.

## Decision

Phase 3 implements a pure Mutation Decision Engine (`src/evidline/mutation.py`).
It accepts an already-evaluated `PathEvaluation` and a typed `StateDocument`
and produces a deterministic, immutable `MutationDecision`. The core performs no
filesystem, subprocess, network, clock, randomness, or persistence work.
After its exact `StateDocument` type check, `decide_mutation` validates state
internally. A `StateValidationError` is exposed at this API boundary as a chained
`MutationInputError`.

## Scope

Phase 3 is a pure adapter-neutral Mutation Decision Engine. No CLI/hook/live
enforcement. Adapters remain future work (ADR-0008); this phase builds no adapter
and no hook.

Every declared-scope entry must be the canonical project root or one of its
descendants, and the target must be contained by at least one usable entry.
Invalid, above-root, or drive-mismatched entries produce `SCOPE_VIOLATION` rather
than an exception. Scope containment uses normalized path components, not string
prefixes.

## Request intent

`MutationRequest.request_intent` reuses the existing `state.Intent`. It is
transient: it persists nothing, promotes no state record, is not authenticated
authority, and must not be treated as proof merely because the caller supplied it.

Behavior across all tiers:

- `DENIED` → BLOCK at every tier (`REQUEST_INTENT_DENIED`).
- `PROPOSED` → never ALLOW (`REQUEST_INTENT_INSUFFICIENT`).
- `REQUESTED` and `AUTHORIZED` are sufficient transient intent to continue through
  the remaining gates.

Intent never overrides an unsafe or protected target.

## Risk-proportional task anchoring

No ACTIVE task:

- `LOW` → does not by itself prevent ALLOW.
- `NORMAL` → ASK (`NO_ACTIVE_TASK`).
- `HIGH` → BLOCK (`NO_ACTIVE_TASK`).
- `CRITICAL` → BLOCK regardless.

An ACTIVE task is not required for exact LOW edits.

## Authorization IDs

- `LOW` → ignored; no ceremony.
- `NORMAL` → optional; an ACTIVE task is sufficient authorization. If ids are
  supplied, every supplied id must resolve and be sufficient.
- `HIGH` → at least one authorizing id is required and valid.

Valid authority is only what current state contracts support: an authorized
`Decision` (`intent == AUTHORIZED`) or an active `Task` (`status == ACTIVE`), using
exact existing state semantics. `Execution` is never consulted as authority.

## Invariants

- `ACTIVE + ADVISE` → non-enforcing; never BLOCK and never ASK merely because of
  advisory; id recorded in `advisory_invariant_ids`; never inserted into failure
  or escalation `reasons`.
- `ACTIVE + BLOCK` asserted conflict → deterministic BLOCK; id recorded in
  `conflicting_invariant_ids`.
- `SUPERSEDED` → non-operative.

An unresolvable asserted invariant fails closed (`INVARIANT_UNRESOLVED`).

Invariant conflicts are caller-asserted because invariant descriptions are not
machine-evaluable in V1. The engine never semantically parses invariant prose.

## Risk

Risk is caller-declared. Path rules may escalate it monotonically. Risk is never
lowered. There is no heuristic content or file-extension inference.

## Evidence

Phase 3 collects no evidence. HIGH reasons over persisted claims plus
caller-supplied ephemeral verified evidence ids. Phase 3 implements no
reproducible verifier. Persisted `VERIFIED` remains impossible under current state
semantics, and persisted `STALE` remains rejected (ADR-0003, ADR-0004). Ephemeral
evidence is never persisted and no claim is promoted to `VERIFIED`.
`Execution.EXECUTED` does not satisfy verification, and provenance labels do not
confer verification privilege.

Every supplied support id is evaluated. An unresolved supplied claim, or a
supplied claim marked `FAILED`, `STALE`, or `VERIFIED`, disqualifies HIGH support.
A reproducible supplied claim supports HIGH only when it has evidence ids and all
of them are covered by the supplied ephemeral ids. For resolved supplied evidence,
`FAILED` and `BLOCKED` disqualify support; `NOT_RUN` and `EXECUTED` are neutral.
Extra unresolved ephemeral evidence ids are neutral. Execution never positively
verifies a claim.

## Outcomes

Maximum severity: `BLOCK > ASK > ALLOW`. Any gate may escalate; no later gate may
lower an earlier result.

Satisfied baseline mapping, subject to all other gates:

- `LOW` → ALLOW
- `NORMAL` → ALLOW
- `HIGH` → ASK
- `CRITICAL` → BLOCK

Any policy failure may BLOCK as defined. CRITICAL always resolves to BLOCK; no
Phase 3 code path ALLOWs or ASKs CRITICAL.

`ALLOW` is logically silent: `reasons == ()` and `next_step == ""`. Advisory
metadata and `MutationDecision.target` may still be present on an ALLOW result;
target metadata does not violate ALLOW silence. Every decision records the
canonical target string when available, otherwise `None`. ASK and BLOCK select
`next_step` deterministically from the highest-priority emitted reason.

## API surface

`MUTATION_SCHEMA_VERSION` identifies the mutation result schema. The optional
`MutationOperation` is informational and is not a policy gate.
`applicable_invariant_ids` reports every state invariant that is both `ACTIVE`
and `BLOCK`; it is not target-scoped. `MutationDecision.target` is the canonical
target string or `None` when path evaluation could not establish one.

## Purity

`decide_mutation(...)` is pure and accepts a previously evaluated
`PathEvaluation`. A thin wrapper may call `evaluate_mutation_path`. No
subprocess/network/clock/state writes. Harness capability is excluded from the
core request/result.

## Residual limitations

The engine cannot out-verify its inputs and is explicitly bounded by:

- caller-asserted risk;
- caller-asserted transient request intent;
- caller-declared scope;
- caller-asserted invariant conflicts;
- ephemeral evidence supplied by the caller;
- the adapter must fail closed on engine exceptions.

This phase does not implement enforcement, so these limitations are not overstated
as enforcement guarantees.

## Consequences

The policy from ADR-0006, ADR-0007, ADR-0009, and ADR-0010 is now implemented as a
deterministic, pure decision core with a thin filesystem-evaluation wrapper. No
adapter or hook is installed, and no CLI surface is added. Enforcement remains a
later phase.
