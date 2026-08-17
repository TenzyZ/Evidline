# ADR-0021 — Supported Authoring Surface

Status: Accepted

## Amends

ADR-0012 — CLI Surface

## Context

V1 needs a supported path from `evidline init` to authored Task and Invariant
records without manually editing `.evidline/state.json`. Authoring must not
manufacture trusted authority or alter the existing interactive approval
ceremony.

## Decision

Phase 10 adds exactly two flat, non-interactive commands: `evidline add-task`
and `evidline add-invariant`. Operators supply record IDs explicitly. Counters
remain inert and reserved; automatic allocation requires a separate decision.

`add-task` creates only `DRAFT` / `PROPOSED` / `NOT_RUN` Tasks with empty
authorized scope, acknowledgements, and approval metadata. Authoring is not
authorization: `approve` remains the sole trusted Task authorization ceremony.

`add-invariant` creates only ACTIVE Invariants with no supersession and no
manufactured approval metadata. Its repeatable governed scope uses the existing
root-relative scope normalizer, preserves supplied order, and rejects duplicate
normalized values. `governed_scope == ()` is no target binding; `(".",)` is the
explicit whole-repository scope.

Neither command restamps `scope_semantics`. Native governed-scope authoring is
rejected for a foreign scope marker; empty-scope Invariant authoring preserves a
foreign empty marker. Both commands load validated state, construct typed
records, validate the proposal, and perform one optimistic locked write with the
current revision. Existing schema version 4, lock behavior, and concurrency
contract remain unchanged. No dependency is added.

## Non-goals and residual limitations

This phase provides no general state editor, interactive authoring wizard,
automatic or UUID IDs, Task completion, Invariant supersession, schema change,
migration, verifier wiring, hooks, live enforcement, or installed harness
integration. Cross-platform authoring of native scopes under a foreign marker
remains intentionally deferred to the existing interactive restamp ceremony.

## Acceptance ledger boundary

VAB-6 is `IMPLEMENTED_PENDING_REVIEW`. The ledger entry remains `OPEN` and
`v1_acceptance` remains `BLOCKED` until the accepted closure workflow occurs.
