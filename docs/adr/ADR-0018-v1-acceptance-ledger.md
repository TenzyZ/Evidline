# ADR-0018 — V1 Acceptance Ledger Correction

Status: Accepted

## Amends

ADR-0015 — Cross-Harness Benchmark; ADR-0016 — Scoped Authority Binding; and
ADR-0017 — Invariant Scope Binding. This ADR records only the corrected
acceptance ledger truth; it performs no product, schema, CLI, adapter, or
dependency change.

## Decision purpose

Correct the accepted V1 acceptance ledger after the engineering closure of
VAB-1 and VAB-2. Their independent review and synthetic benchmark closure are
recorded, while the remaining acceptance requirements stay unsatisfied, so
overall `v1_acceptance` remains `BLOCKED`.

## Status vocabulary

`OPEN`

A confirmed V1 acceptance requirement remains unsatisfied.

`CLOSED`

The specific acceptance blocker has been satisfied and closed by accepted
evidence.

`UNRESOLVED`

The item is within accepted V1 scope, but its exact acceptance contract remains
undefined.

`UNRESOLVED` does NOT mean partially implemented.

## Register

VAB-1 CLOSED — trusted scoped adapter ALLOW implemented and reviewed
VAB-2 CLOSED — target-to-governed-invariant binding and acknowledgement enforcement
VAB-3 OPEN — reproducible evidence verifier absent; persisted claims cannot reach VERIFIED
VAB-4 OPEN — verified handoff absent; handoff profile is explicitly unverified
VAB-5 OPEN — doctor / validation capability absent
VAB-6 OPEN — supported Task and Invariant authoring surface absent
VAB-7 OPEN — live harness evidence absent; installed dispatch, injection, and denial unattempted
VAB-8 UNRESOLVED — V1 demo acceptance contract undefined

## Acceptance rule

Overall `v1_acceptance = BLOCKED` while any acceptance-ledger entry remains
non-`CLOSED`. This ADR records the policy and ledger truth only; it does not
implement derivation logic for this rule. The current benchmark runner literal
remains unchanged.

## Supersession

This ADR supersedes only the stale acceptance-status statements in the
acceptance-blocker section of ADR-0015, and the relevant prior lifecycle or
status sentences in ADR-0016 and ADR-0017. ADR-0015 through ADR-0017 are not
edited and remain historical records.

## Explicit non-goals

ADR-0018 and Phase 8 implement none of: reproducible digest verification,
verified handoff, doctor, Task creation, Invariant creation, governed-scope
authoring, demo design, hook installation, live harness dispatch, live context
injection, live mutation denial, product schema changes, product CLI changes,
adapter changes, or dependency changes.

The demo acceptance contract remains undefined; VAB-8 `UNRESOLVED` implies no
implementation, design, sizing, or partial completion.
