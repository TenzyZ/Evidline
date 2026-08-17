# ADR-0022 — VAB-6 Acceptance Ledger Closure Correction

Status: Accepted

## Amends / supersession boundary

This ADR corrects only the stale VAB-6 acceptance status after ADR-0021's
deferred closure workflow was satisfied. ADR-0018 and ADR-0021 remain
historical records and are not rewritten. This ADR supersedes only ADR-0021's
pre-closure statement that VAB-6 is `IMPLEMENTED_PENDING_REVIEW` and its ledger
entry remains `OPEN`; no unrelated Phase 10 decision is superseded.

## Closure evidence

The accepted closure chain is:

- Phase 10 implementation commit: `64332b43f1d7d9f62320a67dc3714c680477f156`
- Phase 10 merge commit: `3cde1b08bbe4be9d4922db14bb55a66ae75bac4c`
- supported `add-task` implemented
- supported `add-invariant` implemented
- `governed_scope` authoring implemented
- authoring remains distinct from trusted authorization
- full tests passed
- benchmark: 74 / 74 matched
- independent review: approved for human acceptance; 0 CRITICAL; 0 MATERIAL
- accepted merge completed

The independent-review transcript is not stored in the repository. This ADR
records only the concise accepted review statement and does not reconstruct a
transcript.

## Corrected VAB-6 status

VAB-6 CLOSED

**supported Task and Invariant authoring surface implemented and reviewed; authoring remains distinct from trusted authorization**

Supported Task and Invariant authoring now exists, and `governed_scope` can be
authored. New Tasks remain `DRAFT` / `PROPOSED` / `NOT_RUN` and untrusted until
the existing interactive `approve` ceremony.

## Remaining acceptance ledger

VAB-1 CLOSED
VAB-2 CLOSED
VAB-3 CLOSED
VAB-4 OPEN
VAB-5 OPEN
VAB-6 CLOSED
VAB-7 OPEN
VAB-8 UNRESOLVED

`v1_acceptance = BLOCKED`

## Explicit non-goals

This closure performs no:

- product behavior change
- schema change
- CLI change
- adapter change
- verifier change
- hook change
- live enforcement
- dependency change
- VAB-4 change
- VAB-5 change
- VAB-7 change
- VAB-8 resolution
- V1 acceptance

This ADR is a closure correction, not a Phase 10 architecture recap.
