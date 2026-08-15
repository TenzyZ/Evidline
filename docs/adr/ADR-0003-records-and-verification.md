# ADR-0003 — Records and Verification

Status: Accepted

## Context

V1 must keep proposal, execution, and verification distinct.

## Decision

The five V1 record concepts are Invariant, Decision, Task, Claim, and Evidence. Intent is
`PROPOSED | REQUESTED | AUTHORIZED | DENIED`; execution is `NOT_RUN | EXECUTED | FAILED |
BLOCKED`; verification is `UNVERIFIED | VERIFIED | FAILED | STALE`. `EXECUTED` never implies
`VERIFIED`. Persisted `VERIFIED` is reserved for reproducible verification performed by
Evidline. Agent, human, and tool labels are provenance metadata, not authentication.

## Consequences

Claims cannot be promoted by provenance labels alone.
