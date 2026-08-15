# ADR-0009 — Human-Controlled Authority

Status: Accepted

## Context

Authority changes must be separated from agent proposals and claim verification.

## Decision

Agents may propose; agents may not self-authorize. Human-controlled authority transitions are
Decision to AUTHORIZED, Task to ACTIVE, and Invariant to SUPERSEDED. `approve` is reserved for
authority transitions. Claim verification is not an authority transition and does not use
`approve`. Evidline does not authenticate humans; TTY checks may be defense-in-depth only, never
proof of human identity. Covered agent attempts to run `evidline approve ...` and direct agent
mutation of `.evidline/**` are intended to be CRITICAL/BLOCK. Residual bypass and fail-open
limitations remain explicit.

## Consequences

Authority enforcement is deferred to later phases.
