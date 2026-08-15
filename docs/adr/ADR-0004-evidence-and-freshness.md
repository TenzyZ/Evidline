# ADR-0004 — Evidence and Freshness

Status: Accepted

## Context

Persisted evidence needs clear freshness and verification rules.

## Decision

Evidence is durable-until-superseded, digest-bound, persisted-volatile, or ephemeral current
evidence. **Persisted VERIFIED requires reproducible verification.** In V1, digest matching
performed directly by Evidline is the initial reproducible verifier. `R2_CORROBORATED` is not
defined as VERIFIED. Non-reproducible assertions and references remain UNVERIFIED. Persisted
volatile information is always rendered as stale/revalidate; ephemeral current evidence is used
only during the current evaluation and is not persisted as current truth.

## Consequences

Persistence never turns unsupported evidence into durable truth.
