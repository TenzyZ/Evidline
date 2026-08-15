# ADR-0002 — Local State Storage

Status: Accepted

## Context

V1 needs reviewable local state and a separate refusal audit trail.

## Decision

Local state uses `.evidline/state.json`; refusal audit uses `.evidline/journal.jsonl`, which
is gitignored. `state.json` is intended to remain reviewable and committable as one validated
state document with schema version, revision/CAS, and temp-file plus replace writes. `check`
must never modify `state.json`. ALLOW decisions are not journaled; ASK/BLOCK may be journaled.

## Consequences

No `.evidline/` implementation exists yet.
