# ADR-0010 — Context Compiler Relevance Signals (V1 Phase 2)

Status: Accepted

## Amends

This decision amends the selection-signal clause of ADR-0005 for V1 Phase 2.

## Context

ADR-0005 specifies deterministic selection signals including record-level path overlap
and tag relevance. The Phase 1 validated schema has no record-level path or tag fields.
Implementing those signals in Phase 2 would therefore require persisted schema changes,
a `SCHEMA_VERSION` change, and a migration policy.

## Decision

Phase 2 implements the smallest deterministic V1 context compiler with only the
relevance signals the current validated schema can support:

- explicit-link relevance using the current validated schema; and
- deterministic lexical relevance against the active task.

Phase 2 deliberately defers:

- record-level path-overlap relevance; and
- tag relevance.

## Reason

The Phase 1 schema has no record-level path/tag fields; implementing those signals
would require persisted schema changes, `SCHEMA_VERSION` changes, and migration policy.
Future path/tag support requires a separate bounded schema/relevance decision.

## Consequences

The compiler is deterministic and explainable, but its relevance model is
coarser than ADR-0005's original clause. Records reachable only through path or tag
signals remain eligible only when deterministic lexical overlap selects them.
