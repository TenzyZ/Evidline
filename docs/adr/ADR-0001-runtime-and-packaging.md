# ADR-0001 — Runtime and Packaging

Status: Accepted

## Context

Evidline needs a minimal, local-first Python foundation without runtime dependencies.

## Decision

The product name is Evidline. Distribution, import package, and CLI are `evidline`; local
state will live in `.evidline/`. The project uses Python `>=3.11`, a `src` layout, and a
standard-library core with zero runtime dependencies. Hatchling is build-system-only; this
decision installs no dependencies.

## Consequences

The package foundation stays small and no runtime behavior is introduced.
