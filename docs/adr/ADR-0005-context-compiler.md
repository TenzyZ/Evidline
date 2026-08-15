# ADR-0005 — Context Compiler

Status: Accepted

Amended by: ADR-0010 (selection signals, V1 Phase 2)

## Context

Fresh agent sessions need bounded, explainable continuity.

## Decision

The compiler is deterministic: no embeddings or LLM. It uses explicit links, path overlap,
tags, and simple deterministic relevance. It has a character budget with token estimate labeled
approximate and reports INCLUDED, EXCLUDED, and REVALIDATE. Invariants are never silently
truncated. `context --profile handoff` is the continuity representation rather than a separate
Handoff record.

## Consequences

V1 Phase 2 implements the Context Compiler using the selection signals defined by
ADR-0010.
