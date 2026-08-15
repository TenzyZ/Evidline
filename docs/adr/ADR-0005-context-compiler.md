# ADR-0005 — Context Compiler

Status: Accepted

## Context

Fresh agent sessions need bounded, explainable continuity.

## Decision

The compiler is deterministic: no embeddings or LLM. It uses explicit links, path overlap,
tags, and simple deterministic relevance. It has a character budget with token estimate labeled
approximate and reports INCLUDED, EXCLUDED, and REVALIDATE. Invariants are never silently
truncated. `context --profile handoff` is the continuity representation rather than a separate
Handoff record.

## Consequences

No compiler implementation exists yet.
