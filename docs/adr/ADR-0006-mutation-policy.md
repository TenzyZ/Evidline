# ADR-0006 — Mutation Policy

Status: Accepted

## Context

Evidline must distinguish frictionless authorized work from unsupported mutations.

## Decision

Outcomes are ALLOW, ASK, and BLOCK. ALLOW is emitted as silence, so Evidline never grants
permissions beyond the harness; low-risk explicit edits remain frictionless. Five conceptual
gates apply: boundary, classification, scope, invariant plus reproducible evidence, and
disposition/error state. Authority-changing `evidline approve ...` attempts through covered agent
shell tools are CRITICAL/BLOCK. Refusals explain the exact target, reason, missing requirement,
and smallest next step.

## Consequences

Policy implementation is deferred.
