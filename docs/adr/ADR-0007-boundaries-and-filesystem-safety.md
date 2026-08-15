# ADR-0007 — Boundaries and Filesystem Safety

Status: Accepted

## Context

Filesystem and shell boundaries need explicit limitations.

## Decision

Core uses canonical project-root/path containment and normalizes/resolves before containment
checks, including symlink/junction escape handling. Agent mutation of `.evidline/**` and
`.git/**` is CRITICAL. Evidline claims neither TOCTOU nor hardlink protection; shell parsing is
not an OS security boundary. It does not replace sandboxing, permissions, Git review, OS controls,
or human judgment. Core contains no subprocess or network execution.

## Consequences

Residual bypass limitations remain explicit.
