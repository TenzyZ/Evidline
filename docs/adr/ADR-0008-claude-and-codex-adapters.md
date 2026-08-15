# ADR-0008 — Claude and Codex Adapters

Status: Accepted

## Context

V1 needs adapter coverage without making adapters the policy authority.

## Decision

Adapters are thin and translation-only. Claude V1 targets `Edit`, `Write`, `NotebookEdit`,
`Bash`, `PowerShell`, and `Monitor`; Codex targets `apply_patch` and `Bash`. MCP mutation is
outside the deterministic V1 guarantee. For ASK, Claude uses native ASK where currently supported;
Codex renders BLOCK/DENY with human-action instructions because native PreToolUse ASK is not
relied upon. ALLOW remains silence. Hook crash, missing executable, and timeout fail-open
limitations must be disclosed. Vendor hook semantics must be reverified from current primary
documentation during implementation.

## Consequences

No adapters or hooks are installed in this phase.
