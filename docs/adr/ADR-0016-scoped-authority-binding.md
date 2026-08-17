# ADR-0016 — Scoped Authority Binding

Status: Accepted

## Amends

ADR-0009 — Human-Controlled Authority; ADR-0011 — Mutation Decision Engine;
ADR-0012 — CLI Surface; ADR-0013 — Claude Code Adapter; and ADR-0014 — Codex
Adapter.

## Context

Claude and Codex adapters correctly submit covered mutations as `PROPOSED`.
A harness PreToolUse event proves an agent proposal, not human authorization for
the target. The ACTIVE Task is the existing human-controlled authority record,
but state schema version 1 cannot bind it to filesystem scope. Consequently,
real adapter requests cannot reach the ordinary ALLOW path.

## Decision

Persisted state schema version 2 adds only `Task.authorized_scope`, an ordered
tuple of normalized root-relative path prefixes. Empty scope means no derived
authority. `.` is the sole explicit whole-project scope. Absolute paths,
above-root traversal, glob syntax, negation, duplicate entries, and
non-normalized entries are invalid. Schema version 1 is not migrated or silently
accepted; this pre-release change remains strict-versioned and fails closed.

The pure mutation core may derive bounded authority for a `PROPOSED` request only
from the single valid ACTIVE/AUTHORIZED Task when it has required approval
metadata, the exact core-recognized interactive CLI channel and actor labels, a
non-empty scope, and a canonical target contained by that scope. Matching uses
the canonical root and target produced by the existing path boundary, not the
raw adapter label. The decision records the supplying Task as
`authorizing_task_id`.

Derived authority removes only `REQUEST_INTENT_INSUFFICIENT`. It does not
override DENIED intent, unsafe or out-of-root targets, `.git/**`,
`.evidline/**`, CRITICAL risk, caller-declared scope narrowing, evidence or
freshness gates, asserted invariant conflicts, or any stronger ASK/BLOCK gate.
Outcome severity remains monotonic.

Both adapters continue to submit `PROPOSED`, NORMAL, and empty caller authority
fields. They do not inspect Task scope, manufacture decision metadata, infer
authority from prompts or permission modes, or reinterpret harness approval as
Evidline authorization. Evidline ALLOW remains silent adapter non-interference,
not a Claude or Codex permission grant.

`evidline approve TASK_ID --scope ROOT_RELATIVE_PATH` is the sole VAB-1
authoring transition. It operates only on an existing non-DONE, non-DENIED Task,
refuses a conflicting ACTIVE Task, displays normalized scope, requires the
operator to type the exact Task ID, stamps the fixed interactive approval
channel and asserted-actor labels, validates the complete proposed state, and
uses the existing optimistic state write. It is not a general state editor.

TTY input and output are required as defense-in-depth only. Interactivity does
not authenticate a human, establish identity, or create a bearer capability.
No cryptography, credential, signing, secret, token, cloud identity, or OS
authentication is introduced.

## Deferred work and residual boundary

VAB-1 adds no `Invariant.governed_scope`, invariant path relevance,
`INVARIANT_UNACKNOWLEDGED`, invariant acknowledgement, semantic invariant or
diff analysis, architecture classifier, VAB-2 benchmark closure, or V1
acceptance closure.

Task.authorized_scope normalization follows the host `os.path.normcase` discipline and therefore persists platform-relative values. Cross-platform reuse fails closed rather than broadening authority: a scope authored on POSIX with case-preserved paths may be rejected entirely when Windows re-normalizes it to lowercase during state validation; conversely, a Windows-normalized/lowercased scope loaded on a case-sensitive POSIX host may parse without error but fail to match the intended mixed-case target, yielding no derived authority. Portable cross-platform scope normalization is not solved in VAB-1 and is deferred to a separate architecture decision.

Evidline remains incomplete as a shell-security boundary. Bash, PowerShell,
uncovered MCP tools, or another path outside covered mutation tools may mutate
`.evidline/state.json` or invoke the CLI depending on independent harness and OS
controls. Covered paths protect `.evidline/**`; harness sandbox/approval and
human Git review remain separate defenses. Hook absence, startup failure,
timeout, trust failure, or unsupported transport can still fail open. This ADR
makes no hook activation, installed-dispatch, live enforcement, or authentication
claim.

## Consequences

An otherwise permitted covered NORMAL mutation can reach core ALLOW when its
canonical target is inside trusted ACTIVE Task scope, while adapters remain
honest about `PROPOSED`. VAB-2 remains a separate later decision and phase.
