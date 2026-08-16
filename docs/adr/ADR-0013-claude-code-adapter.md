# ADR-0013 — Claude Code Adapter (V1 Phase 5)

Status: Accepted

## Amends

ADR-0008 — Claude and Codex Adapters

## Context

Phase 5 needs a thin Claude Code transport over the existing context compiler,
project-root discovery, state loader, path boundary, and mutation decision
engine. The adapter must not become a second policy implementation or confuse a
Claude tool proposal with human intent, authority, evidence, permission, or
verification.

## Decision

Phase 5 adds the dedicated, stateless command transport
`python -m evidline.adapters.claude`. It supports `session-start` and
`pre-tool-use`, reads hook JSON from stdin, performs no network or subprocess
work, and writes no state, journal, cache, or configuration. Adapter commands use
exit 0 for normal hook results and do not reuse the CLI policy exit codes 10 and
11. Invalid adapter commands and structured-stdout write failure use exit 2.

### Boundary

Phase 5 implements bounded SessionStart context transport and PreToolUse
transport for `Write`, `Edit`, and `NotebookEdit`. The existing path and mutation
cores enforce protected `.git` and `.evidline` components at any depth and
targets outside the canonical Evidline project root. Calls to the same covered
tools from subagents use the same adapter surface.

SessionStart recompiles the session profile on every invocation and takes its
budget from `project.default_budget_chars`. It emits only the existing rendered
payload as plain stdout text. It caches and persists nothing. SessionStart is
advisory: malformed input, unavailable state, and compilation failures emit no
context and exit 0 with a concise stderr diagnostic.

The PreToolUse adapter passes the raw target string unchanged to the existing
core. It does not normalize paths, classify source, parse commands, or duplicate
path or mutation policy.

### Intent

Every covered request uses:

`request_intent = PROPOSED`

The earlier interpretation that "a PreToolUse event means the mutation is
REQUESTED" is rejected. The event shows that the agent proposed or requested a
tool execution; it does not establish that human intent has standing. ADR-0009
forbids agent self-authorization, and schema version 1 has no deterministic
binding between an authority record and a mutation target. The adapter therefore
must not promote the event to `REQUESTED` or `AUTHORIZED`.

### Risk

Every covered request uses:

`risk = NORMAL`

This is a declared non-assessment required by the current request type, not an
actual risk classification. Schema version 1 has no deterministic per-mutation
risk source. The adapter does not infer risk from the filename, extension,
location, tool, source content, prompt, transcript, permission mode, or other
Claude metadata. `NORMAL` exposes `NO_ACTIVE_TASK` where relevant.

### Gate inertness and capability ceiling

Phase 5 cannot populate trustworthy target-bound declared scope, authorizing
ids, asserted invariant conflicts, or HIGH evidence. Those policy gates remain
inert or unreachable for this adapter.

Consequently, Phase 5 cannot generally distinguish an ordinary edit from an
unsupported architectural or security edit. Under the frozen request contract,
a covered non-protected in-root edit reaches ASK rather than a deterministic
architectural BLOCK. General unsupported-mutation blocking requires future
architecture, not adapter heuristics.

### Outcomes and failures

An existing-core ASK maps to Claude `permissionDecision: "ask"`; an
existing-core BLOCK maps to `permissionDecision: "deny"`. Reasons are derived
only from the decision outcome, ordered reasons, and next step, and state that
the result is neither harness nor human authorization.

ALLOW transport remains silence. The adapter is prohibited from emitting
`permissionDecision: "allow"` because an Evidline ALLOW is not a Claude
permission grant. Real covered Phase 5 requests cannot currently reach ALLOW
because their intent is `PROPOSED`; a synthetic mapping test preserves silent
ALLOW handling for forward compatibility.

Malformed input, state-loading failure, `MutationInputError`, unexpected core
failure, and unknown outcomes fail closed with Claude `deny` after the adapter
has successfully started. Their reason begins `evidline adapter failure:` and
states that no `MutationDecision` was produced. They are not represented as an
Evidline policy BLOCK.

### Tool narrowing

ADR-0008's Claude tool direction is narrowed for Phase 5, not erased. Phase 5
covers `Write`, `Edit`, and `NotebookEdit`. It defers `Bash`, `PowerShell`, and
`Monitor` because they expose no reliable single mutation target. MCP mutation
remains outside the deterministic V1 guarantee. The adapter contains no
heuristic shell parser.

### Activation and transport limits

No `.claude/**` file is committed. Hook activation is a separate
human-controlled runtime gate.

If the adapter is successfully invoked, it can translate failures to a deny. If
the hook cannot start, the executable is missing, the interpreter fails before
the adapter runs, or the hook times out, the adapter supplies no decision. Phase
5 is therefore not an unconditionally fail-closed system boundary.

The design selects `permissionDecision: "ask"`, but does not claim live-verified
mode-specific ASK behavior under `bypassPermissions`, `auto`, or `acceptEdits`.
That behavior remains for a separately authorized live-integration gate.

### Deferred authority dependency

ADR-0006 and ADR-0009 refer to `evidline approve ...`, but no such command exists
in the current CLI. Authority enforcement remains deferred; Phase 5 does not
invent an approval or task-authoring workflow.

Before general unsupported-mutation blocking can be claimed, Evidline needs a
deterministic binding between human-authorized authority and mutation targets or
path scope. That dependency requires separate future architecture work and is
not designed here.

## Consequences

Phase 5 provides bounded Claude Code context and direct-file-tool transport over
the existing core without adding runtime dependencies, state mutations, hook
activation, or general shell and MCP enforcement. Its guarantees and residual
fail-open and coverage limits must remain explicit in user documentation.
