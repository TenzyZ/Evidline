# ADR-0031 — Claude Productization and VAB-8 Contract

Status: Accepted

## Amends / supersession boundary

This ADR supersedes only the stale VAB-8 `UNRESOLVED` statements in ADR-0018
and ADR-0030, and the exact-check-count and Doctor output-schema clauses in
ADR-0025. Historical records are not rewritten. All VAB-7 closure literals,
Claude-only evidence, Codex post-V1 deferral, adapter decision semantics, and
known coverage and fail-open boundaries remain unchanged.

## VAB-8 acceptance contract

VAB-8 requires one external developer to complete this journey on a clean
machine:

```text
install Evidline and its Claude integration
-> receive verified compiled context at SessionStart
-> have an out-of-scope mutation BLOCKED
-> complete an in-scope approved mutation ALLOWED
-> remove the integration cleanly
```

The contract is defined but no element of the journey has been live-verified
by this decision. Therefore:

```text
VAB-8 = OPEN
v1_acceptance = BLOCKED
```

Phase 18 owns the external-user acceptance proof. This ADR does not execute or
design that campaign and does not close VAB-8.

## Claude productization

The Python distribution adds the public console script
`evidline-claude-hook = evidline.adapters.claude:main`. The existing `evidline`
CLI and `python -m evidline.adapters.claude` transport remain supported.

The repository provides one declarative Claude plugin under
`integrations/claude-code/` and one repository-local marketplace manifest.
Claude Code owns marketplace addition, plugin installation, enablement,
disablement, and uninstallation. Evidline implements no lifecycle command,
settings writer, or marketplace manager and writes no `.claude/**`
configuration.

The plugin carries only the accepted adapter paths: SessionStart and
PreToolUse for `Edit|Write|NotebookEdit`, using exec-form
`evidline-claude-hook` with direct argv and the accepted 10-second timeout.

## Doctor amendment

Doctor output schema becomes `DOCTOR_SCHEMA_VERSION = 2` and contains ten
ordered checks. D010 is `integration.claude_hook_invocable`; it reports PASS
when `evidline-claude-hook` resolves in the current process environment and
WARN otherwise. The WARN makes the report `DEGRADED`, not `UNHEALTHY` by
itself.

D010 is diagnostic only. It does not establish that the Claude plugin is
installed, enabled, loaded, or executed; that SessionStart injected context;
that PreToolUse ran; that a mutation was blocked; or that live enforcement was
verified. Doctor remains read-only and performs no adapter import or state
mutation.

## Consequences

Phase 17 productizes the already-accepted Claude adapter surface without
changing its policy semantics or proving Windows Claude-process PATH
resolution. Installed-wrapper reachability and the complete VAB-8 journey
remain Phase 18 preconditions.
