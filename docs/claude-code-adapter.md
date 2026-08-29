# Claude Code adapter

Evidline provides a local, stateless Claude Code transport over the
existing context, path, state, and mutation-policy cores. It does not install or
activate itself, grant Claude permission, or provide complete mutation
enforcement. The repository includes a declarative plugin; Claude Code owns its
lifecycle.

## What Phase 5 guarantees

When the adapter process successfully runs against an initialized Evidline
project, it provides:

- bounded SessionStart context compiled from current state using the project's
  `default_budget_chars`;
- deterministic `.git` protection for covered `Write`, `Edit`, and
  `NotebookEdit` targets, including nested `.git` components;
- deterministic `.evidline` protection for those covered tools, including
  nested `.evidline` components;
- deterministic denial of covered targets outside the canonical Evidline
  project root;
- the same adapter surface when a subagent invokes one of those covered tools;
- no Claude permission grant; and
- local, read-only, dependency-free operation with no network, persistence, or
  cache.

SessionStart recompiles on `startup`, `resume`, `clear`, `compact`, and `fork`.
The compiled packet is emitted as plain stdout text and is never persisted.

## Capability limits

Phase 5 does not provide:

- general architecture-change or unsupported-security-change blocking;
- semantic risk classification;
- semantic invariant evaluation;
- evidence-backed HIGH authorization;
- deterministic `Bash`, `PowerShell`, or `Monitor` coverage; or
- deterministic MCP mutation coverage.

The adapter does not parse shell commands. Commands such as `git`, `rm`, shell
redirection, scripts, PowerShell commands, monitors, and similar mechanisms may
mutate files outside the covered direct-file tools. MCP tools may do the same.
Phase 5 does not hide or heuristically compensate for that gap.

The adapter continues to represent every Claude PreToolUse event as `PROPOSED`,
not as human-requested or human-authorized intent. The core may derive bounded
authority from a trusted, ACTIVE Task whose `authorized_scope` contains the
canonical target. Without that exact binding, a normal covered mutation reaches
at least ASK. This does not add semantic architecture or invariant evaluation.

## ASK and permission modes

The adapter maps an Evidline ASK to Claude
`permissionDecision: "ask"`. Mode-specific ASK behavior under
`bypassPermissions`, `auto`, and `acceptEdits` has not been live-verified for
Evidline and is intentionally left unclaimed until a separately authorized live
integration gate.

Current Claude Code documentation describes `dontAsk` as denying actions that
would otherwise require a prompt; it does not provide an interactive approval
prompt. Phase 5 has not performed a live `dontAsk` integration test.

An Evidline ALLOW is a policy result, not permission. This adapter never emits
`permissionDecision: "allow"`; ALLOW transport is silence. Claude's permission
system, the harness, the operating system, and the human remain separate
authorities.

## Fail-open transport boundary

Once the adapter is running, malformed covered input, state failures, and core
failures translate to Claude `deny` without fabricating an Evidline policy
BLOCK. However, no Evidline decision may reach Claude if:

- Python or the configured executable is missing;
- the hook process cannot start;
- the interpreter fails before the adapter runs; or
- the hook times out.

Phase 5 is not an unconditionally fail-closed security boundary.

## Packaged plugin

The repository-local plugin at `integrations/claude-code/` runs the installed
`evidline-claude-hook` console executable in exec form with direct argv. It
carries only the accepted SessionStart and `Edit|Write|NotebookEdit`
PreToolUse paths and the accepted 10-second timeout. The existing
`python -m evidline.adapters.claude` transport remains supported.

Installed does not mean enabled; enabled does not mean loaded; loaded does not
mean executed; executed does not mean a decision was returned; and a decision
does not mean the mutation was actually blocked.

`evidline doctor` D010 reports only whether the hook executable name resolves
from the current process environment. A PASS does not prove any plugin or live
hook state. A WARN is a support and security concern: if the surrounding Claude
hook cannot start the executable, execution may proceed without Evidline
enforcement.

Use Claude Code's native marketplace and plugin commands to install, inspect,
enable, disable, and uninstall the plugin. Evidline never writes
`.claude/settings.json`, `.claude/settings.local.json`, or user settings.

## Bounded task approval

For an existing Task record, `evidline approve TASK_ID --scope PATH` performs the
interactive transition to ACTIVE/AUTHORIZED and records normalized root-relative
scope. The command requires interactive TTY input and output, displays the exact
scope, and requires the operator to type the Task ID. TTY interactivity is
defense-in-depth, not authentication or proof of human identity. The CLI still
does not provide a general Task creator or arbitrary state editor. Do not
manually edit `.evidline/state.json`; `.evidline/**` remains protected on covered
mutation paths.
