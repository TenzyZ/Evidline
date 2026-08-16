# Claude Code adapter

Evidline Phase 5 provides a local, stateless Claude Code transport over the
existing context, path, state, and mutation-policy cores. It does not install or
activate a hook, grant Claude permission, or provide complete mutation
enforcement.

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
- task-bound path scope;
- semantic invariant evaluation;
- evidence-backed HIGH authorization;
- deterministic `Bash`, `PowerShell`, or `Monitor` coverage; or
- deterministic MCP mutation coverage.

The adapter does not parse shell commands. Commands such as `git`, `rm`, shell
redirection, scripts, PowerShell commands, monitors, and similar mechanisms may
mutate files outside the covered direct-file tools. MCP tools may do the same.
Phase 5 does not hide or heuristically compensate for that gap.

Every normal covered, in-root, non-protected mutation currently evaluates to ASK
because the adapter correctly represents a Claude PreToolUse event as
`PROPOSED`, not as human-requested or human-authorized intent. Phase 5 cannot
generally tell an ordinary edit from an unsupported architectural edit; both
reach ASK unless the existing core finds a deterministic path boundary or
protected-path violation.

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

## Reference configuration only

The following is a reference configuration. It is not automatically installed,
is not active by virtue of Phase 5, and is intended only for a separately
human-authorized future activation gate.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python",
            "args": [
              "-m",
              "evidline.adapters.claude",
              "session-start"
            ],
            "timeout": 10
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Edit|Write|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python",
            "args": [
              "-m",
              "evidline.adapters.claude",
              "pre-tool-use"
            ],
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Do not treat this example as authorization to create or modify
`.claude/settings.json` or `~/.claude/settings.json`. Activation and live mode
testing require a separate human decision.

## Current task-authoring limitation

There is no supported task-authoring or task-activation workflow. Do not
manually edit `.evidline/state.json`; `.evidline/**` is protected. The current
CLI also has no `evidline approve` command. Phase 5 does not invent an authority
workflow around those limitations.
