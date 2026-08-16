# ADR-0012 — CLI Surface (V1 Phase 4)

Status: Accepted

## Context

Phase 4 exposes the already-established state, context, and mutation-policy cores
through a deterministic local command-line interface. The interface must keep
inspection separate from permission, execution, verification, and enforcement.

## Decision

The V1 Phase 4 command set is exactly `init`, `status`, the existing `context`,
and the manually invoked non-enforcing `check-mutation`. Stdlib `argparse` remains
the parser and Phase 4 adds no runtime dependency.

Bare `evidline` writes help to stderr and exits 2. `evidline --help` retains normal
argparse help on stdout with exit 0, and the existing version and `context`
contracts remain unchanged.

## Initialization

`init` creates `.evidline/state.json` with exclusive-create semantics. It never
overwrites an existing state file. A valid existing document makes initialization
idempotent and leaves the file byte-identical; an invalid existing document is
reported without replacement. Initialization creates no journal, lock, config,
ignore rule, or additional state file.

Exclusive creation applies only to initialization. Existing state updates continue
to use the established validated temp-file-plus-`os.replace` persistence contract.

## Status

`status` is read-only and reports only the current validated `StateDocument` plus
canonical root and state paths. Text and JSON ordering are deterministic.
`STATUS_SCHEMA_VERSION` versions only the status output contract and does not
change the persisted state schema.

## Mutation inspection

`check-mutation` evaluates the existing policy through its thin discovery and
state-loading wrapper. It executes nothing, grants nothing, changes no harness or
OS permission, installs no hook, and is not enforcement. An `ALLOW` means only
that the supplied request and current evidence satisfy Evidline policy.

The command does not modify `state.json`. Phase 4 performs no check journaling and
adds no product subprocess, shell, or network behavior.

## Exit codes and streams

The public exit-code contract is:

- `0`: success or policy `ALLOW`;
- `2`: invalid CLI usage;
- `3`: state not initialized;
- `4`: invalid or unsupported state;
- `5`: state or path I/O failure;
- `6`: invalid input;
- `7`: unexpected internal decision-path failure;
- `10`: policy `ASK`; and
- `11`: policy `BLOCK`.

Exit 7 is distinct from exit 11 because an internal failure is not a fabricated
policy decision. Callers must fail closed without representing it as a
`MutationDecision`.

Successful command data is written to stdout. Usage and error diagnostics are
written to stderr. Every actual `check-mutation` evaluation writes the fixed
non-enforcement notice to stderr, never stdout.

## Deferred and rejected work

`doctor` and verified handoff capability are deferred. A separate `handoff`
command is rejected for V1 under the existing continuity design. Claude Code and
Codex adapters, hooks, hook installation, and live enforcement are deferred.

## Consequences

Phase 4 provides a small deterministic local CLI without widening authority or
execution. Persisted schema version 1 remains unchanged, and inspection remains
explicitly separate from harness permission, mutation execution, and verification.
