# Synthetic cross-harness benchmark

Evidline's Phase 7 benchmark measures the implemented core and adapter
transports without installing or activating hooks.

## Run

From the repository root:

```text
PYTHONPATH=src python -m benchmarks.runner
```

In PowerShell:

```powershell
$env:PYTHONPATH='src'; python -m benchmarks.runner
```

The expected successful result is:

```text
benchmark_execution = COMPLETED
v1_acceptance = BLOCKED
```

Open V1 blockers do not make a correctly executed benchmark fail.

## Verification labels

- `CORE_POLICY_VERIFIED`: direct synthetic core scenarios match their declared
  policy results.
- `CONTEXT_COMPILATION_VERIFIED`: synthetic selection, freshness, audit, and
  budget invariants match the current compiler.
- `ADAPTER_TRANSPORT_VERIFIED`: in-process adapter output mapping matches the
  existing transport contract.
- `REPRODUCIBLE_EVIDENCE_VERIFIED`: deterministic library-only evidence and
  claim verification scenarios match their declared byte-binding results.
- `SYNTHETIC_CROSS_HARNESS_PARITY_VERIFIED`: paired synthetic Claude and Codex
  scenarios match their declared parity contract.
- `SYNTHETIC_MAPPING_ONLY`: an injected ALLOW decision tests output mapping
  independently from the real scoped-authority scenarios.
- `UNCOVERED`: the adapter is silent and made no Evidline policy decision.
- `NOT_MEASURABLE_V1`: the accepted property is outside the implemented V1
  measurement boundary.

Live verification is always explicit:

```text
INSTALLED_HARNESS_DISPATCH = VERIFIED_CLAUDE_ONLY
LIVE_MUTATION_DENIAL       = VERIFIED_CLAUDE_ONLY
LIVE_CONTEXT_INJECTION     = VERIFIED_CLAUDE_ONLY
```

## Phase 9B verifier coverage

The nine `verify.*` scenarios exercise the library verifier directly: matching,
mismatching, missing, and protected evidence sources; verified, failed, and
unverified claim precedence; persisted-volatile freshness separation; and the
no-state-write invariant. They hash deterministic raw text, empty, and binary
fixture files inside the disposable benchmark sandbox.

This proves only the Phase 9B library verifier. It does not prove CLI
verification, automatic state-load verification, context integration, mutation
integration, live Claude enforcement, live Codex enforcement, hooks, persisted
`VERIFIED`, TOCTOU protection, or hardlink protection.

## Phase 10 authoring coverage

The three `authoring.*` scenarios prove that supported Task creation exists and
the new Task remains unapproved and untrusted; supported ACTIVE Invariant
creation exists; governed scope persists with existing semantics; and empty
scope differs from explicit repository root.

They do not prove live hook dispatch, live context injection, live mutation
denial, installed harness integration, human acceptance, or VAB-6 closure.

## Phase 11 verified-handoff coverage

The twelve `handoff.*` scenarios exercise the explicit
`context --profile verified-handoff` architecture through direct library and
wrapper boundaries. They cover matching, changed, missing, unsafe, historical,
and foreign-scope results; persisted-VERIFIED rejection; no state/source write;
deterministic rendering; partial per-record degradation; exact budget
accounting; and unchanged SESSION output. The current benchmark total is
86 / 86 matched.

This proves deterministic synthetic composition of current per-record Evidence
and Claim verdicts into a handoff-style context. It does not certify the payload
as a whole, byte-verify Tasks/Decisions/Invariants, semantically prove Claim
prose, by itself satisfy any acceptance-ledger requirement, install hooks, integrate adapters or mutation policy, or
eliminate the accepted TOCTOU/hardlink residual.

## V1 blockers

`VAB-1` — **trusted scoped adapter ALLOW implemented and reviewed** — is
`CLOSED`. Its engineering implementation, independent review, and synthetic
benchmark closure are recorded. The benchmark proves that both adapters still
submit `PROPOSED`, the core derives authority from a trusted ACTIVE Task with
matching `authorized_scope`, and the existing silent ALLOW transport is
reached. Outside-scope and untrusted-channel scenarios do not derive authority.
This remains synthetic in-process proof, not live hook proof or human
acceptance.

`VAB-2` — **target-to-governed-invariant binding and acknowledgement
enforcement** — is `CLOSED`. Its engineering implementation, independent
review, and synthetic benchmark closure are recorded. A covered mutation whose
canonical target lies inside the governed filesystem scope of an ACTIVE BLOCK
invariant is deterministically blocked unless the trusted ACTIVE Task
explicitly acknowledges that invariant, provided no earlier failure prevents
policy evaluation. The benchmark also proves that acknowledgement does not
suppress caller-asserted invariant conflicts and that both existing adapters
transport the core BLOCK as denial.

VAB-1, VAB-2, VAB-3, VAB-4, VAB-5, and VAB-6 closure does not invalidate the remaining V1 limitations below.
Because they are closed while other acceptance requirements remain unsatisfied,
overall `v1_acceptance` remains `BLOCKED`.

`VAB-3` — **reproducible evidence verifier implemented; verdicts remain ephemeral
and persisted VERIFIED stays prohibited** — is `CLOSED`.

`VAB-4` — **explicit verified-handoff profile implemented and reviewed; per-record Evidence and Claim verdicts are derived fresh, remain ephemeral, and whole-payload certification is not claimed** — is `CLOSED`.
Closure is based on the explicit `verified-handoff` profile implementation;
current per-record Evidence/Claim verification is fresh and ephemeral; full
suite passed; benchmark 86/86 matched; independent review approved; and the
accepted Phase 11 merge completed.

`VAB-5` — **read-only doctor diagnostics implemented and reviewed; deterministic local project and state health reporting performs no repair and establishes no live harness evidence** — is `CLOSED`.
Closure is based on supported `evidline doctor`; the original deterministic D001–D009 diagnostics;
read-only/no-repair contract; focused 82 tests passed; full suite 488 passed / 5 skipped;
benchmark 95/95 matched; independent review approved with 0 CRITICAL / 0 MATERIAL;
and the accepted Phase 12 merge completed.

## Phase 12 Doctor coverage

Doctor scenarios prove deterministic local diagnostic behavior, the ten-check
result contract, expected broken-state decomposition, read-only/no-write
behavior, deterministic rendering, and that optional absence is not corruption.
They do not perform Evidence verification or any live Claude behavior. The
benchmark contract records the separately accepted Claude-only installed
dispatch, injection, and denial evidence. Overall `v1_acceptance` remains
`BLOCKED`. This VAB-5 acceptance-ledger
closure completes the previously deferred ledger correction. The current frozen synthetic benchmark matches
`95/95` scenarios.

`VAB-6` — **supported Task and Invariant authoring surface implemented and reviewed; authoring remains distinct from trusted authorization** — is `CLOSED`.
Closure is based on supported Task and Invariant authoring, governed_scope
authoring, tests, the 74/74 synthetic benchmark, independent review, and the
accepted merge. Authored Tasks remain untrusted until the existing approval ceremony.

`VAB-7` — **Claude-only live harness evidence accepted; installed SessionStart dispatch, live context injection, and selected-path Write mutation denial verified; Codex live acceptance deferred post-V1** — is `CLOSED` based on the accepted sanitized evidence recorded in [ADR-0030](adr/ADR-0030-vab-7-closure.md).

VAB-1 through VAB-7 are `CLOSED`.

`VAB-8` — **external developer clean-machine Claude integration journey** — is
`OPEN`. The ratified contract requires an external developer on a clean machine
to install Evidline and its Claude integration, receive verified compiled
SessionStart context, observe an out-of-scope mutation BLOCK, complete an
in-scope approved mutation ALLOW, and remove the integration cleanly. This
journey has not been executed; `v1_acceptance` remains `BLOCKED`.

VAB-1 through VAB-8 are present acceptance limitations or status, not
implementation work already underway. VAB-8 remains open until its separately
authorized external-user acceptance proof is reviewed.

## Coverage boundary

The benchmark records current non-coverage instead of interpreting silence as
ALLOW. Representative uncovered surfaces are Claude Bash, PowerShell, and MCP;
Codex Bash, MCP, other local functions, and `spawn_agent`.

No `.claude/**` or `.codex/**` configuration is created. No live harness action
is performed.

## Result document

- `contract`: semantic values compared with the frozen expected contract;
- `observations`: deterministic measurements and diagnostics excluded from the
  frozen equality check;
- `benchmark_execution`: assigned after determinism and contract comparison.

The expected file contains only `schema_version` and `contract`. The runner and
tests never create, rewrite, bless, or regenerate it.

Benchmark-local exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | `COMPLETED` |
| 1 | `MISMATCHED` |
| 2 | `NONDETERMINISTIC` |
| 3 | `FAILED` |

The design is deterministic, local, network-free, subprocess-free, and uses
only the Python standard library. Character counts and Evidline's approximate
token estimate are observations; no real tokenizer is used.

## What this does not prove

The benchmark does not prove live hook dispatch, denial before a live mutation,
live context injection, semantic architecture conflict detection, diff-content
understanding, live adapter-level ordinary ALLOW, recovery telemetry, LLM-graded
recovery accuracy, real tokenizer measurement, comprehensive tool coverage, or
V1 release acceptance.
