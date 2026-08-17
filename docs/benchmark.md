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
- `SYNTHETIC_CROSS_HARNESS_PARITY_VERIFIED`: paired synthetic Claude and Codex
  scenarios match their declared parity contract.
- `SYNTHETIC_MAPPING_ONLY`: an injected ALLOW decision tests output mapping
  independently from the real scoped-authority scenarios.
- `UNCOVERED`: the adapter is silent and made no Evidline policy decision.
- `NOT_MEASURABLE_V1`: the accepted property is outside the implemented V1
  measurement boundary.

Live verification is always explicit:

```text
INSTALLED_HARNESS_DISPATCH = NOT_ATTEMPTED
LIVE_MUTATION_DENIAL       = NOT_ATTEMPTED
LIVE_CONTEXT_INJECTION     = NOT_ATTEMPTED
```

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

VAB-1 and VAB-2 closure does not invalidate the remaining V1 limitations below.
Because they are closed while other acceptance requirements remain unsatisfied,
overall `v1_acceptance` remains `BLOCKED`.

`VAB-3` — **reproducible evidence verifier absent; persisted claims cannot reach
VERIFIED** — is `OPEN`.

`VAB-4` — **verified handoff absent; handoff profile is explicitly unverified**
— is `OPEN`.

`VAB-5` — **doctor / validation capability absent** — is `OPEN`.

`VAB-6` — **supported Task and Invariant authoring surface absent** — is `OPEN`.

`VAB-7` — **live harness evidence absent; installed dispatch, injection, and
denial unattempted** — is `OPEN`.

`VAB-8` — **V1 demo acceptance contract undefined** — is `UNRESOLVED`. The item
is within accepted V1 scope, but its exact acceptance contract has not yet been
defined.

VAB-1 through VAB-8 are present acceptance limitations or status, not
implementation work already underway. Nothing in this section is a commitment to
future-phase work, and the demo contract is deliberately not defined here.

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
