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
- `SYNTHETIC_ONLY_UNREACHABLE_IN_PRODUCTION`: an injected ALLOW decision tests
  output mapping only; no current covered adapter path reaches ALLOW.
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

`VAB-1` — **adapter-path normal-edit ALLOW unreachable** — is OPEN. Existing
adapters correctly submit `PROPOSED`, so a safe covered edit reaches Evidline
ASK. Claude transports it as `ask`; Codex cannot represent that ASK and
transports it as `deny`. This expected asymmetry is not a divergence.
No passing adapter false-block rate is claimed while ordinary adapter ALLOW is
structurally unreachable.

`VAB-2` — **automatic unsupported-architecture-mutation blocking unreachable**
— is OPEN. Adapters do not bind targets to human-authorized scope or asserted
invariant conflicts. The benchmark proves only asserted-conflict blocking and
scope enforcement when those inputs are directly supplied to the core.

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
live context injection, automatic architecture conflict detection, adapter-level
ordinary ALLOW, recovery telemetry, LLM-graded recovery accuracy, real tokenizer
measurement, comprehensive tool coverage, or V1 release acceptance.
