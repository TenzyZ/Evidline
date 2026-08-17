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

`VAB-1` — **trusted scoped adapter ALLOW implemented; independent review
pending** — is `IMPLEMENTED_PENDING_REVIEW`, not CLOSED. The benchmark proves
that both adapters still submit `PROPOSED`, the core derives authority from a
trusted ACTIVE Task with matching `authorized_scope`, and the existing silent
ALLOW transport is reached. Outside-scope and untrusted-channel scenarios do
not derive authority. This is synthetic in-process proof, not live hook proof or
human acceptance.

`VAB-2` — **automatic unsupported-architecture-mutation blocking unreachable**
— is OPEN. VAB-1 binds targets to Task scope, but no automatic path-scoped
invariant relevance or acknowledgement exists. The benchmark proves only
caller-asserted invariant-conflict blocking.

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
live context injection, automatic architecture conflict detection, live
adapter-level ordinary ALLOW, recovery telemetry, LLM-graded recovery accuracy,
real tokenizer measurement, comprehensive tool coverage, or V1 release
acceptance.
