# ADR-0015 — Cross-Harness Benchmark (V1 Phase 7)

Status: Accepted

## Context

The implemented state, path, mutation, context, Claude transport, and Codex
transport boundaries need one deterministic benchmark without expanding those
boundaries or implying live enforcement. The accepted V1 criterion also needs a
verdict independent from whether the benchmark itself executed correctly.

## Decision

Phase 7 adds a standard-library-only synthetic benchmark outside the installed
`evidline` package. It performs direct in-process core calls and invokes the
existing Claude and Codex adapter `main()` functions with patched standard I/O.
It performs no installed hook dispatch, configuration, trust, activation, live
mutation, live context injection, network access, subprocess call, dependency
change, product schema change, public API change, CLI change, or package entry
point change.

The benchmark produces independent verdicts:

- `benchmark_execution`: `COMPLETED`, `MISMATCHED`, `NONDETERMINISTIC`, or
  `FAILED`;
- `v1_acceptance`: `BLOCKED` for Phase 7.

A successful Phase 7 run is therefore `benchmark_execution = COMPLETED` and
`v1_acceptance = BLOCKED`.

## Acceptance blockers

`VAB-1` remains OPEN: adapter-path normal-edit ALLOW is unreachable. Both
adapters correctly submit `PROPOSED`; the core therefore returns at least ASK.
Claude transports ASK as `ask`, while Codex transports ASK as `deny`.

`VAB-2` remains OPEN: automatic unsupported-architecture-mutation blocking is
unreachable. The adapters supply no target-bound declared scope or asserted
invariant conflict. The core can test supplied scope and asserted conflicts, but
that is not automatic architecture enforcement.

Phase 7 resolves neither blocker.

## Result architecture

The result has three top-level regions. `contract` contains only human-authorable
semantic values and participates in the frozen comparison. `observations`
contains deterministic measurements and diagnostics and does not participate in
that comparison. `benchmark_execution` is assigned only after determinism and
expected-contract comparison.

The expected document contains only its local benchmark `schema_version` and
`contract`. It is unrelated to every Evidline product schema version.

## Containment and oracles

Containment has two levels. Every scenario path remains inside one disposable
temporary sandbox, while each scenario declares `IN_ROOT`,
`OUT_OF_ROOT_IN_SANDBOX`, or `NO_ROOT`. A sandbox escape fails the run; a root
declaration mismatch is a scenario mismatch.

The primary oracle is the literal scenario table in `benchmarks/scenarios.py`.
The secondary oracle is `benchmarks/expected/results.json`. The runner and tests
have no update, bless, regenerate, or write-expected mode. Intentional oracle
changes require human review of both the scenario contract and expected diff.

## Determinism

The runner builds two full observations against independently created fixtures
and compares canonical serializations before reading the expected document. It
uses fixed state data and records no clock, duration, randomness, network,
hostname, PID, or temporary path. Exit codes are benchmark-local: 0 completed,
1 mismatched, 2 nondeterministic, and 3 failed.

## Consequences

Phase 7 proves synthetic core policy behavior, context compilation behavior,
adapter output mapping, expected cross-harness parity, and the expected Claude
ASK versus Codex ASK-to-deny asymmetry. It records uncovered tools explicitly.

It does not prove installed dispatch, live denial before mutation, live context
injection, automatic architecture conflict detection, production adapter ALLOW,
LLM-graded recovery, live telemetry, real tokenizer counts, or V1 acceptance.
