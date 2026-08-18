# ADR-0025 — Doctor / Diagnostic Validation

Status: Accepted

## Decision

`evidline doctor [--root PATH] [--format {text,json}]` is the supported,
read-only local diagnostic surface. It answers whether local Evidline state is
healthy and usable; it grants no permission or authorization and performs no
repair, migration, execution, verification, or enforcement.

This narrowly supersedes ADR-0012's `doctor` deferral and extends its CLI
contract only for Doctor: its historical decisions remain unchanged. Existing
commands retain exits `0/2/3/4/5/6/7/10/11`; Doctor adds `20` for a completed
`UNHEALTHY` report. Expected broken state is rendered as diagnostics rather
than ordinary state-error exits. Unexpected Doctor failure remains exit `7`.
`DEGRADED` exits `0` because the project remains usable.

## Diagnostic contract

Doctor output schema is `DOCTOR_SCHEMA_VERSION = 1`. Text and sorted-key JSON
are deterministic, contain no generic details field, and expose exactly nine
ordered checks: runtime support; root discovery; state presence; readability;
JSON validity; schema support; scope-semantics compatibility; structure; and
context default-budget readiness.

D003–D008 derive from exactly one `load_state()` operation. Exception types,
not exception strings, select the failed layer. A residual
`StateValidationError` makes D008 fail, D006 `SKIP/NOT_REACHED` because schema
support may not have been established, D007 `SKIP/NOT_REACHED` because scope
compatibility may not have been established, and D009 not reached. Doctor must
never report an unestablished prerequisite as PASS. Checks use only `PASS/WARN/FAIL/SKIP` and
the frozen `DoctorReason` codes. Any FAIL is `UNHEALTHY`; otherwise any WARN is
`DEGRADED`; otherwise the report is `HEALTHY`. An uninitialized root still
returns all nine checks and exit 20.

Doctor does not import status, the verifier, mutation policy, or adapters. It
does not report status counts or inspect live harness behavior. It adds no
dependency or persisted-state schema change, and does not invoke `verify_state`.

## Acceptance boundary

Benchmark coverage proves deterministic rendering, expected broken-state
decomposition, optional absence, and no state write. VAB-7 live harness
surfaces remain unattempted. `VAB-5 remains OPEN` and `v1_acceptance remains
BLOCKED`: implementation is not acceptance-ledger closure.
