# ADR-0024 — VAB-4 Acceptance Ledger Closure Correction

Status: Accepted

## Amends / supersession boundary

This ADR corrects only the stale post-Phase-11 VAB-4 acceptance truth. It
supersedes only ADR-0023's deferred-closure statement that VAB-4 remains
`OPEN` pending independent review, merge acceptance, and later ledger
correction. ADR-0018 and ADR-0023 remain historical records and are not
rewritten. No Phase 11 architecture decisions are superseded.

## Closure evidence

The accepted closure chain is:

- Phase 11 implementation commit: `ca4d0f42c87b06cd701a196775da7a901fa97da5`
- Phase 11 merge commit: `9a87a9cabfdfbc3d4702eefc1024551e4d0a83df`
- PR #17 merged
- `context --profile verified-handoff` implemented
- current Evidence/Claim verdicts derived fresh and remain ephemeral
- `compile_context(...)` remains pure
- verification I/O remains in `load_and_compile(...)`
- persisted `Claim.verification = VERIFIED` remains prohibited
- `SCHEMA_VERSION = 4`
- ordinary SESSION and HANDOFF behavior unchanged
- full suite: 476 tests, 5 skipped
- benchmark: 86 / 86 matched
- independent review: `APPROVE_FOR_HUMAN_ACCEPTANCE`
- finding counts: 0 CRITICAL, 0 MATERIAL, 2 MINOR
- accepted merge completed

The independent-review transcript is not stored in the repository. This ADR
records only the concise accepted review statement and does not reconstruct a
transcript. Both accepted MINOR findings were reviewed against the closure
condition and neither contradicts VAB-4 ledger truth.

## Corrected VAB-4 status

VAB-4 CLOSED

**explicit verified-handoff profile implemented and reviewed; per-record Evidence and Claim verdicts are derived fresh, remain ephemeral, and whole-payload certification is not claimed**

Closure establishes that fresh-session verified-handoff composition is
available but does not expand its claims beyond ADR-0023.

## Remaining acceptance ledger

VAB-1 CLOSED
VAB-2 CLOSED
VAB-3 CLOSED
VAB-4 CLOSED
VAB-5 OPEN
VAB-6 CLOSED
VAB-7 OPEN
VAB-8 UNRESOLVED

`v1_acceptance = BLOCKED`

## Explicit non-goals

This closure performs no:

- product behavior change
- state schema change
- context schema change
- context behavior change
- verifier change
- CLI change
- adapter change
- mutation-engine change
- path-safety change
- hook/live-harness change
- dependency change
- VAB-5 change
- VAB-7 change
- VAB-8 resolution
- V1 acceptance

This ADR is a closure correction, not a Phase 11 architecture recap.
