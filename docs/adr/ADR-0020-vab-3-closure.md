# ADR-0020 — VAB-3 Acceptance Ledger Closure Correction

Status: Accepted

## Amends / supersession boundary

This ADR corrects only the stale VAB-3 acceptance status after ADR-0019's
deferred closure criterion is satisfied. ADR-0018 and ADR-0019 remain
historical records and are not rewritten. No unrelated clause of either record
is superseded.

## Closure evidence

The established closure chain is:

- Phase 9B implementation commit: `7c24ae3e2b98447ff49c0b8554bbf8148e3bf0cd`
- Phase 9B merge commit: `8ef30766f8f36913ecab332e0acaf86fc53c740c`
- reproducible verifier implemented
- schema v4 + source/digest binding implemented
- tests passed
- benchmark: 71 / 71 matched
- independent review: approved for human acceptance; 0 CRITICAL; 0 MATERIAL
- accepted merge completed

A concise statement that independent review approved the merged Phase 9B work
is recorded here; no review transcript is invented or persisted.

## Corrected VAB-3 status

VAB-3 CLOSED

Evidline-controlled reproducible evidence verification exists; verdicts are
derived ephemerally; persisted `Claim.verification = VERIFIED` remains
intentionally prohibited.

## Remaining acceptance ledger

VAB-1 CLOSED
VAB-2 CLOSED
VAB-3 CLOSED
VAB-4 OPEN
VAB-5 OPEN
VAB-6 OPEN
VAB-7 OPEN
VAB-8 UNRESOLVED

`v1_acceptance = BLOCKED`

## Explicit non-goals

This ADR performs no:

- product behavior change
- schema change
- CLI change
- adapter change
- verifier change
- hook change
- dependency change
- live enforcement
- VAB-4/5/6/7 change
- VAB-8 resolution
- V1 acceptance

This ADR is not a Phase 9B architecture recap.