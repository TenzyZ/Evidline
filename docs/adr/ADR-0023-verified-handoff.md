# ADR-0023 — Verified Handoff

Status: Accepted

## Amends / supersession boundary

This ADR amends ADR-0005, ADR-0012, and ADR-0019 only where those records defer
verified handoff or prohibit context invocation of the verifier. Their unrelated
decisions remain in force and the historical ADR files are not rewritten.

ADR-0005's handoff-as-context-profile architecture is extended with a second
profile, `verified-handoff`. ADR-0012's deferral of verified handoff is
superseded only for this profile; no separate `handoff` or `verify` command is
introduced. ADR-0019's prohibition on automatic context invocation is
superseded only for the `load_and_compile` wrapper when this profile is
explicitly requested. Ordinary `session` and `handoff` behavior remains
unchanged.

## Context

Fresh sessions need a bounded continuity representation that distinguishes
current byte-binding results from persisted provenance. The existing HANDOFF
selection architecture and Phase 9 ephemeral verifier already own those two
concerns. A new persisted Handoff entity or second state store would duplicate
ownership and risk promoting historical verification metadata into current
truth.

## Decision

Verified handoff remains a context profile, not a persisted Handoff record. The
public workflow is:

`evidline context --profile verified-handoff`

`load_and_compile` loads current validated state and invokes document-level
fresh verification only for this profile. It passes the resulting explicit
ephemeral map into `compile_context`. The compiler remains pure: it performs no
filesystem, network, clock, subprocess, environment, or persistence operation.
Supplying verification metadata to `session` or ordinary `handoff` is rejected.

The document-level verifier derives one current result for every Evidence and
Claim in persisted order. It reuses the existing Evidence and Claim verifier
contracts and raw-byte SHA-256 R1 subject. Tasks, Decisions, and Invariants do
not receive fabricated byte-verification results.

If persisted scope semantics differ from current host semantics, the document
sweep fails closed before any Evidence source read. Every Claim and Evidence
result is `UNVERIFIED / SCOPE_SEMANTICS_INCOMPATIBLE`; no fallback verification
is attempted.

Current verdicts and reasons exist only in the in-memory context result. They
are never serialized into `.evidline/state.json`. Absence of a verifier result
for non-verifiable records is represented by absent/null context metadata, not
by a new `VerificationReason`. `VerificationReason` continues to describe
actual verifier outcomes.

`VERIFIED` removes the context-only `DIGEST_NOT_RECHECKED` reason and adds
`VERIFIED_NOW` when the current binding reproduces. Independent freshness rules
remain authoritative: `PERSISTED_VOLATILE` stays `REVALIDATE`, and a persisted
historical `FAILED` Claim is not silently rewritten. `FAILED` forces the
verifiable record to `REVALIDATE`; `UNVERIFIED` is never promoted. Partial
verification degrades per record and does not abort the complete handoff.

The payload states that verification is current and per verifiable record, not
a global certification. Durable Tasks, Decisions, and Invariants remain useful
continuity/state records and are not presented as byte-verified. Machine output
adds explicit nullable current-verification fields and advances only the
context output schema to version 2.

## Preserved boundaries

- persisted state schema remains version 4;
- persisted `Claim.verification = VERIFIED` remains prohibited;
- `Verification.STALE` remains computed rather than persisted current truth;
- historical verification provenance is not current truth;
- verification verdicts remain ephemeral and verification performs no state
  write;
- raw-byte SHA-256 and the accepted TOCTOU/hardlink residual remain unchanged;
- ordinary SESSION and HANDOFF payload behavior remains unchanged;
- no dependency is added;
- no new handoff command or `evidline verify` command is added;
- no mutation-engine, status, adapter, hook, or live-harness integration is
  added;
- no VAB-5, VAB-7, or VAB-8 work is performed.

## Acceptance ledger boundary

VAB-4 remains `OPEN`. This phase implements the engineering capability but does
not perform independent acceptance review, merge acceptance, or the later
ledger-closure correction.

`v1_acceptance = BLOCKED`.

## Consequences

An explicit verified-handoff invocation can preserve useful continuity while
showing current `VERIFIED`, `FAILED`, and `UNVERIFIED` results exactly where byte
verification applies. The representation does not claim semantic proof of
record prose, whole-payload certification, stronger filesystem race protection,
or persisted current truth.
