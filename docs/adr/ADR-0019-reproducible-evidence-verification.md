# ADR-0019 — Reproducible Evidence Verification

Status: Accepted

## Amends

ADR-0003 — Records and Verification; ADR-0004 — Evidence and Freshness;
ADR-0017 — Invariant Scope Binding; and ADR-0018 — V1 Acceptance Ledger
Correction. This decision fixes the V1 reproducible-verification contract
without changing the current acceptance ledger or implementing the verifier.

## Amendment boundary

ADR-0019 supersedes only the exact displaced clauses listed below. Every
unrelated accepted decision in ADR-0003, ADR-0004, ADR-0017, and ADR-0018
remains in force, and the historical ADR files are not rewritten.

- ADR-0003 — the persisted-`VERIFIED` reservation sentence
  "Persisted `VERIFIED` is reserved for reproducible verification performed by
  Evidline" is displaced only insofar as it could be read as making persisted
  `VERIFIED` legal once a reproducible verifier exists. Persisted
  `Claim.verification = VERIFIED` remains prohibited even after the verifier
  exists.

- ADR-0004 — the persisted-`VERIFIED` prerequisite sentence
  "Persisted `VERIFIED` requires reproducible verification" is displaced only
  insofar as it could be read as making persisted `VERIFIED` legal once a
  reproducible verifier exists. Persisted `Claim.verification = VERIFIED`
  remains prohibited even after the verifier exists.

- ADR-0017 — only the prior version-support sentence "Schema versions 2 and 4
  are unsupported" is superseded insofar as it declared schema version 4
  unsupported. ADR-0019 makes schema version 4 the supported persisted format
  after Phase 9 implementation; prior schema versions remain unsupported
  unless a separately authorized migration policy is accepted; and no
  automatic/silent migration is introduced. No other clause of ADR-0017 is
  superseded, including its scope-semantics fail-closed boundary.

- ADR-0018 — only the VAB-3 closure implication, the implication that
  persisted `VERIFIED` must become reachable for VAB-3 closure. The resolved
  condition is: the reproducible verifier exists; the verdict is ephemeral;
  and persisted `VERIFIED` remains intentionally prohibited. VAB-3 remains
  OPEN and the ledger is not changed now.

## Context

`Evidence` currently permits a SHA-256 digest but persists no source binding,
so Evidline has no deterministic source to re-read and hash independently.
Persisting a verification verdict would also make current truth stale as soon
as the source bytes changed. V1 therefore needs a durable reproducible binding
and an ephemeral verifier result while preserving the distinction between
stored state and freshly derived evidence.

## Persisted source binding

The future implementation adds `Evidence.source_path: str | None`. A source
path is project-root-relative and uses the same persisted normalization
discipline as existing root-relative scope paths. It permits no absolute path,
parent traversal, glob syntax, NUL or control character, and remains subject to
the existing Windows-safe grammar.

A non-empty evidence source path is path-bearing persisted state. A mismatch
between its recorded path semantics and the current host's path semantics must
fail closed rather than reinterpret the path.

This persisted-shape change requires `SCHEMA_VERSION = 4`. Schema version 3 is
not silently migrated. This ADR does not perform the version change or add the
field.

For schema version 4, `source_path` and `digest` form one reproducible binding:
both are present or both are absent. A digest without a source path and a source
path without a digest are not reproducible bindings. No digest-algorithm
negotiation is introduced.

The future schema-v4 reader support posture is explicit. After Phase 9
implementation, schema version 4 is the supported version; schema versions 1,
2, and 3 are unsupported; later or unknown schema versions are rejected; and no
migration or compatibility shim is implied.

## Ephemeral verification

The future verifier computes the current verdict fresh and does not persist
verification results. Persisted state stores `source_path + digest`, not current
truth. Verification verdicts are ephemeral.

The existing unconditional rejection of persisted
`Claim.verification = VERIFIED` remains in force and must not be relaxed or
deleted. Persisted `VERIFIED` does not become legal as part of reproducible
verification. The existence or successful execution of the reproducible
verifier does NOT make persisted `Claim.verification = VERIFIED` legal. The
verifier verdict remains ephemeral. Persisted state stores the reproducible
source/digest binding, not the current verdict.

Fresh Phase 9 ephemeral derivation uses only the current `claim.evidence_ids`
set: every referenced evidence id participates. The persisted fields
`Claim.verifier_rule`, `Claim.verified_at`, and
`Claim.verifying_evidence_ids` are historical persisted verification
provenance and are not trusted as current verifier input:
`claim.verifier_rule` does not gate the fresh verdict, and
`claim.verifying_evidence_ids` does not narrow the fresh verification set.

Persisted `Verification.FAILED` with its currently legal verification
provenance remains valid and unchanged. The new verifier does not write
persisted `FAILED`, does not consume persisted `FAILED` provenance as current
verification truth, and performs no state write. The existing validator
behavior for `FAILED` is neither tightened nor rewritten.

## R1 digest contract

`R1_DIGEST_MATCH` remains the verifier rule and SHA-256 remains the only
algorithm. The persisted digest format remains `sha256:` followed by exactly 64
lowercase hexadecimal characters; the existing digest grammar is unchanged.

The exact verification subject is the complete raw byte sequence of the file
named by `Evidence.source_path`. The file is opened and read in binary mode so
the exact raw bytes are the verification subject. Verification performs no
text decoding, newline normalization, JSON canonicalization, whitespace
normalization, or semantic parsing. Binary files and empty files are valid
subjects.

## Path safety and residual boundary

The future verifier reuses Evidline's existing path-safety primitives and does
not create a second path-safety system. It resolves the evidence source through
the existing canonical project-root containment logic before opening bytes.

Unsafe conditions never yield `VERIFIED`. This includes traversal, an absolute
or out-of-root source, symlink or junction escape, protected `.git/**` or
`.evidline/**`, and unsafe Windows path forms.

The existing filesystem boundary remains explicit: canonical evaluation does
not eliminate post-check replacement races, and Evidline claims neither TOCTOU
nor hardlink protection. This decision does not claim stronger filesystem
atomicity than the existing architecture provides.

`Evidence.source_path` inherits the existing persisted `CASE_FOLDED` /
`CASE_SENSITIVE` scope-semantics discipline, which may case-fold persisted
source paths. Evidline does not detect or claim the actual filesystem's case
sensitivity. On a case-divergent filesystem, that inherited normalization can
cause an otherwise valid source lookup to become `UNVERIFIED` or, if another
regular file resolves, `FAILED`. This condition must never produce `VERIFIED`
without matching bytes. No new case-preserving source-path subsystem is
authorized, and the document-level scope-semantics fail-closed boundary is
unchanged.

## Result semantics

No new verification lifecycle state is introduced. The future verifier uses
the existing vocabulary and returns a machine-readable reason:

- `VERIFIED`: current source bytes reproduce the recorded digest.
- `FAILED`: current source bytes were successfully read but contradict the
  recorded binding because their digest does not match.
- `UNVERIFIED`: verification cannot be completed, including when the source is
  missing, unsafe, unreadable, a directory or non-regular file; the binding is
  absent; the digest is malformed at the defensive verifier boundary; or a
  verifier or internal read error occurs.

Inability to verify is not collapsed into `FAILED`. Neither `FAILED` nor
`UNVERIFIED` may become `VERIFIED` through fallback.

## Claim derivation

A reproducible claim derives ephemeral `VERIFIED` only when
`claim.reproducible is True`, `claim.evidence_ids` is non-empty, every referenced
evidence record resolves, and every referenced evidence binding independently
verifies.

If any referenced evidence is `FAILED`, the claim result is `FAILED`. If none
fails but at least one reference or binding is unverifiable, the claim result is
`UNVERIFIED`.

This derivation does not semantically prove the natural-language claim prose. It
proves only that every referenced byte binding reproduced.

## ClaimFreshness interaction

`ClaimFreshness` does NOT gate whether the Phase 9 verifier can compute an
ephemeral byte-binding verdict. Fresh verification answers only whether the
current named evidence bytes reproduce the persisted bindings. ADR-0004's
persisted-volatile stale/revalidate behavior remains a context/rendering/
freshness rule and is not overridden by an ephemeral digest result. Therefore:

- a `PERSISTED_VOLATILE` claim may receive a fresh ephemeral byte-binding
  verification result;
- that does NOT make its persisted freshness durable;
- existing stale/revalidate rendering behavior remains authoritative where
  applicable;
- the verifier must not rewrite freshness state.

No context behavior is modified in this phase.

## VAB-3 ledger clause

ADR-0018 currently records VAB-3 approximately as "reproducible evidence
verifier absent; persisted claims cannot reach VERIFIED". The second clause
remains true by design after the verifier exists. ADR-0019 supersedes only the
implication that persisted `VERIFIED` must become reachable for VAB-3 closure.
The later ledger correction should describe the resolved condition truthfully:
reproducible verifier exists; verdict is ephemeral; persisted `VERIFIED`
remains intentionally prohibited. ADR-0018 is not changed now, and VAB-3 is not
marked `CLOSED` now.

## VAB-3 closure criterion

VAB-3 is closed by establishing an Evidline-controlled reproducible verifier,
not by making persisted `VERIFIED` legal. Durable state stores reproducible
bindings, and current verification is re-derived ephemerally. This is the
intended meaning of V1 reproducible verification.

This ADR does not mark VAB-3 `CLOSED`. Closure still requires implementation,
tests and benchmark evidence, independent review, accepted merge, and a later
acceptance-ledger correction under the current workflow.

## Future validator message

The current validator rejects persisted `VERIFIED` with approximately
"VERIFIED cannot be persisted until Evidline performs reproducible
verification". Once Phase 9 exists, the word `until` becomes misleading. Phase
9 implementation is expected to reword that diagnostic to an unconditional
persisted-`VERIFIED` prohibition while preserving the rejection behavior
exactly. This authorizes a diagnostic-message correction only in the later
implementation; it does NOT authorize relaxing the check.

## Explicit non-goals

The Phase 9 verifier is an explicit library capability only. No invocation
surface is authorized by this ADR:

- no new CLI commands;
- no changed CLI commands;
- no `evidline verify` command;
- no mutation decision engine integration;
- no mutation evidence-gate wiring;
- no ADR-0006/ADR-0011 evidence-gate integration;
- no automatic invocation from context compilation;
- no automatic invocation from state validation/loading;
- no automatic invocation from adapters/hooks.

The verifier is not wired into mutation decisions.

This decision neither implements nor authorizes Verified Handoff; Doctor; Task
creation; Invariant creation; a Claim or Evidence authoring CLI; a general state
editor; governed-scope authoring; Claude adapter changes; Codex adapter changes;
hooks; live enforcement; live context injection; demo design; new digest
algorithms; new verifier rules; persisted `VERIFIED`; migration from schema
version 3; or dependency additions.

## Consequences

Evidline can later reproduce a recorded byte binding without silently promoting
persisted state to current truth. Schema version 3 remains unsupported by the
future version-4 reader unless a separately authorized migration policy is
adopted, and filesystem race and hardlink limitations remain explicit.
