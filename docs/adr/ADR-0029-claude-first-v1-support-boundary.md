# ADR-0029 — Claude-First V1 Support Boundary

Status: Accepted

## Amends / supersession boundary

This ADR changes only the V1 harness-support and live-acceptance clauses
identified below. ADR-0008 and ADR-0027 remain historical records and are not
rewritten. Every unrelated accepted decision in those ADRs remains in force.

In ADR-0008, only the sentence-level clause `Codex targets apply_patch and
Bash` is superseded insofar as it represents Codex as a V1-supported adapter
target. The Codex implementation remains in-tree, but is experimental,
deferred, and unsupported for V1 production. ADR-0008's Claude tool coverage,
ASK semantics, fail-open disclosure, and all other decisions remain unchanged.

In ADR-0027, only these harness-scope clauses are superseded:

- `VAB_7_HARNESS_DECISION = CLAUDE_AND_CODEX` becomes Claude-only for current
  V1 product acceptance.
- The required live claims apply to Claude Code only, not both proving
  harnesses.
- The clean committed-baseline requirement and V1 live-acceptance status apply
  to Claude only.
- The Codex SessionStart, PreToolUse, and `apply_patch` proving paths are
  deferred to post-V1 work and do not block V1 acceptance.
- The Phase 13 deterministic context-payload amendment's Codex-shaped JSON
  envelope comparison is replaced for Claude acceptance by the plain-stdout
  byte comparison defined below.

ADR-0027's denial layers, deterministic BLOCK, privacy and sanitization rules,
evidence retention, failure classifications, uncovered paths, known fail-open
boundaries, disposable-environment rules, and separation of execution from
verification remain unchanged.

## Decision

Evidline V1.0 production support is limited to Claude Code. Codex adapter code
and tests remain retained, but Codex production support and cross-harness live
parity are experimental, deferred to post-V1 work, and are not V1 acceptance
requirements. A Codex live campaign is not required to close V1 acceptance.

This boundary does not state that the Codex implementation is removed, broken,
invalid, or abandoned. ADR-0014's Codex adapter architecture, ADR-0015's
synthetic cross-harness benchmark architecture, and ADR-0028's deterministic
UTF-8 machine transport remain accepted. Codex tests, Codex synthetic benchmark
scenarios, and `cross.*` synthetic benchmark scenarios remain measured; they
are not V1 live-acceptance gates.

## Claude SessionStart acceptance transport

The current Claude adapter emits the rendered SessionStart context as plain
UTF-8 stdout. Current Anthropic Claude Code hook documentation states that
SessionStart plain stdout is added directly to Claude's context and supports
`hookSpecificOutput.additionalContext` as an alternative form. V1 keeps the
implemented plain-stdout transport and does not introduce a JSON envelope for
symmetry with Codex.

The Claude-specific P7 relation is exact byte equality:

```text
adapter_stdout_bytes == direct_payload_bytes
```

No Unicode normalization, newline normalization, whitespace trimming, or case
folding is permitted.

The Claude SessionStart transport proven by the remaining live acceptance must
remain unchanged through VAB-7 closure and V1 productization. Any later
behavior-changing SessionStart transport modification invalidates the
corresponding live evidence and requires separately authorized revalidation
against the changed committed runtime. Phase 14 neither implements nor executes
that revalidation.

## Anthropic output limit

Current Anthropic documentation caps context-bearing hook output, including
plain stdout and `additionalContext`, at **10,000 characters**. Characters are
not UTF-8 bytes. The existing `context_payload_length` evidence field measures
UTF-8 bytes and therefore does not express or enforce this vendor constraint.
No independently verified decoded-character-count field exists in the current
Phase 13 evidence contract. Exact deterministic enforcement and verification
of the 10,000-character limit is deferred to separately bounded Phase 15
planning; this ADR adds no evidence field or gate.

## Historical Phase 13 tooling

`tools/phase13/contract.py` intentionally retains
`VAB_7_HARNESS_DECISION = "CLAUDE_AND_CODEX"`, and its existing test remains
unchanged. That constant records the superseded Phase 13 campaign contract; it
is historical developer-tooling state, not the authoritative current V1
support boundary after this ADR. No shadow constant is introduced.

## Claude T3 evidence classes

The sanitized committed T3 record represents the already-verified Claude
`LIVE_MUTATION_DENIAL` claim. It is not a new live proof, a replacement for raw
captures, or a VAB-7 closure decision.

```text
T3_CARRY_FORWARD = PRESERVED
T3_RERUN_AUTHORIZED = NO
```

Capture-bound facts are limited to values independently derivable from retained
captures and the private correlation record: the Claude PreToolUse `Write`
identity digests, adapter exit 0, structured `deny`, captured core `BLOCK` and
`INVARIANT_UNACKNOWLEDGED` reason, raw-capture digests, positive-control session
and tool-use digests, and the captured positive-control `Write` attempt. Probe
captures independently establish that the governed target was absent before
and after and that the positive-control target changed from absent to a
seven-byte file with the frozen `PHASE13` digest.

Fields validated only for format or supplied by the operator remain
operator-asserted. In particular, `evidline_commit_sha`, `harness_version`,
`captured_at_utc`, and the semantic labels translating retained observations
into `harness_tool_result`, `harness_blocking_result`, and `live_status` are not
cryptographically self-bound by the raw T3 capture merely because the evidence
schema accepts them.

A separate read-only comparison established that the installed T3 package and
committed `src/evidline` each contain 14 Python files, with no file present on
only one side, and that all 14 are equivalent after CRLF-to-LF normalization.
This is out-of-band independent corroboration, not a fact encoded in the raw T3
capture. Newline-normalized equivalence is not byte-exact equivalence.
Chronology alone—such as a commit existing before a campaign—does not prove
runtime identity.

Raw T3 evidence remains outside Git and must be retained under ADR-0027's
review and cleanup boundary.

## Consequences

V1 live acceptance proceeds Claude-first and Claude-only. Codex implementation,
tests, documentation, and synthetic measurements remain available for future
post-V1 production-support work. This ADR changes records, documentation, and
evidence only; it changes no product runtime, tests, benchmark contract, or
Phase 13 tooling.
