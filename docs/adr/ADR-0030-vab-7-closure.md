# ADR-0030 — VAB-7 Acceptance Ledger Closure

Status: Accepted

## Amends / supersession boundary

This ADR supersedes only stale or open acceptance-ledger statements concerning
VAB-7 and the associated unattempted live-verification state. Historical ADRs
are not rewritten. ADR-0027's denial-layer semantics, sanitization and retention
requirements, failure classes, uncovered-path boundaries, and known fail-open
limitations remain in force.

## Scope authority

ADR-0029 limits V1 live acceptance to Claude Code. Codex live production
acceptance and cross-harness live parity remain deferred to post-V1 work and do
not block VAB-7 closure.

## Closure evidence

The committed sanitized evidence is:

- `docs/evidence/phase-13/claude-t2-installed-harness-dispatch.json`
- `docs/evidence/phase-13/claude-t2-live-context-injection.json`
- `docs/evidence/phase-13/claude-t3-live-mutation-denial.json`

Those records respectively declare `INSTALLED_HARNESS_DISPATCH`,
`LIVE_CONTEXT_INJECTION`, and `LIVE_MUTATION_DENIAL`, each with verdict
`VERIFIED`.

The T2 records identify Evidline commit
`77a93c21ea8ecd1614c0864a76fde11c4ab61ece`; the T3 record identifies
`bc098a9946ec61dc19c88aee942271d338ba60f8`. Both commits are ancestors of the
Phase 16 closure baseline `4a337f57a2378f8d14ede924dd7da8a316cc3c3f`,
and Git records no `src/evidline` delta from either evidence commit through that
baseline.

The evidence records identify Claude harness versions `2.1.243` for T2 and
`2.1.241 (Claude Code)` for T3. The evidence schema validates their format but
does not cryptographically self-bind `evidline_commit_sha`, `harness_version`,
`captured_at_utc`, or the semantic harness result labels; those fields may be
operator-asserted. The independently recorded installed-package comparison was
newline-normalized and is not a claim of byte identity.

Phase 16 performs no new live execution and does not regenerate evidence.

## Closure decision

**VAB-7 = CLOSED**

**Claude-only live harness evidence accepted; installed SessionStart dispatch, live context injection, and selected-path Write mutation denial verified; Codex live acceptance deferred post-V1**

The benchmark records:

```text
INSTALLED_HARNESS_DISPATCH = VERIFIED_CLAUDE_ONLY
LIVE_CONTEXT_INJECTION = VERIFIED_CLAUDE_ONLY
LIVE_MUTATION_DENIAL = VERIFIED_CLAUDE_ONLY
```

## Remaining acceptance ledger

VAB-1 through VAB-7 are `CLOSED`.

VAB-8 remains `UNRESOLVED` and is the remaining V1 acceptance blocker.

`v1_acceptance = BLOCKED`

## Explicit non-claims

This closure does not establish:

- complete harness enforcement
- Bash, PowerShell, MCP, or hosted-tool coverage
- global fail-closed behavior
- productized hook installation
- Codex live acceptance
- Phase 17 productization
- VAB-8 resolution
- final V1 acceptance
- a V1.0.0 release

Phase 16 does not authorize cleanup of raw or private captures. Existing raw
and private evidence remains governed by ADR-0027's retention and explicit
human-cleanup authorization boundary.
