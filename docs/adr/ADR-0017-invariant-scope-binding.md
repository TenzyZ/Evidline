# ADR-0017 — Invariant Scope Binding

Status: Accepted

## Amends

ADR-0011 — Mutation Decision Engine; ADR-0015 — Cross-Harness Benchmark; and
ADR-0016 — Scoped Authority Binding.

## Context

ADR-0016 binds a trusted ACTIVE Task to normalized filesystem scope, but it
deliberately leaves invariant relevance and acknowledgement unresolved. Its
cross-platform residual also permits a Windows-normalized scope to be read on a
case-sensitive host without proving that the persisted path retains its intended
meaning. VAB-2 must close that ambiguity before target-scoped invariant policy is
evaluated.

## Decision

Persisted state schema version 3 adds:

- `Invariant.governed_scope`, an ordered tuple using the existing validated
  root-relative scope language;
- `Task.acknowledged_invariant_ids`, an ordered tuple of IDs that must resolve
  only to existing `Invariant` records; and
- `StateDocument.scope_semantics`, a mandatory serialized normalization marker.

Schema versions 2 and 4 are unsupported. There is no migration, automatic
upgrade, compatibility shim, or implicit default while parsing JSON.

`governed_scope == ()` means no automatic VAB-2 target binding. It is not
repository-global. `authorized_scope == ()` keeps its ADR-0016 meaning: no
derived VAB-1 authority. `.` remains the sole explicit whole-repository scope.
Both fields share the existing grammar, normalization, duplicate rejection, and
component-aware matching rules. No glob, regular expression, or second path
language is introduced.

## Scope semantics and portability

`scope_semantics` has exactly two values:

- `CASE_FOLDED`: the existing Windows normalization flavour, including Windows
  separator, reserved-name, device-name, and `ntpath.normcase` behavior;
- `CASE_SENSITIVE`: the existing non-Windows normalization flavour.

These values record Evidline's normalization discipline derived from `os.name`.
They do not detect or claim the actual filesystem's case sensitivity. Host
selection is pure and performs no filesystem, network, clock, or subprocess
operation. A flavour-explicit normalization seam exists for deterministic tests;
the existing host wrapper remains behavior-compatible.

State validation checks the typed marker and compatibility before applying host
normalization to any persisted scope. A semantics mismatch plus any non-empty
`Task.authorized_scope` or `Invariant.governed_scope` raises
`IncompatibleScopeSemanticsError`. Therefore a foreign scoped state cannot reach
matching and cannot degrade into a no-match ALLOW. A mismatched document is
portable only when every path-scope tuple is empty, because no persisted path is
then reinterpreted.

Initialization stamps the host semantics. Ordinary serialization and persistence
preserve the proposed marker and never silently re-stamp it. An incompatible
non-empty foreign document is rejected before replacement. The interactive
`approve` ceremony may explicitly change an empty foreign marker while authoring
new native scopes; it displays the transition and requires exact Task-ID
confirmation. It cannot relabel existing non-empty foreign scopes.

This explicitly amends ADR-0016's cross-platform residual: incompatible scoped
state now rejects as a whole instead of allowing platform-dependent parse or
match behavior.

## Acknowledgement provenance

Acknowledgements preserve order, reject duplicates, and must resolve to
`Invariant` records. References to Tasks, Decisions, Claims, Evidence, or absent
IDs are invalid. Acknowledging an ACTIVE BLOCK invariant is operative.
Acknowledging ACTIVE ADVISE or SUPERSEDED state is valid but inert.

Only the existing ADR-0016 trusted ACTIVE Task provenance supplies operative
acknowledgements: ACTIVE status, AUTHORIZED intent, approval timestamp, the fixed
interactive CLI approval channel, and the fixed asserted actor. This shared
predicate does not require non-empty `authorized_scope` or a safe path; those are
separate authority-derivation conditions. Refactoring VAB-1 to use this predicate
does not broaden VAB-1 target authority.

`evidline approve TASK_ID --scope PATH [--acknowledge INVARIANT_ID ...]` is the
only product ceremony added here. It validates IDs and the complete proposed
state before prompting, shows normalized scope and each acknowledgement's
enforcement/status, marks ADVISE and SUPERSEDED entries inert, preserves argument
order, and uses the existing optimistic single-revision write. TTY interactivity
and fixed labels remain defense-in-depth, not authentication.

`Task.related_ids` remains a context/relevance relation and never implies
acknowledgement.

## Mutation policy

Mutation result schema version 2 adds `INVARIANT_UNACKNOWLEDGED` and the separate
`unacknowledged_invariant_ids` result field. After caller-asserted invariant
conflicts are processed, a safe canonical target is structurally relevant to an
invariant only when the invariant is ACTIVE, has non-empty `governed_scope`, and
the target lies within that scope under the existing canonical matcher.

Every relevant ACTIVE BLOCK invariant absent from the trusted ACTIVE Task's
acknowledgement set produces a deterministic BLOCK and is reported in sorted,
deduplicated order. The gate is risk-independent. ACTIVE ADVISE remains advisory;
SUPERSEDED is non-operative. `applicable_invariant_ids` retains its state-wide
ACTIVE+BLOCK meaning and is not target-scoped.

Acknowledgement records awareness, not satisfaction. It does not suppress
`INVARIANT_CONFLICT`, `INVARIANT_UNRESOLVED`, denied intent, unsafe or protected
targets, CRITICAL risk, declared-scope narrowing, evidence/freshness gates, or
any stronger result. Authorization and acknowledgement are independent: VAB-1
may still report `authorizing_task_id` while VAB-2 blocks the target.
Acknowledgement is also not invariant supersession.

The next-step priority places `INVARIANT_UNACKNOWLEDGED` after
`INVARIANT_UNRESOLVED` and before `SCOPE_VIOLATION`. Outcome severity remains
monotonic.

## Adapter and benchmark boundary

Claude and Codex adapters remain thin and unchanged. They do not inspect governed
scope or acknowledgements, classify invariant prose, manufacture acknowledgement,
change request intent, or treat harness permission as Evidline authority. Their
existing decision translation transports the new core BLOCK.

The synthetic benchmark adds structural core, Claude, Codex, and parity scenarios
for governed matches, acknowledgements, inert cases, multiple invariants,
untrusted provenance, asserted-conflict independence, malformed scope, and
incompatible semantics. Shared fixture invariants remain ungoverned by default so
unrelated context results do not change.

This is synthetic in-process proof. It does not prove installed hook dispatch,
live denial, live context injection, or complete channel coverage. VAB-2 is
`IMPLEMENTED_PENDING_REVIEW`; V1 acceptance remains a separate blocked decision.

## Residual limitations and non-goals

VAB-2 performs no semantic interpretation of invariant descriptions, diff-content
understanding, or architecture-violation inference from prose. Relevance is only
canonical target containment in declared governed scope. Trusted channel and actor
labels are not authentication. There is no TTL, clock-based grant, token,
credential, signing, telemetry, LLM, embedding, vector database, knowledge graph,
cloud state, hook activation, or expansion to uncovered shell/MCP channels.

## Consequences

A covered mutation inside an ACTIVE BLOCK invariant's governed filesystem scope
cannot reach ALLOW unless the trusted ACTIVE Task explicitly acknowledges that
invariant and no independent gate prevents ALLOW. Foreign non-empty scoped state
fails before matching, while empty-scope state remains portable. The mutation core
remains deterministic, adapter-neutral, and free of I/O.
