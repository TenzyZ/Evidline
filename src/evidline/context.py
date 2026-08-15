"""Deterministic V1 context compiler: bounded, explainable context selection.

The compiler answers: "What is the smallest high-signal context packet required
for this task?" It is pure and deterministic.  The pure core performs no
filesystem I/O, no network calls, no subprocess execution, reads no environment
variable, accesses no clock, uses no randomness, and persists nothing.  All I/O
lives in the thin :func:`load_and_compile` wrapper.  The compiler performs no
verification: persisted claims are never promoted to ``VERIFIED``, and
``EXECUTED`` never means ``VERIFIED``.

Selection is band-based and anchored on the unique ``ACTIVE`` task.  Budget is
charged in rendered payload characters; every record is atomic.  The
agent-facing payload, the human/audit report, and the machine-readable JSON are
three strictly separated views of one immutable result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import math
import os
import re
from types import MappingProxyType
from typing import Any, Final, Mapping

from evidline import paths as _paths
from evidline import state as _state

CONTEXT_SCHEMA_VERSION: Final = 1

_TOKEN_PATTERN = re.compile(r"\w+", re.UNICODE)
_WHITESPACE_RE = re.compile(r"\s+")
_MIN_TOKEN_LENGTH: Final = 3

# One fixed module-level stopword set.  Membership checks use the casefolded
# token form only.
_STOPWORDS: Final = frozenset(
    {
        "and", "are", "but", "for", "has", "how", "not", "our", "out",
        "the", "their", "then", "them", "these", "they", "this", "was",
        "what", "when", "where", "which", "who", "why", "will", "with",
        "your",
    }
)

_HANDOFF_DISCLAIMER: Final = (
    "NOTE: this is an unverified continuity representation, "
    "not a verified handoff."
)


class ContextProfile(str, Enum):
    """Output profile. ``session`` is the default agent-facing profile."""

    SESSION = "session"
    HANDOFF = "handoff"


class Disposition(str, Enum):
    INCLUDED = "INCLUDED"
    REVALIDATE = "REVALIDATE"
    EXCLUDED = "EXCLUDED"


class RecordKind(str, Enum):
    INVARIANT = "INVARIANT"
    TASK = "TASK"
    DECISION = "DECISION"
    CLAIM = "CLAIM"
    EVIDENCE = "EVIDENCE"


class ReasonCode(str, Enum):
    """Record-level reasons, followed by the report-level reasons.

    The report-level partition starts at ``NO_ACTIVE_TASK``.  Report-level
    codes must never appear inside ``ContextEntry.reasons`` and non-report
    codes must never appear in ``CompiledContext.report_reasons``.  Reason
    lists are ordered by this declaration order, deduplicated.
    """

    RULE_EXCLUDED = "RULE_EXCLUDED"
    NO_LEXICAL_OVERLAP = "NO_LEXICAL_OVERLAP"
    DIGEST_NOT_RECHECKED = "DIGEST_NOT_RECHECKED"
    VOLATILE_MUST_REVALIDATE = "VOLATILE_MUST_REVALIDATE"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NO_ACTIVE_TASK = "NO_ACTIVE_TASK"
    INVARIANT_BUDGET_OVERFLOW = "INVARIANT_BUDGET_OVERFLOW"


_REPORT_LEVEL_CODES: Final = frozenset(
    {ReasonCode.NO_ACTIVE_TASK, ReasonCode.INVARIANT_BUDGET_OVERFLOW}
)

# Deterministic rule-excluded ordering: fixed kind rank, then record id.
_KIND_RANK: Final = MappingProxyType(
    {
        RecordKind.INVARIANT: 0,
        RecordKind.TASK: 1,
        RecordKind.DECISION: 2,
        RecordKind.CLAIM: 3,
        RecordKind.EVIDENCE: 4,
    }
)


class ContextInputError(ValueError):
    """The compiler input is invalid, including a budget below the minimum."""


@dataclass(frozen=True, slots=True)
class ContextEntry:
    """One state record as represented in the compiled output."""

    record_id: str
    kind: RecordKind
    band: int
    score: int
    disposition: Disposition
    rendered_freshness: str
    reasons: tuple[ReasonCode, ...]
    description: str = ""
    discriminator: str = ""

    def __post_init__(self) -> None:
        seen: set[ReasonCode] = set()
        for reason in self.reasons:
            if reason in seen or reason in _REPORT_LEVEL_CODES:
                raise AssertionError(f"invalid entry reasons for {self.record_id}")
            seen.add(reason)


@dataclass(frozen=True, slots=True)
class BudgetReport:
    profile: ContextProfile
    budget_chars: int
    chrome_chars: int
    used_chars: int
    over_budget: bool
    approximate_token_estimate: int


@dataclass(frozen=True, slots=True)
class CompiledContext:
    schema_version: int
    profile: ContextProfile
    state_revision: int
    active_task_id: str | None
    entries: tuple[ContextEntry, ...] = field(default=(), hash=False)
    report_entries: tuple[ContextEntry, ...] = field(default=(), hash=False)
    report_reasons: tuple[ReasonCode, ...] = ()
    budget: BudgetReport | None = None

    def __post_init__(self) -> None:
        for entry in self.entries:
            if entry.disposition is Disposition.EXCLUDED:
                raise AssertionError(
                    f"{entry.record_id}: CompiledContext.entries is payload-only"
                )
        if any(code not in _REPORT_LEVEL_CODES for code in self.report_reasons):
            raise AssertionError("report_reasons may contain report-level codes only")

    def entries_in_selection_order(self) -> tuple[ContextEntry, ...]:
        """Return payload entries ordered by the profile's selection key."""
        if self.budget is None:
            raise ContextInputError("compiled context carries no budget report")
        if self.profile is ContextProfile.SESSION:
            key = _record_id_key
        else:
            key = _handoff_selection_key
        return tuple(sorted(self.entries, key=key))


def minimum_budget_chars(profile: ContextProfile) -> int:
    """Return the exact rendered chrome size for one profile."""
    try:
        return PAYLOAD_CHROME_CHARS[profile]
    except KeyError as exc:
        raise ContextInputError(f"unknown profile: {profile}") from exc


def compile_context(
    state: _state.StateDocument,
    *,
    profile: ContextProfile = ContextProfile.SESSION,
    budget_chars: int | None = None,
) -> CompiledContext:
    """Compile a validated state document into a bounded, explainable context.

    This is the pure core: validation, selection, budgeting, and rendering
    decisions happen here with no side effects and no ambient inputs.
    """
    _validate_profile(profile)
    _state.validate_state(state)
    resolved_budget = (
        budget_chars if budget_chars is not None else state.project.default_budget_chars
    )
    if type(resolved_budget) is not int or isinstance(resolved_budget, bool):
        raise ContextInputError("budget_chars must be an integer")
    chrome = PAYLOAD_CHROME_CHARS[profile]
    if resolved_budget < chrome:
        raise ContextInputError(
            f"budget {resolved_budget} is below the minimum {chrome} "
            f"for profile {profile.value}"
        )

    task = _active_task(state)
    report_reasons = [] if task is not None else [ReasonCode.NO_ACTIVE_TASK]
    kinds = _kind_by_id(state)
    anchor_tokens = _tokens(task.description) if task is not None else frozenset()
    selected, rule_excluded = _select_bands(state, task, kinds, profile, anchor_tokens)

    order = sorted(
        selected,
        key=(
            _record_id_key
            if profile is ContextProfile.SESSION
            else _handoff_selection_key
        ),
    )
    first_miss, _ = _fill_budget(order, chrome, resolved_budget)
    survivors = _survivors(order, first_miss)
    payload_entries = tuple(
        entry for entry in survivors if entry.disposition is not Disposition.EXCLUDED
    )
    report_entries = tuple(survivors) + tuple(
        sorted(
            rule_excluded,
            key=lambda entry: (_KIND_RANK[entry.kind], entry.record_id),
        )
    )

    # One exact accounting path for both default and explicit budgets:
    # used_chars is derived from the same emission path that render_payload
    # uses, so used_chars == len(render_payload(ctx)) by construction.
    used = _measure_payload(profile, payload_entries)
    over_budget = used > resolved_budget
    if over_budget:
        report_reasons.append(ReasonCode.INVARIANT_BUDGET_OVERFLOW)

    budget = BudgetReport(
        profile=profile,
        budget_chars=resolved_budget,
        chrome_chars=chrome,
        used_chars=used,
        over_budget=over_budget,
        approximate_token_estimate=_approximate_token_estimate(used),
    )
    return CompiledContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        profile=profile,
        state_revision=state.revision,
        active_task_id=task.id if task is not None else None,
        entries=payload_entries,
        report_entries=report_entries,
        report_reasons=_ordered_report_reasons(report_reasons),
        budget=budget,
    )


def load_and_compile(
    project_root: str | os.PathLike[str] | None = None,
    *,
    profile: ContextProfile = ContextProfile.SESSION,
    budget_chars: int | None = None,
) -> CompiledContext:
    """Load validated state and compile it; the only I/O in this module."""
    if project_root is None:
        project_root = os.curdir
    root = _paths.discover_project_root(project_root)
    if root is None:
        raise _state.StateNotInitializedError("no initialized Evidline root discovered")
    state = _state.load_state(root)
    return compile_context(state, profile=profile, budget_chars=budget_chars)


def render_payload(ctx: CompiledContext) -> str:
    """Render the agent-facing, budgeted context string.

    Fixed sections are emitted in the order INVARIANTS, REVALIDATE, CONTEXT;
    within each section the profile's selection order is preserved.  EXCLUDED
    records and audit metadata never appear here.
    """
    return _render_payload_from_entries(ctx)


def _render_payload_from_entries(ctx: CompiledContext) -> str:
    _validate_compiled(ctx)
    order = ctx.entries_in_selection_order()
    invariants = tuple(_render_invariant(e) for e in order if e.kind is RecordKind.INVARIANT)
    revalidate = tuple(
        _render_entry(e)
        for e in order
        if e.kind is not RecordKind.INVARIANT
        and e.disposition is Disposition.REVALIDATE
    )
    context = tuple(
        _render_entry(e)
        for e in order
        if e.kind is not RecordKind.INVARIANT
        and e.disposition is Disposition.INCLUDED
    )
    return _render_payload_frame(ctx.profile, invariants, revalidate, context)


def render_report(ctx: CompiledContext) -> str:
    """Render the human/audit representation, which is not budget-bounded.

    Every state record appears exactly once with its band, score, disposition,
    kind, freshness, and reasons.  The report states that it is not
    budget-bounded without embedding a measurement of its own rendered length.
    """
    _validate_compiled(ctx)
    lines: list[str] = [
        "Evidline context compiler report",
        f"profile: {ctx.profile.value}",
        f"state_revision: {ctx.state_revision}",
        f"schema_version: {ctx.schema_version}",
        f"active_task: {ctx.active_task_id or '-'}",
        f"report_reasons: {_format_reasons(ctx.report_reasons)}",
        "budget: " + (_format_budget(ctx.budget) if ctx.budget else "absent"),
        "report: this report is not budget-bounded",
        "records:",
    ]
    for entry in ctx.report_entries:
        lines.append(
            "  "
            + " | ".join(
                (
                    f"band={entry.band}",
                    f"score={entry.score}",
                    f"disposition={entry.disposition.value}",
                    f"kind={entry.kind.value}",
                    f"id={entry.record_id}",
                    f"freshness={entry.rendered_freshness}",
                    f"reasons={_format_reasons(entry.reasons)}",
                )
            )
        )
    if not ctx.report_entries:
        lines.append("  (no state records)")
    return "\n".join(lines) + "\n"


def render_json(ctx: CompiledContext) -> str:
    """Render the canonical machine-readable audit representation.

    No field claims to measure the JSON or report string's own length.
    """
    _validate_compiled(ctx)
    document: dict[str, Any] = {
        "schema_version": ctx.schema_version,
        "profile": ctx.profile.value,
        "state_revision": ctx.state_revision,
        "active_task_id": ctx.active_task_id,
        "report_reasons": [code.value for code in ctx.report_reasons],
        "budget": _budget_to_dict(ctx.budget) if ctx.budget else None,
        "records": [
            {
                "record_id": entry.record_id,
                "kind": entry.kind.value,
                "band": entry.band,
                "score": entry.score,
                "disposition": entry.disposition.value,
                "rendered_freshness": entry.rendered_freshness,
                "reasons": [code.value for code in entry.reasons],
            }
            for entry in ctx.report_entries
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def report_chars(ctx: CompiledContext) -> int:
    """Derived helper: rendered length of ``render_report(ctx)``.

    The measurement is never embedded in the string being measured.
    """
    return len(render_report(ctx))


def _validate_profile(profile: ContextProfile) -> None:
    if not isinstance(profile, ContextProfile):
        raise ContextInputError("profile must be a ContextProfile")


def _validate_compiled(ctx: CompiledContext) -> None:
    if type(ctx) is not CompiledContext:
        raise ContextInputError("expected a CompiledContext")


def _tokens(text: str) -> frozenset[str]:
    return frozenset(
        token
        for token in (
            match.group(0).casefold() for match in _TOKEN_PATTERN.finditer(text)
        )
        if len(token) >= _MIN_TOKEN_LENGTH and token not in _STOPWORDS
    )


def _record_id_key(entry: ContextEntry) -> tuple[Any, ...]:
    return (entry.band, -entry.score, entry.record_id)


def _handoff_selection_key(entry: ContextEntry) -> tuple[Any, ...]:
    rank = 0 if entry.disposition is Disposition.REVALIDATE else 1
    return (entry.band, rank, -entry.score, entry.record_id)


def _disposition_kind(record: Any) -> Disposition:
    if isinstance(record, _state.Claim):
        if (
            record.verification is _state.Verification.UNVERIFIED
            and record.freshness is _state.ClaimFreshness.DURABLE_UNTIL_SUPERSEDED
        ):
            return Disposition.INCLUDED
        return Disposition.REVALIDATE
    return Disposition.INCLUDED


def _kind_of(record: Any) -> RecordKind:
    if isinstance(record, _state.Invariant):
        return RecordKind.INVARIANT
    if isinstance(record, _state.Task):
        return RecordKind.TASK
    if isinstance(record, _state.Decision):
        return RecordKind.DECISION
    if isinstance(record, _state.Claim):
        return RecordKind.CLAIM
    return RecordKind.EVIDENCE


def _kind_by_id(
    state: _state.StateDocument,
) -> dict[str, tuple[RecordKind, Any]]:
    result: dict[str, tuple[RecordKind, Any]] = {}
    for record in state.invariants:
        result[record.id] = (RecordKind.INVARIANT, record)
    for record in state.tasks:
        result[record.id] = (RecordKind.TASK, record)
    for record in state.decisions:
        result[record.id] = (RecordKind.DECISION, record)
    for record in state.claims:
        result[record.id] = (RecordKind.CLAIM, record)
    for record in state.evidence:
        result[record.id] = (RecordKind.EVIDENCE, record)
    return result


def _ordered_report_reasons(reasons: list[ReasonCode]) -> tuple[ReasonCode, ...]:
    wanted = set(reasons)
    return tuple(
        code
        for code in ReasonCode
        if code in _REPORT_LEVEL_CODES and code in wanted
    )


def _select_bands(
    state: _state.StateDocument,
    task: _state.Task | None,
    kinds: Mapping[str, tuple[RecordKind, Any]],
    profile: ContextProfile,
    anchor_tokens: frozenset[str],
) -> tuple[list[ContextEntry], list[ContextEntry]]:
    """Classify every state record into selections or rule exclusions.

    ``select`` keeps the strongest (smallest-band) classification only; records
    reachable through multiple signals appear once.
    """
    selections: list[ContextEntry] = []
    exclusions: list[ContextEntry] = []
    selected: set[str] = set()
    excluded: set[str] = set()

    def select(record: Any, band: int, score: int) -> None:
        if record.id in selected or record.id in excluded:
            return
        selected.add(record.id)
        selections.append(
            _make_entry(record, band, score, _freshness_reasons(record))
        )

    def rule_excluded(
        record: Any, band: int, score: int, reasons: tuple[ReasonCode, ...]
    ) -> None:
        if record.id in selected or record.id in excluded:
            return
        excluded.add(record.id)
        exclusions.append(
            _make_entry(
                record, band, score, reasons, disposition=Disposition.EXCLUDED
            )
        )

    # Band 0: all ACTIVE invariants.  Superseded invariants are never
    # silently resurrected.
    for item in state.invariants:
        if item.status is _state.InvariantStatus.ACTIVE:
            select(item, 0, 0)
        else:
            rule_excluded(item, 0, 0, (ReasonCode.RULE_EXCLUDED,))

    if task is None:
        # Bands requiring an anchor remain empty; everything else is a
        # rule exclusion and stays explainable in the report.
        for record in state.tasks:
            rule_excluded(record, 0, 0, (ReasonCode.RULE_EXCLUDED,))
        for record in state.decisions:
            rule_excluded(record, 0, 0, (ReasonCode.RULE_EXCLUDED,))
        for record in state.claims:
            rule_excluded(record, 0, 0, (ReasonCode.RULE_EXCLUDED,))
        for record in state.evidence:
            rule_excluded(record, 0, 0, (ReasonCode.RULE_EXCLUDED,))
        return selections, exclusions

    # Band 1: the ACTIVE task.
    select(task, 1, 0)

    # Band 2: records directly referenced by the active task's related_ids.
    for related_id in task.related_ids:
        if related_id not in kinds or related_id in selected:
            continue
        kind, record = kinds[related_id]
        if kind is RecordKind.CLAIM:
            select(record, 2, 0)
        elif kind is RecordKind.DECISION:
            if record.intent in (_state.Intent.PROPOSED, _state.Intent.REQUESTED):
                rule_excluded(record, 2, 0, (ReasonCode.RULE_EXCLUDED,))
            else:
                select(record, 2, 0)
        elif kind is RecordKind.TASK and record.status is _state.TaskStatus.DONE:
            if profile is ContextProfile.HANDOFF:
                select(record, 2, 0)
            else:
                rule_excluded(record, 2, 0, (ReasonCode.RULE_EXCLUDED,))
        elif kind is RecordKind.EVIDENCE:
            # An Evidence record referenced directly by the ACTIVE task is not
            # rule-excluded here.  It remains recoverable at band 3 through a
            # band-2 Claim's evidence_ids; the later catch-all (band 6) still
            # rule-excludes evidence that band 3 never legitimately reached.
            continue
        else:
            select(record, 2, 0)

    # Band 3: evidence referenced by evidence_ids of a band-2 claim.
    for candidate in list(selections):
        if candidate.band != 2 or candidate.kind is not RecordKind.CLAIM:
            continue
        claim = kinds[candidate.record_id][1]
        for evidence_id in claim.evidence_ids:
            if evidence_id in selected or evidence_id not in kinds:
                continue
            select(kinds[evidence_id][1], 3, 0)

    # Band 4/5: AUTHORIZED then DENIED decisions not already selected.
    for record in state.decisions:
        if record.intent is _state.Intent.AUTHORIZED:
            select(record, 4, 0)
    for record in state.decisions:
        if record.intent is _state.Intent.DENIED:
            select(record, 5, 0)

    # Rule exclusions among remaining records.
    for record in state.tasks:
        if record.status is _state.TaskStatus.ACTIVE:
            continue
        if record.status is _state.TaskStatus.DONE:
            if profile is ContextProfile.HANDOFF:
                continue  # eligible through band 6 below
            rule_excluded(record, 6, 0, (ReasonCode.RULE_EXCLUDED,))
        else:
            rule_excluded(record, 6, 0, (ReasonCode.RULE_EXCLUDED,))
    for record in state.decisions:
        if record.intent in (_state.Intent.PROPOSED, _state.Intent.REQUESTED):
            rule_excluded(record, 6, 0, (ReasonCode.RULE_EXCLUDED,))
    for record in state.evidence:
        rule_excluded(record, 6, 0, (ReasonCode.RULE_EXCLUDED,))

    # Band 6: remaining eligible records with deterministic lexical overlap.
    # A persisted FAILED claim is not rule-excluded; it is selected here when
    # lexical overlap holds and carries FAILED_VERIFICATION + REVALIDATE.
    for record in state.tasks:
        if (
            record.status is _state.TaskStatus.DONE
            and profile is ContextProfile.HANDOFF
            and record.id not in selected
        ):
            score = _lexical_score(record.description, anchor_tokens)
            if score >= 1:
                select(record, 6, score)
            else:
                rule_excluded(record, 6, 0, (ReasonCode.NO_LEXICAL_OVERLAP,))
    for record in state.claims:
        score = _lexical_score(record.description, anchor_tokens)
        # A persisted FAILED claim must revalidate even when it has no
        # lexical overlap; it carries FAILED_VERIFICATION and REVALIDATE.
        if score >= 1 or record.verification is _state.Verification.FAILED:
            select(record, 6, score)
        else:
            rule_excluded(record, 6, 0, (ReasonCode.NO_LEXICAL_OVERLAP,))
    for record in state.decisions:
        score = _lexical_score(record.description, anchor_tokens)
        if score >= 1:
            select(record, 6, score)
        else:
            rule_excluded(record, 6, 0, (ReasonCode.NO_LEXICAL_OVERLAP,))
    return selections, exclusions


def _freshness_reasons(record: Any) -> tuple[ReasonCode, ...]:
    if isinstance(record, _state.Claim):
        if record.verification is _state.Verification.FAILED:
            return (ReasonCode.FAILED_VERIFICATION,)
        if record.freshness is _state.ClaimFreshness.DIGEST_BOUND:
            return (ReasonCode.DIGEST_NOT_RECHECKED,)
        if record.freshness is _state.ClaimFreshness.PERSISTED_VOLATILE:
            return (ReasonCode.VOLATILE_MUST_REVALIDATE,)
    return ()


def _lexical_score(description: str, anchor_tokens: frozenset[str]) -> int:
    return len(anchor_tokens & _tokens(description))


def _make_entry(
    record: Any,
    band: int,
    score: int,
    reasons: tuple[ReasonCode, ...],
    *,
    disposition: Disposition | None = None,
) -> ContextEntry:
    return ContextEntry(
        record_id=record.id,
        kind=_kind_of(record),
        band=band,
        score=score,
        disposition=(
            disposition if disposition is not None else _disposition_kind(record)
        ),
        rendered_freshness=_rendered_freshness(record),
        reasons=reasons,
        description=_normalized_description(record),
        discriminator=_discriminator(record),
    )


def _normalized_description(record: Any) -> str:
    """Deterministic single-line normalization; never mutates persisted state."""
    return _WHITESPACE_RE.sub(" ", record.description).strip()


def _discriminator(record: Any) -> str:
    """Phase 1 discriminator rendered before the normalized description.

    Invariants render enforcement, tasks render status, decisions render
    intent, evidence renders provenance.  Claims carry no discriminator:
    their freshness is emitted by :func:`_render_entry` instead.
    """
    if isinstance(record, _state.Invariant):
        return record.enforcement.value
    if isinstance(record, _state.Task):
        return record.status.value
    if isinstance(record, _state.Decision):
        return record.intent.value
    if isinstance(record, _state.Evidence):
        return record.provenance.value
    return ""


def _rendered_freshness(record: Any) -> str:
    if isinstance(record, _state.Claim):
        if record.verification is _state.Verification.FAILED:
            return "FAILED"
        if (
            record.verification is _state.Verification.UNVERIFIED
            and record.freshness is _state.ClaimFreshness.DURABLE_UNTIL_SUPERSEDED
        ):
            return "UNVERIFIED"
        if record.freshness in (
            _state.ClaimFreshness.DIGEST_BOUND,
            _state.ClaimFreshness.PERSISTED_VOLATILE,
        ):
            return "STALE"
    return "N/A"


def _fill_budget(
    order: list[ContextEntry], chrome: int, budget_chars: int
) -> tuple[int | None, int]:
    """Reserve invariants, then fill by selection order with first-miss stop.

    Returns ``(first_miss_index, spent_before_window)`` where
    ``first_miss_index`` indexes ``order`` and ``None`` means every candidate
    fit.  Invariants are never silently truncated: if they overflow the
    budget they are all included anyway and the remaining candidates miss.

    The frame is rendered exactly as in :func:`render_payload`, so every
    block contributes its rendered characters plus the joining newline.
    """
    spent = chrome + sum(
        len(_render_invariant(entry)) + 1
        for entry in order
        if entry.kind is RecordKind.INVARIANT
    )
    remaining = budget_chars - spent
    first_miss: int | None = None
    for position, entry in enumerate(order):
        if entry.kind is RecordKind.INVARIANT:
            continue
        block = _render_entry(entry)
        if len(block) + 1 > remaining:
            first_miss = position
            break
        spent += len(block) + 1
        remaining -= len(block) + 1
    return first_miss, spent


def _survivors(
    order: list[ContextEntry], first_miss: int | None
) -> list[ContextEntry]:
    if first_miss is None:
        return list(order)
    return [
        entry if position < first_miss else _budget_excluded(entry)
        for position, entry in enumerate(order)
    ]


def _budget_excluded(entry: ContextEntry) -> ContextEntry:
    return ContextEntry(
        record_id=entry.record_id,
        kind=entry.kind,
        band=entry.band,
        score=entry.score,
        disposition=Disposition.EXCLUDED,
        rendered_freshness=entry.rendered_freshness,
        reasons=tuple(dict.fromkeys(entry.reasons + (ReasonCode.BUDGET_EXHAUSTED,))),
        description=entry.description,
        discriminator=entry.discriminator,
    )


def _active_task(state: _state.StateDocument) -> _state.Task | None:
    for item in state.tasks:
        if item.status is _state.TaskStatus.ACTIVE:
            return item
    return None


def _approximate_token_estimate(used_chars: int) -> int:
    return math.ceil(used_chars / 4)


def _render_payload_frame(
    profile: ContextProfile,
    invariant_blocks: tuple[str, ...],
    revalidate_blocks: tuple[str, ...],
    context_blocks: tuple[str, ...],
) -> str:
    parts = ["EVIDLINE CONTEXT", f"profile: {profile.value}"]
    if profile is ContextProfile.HANDOFF:
        parts.append(_HANDOFF_DISCLAIMER)
    parts.append("INVARIANTS")
    parts.extend(invariant_blocks)
    parts.append("REVALIDATE")
    parts.extend(revalidate_blocks)
    parts.append("CONTEXT")
    parts.extend(context_blocks)
    return "\n".join(parts) + "\n"


def _render_invariant(entry: ContextEntry) -> str:
    return f"[INVARIANT {entry.record_id}] {entry.discriminator} — {entry.description}"


def _render_entry(entry: ContextEntry) -> str:
    if entry.kind is RecordKind.CLAIM:
        head = f"[CLAIM {entry.record_id}] fresh:{entry.rendered_freshness}"
    else:
        head = f"[{entry.kind.value} {entry.record_id}] {entry.discriminator}"
        if entry.band == 1:
            head += " anchor"
    return f"{head} — {entry.description}"


# Derive profile chrome from the exact payload-frame renderer.  Chrome
# depends only on the profile; HANDOFF includes its fixed unverified
# continuity disclaimer.  All section headers are always emitted.
PAYLOAD_CHROME_CHARS: Final = MappingProxyType(
    {
        profile: len(_render_payload_frame(profile, (), (), ()))
        for profile in ContextProfile
    }
)


def _measure_payload(
    profile: ContextProfile, entries: tuple[ContextEntry, ...]
) -> int:
    """Measure the exact payload length for a payload entry tuple.

    Constructs a payload-only CompiledContext over the same entries and runs
    the same emission path as :func:`render_payload`, so the measurement
    equals the rendered length by construction.
    """
    probe = CompiledContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        profile=profile,
        state_revision=0,
        active_task_id=None,
        entries=entries,
        budget=BudgetReport(
            profile=profile,
            budget_chars=0,
            chrome_chars=PAYLOAD_CHROME_CHARS[profile],
            used_chars=0,
            over_budget=False,
            approximate_token_estimate=0,
        ),
    )
    return len(_render_payload_from_entries(probe))


def _format_reasons(reasons: tuple[ReasonCode, ...]) -> str:
    return ",".join(code.value for code in reasons) if reasons else "none"


def _format_budget(budget: BudgetReport) -> str:
    return (
        f"budget_chars={budget.budget_chars} "
        f"chrome_chars={budget.chrome_chars} "
        f"used_chars={budget.used_chars} "
        f"over_budget={budget.over_budget} "
        f"approximate_token_estimate={budget.approximate_token_estimate}"
    )


def _budget_to_dict(budget: BudgetReport) -> dict[str, Any]:
    return {
        "budget_chars": budget.budget_chars,
        "chrome_chars": budget.chrome_chars,
        "used_chars": budget.used_chars,
        "over_budget": budget.over_budget,
        "approximate_token_estimate": budget.approximate_token_estimate,
    }
