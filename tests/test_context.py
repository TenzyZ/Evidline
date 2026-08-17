from __future__ import annotations

from dataclasses import replace
import io
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from evidline.context import (
    CONTEXT_SCHEMA_VERSION,
    PAYLOAD_CHROME_CHARS,
    BudgetReport,
    CompiledContext,
    ContextEntry,
    ContextInputError,
    ContextProfile,
    Disposition,
    RecordKind,
    ReasonCode,
    compile_context,
    load_and_compile,
    minimum_budget_chars,
    render_json,
    render_payload,
    render_report,
    report_chars,
)
from evidline.state import (
    Claim,
    ClaimFreshness,
    Decision,
    Evidence,
    EvidenceProvenance,
    Execution,
    Intent,
    Invariant,
    InvariantEnforcement,
    InvariantStatus,
    Project,
    StateDocument,
    Task,
    TaskStatus,
    Verification,
)


def base_state(*, revision: int = 0) -> StateDocument:
    return StateDocument(
        schema_version=4,
        revision=revision,
        project=Project(
            name="Evidline",
            purpose="Verified local continuity",
            ignore_globs=("*.pyc",),
            default_budget_chars=100000,
        ),
        invariants=(),
        decisions=(),
        tasks=(),
        claims=(),
        evidence=(),
        counters={},
    )


def task(record_id: str, description: str, *, status: TaskStatus = TaskStatus.ACTIVE, related: tuple[str, ...] = ()) -> Task:
    return Task(
        id=record_id,
        description=description,
        status=status,
        intent=Intent.AUTHORIZED,
        execution=Execution.EXECUTED,
        related_ids=related,
        approved_at="2026-08-15T00:00:00+04:00",
        approval_channel="interactive",
        asserted_actor="human",
    )


def invariant(record_id: str, *, active: bool = True) -> Invariant:
    return Invariant(
        id=record_id,
        description="Never promote unsupported claims",
        enforcement=InvariantEnforcement.BLOCK,
        status=InvariantStatus.ACTIVE if active else InvariantStatus.SUPERSEDED,
        superseded_by="inv-newer" if not active else None,
        approved_at="2026-08-15T00:00:00+04:00" if not active else None,
        approval_channel="interactive" if not active else None,
    )


def decision(record_id: str, description: str, intent: Intent) -> Decision:
    return Decision(
        id=record_id,
        description=description,
        intent=intent,
        execution=Execution.NOT_RUN,
        approved_at="2026-08-15T00:00:00+04:00",
        approval_channel="interactive",
    )


def evidence(record_id: str, description: str) -> Evidence:
    return Evidence(
        id=record_id,
        description=description,
        provenance=EvidenceProvenance.DIRECT_OBSERVATION,
        execution=Execution.EXECUTED,
    )


def claim(
    record_id: str,
    description: str,
    freshness: ClaimFreshness = ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
    *,
    evidence_ids: tuple[str, ...] = (),
) -> Claim:
    return Claim(
        id=record_id,
        description=description,
        freshness=freshness,
        verification=Verification.UNVERIFIED,
        reproducible=False,
        evidence_ids=evidence_ids,
    )


def one_evidence() -> Evidence:
    return Evidence(
        id="evidence-1",
        description="Observed digest",
        provenance=EvidenceProvenance.DIRECT_OBSERVATION,
        execution=Execution.EXECUTED,
        source_path="evidence/observed.txt",
        digest="sha256:" + "a" * 64,
    )


def state_with_active_task() -> StateDocument:
    return replace(
        base_state(),
        invariants=(invariant("inv-1"),),
        decisions=(decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),),
        tasks=(task("task-1", "Implement context compiler", related=("dec-1",)),),
        claims=(),
        evidence=(),
    )


def state_with_claim(claim_record: Claim) -> StateDocument:
    state = replace(
        state_with_active_task(),
        tasks=(
            task(
                "task-1",
                "Implement context compiler",
                related=("dec-1", claim_record.id),
            ),
        ),
        claims=(claim_record,),
        evidence=(one_evidence(),),
        counters={"claim": 1, "evidence": 1},
    )
    return state


class CoreModelTests(unittest.TestCase):
    def test_context_schema_version_is_one(self) -> None:
        self.assertEqual(CONTEXT_SCHEMA_VERSION, 1)

    def test_profile_values(self) -> None:
        self.assertEqual(ContextProfile.SESSION.value, "session")
        self.assertEqual(ContextProfile.HANDOFF.value, "handoff")

    def test_handoff_chrome_contains_fixed_disclaimer(self) -> None:
        self.assertIn(
            "unverified continuity representation",
            _frame_with_handoff_chrome(),
        )
        self.assertIn("not a verified handoff", _frame_with_handoff_chrome())

    def test_session_chrome_has_no_disclaimer(self) -> None:
        self.assertNotIn("verified handoff", _frame_with_session_chrome())

    def test_minimum_budget_chars_equals_chrome_mapping(self) -> None:
        for profile in ContextProfile:
            self.assertEqual(
                minimum_budget_chars(profile), PAYLOAD_CHROME_CHARS[profile]
            )

    def test_budget_below_minimum_is_rejected(self) -> None:
        for profile in ContextProfile:
            with self.assertRaises(ContextInputError):
                compile_context(
                    state_with_active_task(),
                    profile=profile,
                    budget_chars=minimum_budget_chars(profile) - 1,
                )

    def test_budget_equal_to_minimum_is_valid(self) -> None:
        for profile in ContextProfile:
            ctx = compile_context(
                base_state(),
                profile=profile,
                budget_chars=minimum_budget_chars(profile),
            )
            self.assertEqual(len(render_payload(ctx)), minimum_budget_chars(profile))
            self.assertEqual(ctx.budget.used_chars, len(render_payload(ctx)))
            self.assertFalse(ctx.budget.over_budget)

    def test_compile_validates_the_supplied_state_document(self) -> None:
        with self.assertRaises(Exception):
            compile_context("not a state document")

    def test_invalid_profile_is_rejected(self) -> None:
        with self.assertRaises(ContextInputError):
            compile_context(state_with_active_task(), profile="session")

    def test_bad_budget_type_is_rejected(self) -> None:
        with self.assertRaises(ContextInputError):
            compile_context(state_with_active_task(), budget_chars="9000")

    def test_output_is_budget_independent_of_report_reasons(self) -> None:
        no_task = base_state()
        no_task_ctx = compile_context(no_task)
        with_task = state_with_active_task()
        with_task_ctx = compile_context(with_task)
        self.assertEqual(
            render_payload(no_task_ctx),
            render_payload(
                replace(
                    no_task_ctx,
                    report_reasons=(ReasonCode.INVARIANT_BUDGET_OVERFLOW,),
                )
            ),
        )
        self.assertEqual(
            len(render_payload(with_task_ctx)),
            with_task_ctx.budget.used_chars,
        )


def _frame_with_handoff_chrome() -> str:
    from evidline.context import _render_payload_frame

    return _render_payload_frame(ContextProfile.HANDOFF, (), (), ())


def _frame_with_session_chrome() -> str:
    from evidline.context import _render_payload_frame

    return _render_payload_frame(ContextProfile.SESSION, (), (), ())


class SelectionTests(unittest.TestCase):
    def test_band0_active_invariants_first(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        self.assertEqual(
            [(e.kind, e.band) for e in ctx.entries],
            [(RecordKind.INVARIANT, 0), (RecordKind.TASK, 1), (RecordKind.DECISION, 2)],
        )

    def test_superseded_invariant_is_rule_excluded(self) -> None:
        state = replace(
            state_with_active_task(),
            invariants=(invariant("inv-1", active=False), invariant("inv-newer")),
        )
        ctx = compile_context(state)
        self.assertNotIn("inv-1", {e.record_id for e in ctx.entries})
        excluded = [e for e in ctx.report_entries if e.record_id == "inv-1"]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0].disposition, Disposition.EXCLUDED)
        self.assertIn(ReasonCode.RULE_EXCLUDED, excluded[0].reasons)

    def test_band1_active_task(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        self.assertEqual(ctx.active_task_id, "task-1")
        task_entry = [e for e in ctx.entries if e.kind is RecordKind.TASK]
        self.assertEqual([(e.record_id, e.band) for e in task_entry], [("task-1", 1)])

    def test_band2_task_links(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        decision_entry = [e for e in ctx.entries if e.kind is RecordKind.DECISION]
        self.assertEqual([(e.record_id, e.band) for e in decision_entry], [("dec-1", 2)])

    def test_band3_supporting_evidence(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(task("task-1", "Implement context compiler", related=("claim-1",)),),
            claims=(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DIGEST_BOUND,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        entries = {e.record_id: e for e in ctx.entries}
        self.assertEqual(entries["claim-1"].band, 2)
        self.assertEqual(entries["evidence-1"].band, 3)
        self.assertEqual(entries["claim-1"].disposition, Disposition.REVALIDATE)
        self.assertIn(ReasonCode.DIGEST_NOT_RECHECKED, entries["claim-1"].reasons)

    def test_band4_authorized_decisions(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(task("task-1", "Implement context compiler"),),
            decisions=(
                decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),
                decision("dec-2", "Extra authorized decision", Intent.AUTHORIZED),
            ),
        )
        ctx = compile_context(state)
        dec2 = [e for e in ctx.entries if e.record_id == "dec-2"][0]
        self.assertEqual(dec2.band, 4)

    def test_band5_denied_decisions(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(task("task-1", "Implement context compiler"),),
            decisions=(decision("dec-1", "Denied change", Intent.DENIED),),
        )
        ctx = compile_context(state)
        denied = [e for e in ctx.entries if e.kind is RecordKind.DECISION][0]
        self.assertEqual(denied.band, 5)

    def test_band6_lexical_overlap(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                claim(
                    "claim-1",
                    "The context compiler is deterministic and local",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1},
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertEqual(entry.band, 6)
        self.assertGreater(entry.score, 0)

    def test_zero_lexical_overlap_is_excluded(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                claim(
                    "claim-1",
                    "zzz qqq",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1},
        )
        ctx = compile_context(state)
        self.assertNotIn("claim-1", {e.record_id for e in ctx.entries})
        report_entry = [e for e in ctx.report_entries if e.record_id == "claim-1"][0]
        self.assertEqual(report_entry.disposition, Disposition.EXCLUDED)
        self.assertIn(ReasonCode.NO_LEXICAL_OVERLAP, report_entry.reasons)
        self.assertEqual(report_entry.band, 6)
        self.assertEqual(report_entry.score, 0)

    def test_no_active_task_is_handled_honestly(self) -> None:
        ctx = compile_context(base_state())
        self.assertIn(ReasonCode.NO_ACTIVE_TASK, ctx.report_reasons)
        self.assertEqual(ctx.active_task_id, None)
        self.assertEqual(ctx.entries, ())
        for entry in ctx.report_entries:
            self.assertIs(entry.disposition, Disposition.EXCLUDED)
            self.assertIn(ReasonCode.RULE_EXCLUDED, entry.reasons)

    def test_no_active_task_with_records_is_handled_honestly(self) -> None:
        state = replace(
            base_state(),
            invariants=(invariant("inv-1"),),
            decisions=(decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),),
            tasks=(task("task-1", "Old finished task", status=TaskStatus.DONE),),
        )
        ctx = compile_context(state)
        self.assertIn(ReasonCode.NO_ACTIVE_TASK, ctx.report_reasons)
        self.assertEqual(
            [(e.kind, e.band) for e in ctx.entries],
            [(RecordKind.INVARIANT, 0)],
        )
        self.assertEqual(
            len(ctx.report_entries),
            len(state.invariants) + len(state.tasks) + len(state.decisions),
        )
        for entry in ctx.report_entries:
            if entry.kind is RecordKind.INVARIANT:
                self.assertIs(entry.disposition, Disposition.INCLUDED)
            else:
                self.assertIs(entry.disposition, Disposition.EXCLUDED)

    def test_related_claim_and_linked_decision_bands(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("claim-1", "dec-1"),
                ),
            ),
            claims=(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DIGEST_BOUND,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        entries = {e.record_id: e for e in ctx.entries}
        self.assertEqual(entries["claim-1"].band, 2)
        self.assertEqual(entries["dec-1"].band, 2)
        self.assertEqual(entries["evidence-1"].band, 3)


class FreshnessTests(unittest.TestCase):
    def test_durable_unverified_claim_is_included_and_unverified(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "Never promote unsupported claims",
                ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
            )
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(entry.disposition, Disposition.INCLUDED)
        self.assertEqual(entry.rendered_freshness, "UNVERIFIED")
        self.assertIn("UNVERIFIED", render_payload(ctx))

    def test_digest_bound_revalidates(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "A digest matches",
                ClaimFreshness.DIGEST_BOUND,
                evidence_ids=("evidence-1",),
            )
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(entry.disposition, Disposition.REVALIDATE)
        self.assertEqual(entry.rendered_freshness, "STALE")
        self.assertIn(ReasonCode.DIGEST_NOT_RECHECKED, entry.reasons)

    def test_persisted_volatile_revalidates(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "A transient observation",
                ClaimFreshness.PERSISTED_VOLATILE,
            )
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(entry.disposition, Disposition.REVALIDATE)
        self.assertEqual(entry.rendered_freshness, "STALE")
        self.assertIn(ReasonCode.VOLATILE_MUST_REVALIDATE, entry.reasons)

    def test_failed_verification_revalidates(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                Claim(
                    id="claim-1",
                    description="A failed verification",
                    freshness=ClaimFreshness.DIGEST_BOUND,
                    verification=Verification.FAILED,
                    reproducible=False,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(entry.disposition, Disposition.REVALIDATE)
        self.assertEqual(entry.rendered_freshness, "FAILED")
        self.assertIn(ReasonCode.FAILED_VERIFICATION, entry.reasons)

    def test_compiler_never_emits_persisted_claim_as_verified(self) -> None:
        from evidline.context import _render_entry

        for freshness in ClaimFreshness:
            with self.subTest(freshness=freshness):
                state = state_with_claim(
                    claim("claim-1", "Any stored claim", freshness)
                )
                ctx = compile_context(state)
                self.assertNotIn("fresh:VERIFIED", render_payload(ctx))
                self.assertNotIn("freshness=VERIFIED", render_report(ctx))
                for entry in ctx.report_entries:
                    self.assertNotEqual(entry.rendered_freshness, "VERIFIED")
                    self.assertNotEqual(
                        _render_entry(entry).split(" fresh:")[-1], "VERIFIED"
                    )

    def test_executed_evidence_does_not_imply_verification(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "Executed evidence claim",
                ClaimFreshness.DIGEST_BOUND,
                evidence_ids=("evidence-1",),
            )
        )
        ctx = compile_context(state)
        claim_entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(claim_entry.disposition, Disposition.REVALIDATE)
        self.assertNotIn("fresh:VERIFIED", render_payload(ctx))
        self.assertNotIn("freshness=VERIFIED", render_report(ctx))

    def test_provenance_labels_do_not_affect_disposition(self) -> None:
        claims = []
        for provenance in EvidenceProvenance:
            claims.append(
                claim(
                    f"claim-{provenance.value.lower()}",
                    f"claim about {provenance.value}",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                    evidence_ids=(f"evidence-{provenance.value.lower()}",),
                )
            )
        evidence_records = [
            Evidence(
                id=f"evidence-{provenance.value.lower()}",
                description=f"evidence from {provenance.value}",
                provenance=provenance,
                execution=Execution.EXECUTED,
            )
            for provenance in EvidenceProvenance
        ]
        state = replace(
            base_state(),
            tasks=(
                task(
                    "task-1",
                    "provenance investigation",
                    related=tuple(c.id for c in claims),
                ),
            ),
            claims=tuple(claims),
            evidence=tuple(evidence_records),
            counters={"claim": len(claims), "evidence": len(evidence_records)},
        )
        ctx = compile_context(state)
        for entry in ctx.entries:
            if entry.kind is RecordKind.CLAIM:
                self.assertIs(entry.disposition, Disposition.INCLUDED)


class BudgetTests(unittest.TestCase):
    def assert_used_equals_payload(self, ctx: CompiledContext) -> None:
        self.assertEqual(ctx.budget.used_chars, len(render_payload(ctx)))

    def test_invariant_overflow_includes_all_invariants_and_reports(self) -> None:
        state = replace(
            state_with_active_task(),
            invariants=(
                invariant("inv-1"),
                invariant("inv-2"),
                invariant("inv-3"),
            ),
        )
        minimum = minimum_budget_chars(ContextProfile.SESSION)
        ctx = compile_context(
            state, budget_chars=minimum
        )
        self.assertTrue(ctx.budget.over_budget)
        self.assertIn(ReasonCode.INVARIANT_BUDGET_OVERFLOW, ctx.report_reasons)
        invariant_ids = {
            e.record_id for e in ctx.entries if e.kind is RecordKind.INVARIANT
        }
        self.assertEqual(invariant_ids, {"inv-1", "inv-2", "inv-3"})
        self.assert_used_equals_payload(ctx)

    def test_used_chars_equals_payload_for_session_and_handoff(self) -> None:
        for profile in ContextProfile:
            for budget in (
                minimum_budget_chars(profile) + 500,
                100000,
            ):
                with self.subTest(profile=profile, budget=budget):
                    ctx = compile_context(state_with_active_task(), profile=profile, budget_chars=budget)
                    self.assert_used_equals_payload(ctx)

    def test_empty_state_payload_is_chrome_only(self) -> None:
        ctx = compile_context(base_state())
        self.assertEqual(render_payload(ctx), _frame_with_session_chrome())
        self.assert_used_equals_payload(ctx)

    def test_explicit_budget_equal_to_minimum(self) -> None:
        for profile in ContextProfile:
            ctx = compile_context(
                base_state(),
                profile=profile,
                budget_chars=minimum_budget_chars(profile),
            )
            self.assert_used_equals_payload(ctx)

    def test_first_miss_stops_lower_priority_inclusion(self) -> None:
        state = replace(
            state_with_active_task(),
            decisions=(
                decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),
                decision("dec-2", "Second authorized decision", Intent.AUTHORIZED),
                decision("dec-3", "Third authorized decision", Intent.AUTHORIZED),
            ),
        )
        # Budget covers chrome plus the band-0 invariant plus the band-1
        # task exactly (each block also pays its joining newline); the
        # band-2 decisions are lower priority and must miss.
        budget = (
            minimum_budget_chars(ContextProfile.SESSION)
            + len("[INVARIANT inv-1] BLOCK — Never promote unsupported claims") + 1
            + len("[TASK task-1] ACTIVE anchor — Implement context compiler") + 1
        )
        ctx = compile_context(state, budget_chars=budget)
        self.assertFalse(ctx.budget.over_budget)
        included = {e.record_id for e in ctx.entries}
        self.assertIn("task-1", included)
        self.assertNotIn("dec-1", included)
        self.assertNotIn("dec-2", included)
        self.assertNotIn("dec-3", included)
        excluded_entries = [
            e for e in ctx.report_entries if e.disposition is Disposition.EXCLUDED
        ]
        for entry in excluded_entries:
            self.assertIn(ReasonCode.BUDGET_EXHAUSTED, entry.reasons)
        self.assert_used_equals_payload(ctx)

    def test_no_partial_records(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                claim(
                    "claim-1",
                    "The context compiler is deterministic",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                ),
            ),
        )
        # A budget mid-block forces the band-6 claim to miss without a
        # partial record; the band-1 task is atomic and fits exactly.
        budget = (
            minimum_budget_chars(ContextProfile.SESSION)
            + len("[TASK task-1] ACTIVE anchor — Implement context compiler") - 1
        )
        ctx = compile_context(state, budget_chars=budget)
        included = {e.record_id for e in ctx.entries}
        self.assertNotIn("claim-1", included)
        report = {e.record_id: e for e in ctx.report_entries}
        for record_id, entry in report.items():
            if record_id in included:
                self.assertIsNot(entry.disposition, Disposition.EXCLUDED)
            else:
                self.assertIs(entry.disposition, Disposition.EXCLUDED)
        self.assert_used_equals_payload(ctx)

    def test_approximate_token_estimate_is_ceil_chars_over_4(self) -> None:
        for used in (0, 1, 4, 5, 1001):
            ctx = compile_context(base_state(), budget_chars=100000)
            expected = math.ceil(used / 4)
            fake_budget = BudgetReport(
                profile=ContextProfile.SESSION,
                budget_chars=100000,
                chrome_chars=PAYLOAD_CHROME_CHARS[ContextProfile.SESSION],
                used_chars=used,
                over_budget=False,
                approximate_token_estimate=expected,
            )
            self.assertEqual(fake_budget.approximate_token_estimate, expected)
        ctx = compile_context(base_state())
        self.assertEqual(
            ctx.budget.approximate_token_estimate,
            math.ceil(ctx.budget.used_chars / 4),
        )


class PayloadReportSeparationTests(unittest.TestCase):
    def test_excluded_content_never_appears_in_payload(self) -> None:
        # The claim is NOT linked through related_ids, so only lexical
        # relevance can select it; "zzz qqq" has no overlap and it is
        # excluded from the payload but visible in the report.
        state = replace(
            base_state(),
            tasks=(task("task-1", "Implement context compiler"),),
            claims=(claim("claim-1", "zzz qqq", ClaimFreshness.DURABLE_UNTIL_SUPERSEDED),),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        self.assertNotIn("claim-1", payload)
        report = render_report(ctx)
        self.assertIn("id=claim-1", report)
        self.assertIn(Disposition.EXCLUDED.value, report)

    def test_report_contains_all_record_ids_exactly_once(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        report = render_report(ctx)
        record_lines = [
            line for line in report.splitlines() if line.strip().startswith("band=")
        ]
        ids = [line.split("id=")[1].split(" ")[0] for line in record_lines]
        self.assertEqual(ids, ["inv-1", "task-1", "dec-1"])
        self.assertEqual(len(ids), len(set(ids)))

    def test_report_growth_cannot_inflate_payload_budget(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        small = report_chars(ctx)
        bigger = render_report(ctx) + "extra audit metadata appended"
        self.assertGreater(len(bigger), small)
        self.assertEqual(ctx.budget.used_chars, len(render_payload(ctx)))

    def test_report_has_no_self_length_measurement(self) -> None:
        ctx = compile_context(state_with_active_task())
        report = render_report(ctx)
        self.assertNotIn("report_chars", report)
        self.assertNotIn("report length", report)
        self.assertNotIn(str(len(report)), report)

    def test_fixed_section_headers_exist_even_if_empty(self) -> None:
        ctx = compile_context(base_state())
        payload = render_payload(ctx)
        self.assertIn("INVARIANTS", payload)
        self.assertIn("REVALIDATE", payload)
        self.assertIn("CONTEXT", payload)

    def test_revalidate_content_appears_and_is_charged(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "A digest matches",
                ClaimFreshness.DIGEST_BOUND,
                evidence_ids=("evidence-1",),
            )
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        self.assertIn("REVALIDATE", payload)
        self.assertIn("claim-1", payload)
        self.assertIn("fresh:STALE", payload)
        entry = [e for e in ctx.entries if e.record_id == "claim-1"][0]
        self.assertIs(entry.disposition, Disposition.REVALIDATE)
        self.assertEqual(ctx.budget.used_chars, len(payload))

    def test_report_level_reasons_appear_in_report_and_json_but_not_payload(self) -> None:
        ctx = compile_context(base_state())
        payload = render_payload(ctx)
        report = render_report(ctx)
        json_text = render_json(ctx)
        self.assertNotIn("NO_ACTIVE_TASK", payload)
        self.assertIn("NO_ACTIVE_TASK", report)
        self.assertIn("NO_ACTIVE_TASK", json_text)

    def test_adding_report_metadata_alone_cannot_influence_survival(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        before = {e.record_id: e for e in ctx.entries}
        # Diagnostic metadata exists only in the report view; it cannot
        # appear in the payload entry tuple at all.
        self.assertEqual(ctx.report_reasons, ())
        payload = render_payload(ctx)
        self.assertNotIn("report_reasons", payload)
        after = {e.record_id: e for e in ctx.entries}
        self.assertEqual(before, after)
        self.assertEqual(ctx.budget.used_chars, len(payload))


class OrderingTests(unittest.TestCase):
    def test_session_selection_key(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                claim("claim-1", "Implement context compiler", ClaimFreshness.DURABLE_UNTIL_SUPERSEDED),
                claim("claim-2", "Implement context compiler plus more", ClaimFreshness.DURABLE_UNTIL_SUPERSEDED),
            ),
        )
        ctx = compile_context(state)
        claim_entries = [e for e in ctx.entries if e.kind is RecordKind.CLAIM]
        self.assertEqual(
            [(e.band, -e.score, e.record_id) for e in claim_entries],
            sorted((e.band, -e.score, e.record_id) for e in claim_entries),
        )

    def test_handoff_selection_key(self) -> None:
        from evidline.context import _handoff_selection_key

        state = replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("task-2",),
                ),
                task("task-2", "Old done task", status=TaskStatus.DONE),
            ),
        )
        ctx = compile_context(state, profile=ContextProfile.HANDOFF)
        order = ctx.entries_in_selection_order()
        self.assertEqual(
            [_handoff_selection_key(e) for e in order],
            sorted(_handoff_selection_key(e) for e in order),
        )
        done = [e for e in order if e.record_id == "task-2"][0]
        self.assertEqual(done.band, 2)

    def test_handoff_revalidation_priority_within_band(self) -> None:
        from evidline.context import _handoff_selection_key

        state = replace(
            state_with_active_task(),
            claims=(
                claim("claim-1", "Context compiler is deterministic", ClaimFreshness.DIGEST_BOUND),
                claim("claim-2", "Context compiler is local", ClaimFreshness.DURABLE_UNTIL_SUPERSEDED),
            ),
        )
        ctx = compile_context(state, profile=ContextProfile.HANDOFF)
        claim_entries = [
            e for e in ctx.entries_in_selection_order() if e.kind is RecordKind.CLAIM
        ]
        # The pre-budget disposition rank (REVALIDATE=0, INCLUDED=1) puts
        # the digest-bound claim first within band 6.
        self.assertEqual(
            [e.record_id for e in claim_entries],
            ["claim-1", "claim-2"],
        )
        self.assertEqual(
            [_handoff_selection_key(e) for e in claim_entries],
            sorted(_handoff_selection_key(e) for e in claim_entries),
        )

    def test_payload_section_grouping_differs_from_selection_order(self) -> None:
        # The claim is linked through related_ids, so it is band 2 with
        # REVALIDATE disposition; the evidence is band 3.  The payload
        # regroups by section even though selection order differs.
        state = replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("dec-1", "claim-1"),
                ),
            ),
            claims=(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DIGEST_BOUND,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        lines = payload.splitlines()
        self.assertIn("INVARIANTS", lines)
        self.assertIn("REVALIDATE", lines)
        self.assertIn("CONTEXT", lines)
        self.assertLess(lines.index("REVALIDATE"), lines.index("CONTEXT"))
        self.assertLess(lines.index("INVARIANTS"), lines.index("REVALIDATE"))
        # The REVALIDATE section holds the band-2 claim even though the
        # band-3 evidence sorts before it in selection order.
        revalidate_section = lines[lines.index("REVALIDATE") + 1 : lines.index("CONTEXT")]
        self.assertTrue(any("[CLAIM claim-1]" in line for line in revalidate_section))

    def test_grouping_cannot_alter_survival_or_used_chars(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(claim("claim-1", "A digest matches", ClaimFreshness.DIGEST_BOUND, evidence_ids=("evidence-1",)),),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        grouped = ctx.entries_in_selection_order()
        regrouped = sorted(grouped, key=lambda e: e.kind.value)
        self.assertEqual({e.record_id for e in grouped}, {e.record_id for e in regrouped})
        self.assertEqual(ctx.budget.used_chars, len(payload))

    def test_report_candidate_order_follows_selection_order(self) -> None:
        state = replace(
            state_with_active_task(),
            decisions=(
                decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),
                decision("dec-2", "Extra authorized decision", Intent.AUTHORIZED),
            ),
        )
        ctx = compile_context(state)
        bands = [e.band for e in ctx.report_entries if e.disposition is not Disposition.EXCLUDED]
        self.assertEqual(bands, sorted(bands))

    def test_rule_excluded_report_order_is_deterministic(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(claim("claim-1", "zzz qqq", ClaimFreshness.DURABLE_UNTIL_SUPERSEDED),),
        )
        first = render_report(compile_context(state))
        second = render_report(compile_context(state))
        self.assertEqual(first, second)


class ReportReasonsTests(unittest.TestCase):
    def test_no_active_task_surfaced(self) -> None:
        ctx = compile_context(base_state())
        self.assertEqual(ctx.report_reasons, (ReasonCode.NO_ACTIVE_TASK,))

    def test_invariant_budget_overflow_surfaced(self) -> None:
        state = replace(state_with_active_task(), invariants=(invariant("inv-1"), invariant("inv-2")))
        minimum = minimum_budget_chars(ContextProfile.SESSION)
        ctx = compile_context(state, budget_chars=minimum)
        self.assertIn(ReasonCode.INVARIANT_BUDGET_OVERFLOW, ctx.report_reasons)

    def test_declaration_order_is_deterministic(self) -> None:
        ctx = compile_context(base_state())
        self.assertEqual(ctx.report_reasons, (ReasonCode.NO_ACTIVE_TASK,))
        self.assertLess(
            list(ReasonCode).index(ReasonCode.NO_ACTIVE_TASK),
            list(ReasonCode).index(ReasonCode.INVARIANT_BUDGET_OVERFLOW),
        )

    def test_partition_is_enforced(self) -> None:
        with self.assertRaises(AssertionError):
            ContextEntry(
                record_id="claim-1",
                kind=RecordKind.CLAIM,
                band=0,
                score=0,
                disposition=Disposition.INCLUDED,
                rendered_freshness="UNVERIFIED",
                reasons=(ReasonCode.NO_ACTIVE_TASK,),
            )
        with self.assertRaises(AssertionError):
            CompiledContext(
                schema_version=1,
                profile=ContextProfile.SESSION,
                state_revision=0,
                active_task_id=None,
                report_reasons=(ReasonCode.RULE_EXCLUDED,),
            )

    def test_empty_tuple_when_no_report_level_reason_applies(self) -> None:
        ctx = compile_context(state_with_active_task())
        self.assertEqual(ctx.report_reasons, ())


class HandoffTruthfulnessTests(unittest.TestCase):
    def test_linked_done_task_is_included_in_handoff(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("task-2",),
                ),
                task("task-2", "Old done task", status=TaskStatus.DONE),
            ),
        )
        session_ctx = compile_context(state, profile=ContextProfile.SESSION)
        handoff_ctx = compile_context(state, profile=ContextProfile.HANDOFF)
        self.assertNotIn("task-2", {e.record_id for e in session_ctx.entries})
        self.assertIn("task-2", {e.record_id for e in handoff_ctx.entries})

    def test_handoff_payload_contains_fixed_disclaimer(self) -> None:
        ctx = compile_context(state_with_active_task(), profile=ContextProfile.HANDOFF)
        payload = render_payload(ctx)
        self.assertIn(
            "unverified continuity representation, not a verified handoff",
            payload,
        )

    def test_handoff_claims_not_verified(self) -> None:
        ctx = compile_context(
            state_with_claim(
                claim(
                    "claim-1",
                    "Never promote unsupported claims",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                )
            ),
            profile=ContextProfile.HANDOFF,
        )
        self.assertNotIn("fresh:VERIFIED", render_payload(ctx))
        self.assertNotIn("freshness=VERIFIED", render_report(ctx))
        for entry in ctx.report_entries:
            self.assertNotEqual(entry.rendered_freshness, "VERIFIED")


class DeterminismAndPurityTests(unittest.TestCase):
    def test_repeated_compile_and_render_is_byte_identical(self) -> None:
        state = state_with_claim(
            claim(
                "claim-1",
                "A digest matches",
                ClaimFreshness.DIGEST_BOUND,
                evidence_ids=("evidence-1",),
            )
        )
        first = (
            render_payload(compile_context(state)),
            render_report(compile_context(state)),
            render_json(compile_context(state)),
        )
        for _ in range(5):
            self.assertEqual(
                first,
                (
                    render_payload(compile_context(state)),
                    render_report(compile_context(state)),
                    render_json(compile_context(state)),
                ),
            )

    def test_serialize_parse_round_trip_equivalent(self) -> None:
        state = state_with_active_task()
        ctx = compile_context(state)
        document = json.loads(render_json(ctx))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["state_revision"], 0)
        self.assertEqual(document["profile"], "session")
        self.assertEqual(len(document["records"]), len(state.invariants) + len(state.tasks) + len(state.decisions))

    def test_input_tuple_reordering_cannot_alter_semantic_total_order(self) -> None:
        base = replace(
            base_state(),
            tasks=(task("task-1", "Implement context compiler"),),
            decisions=(decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),),
        )
        reordered = replace(
            base,
            decisions=(decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),),
            tasks=(task("task-1", "Implement context compiler"),),
        )
        self.assertEqual(
            render_payload(compile_context(base)),
            render_payload(compile_context(reordered)),
        )

    def test_hash_and_set_iteration_cannot_leak_into_output(self) -> None:
        for _ in range(10):
            state = state_with_claim(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DIGEST_BOUND,
                    evidence_ids=("evidence-1",),
                )
            )
            first = render_json(compile_context(state))
            second = render_json(compile_context(state))
            self.assertEqual(first, second)

    def test_pure_compiler_performs_no_filesystem_io(self) -> None:
        state = state_with_active_task()
        with mock.patch(
            "pathlib.Path.read_text", side_effect=RuntimeError("fs read")
        ), mock.patch(
            "pathlib.Path.write_text", side_effect=RuntimeError("fs write")
        ), mock.patch(
            "pathlib.Path.open", side_effect=RuntimeError("fs open")
        ), mock.patch(
            "builtins.open", side_effect=RuntimeError("fs open")
        ):
            ctx = compile_context(state)
        self.assertIsNotNone(ctx)
        self.assertGreater(len(render_payload(ctx)), 0)

    def test_no_clock_dependency(self) -> None:
        for clock in ("evidline.context.time", "evidline.context.datetime"):
            with self.subTest(clock=clock):
                with mock.patch(
                    clock,
                    new=mock.Mock(side_effect=RuntimeError("clock accessed")),
                    create=True,
                ):
                    first = render_payload(compile_context(state_with_active_task()))
                    second = render_payload(compile_context(state_with_active_task()))
        self.assertEqual(first, second)


class WrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()

    def test_load_and_compile_discovers_root_and_compiles(self) -> None:
        from evidline.state import serialize_state

        state = state_with_active_task()
        (self.root / ".evidline").mkdir()
        (self.root / ".evidline" / "state.json").write_text(
            serialize_state(state), encoding="utf-8"
        )
        ctx = load_and_compile(self.root)
        self.assertEqual(ctx.state_revision, 0)
        self.assertIsInstance(ctx, CompiledContext)
        self.assertEqual(len(render_payload(ctx)), ctx.budget.used_chars)

    def test_load_and_compile_defaults_to_cwd(self) -> None:
        from evidline.state import serialize_state

        state = state_with_active_task()
        (self.root / ".evidline").mkdir()
        (self.root / ".evidline" / "state.json").write_text(
            serialize_state(state), encoding="utf-8"
        )
        original = Path.cwd()
        try:
            os.chdir(self.root)
            ctx = load_and_compile()
            self.assertIsInstance(ctx, CompiledContext)
        finally:
            os.chdir(original)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        from evidline.state import serialize_state

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        (self.root / ".evidline").mkdir()
        (self.root / ".evidline" / "state.json").write_text(
            serialize_state(state_with_active_task()), encoding="utf-8"
        )
        self.state_bytes = (self.root / ".evidline" / "state.json").read_bytes()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        from evidline.cli import main

        stdout = io.StringIO()
        stderr = io.StringIO()
        code = 0
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            with mock.patch("os.curdir", str(self.root)):
                try:
                    code = main(args)
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else 0
        return code, stdout.getvalue(), stderr.getvalue()

    def test_version_regression(self) -> None:
        code, stdout, stderr = self.run_cli("--version")
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), "0.0.0")

    def test_context_payload_success(self) -> None:
        code, stdout, stderr = self.run_cli("context")
        self.assertEqual(code, 0)
        self.assertIn("EVIDLINE CONTEXT", stdout)
        self.assertIn("task-1", stdout)

    def test_context_report_and_json_formats(self) -> None:
        for fmt in ("report", "json"):
            code, stdout, stderr = self.run_cli("context", "--format", fmt)
            self.assertEqual(code, 0)
            self.assertTrue(stdout)

    def test_context_handoff_profile(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--profile", "handoff")
        self.assertEqual(code, 0)
        self.assertIn("unverified continuity representation", stdout)

    def test_context_budget_option(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--budget", "1000")
        self.assertEqual(code, 0)
        self.assertTrue(stdout)

    def test_context_root_option(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("task-1", stdout)

    def test_budget_below_minimum_exits_6(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--budget", "1")
        self.assertEqual(code, 6)
        self.assertIn("invalid compiler input", stderr)

    def test_non_integer_budget_is_usage_error(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--budget", "not-a-number")
        self.assertEqual(code, 2)

    def test_state_not_initialized_exits_3(self) -> None:
        empty = Path(self.temporary.name) / "empty"
        empty.mkdir()
        code, stdout, stderr = self.run_cli("context", "--root", str(empty))
        self.assertEqual(code, 3)
        self.assertIn("state not initialized", stderr)

    def test_invalid_state_exits_4(self) -> None:
        (self.root / ".evidline" / "state.json").write_text(
            '{"schema_version": 1, "broken": true}', encoding="utf-8"
        )
        code, stdout, stderr = self.run_cli("context")
        self.assertEqual(code, 4)
        self.assertIn("invalid or unsupported state", stderr)

    def test_usage_error_exits_2(self) -> None:
        code, stdout, stderr = self.run_cli("context", "--nope")
        self.assertEqual(code, 2)

    def test_state_remains_byte_identical(self) -> None:
        self.run_cli("context")
        self.run_cli("context", "--format", "json")
        self.run_cli("context", "--format", "report")
        self.assertEqual(
            (self.root / ".evidline" / "state.json").read_bytes(), self.state_bytes
        )

    def test_no_temp_or_write_lock_created(self) -> None:
        self.run_cli("context")
        self.run_cli("context", "--format", "json")
        self.run_cli("context", "--format", "report")
        entries = list((self.root / ".evidline").iterdir())
        self.assertEqual([e.name for e in entries], ["state.json"])

    def test_journal_never_opened(self) -> None:
        with mock.patch("builtins.open") as opened:
            code, stdout, stderr = self.run_cli("context")
        self.assertEqual(code, 0)
        journal_calls = [
            call for call in opened.call_args_list if "journal" in str(call)
        ]
        self.assertEqual(journal_calls, [])


class F1EvidenceRecoveryTests(unittest.TestCase):
    def _linked_evidence_state(self) -> StateDocument:
        return replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("claim-1",),
                ),
            ),
            claims=(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DIGEST_BOUND,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )

    def test_claim_linked_evidence_is_included_at_band_3(self) -> None:
        ctx = compile_context(self._linked_evidence_state())
        entry = [e for e in ctx.entries if e.record_id == "evidence-1"][0]
        self.assertEqual(entry.band, 3)
        self.assertIs(entry.disposition, Disposition.INCLUDED)

    def test_evidence_stays_band_3_when_also_directly_linked(self) -> None:
        state = replace(
            self._linked_evidence_state(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("claim-1", "evidence-1"),
                ),
            ),
        )
        ctx = compile_context(state)
        entry = [e for e in ctx.entries if e.record_id == "evidence-1"][0]
        self.assertEqual(entry.band, 3)
        self.assertIs(entry.disposition, Disposition.INCLUDED)

    def test_directly_linked_unreferenced_evidence_is_excluded(self) -> None:
        state = replace(
            state_with_active_task(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"evidence": 1},
        )
        ctx = compile_context(state)
        self.assertNotIn("evidence-1", {e.record_id for e in ctx.entries})
        report_entry = [e for e in ctx.report_entries if e.record_id == "evidence-1"][0]
        self.assertIs(report_entry.disposition, Disposition.EXCLUDED)
        self.assertIn(ReasonCode.RULE_EXCLUDED, report_entry.reasons)

    def test_every_record_appears_exactly_once_in_report(self) -> None:
        state = replace(
            self._linked_evidence_state(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("claim-1", "evidence-1"),
                ),
            ),
        )
        ctx = compile_context(state)
        ids = [e.record_id for e in ctx.report_entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            len(ids),
            len(state.invariants)
            + len(state.tasks)
            + len(state.decisions)
            + len(state.claims)
            + len(state.evidence),
        )


class F2PayloadContentTests(unittest.TestCase):
    def test_task_status_rendered_and_single_anchor(self) -> None:
        state = replace(
            base_state(),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("task-2", "task-3"),
                ),
                task("task-2", "Draft follow-up", status=TaskStatus.DRAFT),
                task("task-3", "Finished task", status=TaskStatus.DONE),
            ),
        )
        ctx = compile_context(state, profile=ContextProfile.HANDOFF)
        payload = render_payload(ctx)
        self.assertIn("ACTIVE", payload)
        self.assertIn("DRAFT", payload)
        self.assertIn("DONE", payload)
        task_lines = [line for line in payload.splitlines() if line.startswith("[TASK")]
        anchor_lines = [line for line in task_lines if " anchor" in line]
        self.assertEqual(len(anchor_lines), 1)
        self.assertIn("task-1", anchor_lines[0])
        self.assertEqual(ctx.budget.used_chars, len(payload))

    def test_substantive_payload_content(self) -> None:
        state = replace(
            base_state(),
            invariants=(invariant("inv-1"),),
            tasks=(
                task(
                    "task-1",
                    "Implement context compiler",
                    related=("dec-1", "dec-denied", "claim-1"),
                ),
            ),
            decisions=(
                decision("dec-1", "Use local JSON state", Intent.AUTHORIZED),
                decision("dec-denied", "Reject remote backend", Intent.DENIED),
            ),
            claims=(
                claim(
                    "claim-1",
                    "A digest matches",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(
                Evidence(
                    id="evidence-1",
                    description="Observed digest output",
                    provenance=EvidenceProvenance.AGENT_ASSERTION,
                    execution=Execution.EXECUTED,
                ),
            ),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        self.assertIn("Implement context compiler", payload)
        self.assertIn("Never promote unsupported claims", payload)
        self.assertIn("BLOCK", payload)
        self.assertIn("Use local JSON state", payload)
        self.assertIn("AUTHORIZED", payload)
        self.assertIn("DENIED", payload)
        self.assertIn("A digest matches", payload)
        self.assertIn("fresh:UNVERIFIED", payload)
        self.assertIn("Observed digest output", payload)
        self.assertIn("AGENT_ASSERTION", payload)
        self.assertNotIn("EXECUTED", payload)
        self.assertEqual(ctx.budget.used_chars, len(payload))

    def test_normalization_and_no_section_injection(self) -> None:
        from evidline.context import _render_entry, _render_invariant

        state = replace(
            base_state(),
            invariants=(invariant("inv-1"),),
            tasks=(
                task(
                    "task-1",
                    "Implement\tcontext\ncompiler   carefully",
                    related=("dec-1", "claim-1"),
                ),
            ),
            decisions=(
                decision(
                    "dec-1",
                    "Use CONTEXT and [INVARIANT inv-9] markers",
                    Intent.AUTHORIZED,
                ),
            ),
            claims=(
                claim(
                    "claim-1",
                    "A digest\n\tmatches   with  spacing",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                    evidence_ids=("evidence-1",),
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        payload = render_payload(ctx)
        self.assertIn("Implement context compiler carefully", payload)
        self.assertIn("Use CONTEXT and [INVARIANT inv-9] markers", payload)
        self.assertIn("A digest matches with spacing", payload)
        lines = payload.splitlines()
        self.assertEqual(lines.count("INVARIANTS"), 1)
        self.assertEqual(lines.count("REVALIDATE"), 1)
        self.assertEqual(lines.count("CONTEXT"), 1)
        for entry in ctx.entries:
            block = (
                _render_invariant(entry)
                if entry.kind is RecordKind.INVARIANT
                else _render_entry(entry)
            )
            self.assertNotIn("\n", block)
            self.assertNotIn("\t", block)
        self.assertEqual(ctx.budget.used_chars, len(payload))


class F3JsonContractTests(unittest.TestCase):
    def test_records_key_and_no_entries_alias(self) -> None:
        state = replace(
            state_with_active_task(),
            claims=(
                claim(
                    "claim-1",
                    "zzz qqq",
                    ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
                ),
            ),
            evidence=(one_evidence(),),
            counters={"claim": 1, "evidence": 1},
        )
        ctx = compile_context(state)
        document = json.loads(render_json(ctx))
        self.assertEqual(len(document["records"]), len(ctx.report_entries))
        self.assertGreater(len(document["records"]), len(ctx.entries))
        self.assertNotIn("entries", document)


if __name__ == "__main__":
    unittest.main()
