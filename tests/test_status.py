from __future__ import annotations

import json
import unittest

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
    StateValidationError,
    Task,
    TaskStatus,
    Verification,
)
from evidline.status import (
    STATUS_SCHEMA_VERSION,
    StatusReport,
    render_status_json,
    render_status_text,
    summarize_state,
)


def populated_state(*, active_task: bool = True) -> StateDocument:
    evidence = Evidence(
        id="evidence-1",
        description="Observed output",
        provenance=EvidenceProvenance.TOOL_OUTPUT,
        execution=Execution.EXECUTED,
    )
    tasks = (
        Task(
            id="task-1",
            description="Phase 4",
            status=TaskStatus.ACTIVE if active_task else TaskStatus.DRAFT,
            intent=Intent.AUTHORIZED if active_task else Intent.PROPOSED,
            execution=Execution.NOT_RUN,
            approved_at="2026-08-16T00:00:00+04:00" if active_task else None,
            approval_channel="interactive" if active_task else None,
        ),
    )
    return StateDocument(
        schema_version=2,
        revision=4,
        project=Project("Evidline", "Local continuity", (), 8000),
        invariants=(
            Invariant(
                "inv-1",
                "Current rule",
                InvariantEnforcement.BLOCK,
                InvariantStatus.ACTIVE,
            ),
            Invariant(
                "inv-2",
                "Old rule",
                InvariantEnforcement.ADVISE,
                InvariantStatus.SUPERSEDED,
                superseded_by="inv-1",
                approved_at="2026-08-16T00:00:00+04:00",
                approval_channel="interactive",
            ),
        ),
        decisions=(
            Decision(
                "dec-1", "A proposal", Intent.PROPOSED, Execution.NOT_RUN
            ),
        ),
        tasks=tasks,
        claims=(
            Claim(
                "claim-1",
                "A claim",
                ClaimFreshness.DIGEST_BOUND,
                Verification.UNVERIFIED,
                True,
                evidence_ids=("evidence-1",),
            ),
        ),
        evidence=(evidence,),
        counters={},
    )


def report_for(state: StateDocument) -> StatusReport:
    return StatusReport(
        status=summarize_state(state),
        root="C:\\project",
        state_path="C:\\project\\.evidline\\state.json",
    )


class StatusTests(unittest.TestCase):
    def test_output_schema_version_is_one(self) -> None:
        self.assertEqual(STATUS_SCHEMA_VERSION, 1)

    def test_summarize_state_reports_active_task_invariants_and_counts(self) -> None:
        summary = summarize_state(populated_state())
        self.assertEqual(summary.active_task_id, "task-1")
        self.assertEqual(summary.active_invariants, 1)
        self.assertEqual(
            (
                summary.invariants,
                summary.decisions,
                summary.tasks,
                summary.claims,
                summary.evidence,
            ),
            (2, 1, 1, 1, 1),
        )

    def test_summarize_state_reports_no_active_task(self) -> None:
        self.assertIsNone(summarize_state(populated_state(active_task=False)).active_task_id)

    def test_summarize_state_uses_core_type_validation(self) -> None:
        with self.assertRaises(StateValidationError):
            summarize_state("not-state")

    def test_text_contract_order_and_trailing_newline(self) -> None:
        rendered = render_status_text(report_for(populated_state()))
        self.assertEqual(
            rendered.splitlines(),
            [
                "Evidline status",
                "root: C:\\project",
                "state: C:\\project\\.evidline\\state.json",
                "status_schema_version: 1",
                "state_schema_version: 2",
                "state_revision: 4",
                "project: Evidline",
                "default_budget_chars: 8000",
                "active_task: task-1",
                "invariants: 2 (active 1)",
                "decisions: 1",
                "tasks: 1",
                "claims: 1",
                "evidence: 1",
            ],
        )
        self.assertTrue(rendered.endswith("\n"))
        self.assertFalse(rendered.endswith("\n\n"))

    def test_text_uses_dash_without_active_task(self) -> None:
        self.assertIn(
            "active_task: -\n",
            render_status_text(report_for(populated_state(active_task=False))),
        )

    def test_json_has_exact_keys_and_counts_contract(self) -> None:
        payload = json.loads(render_status_json(report_for(populated_state())))
        self.assertEqual(
            set(payload),
            {
                "status_schema_version",
                "state_schema_version",
                "state_revision",
                "root",
                "state_path",
                "project_name",
                "default_budget_chars",
                "active_task_id",
                "active_invariants",
                "counts",
            },
        )
        self.assertEqual(
            set(payload["counts"]),
            {"invariants", "decisions", "tasks", "claims", "evidence"},
        )
        self.assertEqual(payload["active_task_id"], "task-1")
        self.assertEqual(payload["active_invariants"], 1)

    def test_json_null_and_renderers_are_repeatable(self) -> None:
        report = report_for(populated_state(active_task=False))
        first_json = render_status_json(report)
        self.assertIsNone(json.loads(first_json)["active_task_id"])
        self.assertEqual(first_json, render_status_json(report))
        self.assertEqual(
            render_status_text(report),
            render_status_text(report),
        )


if __name__ == "__main__":
    unittest.main()
