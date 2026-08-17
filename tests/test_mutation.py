from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from evidline.mutation import (
    MUTATION_SCHEMA_VERSION,
    MutationDecision,
    MutationInputError,
    MutationOperation,
    MutationOutcome,
    MutationReason,
    MutationRequest,
    MutationRisk,
    _NEXT_STEP_PRIORITY,
    _select_next_step,
    decide_mutation,
    evaluate_and_decide,
    explain,
    load_and_decide,
    render_decision_json,
)
from evidline.paths import PathEvaluation, ScopePathSemantics, host_scope_semantics
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
    StateNotInitializedError,
    StateValidationError,
    Task,
    TaskStatus,
    TRUSTED_APPROVAL_CHANNEL,
    TRUSTED_ASSERTED_ACTOR,
    Verification,
    serialize_state,
)

APPROVED_AT = "2026-08-15T00:00:00+04:00"
APPROVAL_CHANNEL = "interactive"


def make_state(
    *,
    tasks: tuple[Task, ...] = (),
    decisions: tuple[Decision, ...] = (),
    claims: tuple[Claim, ...] = (),
    evidence: tuple[Evidence, ...] = (),
    invariants: tuple[Invariant, ...] = (),
) -> StateDocument:
    return StateDocument(
        schema_version=4,
        revision=0,
        project=Project(
            name="Evidline",
            purpose="Verified local continuity",
            ignore_globs=(),
            default_budget_chars=9000,
        ),
        invariants=invariants,
        decisions=decisions,
        tasks=tasks,
        claims=claims,
        evidence=evidence,
        counters={},
    )


def make_task(
    status: TaskStatus = TaskStatus.ACTIVE,
    task_id: str = "task-1",
    *,
    authorized_scope: tuple[str, ...] = (),
    approval_channel: str = APPROVAL_CHANNEL,
    asserted_actor: str | None = None,
    acknowledged_invariant_ids: tuple[str, ...] = (),
) -> Task:
    return Task(
        id=task_id,
        description="Active work",
        status=status,
        intent=Intent.AUTHORIZED,
        execution=Execution.EXECUTED,
        authorized_scope=authorized_scope,
        approved_at=APPROVED_AT,
        approval_channel=approval_channel,
        asserted_actor=asserted_actor,
        acknowledged_invariant_ids=acknowledged_invariant_ids,
    )


def make_trusted_task(
    status: TaskStatus = TaskStatus.ACTIVE,
    *,
    authorized_scope: tuple[str, ...] = ("src",),
    acknowledged_invariant_ids: tuple[str, ...] = (),
) -> Task:
    return make_task(
        status,
        authorized_scope=authorized_scope,
        approval_channel=TRUSTED_APPROVAL_CHANNEL,
        asserted_actor=TRUSTED_ASSERTED_ACTOR,
        acknowledged_invariant_ids=acknowledged_invariant_ids,
    )


def make_decision(
    intent: Intent, decision_id: str = "dec-1", execution: Execution = Execution.NOT_RUN
) -> Decision:
    return Decision(
        id=decision_id,
        description="Authorized choice",
        intent=intent,
        execution=execution,
        approved_at=APPROVED_AT,
        approval_channel=APPROVAL_CHANNEL,
    )


def make_claim(
    *,
    verification: Verification = Verification.UNVERIFIED,
    reproducible: bool = True,
    evidence_ids: tuple[str, ...] = ("evidence-1",),
    claim_id: str = "claim-1",
) -> Claim:
    return Claim(
        id=claim_id,
        description="Supporting claim",
        freshness=ClaimFreshness.DIGEST_BOUND,
        verification=verification,
        reproducible=reproducible,
        evidence_ids=evidence_ids,
    )


def make_evidence(
    execution: Execution = Execution.EXECUTED,
    evidence_id: str = "evidence-1",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        description="Observed output",
        provenance=EvidenceProvenance.DIRECT_OBSERVATION,
        execution=execution,
    )


def make_invariant(
    invariant_id: str,
    enforcement: InvariantEnforcement,
    status: InvariantStatus,
    superseded_by: str | None = None,
    governed_scope: tuple[str, ...] = (),
) -> Invariant:
    return Invariant(
        id=invariant_id,
        description="A durable constraint",
        enforcement=enforcement,
        status=status,
        superseded_by=superseded_by,
        approved_at=APPROVED_AT if status is InvariantStatus.SUPERSEDED else None,
        approval_channel=(
            APPROVAL_CHANNEL if status is InvariantStatus.SUPERSEDED else None
        ),
        governed_scope=governed_scope,
    )


def safe_eval(target: str = "src/file.txt") -> PathEvaluation:
    return PathEvaluation(True, Path("proj"), Path("proj") / target, None)


def unsafe_eval() -> PathEvaluation:
    return PathEvaluation(
        False, Path("proj"), Path("outside") / "file.txt", "outside root"
    )


def protected_eval(component: str = ".git") -> PathEvaluation:
    return PathEvaluation(
        False, Path("proj"), Path("proj") / component / "item", "protected"
    )


def make_request(intent: Intent, risk: MutationRisk, **kwargs) -> MutationRequest:
    return MutationRequest(request_intent=intent, risk=risk, **kwargs)


class LowRiskTests(unittest.TestCase):
    def test_requested_without_active_task_allows(self) -> None:
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.next_step, "")
        self.assertEqual(decision.target, str(Path("proj") / "src/file.txt"))

    def test_authorized_without_active_task_allows(self) -> None:
        decision = decide_mutation(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)

    def test_proposed_asks(self) -> None:
        decision = decide_mutation(
            make_request(Intent.PROPOSED, MutationRisk.LOW),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ASK)
        self.assertIn(MutationReason.REQUEST_INTENT_INSUFFICIENT, decision.reasons)

    def test_denied_blocks(self) -> None:
        decision = decide_mutation(
            make_request(Intent.DENIED, MutationRisk.LOW),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.REQUEST_INTENT_DENIED, decision.reasons)

    def test_authorizing_ids_ignored_for_ceremony(self) -> None:
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW, authorizing_ids=("bogus",)),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)


class NormalRiskTests(unittest.TestCase):
    def test_no_active_task_asks(self) -> None:
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.NORMAL),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ASK)
        self.assertIn(MutationReason.NO_ACTIVE_TASK, decision.reasons)

    def test_active_task_allows(self) -> None:
        state = make_state(tasks=(make_task(),))
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.NORMAL),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())

    def test_supplied_insufficient_authorizing_id_blocks(self) -> None:
        state = make_state(tasks=(make_task(),))
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.NORMAL,
                authorizing_ids=("dec-missing",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INSUFFICIENT_AUTHORIZATION, decision.reasons)


class DerivedAuthorizationTests(unittest.TestCase):
    def decide(
        self,
        *,
        task: Task | None = None,
        target: str = "src/file.txt",
        request: MutationRequest | None = None,
        evaluation: PathEvaluation | None = None,
        invariants: tuple[Invariant, ...] = (),
    ) -> MutationDecision:
        return decide_mutation(
            request or make_request(Intent.PROPOSED, MutationRisk.NORMAL),
            evaluation or safe_eval(target),
            make_state(tasks=(() if task is None else (task,)), invariants=invariants),
        )

    def test_matching_trusted_active_task_derives_authority(self) -> None:
        decision = self.decide(task=make_trusted_task())
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_outside_or_empty_scope_does_not_derive(self) -> None:
        for task in (
            make_trusted_task(authorized_scope=("docs",)),
            make_trusted_task(authorized_scope=()),
        ):
            with self.subTest(scope=task.authorized_scope):
                decision = self.decide(task=task)
                self.assertEqual(decision.outcome, MutationOutcome.ASK)
                self.assertIn(
                    MutationReason.REQUEST_INTENT_INSUFFICIENT, decision.reasons
                )
                self.assertIsNone(decision.authorizing_task_id)

    def test_untrusted_channel_or_actor_does_not_derive(self) -> None:
        for task in (
            make_task(
                authorized_scope=("src",),
                approval_channel="caller-asserted",
                asserted_actor=TRUSTED_ASSERTED_ACTOR,
            ),
            make_task(
                authorized_scope=("src",),
                approval_channel=TRUSTED_APPROVAL_CHANNEL,
                asserted_actor="agent",
            ),
        ):
            with self.subTest(channel=task.approval_channel, actor=task.asserted_actor):
                decision = self.decide(task=task)
                self.assertEqual(decision.outcome, MutationOutcome.ASK)
                self.assertIsNone(decision.authorizing_task_id)

    def test_non_active_task_does_not_derive(self) -> None:
        for status in (TaskStatus.DRAFT, TaskStatus.DONE):
            with self.subTest(status=status):
                decision = self.decide(task=make_trusted_task(status))
                self.assertNotEqual(decision.outcome, MutationOutcome.ALLOW)
                self.assertIsNone(decision.authorizing_task_id)

    def test_denied_intent_still_blocks(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(Intent.DENIED, MutationRisk.NORMAL),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.REQUEST_INTENT_DENIED, decision.reasons)
        self.assertIsNone(decision.authorizing_task_id)

    def test_caller_authorized_intent_is_not_recorded_as_derived_authority(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(Intent.AUTHORIZED, MutationRisk.NORMAL),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertIsNone(decision.authorizing_task_id)

    def test_derived_authority_does_not_validate_bad_caller_authorizing_ids(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(
                Intent.PROPOSED,
                MutationRisk.NORMAL,
                authorizing_ids=("dec-missing",),
            ),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INSUFFICIENT_AUTHORIZATION, decision.reasons)
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_derived_authority_does_not_bypass_high_evidence(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(
                Intent.PROPOSED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
            ),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertNotIn(MutationReason.REQUEST_INTENT_INSUFFICIENT, decision.reasons)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_derived_authority_does_not_bypass_critical_risk(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(Intent.PROPOSED, MutationRisk.CRITICAL),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.CRITICAL_RISK, decision.reasons)
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_derived_authority_does_not_bypass_invariant_conflict(self) -> None:
        invariant = make_invariant(
            "inv-block", InvariantEnforcement.BLOCK, InvariantStatus.ACTIVE
        )
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(
                Intent.PROPOSED,
                MutationRisk.NORMAL,
                asserted_conflicting_invariant_ids=("inv-block",),
            ),
            invariants=(invariant,),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INVARIANT_CONFLICT, decision.reasons)
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_derived_authority_cannot_widen_declared_scope(self) -> None:
        decision = self.decide(
            task=make_trusted_task(),
            request=make_request(
                Intent.PROPOSED,
                MutationRisk.NORMAL,
                declared_scope=("docs",),
            ),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    def test_protected_and_out_of_root_targets_never_derive(self) -> None:
        cases = (
            (protected_eval(".git"), (".git",)),
            (protected_eval(".evidline"), (".evidline",)),
            (unsafe_eval(), (".",)),
        )
        for evaluation, scope in cases:
            with self.subTest(target=evaluation.canonical_target):
                decision = self.decide(
                    task=make_trusted_task(authorized_scope=scope),
                    evaluation=evaluation,
                )
                self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
                self.assertIsNone(decision.authorizing_task_id)

    def test_canonical_target_is_matched_instead_of_raw_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            (root / ".evidline").mkdir(parents=True)
            (root / "src").mkdir()
            (root / "docs").mkdir()
            target = root / "docs" / "file.txt"
            target.write_text("x", encoding="utf-8")
            decision = evaluate_and_decide(
                make_request(Intent.PROPOSED, MutationRisk.NORMAL),
                root,
                "src/../docs/file.txt",
                make_state(tasks=(make_trusted_task(authorized_scope=("docs",)),)),
            )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.authorizing_task_id, "task-1")

    def test_authorizing_task_metadata_is_rendered(self) -> None:
        decision = self.decide(task=make_trusted_task())
        self.assertIn("authorizing_task_id: task-1\n", explain(decision))
        self.assertEqual(
            json.loads(render_decision_json(decision))["authorizing_task_id"],
            "task-1",
        )
        unrelated = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW), safe_eval(), make_state()
        )
        self.assertIsNone(
            json.loads(render_decision_json(unrelated))["authorizing_task_id"]
        )


class HighRiskTests(unittest.TestCase):
    def _satisfied_state(self) -> StateDocument:
        return make_state(
            tasks=(make_task(),),
            claims=(make_claim(),),
            evidence=(make_evidence(),),
        )

    def test_no_active_task_blocks(self) -> None:
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.HIGH),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.NO_ACTIVE_TASK, decision.reasons)

    def test_proposed_blocks(self) -> None:
        state = self._satisfied_state()
        decision = decide_mutation(
            make_request(
                Intent.PROPOSED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.REQUEST_INTENT_INSUFFICIENT, decision.reasons)

    def test_missing_supporting_claim_blocks(self) -> None:
        state = make_state(tasks=(make_task(),))
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_uncovered_evidence_blocks(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(),),
            evidence=(make_evidence(),),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_persisted_stale_claim_is_rejected_as_invalid_state(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(verification=Verification.STALE),),
            evidence=(make_evidence(),),
        )
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(
                    Intent.REQUESTED,
                    MutationRisk.HIGH,
                    authorizing_ids=("task-1",),
                    supporting_claim_ids=("claim-1",),
                    ephemeral_evidence_ids=("evidence-1",),
                ),
                safe_eval(),
                state,
            )

    def test_failed_claim_blocks(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(verification=Verification.FAILED),),
            evidence=(make_evidence(),),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_non_reproducible_claim_blocks(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(reproducible=False),),
            evidence=(make_evidence(),),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_conflicting_failed_evidence_blocks(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(),),
            evidence=(make_evidence(execution=Execution.FAILED),),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_fully_satisfied_high_asks(self) -> None:
        state = self._satisfied_state()
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ASK)
        self.assertEqual(decision.reasons, ())

    def test_authorizing_decision_authorized_satisfies_high(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            decisions=(make_decision(Intent.AUTHORIZED),),
            claims=(make_claim(),),
            evidence=(make_evidence(),),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("dec-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ASK)

    def test_unresolved_support_alongside_valid_support_blocks(self) -> None:
        state = self._satisfied_state()
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1", "claim-missing"),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_failed_support_blocks_in_both_tuple_orders(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(
                make_claim(claim_id="claim-1", evidence_ids=("evidence-1",)),
                make_claim(
                    claim_id="claim-2",
                    verification=Verification.FAILED,
                    evidence_ids=("evidence-2",),
                ),
            ),
            evidence=(
                make_evidence(evidence_id="evidence-1"),
                make_evidence(evidence_id="evidence-2"),
            ),
        )
        for supporting_claim_ids in (
            ("claim-1", "claim-2"),
            ("claim-2", "claim-1"),
        ):
            with self.subTest(supporting_claim_ids=supporting_claim_ids):
                decision = decide_mutation(
                    make_request(
                        Intent.REQUESTED,
                        MutationRisk.HIGH,
                        authorizing_ids=("task-1",),
                        supporting_claim_ids=supporting_claim_ids,
                        ephemeral_evidence_ids=("evidence-1", "evidence-2"),
                    ),
                    safe_eval(),
                    state,
                )
                self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
                self.assertIn(
                    MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons
                )

    def test_ephemeral_execution_matrix(self) -> None:
        for execution, expected_outcome in (
            (Execution.NOT_RUN, MutationOutcome.ASK),
            (Execution.EXECUTED, MutationOutcome.ASK),
            (Execution.FAILED, MutationOutcome.BLOCK),
            (Execution.BLOCKED, MutationOutcome.BLOCK),
        ):
            with self.subTest(execution=execution):
                state = make_state(
                    tasks=(make_task(),),
                    claims=(make_claim(),),
                    evidence=(make_evidence(execution=execution),),
                )
                decision = decide_mutation(
                    make_request(
                        Intent.REQUESTED,
                        MutationRisk.HIGH,
                        authorizing_ids=("task-1",),
                        supporting_claim_ids=("claim-1",),
                        ephemeral_evidence_ids=("evidence-1",),
                    ),
                    safe_eval(),
                    state,
                )
                self.assertEqual(decision.outcome, expected_outcome)
                if execution in (Execution.FAILED, Execution.BLOCKED):
                    self.assertIn(
                        MutationReason.HIGH_EVIDENCE_INSUFFICIENT,
                        decision.reasons,
                    )
                else:
                    self.assertNotIn(
                        MutationReason.HIGH_EVIDENCE_INSUFFICIENT,
                        decision.reasons,
                    )

    def test_extra_unresolved_ephemeral_evidence_is_neutral(self) -> None:
        state = self._satisfied_state()
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1", "evidence-missing"),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ASK)
        self.assertNotIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)


class BoundaryTests(unittest.TestCase):
    def test_outside_root_blocks(self) -> None:
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            unsafe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_UNSAFE, decision.reasons)

    def test_git_metadata_is_critical_block(self) -> None:
        decision = decide_mutation(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            protected_eval(".git"),
            make_state(),
        )
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_evidline_metadata_is_critical_block(self) -> None:
        decision = decide_mutation(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            protected_eval(".evidline"),
            make_state(),
        )
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_intent_never_overrides_protection(self) -> None:
        decision = decide_mutation(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            protected_eval(".git"),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)

    def test_synthetic_nested_protected_evaluation_blocks(self) -> None:
        evaluation = PathEvaluation(
            False,
            Path("proj"),
            Path("proj") / "vendor/.git/config",
            "protected",
        )
        decision = decide_mutation(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            evaluation,
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_declared_critical_risk_blocks_all_intents(self) -> None:
        for intent in (
            Intent.PROPOSED,
            Intent.REQUESTED,
            Intent.AUTHORIZED,
            Intent.DENIED,
        ):
            with self.subTest(intent=intent):
                decision = decide_mutation(
                    make_request(intent, MutationRisk.CRITICAL),
                    safe_eval(),
                    make_state(),
                )
                self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
                self.assertEqual(decision.risk, MutationRisk.CRITICAL)
                self.assertIn(MutationReason.CRITICAL_RISK, decision.reasons)


class ScopeTests(unittest.TestCase):
    def test_outside_declared_scope_blocks(self) -> None:
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=("docs",),
            ),
            safe_eval("src/file.txt"),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    def test_inside_declared_scope_passes(self) -> None:
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=("src",),
            ),
            safe_eval("src/file.txt"),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)

    def test_parent_scope_is_violation(self) -> None:
        for scope in ("..", "src/../.."):
            with self.subTest(scope=scope):
                decision = decide_mutation(
                    make_request(
                        Intent.REQUESTED,
                        MutationRisk.LOW,
                        declared_scope=(scope,),
                    ),
                    safe_eval(),
                    make_state(),
                )
                self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
                self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    def test_filesystem_root_scope_is_violation(self) -> None:
        root = Path.cwd() / "project"
        evaluation = PathEvaluation(True, root, root / "src/file.txt", None)
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=(root.anchor,),
            ),
            evaluation,
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    def test_character_prefix_does_not_establish_scope(self) -> None:
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=("src",),
            ),
            safe_eval("src-evil/file.txt"),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    @unittest.skipUnless(os.name == "nt", "Windows drive semantics")
    def test_different_windows_drive_scope_is_violation(self) -> None:
        evaluation = PathEvaluation(
            True,
            Path("C:/project"),
            Path("C:/project/src/file.txt"),
            None,
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=("D:/scope",),
            ),
            evaluation,
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.SCOPE_VIOLATION, decision.reasons)

    def test_scope_equal_to_canonical_root_passes(self) -> None:
        root = Path.cwd() / "project"
        evaluation = PathEvaluation(True, root, root / "src/file.txt", None)
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                declared_scope=(str(root),),
            ),
            evaluation,
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)


class InvariantTests(unittest.TestCase):
    def test_active_block_asserted_blocks(self) -> None:
        state = make_state(
            invariants=(
                make_invariant("inv-block", InvariantEnforcement.BLOCK, InvariantStatus.ACTIVE),
            )
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                asserted_conflicting_invariant_ids=("inv-block",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INVARIANT_CONFLICT, decision.reasons)
        self.assertEqual(decision.conflicting_invariant_ids, ("inv-block",))

    def test_active_advise_asserted_does_not_escalate(self) -> None:
        state = make_state(
            invariants=(
                make_invariant("inv-advise", InvariantEnforcement.ADVISE, InvariantStatus.ACTIVE),
            )
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                asserted_conflicting_invariant_ids=("inv-advise",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())
        self.assertIn("inv-advise", decision.advisory_invariant_ids)
        self.assertEqual(decision.conflicting_invariant_ids, ())

    def test_superseded_has_no_effect(self) -> None:
        state = make_state(
            invariants=(
                make_invariant("inv-block", InvariantEnforcement.BLOCK, InvariantStatus.ACTIVE),
                make_invariant(
                    "inv-old",
                    InvariantEnforcement.BLOCK,
                    InvariantStatus.SUPERSEDED,
                    superseded_by="inv-block",
                ),
            )
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                asserted_conflicting_invariant_ids=("inv-old",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.conflicting_invariant_ids, ())
        self.assertNotIn("inv-old", decision.applicable_invariant_ids)

    def test_unresolved_asserted_invariant_blocks(self) -> None:
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                asserted_conflicting_invariant_ids=("inv-missing",),
            ),
            safe_eval(),
            make_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INVARIANT_UNRESOLVED, decision.reasons)

    def test_invariant_advisory_reason_is_absent(self) -> None:
        for reason in MutationReason:
            self.assertNotIn("INVARIANT_ADVISORY", reason.value)

    def test_applicable_ids_expose_active_block_invariants_sorted(self) -> None:
        state = make_state(
            invariants=(
                make_invariant("inv-b", InvariantEnforcement.BLOCK, InvariantStatus.ACTIVE),
                make_invariant("inv-a", InvariantEnforcement.BLOCK, InvariantStatus.ACTIVE),
                make_invariant("inv-advise", InvariantEnforcement.ADVISE, InvariantStatus.ACTIVE),
            )
        )
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.applicable_invariant_ids, ("inv-a", "inv-b"))
        self.assertEqual(decision.advisory_invariant_ids, ("inv-advise",))


class InvariantScopeBindingTests(unittest.TestCase):
    def block(
        self,
        invariant_id: str = "inv-block",
        scope: tuple[str, ...] = ("src",),
    ) -> Invariant:
        return make_invariant(
            invariant_id,
            InvariantEnforcement.BLOCK,
            InvariantStatus.ACTIVE,
            governed_scope=scope,
        )

    def test_no_match_advise_and_superseded_are_non_blocking(self) -> None:
        no_match = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(invariants=(self.block(scope=("docs",)),)),
        )
        self.assertEqual(no_match.outcome, MutationOutcome.ALLOW)
        self.assertEqual(no_match.unacknowledged_invariant_ids, ())

        advise = make_invariant(
            "inv-advise",
            InvariantEnforcement.ADVISE,
            InvariantStatus.ACTIVE,
            governed_scope=("src",),
        )
        advised = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(invariants=(advise,)),
        )
        self.assertEqual(advised.outcome, MutationOutcome.ALLOW)
        self.assertEqual(advised.advisory_invariant_ids, ("inv-advise",))
        self.assertEqual(advised.unacknowledged_invariant_ids, ())

        current = self.block("inv-current", ())
        old = make_invariant(
            "inv-old",
            InvariantEnforcement.BLOCK,
            InvariantStatus.SUPERSEDED,
            superseded_by="inv-current",
            governed_scope=("src",),
        )
        superseded = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(invariants=(current, old)),
        )
        self.assertEqual(superseded.outcome, MutationOutcome.ALLOW)
        self.assertEqual(superseded.unacknowledged_invariant_ids, ())

    def test_active_block_requires_trusted_task_acknowledgement(self) -> None:
        invariant = self.block()
        unacknowledged = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(invariants=(invariant,)),
        )
        self.assertEqual(unacknowledged.outcome, MutationOutcome.BLOCK)
        self.assertEqual(
            unacknowledged.reasons,
            (MutationReason.INVARIANT_UNACKNOWLEDGED,),
        )
        self.assertEqual(
            unacknowledged.unacknowledged_invariant_ids,
            ("inv-block",),
        )

        task = make_trusted_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-block",),
        )
        acknowledged = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(tasks=(task,), invariants=(invariant,)),
        )
        self.assertEqual(acknowledged.outcome, MutationOutcome.ALLOW)
        self.assertEqual(acknowledged.unacknowledged_invariant_ids, ())

    def test_multiple_matches_report_every_unacknowledged_id_sorted(self) -> None:
        invariants = (self.block("inv-z"), self.block("inv-a"))
        task = make_trusted_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-z",),
        )
        decision = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(tasks=(task,), invariants=invariants),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertEqual(decision.unacknowledged_invariant_ids, ("inv-a",))
        self.assertEqual(decision.applicable_invariant_ids, ("inv-a", "inv-z"))

    def test_vab1_authority_and_vab2_block_are_independent(self) -> None:
        task = make_trusted_task(authorized_scope=("src",))
        decision = decide_mutation(
            make_request(Intent.PROPOSED, MutationRisk.NORMAL),
            safe_eval(),
            make_state(tasks=(task,), invariants=(self.block(),)),
        )
        self.assertEqual(decision.authorizing_task_id, "task-1")
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertNotIn(
            MutationReason.REQUEST_INTENT_INSUFFICIENT,
            decision.reasons,
        )
        self.assertIn(MutationReason.INVARIANT_UNACKNOWLEDGED, decision.reasons)

    def test_acknowledgement_never_suppresses_asserted_conflict(self) -> None:
        invariant = self.block()
        task = make_trusted_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-block",),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.LOW,
                asserted_conflicting_invariant_ids=("inv-block",),
            ),
            safe_eval(),
            make_state(tasks=(task,), invariants=(invariant,)),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INVARIANT_CONFLICT, decision.reasons)
        self.assertEqual(decision.conflicting_invariant_ids, ("inv-block",))
        self.assertEqual(decision.unacknowledged_invariant_ids, ())

    def test_existing_stronger_gates_remain_monotonic(self) -> None:
        invariant = self.block()
        task = make_trusted_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-block",),
        )
        state = make_state(tasks=(task,), invariants=(invariant,))
        cases = (
            (
                make_request(Intent.DENIED, MutationRisk.LOW),
                safe_eval(),
                MutationReason.REQUEST_INTENT_DENIED,
            ),
            (
                make_request(Intent.REQUESTED, MutationRisk.CRITICAL),
                safe_eval(),
                MutationReason.CRITICAL_RISK,
            ),
            (
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                protected_eval(),
                MutationReason.TARGET_PROTECTED,
            ),
            (
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                unsafe_eval(),
                MutationReason.TARGET_UNSAFE,
            ),
        )
        for request, evaluation, reason in cases:
            with self.subTest(reason=reason):
                decision = decide_mutation(request, evaluation, state)
                self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
                self.assertIn(reason, decision.reasons)

        denied_unacknowledged = decide_mutation(
            make_request(Intent.DENIED, MutationRisk.LOW),
            safe_eval(),
            make_state(invariants=(invariant,)),
        )
        self.assertEqual(
            denied_unacknowledged.reasons,
            (
                MutationReason.REQUEST_INTENT_DENIED,
                MutationReason.INVARIANT_UNACKNOWLEDGED,
            ),
        )

    def test_missing_or_untrusted_active_task_cannot_acknowledge(self) -> None:
        invariant = self.block()
        no_task = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.NORMAL),
            safe_eval(),
            make_state(invariants=(invariant,)),
        )
        self.assertEqual(no_task.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.NO_ACTIVE_TASK, no_task.reasons)
        self.assertIn(MutationReason.INVARIANT_UNACKNOWLEDGED, no_task.reasons)

        untrusted = make_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-block",),
        )
        ignored = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(tasks=(untrusted,), invariants=(invariant,)),
        )
        self.assertEqual(ignored.outcome, MutationOutcome.BLOCK)
        self.assertEqual(
            ignored.unacknowledged_invariant_ids,
            ("inv-block",),
        )

    def test_low_requested_match_still_blocks_and_outcome_never_decreases(self) -> None:
        request = make_request(Intent.REQUESTED, MutationRisk.LOW)
        baseline = decide_mutation(
            request,
            safe_eval(),
            make_state(invariants=(self.block(scope=()),)),
        )
        governed = decide_mutation(
            request,
            safe_eval(),
            make_state(invariants=(self.block(),)),
        )
        self.assertEqual(baseline.outcome, MutationOutcome.ALLOW)
        self.assertEqual(governed.outcome, MutationOutcome.BLOCK)

    def test_incompatible_or_malformed_state_never_reaches_scope_matching(self) -> None:
        invariant = self.block()
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        incompatible = replace(
            make_state(invariants=(invariant,)),
            scope_semantics=foreign,
        )
        with mock.patch(
            "evidline.mutation._paths.canonical_target_in_authorized_scope"
        ) as matcher:
            with self.assertRaises(MutationInputError):
                decide_mutation(
                    make_request(Intent.REQUESTED, MutationRisk.LOW),
                    safe_eval(),
                    incompatible,
                )
        matcher.assert_not_called()

        malformed_task = make_trusted_task(
            authorized_scope=(),
            acknowledged_invariant_ids=("inv-missing",),
        )
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                make_state(tasks=(malformed_task,), invariants=(invariant,)),
            )

    def test_vab2_ids_and_rendering_are_deterministic_and_distinct(self) -> None:
        invariants = (self.block("inv-z"), self.block("inv-a"))
        request = make_request(Intent.DENIED, MutationRisk.LOW)
        first = decide_mutation(
            request,
            safe_eval(),
            make_state(invariants=invariants),
        )
        second = decide_mutation(
            request,
            safe_eval(),
            make_state(invariants=invariants),
        )
        self.assertEqual(first, second)
        self.assertEqual(first.unacknowledged_invariant_ids, ("inv-a", "inv-z"))
        self.assertEqual(first.conflicting_invariant_ids, ())
        self.assertIn(
            "unacknowledged_invariant_ids: [inv-a, inv-z]",
            explain(first),
        )
        self.assertEqual(
            json.loads(render_decision_json(first))[
                "unacknowledged_invariant_ids"
            ],
            ["inv-a", "inv-z"],
        )


class SemanticSeparationTests(unittest.TestCase):
    def test_execution_executed_never_authorizes(self) -> None:
        decision = make_decision(Intent.REQUESTED, execution=Execution.EXECUTED)
        state = make_state(
            tasks=(make_task(),),
            decisions=(decision,),
            claims=(make_claim(),),
            evidence=(make_evidence(),),
        )
        result = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("dec-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(result.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INSUFFICIENT_AUTHORIZATION, result.reasons)

    def test_provenance_never_verifies(self) -> None:
        state = make_state(
            tasks=(make_task(),),
            claims=(make_claim(verification=Verification.FAILED),),
            evidence=(
                Evidence(
                    id="evidence-1",
                    description="Asserted output",
                    provenance=EvidenceProvenance.HUMAN_ASSERTION,
                    execution=Execution.EXECUTED,
                ),
            ),
        )
        decision = decide_mutation(
            make_request(
                Intent.REQUESTED,
                MutationRisk.HIGH,
                authorizing_ids=("task-1",),
                supporting_claim_ids=("claim-1",),
                ephemeral_evidence_ids=("evidence-1",),
            ),
            safe_eval(),
            state,
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.HIGH_EVIDENCE_INSUFFICIENT, decision.reasons)

    def test_no_permission_field_participates(self) -> None:
        self.assertFalse(hasattr(MutationRequest("x", MutationRisk.LOW), "permission"))
        with self.assertRaises(TypeError):
            MutationRequest(
                request_intent=Intent.REQUESTED, risk=MutationRisk.LOW, permission=True
            )
        rendered = render_decision_json(
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                make_state(),
            )
        )
        self.assertNotIn("permission", json.loads(rendered))


class DeterminismTests(unittest.TestCase):
    def _request(self) -> MutationRequest:
        return make_request(
            Intent.DENIED,
            MutationRisk.HIGH,
            authorizing_ids=("bogus",),
        )

    def test_repeated_decisions_identical(self) -> None:
        first = decide_mutation(self._request(), safe_eval(), make_state())
        second = decide_mutation(self._request(), safe_eval(), make_state())
        self.assertEqual(first, second)

    def test_repeated_rendering_identical(self) -> None:
        first = decide_mutation(self._request(), safe_eval(), make_state())
        second = decide_mutation(self._request(), safe_eval(), make_state())
        self.assertEqual(explain(first), explain(second))

    def test_repeated_json_byte_identical(self) -> None:
        first = decide_mutation(self._request(), safe_eval(), make_state())
        second = decide_mutation(self._request(), safe_eval(), make_state())
        first_rendered = render_decision_json(first)
        second_rendered = render_decision_json(second)
        self.assertEqual(first_rendered, second_rendered)
        self.assertTrue(first_rendered.endswith("\n"))
        parsed = json.loads(first_rendered)
        self.assertEqual(
            parsed["reasons"],
            [
                MutationReason.REQUEST_INTENT_DENIED.value,
                MutationReason.NO_ACTIVE_TASK.value,
                MutationReason.INSUFFICIENT_AUTHORIZATION.value,
                MutationReason.HIGH_EVIDENCE_INSUFFICIENT.value,
            ],
        )

    def test_reason_order_is_deterministic(self) -> None:
        decision = decide_mutation(self._request(), safe_eval(), make_state())
        self.assertEqual(
            decision.reasons,
            (
                MutationReason.REQUEST_INTENT_DENIED,
                MutationReason.NO_ACTIVE_TASK,
                MutationReason.INSUFFICIENT_AUTHORIZATION,
                MutationReason.HIGH_EVIDENCE_INSUFFICIENT,
            ),
        )

    def test_no_duplicate_reasons(self) -> None:
        decision = decide_mutation(self._request(), safe_eval(), make_state())
        self.assertEqual(len(decision.reasons), len(set(decision.reasons)))

    def test_json_uses_canonical_conventions(self) -> None:
        decision = decide_mutation(self._request(), safe_eval(), make_state())
        rendered = render_decision_json(decision)
        self.assertTrue(rendered.startswith("{\n"))
        self.assertIn('\n  "advisory_invariant_ids"', rendered)
        self.assertNotIn("permission", rendered)


class RefusalReportingTests(unittest.TestCase):
    def test_exact_next_step_mapping_for_every_reason(self) -> None:
        expected = {
            MutationReason.TARGET_PROTECTED: (
                "Target is protected project metadata; choose a target outside "
                ".git and .evidline."
            ),
            MutationReason.TARGET_UNSAFE: (
                "Target is outside the project root or cannot be resolved; choose "
                "a target inside the project root."
            ),
            MutationReason.REQUEST_INTENT_DENIED: (
                "Request intent is DENIED; obtain a human decision before re-requesting."
            ),
            MutationReason.CRITICAL_RISK: (
                "Risk is CRITICAL; a human must perform this change outside Evidline."
            ),
            MutationReason.INVARIANT_CONFLICT: (
                "Resolve or supersede the conflicting invariant before re-requesting."
            ),
            MutationReason.INVARIANT_UNRESOLVED: (
                "An asserted invariant id does not resolve; supply an existing "
                "invariant id."
            ),
            MutationReason.INVARIANT_UNACKNOWLEDGED: (
                "A relevant ACTIVE BLOCK invariant is not acknowledged by the "
                "ACTIVE task; a human must acknowledge that invariant on the "
                "ACTIVE task, or choose a target outside its governed scope."
            ),
            MutationReason.SCOPE_VIOLATION: (
                "Target is outside the declared scope; narrow the target or declare "
                "a scope inside the project root."
            ),
            MutationReason.NO_ACTIVE_TASK: (
                "No ACTIVE task anchors this change; activate an authorized task."
            ),
            MutationReason.INSUFFICIENT_AUTHORIZATION: (
                "Supply at least one authorizing id resolving to an AUTHORIZED "
                "decision or an ACTIVE task."
            ),
            MutationReason.HIGH_EVIDENCE_INSUFFICIENT: (
                "Supply a reproducible supporting claim whose evidence ids are all "
                "covered by ephemeral verified evidence."
            ),
            MutationReason.REQUEST_INTENT_INSUFFICIENT: (
                "Request human confirmation before executing."
            ),
        }
        for reason, text in expected.items():
            with self.subTest(reason=reason):
                self.assertEqual(_select_next_step((reason,)), text)

    def test_next_step_priority_covers_every_reason(self) -> None:
        self.assertEqual(set(_NEXT_STEP_PRIORITY), set(MutationReason))
        self.assertEqual(len(_NEXT_STEP_PRIORITY), len(MutationReason))

    def test_target_protected_next_step_has_priority_over_high_evidence(self) -> None:
        self.assertEqual(
            _select_next_step(
                (
                    MutationReason.HIGH_EVIDENCE_INSUFFICIENT,
                    MutationReason.TARGET_PROTECTED,
                )
            ),
            "Target is protected project metadata; choose a target outside "
            ".git and .evidline.",
        )

    def test_unacknowledged_priority_is_after_unresolved_before_scope(self) -> None:
        reasons = (
            MutationReason.SCOPE_VIOLATION,
            MutationReason.INVARIANT_UNACKNOWLEDGED,
        )
        self.assertEqual(
            _select_next_step(reasons),
            _select_next_step((MutationReason.INVARIANT_UNACKNOWLEDGED,)),
        )
        self.assertEqual(
            _select_next_step(
                reasons + (MutationReason.INVARIANT_UNRESOLVED,)
            ),
            _select_next_step((MutationReason.INVARIANT_UNRESOLVED,)),
        )

    def test_target_renders_for_text_and_json_including_none(self) -> None:
        populated = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            safe_eval(),
            make_state(),
        )
        absent = decide_mutation(
            make_request(Intent.REQUESTED, MutationRisk.LOW),
            PathEvaluation(False, None, None, "unresolved"),
            make_state(),
        )

        self.assertIn(
            f"target: {Path('proj') / 'src/file.txt'}\n", explain(populated)
        )
        self.assertEqual(
            json.loads(render_decision_json(populated))["target"], populated.target
        )
        self.assertIn("target: -\n", explain(absent))
        self.assertIsNone(json.loads(render_decision_json(absent))["target"])


class PurityTests(unittest.TestCase):
    def test_decide_mutation_performs_no_io(self) -> None:
        scoped_request = make_request(
            Intent.REQUESTED, MutationRisk.LOW, declared_scope=("src",)
        )
        protected_request = make_request(Intent.AUTHORIZED, MutationRisk.LOW)
        with (
            mock.patch("os.stat") as stat,
            mock.patch("os.listdir") as listdir,
            mock.patch("os.scandir") as scandir,
            mock.patch("builtins.open") as open_file,
            mock.patch("subprocess.run") as run,
            mock.patch("time.time") as clock,
            mock.patch("random.random") as random_call,
            mock.patch("os.path.realpath") as realpath,
            mock.patch("os.lstat") as lstat,
        ):
            scoped = decide_mutation(scoped_request, safe_eval(), make_state())
            derived = decide_mutation(
                make_request(Intent.PROPOSED, MutationRisk.NORMAL),
                safe_eval(),
                make_state(tasks=(make_trusted_task(),)),
            )
            protected = decide_mutation(
                protected_request, protected_eval(".git"), make_state()
            )
            governed = decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                make_state(
                    invariants=(
                        make_invariant(
                            "inv-block",
                            InvariantEnforcement.BLOCK,
                            InvariantStatus.ACTIVE,
                            governed_scope=("src",),
                        ),
                    )
                ),
            )
        self.assertEqual(scoped.outcome, MutationOutcome.ALLOW)
        self.assertEqual(derived.outcome, MutationOutcome.ALLOW)
        self.assertEqual(derived.authorizing_task_id, "task-1")
        self.assertEqual(protected.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, protected.reasons)
        self.assertEqual(governed.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.INVARIANT_UNACKNOWLEDGED, governed.reasons)
        stat.assert_not_called()
        listdir.assert_not_called()
        scandir.assert_not_called()
        open_file.assert_not_called()
        run.assert_not_called()
        clock.assert_not_called()
        random_call.assert_not_called()
        realpath.assert_not_called()
        lstat.assert_not_called()


class SchemaAndValidationTests(unittest.TestCase):
    def test_schema_version_is_two(self) -> None:
        self.assertEqual(MUTATION_SCHEMA_VERSION, 2)

    def test_invalid_request_type_raises(self) -> None:
        with self.assertRaises(MutationInputError):
            decide_mutation("not-a-request", safe_eval(), make_state())

    def test_invalid_evaluation_type_raises(self) -> None:
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                "not-an-evaluation",
                make_state(),
            )

    def test_invalid_state_type_raises(self) -> None:
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                "not-a-state",
            )

    def test_duplicate_ids_raise_mutation_input_error(self) -> None:
        state = make_state(
            evidence=(
                make_evidence(evidence_id="evidence-1"),
                make_evidence(evidence_id="evidence-1"),
            )
        )
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                state,
            )

    def test_dangling_evidence_reference_raises_mutation_input_error(self) -> None:
        state = make_state(
            claims=(make_claim(evidence_ids=("evidence-missing",)),),
        )
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                state,
            )

    def test_two_active_tasks_raise_mutation_input_error(self) -> None:
        state = make_state(
            tasks=(make_task(task_id="task-1"), make_task(task_id="task-2")),
        )
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(Intent.REQUESTED, MutationRisk.LOW),
                safe_eval(),
                state,
            )

    def test_non_tuple_request_field_raises(self) -> None:
        with self.assertRaises(MutationInputError):
            decide_mutation(
                make_request(
                    Intent.REQUESTED,
                    MutationRisk.LOW,
                    authorizing_ids=["task-1"],
                ),
                safe_eval(),
                make_state(),
            )

    def test_explain_and_json_reject_non_decision(self) -> None:
        with self.assertRaises(MutationInputError):
            explain("not-a-decision")
        with self.assertRaises(MutationInputError):
            render_decision_json("not-a-decision")


class EvaluateAndDecideTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        (self.root / ".evidline").mkdir()

    def test_wrapper_delegates_to_path_evaluation(self) -> None:
        decision = evaluate_and_decide(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            self.root,
            ".git/config",
            make_state(),
        )
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_nested_vendor_git_is_protected(self) -> None:
        decision = evaluate_and_decide(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            self.root,
            "vendor/.git/config",
            make_state(),
        )
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_nested_sub_evidline_is_protected(self) -> None:
        decision = evaluate_and_decide(
            make_request(Intent.AUTHORIZED, MutationRisk.LOW),
            self.root,
            "sub/.evidline/state.json",
            make_state(),
        )
        self.assertEqual(decision.risk, MutationRisk.CRITICAL)
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertIn(MutationReason.TARGET_PROTECTED, decision.reasons)

    def test_dotdir_siblings_are_not_protected(self) -> None:
        for target in (".github/workflows/check.yml", ".evidline-backup/state.json"):
            decision = evaluate_and_decide(
                make_request(Intent.AUTHORIZED, MutationRisk.LOW),
                self.root,
                target,
                make_state(),
            )
            self.assertEqual(decision.outcome, MutationOutcome.ALLOW, target)


class Phase4LoadAndDecideTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        (self.root / ".evidline").mkdir()
        self.state = make_state(tasks=(make_task(),))
        (self.root / ".evidline" / "state.json").write_text(
            serialize_state(self.state), encoding="utf-8"
        )
        self.request = make_request(Intent.REQUESTED, MutationRisk.LOW)

    def test_project_discovery_failure_is_not_initialized(self) -> None:
        unrelated = Path(self.temporary.name) / "unrelated"
        unrelated.mkdir()
        with self.assertRaises(StateNotInitializedError):
            load_and_decide(unrelated, self.request, "src/app.py")

    def test_state_load_failure_is_preserved(self) -> None:
        (self.root / ".evidline" / "state.json").write_text("{", encoding="utf-8")
        with self.assertRaises(StateValidationError):
            load_and_decide(self.root, self.request, "src/app.py")

    def test_matches_existing_evaluate_and_decide(self) -> None:
        expected = evaluate_and_decide(
            self.request, self.root, "src/app.py", self.state
        )
        actual = load_and_decide(self.root, self.request, "src/app.py")
        self.assertEqual(actual, expected)

    def test_wrapper_adds_no_policy_behavior(self) -> None:
        sentinel = mock.sentinel.decision
        with mock.patch(
            "evidline.mutation.evaluate_and_decide", return_value=sentinel
        ) as delegated:
            result = load_and_decide(self.root, self.request, "src/app.py")
        self.assertIs(result, sentinel)
        delegated.assert_called_once_with(
            self.request, self.root.resolve(), "src/app.py", self.state
        )


if __name__ == "__main__":
    unittest.main()
