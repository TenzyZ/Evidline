from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


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
    LOCK_FILENAME,
    Project,
    StateAlreadyInitializedError,
    StateConflictError,
    StateDocument,
    StateIOError,
    StateJSONError,
    StateNotInitializedError,
    StateValidationError,
    Task,
    TaskStatus,
    UnsupportedSchemaError,
    Verification,
    VerifierRule,
    initialize_project,
    load_state,
    parse_state,
    serialize_state,
    validate_state,
    write_state,
)


DIGEST = "sha256:" + "a" * 64


def valid_state(*, revision: int = 0) -> StateDocument:
    evidence = Evidence(
        id="evidence-1",
        description="Observed digest",
        provenance=EvidenceProvenance.DIRECT_OBSERVATION,
        execution=Execution.EXECUTED,
        digest=DIGEST,
    )
    return StateDocument(
        schema_version=1,
        revision=revision,
        project=Project(
            name="Evidline",
            purpose="Verified local continuity",
            ignore_globs=("*.pyc",),
            default_budget_chars=9000,
        ),
        invariants=(
            Invariant(
                id="inv-1",
                description="Never promote unsupported claims",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
            ),
        ),
        decisions=(
            Decision(
                id="dec-1",
                description="Use local JSON state",
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                approved_at="2026-08-15T00:00:00+04:00",
                approval_channel="interactive",
                asserted_actor="human",
            ),
        ),
        tasks=(
            Task(
                id="task-1",
                description="Implement state foundation",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.EXECUTED,
                related_ids=("dec-1",),
                approved_at="2026-08-15T00:00:00+04:00",
                approval_channel="interactive",
            ),
        ),
        claims=(
            Claim(
                id="claim-1",
                description="A digest matches",
                freshness=ClaimFreshness.DIGEST_BOUND,
                verification=Verification.UNVERIFIED,
                reproducible=False,
                evidence_ids=("evidence-1",),
            ),
        ),
        evidence=(evidence,),
        counters={"claim": 1, "evidence": 1},
    )


class StateValidationTests(unittest.TestCase):
    def test_valid_state_round_trip(self) -> None:
        state = valid_state()
        self.assertEqual(parse_state(serialize_state(state)), state)

    def test_serialization_is_deterministic(self) -> None:
        state = valid_state()
        first = serialize_state(state)
        self.assertEqual(first, serialize_state(state))
        self.assertTrue(first.endswith("\n"))
        self.assertEqual(json.loads(first)["revision"], 0)

    def test_unsupported_schema_is_rejected(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw["schema_version"] = 2
        with self.assertRaises(UnsupportedSchemaError):
            parse_state(json.dumps(raw))

    def test_malformed_json_is_rejected(self) -> None:
        with self.assertRaises(StateJSONError):
            parse_state("{")

    def test_wrong_field_type_is_rejected(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw["revision"] = "0"
        with self.assertRaises(StateValidationError):
            parse_state(json.dumps(raw))

    def test_duplicate_record_ids_are_rejected(self) -> None:
        state = valid_state()
        duplicate = replace(state.invariants[0])
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, invariants=(state.invariants[0], duplicate)))

    def test_broken_evidence_reference_is_rejected(self) -> None:
        state = valid_state()
        claim = replace(state.claims[0], evidence_ids=("evidence-missing",))
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_more_than_one_active_task_is_rejected(self) -> None:
        state = valid_state()
        second = replace(state.tasks[0], id="task-2")
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, tasks=(state.tasks[0], second)))

    def test_persisted_verified_is_rejected_for_every_provenance(self) -> None:
        state = valid_state()
        for provenance in EvidenceProvenance:
            with self.subTest(provenance=provenance):
                evidence = replace(
                    state.evidence[0],
                    provenance=provenance,
                    digest=DIGEST,
                )
                claim = replace(
                    state.claims[0],
                    verification=Verification.VERIFIED,
                    reproducible=True,
                    verifier_rule=VerifierRule.R1_DIGEST_MATCH,
                    verified_at="2026-08-15T00:01:00+04:00",
                    verifying_evidence_ids=("evidence-1",),
                )
                with self.assertRaises(StateValidationError):
                    validate_state(
                        replace(state, claims=(claim,), evidence=(evidence,))
                    )

    def test_verified_persisted_volatile_is_rejected(self) -> None:
        state = valid_state()
        claim = replace(
            state.claims[0],
            freshness=ClaimFreshness.PERSISTED_VOLATILE,
            verification=Verification.VERIFIED,
            reproducible=True,
            verifier_rule=VerifierRule.R1_DIGEST_MATCH,
            verified_at="2026-08-15T00:01:00+04:00",
            verifying_evidence_ids=("evidence-1",),
        )
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_executed_evidence_does_not_change_verification(self) -> None:
        state = valid_state()
        validate_state(state)
        self.assertIs(state.evidence[0].execution, Execution.EXECUTED)
        self.assertIs(state.claims[0].verification, Verification.UNVERIFIED)

    def test_unverified_without_verification_provenance_is_valid(self) -> None:
        validate_state(valid_state())

    def test_unverified_with_verifier_rule_is_rejected(self) -> None:
        state = valid_state()
        claim = replace(
            state.claims[0], verifier_rule=VerifierRule.R1_DIGEST_MATCH
        )
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_unverified_with_verified_at_is_rejected(self) -> None:
        state = valid_state()
        claim = replace(state.claims[0], verified_at="2026-08-15T00:01:00+04:00")
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_unverified_with_verifying_evidence_is_rejected(self) -> None:
        state = valid_state()
        claim = replace(state.claims[0], verifying_evidence_ids=("evidence-1",))
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_unverified_with_all_provenance_is_rejected_by_parse(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw_claim = raw["claims"][0]
        raw_claim["verifier_rule"] = VerifierRule.R1_DIGEST_MATCH.value
        raw_claim["verified_at"] = "2026-08-15T00:01:00+04:00"
        raw_claim["verifying_evidence_ids"] = ["evidence-1"]
        with self.assertRaises(StateValidationError):
            parse_state(json.dumps(raw))

    def test_failed_with_verification_provenance_remains_valid(self) -> None:
        state = valid_state()
        claim = replace(
            state.claims[0],
            verification=Verification.FAILED,
            verifier_rule=VerifierRule.R1_DIGEST_MATCH,
            verified_at="2026-08-15T00:01:00+04:00",
            verifying_evidence_ids=("evidence-1",),
        )
        validate_state(replace(state, claims=(claim,)))

    def test_stale_cannot_be_persisted_as_current_truth(self) -> None:
        state = valid_state()
        claim = replace(state.claims[0], verification=Verification.STALE)
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, claims=(claim,)))

    def test_unknown_top_level_key_is_rejected(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw["unknown"] = True
        with self.assertRaises(StateValidationError):
            parse_state(json.dumps(raw))


class StatePersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.state_directory = self.root / ".evidline"
        self.state_directory.mkdir(parents=True)
        self.state_path = self.state_directory / "state.json"
        self.state_path.write_text(serialize_state(valid_state()), encoding="utf-8")

    def test_revision_increments_exactly_once(self) -> None:
        updated = write_state(self.root, valid_state(), expected_revision=0)
        self.assertEqual(updated.revision, 1)
        self.assertEqual(load_state(self.root).revision, 1)

    def test_stale_expected_revision_is_rejected(self) -> None:
        self.state_path.write_text(serialize_state(valid_state(revision=1)), encoding="utf-8")
        with self.assertRaises(StateConflictError):
            write_state(self.root, valid_state(), expected_revision=0)
        self.assertEqual(load_state(self.root).revision, 1)

    def test_held_write_lock_causes_safe_refusal(self) -> None:
        lock = self.state_directory / LOCK_FILENAME
        lock.write_text("held", encoding="utf-8")
        with self.assertRaises(StateConflictError):
            write_state(self.root, valid_state(), expected_revision=0)
        self.assertEqual(load_state(self.root).revision, 0)

    def test_failed_replace_leaves_prior_state_intact(self) -> None:
        before = self.state_path.read_bytes()
        with mock.patch("evidline.state.os.replace", side_effect=OSError("failure")):
            with self.assertRaises(StateIOError):
                write_state(self.root, valid_state(), expected_revision=0)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(load_state(self.root).revision, 0)

    def test_temporary_file_is_cleaned_after_failed_write(self) -> None:
        with mock.patch("evidline.state.os.replace", side_effect=OSError("failure")):
            with self.assertRaises(StateIOError):
                write_state(self.root, valid_state(), expected_revision=0)
        self.assertEqual(list(self.state_directory.glob(".state.*.tmp")), [])
        self.assertFalse((self.state_directory / LOCK_FILENAME).exists())

    def test_malformed_durable_state_is_never_partially_returned(self) -> None:
        self.state_path.write_text('{"schema_version": 1}', encoding="utf-8")
        with self.assertRaises(StateValidationError):
            load_state(self.root)

    def test_invalid_json_load_is_distinct(self) -> None:
        self.state_path.write_text("{", encoding="utf-8")
        with self.assertRaises(StateJSONError):
            load_state(self.root)

    def test_missing_state_file_is_distinct(self) -> None:
        self.state_path.unlink()
        with self.assertRaises(StateNotInitializedError):
            load_state(self.root)

    def test_missing_state_directory_is_not_created(self) -> None:
        other_root = Path(self.temporary.name) / "other"
        other_root.mkdir()
        with self.assertRaises(StateNotInitializedError):
            write_state(other_root, valid_state(), expected_revision=0)
        self.assertFalse((other_root / ".evidline").exists())


class Phase4InitializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.project = Project(
            name="project",
            purpose="Purpose not yet stated.",
            ignore_globs=(),
            default_budget_chars=8000,
        )

    def test_creates_valid_empty_revision_zero_state(self) -> None:
        created = initialize_project(self.root, project=self.project)
        loaded = load_state(self.root)
        self.assertEqual(created, loaded)
        self.assertEqual(loaded.revision, 0)
        self.assertEqual(
            (
                loaded.invariants,
                loaded.decisions,
                loaded.tasks,
                loaded.claims,
                loaded.evidence,
            ),
            ((), (), (), (), ()),
        )
        self.assertEqual(loaded.counters, {})
        self.assertEqual(parse_state(serialize_state(loaded)), loaded)

    def test_exclusive_create_refuses_existing_valid_state_unchanged(self) -> None:
        initialize_project(self.root, project=self.project)
        state_path = self.root / ".evidline" / "state.json"
        before = state_path.read_bytes()
        with self.assertRaises(StateAlreadyInitializedError):
            initialize_project(self.root, project=self.project)
        self.assertEqual(state_path.read_bytes(), before)

    def test_protected_root_is_refused_without_initialization(self) -> None:
        protected = Path(self.temporary.name) / ".git" / "nested"
        protected.mkdir(parents=True)
        with self.assertRaises(StateValidationError):
            initialize_project(protected, project=self.project)
        self.assertFalse((protected / ".evidline").exists())

    def test_success_creates_no_extra_files(self) -> None:
        initialize_project(self.root, project=self.project)
        self.assertEqual(
            [entry.name for entry in (self.root / ".evidline").iterdir()],
            ["state.json"],
        )

    def test_evidline_regular_file_is_io_failure(self) -> None:
        (self.root / ".evidline").write_text("user data", encoding="utf-8")
        with self.assertRaises(StateIOError):
            initialize_project(self.root, project=self.project)
        self.assertEqual(
            (self.root / ".evidline").read_text(encoding="utf-8"), "user data"
        )

    def test_missing_root_is_io_failure(self) -> None:
        with self.assertRaises(StateIOError):
            initialize_project(self.root / "missing", project=self.project)

    def test_create_os_error_is_translated(self) -> None:
        with mock.patch("evidline.state.os.open", side_effect=OSError("denied")):
            with self.assertRaises(StateIOError):
                initialize_project(self.root, project=self.project)


if __name__ == "__main__":
    unittest.main()
