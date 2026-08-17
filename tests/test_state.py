from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


from evidline.paths import (
    ScopePathSemantics,
    host_scope_semantics,
    normalize_scope_for_semantics,
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
    IncompatibleScopeSemanticsError,
    LOCK_FILENAME,
    Project,
    SCHEMA_VERSION,
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
        source_path="evidence/observed.txt",
        digest=DIGEST,
    )
    return StateDocument(
        schema_version=4,
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
                governed_scope=("src",),
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
                authorized_scope=("src", "docs/api"),
                approved_at="2026-08-15T00:00:00+04:00",
                approval_channel="interactive",
                acknowledged_invariant_ids=("inv-1",),
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
        scope_semantics=host_scope_semantics(),
    )


class StateValidationTests(unittest.TestCase):
    def test_schema_version_is_four(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 4)

    def test_valid_state_round_trip(self) -> None:
        state = valid_state()
        self.assertEqual(parse_state(serialize_state(state)), state)
        self.assertEqual(state.tasks[0].authorized_scope, ("src", "docs/api"))
        self.assertEqual(state.invariants[0].governed_scope, ("src",))
        self.assertEqual(state.tasks[0].acknowledged_invariant_ids, ("inv-1",))
        self.assertEqual(state.evidence[0].source_path, "evidence/observed.txt")
        self.assertIs(state.scope_semantics, host_scope_semantics())

    def test_serialization_is_deterministic(self) -> None:
        state = valid_state()
        first = serialize_state(state)
        self.assertEqual(first, serialize_state(state))
        self.assertTrue(first.endswith("\n"))
        self.assertEqual(json.loads(first)["revision"], 0)

    def test_unsupported_schema_is_rejected(self) -> None:
        for version in (1, 2, 3, 5):
            with self.subTest(version=version):
                raw = json.loads(serialize_state(valid_state()))
                raw["schema_version"] = version
                with self.assertRaises(UnsupportedSchemaError):
                    parse_state(json.dumps(raw))
        old = json.loads(serialize_state(valid_state()))
        old["schema_version"] = 2
        del old["scope_semantics"]
        del old["invariants"][0]["governed_scope"]
        del old["tasks"][0]["acknowledged_invariant_ids"]
        with self.assertRaises(UnsupportedSchemaError):
            parse_state(json.dumps(old))

    def test_schema_four_exact_keys_are_required(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        self.assertEqual(raw["scope_semantics"], host_scope_semantics().value)
        self.assertIn("governed_scope", raw["invariants"][0])
        self.assertIn("acknowledged_invariant_ids", raw["tasks"][0])
        self.assertIn("source_path", raw["evidence"][0])
        for key in (
            "scope_semantics",
            "governed_scope",
            "acknowledged_invariant_ids",
            "source_path",
        ):
            with self.subTest(key=key):
                candidate = json.loads(serialize_state(valid_state()))
                target = candidate
                if key == "governed_scope":
                    target = candidate["invariants"][0]
                elif key == "acknowledged_invariant_ids":
                    target = candidate["tasks"][0]
                elif key == "source_path":
                    target = candidate["evidence"][0]
                del target[key]
                with self.assertRaises(StateValidationError):
                    parse_state(json.dumps(candidate))

    def test_evidence_binding_may_be_absent(self) -> None:
        state = valid_state()
        evidence = replace(state.evidence[0], source_path=None, digest=None)
        validate_state(replace(state, evidence=(evidence,)))

    def test_normalized_evidence_binding_is_valid(self) -> None:
        validate_state(valid_state())

    def test_evidence_source_without_digest_is_rejected(self) -> None:
        state = valid_state()
        evidence = replace(state.evidence[0], digest=None)
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, evidence=(evidence,)))

    def test_evidence_digest_without_source_is_rejected(self) -> None:
        state = valid_state()
        evidence = replace(state.evidence[0], source_path=None)
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, evidence=(evidence,)))

    def test_invalid_or_unsafe_evidence_source_path_is_rejected(self) -> None:
        state = valid_state()
        for source_path in (
            "",
            "C:/outside",
            "/outside",
            "../outside",
            "src/../outside",
            "*.py",
            "!src",
            "src\0bad",
            "src\nspoof",
            "src/",
        ):
            with self.subTest(source_path=source_path):
                evidence = replace(state.evidence[0], source_path=source_path)
                with self.assertRaises(StateValidationError):
                    validate_state(replace(state, evidence=(evidence,)))

    def test_root_evidence_source_is_grammar_valid(self) -> None:
        state = valid_state()
        evidence = replace(state.evidence[0], source_path=".")
        validate_state(replace(state, evidence=(evidence,)))

    def test_windows_invalid_evidence_source_rejects_under_folded_semantics(self) -> None:
        state = valid_state()
        evidence = replace(state.evidence[0], source_path="CON")
        candidate = replace(
            state,
            evidence=(evidence,),
            scope_semantics=ScopePathSemantics.CASE_FOLDED,
        )
        with mock.patch(
            "evidline.state._paths.host_scope_semantics",
            return_value=ScopePathSemantics.CASE_FOLDED,
        ):
            with self.assertRaises(StateValidationError):
                validate_state(candidate)

    def test_scope_semantics_marker_failures_are_rejected(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        for value in ("UNKNOWN", 1, None):
            with self.subTest(value=value):
                candidate = dict(raw)
                candidate["scope_semantics"] = value
                with self.assertRaises(StateValidationError):
                    parse_state(json.dumps(candidate))
        with self.assertRaises(StateValidationError):
            validate_state(replace(valid_state(), scope_semantics="CASE_FOLDED"))

    def test_empty_authorized_scope_is_valid(self) -> None:
        state = valid_state()
        task = replace(state.tasks[0], authorized_scope=())
        validate_state(replace(state, tasks=(task,)))

    def test_root_scope_is_explicit_and_valid(self) -> None:
        state = valid_state()
        task = replace(state.tasks[0], authorized_scope=(".",))
        validate_state(replace(state, tasks=(task,)))

    def test_unsafe_authorized_scope_is_rejected(self) -> None:
        state = valid_state()
        for scope in (
            "C:/outside",
            "/outside",
            "../outside",
            "src/../outside",
            "*.py",
            "!src",
            "src\nspoof",
        ):
            with self.subTest(scope=scope):
                task = replace(state.tasks[0], authorized_scope=(scope,))
                with self.assertRaises(StateValidationError):
                    validate_state(replace(state, tasks=(task,)))

    def test_non_normalized_or_duplicate_authorized_scope_is_rejected(self) -> None:
        state = valid_state()
        for scope in (("src/",), ("./src",), ("src", "src")):
            with self.subTest(scope=scope):
                task = replace(state.tasks[0], authorized_scope=scope)
                with self.assertRaises(StateValidationError):
                    validate_state(replace(state, tasks=(task,)))

    def test_malformed_task_scope_state_fails_closed(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw["tasks"][0]["authorized_scope"] = "src"
        with self.assertRaises(StateValidationError):
            parse_state(json.dumps(raw))

    def test_governed_scope_accepts_the_shared_scope_language(self) -> None:
        state = valid_state()
        for governed_scope in (
            (),
            (".",),
            ("src",),
            ("src/package/app.py",),
            ("src", "docs/api"),
        ):
            with self.subTest(governed_scope=governed_scope):
                invariant = replace(
                    state.invariants[0],
                    governed_scope=governed_scope,
                )
                validate_state(replace(state, invariants=(invariant,)))

    def test_invalid_governed_scope_is_rejected(self) -> None:
        state = valid_state()
        invalid_scopes = (
            ("",),
            ("C:/outside",),
            ("/outside",),
            ("../outside",),
            ("src/../outside",),
            ("*.py",),
            ("!src",),
            ("src\0bad",),
            ("src\nspoof",),
            ("src/",),
            ("src", "src"),
        )
        for governed_scope in invalid_scopes:
            with self.subTest(governed_scope=governed_scope):
                invariant = replace(
                    state.invariants[0],
                    governed_scope=governed_scope,
                )
                with self.assertRaises(StateValidationError):
                    validate_state(replace(state, invariants=(invariant,)))
        invariant = replace(state.invariants[0], governed_scope=["src"])
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, invariants=(invariant,)))

    def test_windows_invalid_governed_scope_rejects_under_folded_semantics(self) -> None:
        state = valid_state()
        invariant = replace(state.invariants[0], governed_scope=("CON",))
        candidate = replace(
            state,
            invariants=(invariant,),
            scope_semantics=ScopePathSemantics.CASE_FOLDED,
        )
        with mock.patch(
            "evidline.state._paths.host_scope_semantics",
            return_value=ScopePathSemantics.CASE_FOLDED,
        ):
            with self.assertRaises(StateValidationError):
                validate_state(candidate)

    def test_acknowledgements_must_resolve_only_to_invariants(self) -> None:
        state = valid_state()
        invalid = (
            ("inv-missing",),
            ("task-1",),
            ("dec-1",),
            ("claim-1",),
            ("evidence-1",),
            ("inv-1", "inv-1"),
        )
        for acknowledged in invalid:
            with self.subTest(acknowledged=acknowledged):
                task = replace(
                    state.tasks[0],
                    acknowledged_invariant_ids=acknowledged,
                )
                with self.assertRaises(StateValidationError):
                    validate_state(replace(state, tasks=(task,)))
        task = replace(state.tasks[0], acknowledged_invariant_ids=["inv-1"])
        with self.assertRaises(StateValidationError):
            validate_state(replace(state, tasks=(task,)))

    def test_superseded_invariant_acknowledgement_is_valid(self) -> None:
        state = valid_state()
        old = Invariant(
            id="inv-old",
            description="Superseded constraint",
            enforcement=InvariantEnforcement.BLOCK,
            status=InvariantStatus.SUPERSEDED,
            superseded_by="inv-1",
            approved_at="2026-08-15T00:00:00+04:00",
            approval_channel="interactive",
            governed_scope=("src",),
        )
        task = replace(
            state.tasks[0],
            acknowledged_invariant_ids=("inv-old",),
        )
        validate_state(
            replace(
                state,
                invariants=(state.invariants[0], old),
                tasks=(task,),
            )
        )

    def test_incompatible_scoped_states_fail_before_scope_normalization(self) -> None:
        cases = (
            (
                ScopePathSemantics.CASE_FOLDED,
                ScopePathSemantics.CASE_SENSITIVE,
                normalize_scope_for_semantics(
                    "Src", ScopePathSemantics.CASE_FOLDED
                ),
            ),
            (
                ScopePathSemantics.CASE_SENSITIVE,
                ScopePathSemantics.CASE_FOLDED,
                "Src",
            ),
            (
                ScopePathSemantics.CASE_SENSITIVE,
                ScopePathSemantics.CASE_FOLDED,
                "src",
            ),
        )
        for authored, reading, scope in cases:
            with self.subTest(authored=authored, reading=reading, scope=scope):
                state = valid_state()
                task = replace(state.tasks[0], authorized_scope=(scope,))
                invariant = replace(state.invariants[0], governed_scope=())
                candidate = replace(
                    state,
                    tasks=(task,),
                    invariants=(invariant,),
                    scope_semantics=authored,
                )
                with (
                    mock.patch(
                        "evidline.state._paths.host_scope_semantics",
                        return_value=reading,
                    ),
                    mock.patch(
                        "evidline.state._paths.normalize_root_relative_scope"
                    ) as normalizer,
                ):
                    with self.assertRaises(IncompatibleScopeSemanticsError):
                        validate_state(candidate)
                normalizer.assert_not_called()

    def test_incompatible_bound_evidence_fails_before_path_normalization(self) -> None:
        state = valid_state()
        task = replace(state.tasks[0], authorized_scope=())
        invariant = replace(state.invariants[0], governed_scope=())
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        candidate = replace(
            state,
            tasks=(task,),
            invariants=(invariant,),
            scope_semantics=foreign,
        )
        with mock.patch(
            "evidline.state._paths.normalize_root_relative_scope"
        ) as normalizer:
            with self.assertRaises(IncompatibleScopeSemanticsError):
                validate_state(candidate)
        normalizer.assert_not_called()

    def test_matching_semantics_and_empty_scope_exception_are_valid(self) -> None:
        for semantics in ScopePathSemantics:
            scope = normalize_scope_for_semantics("Src", semantics)
            state = valid_state()
            task = replace(state.tasks[0], authorized_scope=(scope,))
            invariant = replace(state.invariants[0], governed_scope=())
            candidate = replace(
                state,
                tasks=(task,),
                invariants=(invariant,),
                scope_semantics=semantics,
            )
            with mock.patch(
                "evidline.state._paths.host_scope_semantics",
                return_value=semantics,
            ):
                validate_state(candidate)

        state = valid_state()
        task = replace(state.tasks[0], authorized_scope=())
        invariant = replace(state.invariants[0], governed_scope=())
        evidence = replace(state.evidence[0], source_path=None, digest=None)
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        validate_state(
            replace(
                state,
                tasks=(task,),
                invariants=(invariant,),
                evidence=(evidence,),
                scope_semantics=foreign,
            )
        )

    def test_unknown_task_key_is_rejected(self) -> None:
        raw = json.loads(serialize_state(valid_state()))
        raw["tasks"][0]["unknown"] = True
        with self.assertRaises(StateValidationError):
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

    def test_persisted_verified_diagnostic_is_unconditional(self) -> None:
        state = valid_state()
        claim = replace(state.claims[0], verification=Verification.VERIFIED)
        with self.assertRaisesRegex(
            StateValidationError,
            r"claim-1 VERIFIED cannot be persisted$",
        ):
            validate_state(replace(state, claims=(claim,)))

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
        evidence = replace(state.evidence[0], source_path=None, digest=None)
        claim = replace(
            state.claims[0],
            verification=Verification.FAILED,
            verifier_rule=VerifierRule.R1_DIGEST_MATCH,
            verified_at="2026-08-15T00:01:00+04:00",
            verifying_evidence_ids=("evidence-1",),
        )
        validate_state(replace(state, claims=(claim,), evidence=(evidence,)))

    def test_failed_with_reproducible_binding_remains_valid(self) -> None:
        state = valid_state()
        claim = replace(
            state.claims[0],
            verification=Verification.FAILED,
            reproducible=True,
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

    def test_incompatible_write_leaves_state_and_revision_unchanged(self) -> None:
        before = self.state_path.read_bytes()
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        with self.assertRaises(IncompatibleScopeSemanticsError):
            write_state(
                self.root,
                replace(valid_state(), scope_semantics=foreign),
                expected_revision=0,
            )
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(load_state(self.root).revision, 0)

    def test_ordinary_write_preserves_compatible_foreign_empty_marker(self) -> None:
        state = valid_state()
        task = replace(state.tasks[0], authorized_scope=())
        invariant = replace(state.invariants[0], governed_scope=())
        evidence = replace(state.evidence[0], source_path=None, digest=None)
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        document = replace(
            state,
            tasks=(task,),
            invariants=(invariant,),
            evidence=(evidence,),
            scope_semantics=foreign,
        )
        self.state_path.write_text(serialize_state(document), encoding="utf-8")
        updated = write_state(self.root, document, expected_revision=0)
        self.assertIs(updated.scope_semantics, foreign)
        self.assertIs(load_state(self.root).scope_semantics, foreign)
        self.assertEqual(updated.revision, 1)


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
        self.assertIs(loaded.scope_semantics, host_scope_semantics())
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
