from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from benchmarks.fixture import BenchmarkFixture, SandboxContainmentError
from benchmarks.runner import (
    EXPECTED_RESULTS_PATH,
    build_observed_document,
    compare_contract,
    load_expected_document,
    run,
)


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.observed = build_observed_document()
        cls.results = {
            item["id"]: item
            for item in cls.observed["observations"]["scenario_results"]
        }

    def assert_category_matched(self, category: str) -> None:
        selected = [
            item for item in self.results.values() if item["category"] == category
        ]
        self.assertTrue(selected)
        self.assertTrue(all(item["matched"] for item in selected))

    def test_fixture_isolation(self) -> None:
        with BenchmarkFixture.create() as first, BenchmarkFixture.create() as second:
            self.assertNotEqual(first.sandbox, second.sandbox)
            self.assertTrue((first.root / ".evidline" / "state.json").is_file())
            self.assertTrue((first.root / "src" / "app.py").is_file())
            self.assertTrue(
                (first.handoff_root / ".evidline" / "state.json").is_file()
            )
            with self.assertRaises(SandboxContainmentError):
                first.assert_sandbox_path(Path.cwd())
            self.assertFalse(
                os.path.commonpath(
                    (
                        os.path.normcase(str(first.sandbox.resolve())),
                        os.path.normcase(str(Path.cwd().resolve())),
                    )
                )
                == os.path.normcase(str(first.sandbox.resolve()))
            )

    def test_every_declared_scenario_matches(self) -> None:
        self.assertEqual(
            self.observed["contract"]["metrics"]["scenarios_matched"],
            self.observed["contract"]["metrics"]["scenarios_total"],
        )
        self.assertEqual(self.observed["observations"]["scenario_mismatch_ids"], [])

    def test_core_scenarios(self) -> None:
        self.assert_category_matched("core")

    def test_context_scenarios(self) -> None:
        self.assert_category_matched("context")
        metrics = self.observed["contract"]["metrics"]
        self.assertTrue(metrics["accounting_exact"])
        self.assertTrue(metrics["audit_completeness"])
        self.assertEqual(metrics["stale_reuse_count"], 0)
        self.assertEqual(metrics["stale_revalidation_count"], 2)

    def test_claude_adapter_scenarios(self) -> None:
        self.assert_category_matched("claude")
        result = self.results["claude.uncovered_tool"]["actual"]
        self.assertEqual(result["classification"], "UNCOVERED")

    def test_codex_adapter_scenarios(self) -> None:
        self.assert_category_matched("codex")
        result = self.results["codex.malformed_patches"]["actual"]
        self.assertTrue(result["all_adapter_failure"])
        self.assertTrue(result["no_policy_block"])

    def test_shared_adapter_scenarios(self) -> None:
        self.assert_category_matched("adapters")
        result = self.results["adapters.synthetic_allow_mapping"]["actual"]
        self.assertEqual(
            result["classification"],
            "SYNTHETIC_MAPPING_ONLY",
        )

    def test_verify_scenarios(self) -> None:
        self.assert_category_matched("verify")
        mismatch = self.results["verify.evidence_digest_mismatch"]["actual"]
        self.assertEqual(mismatch["verification"], "FAILED")
        self.assertEqual(mismatch["reason"], "DIGEST_MISMATCH")
        volatile = self.results[
            "verify.claim_volatile_freshness_does_not_gate"
        ]["actual"]
        self.assertEqual(volatile["verification"], "VERIFIED")
        no_write = self.results["verify.no_state_write"]["actual"]
        self.assertTrue(no_write["state_bytes_unchanged"])
        self.assertTrue(no_write["revision_unchanged"])

    def test_handoff_scenarios(self) -> None:
        self.assert_category_matched("handoff")
        partial = self.results[
            "handoff.partial_verification_contract"
        ]["actual"]
        self.assertEqual(
            partial["verdict_counts"],
            {"VERIFIED": 4, "FAILED": 2, "UNVERIFIED": 4},
        )
        self.assertTrue(partial["failed_revalidate"])
        self.assertTrue(partial["unverified_never_verified"])
        self.assertTrue(partial["continuity_present"])
        self.assertFalse(partial["global_success_claim"])
        foreign = self.results[
            "handoff.foreign_scope_semantics_fails_closed"
        ]["actual"]
        self.assertTrue(foreign["zero_source_reads"])

    def test_authoring_scenarios(self) -> None:
        self.assert_category_matched("authoring")
        task = self.results["authoring.task_created_unapproved"]["actual"]
        self.assertEqual(task["status"], "DRAFT")
        self.assertFalse(task["trusted_active_task"])
        empty_scope = self.results[
            "authoring.empty_governed_scope_is_not_repository_global"
        ]["actual"]
        self.assertEqual(empty_scope["meaning"], "NO_TARGET_BINDING")
        self.assertEqual(empty_scope["dot_scope_meaning"], "WHOLE_REPOSITORY")
        self.assertFalse(empty_scope["equal"])

    def test_doctor_scenarios(self) -> None:
        self.assert_category_matched("doctor")
        self.assertEqual(self.results["doctor.not_initialized"]["actual"]["exit"], 20)
        self.assertEqual(self.results["doctor.budget_below_profile_minimum"]["actual"]["overall"], "DEGRADED")
        self.assertTrue(self.results["doctor.no_state_write"]["actual"]["bytes_unchanged"])

    def test_vab1_scoped_adapter_proofs(self) -> None:
        for scenario_id in (
            "claude.authorized_normal_mutation",
            "codex.authorized_normal_apply_patch",
        ):
            with self.subTest(scenario_id=scenario_id):
                result = self.results[scenario_id]["actual"]
                self.assertEqual(result["core_outcome"], "ALLOW")
                self.assertEqual(result["authorizing_task_id"], "task-active")
                self.assertTrue(result["adapter_silent"])
        for scenario_id in (
            "core.derived_outside_authorized_scope",
            "core.untrusted_authorization_channel",
        ):
            with self.subTest(scenario_id=scenario_id):
                result = self.results[scenario_id]["actual"]
                self.assertEqual(result["outcome"], "ASK")
                self.assertIsNone(result["authorizing_task_id"])

    def test_vab2_structural_scope_and_adapter_proofs(self) -> None:
        blocked = self.results["core.governed_block_unacknowledged"]["actual"]
        self.assertEqual(blocked["outcome"], "BLOCK")
        self.assertEqual(blocked["unacknowledged"], ["inv-block"])
        acknowledged = self.results["core.governed_block_acknowledged"]["actual"]
        self.assertEqual(acknowledged["outcome"], "ALLOW")
        conflict = self.results[
            "core.governed_acknowledgement_does_not_suppress_asserted_conflict"
        ]["actual"]
        self.assertEqual(conflict["outcome"], "BLOCK")
        self.assertEqual(conflict["conflicting"], ["inv-block"])
        for scenario_id in (
            "claude.governed_block_unacknowledged",
            "codex.governed_block_unacknowledged",
        ):
            with self.subTest(scenario_id=scenario_id):
                result = self.results[scenario_id]["actual"]
                self.assertEqual(result["policy"], "BLOCK")
                self.assertEqual(result["permission"], "deny")
                self.assertTrue(result["contains_unacknowledged"])

    def test_cross_harness_parity_and_asymmetry(self) -> None:
        self.assert_category_matched("cross")
        result = self.results["cross.safe_target_asymmetry"]["actual"]
        self.assertEqual(result["classification"], "EXPECTED_ASYMMETRY")
        self.assertEqual(result["claude_transport"], "ask")
        self.assertEqual(result["codex_transport"], "deny")

    def test_v1_acceptance_remains_blocked(self) -> None:
        blockers = {
            item["id"]: item
            for item in self.observed["contract"]["v1_acceptance_blockers"]
        }
        self.assertEqual(blockers["VAB-1"]["status"], "CLOSED")
        self.assertEqual(blockers["VAB-2"]["status"], "CLOSED")
        self.assertEqual(blockers["VAB-3"]["status"], "CLOSED")
        self.assertEqual(blockers["VAB-4"]["status"], "CLOSED")
        self.assertEqual(blockers["VAB-5"]["status"], "CLOSED")
        self.assertEqual(blockers["VAB-6"]["status"], "CLOSED")
        self.assertGreater(
            len([item for item in blockers.values() if item["status"] != "CLOSED"]),
            0,
        )
        self.assertEqual(self.observed["contract"]["v1_acceptance"], "BLOCKED")

    def test_live_verification_is_not_attempted(self) -> None:
        self.assertEqual(
            self.observed["contract"]["live_verification"],
            {
                "INSTALLED_HARNESS_DISPATCH": "NOT_ATTEMPTED",
                "LIVE_MUTATION_DENIAL": "NOT_ATTEMPTED",
                "LIVE_CONTEXT_INJECTION": "NOT_ATTEMPTED",
            },
        )

    def test_raw_observation_is_deterministic(self) -> None:
        first = build_observed_document()
        second = build_observed_document()
        self.assertEqual(
            json.dumps(first, ensure_ascii=False, sort_keys=True),
            json.dumps(second, ensure_ascii=False, sort_keys=True),
        )

    def test_frozen_expected_contract_matches(self) -> None:
        expected = load_expected_document()
        self.assertTrue(compare_contract(self.observed, expected))
        self.assertEqual(set(expected), {"schema_version", "contract"})

    def test_absent_expected_document_fails_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = run(expected_path=path, stdout=stdout, stderr=stderr)
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(stdout.getvalue())["benchmark_execution"], "FAILED")
            self.assertFalse(path.exists())

    def test_malformed_expected_document_fails_without_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "malformed.json"
            original = b"{malformed\n"
            path.write_bytes(original)
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = run(expected_path=path, stdout=stdout, stderr=stderr)
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(stdout.getvalue())["benchmark_execution"], "FAILED")
            self.assertEqual(path.read_bytes(), original)

    def test_runner_never_rewrites_expected_document(self) -> None:
        original = EXPECTED_RESULTS_PATH.read_bytes()
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(run(stdout=stdout, stderr=stderr), 0)
        self.assertEqual(EXPECTED_RESULTS_PATH.read_bytes(), original)

    def test_runner_output_is_canonical_json_only(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(run(stdout=stdout, stderr=stderr), 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["benchmark_execution"], "COMPLETED")
        self.assertTrue(stdout.getvalue().endswith("\n"))
        self.assertEqual(
            stdout.getvalue(),
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        self.assertIn("benchmark_execution=COMPLETED", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
