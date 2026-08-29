from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from evidline import doctor, state
from evidline.context import ContextProfile, minimum_budget_chars


class DoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        state.initialize_project(
            self.root,
            project=state.Project("project", "Doctor tests", (), 8000),
        )
        which = mock.patch(
            "evidline.doctor.shutil.which",
            return_value=str(self.root / "evidline-claude-hook.exe"),
        )
        which.start()
        self.addCleanup(which.stop)

    def test_healthy_project_has_all_ten_passing_checks(self) -> None:
        report = doctor.run_diagnostics(self.root)
        self.assertEqual(report.overall_status, doctor.OverallStatus.HEALTHY)
        self.assertEqual(
            [item.id for item in report.checks],
            [f"D{item:03d}" for item in range(1, 11)],
        )
        self.assertTrue(all(item.status is doctor.CheckStatus.PASS for item in report.checks))

    def test_claude_hook_invocable_pass_is_diagnostic_only(self) -> None:
        report = doctor.run_diagnostics(self.root)
        check = report.checks[9]
        self.assertEqual(
            (check.id, check.label, check.status, check.reason),
            (
                "D010",
                "integration.claude_hook_invocable",
                doctor.CheckStatus.PASS,
                doctor.DoctorReason.CHECK_PASSED,
            ),
        )
        self.assertIn("current process environment", check.message)
        self.assertIn("does not prove", check.message)

    def test_missing_claude_hook_warns_without_becoming_unhealthy(self) -> None:
        with mock.patch("evidline.doctor.shutil.which", return_value=None):
            report = doctor.run_diagnostics(self.root)
        check = report.checks[9]
        self.assertEqual(check.status, doctor.CheckStatus.WARN)
        self.assertEqual(
            check.reason,
            doctor.DoctorReason.CLAUDE_HOOK_NOT_RESOLVABLE,
        )
        self.assertEqual(report.overall_status, doctor.OverallStatus.DEGRADED)
        self.assertNotEqual(report.overall_status, doctor.OverallStatus.UNHEALTHY)
        self.assertIn("current process environment", check.message)

    def test_uninitialized_root_has_complete_report(self) -> None:
        report = doctor.run_diagnostics(Path(self.temporary.name) / "missing")
        self.assertEqual(report.overall_status, doctor.OverallStatus.UNHEALTHY)
        self.assertEqual(report.checks[1].reason, doctor.DoctorReason.PROJECT_ROOT_NOT_FOUND)
        self.assertTrue(all(item.reason is doctor.DoctorReason.NOT_REACHED for item in report.checks[2:9]))
        self.assertEqual(report.checks[9].status, doctor.CheckStatus.PASS)

    def test_exception_mapping_and_single_load(self) -> None:
        cases = (
            (state.StateNotInitializedError("absent"), 2, doctor.DoctorReason.STATE_FILE_ABSENT, ()),
            (state.StateIOError("denied"), 3, doctor.DoctorReason.STATE_UNREADABLE, (2,)),
            (state.StateJSONError("json"), 4, doctor.DoctorReason.STATE_JSON_INVALID, (2, 3)),
            (state.UnsupportedSchemaError("schema"), 5, doctor.DoctorReason.SCHEMA_UNSUPPORTED, (2, 3, 4)),
            (state.IncompatibleScopeSemanticsError("scope"), 6, doctor.DoctorReason.SCOPE_SEMANTICS_INCOMPATIBLE, (2, 3, 4, 5)),
            (state.StateValidationError("structure"), 7, doctor.DoctorReason.STATE_STRUCTURE_INVALID, (2, 3, 4)),
        )
        for error, failed, reason, passing in cases:
            with self.subTest(error=type(error).__name__), mock.patch("evidline.doctor._state.load_state", side_effect=error) as load:
                report = doctor.run_diagnostics(self.root)
                self.assertEqual(load.call_count, 1)
                self.assertEqual(report.checks[failed].reason, reason)
                self.assertTrue(all(report.checks[index].status is doctor.CheckStatus.PASS for index in passing))
                self.assertTrue(all(item.status is doctor.CheckStatus.SKIP for item in report.checks[failed + 1:9]))
                self.assertEqual(report.checks[9].status, doctor.CheckStatus.PASS)
        with mock.patch("evidline.doctor._state.load_state", side_effect=state.StateValidationError("structure")):
            report = doctor.run_diagnostics(self.root)
        self.assertEqual(report.checks[6].status, doctor.CheckStatus.SKIP)
        self.assertEqual(report.checks[6].reason, doctor.DoctorReason.NOT_REACHED)

    def test_real_structural_failure_does_not_promote_schema_or_scope(self) -> None:
        (self.root / ".evidline" / "state.json").write_text("{}\n", encoding="utf-8")
        report = doctor.run_diagnostics(self.root)
        self.assertEqual(report.checks[4].status, doctor.CheckStatus.PASS)
        self.assertEqual(report.checks[5].status, doctor.CheckStatus.SKIP)
        self.assertEqual(report.checks[5].reason, doctor.DoctorReason.NOT_REACHED)
        self.assertEqual(report.checks[6].status, doctor.CheckStatus.SKIP)
        self.assertEqual(report.checks[6].reason, doctor.DoctorReason.NOT_REACHED)
        self.assertEqual(report.checks[7].status, doctor.CheckStatus.FAIL)
        self.assertEqual(report.checks[7].reason, doctor.DoctorReason.STATE_STRUCTURE_INVALID)
        self.assertIsNone(report.state_schema_version)
        self.assertEqual(report.overall_status, doctor.OverallStatus.UNHEALTHY)

    def test_budget_degraded_and_read_only_rendering(self) -> None:
        document = state.load_state(self.root)
        minimums = [minimum_budget_chars(profile) for profile in ContextProfile]
        budget = min(minimums)
        state.write_state(self.root, replace(document, project=replace(document.project, default_budget_chars=budget)), expected_revision=document.revision)
        before = (self.root / ".evidline" / "state.json").read_bytes()
        report = doctor.run_diagnostics(self.root)
        after = (self.root / ".evidline" / "state.json").read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(report.overall_status, doctor.OverallStatus.DEGRADED)
        self.assertEqual(
            report.checks[8].reason,
            doctor.DoctorReason.BUDGET_BELOW_PROFILE_MINIMUM,
        )
        first_json = doctor.render_doctor_json(report)
        self.assertEqual(first_json, doctor.render_doctor_json(report))
        self.assertEqual(json.loads(first_json)["checks"][0]["id"], "D001")
        self.assertEqual(doctor.render_doctor_text(report), doctor.render_doctor_text(report))

    def test_budget_below_all_profiles_is_unhealthy(self) -> None:
        document = state.load_state(self.root)
        minimums = [minimum_budget_chars(profile) for profile in ContextProfile]
        state.write_state(
            self.root,
            replace(document, project=replace(document.project, default_budget_chars=min(minimums) - 1)),
            expected_revision=document.revision,
        )
        report = doctor.run_diagnostics(self.root)
        self.assertEqual(report.checks[8].status, doctor.CheckStatus.FAIL)
        self.assertEqual(report.checks[8].reason, doctor.DoctorReason.BUDGET_BELOW_ALL_PROFILES)
        self.assertEqual(report.overall_status, doctor.OverallStatus.UNHEALTHY)

    def test_renderers_reject_wrong_type(self) -> None:
        with self.assertRaises(TypeError):
            doctor.render_doctor_json(object())
        with self.assertRaises(TypeError):
            doctor.render_doctor_text(object())


if __name__ == "__main__":
    unittest.main()
