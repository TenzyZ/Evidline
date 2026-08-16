from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from evidline import context
from evidline.adapters import claude
from evidline.context import ContextProfile
from evidline.mutation import (
    MutationDecision,
    MutationInputError,
    MutationOutcome,
    MutationReason,
    MutationRequest,
    MutationRisk,
)
from evidline.state import (
    Execution,
    Intent,
    Project,
    StateDocument,
    StateIOError,
    StateNotInitializedError,
    StateValidationError,
    Task,
    TaskStatus,
    serialize_state,
)


def make_state(
    *, default_budget_chars: int = 8000, active_task: bool = False
) -> StateDocument:
    tasks: tuple[Task, ...] = ()
    if active_task:
        tasks = (
            Task(
                id="task-1",
                description="Implement the Claude Code adapter",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                approved_at="2026-08-16T00:00:00+04:00",
                approval_channel="interactive",
            ),
        )
    return StateDocument(
        schema_version=1,
        revision=0,
        project=Project(
            name="Evidline",
            purpose="Verified local continuity",
            ignore_globs=(),
            default_budget_chars=default_budget_chars,
        ),
        invariants=(),
        decisions=(),
        tasks=tasks,
        claims=(),
        evidence=(),
        counters={},
    )


def synthetic_decision(outcome: MutationOutcome) -> MutationDecision:
    reason = (
        MutationReason.TARGET_PROTECTED
        if outcome is MutationOutcome.BLOCK
        else MutationReason.REQUEST_INTENT_INSUFFICIENT
    )
    return MutationDecision(
        outcome=outcome,
        risk=MutationRisk.NORMAL,
        target="target.py",
        reasons=() if outcome is MutationOutcome.ALLOW else (reason,),
        next_step="" if outcome is MutationOutcome.ALLOW else "Next step.",
        conflicting_invariant_ids=(),
        advisory_invariant_ids=(),
        applicable_invariant_ids=(),
    )


class ClaudeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "project"
        self.root.mkdir()
        self.write_state(make_state())

    def write_state(self, document: StateDocument) -> Path:
        state_directory = self.root / ".evidline"
        state_directory.mkdir(exist_ok=True)
        state_path = state_directory / "state.json"
        state_path.write_text(serialize_state(document), encoding="utf-8")
        return state_path

    def session_payload(self, *, source: str = "startup") -> dict[str, object]:
        return {
            "hook_event_name": "SessionStart",
            "cwd": str(self.root),
            "source": source,
        }

    def tool_payload(
        self,
        tool_name: str = "Write",
        target: object | None = None,
        **extra: object,
    ) -> dict[str, object]:
        field = {
            "Write": "file_path",
            "Edit": "file_path",
            "NotebookEdit": "notebook_path",
        }.get(tool_name, "command")
        if target is None:
            target = "src/file.py"
        payload: dict[str, object] = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root),
            "tool_name": tool_name,
            "tool_input": {field: target},
        }
        payload.update(extra)
        return payload

    def invoke(
        self,
        command: str,
        payload: object | None = None,
        *,
        raw_input: str | None = None,
    ) -> tuple[int, str, str]:
        stdin = io.StringIO(
            raw_input if raw_input is not None else json.dumps(payload)
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = claude.main((command,))
        return code, stdout.getvalue(), stderr.getvalue()

    def permission_output(self, stdout: str) -> dict[str, object]:
        document = json.loads(stdout)
        self.assertEqual(set(document), {"hookSpecificOutput"})
        output = document["hookSpecificOutput"]
        self.assertIsInstance(output, dict)
        self.assertEqual(
            set(output),
            {
                "hookEventName",
                "permissionDecision",
                "permissionDecisionReason",
            },
        )
        return output

    def snapshot_state_directory(self) -> tuple[bytes, tuple[str, ...]]:
        state_directory = self.root / ".evidline"
        paths = tuple(
            sorted(
                str(path.relative_to(state_directory))
                for path in state_directory.rglob("*")
            )
        )
        return (state_directory.joinpath("state.json").read_bytes(), paths)

    def test_session_start_matches_current_core_payload_byte_for_byte(self) -> None:
        expected = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=None,
            )
        )
        code, stdout, stderr = self.invoke("session-start", self.session_payload())
        self.assertEqual((code, stdout, stderr), (0, expected, ""))

    def test_session_start_uses_project_default_budget(self) -> None:
        minimum = context.minimum_budget_chars(ContextProfile.SESSION)
        self.write_state(
            make_state(default_budget_chars=minimum, active_task=True)
        )
        default_payload = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=None,
            )
        )
        large_payload = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=100000,
            )
        )
        code, stdout, stderr = self.invoke("session-start", self.session_payload())
        self.assertEqual((code, stdout, stderr), (0, default_payload, ""))
        self.assertNotEqual(stdout, large_payload)

    def test_all_session_sources_recompile_to_identical_payload(self) -> None:
        outputs = []
        for source in ("startup", "resume", "clear", "compact", "fork"):
            with self.subTest(source=source):
                code, stdout, stderr = self.invoke(
                    "session-start", self.session_payload(source=source)
                )
                self.assertEqual((code, stderr), (0, ""))
                outputs.append(stdout)
        self.assertEqual(len(set(outputs)), 1)

    def test_session_start_without_root_is_silent(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        payload = self.session_payload()
        payload["cwd"] = str(outside)
        self.assertEqual(self.invoke("session-start", payload), (0, "", ""))

    def test_session_start_state_failures_are_advisory_and_silent(self) -> None:
        cases: list[tuple[str, Path]] = []
        missing = self.base / "missing-state"
        missing.joinpath(".evidline").mkdir(parents=True)
        cases.append(("missing", missing))
        malformed = self.base / "malformed-state"
        malformed.joinpath(".evidline").mkdir(parents=True)
        malformed.joinpath(".evidline", "state.json").write_text(
            "{not json", encoding="utf-8"
        )
        cases.append(("malformed", malformed))

        for name, root in cases:
            with self.subTest(name=name):
                payload = self.session_payload()
                payload["cwd"] = str(root)
                code, stdout, stderr = self.invoke("session-start", payload)
                self.assertEqual((code, stdout), (0, ""))
                self.assertTrue(stderr.startswith("evidline session-start failure:"))

    def test_session_start_compilation_failure_is_advisory(self) -> None:
        with mock.patch.object(
            claude.context,
            "load_and_compile",
            side_effect=context.ContextInputError("failure"),
        ):
            code, stdout, stderr = self.invoke(
                "session-start", self.session_payload()
            )
        self.assertEqual((code, stdout), (0, ""))
        self.assertTrue(stderr.startswith("evidline session-start failure:"))

    def test_session_start_malformed_json_is_advisory(self) -> None:
        code, stdout, stderr = self.invoke(
            "session-start", raw_input="{not json"
        )
        self.assertEqual((code, stdout), (0, ""))
        self.assertTrue(stderr.startswith("evidline session-start failure:"))

    def test_session_start_event_mismatch_is_silent(self) -> None:
        payload = self.session_payload()
        payload["hook_event_name"] = "PreToolUse"
        self.assertEqual(self.invoke("session-start", payload), (0, "", ""))

    def test_session_start_is_repeatable_and_read_only(self) -> None:
        before = self.snapshot_state_directory()
        results = [
            self.invoke("session-start", self.session_payload()) for _ in range(10)
        ]
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.snapshot_state_directory(), before)

    def test_supported_tools_use_exact_target_fields_without_rewriting(self) -> None:
        cases = (
            ("Write", "file_path", r"src\folder\..\write.py"),
            ("Edit", "file_path", "src//edit.py"),
            ("NotebookEdit", "notebook_path", r"notebooks\demo.ipynb"),
        )
        for tool_name, field, raw_target in cases:
            with self.subTest(tool_name=tool_name):
                payload = self.tool_payload(tool_name, raw_target)
                with mock.patch.object(
                    claude.mutation,
                    "evaluate_and_decide",
                    return_value=synthetic_decision(MutationOutcome.ASK),
                ) as evaluate:
                    code, stdout, stderr = self.invoke("pre-tool-use", payload)
                self.assertEqual((code, stderr), (0, ""))
                self.assertEqual(
                    payload["tool_input"],
                    {field: raw_target},
                )
                self.assertEqual(evaluate.call_args.args[2], raw_target)
                self.assertEqual(
                    self.permission_output(stdout)["permissionDecision"], "ask"
                )

    def test_exact_constant_request_is_passed_to_core(self) -> None:
        expected = MutationRequest(
            request_intent=Intent.PROPOSED,
            risk=MutationRisk.NORMAL,
            operation=None,
            authorizing_ids=(),
            declared_scope=(),
            supporting_claim_ids=(),
            ephemeral_evidence_ids=(),
            asserted_conflicting_invariant_ids=(),
        )
        with mock.patch.object(
            claude.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ) as evaluate:
            self.invoke("pre-tool-use", self.tool_payload())
        self.assertEqual(evaluate.call_args.args[0], expected)

    def test_root_discovery_falls_back_to_raw_target(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        raw_target = str(self.root / "src" / "file.py")
        payload = self.tool_payload(target=raw_target)
        payload["cwd"] = str(outside)
        with mock.patch.object(
            claude.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ) as evaluate:
            code, stdout, stderr = self.invoke("pre-tool-use", payload)
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(evaluate.call_args.args[2], raw_target)
        self.assertEqual(
            self.permission_output(stdout)["permissionDecision"], "ask"
        )

    def test_unsupported_tools_and_shell_content_are_silent(self) -> None:
        cases = (
            ("Bash", {"command": "rm -rf src"}),
            ("Bash", {"command": "ls"}),
            ("Bash", {"command": "git checkout ."}),
            ("Bash", {"command": "echo x > a.txt"}),
            ("PowerShell", {"command": "Remove-Item src\\file.py"}),
            ("Monitor", {"command": "git status"}),
            ("Monitor", {"ws": "status"}),
            ("Read", {"file_path": "src/file.py"}),
            ("mcp__filesystem__write", {"path": "src/file.py"}),
        )
        with mock.patch.object(claude.mutation, "evaluate_and_decide") as evaluate:
            for tool_name, tool_input in cases:
                with self.subTest(tool_name=tool_name, tool_input=tool_input):
                    payload = self.tool_payload(tool_name)
                    payload["tool_input"] = tool_input
                    self.assertEqual(
                        self.invoke("pre-tool-use", payload), (0, "", "")
                    )
        evaluate.assert_not_called()

    def test_malformed_supported_inputs_fail_closed(self) -> None:
        base = self.tool_payload()
        cases: list[tuple[str, object | None, str | None]] = [
            ("malformed-json", None, "{not json"),
            ("missing-cwd", {k: v for k, v in base.items() if k != "cwd"}, None),
            (
                "missing-tool-name",
                {k: v for k, v in base.items() if k != "tool_name"},
                None,
            ),
            (
                "missing-tool-input",
                {k: v for k, v in base.items() if k != "tool_input"},
                None,
            ),
            ("tool-input-type", {**base, "tool_input": "wrong"}, None),
            ("missing-target", {**base, "tool_input": {}}, None),
            ("target-int", {**base, "tool_input": {"file_path": 1}}, None),
            ("target-none", {**base, "tool_input": {"file_path": None}}, None),
            ("target-empty", {**base, "tool_input": {"file_path": ""}}, None),
        ]
        for name, payload, raw_input in cases:
            with self.subTest(name=name):
                code, stdout, stderr = self.invoke(
                    "pre-tool-use", payload, raw_input=raw_input
                )
                self.assertEqual((code, stderr), (0, ""))
                output = self.permission_output(stdout)
                self.assertEqual(output["permissionDecision"], "deny")
                self.assertTrue(
                    str(output["permissionDecisionReason"]).startswith(
                        "evidline adapter failure:"
                    )
                )

    def test_pre_tool_use_event_mismatch_fails_closed(self) -> None:
        payload = self.tool_payload()
        payload["hook_event_name"] = "PostToolUse"
        code, stdout, stderr = self.invoke("pre-tool-use", payload)
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(
            self.permission_output(stdout)["permissionDecision"], "deny"
        )

    def test_project_without_evidline_root_is_outside_jurisdiction(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        payload = self.tool_payload(target="src/file.py")
        payload["cwd"] = str(outside)
        self.assertEqual(self.invoke("pre-tool-use", payload), (0, "", ""))

    def test_state_loader_failures_are_adapter_denials(self) -> None:
        failures = (
            StateNotInitializedError("missing"),
            StateValidationError("invalid"),
            StateIOError("unreadable"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    claude.state, "load_state", side_effect=failure
                ):
                    code, stdout, stderr = self.invoke(
                        "pre-tool-use", self.tool_payload()
                    )
                self.assertEqual((code, stderr), (0, ""))
                output = self.permission_output(stdout)
                self.assertEqual(output["permissionDecision"], "deny")
                reason = str(output["permissionDecisionReason"])
                self.assertTrue(reason.startswith("evidline adapter failure:"))
                self.assertNotIn("evidline BLOCK:", reason)
                self.assertIn("no MutationDecision was produced", reason)

    def test_core_and_unknown_outcome_failures_are_adapter_denials(self) -> None:
        cases = (
            MutationInputError("invalid"),
            RuntimeError("unexpected"),
        )
        for failure in cases:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    claude.mutation,
                    "evaluate_and_decide",
                    side_effect=failure,
                ):
                    code, stdout, stderr = self.invoke(
                        "pre-tool-use", self.tool_payload()
                    )
                self.assertEqual((code, stderr), (0, ""))
                reason = str(
                    self.permission_output(stdout)["permissionDecisionReason"]
                )
                self.assertTrue(reason.startswith("evidline adapter failure:"))
                self.assertNotIn("evidline BLOCK:", reason)

        unknown = SimpleNamespace(outcome="UNKNOWN")
        with mock.patch.object(
            claude.mutation, "evaluate_and_decide", return_value=unknown
        ):
            code, stdout, stderr = self.invoke(
                "pre-tool-use", self.tool_payload()
            )
        self.assertEqual((code, stderr), (0, ""))
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline adapter failure:"))

    def test_real_policy_ask_has_exact_claude_shape_and_ordered_reason(self) -> None:
        code, stdout, stderr = self.invoke("pre-tool-use", self.tool_payload())
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "ask")
        reason = str(output["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline ASK:"))
        self.assertLess(
            reason.index("REQUEST_INTENT_INSUFFICIENT"),
            reason.index("NO_ACTIVE_TASK"),
        )
        self.assertTrue(
            reason.endswith(
                "this is an Evidline policy result and is not harness or human "
                "authorization."
            )
        )

    def test_real_policy_block_has_exact_claude_shape(self) -> None:
        code, stdout, stderr = self.invoke(
            "pre-tool-use", self.tool_payload(target=".git/config")
        )
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertTrue(
            str(output["permissionDecisionReason"]).startswith("evidline BLOCK:")
        )

    def test_synthetic_allow_mapping_is_exact_silence(self) -> None:
        with mock.patch.object(
            claude.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ALLOW),
        ):
            code, stdout, stderr = self.invoke(
                "pre-tool-use", self.tool_payload()
            )
        self.assertEqual((code, stdout, stderr), (0, "", ""))
        self.assertNotIn("allow", stdout)

    def test_real_covered_policy_matrix_never_emits_silence(self) -> None:
        outside = self.base / "outside.py"
        cases = (
            (False, "src/file.py"),
            (True, "src/file.py"),
            (True, ".git/config"),
            (True, str(outside)),
        )
        for active_task, target in cases:
            with self.subTest(active_task=active_task, target=target):
                self.write_state(make_state(active_task=active_task))
                code, stdout, stderr = self.invoke(
                    "pre-tool-use", self.tool_payload(target=target)
                )
                self.assertEqual((code, stderr), (0, ""))
                self.assertNotEqual(stdout, "")

    def test_path_core_remains_authority_for_windows_and_protected_paths(self) -> None:
        safe_absolute = str(self.root / "src" / "file.py")
        outside = str(self.base / "outside" / "file.py")
        cases = (
            ("safe-absolute", safe_absolute, "ask"),
            ("outside", outside, "deny"),
            ("root", str(self.root), "deny"),
            ("git", ".git/config", "deny"),
            ("nested-git", "vendor/.git/config", "deny"),
            ("evidline", ".evidline/state.json", "deny"),
            ("nested-evidline", "vendor/.evidline/state.json", "deny"),
        )
        if os.name == "nt":
            cases += (
                ("drive-relative", "C:relative.py", "deny"),
                ("namespace", r"\\?\C:\project\file.py", "deny"),
            )
            self.assertIn("\\", safe_absolute)
        for name, target, expected in cases:
            with self.subTest(name=name):
                code, stdout, stderr = self.invoke(
                    "pre-tool-use", self.tool_payload(target=target)
                )
                self.assertEqual((code, stderr), (0, ""))
                self.assertEqual(
                    self.permission_output(stdout)["permissionDecision"], expected
                )

    def test_permission_mode_is_not_authority_or_risk(self) -> None:
        outputs = []
        for mode in (
            "default",
            "acceptEdits",
            "auto",
            "dontAsk",
            "bypassPermissions",
        ):
            with self.subTest(mode=mode):
                outputs.append(
                    self.invoke(
                        "pre-tool-use",
                        self.tool_payload(permission_mode=mode),
                    )
                )
        self.assertEqual(len(set(outputs)), 1)

    def test_subagent_fields_do_not_change_covered_decision(self) -> None:
        ordinary = self.invoke("pre-tool-use", self.tool_payload())
        subagent = self.invoke(
            "pre-tool-use",
            self.tool_payload(agent_id="agent-1", agent_type="worker"),
        )
        self.assertEqual(subagent, ordinary)

    def test_adapter_is_reentrant_read_only_and_creates_no_claude_state(self) -> None:
        before_state = self.snapshot_state_directory()
        before_tree = tuple(
            sorted(str(path.relative_to(self.base)) for path in self.base.rglob("*"))
        )
        results = [
            self.invoke("pre-tool-use", self.tool_payload()) for _ in range(20)
        ]
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.snapshot_state_directory(), before_state)
        after_tree = tuple(
            sorted(str(path.relative_to(self.base)) for path in self.base.rglob("*"))
        )
        self.assertEqual(after_tree, before_tree)
        self.assertFalse(self.root.joinpath(".claude").exists())

    def test_adapter_uses_no_network_or_subprocess(self) -> None:
        with (
            mock.patch.object(
                socket, "socket", side_effect=AssertionError("network used")
            ),
            mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess used")
            ),
            mock.patch.object(
                subprocess, "run", side_effect=AssertionError("subprocess used")
            ),
        ):
            code, stdout, stderr = self.invoke(
                "pre-tool-use", self.tool_payload()
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertNotEqual(stdout, "")

    def test_adapter_source_has_no_shell_parser(self) -> None:
        source = Path(claude.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import shlex", source)

    def test_structured_stdout_write_failure_exits_two(self) -> None:
        class FailingStdout:
            def write(self, text: str) -> int:
                del text
                raise OSError("closed")

        stdin = io.StringIO(json.dumps(self.tool_payload()))
        stderr = io.StringIO()
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", FailingStdout()),
            mock.patch("sys.stderr", stderr),
        ):
            code = claude.main(("pre-tool-use",))
        self.assertEqual(code, 2)
        self.assertEqual(
            stderr.getvalue(),
            "evidline claude adapter: structured stdout write failed\n",
        )

    def test_missing_and_unknown_adapter_commands_exit_two(self) -> None:
        for arguments in ((), ("unknown",), ("session-start", "extra")):
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch("sys.stdout", stdout),
                    mock.patch("sys.stderr", stderr),
                ):
                    code = claude.main(arguments)
                self.assertEqual((code, stdout.getvalue()), (2, ""))
                self.assertNotEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
