from __future__ import annotations

import errno
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from evidline import context
from evidline.adapters import codex
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
    Invariant,
    InvariantEnforcement,
    InvariantStatus,
    Project,
    StateDocument,
    StateIOError,
    StateNotInitializedError,
    StateValidationError,
    Task,
    TaskStatus,
    TRUSTED_APPROVAL_CHANNEL,
    TRUSTED_ASSERTED_ACTOR,
    serialize_state,
)


def make_state(
    *,
    default_budget_chars: int = 8000,
    active_task: bool = False,
    authorized_scope: tuple[str, ...] = (),
    trusted: bool = False,
    governed_scope: tuple[str, ...] = (),
) -> StateDocument:
    tasks: tuple[Task, ...] = ()
    if active_task:
        tasks = (
            Task(
                id="task-1",
                description="Implement the Codex adapter",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                authorized_scope=authorized_scope,
                approved_at="2026-08-16T00:00:00+04:00",
                approval_channel=(
                    TRUSTED_APPROVAL_CHANNEL if trusted else "interactive"
                ),
                asserted_actor=TRUSTED_ASSERTED_ACTOR if trusted else None,
            ),
        )
    invariants = (
        (
            Invariant(
                id="inv-governed",
                description="Governed adapter target",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
                governed_scope=governed_scope,
            ),
        )
        if governed_scope
        else ()
    )
    return StateDocument(
        schema_version=4,
        revision=0,
        project=Project(
            name="Evidline",
            purpose="Verified local continuity",
            ignore_globs=(),
            default_budget_chars=default_budget_chars,
        ),
        invariants=invariants,
        decisions=(),
        tasks=tasks,
        claims=(),
        evidence=(),
        counters={},
    )


def synthetic_decision(
    outcome: MutationOutcome,
    *,
    target: str = "target.py",
    next_step: str = "Next step.",
) -> MutationDecision:
    reason = (
        MutationReason.TARGET_PROTECTED
        if outcome is MutationOutcome.BLOCK
        else MutationReason.REQUEST_INTENT_INSUFFICIENT
    )
    return MutationDecision(
        outcome=outcome,
        risk=MutationRisk.NORMAL,
        target=target,
        reasons=() if outcome is MutationOutcome.ALLOW else (reason,),
        next_step="" if outcome is MutationOutcome.ALLOW else next_step,
        conflicting_invariant_ids=(),
        advisory_invariant_ids=(),
        applicable_invariant_ids=(),
    )


def patch_text(*lines: str) -> str:
    return "\n".join(("*** Begin Patch", *lines, "*** End Patch"))


class BinaryOutput:
    """Text facade with an independently controllable binary boundary."""

    def __init__(
        self,
        *,
        text_encoding: str = "utf-8",
        fail_binary_writes: int | None = 0,
        write_actions: tuple[int | BaseException | _EmitThenRaise, ...] = (),
        zero_progress_forever: bool = False,
    ) -> None:
        self._raw = io.BytesIO()
        self._text_encoding = text_encoding
        self.buffer = _ControlledBinaryWriter(
            self._raw,
            fail_binary_writes,
            write_actions,
            zero_progress_forever,
        )

    def write(self, text: str) -> int:
        self._raw.write(text.encode(self._text_encoding))
        return len(text)

    def flush(self) -> None:
        self._raw.flush()

    def getvalue(self) -> bytes:
        return self._raw.getvalue()


class _ControlledBinaryWriter:
    def __init__(
        self,
        raw: io.BytesIO,
        failures_remaining: int | None,
        write_actions: tuple[int | BaseException | _EmitThenRaise, ...],
        zero_progress_forever: bool,
    ) -> None:
        self._raw = raw
        self._failures_remaining = failures_remaining
        self._write_actions = list(write_actions)
        self._zero_progress_forever = zero_progress_forever

    def write(self, data: bytes) -> int:
        if self._write_actions:
            action = self._write_actions.pop(0)
            if isinstance(action, _EmitThenRaise):
                self._raw.write(data[: action.byte_count])
                raise action.error
            if isinstance(action, BaseException):
                raise action
            self._raw.write(data[:action])
            return action
        if self._zero_progress_forever:
            return 0
        if self._failures_remaining is None:
            raise OSError("binary stdout unavailable")
        if self._failures_remaining:
            self._failures_remaining -= 1
            raise OSError("binary stdout unavailable")
        return self._raw.write(data)

    def flush(self) -> None:
        self._raw.flush()


class _EmitThenRaise:
    def __init__(self, byte_count: int, error: BaseException) -> None:
        self.byte_count = byte_count
        self.error = error


class _FailOnceRaw(io.RawIOBase):
    def __init__(self, byte_count: int) -> None:
        super().__init__()
        self.sink = io.BytesIO()
        self._byte_count = byte_count
        self._failed = False

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        if not self._failed:
            self._failed = True
            self.sink.write(bytes(data[: self._byte_count]))
            raise OSError("raw write failed after emitting bytes")
        return self.sink.write(bytes(data))


class _BufferedFailOnceOutput:
    def __init__(self) -> None:
        self.raw = _FailOnceRaw(byte_count=7)
        self.buffer = io.BufferedWriter(self.raw, buffer_size=8)

    def getvalue(self) -> bytes:
        return self.raw.sink.getvalue()


class CodexAdapterTests(unittest.TestCase):
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
            "model": "gpt-test",
            "permission_mode": "default",
        }

    def tool_payload(
        self,
        command: object | None = None,
        *,
        tool_name: object = "apply_patch",
        cwd: object | None = None,
        **extra: object,
    ) -> dict[str, object]:
        if command is None:
            command = patch_text("*** Update File: src/file.py", "@@", "+line")
        payload: dict[str, object] = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root) if cwd is None else cwd,
            "tool_name": tool_name,
            "tool_input": {"command": command},
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
        code, stdout, stderr = self.invoke_bytes(
            command,
            payload,
            raw_input=raw_input,
        )
        return code, stdout.decode("utf-8"), stderr.decode("utf-8")

    def invoke_bytes(
        self,
        command: str,
        payload: object | None = None,
        *,
        raw_input: str | None = None,
        stdout: BinaryOutput | _BufferedFailOnceOutput | None = None,
    ) -> tuple[int, bytes, bytes]:
        stdin = io.StringIO(
            raw_input if raw_input is not None else json.dumps(payload)
        )
        stdout = stdout or BinaryOutput()
        stderr = BinaryOutput()
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = codex.main((command,))
        return code, stdout.getvalue(), stderr.getvalue()

    def strict_utf8(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"stdout is not strict UTF-8: {exc}")

    def session_output(self, stdout: str) -> dict[str, object]:
        document = json.loads(stdout)
        self.assertEqual(set(document), {"hookSpecificOutput"})
        output = document["hookSpecificOutput"]
        self.assertIsInstance(output, dict)
        self.assertEqual(set(output), {"hookEventName", "additionalContext"})
        self.assertEqual(output["hookEventName"], "SessionStart")
        return output

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
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertTrue(str(output["permissionDecisionReason"]).strip())
        return output

    def assert_adapter_failure(self, result: tuple[int, str, str]) -> None:
        code, stdout, stderr = result
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        reason = str(output["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline adapter failure:"))
        self.assertIn("no MutationDecision was produced", reason)
        self.assertNotIn("evidline BLOCK:", reason)

    def snapshot_tree(self) -> tuple[tuple[str, bytes | None], ...]:
        snapshot: list[tuple[str, bytes | None]] = []
        for path in sorted(self.root.rglob("*")):
            relative = str(path.relative_to(self.root))
            snapshot.append((relative, path.read_bytes() if path.is_file() else None))
        return tuple(snapshot)

    def test_session_start_matches_current_core_payload_exactly(self) -> None:
        expected = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=None,
            )
        )
        code, stdout, stderr = self.invoke("session-start", self.session_payload())
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(self.session_output(stdout)["additionalContext"], expected)

    def test_session_start_emits_unicode_context_as_utf8_bytes(self) -> None:
        self.write_state(make_state(governed_scope=("src",)))
        expected = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=None,
            )
        )
        self.assertIn("—", expected)
        output = BinaryOutput(text_encoding="cp1252")

        code, raw, stderr = self.invoke_bytes(
            "session-start", self.session_payload(), stdout=output
        )

        self.assertEqual((code, stderr), (0, b""))
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        document = json.loads(self.strict_utf8(raw))
        hook_output = document["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "SessionStart")
        self.assertEqual(hook_output["additionalContext"], expected)

    def test_session_start_preserves_unicode_outside_cp1252(self) -> None:
        document = make_state(governed_scope=("src",))
        invariant = document.invariants[0]
        self.write_state(
            StateDocument(
                schema_version=document.schema_version,
                revision=document.revision,
                project=document.project,
                invariants=(
                    Invariant(
                        id=invariant.id,
                        description="Protect ✓ 漢字",
                        enforcement=invariant.enforcement,
                        status=invariant.status,
                        governed_scope=invariant.governed_scope,
                    ),
                ),
                decisions=document.decisions,
                tasks=document.tasks,
                claims=document.claims,
                evidence=document.evidence,
                counters=document.counters,
            )
        )
        output = BinaryOutput(text_encoding="cp1252")

        code, raw, stderr = self.invoke_bytes(
            "session-start", self.session_payload(), stdout=output
        )

        self.assertEqual((code, stderr), (0, b""))
        decoded = self.strict_utf8(raw)
        self.assertIn("✓", decoded)
        self.assertIn("漢字", decoded)

    def test_session_start_uses_project_default_budget(self) -> None:
        minimum = context.minimum_budget_chars(ContextProfile.SESSION)
        self.write_state(make_state(default_budget_chars=minimum, active_task=True))
        expected = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=None,
            )
        )
        unbounded = context.render_payload(
            context.load_and_compile(
                self.root,
                profile=ContextProfile.SESSION,
                budget_chars=100000,
            )
        )
        _, stdout, _ = self.invoke("session-start", self.session_payload())
        actual = str(self.session_output(stdout)["additionalContext"])
        self.assertEqual(actual, expected)
        self.assertNotEqual(actual, unbounded)

    def test_all_documented_and_unknown_session_sources_are_identical(self) -> None:
        outputs = []
        for source in ("startup", "resume", "clear", "compact", "unknown"):
            with self.subTest(source=source):
                result = self.invoke("session-start", self.session_payload(source=source))
                self.assertEqual((result[0], result[2]), (0, ""))
                outputs.append(result[1])
        self.assertEqual(len(set(outputs)), 1)

    def test_session_start_input_failures_are_advisory(self) -> None:
        base = self.session_payload()
        cases: tuple[tuple[str, object | None, str | None], ...] = (
            ("malformed-json", None, "{not json"),
            ("wrong-shape", [], None),
            ("wrong-event", {**base, "hook_event_name": "PreToolUse"}, None),
            ("missing-cwd", {key: value for key, value in base.items() if key != "cwd"}, None),
            ("blank-cwd", {**base, "cwd": "   "}, None),
        )
        for name, payload, raw_input in cases:
            with self.subTest(name=name):
                code, stdout, stderr = self.invoke(
                    "session-start", payload, raw_input=raw_input
                )
                self.assertEqual((code, stdout), (0, ""))
                self.assertEqual(
                    stderr,
                    "evidline codex session-start failure: context unavailable\n",
                )

    def test_session_start_without_root_is_silent(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        payload = self.session_payload()
        payload["cwd"] = str(outside)
        self.assertEqual(self.invoke("session-start", payload), (0, "", ""))

    def test_session_start_missing_and_malformed_state_are_advisory(self) -> None:
        missing = self.base / "missing"
        missing.joinpath(".evidline").mkdir(parents=True)
        malformed = self.base / "malformed"
        malformed.joinpath(".evidline").mkdir(parents=True)
        malformed.joinpath(".evidline", "state.json").write_text(
            "{not json", encoding="utf-8"
        )
        for name, root in (("missing", missing), ("malformed", malformed)):
            with self.subTest(name=name):
                payload = self.session_payload()
                payload["cwd"] = str(root)
                code, stdout, stderr = self.invoke("session-start", payload)
                self.assertEqual((code, stdout), (0, ""))
                self.assertEqual(
                    stderr,
                    "evidline codex session-start failure: context unavailable\n",
                )

    def test_session_start_context_failure_is_advisory(self) -> None:
        with mock.patch.object(
            codex.context,
            "load_and_compile",
            side_effect=context.ContextInputError("failure"),
        ):
            result = self.invoke("session-start", self.session_payload())
        self.assertEqual(
            result,
            (
                0,
                "",
                "evidline codex session-start failure: context unavailable\n",
            ),
        )

    def test_session_start_is_deterministic_and_read_only(self) -> None:
        before = self.snapshot_tree()
        results = [
            self.invoke("session-start", self.session_payload()) for _ in range(10)
        ]
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.snapshot_tree(), before)

    def test_extracts_all_operations_and_frozen_body_forms(self) -> None:
        command = patch_text(
            "*** Add File: add.py",
            "+added",
            "*** Update File: old.py",
            "*** Move to: new.py",
            "@@",
            "@@ context",
            "-old",
            "+new",
            " context",
            "*** End of File",
            "",
            "*** Delete File: delete.py",
        )
        self.assertEqual(
            codex._extract_patch_targets(command),
            ("add.py", "old.py", "new.py", "delete.py"),
        )

    def test_rename_extracts_source_before_destination(self) -> None:
        command = patch_text(
            "*** Update File: source.py",
            "*** Move to: destination.py",
            "@@",
            "-old",
            "+new",
        )
        self.assertEqual(
            codex._extract_patch_targets(command),
            ("source.py", "destination.py"),
        )

    def test_all_three_heredoc_wrappers_are_supported(self) -> None:
        direct = patch_text("*** Add File: file.py", "+content")
        for opener in ("<<EOF", "<<'EOF'", '<<"EOF"'):
            with self.subTest(opener=opener):
                wrapped = f"{opener}\n{direct}\nEOF"
                self.assertEqual(codex._extract_patch_targets(wrapped), ("file.py",))

    def test_target_paths_strip_only_surrounding_whitespace(self) -> None:
        command = patch_text("*** Add File:   folder/../file.py   ", "+content")
        self.assertEqual(
            codex._extract_patch_targets(command), ("folder/../file.py",)
        )

    def test_malformed_patch_envelopes_fail_closed(self) -> None:
        cases = {
            "missing-begin": "*** Add File: file.py\n+content\n*** End Patch",
            "missing-end": "*** Begin Patch\n*** Add File: file.py\n+content",
            "empty-command": "   ",
            "empty-patch": patch_text(),
            "bad-heredoc": "<<PATCH\n" + patch_text("*** Add File: file.py") + "\nPATCH",
            "missing-heredoc-end": "<<EOF\n" + patch_text("*** Add File: file.py"),
        }
        for name, command in cases.items():
            with self.subTest(name=name):
                self.assert_adapter_failure(
                    self.invoke("pre-tool-use", self.tool_payload(command))
                )

    def test_malformed_patch_operations_fail_closed(self) -> None:
        cases = {
            "empty-add": patch_text("*** Add File:   "),
            "empty-delete": patch_text("*** Delete File:   "),
            "empty-update": patch_text("*** Update File:   "),
            "orphan-move": patch_text("*** Move to: destination.py"),
            "second-move": patch_text(
                "*** Update File: source.py",
                "*** Move to: first.py",
                "*** Move to: second.py",
            ),
            "unknown-line": patch_text(
                "*** Add File: file.py", "unclassified"
            ),
            "missing-marker-space": patch_text("*** Add File:file.py", "+content"),
            "environment-id": patch_text(
                "*** Environment ID: remote",
                "*** Add File: file.py",
                "+content",
            ),
        }
        for name, command in cases.items():
            with self.subTest(name=name):
                self.assert_adapter_failure(
                    self.invoke("pre-tool-use", self.tool_payload(command))
                )

    def test_exact_request_contract_is_passed_to_core(self) -> None:
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
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ) as evaluate:
            self.invoke("pre-tool-use", self.tool_payload())
        self.assertEqual(evaluate.call_args.args[0], expected)

    def test_duplicate_targets_are_evaluated_once_in_first_appearance_order(self) -> None:
        command = patch_text(
            "*** Add File: duplicate.py",
            "+content",
            "*** Update File: second.py",
            "@@",
            "+content",
            "*** Delete File: duplicate.py",
        )
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ) as evaluate:
            self.invoke("pre-tool-use", self.tool_payload(command))
        evaluated = [call.args[2] for call in evaluate.call_args_list]
        self.assertEqual(
            evaluated,
            [str(self.root / "duplicate.py"), str(self.root / "second.py")],
        )

    def test_path_and_policy_boundaries_use_existing_core(self) -> None:
        self.write_state(make_state(active_task=True))
        outside = self.base / "outside.py"
        cases = (
            ("root-git", ".git/config", "evidline BLOCK:"),
            ("nested-git", "vendor/.git/config", "evidline BLOCK:"),
            ("root-state", ".evidline/state.json", "evidline BLOCK:"),
            ("nested-state", "vendor/.evidline/state.json", "evidline BLOCK:"),
            ("escape", "../escape.py", "evidline BLOCK:"),
            ("absolute-outside", str(outside), "evidline BLOCK:"),
            ("ordinary", "src/file.py", "evidline ASK:"),
        )
        for name, target, prefix in cases:
            with self.subTest(name=name):
                command = patch_text("*** Add File: " + target, "+content")
                code, stdout, stderr = self.invoke(
                    "pre-tool-use", self.tool_payload(command)
                )
                self.assertEqual((code, stderr), (0, ""))
                reason = str(self.permission_output(stdout)["permissionDecisionReason"])
                self.assertTrue(reason.startswith(prefix))

    def test_cwd_relative_anchoring_and_absolute_passthrough_are_exact(self) -> None:
        subdirectory = self.root / "subdirectory"
        subdirectory.mkdir()
        absolute = str(self.root / "absolute.py")
        cases = (
            (
                "relative",
                "folder/../relative.py",
                os.path.join(str(subdirectory), "folder/../relative.py"),
            ),
            ("absolute", absolute, absolute),
        )
        for name, raw_target, expected in cases:
            with self.subTest(name=name):
                command = patch_text("*** Add File: " + raw_target, "+content")
                with mock.patch.object(
                    codex.mutation,
                    "evaluate_and_decide",
                    return_value=synthetic_decision(MutationOutcome.ASK),
                ) as evaluate:
                    self.invoke(
                        "pre-tool-use",
                        self.tool_payload(command, cwd=str(subdirectory)),
                    )
                self.assertEqual(evaluate.call_args.args[2], expected)

    @unittest.skipUnless(os.name == "nt", "Windows path forms")
    def test_windows_drive_relative_and_namespace_paths_follow_frozen_rules(self) -> None:
        self.write_state(make_state(active_task=True))
        drive_relative = r"C:relative.py"
        command = patch_text("*** Add File: " + drive_relative, "+content")
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ) as evaluate:
            self.invoke("pre-tool-use", self.tool_payload(command))
        self.assertEqual(
            evaluate.call_args.args[2], os.path.join(str(self.root), drive_relative)
        )

        for target in (r"\\?\C:\outside.py", r"\\.\NUL"):
            with self.subTest(target=target):
                command = patch_text("*** Add File: " + target, "+content")
                _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload(command))
                reason = str(self.permission_output(stdout)["permissionDecisionReason"])
                self.assertTrue(reason.startswith("evidline BLOCK:"))

    def test_ask_and_block_map_only_to_codex_deny(self) -> None:
        for outcome, prefix in (
            (MutationOutcome.ASK, "evidline ASK:"),
            (MutationOutcome.BLOCK, "evidline BLOCK:"),
        ):
            with self.subTest(outcome=outcome.value):
                with mock.patch.object(
                    codex.mutation,
                    "evaluate_and_decide",
                    return_value=synthetic_decision(outcome),
                ):
                    code, stdout, stderr = self.invoke(
                        "pre-tool-use", self.tool_payload()
                    )
                self.assertEqual((code, stderr), (0, ""))
                output = self.permission_output(stdout)
                self.assertTrue(
                    str(output["permissionDecisionReason"]).startswith(prefix)
                )
                self.assertNotEqual(output["permissionDecision"], "ask")
                self.assertNotEqual(output["permissionDecision"], "allow")

    def test_ask_reason_requires_state_change_before_retry(self) -> None:
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ASK),
        ):
            _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload())
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertIn("stronger human authorization or evidence is required", reason)
        self.assertIn("retry only after Evidline state changes", reason)

    def test_ask_plus_block_collapses_atomically_to_block(self) -> None:
        command = patch_text(
            "*** Add File: safe.py",
            "+content",
            "*** Add File: .git/config",
            "+content",
        )
        decisions = (
            synthetic_decision(MutationOutcome.ASK),
            synthetic_decision(MutationOutcome.BLOCK),
        )
        with mock.patch.object(
            codex.mutation, "evaluate_and_decide", side_effect=decisions
        ):
            _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload(command))
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline BLOCK:"))
        self.assertIn("target_count=2", reason)

    def test_three_safe_targets_plus_one_protected_target_blocks_all(self) -> None:
        self.write_state(make_state(active_task=True))
        command = patch_text(
            "*** Add File: one.py",
            "+one",
            "*** Add File: two.py",
            "+two",
            "*** Add File: three.py",
            "+three",
            "*** Add File: vendor/.git/config",
            "+protected",
        )
        _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload(command))
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline BLOCK:"))
        self.assertIn("target_count=4", reason)

    def test_same_severity_tie_uses_first_target(self) -> None:
        command = patch_text(
            "*** Add File: first.py",
            "+first",
            "*** Add File: second.py",
            "+second",
        )
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            side_effect=(
                synthetic_decision(MutationOutcome.BLOCK),
                synthetic_decision(MutationOutcome.BLOCK),
            ),
        ):
            _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload(command))
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertIn(str(self.root / "first.py"), reason)
        self.assertNotIn(str(self.root / "second.py"), reason)

    def test_synthetic_allow_is_silence_not_permission(self) -> None:
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ALLOW),
        ):
            result = self.invoke("pre-tool-use", self.tool_payload())
        self.assertEqual(result, (0, "", ""))

    def test_allow_control_emits_no_bytes(self) -> None:
        with mock.patch.object(
            codex.mutation,
            "evaluate_and_decide",
            return_value=synthetic_decision(MutationOutcome.ALLOW),
        ):
            code, stdout, stderr = self.invoke_bytes(
                "pre-tool-use", self.tool_payload()
            )
        self.assertEqual((code, stdout, stderr), (0, b"", b""))

    def test_real_scoped_authorization_reaches_silent_allow(self) -> None:
        self.write_state(
            make_state(
                active_task=True,
                authorized_scope=("src",),
                trusted=True,
            )
        )
        self.assertEqual(
            self.invoke("pre-tool-use", self.tool_payload()),
            (0, "", ""),
        )

    def test_real_governed_block_is_transported_as_codex_deny(self) -> None:
        self.write_state(
            make_state(
                active_task=True,
                authorized_scope=("src",),
                trusted=True,
                governed_scope=("src",),
            )
        )
        code, stdout, stderr = self.invoke(
            "pre-tool-use",
            self.tool_payload(),
        )
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn(
            MutationReason.INVARIANT_UNACKNOWLEDGED.value,
            str(output["permissionDecisionReason"]),
        )

    def test_unicode_block_cannot_become_unparseable_success(self) -> None:
        self.write_state(
            make_state(
                active_task=True,
                authorized_scope=("src",),
                trusted=True,
                governed_scope=("src",),
            )
        )
        output = BinaryOutput(text_encoding="cp1252")

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use",
            self.tool_payload(
                patch_text("*** Update File: src/café.py", "@@", "+line")
            ),
            stdout=output,
        )

        self.assertEqual((code, stderr), (0, b""))
        self.assertNotEqual(raw, b"")
        document = json.loads(self.strict_utf8(raw))
        hook_output = document["hookSpecificOutput"]
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertIn("café.py", hook_output["permissionDecisionReason"])

    def test_denial_transport_completes_multiple_short_writes(self) -> None:
        output = BinaryOutput(write_actions=(1, 2, 3))

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual((code, stderr), (0, b""))
        document = json.loads(self.strict_utf8(raw))
        hook_output = document["hookSpecificOutput"]
        self.assertEqual(hook_output["permissionDecision"], "deny")

    def test_partial_denial_write_then_failure_does_not_append_fallback(self) -> None:
        output = BinaryOutput(
            write_actions=(7, OSError("binary stdout unavailable"))
        )

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual(code, 2)
        self.assertNotEqual(raw, b"")
        self.assertNotIn(b"transport failure", raw)
        self.assertIn(b"structured stdout write failed", stderr)

    def test_same_call_emit_then_failure_does_not_append_fallback(self) -> None:
        output = BinaryOutput(
            write_actions=(_EmitThenRaise(7, OSError("write failed")),)
        )

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual(code, 2)
        self.assertNotEqual(raw, b"")
        self.assertNotIn(b"transport failure", raw)
        self.assertIn(b"structured stdout write failed", stderr)

    def test_blocking_write_with_characters_written_does_not_append_fallback(
        self,
    ) -> None:
        error = BlockingIOError(errno.EAGAIN, "blocked", 7)
        output = BinaryOutput(write_actions=(_EmitThenRaise(7, error),))

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual(code, 2)
        self.assertNotEqual(raw, b"")
        self.assertNotIn(b"transport failure", raw)
        self.assertIn(b"structured stdout write failed", stderr)

    def test_real_buffered_writer_failure_does_not_append_fallback(self) -> None:
        output = _BufferedFailOnceOutput()
        long_reason = "governed target denied: " + ("x" * 16_384)

        with mock.patch.object(codex, "_policy_reason", return_value=long_reason):
            code, raw, stderr = self.invoke_bytes(
                "pre-tool-use", self.tool_payload(), stdout=output
            )

        self.assertEqual(code, 2)
        self.assertNotEqual(raw, b"")
        self.assertNotIn(b"transport failure", raw)
        self.assertIn(b"structured stdout write failed", stderr)

    def test_denial_encoding_failure_emits_ascii_safe_denial(self) -> None:
        with mock.patch.object(codex, "_policy_reason", return_value="deny \ud800"):
            code, raw, stderr = self.invoke_bytes(
                "pre-tool-use", self.tool_payload()
            )

        self.assertEqual((code, stderr), (0, b""))
        document = json.loads(raw.decode("ascii"))
        hook_output = document["hookSpecificOutput"]
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertIn("transport failure", hook_output["permissionDecisionReason"])

    def test_zero_progress_denial_writer_exits_nonzero_without_output(self) -> None:
        output = BinaryOutput(zero_progress_forever=True)

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual((code, raw), (2, b""))
        self.assertIn(b"structured stdout write failed", stderr)

    def test_total_denial_transport_failure_exits_nonzero(self) -> None:
        output = BinaryOutput(fail_binary_writes=None)

        code, raw, stderr = self.invoke_bytes(
            "pre-tool-use", self.tool_payload(), stdout=output
        )

        self.assertEqual((code, raw), (2, b""))
        self.assertIn(b"structured stdout write failed", stderr)

    def test_real_multi_target_uses_max_severity_when_one_target_is_unauthorized(self) -> None:
        self.write_state(
            make_state(
                active_task=True,
                authorized_scope=("src",),
                trusted=True,
            )
        )
        command = patch_text(
            "*** Add File: src/allowed.py",
            "+allowed",
            "*** Add File: docs/unauthorized.py",
            "+unauthorized",
        )
        code, stdout, stderr = self.invoke(
            "pre-tool-use", self.tool_payload(command)
        )
        self.assertEqual((code, stderr), (0, ""))
        reason = str(self.permission_output(stdout)["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline ASK:"))
        self.assertIn("target_count=2", reason)

    def test_state_loader_failures_are_adapter_denials(self) -> None:
        failures = (
            StateNotInitializedError("missing"),
            StateValidationError("invalid"),
            StateIOError("unreadable"),
            RuntimeError("unexpected"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    codex.state, "load_state", side_effect=failure
                ):
                    result = self.invoke("pre-tool-use", self.tool_payload())
                self.assert_adapter_failure(result)

    def test_core_and_unknown_outcome_failures_are_adapter_denials(self) -> None:
        failures = (
            MutationInputError("invalid"),
            RuntimeError("unexpected"),
            SimpleNamespace(outcome="UNKNOWN"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                kwargs = (
                    {"return_value": failure}
                    if isinstance(failure, SimpleNamespace)
                    else {"side_effect": failure}
                )
                with mock.patch.object(
                    codex.mutation, "evaluate_and_decide", **kwargs
                ):
                    result = self.invoke("pre-tool-use", self.tool_payload())
                self.assert_adapter_failure(result)

    def test_malformed_covered_inputs_fail_closed(self) -> None:
        base = self.tool_payload()
        cases: tuple[tuple[str, object | None, str | None], ...] = (
            ("malformed-json", None, "{not json"),
            ("wrong-shape", [], None),
            ("wrong-event", {**base, "hook_event_name": "PostToolUse"}, None),
            ("missing-cwd", {key: value for key, value in base.items() if key != "cwd"}, None),
            ("blank-cwd", {**base, "cwd": " "}, None),
            ("missing-tool", {key: value for key, value in base.items() if key != "tool_name"}, None),
            ("tool-type", {**base, "tool_name": 1}, None),
            ("missing-input", {key: value for key, value in base.items() if key != "tool_input"}, None),
            ("input-type", {**base, "tool_input": "wrong"}, None),
            ("missing-command", {**base, "tool_input": {}}, None),
            ("command-type", {**base, "tool_input": {"command": 1}}, None),
            ("empty-command", {**base, "tool_input": {"command": ""}}, None),
            ("blank-command", {**base, "tool_input": {"command": "  "}}, None),
        )
        for name, payload, raw_input in cases:
            with self.subTest(name=name):
                self.assert_adapter_failure(
                    self.invoke("pre-tool-use", payload, raw_input=raw_input)
                )

    def test_every_deny_uses_only_the_frozen_transport_keys(self) -> None:
        cases = (
            synthetic_decision(MutationOutcome.ASK),
            synthetic_decision(MutationOutcome.BLOCK),
        )
        for decision in cases:
            with self.subTest(outcome=decision.outcome.value):
                with mock.patch.object(
                    codex.mutation,
                    "evaluate_and_decide",
                    return_value=decision,
                ):
                    _, stdout, _ = self.invoke("pre-tool-use", self.tool_payload())
                output = self.permission_output(stdout)
                prohibited = {
                    "updatedInput",
                    "additionalContext",
                    "systemMessage",
                    "continue",
                    "stopReason",
                    "suppressOutput",
                    "decision",
                    "reason",
                }
                self.assertTrue(prohibited.isdisjoint(output))

    def test_permission_and_agent_metadata_do_not_change_policy(self) -> None:
        variants = (
            {},
            {"permission_mode": "default"},
            {"permission_mode": "acceptEdits"},
            {"permission_mode": "plan"},
            {"permission_mode": "dontAsk"},
            {"permission_mode": "bypassPermissions"},
            {"agent_id": "agent-1"},
            {"agent_type": "worker"},
            {"model": "gpt-test"},
        )
        outputs = []
        for extra in variants:
            with self.subTest(extra=extra):
                result = self.invoke(
                    "pre-tool-use", self.tool_payload(**extra)
                )
                self.assertEqual((result[0], result[2]), (0, ""))
                outputs.append(result[1])
        self.assertEqual(len(set(outputs)), 1)

    def test_uncovered_surfaces_are_silent_without_core_evaluation(self) -> None:
        surfaces = (
            ("Bash", {"command": "rm -rf src"}),
            ("Bash", {"command": "apply_patch <<'EOF'\n...\nEOF"}),
            ("Bash", {"command": "Remove-Item src\\file.py"}),
            ("spawn_agent", {"prompt": "edit files"}),
            ("mcp__filesystem__write", {"path": "src/file.py"}),
            ("unknown_function", {"path": "src/file.py"}),
        )
        with mock.patch.object(codex.mutation, "evaluate_and_decide") as evaluate:
            for tool_name, tool_input in surfaces:
                with self.subTest(tool_name=tool_name, tool_input=tool_input):
                    payload = self.tool_payload(tool_name=tool_name)
                    payload["tool_input"] = tool_input
                    self.assertEqual(
                        self.invoke("pre-tool-use", payload), (0, "", "")
                    )
        evaluate.assert_not_called()

    def test_no_project_root_is_outside_jurisdiction(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        with mock.patch.object(codex.mutation, "evaluate_and_decide") as evaluate:
            result = self.invoke(
                "pre-tool-use", self.tool_payload(cwd=str(outside))
            )
        self.assertEqual(result, (0, "", ""))
        evaluate.assert_not_called()

    def test_adapter_is_repeatable_and_has_no_runtime_side_effects(self) -> None:
        self.write_state(make_state(active_task=True))
        before = self.snapshot_tree()
        results = [
            self.invoke("pre-tool-use", self.tool_payload()) for _ in range(10)
        ]
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.snapshot_tree(), before)
        self.assertFalse(any(path.name == ".codex" for path in self.base.rglob("*")))

    def test_adapter_source_has_no_shell_network_or_persistence_helpers(self) -> None:
        source = Path(codex.__file__).read_text(encoding="utf-8")
        for prohibited in (
            "import shlex",
            "import socket",
            "import subprocess",
            "from shlex",
            "from socket",
            "from subprocess",
            ".write_text(",
            ".write_bytes(",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, source)

    def test_invalid_commands_and_structured_write_failure_use_exit_two(self) -> None:
        with mock.patch("sys.stderr", BinaryOutput()):
            self.assertEqual(codex.main(()), 2)
            self.assertEqual(codex.main(("unknown",)), 2)
        stdout = BinaryOutput(fail_binary_writes=None)
        stderr = BinaryOutput()
        with (
            mock.patch("sys.stdin", io.StringIO(json.dumps(self.session_payload()))),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = codex.main(("session-start",))
        self.assertEqual(code, 2)
        self.assertEqual(
            stderr.getvalue().decode("utf-8"),
            "evidline codex adapter: structured stdout write failed\n",
        )


if __name__ == "__main__":
    unittest.main()
