from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from evidline import mutation
from evidline import state as state_module
from evidline.cli import main
from evidline.paths import ScopePathSemantics, host_scope_semantics
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
    StateConflictError,
    StateIOError,
    StateValidationError,
    Task,
    TaskStatus,
    TRUSTED_APPROVAL_CHANNEL,
    TRUSTED_ASSERTED_ACTOR,
    Verification,
    load_state,
    serialize_state,
    validate_state,
)


NOTICE = (
    "evidline: inspection only — not permission, not execution, not enforcement; "
    "ALLOW means justified under Evidline policy, not permitted by the harness or OS."
)


class TTYStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


class BinaryOutput:
    """Text facade that exposes the exact stdout bytes emitted by the CLI."""

    def __init__(self, *, text_encoding: str = "utf-8", isatty: bool = False) -> None:
        self.buffer = io.BytesIO()
        self._text_encoding = text_encoding
        self._isatty = isatty

    def write(self, text: str) -> int:
        self.buffer.write(text.encode(self._text_encoding))
        return len(text)

    def flush(self) -> None:
        self.buffer.flush()

    def isatty(self) -> bool:
        return self._isatty

    def getvalue(self) -> bytes:
        return self.buffer.getvalue()


def high_state() -> StateDocument:
    evidence = Evidence(
        id="evidence-1",
        description="Current evidence",
        provenance=EvidenceProvenance.DIRECT_OBSERVATION,
        execution=Execution.EXECUTED,
    )
    return StateDocument(
        schema_version=4,
        revision=0,
        project=Project("project", "Phase 4", (), 8000),
        invariants=(
            Invariant(
                id="inv-1",
                description="Active invariant",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
            ),
        ),
        decisions=(
            Decision(
                id="dec-1",
                description="Authorized decision",
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                approved_at="2026-08-16T00:00:00+04:00",
                approval_channel="interactive",
            ),
        ),
        tasks=(
            Task(
                id="task-1",
                description="Active Phase 4 task",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                approved_at="2026-08-16T00:00:00+04:00",
                approval_channel="interactive",
            ),
        ),
        claims=(
            Claim(
                id="claim-1",
                description="Reproducible support",
                freshness=ClaimFreshness.DIGEST_BOUND,
                verification=Verification.UNVERIFIED,
                reproducible=True,
                evidence_ids=("evidence-1",),
            ),
        ),
        evidence=(evidence,),
        counters={},
    )


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()

    def run_cli(
        self,
        *args: str,
        stdin_text: str = "",
        interactive: bool = False,
    ) -> tuple[int, str, str]:
        code, stdout, stderr = self.run_cli_bytes(
            *args,
            stdin_text=stdin_text,
            interactive=interactive,
        )
        return code, stdout.decode("utf-8"), stderr.decode("utf-8")

    def run_cli_bytes(
        self,
        *args: str,
        stdin_text: str = "",
        interactive: bool = False,
        stdout_encoding: str = "utf-8",
    ) -> tuple[int, bytes, bytes]:
        stdin = TTYStringIO(stdin_text) if interactive else io.StringIO(stdin_text)
        stdout = BinaryOutput(
            text_encoding=stdout_encoding,
            isatty=interactive,
        )
        stderr = BinaryOutput()
        code = 0
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            with mock.patch("os.curdir", str(self.root)):
                try:
                    code = main(args)
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else 0
        return code, stdout.getvalue(), stderr.getvalue()

    def initialize(self) -> Path:
        code, stdout, stderr = self.run_cli("init", "--root", str(self.root))
        self.assertEqual((code, stderr), (0, ""))
        self.assertTrue(stdout.startswith("initialized: "))
        return self.root / ".evidline" / "state.json"

    def write_state(self, document: StateDocument) -> Path:
        directory = self.root / ".evidline"
        directory.mkdir(exist_ok=True)
        state_path = directory / "state.json"
        state_path.write_text(serialize_state(document), encoding="utf-8")
        return state_path

    def approval_state(self) -> StateDocument:
        document = high_state()
        draft = replace(
            document.tasks[0],
            status=TaskStatus.DRAFT,
            intent=Intent.PROPOSED,
            authorized_scope=(),
            approved_at=None,
            approval_channel=None,
            asserted_actor=None,
        )
        return replace(document, tasks=(draft,))

    def write_verified_handoff_state(self) -> Path:
        document = high_state()
        source_path = "evidence/current.bin"
        evidence = replace(
            document.evidence[0],
            source_path=source_path,
            digest="sha256:" + hashlib.sha256(b"expected").hexdigest(),
        )
        task_record = replace(
            document.tasks[0],
            related_ids=("claim-1",),
        )
        state_path = self.write_state(
            replace(
                document,
                tasks=(task_record,),
                evidence=(evidence,),
            )
        )
        source = self.root / source_path
        source.parent.mkdir(parents=True)
        source.write_bytes(b"changed")
        return state_path

    def test_bare_cli_is_usage_error_with_help_on_stderr(self) -> None:
        code, stdout, stderr = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("usage: evidline"))

    def test_help_and_version_regressions(self) -> None:
        code, stdout, stderr = self.run_cli("--help")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("usage: evidline", stdout)
        code, stdout, stderr = self.run_cli("--version")
        self.assertEqual((code, stdout.strip()), (0, "0.0.0"))

    def test_invalid_usage_cases_exit_two(self) -> None:
        cases = (
            ("unknown",),
            ("check-mutation", "--risk", "LOW"),
            ("check-mutation", "--target", "src/app.py"),
            ("check-mutation", "--target", "src/app.py", "--risk", "tiny"),
            (
                "check-mutation",
                "--target",
                "src/app.py",
                "--risk",
                "LOW",
                "--intent",
                "MAYBE",
            ),
            (
                "check-mutation",
                "--target",
                "src/app.py",
                "--risk",
                "LOW",
                "--format",
                "yaml",
            ),
            ("init", "--budget", "10"),
            ("init", "--budget", "abc"),
        )
        for args in cases:
            with self.subTest(args=args):
                code, stdout, stderr = self.run_cli(*args)
                self.assertEqual(code, 2)

    def test_init_creates_exact_fresh_state_and_only_state_json(self) -> None:
        state_path = self.root / ".evidline" / "state.json"
        code, stdout, stderr = self.run_cli("init", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertEqual(stdout, f"initialized: {state_path.resolve()}\n")
        self.assertEqual(stderr, "")
        document = load_state(self.root)
        self.assertEqual(document.revision, 0)
        self.assertEqual(
            (
                document.invariants,
                document.decisions,
                document.tasks,
                document.claims,
                document.evidence,
            ),
            ((), (), (), (), ()),
        )
        self.assertEqual([item.name for item in state_path.parent.iterdir()], ["state.json"])

    def test_init_explicit_project_values_are_persisted(self) -> None:
        code, stdout, stderr = self.run_cli(
            "init",
            "--root",
            str(self.root),
            "--name",
            "Named",
            "--purpose",
            "Explicit purpose",
            "--budget",
            "9000",
        )
        self.assertEqual(code, 0)
        project = load_state(self.root).project
        self.assertEqual(
            (project.name, project.purpose, project.default_budget_chars),
            ("Named", "Explicit purpose", 9000),
        )
        self.assertEqual(project.ignore_globs, ())

    def test_second_init_is_idempotent_and_byte_identical(self) -> None:
        state_path = self.initialize()
        before = state_path.read_bytes()
        code, stdout, stderr = self.run_cli("init", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertEqual(
            stdout,
            f"already initialized: {state_path.resolve()} (unchanged)\n",
        )
        self.assertEqual(stderr, "")
        self.assertEqual(state_path.read_bytes(), before)

    def test_init_invalid_existing_state_exits_four_unchanged(self) -> None:
        directory = self.root / ".evidline"
        directory.mkdir()
        state_path = directory / "state.json"
        state_path.write_bytes(b"{")
        code, stdout, stderr = self.run_cli("init", "--root", str(self.root))
        self.assertEqual(code, 4)
        self.assertEqual(state_path.read_bytes(), b"{")

    def test_init_path_failures_map_to_five(self) -> None:
        (self.root / ".evidline").write_text("user file", encoding="utf-8")
        code, stdout, stderr = self.run_cli("init", "--root", str(self.root))
        self.assertEqual(code, 5)
        missing = Path(self.temporary.name) / "missing"
        code, stdout, stderr = self.run_cli("init", "--root", str(missing))
        self.assertEqual(code, 5)

    def test_init_protected_canonical_root_exits_six(self) -> None:
        protected = Path(self.temporary.name) / ".git" / "nested"
        protected.mkdir(parents=True)
        code, stdout, stderr = self.run_cli("init", "--root", str(protected))
        self.assertEqual(code, 6)
        self.assertFalse((protected / ".evidline").exists())

    def test_init_root_is_literal_and_independent_of_cwd(self) -> None:
        other = Path(self.temporary.name) / "other"
        other.mkdir()
        code, stdout, stderr = self.run_cli("init", "--root", str(other))
        self.assertEqual(code, 0)
        self.assertTrue((other / ".evidline" / "state.json").is_file())
        self.assertFalse((self.root / ".evidline").exists())

    def test_fresh_init_immediately_supports_status_and_context(self) -> None:
        self.initialize()
        code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("state_revision: 0\n", stdout)
        code, stdout, stderr = self.run_cli("context", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("EVIDLINE CONTEXT", stdout)

    def test_context_payload_emits_utf8_bytes_under_hostile_text_encoding(self) -> None:
        self.write_state(high_state())

        code, raw, stderr = self.run_cli_bytes(
            "context",
            "--root",
            str(self.root),
            "--format",
            "payload",
            stdout_encoding="cp1252",
        )

        self.assertEqual((code, stderr), (0, b""))
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"context payload is not strict UTF-8: {exc}")
        self.assertIn("—", decoded)

    def test_context_payload_subprocess_ignores_hostile_python_encoding(self) -> None:
        self.write_state(high_state())
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[1] / "src")
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_root
            if not existing_pythonpath
            else source_root + os.pathsep + existing_pythonpath
        )
        environment["PYTHONIOENCODING"] = "cp1252"
        environment["PYTHONUTF8"] = "0"

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidline",
                "context",
                "--root",
                str(self.root),
                "--format",
                "payload",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=False,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(completed.stdout.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\n", completed.stdout)
        self.assertNotIn(b"\r\n", completed.stdout)
        try:
            decoded = completed.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"subprocess payload is not strict UTF-8: {exc}")
        self.assertIn("—", decoded)

    def test_unicode_diagnostic_subprocess_ignores_hostile_python_encoding(self) -> None:
        self.initialize()
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[1] / "src")
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_root
            if not existing_pythonpath
            else source_root + os.pathsep + existing_pythonpath
        )
        environment["PYTHONIOENCODING"] = "cp1252"
        environment["PYTHONUTF8"] = "0"

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidline",
                "add-task",
                "--root",
                str(self.root),
                "--id",
                "task-漢字",
                "--description",
                "bounded test",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=False,
            check=False,
        )

        self.assertEqual(completed.returncode, 6, completed.stderr)
        self.assertEqual(completed.stdout, b"")
        try:
            decoded = completed.stderr.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"subprocess diagnostic is not strict UTF-8: {exc}")
        self.assertIn("task-漢字", decoded)
        self.assertIn("invalid proposed state", decoded)

    def test_unicode_argparse_error_ignores_hostile_python_encoding(self) -> None:
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[1] / "src")
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_root
            if not existing_pythonpath
            else source_root + os.pathsep + existing_pythonpath
        )
        environment["PYTHONIOENCODING"] = "cp1252"
        environment["PYTHONUTF8"] = "0"

        completed = subprocess.run(
            [sys.executable, "-m", "evidline", "context", "--漢字"],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=False,
            check=False,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, b"")
        try:
            decoded = completed.stderr.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"argparse diagnostic is not strict UTF-8: {exc}")
        self.assertIn("--漢字", decoded)
        self.assertIn("unrecognized arguments", decoded)

    def test_verified_handoff_context_formats_budget_root_and_degradation(self) -> None:
        state_path = self.write_verified_handoff_state()
        before = state_path.read_bytes()
        for fmt in ("payload", "report", "json"):
            with self.subTest(fmt=fmt):
                code, stdout, stderr = self.run_cli(
                    "context",
                    "--profile",
                    "verified-handoff",
                    "--format",
                    fmt,
                    "--budget",
                    "12000",
                    "--root",
                    str(self.root),
                )
                self.assertEqual((code, stderr), (0, ""))
                if fmt == "payload":
                    self.assertIn("current:FAILED", stdout)
                elif fmt == "report":
                    self.assertIn("current_verification=FAILED", stdout)
                else:
                    records = {
                        item["record_id"]: item
                        for item in json.loads(stdout)["records"]
                    }
                    self.assertEqual(
                        records["claim-1"]["current_verification"],
                        "FAILED",
                    )
        self.assertEqual(state_path.read_bytes(), before)

    def test_verified_handoff_context_error_mapping(self) -> None:
        empty = Path(self.temporary.name) / "empty-verified"
        empty.mkdir()
        code, stdout, stderr = self.run_cli(
            "context",
            "--profile",
            "verified-handoff",
            "--root",
            str(empty),
        )
        self.assertEqual(code, 3)
        self.assertEqual(stdout, "")
        self.assertIn("state not initialized", stderr)

        self.write_verified_handoff_state()
        code, stdout, stderr = self.run_cli(
            "context",
            "--profile",
            "verified-handoff",
            "--budget",
            "1",
            "--root",
            str(self.root),
        )
        self.assertEqual(code, 6)
        self.assertEqual(stdout, "")
        self.assertIn("invalid compiler input", stderr)

        (self.root / ".evidline" / "state.json").write_text(
            '{"schema_version": 1, "broken": true}',
            encoding="utf-8",
        )
        code, stdout, stderr = self.run_cli(
            "context",
            "--profile",
            "verified-handoff",
            "--root",
            str(self.root),
        )
        self.assertEqual(code, 4)
        self.assertEqual(stdout, "")
        self.assertIn("invalid or unsupported state", stderr)

    def test_status_text_is_exact_and_ordered_for_fresh_state(self) -> None:
        state_path = self.initialize()
        code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(
            stdout,
            "\n".join(
                (
                    "Evidline status",
                    f"root: {self.root.resolve()}",
                    f"state: {state_path.resolve()}",
                    "status_schema_version: 1",
                    "state_schema_version: 4",
                    "state_revision: 0",
                    "project: project",
                    "default_budget_chars: 8000",
                    "active_task: -",
                    "invariants: 0 (active 0)",
                    "decisions: 0",
                    "tasks: 0",
                    "claims: 0",
                    "evidence: 0",
                    "",
                )
            ),
        )

    def test_status_json_exact_keys_counts_and_null_task(self) -> None:
        self.initialize()
        code, stdout, stderr = self.run_cli(
            "status", "--root", str(self.root), "--format", "json"
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
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
        self.assertIsNone(payload["active_task_id"])

    def test_status_populated_fixture_reports_counts_and_active_task(self) -> None:
        self.write_state(high_state())
        code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("active_task: task-1\n", stdout)
        self.assertIn("invariants: 1 (active 1)\n", stdout)
        self.assertIn("tasks: 1\n", stdout)
        self.assertIn("claims: 1\n", stdout)

    def test_status_errors_map_to_three_four_and_five(self) -> None:
        code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual(code, 3)
        directory = self.root / ".evidline"
        directory.mkdir()
        (directory / "state.json").write_text("{", encoding="utf-8")
        code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual(code, 4)
        with mock.patch(
            "evidline.status._state.load_state", side_effect=StateIOError("denied")
        ):
            code, stdout, stderr = self.run_cli("status", "--root", str(self.root))
        self.assertEqual(code, 5)

    def test_status_is_read_only_and_deterministic(self) -> None:
        state_path = self.initialize()
        before = state_path.read_bytes()
        listing = [item.name for item in state_path.parent.iterdir()]
        first = self.run_cli("status", "--root", str(self.root))
        second = self.run_cli("status", "--root", str(self.root))
        json_result = self.run_cli(
            "status", "--root", str(self.root), "--format", "json"
        )
        self.assertEqual(first, second)
        self.assertEqual(json_result[0], 0)
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual([item.name for item in state_path.parent.iterdir()], listing)

    def test_approve_interactively_performs_only_bounded_task_transition(self) -> None:
        before = self.approval_state()
        state_path = self.write_state(before)
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                r"src\package/",
                "--scope",
                "docs",
                stdin_text="task-1\n",
                interactive=True,
            )
        normalized_package_scope = (
            "src/package" if os.name == "nt" else r"src\package"
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(
            f"authorized_scope:\n- {normalized_package_scope}\n- docs\n", stdout
        )
        self.assertIn("defense-in-depth, not proof of human identity", stdout)
        updated = load_state(self.root)
        task = updated.tasks[0]
        self.assertEqual(task.status, TaskStatus.ACTIVE)
        self.assertEqual(task.intent, Intent.AUTHORIZED)
        self.assertEqual(task.authorized_scope, (normalized_package_scope, "docs"))
        self.assertEqual(task.acknowledged_invariant_ids, ())
        self.assertEqual(task.approval_channel, TRUSTED_APPROVAL_CHANNEL)
        self.assertEqual(task.asserted_actor, TRUSTED_ASSERTED_ACTOR)
        self.assertEqual(task.approved_at, "2026-08-17T12:00:00+00:00")
        self.assertEqual(updated.revision, before.revision + 1)
        self.assertEqual(updated.project, before.project)
        self.assertEqual(updated.invariants, before.invariants)
        self.assertEqual(updated.decisions, before.decisions)
        self.assertEqual(updated.claims, before.claims)
        self.assertEqual(updated.evidence, before.evidence)
        self.assertEqual(updated.counters, before.counters)
        self.assertTrue(state_path.is_file())
        self.assertIn("task_description: Active Phase 4 task\n", stdout)
        self.assertIn("acknowledged_invariant_ids:\n- (none)\n", stdout)

    def test_approve_cancellation_and_noninteractive_refusal_do_not_mutate(self) -> None:
        state_path = self.write_state(self.approval_state())
        before = state_path.read_bytes()
        cancelled = self.run_cli(
            "approve",
            "task-1",
            "--root",
            str(self.root),
            "--scope",
            "src",
            stdin_text="cancel\n",
            interactive=True,
        )
        self.assertEqual(cancelled[0], 6)
        self.assertIn("state unchanged", cancelled[1])
        self.assertEqual(state_path.read_bytes(), before)

        noninteractive = self.run_cli(
            "approve",
            "task-1",
            "--root",
            str(self.root),
            "--scope",
            "src",
            stdin_text="task-1\n",
        )
        self.assertEqual(noninteractive[0], 6)
        self.assertIn("requires interactive TTY", noninteractive[2])
        self.assertEqual(state_path.read_bytes(), before)

    def test_approve_rejects_unsafe_scope_before_state_write(self) -> None:
        state_path = self.write_state(self.approval_state())
        before = state_path.read_bytes()
        for scope in (
            "C:/outside",
            "../outside",
            "*.py",
            "!src",
            "src\nspoof",
        ):
            with self.subTest(scope=scope):
                code, stdout, stderr = self.run_cli(
                    "approve",
                    "task-1",
                    "--root",
                    str(self.root),
                    "--scope",
                    scope,
                    stdin_text="task-1\n",
                    interactive=True,
                )
                self.assertEqual(code, 6)
                self.assertEqual(stdout, "")
                self.assertIn("invalid approval scope", stderr)
                self.assertEqual(state_path.read_bytes(), before)

    def test_approve_whole_repository_scope_is_explicit_and_visible(self) -> None:
        self.write_state(self.approval_state())
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                ".",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("authorized_scope:\n- .\n", stdout)
        self.assertEqual(load_state(self.root).tasks[0].authorized_scope, (".",))

    def test_approve_records_block_acknowledgement(self) -> None:
        self.write_state(self.approval_state())
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                "src",
                "--acknowledge",
                "inv-1",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(
            "- inv-1 (enforcement=BLOCK, status=ACTIVE)\n",
            stdout,
        )
        task = load_state(self.root).tasks[0]
        self.assertEqual(task.acknowledged_invariant_ids, ("inv-1",))

    def test_approve_preserves_multiple_acknowledgement_order_and_marks_inert(self) -> None:
        document = self.approval_state()
        advise = Invariant(
            id="inv-advise",
            description="Advisory constraint",
            enforcement=InvariantEnforcement.ADVISE,
            status=InvariantStatus.ACTIVE,
            governed_scope=("src",),
        )
        current = Invariant(
            id="inv-current",
            description="Current constraint",
            enforcement=InvariantEnforcement.BLOCK,
            status=InvariantStatus.ACTIVE,
        )
        old = Invariant(
            id="inv-old",
            description="Superseded constraint",
            enforcement=InvariantEnforcement.BLOCK,
            status=InvariantStatus.SUPERSEDED,
            superseded_by="inv-current",
            approved_at="2026-08-17T00:00:00+04:00",
            approval_channel="interactive",
            governed_scope=("src",),
        )
        document = replace(
            document,
            invariants=document.invariants + (advise, current, old),
        )
        self.write_state(document)
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                "src",
                "--acknowledge",
                "inv-old",
                "--acknowledge",
                "inv-1",
                "--acknowledge",
                "inv-advise",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertLess(stdout.index("- inv-old"), stdout.index("- inv-1"))
        self.assertLess(stdout.index("- inv-1"), stdout.index("- inv-advise"))
        self.assertIn(
            "inv-old (enforcement=BLOCK, status=SUPERSEDED, inert)",
            stdout,
        )
        self.assertIn(
            "inv-advise (enforcement=ADVISE, status=ACTIVE, inert)",
            stdout,
        )
        self.assertEqual(
            load_state(self.root).tasks[0].acknowledged_invariant_ids,
            ("inv-old", "inv-1", "inv-advise"),
        )

    def test_approve_rejects_duplicate_unknown_and_non_invariant_ids_unchanged(self) -> None:
        state_path = self.write_state(self.approval_state())
        before = state_path.read_bytes()
        cases = (
            ("--acknowledge", "inv-1", "--acknowledge", "inv-1"),
            ("--acknowledge", "inv-missing"),
            ("--acknowledge", "task-1"),
            ("--acknowledge", "dec-1"),
            ("--acknowledge", "claim-1"),
            ("--acknowledge", "evidence-1"),
        )
        for extra in cases:
            with self.subTest(extra=extra):
                code, stdout, stderr = self.run_cli(
                    "approve",
                    "task-1",
                    "--root",
                    str(self.root),
                    "--scope",
                    "src",
                    *extra,
                    stdin_text="task-1\n",
                    interactive=True,
                )
                self.assertEqual(code, 6)
                self.assertEqual(stdout, "")
                self.assertIn("invalid approval acknowledgement", stderr)
                self.assertEqual(state_path.read_bytes(), before)

    def test_approve_requires_exact_task_id_and_validates_before_prompt(self) -> None:
        state_path = self.write_state(self.approval_state())
        before = state_path.read_bytes()
        code, stdout, stderr = self.run_cli(
            "approve",
            "task-1",
            "--root",
            str(self.root),
            "--scope",
            "src",
            stdin_text="task-1 \n",
            interactive=True,
        )
        self.assertEqual((code, stderr), (6, ""))
        self.assertIn("approval cancelled; state unchanged", stdout)
        self.assertEqual(state_path.read_bytes(), before)

        original_validate = state_module.validate_state

        def reject_proposed(document: StateDocument) -> None:
            original_validate(document)
            if document.tasks[0].status is TaskStatus.ACTIVE:
                raise StateValidationError("synthetic proposed-state rejection")

        with mock.patch(
            "evidline.cli.state.validate_state",
            side_effect=reject_proposed,
        ):
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                "src",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual(code, 6)
        self.assertEqual(stdout, "")
        self.assertIn("approval transition is invalid", stderr)
        self.assertEqual(state_path.read_bytes(), before)

    def test_approve_does_not_convert_related_ids_to_acknowledgements(self) -> None:
        document = self.approval_state()
        task = replace(document.tasks[0], related_ids=("inv-1",))
        self.write_state(replace(document, tasks=(task,)))
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, _, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                "src",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual((code, stderr), (0, ""))
        approved = load_state(self.root).tasks[0]
        self.assertEqual(approved.related_ids, ("inv-1",))
        self.assertEqual(approved.acknowledged_invariant_ids, ())

    def test_approve_explicitly_restamps_only_foreign_empty_scopes(self) -> None:
        document = self.approval_state()
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        document = replace(document, scope_semantics=foreign)
        self.write_state(document)
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve",
                "task-1",
                "--root",
                str(self.root),
                "--scope",
                "src",
                stdin_text="task-1\n",
                interactive=True,
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(
            f"scope_semantics: {foreign.value} -> {host_scope_semantics().value}",
            stdout,
        )
        self.assertIs(load_state(self.root).scope_semantics, host_scope_semantics())

    def test_add_task_creates_exact_untrusted_draft_and_preserves_related_order(self) -> None:
        self.initialize()
        code, stdout, stderr = self.run_cli(
            "add-invariant",
            "--root",
            str(self.root),
            "--id",
            "inv-arch",
            "--description",
            "Architecture boundary",
            "--enforcement",
            "BLOCK",
        )
        self.assertEqual((code, stderr), (0, ""))
        code, stdout, stderr = self.run_cli(
            "add-task",
            "--root",
            str(self.root),
            "--id",
            "task-work",
            "--description",
            "Perform bounded work",
            "--related-id",
            "inv-arch",
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(
            stdout,
            "\n".join(
                (
                    "created: task-work",
                    "state_revision: 2",
                    "status: DRAFT",
                    "intent: PROPOSED",
                    "execution: NOT_RUN",
                    "related_ids:",
                    "- inv-arch",
                    "authorized_scope:",
                    "- (none)",
                    "acknowledged_invariant_ids:",
                    "- (none)",
                    "approval: (none)",
                    "next: evidline approve task-work --scope ROOT_RELATIVE_PATH",
                    "",
                )
            ),
        )
        document = load_state(self.root)
        task = document.tasks[0]
        self.assertEqual(document.revision, 2)
        self.assertEqual(task.status, TaskStatus.DRAFT)
        self.assertEqual(task.intent, Intent.PROPOSED)
        self.assertEqual(task.execution, Execution.NOT_RUN)
        self.assertEqual(task.related_ids, ("inv-arch",))
        self.assertEqual(task.authorized_scope, ())
        self.assertEqual(task.acknowledged_invariant_ids, ())
        self.assertEqual(
            (task.approved_at, task.approval_channel, task.asserted_actor),
            (None, None, None),
        )
        self.assertFalse(mutation._is_trusted_active_task(task))

    def test_add_task_allows_multiple_drafts_without_disturbing_active_task(self) -> None:
        state_path = self.write_state(high_state())
        before_revision = load_state(self.root).revision
        for task_id in ("task-draft-one", "task-draft-two"):
            with self.subTest(task_id=task_id):
                code, stdout, stderr = self.run_cli(
                    "add-task",
                    "--root",
                    str(self.root),
                    "--id",
                    task_id,
                    "--description",
                    "Draft task",
                )
                self.assertEqual((code, stderr), (0, ""))
                self.assertIn(f"created: {task_id}\n", stdout)
        document = load_state(self.root)
        self.assertEqual(document.revision, before_revision + 2)
        self.assertEqual(
            [task.id for task in document.tasks if task.status is TaskStatus.ACTIVE],
            ["task-1"],
        )
        self.assertEqual([task.id for task in document.tasks[1:]], ["task-draft-one", "task-draft-two"])
        self.assertTrue(state_path.is_file())

    def test_add_task_rejects_invalid_proposals_without_mutating(self) -> None:
        state_path = self.write_state(high_state())
        before = state_path.read_bytes()
        cases = (
            ("--id", "task-1", "--description", "Duplicate task"),
            ("--id", "inv-1", "--description", "Duplicate invariant"),
            ("--id", "dec-1", "--description", "Duplicate decision"),
            ("--id", "claim-1", "--description", "Duplicate claim"),
            ("--id", "evidence-1", "--description", "Duplicate evidence"),
            ("--id", "bad", "--description", "Bad id"),
            ("--id", "task-empty", "--description", ""),
            ("--id", "task-duplicate-related", "--description", "Duplicate", "--related-id", "inv-1", "--related-id", "inv-1"),
            ("--id", "task-unknown-related", "--description", "Unknown", "--related-id", "inv-unknown"),
        )
        for extra in cases:
            with self.subTest(extra=extra):
                code, stdout, stderr = self.run_cli(
                    "add-task", "--root", str(self.root), *extra
                )
                self.assertEqual((code, stdout), (6, ""))
                self.assertNotEqual(stderr, "")
                self.assertEqual(state_path.read_bytes(), before)

    def test_add_task_error_mapping_discovery_and_unsupported_flags(self) -> None:
        code, stdout, stderr = self.run_cli(
            "add-task", "--id", "task-missing", "--description", "Missing"
        )
        self.assertEqual((code, stdout), (3, ""))
        self.assertIn("state not initialized", stderr)

        state_path = self.initialize()
        state_path.write_text("{", encoding="utf-8")
        code, stdout, stderr = self.run_cli(
            "add-task", "--id", "task-invalid", "--description", "Invalid"
        )
        self.assertEqual((code, stdout), (4, ""))
        self.assertIn("invalid or unsupported state", stderr)

        self.write_state(high_state())
        before = state_path.read_bytes()
        for error in (StateIOError("denied"), StateConflictError("locked")):
            with self.subTest(error=type(error).__name__), mock.patch(
                "evidline.cli.state.write_state", side_effect=error
            ):
                code, stdout, stderr = self.run_cli(
                    "add-task", "--id", "task-write", "--description", "Write"
                )
                self.assertEqual((code, stdout), (5, ""))
                self.assertNotEqual(stderr, "")
                self.assertEqual(state_path.read_bytes(), before)

        for flag in (
            "--scope",
            "--acknowledge",
            "--status",
            "--intent",
            "--approved-at",
            "--approval-channel",
            "--asserted-actor",
        ):
            with self.subTest(flag=flag):
                code, stdout, stderr = self.run_cli(
                    "add-task",
                    "--id",
                    "task-flag",
                    "--description",
                    "Flags",
                    flag,
                    "value",
                )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("unrecognized arguments", stderr)

    def test_add_task_discovers_root_from_nested_path(self) -> None:
        self.initialize()
        nested = self.root / "src" / "nested"
        nested.mkdir(parents=True)
        code, stdout, stderr = self.run_cli(
            "add-task",
            "--root",
            str(nested),
            "--id",
            "task-nested",
            "--description",
            "Nested root discovery",
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("created: task-nested\n", stdout)
        self.assertEqual(load_state(self.root).tasks[0].id, "task-nested")

    def test_add_invariant_creates_active_record_and_scope_meanings(self) -> None:
        self.initialize()
        cases = (
            ("inv-empty", "ADVISE", (), "NO_TARGET_BINDING"),
            ("inv-root", "BLOCK", (".",), "WHOLE_REPOSITORY"),
            ("inv-prefix", "BLOCK", ("src/", "docs"), "GOVERNED_PREFIXES"),
        )
        for invariant_id, enforcement, scopes, meaning in cases:
            arguments = [
                "add-invariant",
                "--root",
                str(self.root),
                "--id",
                invariant_id,
                "--description",
                "Invariant",
                "--enforcement",
                enforcement,
            ]
            for scope in scopes:
                arguments.extend(("--governed-scope", scope))
            with self.subTest(invariant_id=invariant_id):
                code, stdout, stderr = self.run_cli(*arguments)
                self.assertEqual((code, stderr), (0, ""))
                self.assertIn(f"enforcement: {enforcement}\n", stdout)
                self.assertIn(f"governed_scope_meaning: {meaning}\n", stdout)
        document = load_state(self.root)
        self.assertEqual(document.revision, 3)
        self.assertEqual(document.invariants[0].governed_scope, ())
        self.assertEqual(document.invariants[1].governed_scope, (".",))
        self.assertEqual(document.invariants[2].governed_scope, ("src", "docs"))
        for invariant in document.invariants:
            self.assertEqual(invariant.status, InvariantStatus.ACTIVE)
            self.assertIsNone(invariant.superseded_by)
            self.assertEqual(
                (invariant.approved_at, invariant.approval_channel, invariant.asserted_actor),
                (None, None, None),
            )

    def test_add_invariant_rejects_invalid_scopes_duplicates_and_flags_unchanged(self) -> None:
        state_path = self.initialize()
        before = state_path.read_bytes()
        cases = (
            ("--id", "inv-duplicate", "--description", "Duplicate", "--enforcement", "BLOCK", "--governed-scope", "src", "--governed-scope", "src/"),
            ("--id", "inv-unsafe", "--description", "Unsafe", "--enforcement", "BLOCK", "--governed-scope", "../outside"),
            ("--id", "bad", "--description", "Bad", "--enforcement", "BLOCK"),
        )
        for extra in cases:
            with self.subTest(extra=extra):
                code, stdout, stderr = self.run_cli(
                    "add-invariant", "--root", str(self.root), *extra
                )
                self.assertEqual((code, stdout), (6, ""))
                self.assertNotEqual(stderr, "")
                self.assertEqual(state_path.read_bytes(), before)
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "inv-missing", "--description", "Missing"
        )
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("--enforcement", stderr)
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "inv-choice", "--description", "Choice", "--enforcement", "MAYBE"
        )
        self.assertEqual((code, stdout), (2, ""))
        for flag in (
            "--status",
            "--superseded-by",
            "--approved-at",
            "--approval-channel",
            "--asserted-actor",
        ):
            with self.subTest(flag=flag):
                code, stdout, stderr = self.run_cli(
                    "add-invariant", "--root", str(self.root), "--id", "inv-flag", "--description", "Flag", "--enforcement", "BLOCK", flag, "value"
                )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("unrecognized arguments", stderr)

    def test_add_invariant_preserves_foreign_empty_semantics_and_rejects_native_scope(self) -> None:
        state_path = self.initialize()
        current = load_state(self.root)
        foreign = (
            ScopePathSemantics.CASE_SENSITIVE
            if host_scope_semantics() is ScopePathSemantics.CASE_FOLDED
            else ScopePathSemantics.CASE_FOLDED
        )
        self.write_state(replace(current, scope_semantics=foreign))
        before = state_path.read_bytes()
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "inv-foreign", "--description", "Foreign", "--enforcement", "BLOCK", "--governed-scope", "src"
        )
        self.assertEqual((code, stdout), (6, ""))
        self.assertEqual(
            stderr,
            "evidline: invalid governed scope: cannot author native scope under foreign scope_semantics; use the interactive approve ceremony to restamp\n",
        )
        self.assertEqual(state_path.read_bytes(), before)
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "inv-empty-foreign", "--description", "Empty", "--enforcement", "ADVISE"
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("governed_scope_meaning: NO_TARGET_BINDING\n", stdout)
        self.assertIs(load_state(self.root).scope_semantics, foreign)

    def test_add_invariant_write_conflict_and_cross_record_duplicate_leave_state_unchanged(self) -> None:
        state_path = self.write_state(high_state())
        before = state_path.read_bytes()
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "task-1", "--description", "Duplicate", "--enforcement", "BLOCK"
        )
        self.assertEqual((code, stdout), (6, ""))
        self.assertEqual(state_path.read_bytes(), before)
        with mock.patch(
            "evidline.cli.state.write_state", side_effect=StateConflictError("locked")
        ):
            code, stdout, stderr = self.run_cli(
                "add-invariant", "--root", str(self.root), "--id", "inv-write", "--description", "Write", "--enforcement", "BLOCK"
            )
        self.assertEqual((code, stdout), (5, ""))
        self.assertEqual(state_path.read_bytes(), before)

    def test_supported_authoring_reaches_existing_approval_ceremony(self) -> None:
        self.initialize()
        code, stdout, stderr = self.run_cli(
            "add-invariant", "--root", str(self.root), "--id", "inv-arch", "--description", "Architecture", "--enforcement", "BLOCK", "--governed-scope", "src"
        )
        self.assertEqual((code, stderr), (0, ""))
        code, stdout, stderr = self.run_cli(
            "add-task", "--root", str(self.root), "--id", "task-work", "--description", "Bounded work"
        )
        self.assertEqual((code, stderr), (0, ""))
        with mock.patch("evidline.cli.datetime") as clock:
            clock.now.return_value.isoformat.return_value = "2026-08-17T12:00:00+00:00"
            code, stdout, stderr = self.run_cli(
                "approve", "task-work", "--root", str(self.root), "--scope", "src", "--acknowledge", "inv-arch", stdin_text="task-work\n", interactive=True
            )
        self.assertEqual((code, stderr), (0, ""))
        final_state = load_state(self.root)
        task = final_state.tasks[0]
        self.assertEqual(final_state.revision, 3)
        self.assertEqual(task.status, TaskStatus.ACTIVE)
        self.assertEqual(task.intent, Intent.AUTHORIZED)
        self.assertEqual(task.authorized_scope, ("src",))
        self.assertEqual(task.acknowledged_invariant_ids, ("inv-arch",))
        self.assertEqual(task.approval_channel, TRUSTED_APPROVAL_CHANNEL)
        self.assertEqual(task.asserted_actor, TRUSTED_ASSERTED_ACTOR)
        validate_state(final_state)
        self.assertTrue(mutation._is_trusted_active_task(task))

    def check(self, risk: str, *extra: str, target: str = "src/app.py"):
        return self.run_cli(
            "check-mutation",
            "--root",
            str(self.root),
            "--target",
            target,
            "--risk",
            risk,
            *extra,
        )

    def test_low_requested_allows_with_exact_silent_fields(self) -> None:
        self.initialize()
        code, stdout, stderr = self.check("LOW", "--intent", "REQUESTED")
        self.assertEqual(code, 0)
        self.assertIn("outcome: ALLOW\n", stdout)
        self.assertIn("reasons: -\n", stdout)
        self.assertTrue(stdout.endswith("next_step: \n"))
        self.assertEqual(stderr, NOTICE + "\n")
        self.assertNotIn(NOTICE, stdout)

    def test_policy_ask_and_block_exit_codes_and_reasons(self) -> None:
        self.initialize()
        cases = (
            ("NORMAL", (), "src/app.py", 10, "NO_ACTIVE_TASK"),
            ("LOW", ("--intent", "REQUESTED"), ".git/config", 11, "TARGET_PROTECTED"),
            ("CRITICAL", ("--intent", "REQUESTED"), "src/app.py", 11, "CRITICAL_RISK"),
            ("LOW", ("--intent", "DENIED"), "src/app.py", 11, "REQUEST_INTENT_DENIED"),
            (
                "LOW",
                ("--intent", "REQUESTED", "--scope", "docs"),
                "src/app.py",
                11,
                "SCOPE_VIOLATION",
            ),
        )
        for risk, extra, target, expected_code, reason in cases:
            with self.subTest(reason=reason):
                code, stdout, stderr = self.check(risk, *extra, target=target)
                self.assertEqual(code, expected_code)
                self.assertIn(reason, stdout)

    def test_outside_root_blocks_target_unsafe(self) -> None:
        self.initialize()
        outside = Path(self.temporary.name) / "outside.py"
        code, stdout, stderr = self.check(
            "LOW", "--intent", "REQUESTED", target=str(outside)
        )
        self.assertEqual(code, 11)
        self.assertIn("TARGET_UNSAFE", stdout)

    def test_high_satisfied_baseline_asks_and_insufficient_support_blocks(self) -> None:
        self.write_state(high_state())
        common = (
            "--intent",
            "REQUESTED",
            "--authorizing-id",
            "task-1",
            "--supporting-claim-id",
            "claim-1",
        )
        code, stdout, stderr = self.check(
            "HIGH", *common, "--ephemeral-evidence-id", "evidence-1"
        )
        self.assertEqual(code, 10)
        self.assertIn("outcome: ASK", stdout)
        code, stdout, stderr = self.check("HIGH", *common)
        self.assertEqual(code, 11)
        self.assertIn("HIGH_EVIDENCE_INSUFFICIENT", stdout)

    def test_repeatable_options_preserve_supplied_order(self) -> None:
        decision = mutation.MutationDecision(
            outcome=mutation.MutationOutcome.ALLOW,
            risk=mutation.MutationRisk.LOW,
            target="target",
            reasons=(),
            next_step="",
            conflicting_invariant_ids=(),
            advisory_invariant_ids=(),
            applicable_invariant_ids=(),
        )
        with mock.patch(
            "evidline.mutation.load_and_decide", return_value=decision
        ) as loaded:
            code, stdout, stderr = self.check(
                "LOW",
                "--authorizing-id",
                "dec-2",
                "--authorizing-id",
                "dec-1",
                "--scope",
                "src/b",
                "--scope",
                "src/a",
                "--supporting-claim-id",
                "claim-2",
                "--supporting-claim-id",
                "claim-1",
                "--ephemeral-evidence-id",
                "evidence-2",
                "--ephemeral-evidence-id",
                "evidence-1",
                "--conflicting-invariant-id",
                "inv-2",
                "--conflicting-invariant-id",
                "inv-1",
            )
        request = loaded.call_args.args[1]
        self.assertEqual(request.authorizing_ids, ("dec-2", "dec-1"))
        self.assertEqual(request.declared_scope, ("src/b", "src/a"))
        self.assertEqual(request.supporting_claim_ids, ("claim-2", "claim-1"))
        self.assertEqual(request.ephemeral_evidence_ids, ("evidence-2", "evidence-1"))
        self.assertEqual(
            request.asserted_conflicting_invariant_ids, ("inv-2", "inv-1")
        )

    def test_json_is_existing_renderer_output_verbatim(self) -> None:
        self.initialize()
        request = mutation.MutationRequest(Intent.REQUESTED, mutation.MutationRisk.LOW)
        decision = mutation.load_and_decide(self.root, request, "src/app.py")
        code, stdout, stderr = self.check(
            "LOW", "--intent", "REQUESTED", "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(stdout, mutation.render_decision_json(decision))
        self.assertEqual(stderr, NOTICE + "\n")

    def test_unexpected_failure_is_closed_without_stdout(self) -> None:
        with mock.patch(
            "evidline.mutation.load_and_decide", side_effect=RuntimeError("boom")
        ):
            code, stdout, stderr = self.check("LOW")
        self.assertEqual(code, 7)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr.splitlines(),
            [NOTICE, "evidline: internal failure; treat as BLOCK"],
        )

    def test_mutation_input_error_exits_six(self) -> None:
        with mock.patch(
            "evidline.mutation.load_and_decide",
            side_effect=mutation.MutationInputError("bad request"),
        ):
            code, stdout, stderr = self.check("LOW")
        self.assertEqual(code, 6)
        self.assertEqual(stdout, "")

    def test_checks_are_read_only_for_allow_ask_and_block(self) -> None:
        state_path = self.initialize()
        before = state_path.read_bytes()
        self.check("LOW", "--intent", "REQUESTED")
        self.check("NORMAL", "--intent", "REQUESTED")
        self.check("CRITICAL", "--intent", "REQUESTED")
        self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(
            [item.name for item in state_path.parent.iterdir()], ["state.json"]
        )

    def test_check_uses_no_product_subprocess_or_network(self) -> None:
        self.initialize()
        with mock.patch.object(subprocess, "Popen") as popen, mock.patch.object(
            socket, "socket"
        ) as socket_constructor:
            code, stdout, stderr = self.check("LOW", "--intent", "REQUESTED")
        self.assertEqual(code, 0)
        popen.assert_not_called()
        socket_constructor.assert_not_called()

    def test_identical_checks_are_deterministic(self) -> None:
        self.initialize()
        first = self.check("LOW", "--intent", "REQUESTED")
        second = self.check("LOW", "--intent", "REQUESTED")
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])

    def test_doctor_text_and_json_are_successful_for_healthy_state(self) -> None:
        self.initialize()
        with mock.patch(
            "evidline.doctor.shutil.which",
            return_value="evidline-claude-hook",
        ):
            code, stdout, stderr = self.run_cli("doctor", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("Evidline doctor", stdout)
        self.assertIn("D001 runtime.python_supported", stdout)
        self.assertIn("D009 state.context_budget_sufficient", stdout)
        self.assertIn("D010 integration.claude_hook_invocable", stdout)
        self.assertEqual(stderr, "")
        with mock.patch(
            "evidline.doctor.shutil.which",
            return_value="evidline-claude-hook",
        ):
            code, stdout, stderr = self.run_cli("doctor", "--root", str(self.root), "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["overall_status"], "HEALTHY")
        self.assertEqual(json.loads(stdout)["doctor_schema_version"], 2)
        self.assertEqual(len(json.loads(stdout)["checks"]), 10)
        self.assertEqual(stderr, "")

    def test_doctor_reports_broken_projects_with_exit_twenty(self) -> None:
        code, stdout, stderr = self.run_cli("doctor", "--root", str(self.root))
        self.assertEqual(code, 20)
        self.assertIn("PROJECT_ROOT_NOT_FOUND", stdout)
        self.assertEqual(stderr, "")
        state_path = self.initialize()
        state_path.write_text("{bad\n", encoding="utf-8")
        code, stdout, stderr = self.run_cli("doctor", "--root", str(self.root))
        self.assertEqual(code, 20)
        self.assertIn("STATE_JSON_INVALID", stdout)
        self.assertEqual(stderr, "")

    def test_doctor_bad_format_remains_argparse_usage_error(self) -> None:
        code, _, _ = self.run_cli("doctor", "--format", "xml")
        self.assertEqual(code, 2)

    def test_doctor_unexpected_failure_exits_seven_without_report(self) -> None:
        with mock.patch("evidline.cli.doctor.run_diagnostics", side_effect=RuntimeError("boom")):
            code, stdout, stderr = self.run_cli("doctor", "--root", str(self.root))
        self.assertEqual(code, 7)
        self.assertEqual(stdout, "")
        self.assertIn("evidline: doctor internal failure: boom", stderr)
        self.assertNotIn("Evidline doctor", stderr)


if __name__ == "__main__":
    unittest.main()
