from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = REPO_ROOT / "tools" / "phase13" / "claude_capture.py"

for _root in (REPO_ROOT / "src", REPO_ROOT / "tools"):
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

from evidline.state import (  # noqa: E402
    Execution,
    Intent,
    Invariant,
    InvariantEnforcement,
    InvariantStatus,
    Project,
    StateDocument,
    Task,
    TaskStatus,
    TRUSTED_APPROVAL_CHANNEL,
    TRUSTED_ASSERTED_ACTOR,
    serialize_state,
)


class ClaudeCaptureTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_process_boundary_is_byte_exact_and_preserves_runtime_context(self) -> None:
        child_stdin = self.root / "child-stdin.bin"
        child_context = self.root / "child-context.json"
        hook_input = b'{"tool_use_id":"toolu_transport"}\r\n'
        child_stdout = b'\x00\xffstdout\r\n'
        child_stderr = b'\xfe\x00stderr\n'
        marker = "phase13-context-marker"
        child_code = (
            "import base64,json,os,pathlib,sys;"
            "data=sys.stdin.buffer.read();"
            "pathlib.Path(sys.argv[1]).write_bytes(data);"
            "pathlib.Path(sys.argv[2]).write_text(json.dumps({"
            "'argv':sys.argv[6:],'cwd':os.getcwd(),'marker':os.environ.get('P13_TEST_MARKER')"
            "}),encoding='utf-8');"
            "sys.stdout.buffer.write(base64.b64decode(sys.argv[3]));"
            "sys.stdout.buffer.flush();"
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[4]));"
            "sys.stderr.buffer.flush();"
            "raise SystemExit(int(sys.argv[5]))"
        )
        environment = os.environ.copy()
        environment["P13_TEST_MARKER"] = marker
        child_tail = ["adapter-arg-one", "adapter-arg-two"]

        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--",
                sys.executable,
                "-c",
                child_code,
                str(child_stdin),
                str(child_context),
                base64.b64encode(child_stdout).decode("ascii"),
                base64.b64encode(child_stderr).decode("ascii"),
                "7",
                *child_tail,
            ],
            input=hook_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.root,
            env=environment,
            check=False,
        )

        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, child_stderr)
        self.assertEqual(child_stdin.read_bytes(), hook_input)
        context = json.loads(child_context.read_text(encoding="utf-8"))
        self.assertEqual(context["argv"], child_tail)
        self.assertEqual(Path(context["cwd"]), self.root)
        self.assertEqual(context["marker"], marker)

    def test_missing_child_preserves_prior_nonblocking_effective_behavior(self) -> None:
        missing = self.root / "missing-adapter-executable.exe"

        completed = subprocess.run(
            [sys.executable, str(HELPER), "--", str(missing), "pre-tool-use"],
            input=b'{"hook_event_name":"PreToolUse"}',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")


class ClaudeCaptureRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Synthetic initialized project root so governed-target resolution
        # follows the same root discovery and canonical evaluation as a real
        # Phase 13 sandbox, without touching any live evidence destination.
        self.sandbox = self.root / "sandbox"
        (self.sandbox / "allowed").mkdir(parents=True)
        (self.sandbox / "governed").mkdir()
        (self.sandbox / ".evidline").mkdir()
        # The helper resolves evidline from its executing interpreter's
        # normal import environment; the development stand-in for the
        # sandbox-installed distribution is repository src/ on PYTHONPATH.
        self.helper_environment = os.environ.copy()
        self.helper_environment["PYTHONPATH"] = str(REPO_ROOT / "src")

    def run_helper(
        self,
        hook_input: bytes,
        *,
        record: Path,
        stdout: bytes,
        stderr: bytes = b"",
        exit_code: int = 0,
        child_stdin: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        child_code = (
            "import base64,pathlib,sys;"
            "data=sys.stdin.buffer.read();"
            "pathlib.Path(sys.argv[1]).write_bytes(data) if sys.argv[1] != '-' else None;"
            "sys.stdout.buffer.write(base64.b64decode(sys.argv[2]));"
            "sys.stdout.buffer.flush();"
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[3]));"
            "sys.stderr.buffer.flush();"
            "raise SystemExit(int(sys.argv[4]))"
        )
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--record",
                str(record),
                "--",
                sys.executable,
                "-c",
                child_code,
                str(child_stdin or "-"),
                base64.b64encode(stdout).decode("ascii"),
                base64.b64encode(stderr).decode("ascii"),
                str(exit_code),
            ],
            input=hook_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment if environment is not None else self.helper_environment,
            check=False,
        )

    def hook_input(
        self,
        tool_use_id: str | None,
        *,
        tool_name: str = "Write",
        target_field: str = "file_path",
        target: object = "governed/probe-deny.txt",
    ) -> bytes:
        document: dict[str, object] = {
            "session_id": "session-private-123",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "cwd": str(self.sandbox),
            "tool_input": {
                target_field: target,
                "content": "PRIVATE-WRITE-CONTENT EVIDLINE-P13-NONCE",
            },
            "transcript": "PRIVATE-TRANSCRIPT",
            "reasoning": "PRIVATE-REASONING",
            "environment": {"UNRELATED_SECRET": "PRIVATE-ENVIRONMENT"},
        }
        if tool_use_id is not None:
            document["tool_use_id"] = tool_use_id
        return json.dumps(document, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def session_start_input(
        *,
        event: str = "SessionStart",
        session_id: str = "session-start-private-123",
        source: str = "startup",
    ) -> bytes:
        return json.dumps(
            {
                "session_id": session_id,
                "hook_event_name": event,
                "source": source,
                "transcript": "PRIVATE-SESSION-TRANSCRIPT",
            },
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def deny_stdout(label: str) -> bytes:
        return json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": label,
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def test_record_binds_digests_exact_stdout_and_exit_without_private_input(self) -> None:
        tool_use_id = "toolu-private-456"
        hook_input = self.hook_input(tool_use_id)
        child_stdout = self.deny_stdout("evidline BLOCK: INVARIANT_UNACKNOWLEDGED")
        child_stderr = b"adapter-stderr\r\n"
        record_path = self.root / "correlation.json"

        completed = self.run_helper(
            hook_input,
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
            exit_code=0,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, child_stderr)
        record_bytes = record_path.read_bytes()
        record = json.loads(record_bytes)
        self.assertEqual(
            set(record),
            {
                "adapter_exit_code",
                "adapter_stdout_base64",
                "format",
                "hook_event_name",
                "session_sha256",
                "tool_name",
                "tool_use_sha256",
            },
        )
        self.assertEqual(
            record["format"], "evidline.phase13.claude-pretool-correlation.v1"
        )
        self.assertEqual(
            record["session_sha256"],
            hashlib.sha256(b"session-private-123").hexdigest(),
        )
        self.assertEqual(
            record["tool_use_sha256"], hashlib.sha256(tool_use_id.encode()).hexdigest()
        )
        self.assertEqual(base64.b64decode(record["adapter_stdout_base64"]), child_stdout)
        self.assertEqual(record["adapter_exit_code"], 0)
        for private_value in (
            tool_use_id,
            "session-private-123",
            "PRIVATE-WRITE-CONTENT",
            "EVIDLINE-P13-NONCE",
            "PRIVATE-TRANSCRIPT",
            "PRIVATE-REASONING",
            "PRIVATE-ENVIRONMENT",
        ):
            self.assertNotIn(private_value.encode(), record_bytes)

    def test_session_start_record_binds_source_digest_exact_stdout_and_exit(self) -> None:
        record_path = self.root / "session-start-correlation.json"
        child_stdout = b"context \xff payload\r\n"
        child_stderr = b"session-start-stderr\n"

        completed = self.run_helper(
            self.session_start_input(),
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, child_stderr)
        record_bytes = record_path.read_bytes()
        record = json.loads(record_bytes)
        self.assertEqual(
            set(record),
            {
                "adapter_exit_code",
                "adapter_stdout_base64",
                "format",
                "hook_event_name",
                "session_sha256",
                "source",
            },
        )
        self.assertEqual(
            record["format"],
            "evidline.phase13.claude-sessionstart-correlation.v1",
        )
        self.assertEqual(record["hook_event_name"], "SessionStart")
        self.assertEqual(record["source"], "startup")
        self.assertEqual(
            record["session_sha256"],
            hashlib.sha256(b"session-start-private-123").hexdigest(),
        )
        self.assertEqual(base64.b64decode(record["adapter_stdout_base64"]), child_stdout)
        self.assertEqual(record["adapter_exit_code"], 0)
        self.assertNotIn(b"session-start-private-123", record_bytes)
        self.assertNotIn(b"PRIVATE-SESSION-TRANSCRIPT", record_bytes)

    def test_unrelated_event_does_not_consume_session_start_record(self) -> None:
        record_path = self.root / "session-start-correlation.json"
        child_stdout = b"session context"

        unrelated = self.run_helper(
            self.session_start_input(event="PostCompact"),
            record=record_path,
            stdout=child_stdout,
        )

        self.assertEqual(unrelated.returncode, 0)
        self.assertEqual(unrelated.stdout, child_stdout)
        self.assertFalse(record_path.exists())

        session_start = self.run_helper(
            self.session_start_input(),
            record=record_path,
            stdout=child_stdout,
        )
        self.assertEqual(session_start.returncode, 0)
        self.assertTrue(record_path.is_file())

    def test_two_invocations_cannot_cross_bind(self) -> None:
        paths = (self.root / "one.json", self.root / "two.json")
        identities = ("toolu-one", "toolu-two")
        outputs = (self.deny_stdout("decision-one"), self.deny_stdout("decision-two"))

        for path, identity, output in zip(paths, identities, outputs, strict=True):
            completed = self.run_helper(
                self.hook_input(identity), record=path, stdout=output
            )
            self.assertEqual(completed.returncode, 0)

        records = [json.loads(path.read_bytes()) for path in paths]
        for index, record in enumerate(records):
            self.assertEqual(
                record["tool_use_sha256"],
                hashlib.sha256(identities[index].encode()).hexdigest(),
            )
            self.assertEqual(
                base64.b64decode(record["adapter_stdout_base64"]), outputs[index]
            )
            self.assertNotEqual(
                record["tool_use_sha256"],
                records[1 - index]["tool_use_sha256"],
            )

    def test_positive_write_does_not_consume_reserved_denial_record(self) -> None:
        record_path = self.root / "correlation.json"
        positive = self.hook_input(
            "toolu-positive", target="allowed/probe-allow.txt"
        )
        child_stdout = self.deny_stdout("positive-control-adapter-result")

        completed = self.run_helper(
            positive, record=record_path, stdout=child_stdout, exit_code=0
        )

        # The positive control still exercises the full wrapper -> adapter
        # path; only the reserved denial-correlation slot is withheld.
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertFalse(record_path.exists())

        governed = self.run_helper(
            self.hook_input("toolu-governed-after-positive"),
            record=record_path,
            stdout=self.deny_stdout("governed-adapter-result"),
            exit_code=0,
        )
        self.assertEqual(governed.returncode, 0)
        # The same reserved destination remains available for the governed
        # event after the positive control passed through.
        self.assertTrue(record_path.is_file())
        body = json.loads(record_path.read_bytes())
        self.assertEqual(
            body["tool_use_sha256"],
            hashlib.sha256(b"toolu-governed-after-positive").hexdigest(),
        )

    def test_governed_target_unexpected_allow_result_is_captured(self) -> None:
        record_path = self.root / "correlation.json"
        allow_stdout = json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": "unexpected-allow-result",
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        completed = self.run_helper(
            self.hook_input("toolu-unexpected-allow"),
            record=record_path,
            stdout=allow_stdout,
            exit_code=0,
        )

        # Capture eligibility follows target identity, not the expected deny
        # result: a wrong governed outcome must stay observable.
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, allow_stdout)
        self.assertTrue(record_path.is_file())
        body = json.loads(record_path.read_bytes())
        self.assertEqual(base64.b64decode(body["adapter_stdout_base64"]), allow_stdout)
        self.assertEqual(body["adapter_exit_code"], 0)

    def test_wrong_tool_or_wrong_write_target_never_consumes_record(self) -> None:
        other_sandbox = self.root / "other-sandbox"
        (other_sandbox / "governed").mkdir(parents=True)
        (other_sandbox / ".evidline").mkdir()
        outside_root = str(other_sandbox / "governed" / "probe-deny.txt")
        cases: tuple[tuple[str, bytes], ...] = (
            ("edit-tool", self.hook_input("toolu-edit", tool_name="Edit")),
            (
                "notebook-tool",
                self.hook_input(
                    "toolu-notebook",
                    tool_name="NotebookEdit",
                    target_field="notebook_path",
                ),
            ),
            (
                "positive-target",
                self.hook_input("toolu-wrong-positive", target="allowed/probe-allow.txt"),
            ),
            (
                "unrelated-in-root",
                self.hook_input("toolu-wrong-unrelated", target="unrelated/other.txt"),
            ),
            (
                "governed-suffix",
                self.hook_input(
                    "toolu-wrong-suffix", target="governed/probe-deny.txt.extra"
                ),
            ),
            (
                "nested-governed",
                self.hook_input(
                    "toolu-wrong-nested", target="another/governed/probe-deny.txt"
                ),
            ),
            (
                "outside-root",
                self.hook_input("toolu-wrong-outside", target=outside_root),
            ),
        )

        for name, payload in cases:
            with self.subTest(case=name):
                record_path = self.root / f"record-{name}.json"
                child_stdout = self.deny_stdout(f"dispatched-{name}")
                completed = self.run_helper(
                    payload, record=record_path, stdout=child_stdout, exit_code=5
                )
                # Adapter dispatch stays unchanged for matched events; only
                # the reserved denial-correlation slot is withheld.
                self.assertEqual(completed.returncode, 5)
                self.assertEqual(completed.stdout, child_stdout)
                self.assertFalse(record_path.exists())

    def test_malformed_or_unsafe_write_input_never_consumes_record(self) -> None:
        def governed_document() -> dict[str, object]:
            return json.loads(self.hook_input("toolu-malformed"))

        cases: tuple[tuple[str, dict[str, object]], ...] = (
            ("missing-tool-input", {**governed_document(), "tool_input": None}),
            (
                "non-object-tool-input",
                {**governed_document(), "tool_input": ["governed/probe-deny.txt"]},
            ),
            ("missing-file-path", {"tool_input": {"content": "PRIVATE-CONTENT"}}),
            ("empty-file-path", {"tool_input": {"file_path": ""}}),
            ("non-string-file-path", {"tool_input": {"file_path": 123}}),
            ("nul-path", {"tool_input": {"file_path": "governed/x\0y.txt"}}),
            (
                "ads-path",
                {"tool_input": {"file_path": "governed/probe-deny.txt:hidden"}},
            ),
        )

        for name, overrides in cases:
            with self.subTest(case=name):
                document = governed_document()
                document.update(overrides)
                record_path = self.root / f"record-{name}.json"
                child_stdout = self.deny_stdout(f"malformed-{name}")
                completed = self.run_helper(
                    json.dumps(document).encode("utf-8"),
                    record=record_path,
                    stdout=child_stdout,
                    exit_code=6,
                )
                self.assertEqual(completed.returncode, 6)
                self.assertEqual(completed.stdout, child_stdout)
                self.assertFalse(record_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows case-folded path equality")
    def test_windows_separator_and_case_variants_resolve_to_governed_target(self) -> None:
        for variant in ("governed\\probe-deny.txt", "Governed\\Probe-Deny.TXT"):
            with self.subTest(variant=variant):
                record_path = self.root / f"record-variant-{abs(hash(variant))}.json"
                completed = self.run_helper(
                    self.hook_input(f"toolu-{variant}", target=variant),
                    record=record_path,
                    stdout=self.deny_stdout("windows-variant"),
                    exit_code=0,
                )
                self.assertEqual(completed.returncode, 0)
                self.assertTrue(record_path.is_file())
                body = json.loads(record_path.read_bytes())
                self.assertEqual(body["tool_name"], "Write")

    def test_direct_script_resolves_evidline_from_interpreter_environment(self) -> None:
        fake_environment = self.root / "fake-evidline-environment"
        (fake_environment / "evidline").mkdir(parents=True)
        (fake_environment / "evidline" / "__init__.py").write_text("", encoding="utf-8")
        # A stand-in distribution whose discovery always fails: if the
        # helper imported evidline from anywhere except the interpreter's
        # normal resolution order, the governed target below would stay
        # ineligible in a distinguishable way.
        (fake_environment / "evidline" / "paths.py").write_text(
            "def discover_project_root(start):\n"
            "    return None\n"
            "def evaluate_mutation_path(root, target):\n"
            "    raise AssertionError('evaluate must not run after failed discovery')\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(fake_environment)
        record_path = self.root / "correlation.json"
        child_stdout = self.deny_stdout("fake-evidline-provenance")

        completed = self.run_helper(
            self.hook_input("toolu-fake-evidline"),
            record=record_path,
            stdout=child_stdout,
            environment=environment,
        )

        # The sibling Phase 13 contract still imported from the script
        # directory and transport stayed byte-exact: the adapter child ran
        # to completion instead of the helper dying at import time.
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, b"")
        # evidline.paths resolved from the interpreter environment (the
        # fake distribution), so governed-target discovery returned None
        # and no reserved record was created. A repository src/ injection
        # would have resolved real evidline and created the record.
        self.assertFalse(record_path.exists())

    def test_record_collision_preserves_adapter_result_and_existing_bytes(self) -> None:
        collision_directory = self.root / "collision"
        collision_directory.mkdir()
        record_path = collision_directory / "correlation.json"
        original = b"pre-existing-private-record\x00"
        record_path.write_bytes(original)
        child_stdout = self.deny_stdout("collision-result")
        child_stderr = b"collision-stderr"

        completed = self.run_helper(
            self.hook_input("toolu-collision"),
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
            exit_code=7,
        )

        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, child_stderr)
        self.assertEqual(record_path.read_bytes(), original)
        self.assertEqual(
            {path.name for path in collision_directory.iterdir()},
            {record_path.name},
        )

    def test_missing_tool_use_identity_runs_child_but_creates_no_record(self) -> None:
        record_path = self.root / "correlation.json"
        child_stdin = self.root / "child-stdin.bin"
        hook_input = self.hook_input(None)
        child_stdout = self.deny_stdout("missing-identity-result")

        completed = self.run_helper(
            hook_input,
            record=record_path,
            stdout=child_stdout,
            exit_code=0,
            child_stdin=child_stdin,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(child_stdin.read_bytes(), hook_input)
        self.assertFalse(record_path.exists())

    def test_unparseable_hook_input_transports_child_and_records_nothing(self) -> None:
        record_path = self.root / "correlation.json"
        child_stdin = self.root / "child-stdin.bin"
        hook_input = b'{"tool_use_id": broken json \xff\xfe'
        child_stdout = self.deny_stdout("unparseable-input-result")

        completed = self.run_helper(
            hook_input,
            record=record_path,
            stdout=child_stdout,
            exit_code=3,
            child_stdin=child_stdin,
        )

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(child_stdin.read_bytes(), hook_input)
        self.assertFalse(record_path.exists())

    def test_incomplete_identity_or_event_creates_no_record(self) -> None:
        remove: tuple[tuple[str, object], ...] = (
            ("session_id", None),
            ("hook_event_name", None),
            ("tool_name", None),
            ("tool_use_id", ""),
            ("hook_event_name", "PostToolUse"),
        )
        for field, replacement in remove:
            with self.subTest(field=field):
                document = json.loads(self.hook_input("toolu-incomplete"))
                if replacement is None:
                    document.pop(field)
                else:
                    document[field] = replacement
                record_path = self.root / f"record-{field}.json"
                completed = self.run_helper(
                    json.dumps(document).encode("utf-8"),
                    record=record_path,
                    stdout=self.deny_stdout("incomplete-identity"),
                    exit_code=0,
                )
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(
                    completed.stdout, self.deny_stdout("incomplete-identity")
                )
                self.assertFalse(record_path.exists())

    def test_missing_record_destination_preserves_adapter_result(self) -> None:
        record_path = self.root / "absent-directory" / "correlation.json"
        child_stdout = self.deny_stdout("missing-destination-result")
        child_stderr = b"missing-destination-stderr"

        completed = self.run_helper(
            self.hook_input("toolu-missing-destination"),
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
            exit_code=4,
        )

        self.assertEqual(completed.returncode, 4)
        self.assertEqual(completed.stdout, child_stdout)
        self.assertEqual(completed.stderr, child_stderr)
        self.assertFalse(record_path.exists())
        self.assertFalse(record_path.parent.exists())

    def run_helper_closed_stream(
        self,
        hook_input: bytes,
        *,
        record: Path,
        stdout: bytes,
        stderr: bytes = b"",
        exit_code: int = 0,
        closed: str,
    ) -> tuple[int, bytes]:
        child_code = (
            "import base64,sys;"
            "sys.stdout.buffer.write(base64.b64decode(sys.argv[1]));"
            "sys.stdout.buffer.flush();"
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[2]));"
            "sys.stderr.buffer.flush();"
            "raise SystemExit(int(sys.argv[3]))"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(HELPER),
                "--record",
                str(record),
                "--",
                sys.executable,
                "-c",
                child_code,
                base64.b64encode(stdout).decode("ascii"),
                base64.b64encode(stderr).decode("ascii"),
                str(exit_code),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.helper_environment,
        )
        # The helper relays only after stdin EOF and child exit, so closing
        # one read end first fails exactly that relay, deterministically.
        getattr(process, closed).close()
        assert process.stdin is not None
        process.stdin.write(hook_input)
        process.stdin.close()
        surviving = process.stderr if closed == "stdout" else process.stdout
        assert surviving is not None
        surviving_bytes = surviving.read()
        surviving.close()
        return process.wait(), surviving_bytes

    def test_stdout_relay_failure_creates_no_proof_eligible_record(self) -> None:
        record_path = self.root / "correlation.json"
        child_stdout = self.deny_stdout("relay-still-transported-deny")
        child_stderr = b"adapter-stderr-relayed"

        returncode, relayed_stderr = self.run_helper_closed_stream(
            self.hook_input("toolu-relay-stdout"),
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
            exit_code=7,
            closed="stdout",
        )

        # 120 is the interpreter's std-flush failure status after main()
        # already returned the child exit; the helper never manufactures one.
        self.assertIn(returncode, {7, 120})
        self.assertTrue(relayed_stderr.startswith(child_stderr))
        self.assertFalse(record_path.exists())

    def test_stderr_relay_failure_creates_no_proof_eligible_record(self) -> None:
        record_path = self.root / "correlation.json"
        child_stdout = self.deny_stdout("relay-still-transported-deny")
        child_stderr = b"adapter-stderr-relayed"

        returncode, relayed_stdout = self.run_helper_closed_stream(
            self.hook_input("toolu-relay-stderr"),
            record=record_path,
            stdout=child_stdout,
            stderr=child_stderr,
            exit_code=7,
            closed="stderr",
        )

        self.assertIn(returncode, {7, 120})
        self.assertEqual(relayed_stdout, child_stdout)
        self.assertFalse(record_path.exists())

    def test_session_start_failure_cannot_create_proof_eligible_record(self) -> None:
        nonzero_path = self.root / "session-start-nonzero.json"
        completed = self.run_helper(
            self.session_start_input(),
            record=nonzero_path,
            stdout=b"failed session context",
            exit_code=2,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(nonzero_path.exists())

        relay_path = self.root / "session-start-relay.json"
        returncode, relayed_stderr = self.run_helper_closed_stream(
            self.session_start_input(),
            record=relay_path,
            stdout=b"unrelayed session context",
            stderr=b"adapter-stderr-relayed",
            closed="stdout",
        )
        self.assertIn(returncode, {0, 120})
        self.assertTrue(relayed_stderr.startswith(b"adapter-stderr-relayed"))
        self.assertFalse(relay_path.exists())


# Byte-exact permissionDecisionReason of the real adapter for the accepted
# offline fixture (reproduced from evidline.adapters.claude pre-tool-use).
REAL_BLOCK_REASON = (
    "evidline BLOCK: outcome=BLOCK; reasons=INVARIANT_UNACKNOWLEDGED; "
    "next_step=A relevant ACTIVE BLOCK invariant is not acknowledged by the "
    "ACTIVE task; a human must acknowledge that invariant on the ACTIVE task, "
    "or choose a target outside its governed scope.; this is an Evidline "
    "policy result and is not harness or human authorization."
)


def verified_denial_input(**overrides: object) -> dict[str, object]:
    """Operator-side VERIFIED-grade LIVE_MUTATION_DENIAL document.

    Record-derived fields (session/tool-use digests, adapter exit,
    sanitized_hook_decision) are omitted so the private correlation record
    must supply and corroborate them.
    """

    document: dict[str, object] = {
        "claim": "LIVE_MUTATION_DENIAL",
        "harness_name": "claude",
        "harness_version": "2.1.234",
        "evidline_commit_sha": "0" * 40,
        "event_type": "PreToolUse",
        "supported_tool_path": "Write",
        "verdict": "VERIFIED",
        "live_status": "EXECUTED",
        "core_decision": "BLOCK",
        "block_reason": "INVARIANT_UNACKNOWLEDGED",
        "adapter_transport": "deny",
        "harness_tool_result": "DENIED",
        "harness_blocking_result": "DENIED",
        "target_state": "UNCHANGED",
        "target_existed_before": False,
        "target_existed_after": False,
        "relative_target": "governed/probe-deny.txt",
        "sandbox_state_sha256": "1" * 64,
        "raw_capture_sha256": "2" * 64,
        "proving_tool_attempted": True,
        "positive_control_target": "allowed/probe-allow.txt",
        "positive_control_existed_before": False,
        "positive_control_existed_after": True,
        "positive_control_expected_digest": hashlib.sha256(b"PHASE13").hexdigest(),
        "positive_control_digest_after": hashlib.sha256(b"PHASE13").hexdigest(),
        "positive_control_tool": "Write",
        "positive_control_tool_attempted": True,
        "positive_control_tool_use_sha256": "3" * 64,
        "positive_control_session_sha256": "4" * 64,
        "positive_control_raw_capture_sha256": "5" * 64,
    }
    document.update(overrides)
    return document


class ClaudeCaptureVerifierTests(ClaudeCaptureRecordTests):
    @staticmethod
    def evidence_input(**overrides: object) -> dict[str, object]:
        document: dict[str, object] = {
            "claim": "LIVE_MUTATION_DENIAL",
            "harness_name": "Claude Code",
            "event_type": "PreToolUse",
            "supported_tool_path": "Write",
            "live_status": "NOT_EXECUTED",
            "verdict": "NOT_EXECUTED",
        }
        document.update(overrides)
        return document

    def make_record(
        self,
        name: str = "correlation.json",
        *,
        tool_use_id: str = "toolu-verifier",
        stdout: bytes | None = None,
        exit_code: int = 0,
    ) -> Path:
        path = self.root / name
        completed = self.run_helper(
            self.hook_input(tool_use_id),
            record=path,
            stdout=stdout
            if stdout is not None
            else self.deny_stdout(
                "evidline BLOCK: reasons=INVARIANT_UNACKNOWLEDGED"
            ),
            exit_code=exit_code,
        )
        self.assertEqual(completed.returncode, exit_code)
        self.assertTrue(path.is_file())
        return path

    def run_evidence(
        self,
        evidence_input: dict[str, object],
        *record_paths: Path,
    ) -> subprocess.CompletedProcess[bytes]:
        input_path = self.root / "evidence-input.json"
        input_path.write_text(json.dumps(evidence_input), encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "phase13",
            "evidence",
            "--input",
            str(input_path),
        ]
        for record_path in record_paths:
            command.extend(("--private-correlation-record", str(record_path)))
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(REPO_ROOT / "src"), str(REPO_ROOT / "tools"))
        )
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPO_ROOT,
            env=environment,
            check=False,
        )

    def test_evidence_command_derives_existing_fields_from_one_private_record(self) -> None:
        tool_use_id = "toolu-verifier"
        record_path = self.root / "correlation.json"
        adapter_stdout = self.deny_stdout(
            "evidline BLOCK: reasons=INVARIANT_UNACKNOWLEDGED"
        )
        helper = self.run_helper(
            self.hook_input(tool_use_id),
            record=record_path,
            stdout=adapter_stdout,
            exit_code=0,
        )
        self.assertEqual(helper.returncode, 0)

        completed = self.run_evidence(self.evidence_input(), record_path)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        evidence = json.loads(completed.stdout)
        self.assertEqual(
            evidence["tool_use_sha256"], hashlib.sha256(tool_use_id.encode()).hexdigest()
        )
        self.assertEqual(
            evidence["session_sha256"],
            hashlib.sha256(b"session-private-123").hexdigest(),
        )
        self.assertEqual(evidence["adapter_exit_code"], 0)
        self.assertEqual(
            evidence["sanitized_hook_decision"]["hookSpecificOutput"]
            ["permissionDecision"],
            "deny",
        )

    def test_session_start_record_derives_payload_bindings_and_rejects_mismatch(self) -> None:
        record_path = self.root / "session-start-correlation.json"
        adapter_stdout = b"SessionStart context \xe2\x98\x83\r\n"
        helper = self.run_helper(
            self.session_start_input(),
            record=record_path,
            stdout=adapter_stdout,
        )
        self.assertEqual(helper.returncode, 0)

        evidence_input = {
            "claim": "INSTALLED_HARNESS_DISPATCH",
            "harness_name": "claude",
            "harness_version": "2.1.234",
            "evidline_commit_sha": "0" * 40,
            "event_type": "SessionStart",
            "verdict": "VERIFIED",
            "live_status": "EXECUTED",
            "sandbox_state_sha256": "1" * 64,
            "raw_capture_sha256": "2" * 64,
        }
        completed = self.run_evidence(evidence_input, record_path)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        evidence = json.loads(completed.stdout)
        self.assertEqual(
            evidence["session_sha256"],
            hashlib.sha256(b"session-start-private-123").hexdigest(),
        )
        self.assertEqual(evidence["adapter_exit_code"], 0)
        self.assertEqual(
            evidence["context_payload_sha256"],
            hashlib.sha256(adapter_stdout).hexdigest(),
        )
        self.assertEqual(evidence["context_payload_length"], len(adapter_stdout))

        for field, value in (
            ("session_sha256", "3" * 64),
            ("context_payload_sha256", "4" * 64),
            ("context_payload_length", len(adapter_stdout) + 1),
        ):
            with self.subTest(field=field):
                mismatch = self.run_evidence(
                    {**evidence_input, field: value}, record_path
                )
                self.assertNotEqual(mismatch.returncode, 0)
                self.assertIn(b"phase13:", mismatch.stderr)

    def test_evidence_command_rejects_all_binding_mismatches(self) -> None:
        record_path = self.make_record()
        mismatches: tuple[tuple[str, object], ...] = (
            ("tool_use_sha256", "0" * 64),
            ("session_sha256", "1" * 64),
            ("adapter_exit_code", 2),
            (
                "sanitized_hook_decision",
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": "different",
                    }
                },
            ),
            ("event_type", "PostToolUse"),
            ("supported_tool_path", "Edit"),
        )

        for field, value in mismatches:
            with self.subTest(field=field):
                completed = self.run_evidence(
                    self.evidence_input(**{field: value}), record_path
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"phase13:", completed.stderr)

    def test_evidence_command_rejects_forged_or_malformed_adapter_output(self) -> None:
        cases: tuple[tuple[str, bytes], ...] = (
            ("not-json", b"not-json"),
            (
                "wrong-permission",
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "permissionDecisionReason": "forged",
                        }
                    },
                    separators=(",", ":"),
                ).encode(),
            ),
            ("missing-decision", b'{"hookSpecificOutput":{}}'),
        )

        for name, output in cases:
            with self.subTest(name=name):
                record_path = self.make_record(f"{name}.json", stdout=output)
                completed = self.run_evidence(self.evidence_input(), record_path)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"phase13:", completed.stderr)

    def test_evidence_command_rejects_structurally_tampered_records(self) -> None:
        def tampered(mutate) -> Path:
            source = json.loads(self.make_record().read_bytes())
            mutate(source)
            path = self.root / f"tampered-{abs(hash(json.dumps(source, sort_keys=True)))}.json"
            path.write_bytes(
                json.dumps(source, separators=(",", ":"), sort_keys=True).encode()
                + b"\n"
            )
            return path

        cases: tuple[tuple[str, object], ...] = (
            ("extra-field", lambda r: r.update({"unexpected": 1})),
            ("missing-field", lambda r: r.pop("tool_name")),
            ("wrong-format", lambda r: r.update({"format": "other.v1"})),
            ("bad-digest", lambda r: r.update({"tool_use_sha256": "zz" * 32})),
            ("wrong-event", lambda r: r.update({"hook_event_name": "PostToolUse"})),
            ("empty-tool-name", lambda r: r.update({"tool_name": ""})),
            ("bool-exit", lambda r: r.update({"adapter_exit_code": False})),
            ("string-exit", lambda r: r.update({"adapter_exit_code": "0"})),
            (
                "stdout-with-nonzero-exit",
                lambda r: r.update({"adapter_exit_code": 2}),
            ),
            (
                "invalid-base64",
                lambda r: r.update({"adapter_stdout_base64": "not base64!!"}),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                completed = self.run_evidence(self.evidence_input(), tampered(mutate))
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"phase13:", completed.stderr)

        duplicate_keys = self.root / "duplicate-keys.json"
        duplicate_keys.write_bytes(
            b'{"format":"evidline.phase13.claude-pretool-correlation.v1",'
            b'"format":"evidline.phase13.claude-pretool-correlation.v1"}\n'
        )
        completed = self.run_evidence(self.evidence_input(), duplicate_keys)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"phase13:", completed.stderr)

        non_ascii = self.root / "non-ascii.json"
        non_ascii.write_bytes(b'{"format": "evidline\xc3\xa9"}\n')
        completed = self.run_evidence(self.evidence_input(), non_ascii)
        self.assertNotEqual(completed.returncode, 0)

    def test_evidence_command_rejects_duplicate_missing_and_truncated_records(self) -> None:
        first = self.make_record("first.json", tool_use_id="toolu-first")
        second = self.make_record("second.json", tool_use_id="toolu-second")
        duplicate = self.run_evidence(self.evidence_input(), first, second)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn(b"phase13:", duplicate.stderr)

        missing = self.run_evidence(self.evidence_input(), self.root / "missing.json")
        self.assertNotEqual(missing.returncode, 0)

        truncated_path = self.root / "truncated.json"
        truncated_path.write_bytes(b'{"format":"evidline.phase13')
        truncated = self.run_evidence(self.evidence_input(), truncated_path)
        self.assertNotEqual(truncated.returncode, 0)
        self.assertIn(b"phase13:", truncated.stderr)

    def test_adapter_failure_deny_cannot_become_verified_core_block(self) -> None:
        adapter_failure = self.deny_stdout(
            "evidline adapter failure: state could not be loaded; "
            "no MutationDecision was produced."
        )
        record_path = self.make_record(stdout=adapter_failure)

        completed = self.run_evidence(verified_denial_input(), record_path)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"phase13:", completed.stderr)

    def test_captured_core_block_policy_reason_supports_verified(self) -> None:
        record_path = self.make_record(stdout=self.deny_stdout(REAL_BLOCK_REASON))

        completed = self.run_evidence(verified_denial_input(), record_path)

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        evidence = json.loads(completed.stdout)
        self.assertEqual(evidence["verdict"], "VERIFIED")
        self.assertEqual(evidence["core_decision"], "BLOCK")

    def test_operator_core_semantics_must_match_captured_policy_reason(self) -> None:
        record_path = self.make_record(stdout=self.deny_stdout(REAL_BLOCK_REASON))
        unexecuted = {"verdict": "NOT_EXECUTED", "live_status": "NOT_EXECUTED"}

        cases = (
            {"core_decision": "ASK"},
            {"core_decision": "BLOCK", "block_reason": "SCOPE_VIOLATION"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                completed = self.run_evidence(
                    verified_denial_input(**unexecuted, **overrides), record_path
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"phase13:", completed.stderr)

    def test_captured_ask_policy_cannot_be_upgraded_to_core_block(self) -> None:
        ask_reason = (
            "evidline ASK: outcome=ASK; reasons=NO_ACTIVE_TASK; "
            "next_step=Confirm the active task; this is an Evidline policy "
            "result and is not harness or human authorization."
        )
        record_path = self.make_record(stdout=self.deny_stdout(ask_reason))

        completed = self.run_evidence(verified_denial_input(), record_path)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"phase13:", completed.stderr)


def _offline_state() -> StateDocument:
    """The accepted Phase 13 offline fixture state (INVARIANT_UNACKNOWLEDGED)."""

    return StateDocument(
        schema_version=4,
        revision=1,
        project=Project(
            name="phase13-sandbox",
            purpose="Candidate B offline adapter verification fixture",
            ignore_globs=(),
            default_budget_chars=8000,
        ),
        invariants=(
            Invariant(
                id="inv-p13-governed",
                description="Governed Phase 13 target remains unacknowledged",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
                governed_scope=("governed",),
            ),
        ),
        decisions=(),
        tasks=(
            Task(
                id="task-p13",
                description="Candidate B offline verification task",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                authorized_scope=("allowed", "governed"),
                approved_at="2026-08-18T00:00:00+00:00",
                approval_channel=TRUSTED_APPROVAL_CHANNEL,
                asserted_actor=TRUSTED_ASSERTED_ACTOR,
            ),
        ),
        claims=(),
        evidence=(),
        counters={},
    )


class ClaudeCaptureOfflineAdapterTests(unittest.TestCase):
    """Offline verification: actual helper -> actual adapter -> actual core.

    No Claude Code is invoked. The child argv keeps the accepted
    ``python -m evidline.adapters.claude pre-tool-use`` invocation shape;
    PYTHONPATH stands in for the sandbox venv install. These are offline
    behavior checks only and prove no live claim.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.sandbox = Path(self.temporary.name) / "sandbox"
        (self.sandbox / "allowed").mkdir(parents=True)
        (self.sandbox / "governed").mkdir()
        (self.sandbox / ".evidline").mkdir()
        (self.sandbox / ".evidline" / "state.json").write_text(
            serialize_state(_offline_state()), encoding="utf-8"
        )
        self.records = Path(self.temporary.name) / "private-records"
        self.records.mkdir()
        self.child_environment = os.environ.copy()
        self.child_environment["PYTHONPATH"] = str(REPO_ROOT / "src")

    def hook_input(self, target: str, tool_use_id: str) -> bytes:
        return json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "session_id": "session-offline-private",
                "tool_use_id": tool_use_id,
                "cwd": str(self.sandbox),
                "tool_name": "Write",
                "tool_input": {
                    "file_path": target,
                    "content": "PHASE13-PRIVATE-CONTENT",
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def run_adapter_direct(self, hook_input: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "evidline.adapters.claude",
                "pre-tool-use",
            ],
            input=hook_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.sandbox,
            env=self.child_environment,
            check=False,
        )

    def run_helper(
        self,
        hook_input: bytes,
        *,
        record: Path,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--record",
                str(record),
                "--",
                sys.executable,
                "-m",
                "evidline.adapters.claude",
                "pre-tool-use",
            ],
            input=hook_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.sandbox,
            env=self.child_environment,
            check=False,
        )

    def derive_evidence(self, record: Path, **overrides: object) -> dict[str, object]:
        document: dict[str, object] = {
            "claim": "LIVE_MUTATION_DENIAL",
            "harness_name": "Claude Code",
            "event_type": "PreToolUse",
            "supported_tool_path": "Write",
            "live_status": "NOT_EXECUTED",
            "verdict": "NOT_EXECUTED",
        }
        document.update(overrides)
        input_path = self.records / "evidence-input.json"
        input_path.write_text(json.dumps(document), encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "phase13",
            "evidence",
            "--input",
            str(input_path),
            "--private-correlation-record",
            str(record),
        ]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(REPO_ROOT / "src"), str(REPO_ROOT / "tools"))
        )
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPO_ROOT,
            env=environment,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return json.loads(completed.stdout)

    def test_offline_allow_preserves_adapter_process_boundary(self) -> None:
        payload = self.hook_input("allowed/probe-allow.txt", "toolu-offline-allow")
        direct = self.run_adapter_direct(payload)
        self.assertEqual(
            (direct.returncode, direct.stdout, direct.stderr), (0, b"", b"")
        )

        record = self.records / "allow.json"
        captured = self.run_helper(payload, record=record)

        # The positive control still traverses the full wrapper -> adapter
        # path unchanged, but must not consume the reserved denial record.
        self.assertEqual(captured.returncode, direct.returncode)
        self.assertEqual(captured.stdout, direct.stdout)
        self.assertEqual(captured.stderr, direct.stderr)
        self.assertFalse((self.sandbox / "allowed" / "probe-allow.txt").exists())
        self.assertFalse(record.exists())

        governed = self.hook_input("governed/probe-deny.txt", "toolu-offline-deny")
        captured_governed = self.run_helper(governed, record=record)
        self.assertEqual(captured_governed.returncode, 0)
        # The reserved destination remains available for the governed event.
        self.assertTrue(record.is_file())
        body = json.loads(record.read_bytes())
        self.assertEqual(body["adapter_exit_code"], 0)
        self.assertNotEqual(base64.b64decode(body["adapter_stdout_base64"]), b"")
        self.assertEqual(
            body["tool_use_sha256"],
            hashlib.sha256(b"toolu-offline-deny").hexdigest(),
        )
        self.assertNotIn(b"PHASE13-PRIVATE-CONTENT", record.read_bytes())
        self.assertNotIn(b"toolu-offline-deny", record.read_bytes())

    def test_offline_block_derives_deny_decision_and_exit(self) -> None:
        payload = self.hook_input("governed/probe-deny.txt", "toolu-offline-deny")
        direct = self.run_adapter_direct(payload)
        self.assertEqual(direct.returncode, 0)
        self.assertEqual(direct.stderr, b"")
        decision = json.loads(direct.stdout)
        self.assertEqual(
            decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "INVARIANT_UNACKNOWLEDGED",
            decision["hookSpecificOutput"]["permissionDecisionReason"],
        )

        record = self.records / "deny.json"
        captured = self.run_helper(payload, record=record)

        self.assertEqual(
            (captured.returncode, captured.stdout, captured.stderr),
            (direct.returncode, direct.stdout, direct.stderr),
        )
        self.assertFalse((self.sandbox / "governed" / "probe-deny.txt").exists())
        body = json.loads(record.read_bytes())
        self.assertEqual(body["adapter_exit_code"], 0)
        self.assertEqual(base64.b64decode(body["adapter_stdout_base64"]), direct.stdout)

        evidence = self.derive_evidence(record)
        self.assertEqual(evidence["adapter_exit_code"], 0)
        self.assertEqual(
            evidence["sanitized_hook_decision"]["hookSpecificOutput"][
                "permissionDecision"
            ],
            "deny",
        )
        self.assertEqual(
            evidence["tool_use_sha256"],
            hashlib.sha256(b"toolu-offline-deny").hexdigest(),
        )

    def test_offline_core_block_evidence_reaches_verified(self) -> None:
        payload = self.hook_input("governed/probe-deny.txt", "toolu-offline-verified")
        record = self.records / "verified.json"
        captured = self.run_helper(payload, record=record)
        self.assertEqual(captured.returncode, 0)

        evidence = self.derive_evidence(record, **verified_denial_input())

        self.assertEqual(evidence["verdict"], "VERIFIED")
        self.assertEqual(evidence["core_decision"], "BLOCK")
        self.assertEqual(
            evidence["block_reason"],
            "INVARIANT_UNACKNOWLEDGED",
        )

    def test_offline_adapter_failure_capture_cannot_become_verified(self) -> None:
        # The exact governed target stays capture-eligible even when state
        # cannot be loaded; the record must preserve that adapter failure
        # rather than hiding a non-decision result.
        payload = self.hook_input("governed/probe-deny.txt", "toolu-f")
        (self.sandbox / ".evidline" / "state.json").write_text(
            "{ invalid state", encoding="utf-8"
        )
        direct = self.run_adapter_direct(payload)
        self.assertEqual(direct.returncode, 0)
        reason = json.loads(direct.stdout)["hookSpecificOutput"][
            "permissionDecisionReason"
        ]
        self.assertIn("no MutationDecision was produced", reason)

        record = self.records / "adapter-failure.json"
        captured = self.run_helper(payload, record=record)
        self.assertEqual(
            (captured.returncode, captured.stdout, captured.stderr),
            (direct.returncode, direct.stdout, direct.stderr),
        )
        self.assertTrue(record.is_file())
        body = json.loads(record.read_bytes())
        self.assertEqual(base64.b64decode(body["adapter_stdout_base64"]), direct.stdout)

        with self.assertRaises(AssertionError):
            self.derive_evidence(record, **verified_denial_input())

    def test_offline_correlation_tamper_is_rejected(self) -> None:
        payload = self.hook_input("governed/probe-deny.txt", "toolu-offline-tamper")
        record = self.records / "tamper.json"
        captured = self.run_helper(payload, record=record)
        self.assertEqual(captured.returncode, 0)
        self.assertTrue(record.is_file())

        with self.subTest(case="operator-identity-conflict"):
            input_path = self.records / "tamper-input.json"
            input_path.write_text(
                json.dumps(
                    {
                        "claim": "LIVE_MUTATION_DENIAL",
                        "harness_name": "Claude Code",
                        "event_type": "PreToolUse",
                        "supported_tool_path": "Write",
                        "live_status": "NOT_EXECUTED",
                        "verdict": "NOT_EXECUTED",
                        "tool_use_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "phase13",
                    "evidence",
                    "--input",
                    str(input_path),
                    "--private-correlation-record",
                    str(record),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=REPO_ROOT,
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join(
                        (str(REPO_ROOT / "src"), str(REPO_ROOT / "tools"))
                    ),
                },
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"phase13:", completed.stderr)

        with self.subTest(case="record-result-forged-to-allow"):
            forged = json.loads(record.read_bytes())
            forged["adapter_stdout_base64"] = base64.b64encode(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "permissionDecisionReason": "forged",
                        }
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).decode("ascii")
            forged_path = self.records / "forged.json"
            forged_path.write_text(
                json.dumps(forged, separators=(",", ":"), sort_keys=True),
                encoding="ascii",
            )
            with self.assertRaises(AssertionError):
                self.derive_evidence(forged_path)

    def test_offline_record_write_failure_preserves_adapter_result(self) -> None:
        payload = self.hook_input("governed/probe-deny.txt", "toolu-offline-failure")
        direct = self.run_adapter_direct(payload)
        self.assertEqual(direct.returncode, 0)
        self.assertNotEqual(direct.stdout, b"")

        with self.subTest(case="create-new-collision"):
            collided = self.records / "collided.json"
            original = b"pre-existing-private-record"
            collided.write_bytes(original)
            captured = self.run_helper(payload, record=collided)
            self.assertEqual(captured.returncode, direct.returncode)
            self.assertEqual(captured.stdout, direct.stdout)
            self.assertEqual(captured.stderr, direct.stderr)
            self.assertEqual(collided.read_bytes(), original)

        with self.subTest(case="missing-destination"):
            missing = self.records / "absent" / "record.json"
            captured = self.run_helper(payload, record=missing)
            self.assertEqual(captured.returncode, direct.returncode)
            self.assertEqual(captured.stdout, direct.stdout)
            self.assertEqual(captured.stderr, direct.stderr)
            self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
