from __future__ import annotations

import ast
from dataclasses import replace
import importlib
import io
import json
import logging
import math
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evidline.adapters import claude, codex
from evidline.context import ContextProfile, compile_context, render_payload
from evidline.mutation import (
    MutationOutcome,
    MutationReason,
    MutationRequest,
    MutationRisk,
    evaluate_and_decide,
)
from evidline.state import (
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

_TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from phase13 import contract  # noqa: E402
from phase13.cli import main as phase13_main  # noqa: E402
from phase13.common import Phase13Error, sha256_file, sha256_text  # noqa: E402
from phase13.digest import capture_digest  # noqa: E402
from phase13.evidence import (  # noqa: E402
    classify_denial,
    generate_evidence_record,
    positive_control_expected_digest,
)
from phase13.probes import capture_probes, compare_probes  # noqa: E402
from phase13.rollback import apply_rollback, inspect_rollback  # noqa: E402
from phase13 import sanitize as phase13_sanitize  # noqa: E402
from phase13.sanitize import sanitize_document  # noqa: E402


APPROVED_AT = "2026-08-18T00:00:00+00:00"
PHASE13_REQUEST = MutationRequest(
    request_intent=Intent.PROPOSED,
    risk=MutationRisk.NORMAL,
)
NONCE_DESCRIPTION_TEMPLATE = (
    "Governed Phase 13 target remains unacknowledged. "
    "Evidline challenge token: {token}"
)


def phase13_state() -> StateDocument:
    return StateDocument(
        schema_version=4,
        revision=1,
        project=Project(
            name="phase13-sandbox",
            purpose="Phase 13 offline live-contract fixture",
            ignore_globs=(),
            default_budget_chars=8000,
        ),
        invariants=(
            Invariant(
                id=contract.INVARIANT_ID,
                description="Governed Phase 13 target remains unacknowledged",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
                governed_scope=("governed",),
            ),
        ),
        decisions=(),
        tasks=(
            Task(
                id=contract.TASK_ID,
                description="Phase 13 live-contract task",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                authorized_scope=("allowed", "governed"),
                approved_at=APPROVED_AT,
                approval_channel=TRUSTED_APPROVAL_CHANNEL,
                asserted_actor=TRUSTED_ASSERTED_ACTOR,
            ),
        ),
        claims=(),
        evidence=(),
        counters={},
    )


def phase13_state_with_nonce(token: str) -> StateDocument:
    state = phase13_state()
    invariant = replace(
        state.invariants[0],
        description=NONCE_DESCRIPTION_TEMPLATE.format(token=token),
    )
    return replace(state, invariants=(invariant,))


def measure_nonce_payload(token: str) -> dict[str, object]:
    context = compile_context(
        phase13_state_with_nonce(token),
        profile=ContextProfile.SESSION,
        budget_chars=8000,
    )
    payload = render_payload(context)
    return {
        "chars": len(payload),
        "bytes": len(payload.encode("utf-8")),
        "tokens": math.ceil(len(payload) / 4),
        "sel": sorted(
            (entry.record_id, entry.disposition.value)
            for entry in context.entries
        ),
        "offset": payload.find(token),
        "text": payload,
    }


def patch_text(*lines: str) -> str:
    return "\n".join(("*** Begin Patch", *lines, "*** End Patch"))


def _hex(label: str) -> str:
    return sha256_text(label)


def verified_payload(**overrides: object) -> dict[str, object]:
    phase13_digest = positive_control_expected_digest(
        contract.CLAUDE_HARNESS,
        contract.CLAUDE_PROVING_TOOL,
    )
    payload: dict[str, object] = {
        "claim": contract.CLAIM_DENIAL,
        "harness_name": contract.CLAUDE_HARNESS,
        "harness_version": "2.1.234",
        "evidline_commit_sha": "40a85c9c56ce68d4b369ed927060c102a42d3f82",
        "event_type": contract.CLAUDE_PRETOOL_EVENT,
        "supported_tool_path": contract.CLAUDE_PROVING_TOOL,
        "verdict": "VERIFIED",
        "live_status": "EXECUTED",
        "core_decision": "BLOCK",
        "block_reason": contract.BLOCK_REASON,
        "adapter_transport": "deny",
        "adapter_exit_code": 0,
        "harness_tool_result": "DENIED",
        "harness_blocking_result": "DENIED",
        "target_state": "UNCHANGED",
        "target_existed_before": False,
        "target_existed_after": False,
        "relative_target": contract.GOVERNED_PROBE,
        "sandbox_state_sha256": _hex("sandbox-state"),
        "session_sha256": _hex("session"),
        "tool_use_sha256": _hex("toolu"),
        "raw_capture_sha256": _hex("capture"),
        "proving_tool_attempted": True,
        "sanitized_hook_decision": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "evidline BLOCK: outcome=BLOCK; "
                f"reasons={contract.BLOCK_REASON}"
            ),
        },
        "positive_control_target": contract.ALLOWED_PROBE,
        "positive_control_existed_before": False,
        "positive_control_existed_after": True,
        "positive_control_digest_after": phase13_digest,
        "positive_control_expected_digest": phase13_digest,
        "positive_control_tool": contract.CLAUDE_PROVING_TOOL,
        "positive_control_tool_attempted": True,
        "positive_control_tool_use_sha256": _hex("pc-tool"),
        "positive_control_session_sha256": _hex("pc-session"),
        "positive_control_raw_capture_sha256": _hex("pc-capture"),
    }
    payload.update(overrides)
    tool = payload.get("supported_tool_path")
    if (
        "positive_control_tool" not in overrides
        and isinstance(tool, str)
        and tool
    ):
        payload["positive_control_tool"] = tool
    harness = payload.get("harness_name")
    positive_control_tool = payload.get("positive_control_tool")
    if isinstance(harness, str) and isinstance(positive_control_tool, str):
        try:
            phase13_digest = positive_control_expected_digest(
                harness,
                positive_control_tool,
            )
        except Phase13Error:
            pass
        else:
            if "positive_control_expected_digest" not in overrides:
                payload["positive_control_expected_digest"] = phase13_digest
            if "positive_control_digest_after" not in overrides:
                payload["positive_control_digest_after"] = phase13_digest
    return payload


def dispatch_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "claim": contract.CLAIM_DISPATCH,
        "harness_name": contract.CLAUDE_HARNESS,
        "harness_version": "2.1.234",
        "evidline_commit_sha": "40a85c9c56ce68d4b369ed927060c102a42d3f82",
        "event_type": contract.CLAUDE_SESSION_EVENT,
        "adapter_exit_code": 0,
        "verdict": "VERIFIED",
        "live_status": "EXECUTED",
        "sandbox_state_sha256": _hex("sandbox-state"),
        "session_sha256": _hex("dispatch-session"),
        "raw_capture_sha256": _hex("dispatch-capture"),
        "context_payload_sha256": _hex("context"),
        "context_payload_length": 302,
    }
    payload.update(overrides)
    return payload


def injection_payload(**overrides: object) -> dict[str, object]:
    nonce_digest = _hex("injection-nonce")
    payload: dict[str, object] = {
        "claim": contract.CLAIM_INJECTION,
        "harness_name": contract.CLAUDE_HARNESS,
        "harness_version": "2.1.234",
        "evidline_commit_sha": "40a85c9c56ce68d4b369ed927060c102a42d3f82",
        "event_type": contract.CLAUDE_SESSION_EVENT,
        "adapter_exit_code": 0,
        "verdict": "VERIFIED",
        "live_status": "EXECUTED",
        "sandbox_state_sha256": _hex("sandbox-state"),
        "challenge_nonce_sha256": nonce_digest,
        "enabled_session_sha256": _hex("enabled-session"),
        "control_session_sha256": _hex("control-session"),
        "enabled_raw_capture_sha256": _hex("enabled-capture"),
        "control_raw_capture_sha256": _hex("control-capture"),
        "enabled_answer_sha256": nonce_digest,
        "control_answer_sha256": _hex("control-answer"),
        "context_payload_sha256": _hex("context"),
        "context_payload_length": 302,
        "tool_use_count_before_answer": 0,
        "negative_control_result": contract.NEGATIVE_CONTROL_NONCE_ABSENT,
    }
    payload.update(overrides)
    return payload


class Phase13LiveContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "sandbox"
        self.root.mkdir()
        (self.root / "allowed").mkdir()
        (self.root / "governed").mkdir()
        state_directory = self.root / ".evidline"
        state_directory.mkdir()
        (state_directory / "state.json").write_text(
            serialize_state(phase13_state()),
            encoding="utf-8",
        )

    def allowed_target(self) -> Path:
        return self.root / "allowed" / "probe-allow.txt"

    def governed_target(self) -> Path:
        return self.root / "governed" / "probe-deny.txt"

    def invoke(
        self,
        adapter: object,
        command: str,
        payload: dict[str, object],
    ) -> tuple[int, str, str]:
        stdin = io.StringIO(json.dumps(payload))
        stdout_bytes = io.BytesIO()
        stderr_bytes = io.BytesIO()
        stdout = io.TextIOWrapper(stdout_bytes, encoding="utf-8")
        stderr = io.TextIOWrapper(stderr_bytes, encoding="utf-8")
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = adapter.main((command,))
        stdout.flush()
        stderr.flush()
        return (
            code,
            stdout_bytes.getvalue().decode("utf-8"),
            stderr_bytes.getvalue().decode("utf-8"),
        )

    def permission_output(self, stdout: str) -> dict[str, object]:
        document = json.loads(stdout)
        self.assertEqual(set(document), {"hookSpecificOutput"})
        output = document["hookSpecificOutput"]
        self.assertIsInstance(output, dict)
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertTrue(str(output["permissionDecisionReason"]).strip())
        return output

    def test_nonce_prefix_literal_is_pinned(self) -> None:
        self.assertEqual(contract.NONCE_PREFIX, "EVIDLINE-P13-")
        self.assertEqual(len(contract.NONCE_PREFIX), 13)
        self.assertEqual(len(contract.NONCE_PREFIX.encode("utf-8")), 13)

    def test_nonce_entropy_and_generator_parameters_are_pinned(self) -> None:
        self.assertIs(contract.secrets.token_hex, secrets.token_hex)
        self.assertEqual(contract.NONCE_RANDOM_BYTES, 16)
        self.assertEqual(contract.NONCE_ENTROPY_BITS, 128)
        self.assertEqual(
            contract.NONCE_ENTROPY_BITS,
            contract.NONCE_RANDOM_BYTES * 8,
        )
        self.assertEqual(contract.NONCE_RANDOM_ENCODING, "hex")

    def test_nonce_random_component_length_is_consistent(self) -> None:
        self.assertEqual(contract.NONCE_RANDOM_CHARS, 32)
        self.assertEqual(
            contract.NONCE_RANDOM_CHARS,
            contract.NONCE_RANDOM_BYTES * 2,
        )

    def test_nonce_total_lengths_are_consistent(self) -> None:
        self.assertEqual(contract.NONCE_TOTAL_CHARS, 45)
        self.assertEqual(contract.NONCE_TOTAL_BYTES, 45)
        self.assertEqual(
            contract.NONCE_TOTAL_CHARS,
            len(contract.NONCE_PREFIX) + contract.NONCE_RANDOM_CHARS,
        )
        self.assertEqual(
            contract.NONCE_TOTAL_BYTES,
            len(contract.NONCE_PREFIX.encode("utf-8"))
            + contract.NONCE_RANDOM_CHARS,
        )

    def test_nonce_regex_is_exact(self) -> None:
        self.assertEqual(
            contract.NONCE_PATTERN.pattern,
            r"^EVIDLINE-P13-[0-9a-f]{32}$",
        )
        accepted = contract.NONCE_PREFIX + ("a" * 32)
        self.assertIsNotNone(contract.NONCE_PATTERN.fullmatch(accepted))
        rejected = (
            contract.NONCE_PREFIX + ("A" * 32),
            contract.NONCE_PREFIX + ("a" * 31),
            contract.NONCE_PREFIX + ("a" * 33),
            contract.NONCE_PREFIX,
            " " + accepted,
            accepted + " ",
            accepted + "\n",
            "EVIDLINE-P12-" + ("a" * 32),
            contract.NONCE_PREFIX + ("g" * 32),
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                self.assertIsNone(contract.NONCE_PATTERN.fullmatch(candidate))

    def test_generated_nonce_matches_grammar_and_lengths(self) -> None:
        for _ in range(64):
            nonce = contract.generate_live_nonce()
            self.assertIsNotNone(contract.NONCE_PATTERN.fullmatch(nonce))
            self.assertEqual(len(nonce), 45)
            self.assertEqual(len(nonce.encode("utf-8")), 45)
            random_component = nonce[len(contract.NONCE_PREFIX) :]
            self.assertEqual(random_component, random_component.lower())
            self.assertTrue(nonce.isascii())

    def test_generated_nonce_uses_secrets_token_hex_with_16_bytes(self) -> None:
        random_component = "a" * 32
        with (
            mock.patch.object(
                contract.secrets,
                "token_hex",
                return_value=random_component,
            ) as token_hex,
            mock.patch("secrets.token_bytes", side_effect=AssertionError),
            mock.patch("os.urandom", side_effect=AssertionError),
            mock.patch("random.random", side_effect=AssertionError),
        ):
            nonce = contract.generate_live_nonce()
        token_hex.assert_called_once_with(16)
        self.assertEqual(nonce, contract.NONCE_PREFIX + random_component)

    def test_placeholder_is_deterministic(self) -> None:
        expected = "EVIDLINE-P13-00000000000000000000000000000000"
        self.assertEqual(contract.make_nonce_placeholder(), expected)
        self.assertEqual(contract.NONCE_PLACEHOLDER, expected)
        self.assertEqual(
            contract.NONCE_PLACEHOLDER,
            contract.NONCE_PREFIX
            + (contract.NONCE_PLACEHOLDER_FILL * contract.NONCE_RANDOM_CHARS),
        )

    def test_placeholder_char_and_byte_length_equal_live_nonce(self) -> None:
        placeholder = contract.make_nonce_placeholder()
        for _ in range(32):
            nonce = contract.generate_live_nonce()
            self.assertEqual(len(placeholder), len(nonce))
            self.assertEqual(
                len(placeholder.encode("utf-8")),
                len(nonce.encode("utf-8")),
            )

    def test_placeholder_is_rejected_as_live_nonce(self) -> None:
        placeholder = contract.make_nonce_placeholder()
        self.assertIsNotNone(contract.NONCE_PATTERN.fullmatch(placeholder))
        self.assertFalse(contract.is_live_nonce_candidate(placeholder))

    def test_generated_nonce_differs_from_placeholder(self) -> None:
        for _ in range(64):
            self.assertNotEqual(
                contract.generate_live_nonce(),
                contract.NONCE_PLACEHOLDER,
            )

    def test_nonce_module_import_has_no_side_effects(self) -> None:
        with mock.patch("secrets.token_hex") as token_hex:
            reloaded = importlib.reload(contract)
        token_hex.assert_not_called()
        live_values = [
            value
            for value in vars(reloaded).values()
            if isinstance(value, str) and reloaded.is_live_nonce_candidate(value)
        ]
        self.assertEqual(live_values, [])

    def test_nonce_helpers_perform_no_io_or_logging(self) -> None:
        random_component = "b" * 32
        with (
            mock.patch.object(
                contract.secrets,
                "token_hex",
                return_value=random_component,
            ),
            mock.patch("builtins.open", side_effect=AssertionError),
            mock.patch("pathlib.Path.read_text", side_effect=AssertionError),
            mock.patch("pathlib.Path.write_text", side_effect=AssertionError),
            mock.patch.object(subprocess, "run", side_effect=AssertionError),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError),
            mock.patch.object(socket, "socket", side_effect=AssertionError),
            mock.patch.object(logging.Logger, "_log", side_effect=AssertionError),
        ):
            generated = contract.generate_live_nonce()
            placeholder = contract.make_nonce_placeholder()
            self.assertTrue(contract.is_live_nonce_candidate(generated))
            self.assertFalse(contract.is_live_nonce_candidate(placeholder))
        self.assertEqual(generated, contract.NONCE_PREFIX + random_component)
        self.assertEqual(placeholder, contract.NONCE_PLACEHOLDER)

    def test_contract_module_imports_stdlib_only(self) -> None:
        source = Path(contract.__file__).read_text(encoding="utf-8")
        imported_roots: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertLessEqual(
            imported_roots,
            {"__future__", "re", "secrets", "types", "typing"},
        )

    def test_nonce_is_sanitizer_compatible(self) -> None:
        nonce = contract.generate_live_nonce()
        cleaned = sanitize_document(
            {"note": f"challenge={nonce}"},
            nonce=nonce,
        )
        rendered = json.dumps(cleaned)
        self.assertIn("[REDACTED_NONCE]", rendered)
        self.assertNotIn(nonce, rendered)
        self.assertEqual(cleaned["challenge_nonce_sha256"], sha256_text(nonce))
        for candidate in (nonce, contract.NONCE_PLACEHOLDER):
            self.assertIsNone(phase13_sanitize._SHA256_HEX.search(candidate))
            self.assertIsNone(phase13_sanitize._WINDOWS_ABS.search(candidate))
            self.assertIsNone(phase13_sanitize._POSIX_ABS.search(candidate))

    def test_nonce_file_transport_round_trip(self) -> None:
        nonce = contract.generate_live_nonce()
        payload = self.root / "nonce-evidence-in.json"

        def invoke_with_body(body: bytes) -> dict[str, object]:
            nonce_text = body.decode("utf-8").rstrip("\r\n")
            payload.write_text(
                json.dumps(
                    {
                        "verdict": "NOT_EXECUTED",
                        "notes": f"free text {nonce_text}",
                    }
                ),
                encoding="utf-8",
            )
            nonce_file = self.root / "nonce.txt"
            nonce_file.write_bytes(body)
            stdout = io.StringIO()
            with mock.patch("sys.stdout", stdout):
                code = phase13_main(
                    [
                        "evidence",
                        "--input",
                        str(payload),
                        "--claim",
                        contract.CLAIM_INJECTION,
                        "--nonce-file",
                        str(nonce_file),
                    ]
                )
            self.assertEqual(code, 0)
            rendered = stdout.getvalue()
            self.assertNotIn(nonce_text, rendered)
            return json.loads(rendered)

        digests = {
            invoke_with_body(body)["challenge_nonce_sha256"]
            for body in (
                nonce.encode("utf-8"),
                f"{nonce}\n".encode("utf-8"),
                f"{nonce}\r\n".encode("utf-8"),
            )
        }
        self.assertEqual(digests, {sha256_text(nonce)})
        corrupted = invoke_with_body(f"{nonce} ".encode("utf-8"))
        self.assertEqual(
            corrupted["challenge_nonce_sha256"],
            sha256_text(f"{nonce} "),
        )
        self.assertNotEqual(corrupted["challenge_nonce_sha256"], sha256_text(nonce))

    def test_nonce_is_whitespace_normalization_stable(self) -> None:
        for token in (contract.generate_live_nonce(), contract.NONCE_PLACEHOLDER):
            measured = measure_nonce_payload(token)
            self.assertGreaterEqual(measured["offset"], 0)
            self.assertIn(token, measured["text"])

    def test_nonce_is_json_transparent(self) -> None:
        for token in (contract.generate_live_nonce(), contract.NONCE_PLACEHOLDER):
            self.assertEqual(json.dumps(token), f'"{token}"')
            self.assertEqual(json.loads(json.dumps(token)), token)

    def test_d2_equal_length_substitution_preserves_payload_measurements(self) -> None:
        placeholder = measure_nonce_payload(contract.NONCE_PLACEHOLDER)
        for _ in range(32):
            live = measure_nonce_payload(contract.generate_live_nonce())
            for field in ("chars", "bytes", "tokens", "sel", "offset"):
                self.assertEqual(live[field], placeholder[field])
            self.assertNotEqual(live["text"], placeholder["text"])

        shorter = measure_nonce_payload(contract.NONCE_PREFIX + ("0" * 31))
        longer = measure_nonce_payload(contract.NONCE_PREFIX + ("0" * 33))
        non_ascii = measure_nonce_payload(contract.NONCE_PREFIX + ("é" * 32))
        self.assertEqual(shorter["chars"] - placeholder["chars"], -1)
        self.assertEqual(shorter["bytes"] - placeholder["bytes"], -1)
        self.assertEqual(longer["chars"] - placeholder["chars"], 1)
        self.assertEqual(longer["bytes"] - placeholder["bytes"], 1)
        self.assertEqual(non_ascii["chars"] - placeholder["chars"], 0)
        self.assertNotEqual(non_ascii["bytes"] - placeholder["bytes"], 0)

    def test_d2_payload_length_is_slope_one_in_token_length(self) -> None:
        measurements = {
            length: measure_nonce_payload("x" * length)
            for length in range(1, 61)
        }
        base = measurements[1]["chars"] - 1
        for length, measured in measurements.items():
            self.assertEqual(measured["chars"] - length, base)

        single = measure_nonce_payload("z")
        placeholder = measure_nonce_payload(contract.NONCE_PLACEHOLDER)
        live = measure_nonce_payload(contract.generate_live_nonce())
        self.assertEqual(
            placeholder["chars"] - single["chars"],
            contract.NONCE_TOTAL_CHARS - 1,
        )
        self.assertEqual(
            live["chars"] - single["chars"],
            contract.NONCE_TOTAL_CHARS - 1,
        )
        token_44 = measure_nonce_payload("x" * 44)
        self.assertNotEqual(
            token_44["chars"] - single["chars"],
            contract.NONCE_TOTAL_CHARS - 1,
        )
        self.assertEqual(measure_nonce_payload("")["chars"], base - 1)

    def test_adr_0027_records_the_nonce_contract(self) -> None:
        adr = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "adr"
            / "ADR-0027-vab-7-live-verification-contract.md"
        ).read_text(encoding="utf-8")
        required = (
            contract.NONCE_PREFIX,
            str(contract.NONCE_RANDOM_CHARS),
            f"{contract.NONCE_TOTAL_CHARS} total characters",
            f"{contract.NONCE_TOTAL_BYTES} UTF-8 bytes",
            f"{contract.NONCE_ENTROPY_BITS}-bit entropy",
            contract.NONCE_PATTERN.pattern,
            contract.NONCE_PLACEHOLDER,
            "reserved non-live sentinel",
            "challenge_nonce_sha256",
            "independently recomputed only while",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, adr)

    def test_live_verification_doc_records_the_nonce_contract(self) -> None:
        procedure = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "live-verification.md"
        ).read_text(encoding="utf-8")
        required = (
            contract.NONCE_PREFIX,
            str(contract.NONCE_RANDOM_CHARS),
            f"{contract.NONCE_TOTAL_CHARS} characters",
            f"{contract.NONCE_TOTAL_BYTES} UTF-8 bytes",
            contract.NONCE_PATTERN.pattern,
            contract.NONCE_PLACEHOLDER,
            "--nonce-file",
            "DESCRIPTION TEMPLATE FIXITY",
            "<PRIVATE_REVIEW>/nonce.txt",
            "survive rollback",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, procedure)

    def test_allowed_target_is_allow(self) -> None:
        self.assertFalse(self.allowed_target().exists())
        decision = evaluate_and_decide(
            PHASE13_REQUEST,
            self.root,
            "allowed/probe-allow.txt",
            phase13_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.ALLOW)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.unacknowledged_invariant_ids, ())

    def test_governed_target_is_block_unacknowledged(self) -> None:
        self.assertFalse(self.governed_target().exists())
        decision = evaluate_and_decide(
            PHASE13_REQUEST,
            self.root,
            "governed/probe-deny.txt",
            phase13_state(),
        )
        self.assertEqual(decision.outcome, MutationOutcome.BLOCK)
        self.assertEqual(
            decision.reasons,
            (MutationReason.INVARIANT_UNACKNOWLEDGED,),
        )
        self.assertEqual(
            decision.unacknowledged_invariant_ids,
            (contract.INVARIANT_ID,),
        )
        self.assertEqual(contract.BLOCK_REASON, "INVARIANT_UNACKNOWLEDGED")

    def test_claude_write_allow_is_silence(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root),
            "tool_name": contract.CLAUDE_PROVING_TOOL,
            "tool_input": {"file_path": "allowed/probe-allow.txt"},
        }
        self.assertEqual(self.invoke(claude, "pre-tool-use", payload), (0, "", ""))
        self.assertFalse(self.allowed_target().exists())

    def test_claude_write_deny_transport(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root),
            "tool_name": contract.CLAUDE_PROVING_TOOL,
            "tool_input": {"file_path": "governed/probe-deny.txt"},
        }
        code, stdout, stderr = self.invoke(claude, "pre-tool-use", payload)
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        reason = str(output["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline BLOCK:"))
        self.assertIn(contract.BLOCK_REASON, reason)
        self.assertFalse(self.governed_target().exists())

    def test_codex_apply_patch_deny_transport(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root),
            "tool_name": contract.CODEX_PROVING_TOOL,
            "tool_input": {
                "command": patch_text(
                    "*** Add File: governed/probe-deny.txt",
                    "+denied",
                )
            },
        }
        code, stdout, stderr = self.invoke(codex, "pre-tool-use", payload)
        self.assertEqual((code, stderr), (0, ""))
        output = self.permission_output(stdout)
        reason = str(output["permissionDecisionReason"])
        self.assertTrue(reason.startswith("evidline BLOCK:"))
        self.assertIn(contract.BLOCK_REASON, reason)
        self.assertFalse(self.governed_target().exists())

    def test_uncovered_tools_are_not_proven_enforcement(self) -> None:
        for tool_name in ("Bash", "PowerShell", "Monitor"):
            with self.subTest(tool_name=tool_name):
                self.assertTrue(contract.is_uncovered_tool(tool_name))
                self.assertFalse(
                    contract.is_selected_proving_tool(contract.CLAUDE_HARNESS, tool_name)
                )
                payload = {
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.root),
                    "tool_name": tool_name,
                    "tool_input": {"command": "echo uncovered"},
                }
                self.assertEqual(
                    self.invoke(claude, "pre-tool-use", payload),
                    (0, "", ""),
                )
                self.assertEqual(
                    classify_denial(
                        core_decision="BLOCK",
                        adapter_transport="deny",
                        harness_tool_result="DENIED",
                        target_changed=False,
                        positive_control_succeeded=True,
                        selected_tool_used=False,
                    ),
                    "NOT_COVERED",
                )
                with self.assertRaises(Phase13Error):
                    generate_evidence_record(
                        {
                            "harness_name": contract.CLAUDE_HARNESS,
                            "supported_tool_path": tool_name,
                            "verdict": "VERIFIED",
                            "live_status": "EXECUTED",
                            "core_decision": "BLOCK",
                            "adapter_transport": "deny",
                            "harness_tool_result": "DENIED",
                            "target_state": "UNCHANGED",
                            "target_existed_after": False,
                            "positive_control_result": "succeeded",
                        }
                    )

    def test_codex_uncovered_tool_is_silent(self) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": str(self.root),
            "tool_name": "Bash",
            "tool_input": {
                "command": patch_text(
                    "*** Add File: governed/probe-deny.txt",
                    "+denied",
                )
            },
        }
        self.assertEqual(self.invoke(codex, "pre-tool-use", payload), (0, "", ""))
        self.assertFalse(
            contract.is_selected_proving_tool(contract.CODEX_HARNESS, "Bash")
        )

    def test_sanitizer_removes_nonce_transcript_paths_and_secrets(self) -> None:
        nonce = "EVIDLINE-P13-TESTONLY-NOT-A-LIVE-NONCE"
        raw = {
            "transcript": "operator said the secret",
            "messages": [{"content": nonce}],
            "thinking": "private chain of thought",
            "api_key": "sk-test",
            "token": "abc",
            "cwd": str(self.root / "governed" / "probe-deny.txt"),
            "home": str(self.root),
            "note": f"token={nonce} path={self.root}",
            "relative_target": "governed/probe-deny.txt",
        }
        cleaned = sanitize_document(
            raw,
            nonce=nonce,
            root=self.root,
            home_prefixes=(str(self.root.parent),),
        )
        rendered = json.dumps(cleaned)
        self.assertNotIn(nonce, rendered)
        self.assertNotIn("operator said the secret", rendered)
        self.assertNotIn("private chain of thought", rendered)
        self.assertNotIn("sk-test", rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertEqual(cleaned["transcript"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["messages"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["thinking"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["api_key"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["token"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["home"], "[REDACTED_FIELD]")
        self.assertIn("[REDACTED_NONCE]", cleaned["note"])
        self.assertIn("[SANDBOX_ROOT]", cleaned["note"])
        self.assertEqual(cleaned["relative_target"], "governed/probe-deny.txt")
        self.assertIn("challenge_nonce_sha256", cleaned)
        self.assertNotEqual(cleaned["challenge_nonce_sha256"], nonce)

    def test_evidence_record_refuses_verified_while_not_executed(self) -> None:
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                {
                    "harness_name": contract.CLAUDE_HARNESS,
                    "supported_tool_path": contract.CLAUDE_PROVING_TOOL,
                    "verdict": "VERIFIED",
                    "live_status": contract.LIVE_STATUS,
                    "core_decision": "BLOCK",
                    "adapter_transport": "deny",
                    "harness_tool_result": "DENIED",
                    "target_state": "UNCHANGED",
                    "target_existed_after": False,
                    "positive_control_result": "succeeded",
                }
            )
        record = generate_evidence_record(
            {
                "harness_name": contract.CLAUDE_HARNESS,
                "supported_tool_path": contract.CLAUDE_PROVING_TOOL,
                "verdict": "NOT_EXECUTED",
                "relative_target": contract.GOVERNED_PROBE,
            }
        )
        self.assertEqual(record["live_status"], "NOT_EXECUTED")
        self.assertEqual(record["verdict"], "NOT_EXECUTED")
        self.assertNotIn("nonce", record)

    def test_evidence_record_rejects_plaintext_nonce(self) -> None:
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                {
                    "verdict": "NOT_EXECUTED",
                    "nonce": "EVIDLINE-P13-should-not-be-stored",
                }
            )

    def test_probe_capture_does_not_create_targets(self) -> None:
        captured = capture_probes(
            self.root,
            (contract.ALLOWED_PROBE, contract.GOVERNED_PROBE),
        )
        self.assertFalse(self.allowed_target().exists())
        self.assertFalse(self.governed_target().exists())
        self.assertEqual(
            [item["exists"] for item in captured["probes"]],
            [False, False],
        )
        digest = capture_digest(self.root)
        self.assertTrue(digest["state_present"])
        self.assertRegex(digest["state_sha256"], r"^[0-9a-f]{64}$")
        compared = compare_probes(captured, captured)
        self.assertFalse(any(item["changed"] for item in compared["comparisons"]))

    def test_rollback_defaults_to_inspection_and_dry_run(self) -> None:
        plan = {
            "sandbox_paths": ["allowed/probe-allow.txt"],
            "user_level_paths": ["codex-user-trust-block"],
        }
        inspection = inspect_rollback(plan, sandbox_root=self.root)
        self.assertEqual(inspection["mode"], "inspect")
        self.assertFalse(inspection["items"][0]["exists"])
        self.assertFalse(inspection["items"][1]["apply_supported"])
        dry_run = apply_rollback(plan, sandbox_root=self.root, dry_run=True)
        self.assertEqual(dry_run["mode"], "dry_run")
        self.assertEqual(dry_run["items"][0]["action"], "absent")
        self.assertEqual(dry_run["items"][1]["action"], "skipped")

    def test_classify_denial_matches_frozen_verdicts(self) -> None:
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=False,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "VERIFIED",
        )
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="EXECUTED",
                target_changed=True,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "FAILED_OPEN",
        )
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=True,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "FAILED_OPEN",
        )
        self.assertEqual(
            classify_denial(
                core_decision="ALLOW",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=True,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "FAILED",
        )
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=False,
                positive_control_succeeded=False,
                selected_tool_used=True,
            ),
            "INCONCLUSIVE",
        )

    def test_adr_0027_aligns_with_selected_proving_constants(self) -> None:
        adr = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "adr"
            / "ADR-0027-vab-7-live-verification-contract.md"
        )
        text = adr.read_text(encoding="utf-8")
        self.assertIn(
            f"VAB_7_HARNESS_DECISION = {contract.VAB_7_HARNESS_DECISION}",
            text,
        )
        self.assertIn(
            f"actual proving tool: {contract.CLAUDE_PROVING_TOOL}",
            text,
        )
        self.assertIn(
            f"actual proving tool: {contract.CODEX_PROVING_TOOL}",
            text,
        )
        self.assertIn("complete harness enforcement", text)

    def test_destructive_apply_refuses_filesystem_root(self) -> None:
        rootish = Path(Path.home().anchor)
        with self.assertRaises(Phase13Error) as ctx:
            apply_rollback(
                {"sandbox_paths": ["victim.txt"]},
                sandbox_root=rootish,
                dry_run=False,
            )
        self.assertIn("filesystem root", str(ctx.exception))

    def test_destructive_apply_refuses_mocked_home(self) -> None:
        fake_home = Path(self.temporary.name) / "fake-home"
        fake_home.mkdir()
        keep = fake_home / "keep.txt"
        keep.write_text("keep", encoding="utf-8")
        with mock.patch.object(Path, "home", return_value=fake_home):
            with self.assertRaises(Phase13Error) as ctx:
                apply_rollback(
                    {"sandbox_paths": ["keep.txt"]},
                    sandbox_root=fake_home,
                    dry_run=False,
                )
        self.assertIn("user home directory", str(ctx.exception))
        self.assertTrue(keep.exists())

    def test_destructive_apply_refuses_repository_like_temp(self) -> None:
        for marker, kind in (
            (".git", "dir"),
            ("pyproject.toml", "file"),
            ("AGENTS.md", "file"),
        ):
            with self.subTest(marker=marker):
                repoish = Path(self.temporary.name) / f"repo-{marker.replace('.', '')}"
                repoish.mkdir()
                victim = repoish / "victim.txt"
                victim.write_text("stay", encoding="utf-8")
                if kind == "dir":
                    (repoish / marker).mkdir()
                else:
                    (repoish / marker).write_text("marker\n", encoding="utf-8")
                (repoish / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
                with self.assertRaises(Phase13Error) as ctx:
                    apply_rollback(
                        {"sandbox_paths": ["victim.txt"]},
                        sandbox_root=repoish,
                        dry_run=False,
                    )
                self.assertIn(marker, str(ctx.exception))
                self.assertTrue(victim.exists())

    def test_destructive_apply_refuses_missing_sandbox_marker(self) -> None:
        target = self.root / "allowed" / "probe-allow.txt"
        target.write_text("stay", encoding="utf-8")
        with self.assertRaises(Phase13Error) as ctx:
            apply_rollback(
                {"sandbox_paths": [contract.ALLOWED_PROBE]},
                sandbox_root=self.root,
                dry_run=False,
            )
        self.assertIn(contract.SANDBOX_MARKER, str(ctx.exception))
        self.assertTrue(target.exists())

    def test_destructive_apply_deletes_only_marked_sandbox_target(self) -> None:
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        target = self.root / "allowed" / "probe-allow.txt"
        target.write_text("temp-probe", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("stay", encoding="utf-8")
        state = self.root / ".evidline" / "state.json"
        result = apply_rollback(
            {"sandbox_paths": [contract.ALLOWED_PROBE]},
            sandbox_root=self.root,
            dry_run=False,
        )
        self.assertEqual(result["mode"], "apply")
        self.assertFalse(target.exists())
        self.assertTrue(outside.exists())
        self.assertTrue(state.exists())
        self.assertTrue((self.root / contract.SANDBOX_MARKER).exists())

    def test_cli_rollback_apply_without_sandbox_root_is_refused(self) -> None:
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps({"sandbox_paths": [contract.ALLOWED_PROBE]}),
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            code = phase13_main(
                ["rollback", "--plan", str(plan), "--apply"]
            )
        self.assertEqual(code, 1)
        self.assertIn("--sandbox-root", stderr.getvalue())

    def test_cli_rollback_apply_without_marker_is_refused(self) -> None:
        target = self.root / "allowed" / "probe-allow.txt"
        target.write_text("stay", encoding="utf-8")
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps({"sandbox_paths": [contract.ALLOWED_PROBE]}),
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            code = phase13_main(
                [
                    "rollback",
                    "--plan",
                    str(plan),
                    "--sandbox-root",
                    str(self.root),
                    "--apply",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn(contract.SANDBOX_MARKER, stderr.getvalue())
        self.assertTrue(target.exists())

    def test_cli_rollback_apply_marked_temp_deletes_only_planned_target(self) -> None:
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        target = self.root / "allowed" / "probe-allow.txt"
        target.write_text("temp-probe", encoding="utf-8")
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps({"sandbox_paths": [contract.ALLOWED_PROBE]}),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            code = phase13_main(
                [
                    "rollback",
                    "--plan",
                    str(plan),
                    "--sandbox-root",
                    str(self.root),
                    "--apply",
                ]
            )
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        self.assertTrue((self.root / ".evidline" / "state.json").exists())
        self.assertNotIn("temp-probe", stdout.getvalue())

    def test_cli_help_performs_no_mutation(self) -> None:
        before = tuple(
            sorted((path.relative_to(self.root), path.read_bytes() if path.is_file() else None)
                   for path in self.root.rglob("*"))
        )
        with self.assertRaises(SystemExit) as ctx:
            phase13_main(["rollback", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        after = tuple(
            sorted((path.relative_to(self.root), path.read_bytes() if path.is_file() else None)
                   for path in self.root.rglob("*"))
        )
        self.assertEqual(before, after)

    def test_verified_requires_harness_and_selected_tool(self) -> None:
        with self.assertRaises(Phase13Error):
            generate_evidence_record(verified_payload(harness_name=None))
        with self.assertRaises(Phase13Error):
            generate_evidence_record(verified_payload(supported_tool_path=None))
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(supported_tool_path="Bash")
            )
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(
                    harness_name=contract.CODEX_HARNESS,
                    supported_tool_path="Bash",
                )
            )
        claude = generate_evidence_record(verified_payload())
        self.assertEqual(claude["verdict"], "VERIFIED")
        self.assertEqual(claude["harness_name"], contract.CLAUDE_HARNESS)
        self.assertEqual(claude["supported_tool_path"], "Write")
        codex_record = generate_evidence_record(
            verified_payload(
                harness_name=contract.CODEX_HARNESS,
                supported_tool_path=contract.CODEX_PROVING_TOOL,
            )
        )
        self.assertEqual(codex_record["verdict"], "VERIFIED")
        self.assertEqual(codex_record["supported_tool_path"], "apply_patch")

    def test_exit_2_cannot_become_verified(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(verified_payload(adapter_exit_code=2))
        self.assertIn("exit 2", str(ctx.exception))
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=False,
                positive_control_succeeded=True,
                selected_tool_used=True,
                adapter_exit_code=2,
            ),
            "FAIL_CLOSED_MISATTRIBUTION",
        )

    def test_evidence_redacts_nonce_in_free_text_and_nested_notes(self) -> None:
        nonce = "EVIDLINE-P13-TESTONLY-EVIDENCE-NONCE"
        digest = sha256_text(nonce)
        record = generate_evidence_record(
            {
                "verdict": "NOT_EXECUTED",
                "notes": {
                    "summary": f"challenge {nonce} seen",
                    "relative_target": contract.GOVERNED_PROBE,
                },
                "challenge_nonce_sha256": digest,
            },
            nonce=nonce,
        )
        rendered = json.dumps(record)
        self.assertNotIn(nonce, rendered)
        self.assertEqual(record["challenge_nonce_sha256"], digest)
        self.assertIn("[REDACTED_NONCE]", record["notes"]["summary"])
        self.assertEqual(
            record["notes"]["relative_target"], contract.GOVERNED_PROBE
        )

    def test_evidence_cli_nonce_file_does_not_emit_plaintext(self) -> None:
        nonce = "EVIDLINE-P13-TESTONLY-CLI-NONCE"
        payload = self.root / "evidence-in.json"
        payload.write_text(
            json.dumps(
                {
                    "verdict": "NOT_EXECUTED",
                    "notes": f"free text {nonce}",
                }
            ),
            encoding="utf-8",
        )
        nonce_file = self.root / "nonce.txt"
        nonce_file.write_text(nonce, encoding="utf-8")
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            code = phase13_main(
                [
                    "evidence",
                    "--input",
                    str(payload),
                    "--nonce-file",
                    str(nonce_file),
                ]
            )
        self.assertEqual(code, 0)
        rendered = stdout.getvalue()
        self.assertNotIn(nonce, rendered)
        self.assertIn("challenge_nonce_sha256", rendered)
        self.assertIn(sha256_text(nonce), rendered)

    def test_sanitizer_covers_expanded_sensitive_classes(self) -> None:
        nonce = "EVIDLINE-P13-TESTONLY-SANITIZER-NONCE"
        raw = {
            "Prompt": "user prompt leaked",
            "old-string": "before",
            "new_string": "after",
            "file_text": "file body",
            "wrapper": {
                "tool_response": {"ok": True},
                "tool_result": "tool output",
                "keep_id": "structural-id",
            },
            "items": [{"Text": "nested list text"}, {"keep": "visible"}],
            "bearer_token_value": "tok-123",
            "env": {"ANTHROPIC_API_KEY": "sk-ant", "PATH": "/usr/bin"},
            "environment": {"OPENAI_API_KEY": "sk-openai"},
            "installation_id": "inst-1",
            "machine_id": "mach-1",
            "account_id": "acct-1",
            "user_email": "user@example.test",
            "email": "other@example.test",
            "windows_path": r"C:\Users\example\secret.txt",
            "posix_path": "/home/example/secret.txt",
            "note": f"ordinary free text {nonce}",
            "relative_target": contract.GOVERNED_PROBE,
        }
        cleaned = sanitize_document(raw, nonce=nonce)
        rendered = json.dumps(cleaned)
        self.assertNotIn("user prompt leaked", rendered)
        self.assertNotIn("before", rendered)
        self.assertNotIn("after", rendered)
        self.assertNotIn("file body", rendered)
        self.assertNotIn("tool output", rendered)
        self.assertNotIn("tok-123", rendered)
        self.assertNotIn("sk-ant", rendered)
        self.assertNotIn("/usr/bin", rendered)
        self.assertNotIn("sk-openai", rendered)
        self.assertNotIn("inst-1", rendered)
        self.assertNotIn("mach-1", rendered)
        self.assertNotIn("acct-1", rendered)
        self.assertNotIn("user@example.test", rendered)
        self.assertNotIn("other@example.test", rendered)
        self.assertNotIn(r"C:\Users\example\secret.txt", rendered)
        self.assertNotIn("/home/example/secret.txt", rendered)
        self.assertNotIn(nonce, rendered)
        self.assertEqual(cleaned["Prompt"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["old-string"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["wrapper"]["tool_response"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["wrapper"]["keep_id"], "structural-id")
        self.assertEqual(cleaned["items"][0]["Text"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["items"][1]["keep"], "visible")
        self.assertEqual(cleaned["env"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["environment"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["windows_path"], "[REDACTED_ABSOLUTE_PATH]")
        self.assertEqual(cleaned["posix_path"], "[REDACTED_ABSOLUTE_PATH]")
        self.assertEqual(
            cleaned["note"], "ordinary free text [REDACTED_NONCE]"
        )
        self.assertEqual(cleaned["relative_target"], contract.GOVERNED_PROBE)

    def test_rollback_refuses_relative_and_absolute_escape(self) -> None:
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        with self.assertRaises(Phase13Error):
            apply_rollback(
                {"sandbox_paths": ["../outside"]},
                sandbox_root=self.root,
                dry_run=False,
            )
        with self.assertRaises(Phase13Error):
            apply_rollback(
                {
                    "sandbox_paths": [
                        str(Path(self.temporary.name) / "outside.txt")
                    ]
                },
                sandbox_root=self.root,
                dry_run=False,
            )

    def test_nested_junction_does_not_delete_external_target(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows junction regression requires nt")
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        nest = self.root / "nest"
        nest.mkdir()
        (nest / "own.txt").write_text("sandbox-own", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside-tree"
        (outside / "sub").mkdir(parents=True)
        precious = outside / "precious.txt"
        deep = outside / "sub" / "deep.txt"
        precious.write_text("must-survive", encoding="utf-8")
        deep.write_text("must-survive-deep", encoding="utf-8")
        junction = nest / "nested-junction"
        if not _create_windows_junction(junction, outside):
            self.skipTest("Windows junction creation unavailable")
        self.assertFalse(junction.is_symlink())
        self.assertTrue(junction.is_junction())
        apply_rollback(
            {"sandbox_paths": ["nest"]},
            sandbox_root=self.root,
            dry_run=False,
        )
        self.assertFalse(nest.exists())
        self.assertTrue(precious.is_file())
        self.assertTrue(deep.is_file())
        self.assertEqual(precious.read_text(encoding="utf-8"), "must-survive")
        self.assertEqual(deep.read_text(encoding="utf-8"), "must-survive-deep")

    def test_planned_junction_does_not_traverse_external_target(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows junction regression requires nt")
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        outside = Path(self.temporary.name) / "direct-outside"
        outside.mkdir()
        precious = outside / "precious.txt"
        precious.write_text("must-survive", encoding="utf-8")
        junction = self.root / "direct-junction"
        if not _create_windows_junction(junction, outside):
            self.skipTest("Windows junction creation unavailable")
        self.assertFalse(junction.is_symlink())
        self.assertTrue(junction.is_junction())
        apply_rollback(
            {"sandbox_paths": ["direct-junction"]},
            sandbox_root=self.root,
            dry_run=False,
        )
        self.assertFalse(junction.exists())
        self.assertTrue(precious.is_file())
        self.assertEqual(precious.read_text(encoding="utf-8"), "must-survive")

    def test_ordinary_symlink_is_treated_as_leaf(self) -> None:
        (self.root / contract.SANDBOX_MARKER).write_text("", encoding="utf-8")
        nest = self.root / "nest"
        nest.mkdir()
        (nest / "own.txt").write_text("sandbox-own", encoding="utf-8")
        outside = Path(self.temporary.name) / "symlink-outside"
        outside.mkdir()
        precious = outside / "precious.txt"
        precious.write_text("must-survive", encoding="utf-8")
        link = nest / "nested-link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlink creation unavailable: {error}")
        apply_rollback(
            {"sandbox_paths": ["nest"]},
            sandbox_root=self.root,
            dry_run=False,
        )
        self.assertFalse(nest.exists())
        self.assertTrue(precious.is_file())
        self.assertEqual(precious.read_text(encoding="utf-8"), "must-survive")

    def test_dispatch_verified_requires_dispatch_fields_only(self) -> None:
        record = generate_evidence_record(dispatch_payload())
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["claim"], contract.CLAIM_DISPATCH)
        self.assertNotIn("core_decision", record)
        self.assertNotIn("sanitized_hook_decision", record)
        self.assertNotIn("challenge_nonce_sha256", record)
        self.assertNotIn("tool_use_sha256", record)

    def test_dispatch_rejects_denial_filler(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                dispatch_payload(core_decision="BLOCK", adapter_transport="deny")
            )
        self.assertIn("denial-layer filler", str(ctx.exception))

    def test_dispatch_rejects_missing_capture_bindings(self) -> None:
        for field in (
            "context_payload_sha256",
            "session_sha256",
            "raw_capture_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaises(Phase13Error):
                    generate_evidence_record(dispatch_payload(**{field: None}))
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                dispatch_payload(event_type=contract.CLAUDE_PRETOOL_EVENT)
            )
        self.assertIn("SessionStart", str(ctx.exception))

    def test_injection_verified_requires_enabled_and_control(self) -> None:
        record = generate_evidence_record(injection_payload())
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["claim"], contract.CLAIM_INJECTION)
        self.assertEqual(record["tool_use_count_before_answer"], 0)
        self.assertNotIn("core_decision", record)

    def test_injection_rejects_missing_or_invalid_controls(self) -> None:
        cases = [
            {"enabled_session_sha256": None},
            {"control_session_sha256": None},
            {"enabled_raw_capture_sha256": None},
            {"control_raw_capture_sha256": None},
            {"negative_control_result": None},
            {
                "control_session_sha256": injection_payload()[
                    "enabled_session_sha256"
                ]
            },
            {"enabled_answer_sha256": _hex("not-the-nonce")},
            {"control_answer_sha256": injection_payload()["challenge_nonce_sha256"]},
            {"tool_use_count_before_answer": 1},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(Phase13Error):
                    generate_evidence_record(injection_payload(**overrides))

    def test_denial_verified_requires_proving_tool_and_positive_control(self) -> None:
        record = generate_evidence_record(verified_payload())
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["claim"], contract.CLAIM_DENIAL)
        self.assertNotIn("challenge_nonce_sha256", record)
        self.assertTrue(record["proving_tool_attempted"])
        self.assertEqual(
            record["positive_control_digest_after"],
            sha256_text(contract.POSITIVE_CONTROL_CONTENT),
        )

    def test_positive_control_digest_contract_is_proving_path_specific(self) -> None:
        self.assertEqual(
            positive_control_expected_digest(
                contract.CLAUDE_HARNESS,
                contract.CLAUDE_PROVING_TOOL,
            ),
            "a05884ca9045ba451cdb2e75778d5f9e9b251633890400c647265be431210ef0",
        )
        self.assertEqual(
            positive_control_expected_digest(
                contract.CODEX_HARNESS,
                contract.CODEX_PROVING_TOOL,
            ),
            "154276b4a91b30672508bb653e994be845d993ec069fb31f6becf48184dcef37",
        )
        unsupported_pairs = (
            (contract.CLAUDE_HARNESS, contract.CODEX_PROVING_TOOL),
            (contract.CODEX_HARNESS, contract.CLAUDE_PROVING_TOOL),
            (contract.CLAUDE_HARNESS, "Bash"),
            ("invalid", contract.CLAUDE_PROVING_TOOL),
        )
        for harness, tool in unsupported_pairs:
            with self.subTest(harness=harness, tool=tool):
                with self.assertRaises(Phase13Error):
                    positive_control_expected_digest(harness, tool)

    def test_claude_historical_positive_control_reaches_verified(self) -> None:
        digest = sha256_text("PHASE13")
        record = generate_evidence_record(
            verified_payload(
                positive_control_expected_digest=digest,
                positive_control_digest_after=digest,
            )
        )
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["positive_control_expected_digest"], digest)

    def test_codex_newline_positive_control_reaches_verified(self) -> None:
        digest = sha256_text("PHASE13\n")
        record = generate_evidence_record(
            verified_payload(
                harness_name=contract.CODEX_HARNESS,
                supported_tool_path=contract.CODEX_PROVING_TOOL,
                positive_control_expected_digest=digest,
                positive_control_digest_after=digest,
            )
        )
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["positive_control_tool"], contract.CODEX_PROVING_TOOL)
        self.assertEqual(record["positive_control_expected_digest"], digest)

    def test_codex_rejects_caller_selected_claude_digest(self) -> None:
        caller_selected = sha256_text("PHASE13")
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(
                    harness_name=contract.CODEX_HARNESS,
                    supported_tool_path=contract.CODEX_PROVING_TOOL,
                    positive_control_expected_digest=caller_selected,
                    positive_control_digest_after=caller_selected,
                )
            )

    def test_claude_rejects_caller_selected_codex_digest(self) -> None:
        caller_selected = sha256_text("PHASE13\n")
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(
                    positive_control_expected_digest=caller_selected,
                    positive_control_digest_after=caller_selected,
                )
            )

    def test_accepted_claude_run_3_remains_verified_when_present(self) -> None:
        evidence_path = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "evidence"
            / "phase-13"
            / "claude-run-3-live-mutation-denial.json"
        )
        if not evidence_path.is_file():
            self.skipTest("accepted Claude Run 3 evidence is not present")
        raw = json.loads(evidence_path.read_text(encoding="utf-8"))
        derived = positive_control_expected_digest(
            raw["harness_name"],
            raw["positive_control_tool"],
        )
        self.assertEqual(derived, raw["positive_control_expected_digest"])
        self.assertEqual(derived, raw["positive_control_digest_after"])
        self.assertEqual(generate_evidence_record(raw)["verdict"], "VERIFIED")

    def test_denial_rejects_missing_attempt_and_capture_bindings(self) -> None:
        with self.assertRaises(Phase13Error):
            generate_evidence_record(verified_payload(proving_tool_attempted=False))
        for field in ("tool_use_sha256", "session_sha256", "raw_capture_sha256"):
            with self.subTest(field=field):
                with self.assertRaises(Phase13Error):
                    generate_evidence_record(verified_payload(**{field: None}))

    def test_denial_rejects_invalid_positive_control(self) -> None:
        cases = [
            {"positive_control_existed_before": True},
            {"positive_control_existed_after": False},
            {"positive_control_digest_after": _hex("wrong-bytes")},
            {"positive_control_expected_digest": _hex("wrong-expected")},
            {"positive_control_target": None},
            {"positive_control_tool_attempted": False},
            {"sanitized_hook_decision": {"permissionDecision": "allow"}},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(Phase13Error):
                    generate_evidence_record(verified_payload(**overrides))

    def test_model_only_refusal_cannot_be_verified(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(
                    proving_tool_attempted=False,
                    tool_use_sha256=None,
                )
            )
        self.assertRegex(
            str(ctx.exception),
            r"NOT_COVERED|proving_tool_attempted|tool_use_sha256",
        )

    def test_target_changed_cannot_be_verified(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(
                    target_existed_after=True,
                    target_state="CHANGED",
                )
            )
        self.assertIn("FAILED_OPEN", str(ctx.exception))

    def test_classifier_results_cannot_be_overridden_to_verified(self) -> None:
        cases = [
            (
                "NOT_COVERED",
                verified_payload(proving_tool_attempted=False, tool_use_sha256=None),
            ),
            (
                "INCONCLUSIVE",
                verified_payload(positive_control_existed_after=False),
            ),
            (
                "FAILED",
                verified_payload(
                    core_decision="ALLOW",
                    target_existed_after=True,
                    target_state="CHANGED",
                ),
            ),
            (
                "FAILED_OPEN",
                verified_payload(
                    target_existed_after=True,
                    target_state="CHANGED",
                ),
            ),
            (
                "FAIL_CLOSED_MISATTRIBUTION",
                verified_payload(adapter_exit_code=2),
            ),
        ]
        for derived, payload in cases:
            with self.subTest(derived=derived):
                with self.assertRaises(Phase13Error) as ctx:
                    generate_evidence_record(payload)
                self.assertIn(derived, str(ctx.exception))

    def test_committed_output_contains_digests_not_raw_identifiers(self) -> None:
        session = "cc4b6b42-186d-471e-a7c2-0f60a9cc9300"
        tool = "toolu_01JJvxsnAaqByJ1st8Yow5Dk"
        nonce = "EVIDLINE-P13-TESTONLY-PRIVACY"
        record = generate_evidence_record(
            verified_payload(
                session_id=session,
                tool_use_id=tool,
                session_sha256=None,
                tool_use_sha256=None,
            )
        )
        rendered = json.dumps(record)
        self.assertNotIn(session, rendered)
        self.assertNotIn(tool, rendered)
        self.assertNotIn(nonce, rendered)
        self.assertEqual(record["session_sha256"], sha256_text(session))
        self.assertEqual(record["tool_use_sha256"], sha256_text(tool))
        self.assertNotIn("session_id", record)
        self.assertNotIn("tool_use_id", record)

    def test_operator_summary_does_not_satisfy_verified(self) -> None:
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                {
                    "claim": contract.CLAIM_DISPATCH,
                    "verdict": "VERIFIED",
                    "live_status": "EXECUTED",
                    "operator_summary": "hooks definitely fired",
                    "notes": "VERIFIED because I said so",
                    "harness_name": "claude",
                }
            )

    def test_existing_rejected_claude_artifacts_fail_new_contract(self) -> None:
        evidence_dir = (
            Path(__file__).resolve().parents[1] / "docs" / "evidence" / "phase-13"
        )
        for name in (
            "claude-dispatch.json",
            "claude-injection.json",
            "claude-denial.json",
        ):
            with self.subTest(name=name):
                raw = json.loads((evidence_dir / name).read_text(encoding="utf-8"))
                self.assertEqual(raw["verdict"], "VERIFIED")
                with self.assertRaises(Phase13Error) as ctx:
                    generate_evidence_record(raw)
                self.assertIn("claim", str(ctx.exception).lower())

    def test_sanitize_promotes_session_and_tool_digests(self) -> None:
        cleaned = sanitize_document(
            {
                "session_id": "abc-session",
                "tool_use_id": "toolu_secret",
                "keep": "visible",
            }
        )
        self.assertEqual(cleaned["session_id"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["tool_use_id"], "[REDACTED_FIELD]")
        self.assertEqual(cleaned["session_sha256"], sha256_text("abc-session"))
        self.assertEqual(cleaned["tool_use_sha256"], sha256_text("toolu_secret"))
        self.assertEqual(cleaned["keep"], "visible")

    def test_evidence_cli_derives_capture_digest_without_printing_bytes(self) -> None:
        payload = self.root / "dispatch-in.json"
        payload.write_text(
            json.dumps(dispatch_payload(raw_capture_sha256=None)),
            encoding="utf-8",
        )
        capture = self.root / "raw-stream.jsonl"
        secret = "session_id=must-not-appear-in-output"
        capture.write_text(secret, encoding="utf-8")
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            code = phase13_main(
                [
                    "evidence",
                    "--input",
                    str(payload),
                    "--raw-capture",
                    str(capture),
                ]
            )
        self.assertEqual(code, 0)
        rendered = stdout.getvalue()
        self.assertNotIn(secret, rendered)
        self.assertIn(sha256_file(capture), rendered)

    def test_dispatch_dict_denial_filler_rejects_without_typeerror(self) -> None:
        payload = dispatch_payload(
            sanitized_hook_decision={
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
            }
        )
        try:
            generate_evidence_record(payload)
        except TypeError as error:
            self.fail(f"dict denial filler raised TypeError: {error}")
        except Phase13Error as error:
            self.assertIn("denial-layer filler", str(error))
        else:
            self.fail("dict denial filler on dispatch was accepted")

    def test_injection_dict_denial_filler_rejects_without_typeerror(self) -> None:
        payload = injection_payload(
            sanitized_hook_decision={
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
            }
        )
        try:
            generate_evidence_record(payload)
        except TypeError as error:
            self.fail(f"dict denial filler raised TypeError: {error}")
        except Phase13Error as error:
            self.assertIn("denial-layer filler", str(error))
        else:
            self.fail("dict denial filler on injection was accepted")

    def test_dispatch_empty_denial_filler_values_remain_allowed(self) -> None:
        record = generate_evidence_record(
            dispatch_payload(
                core_decision=None,
                adapter_transport="",
                proving_tool_attempted=False,
            )
        )
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertNotIn("core_decision", record)
        self.assertNotIn("adapter_transport", record)

    def test_cli_dict_denial_filler_uses_contract_diagnostic(self) -> None:
        payload = self.root / "dispatch-dict-filler.json"
        payload.write_text(
            json.dumps(
                dispatch_payload(
                    sanitized_hook_decision={"permissionDecision": "deny"}
                )
            ),
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            code = phase13_main(["evidence", "--input", str(payload)])
        self.assertEqual(code, 1)
        rendered = stderr.getvalue()
        self.assertIn("phase13:", rendered)
        self.assertIn("denial-layer filler", rendered)
        self.assertNotIn("TypeError", rendered)
        self.assertNotIn("Traceback", rendered)

    def test_run1_artifacts_plus_claim_reject_without_crash(self) -> None:
        evidence_dir = (
            Path(__file__).resolve().parents[1] / "docs" / "evidence" / "phase-13"
        )
        cases = (
            ("claude-dispatch.json", contract.CLAIM_DISPATCH),
            ("claude-injection.json", contract.CLAIM_INJECTION),
            ("claude-denial.json", contract.CLAIM_DENIAL),
        )
        for name, claim in cases:
            with self.subTest(name=name, claim=claim):
                path = evidence_dir / name
                original = path.read_bytes()
                raw = json.loads(original.decode("utf-8"))
                raw["claim"] = claim
                try:
                    generate_evidence_record(raw)
                except TypeError as error:
                    self.fail(f"{name} + claim raised TypeError: {error}")
                except Phase13Error:
                    pass
                else:
                    self.fail(f"{name} + claim was accepted as evidence")
                self.assertEqual(path.read_bytes(), original)

    def test_absolute_positive_control_target_cannot_verify(self) -> None:
        for target in (
            "C:/x/probe.txt",
            "C:/outside/governed.txt",
            r"C:\x\probe.txt",
        ):
            with self.subTest(target=target):
                with self.assertRaises(Phase13Error) as ctx:
                    generate_evidence_record(
                        verified_payload(positive_control_target=target)
                    )
                self.assertNotIn("TypeError", type(ctx.exception).__name__)
                self.assertIn("root-relative", str(ctx.exception))

    def test_absolute_relative_target_cannot_verify(self) -> None:
        for target in (
            "C:/x/probe.txt",
            "C:/outside/governed.txt",
            r"C:\outside\governed.txt",
        ):
            with self.subTest(target=target):
                with self.assertRaises(Phase13Error) as ctx:
                    generate_evidence_record(
                        verified_payload(relative_target=target)
                    )
                self.assertIn("root-relative", str(ctx.exception))

    def test_posix_absolute_target_cannot_verify(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(relative_target="/home/user/x.txt")
            )
        self.assertIn("root-relative", str(ctx.exception))
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(positive_control_target="/home/user/x.txt")
            )

    def test_traversal_target_cannot_verify(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(relative_target="../outside/probe.txt")
            )
        self.assertIn("root-relative", str(ctx.exception))
        with self.assertRaises(Phase13Error):
            generate_evidence_record(
                verified_payload(
                    positive_control_target="../outside/probe.txt"
                )
            )

    def test_redacted_absolute_target_token_cannot_verify(self) -> None:
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(relative_target="[REDACTED_ABSOLUTE_PATH]")
            )
        self.assertIn("root-relative", str(ctx.exception))

    def test_valid_root_relative_targets_remain_inspectable(self) -> None:
        record = generate_evidence_record(verified_payload())
        self.assertEqual(record["verdict"], "VERIFIED")
        self.assertEqual(record["relative_target"], contract.GOVERNED_PROBE)
        self.assertEqual(record["positive_control_target"], contract.ALLOWED_PROBE)
        self.assertNotEqual(record["relative_target"], "[REDACTED_ABSOLUTE_PATH]")
        self.assertNotEqual(
            record["positive_control_target"], "[REDACTED_ABSOLUTE_PATH]"
        )

    def test_raw_session_id_in_notes_is_absent_from_sanitized_output(self) -> None:
        session = "sess-REALID-12345"
        tool = "toolu_X"
        record = generate_evidence_record(
            verified_payload(
                session_id=session,
                tool_use_id=tool,
                session_sha256=None,
                tool_use_sha256=None,
                notes=f"run used session {session} tool {tool}",
            )
        )
        rendered = json.dumps(record)
        self.assertNotIn(session, rendered)
        self.assertNotIn(tool, rendered)
        self.assertEqual(record["session_sha256"], sha256_text(session))
        self.assertEqual(record["tool_use_sha256"], sha256_text(tool))
        self.assertIn(record["session_sha256"], rendered)
        self.assertIn(record["tool_use_sha256"], rendered)

    def test_raw_tool_use_id_in_operator_summary_is_absent(self) -> None:
        session = "sess-REALID-12345"
        tool = "toolu_X"
        record = generate_evidence_record(
            verified_payload(
                session_id=session,
                tool_use_id=tool,
                session_sha256=None,
                tool_use_sha256=None,
                operator_summary=f"run used session {session} tool {tool}",
            )
        )
        rendered = json.dumps(record)
        self.assertNotIn(session, rendered)
        self.assertNotIn(tool, rendered)
        self.assertEqual(record["session_sha256"], sha256_text(session))
        self.assertEqual(record["tool_use_sha256"], sha256_text(tool))

    def test_raw_identifiers_in_nested_notes_are_absent(self) -> None:
        session = "sess-REALID-12345"
        tool = "toolu_X"
        record = generate_evidence_record(
            verified_payload(
                session_id=session,
                tool_use_id=tool,
                session_sha256=None,
                tool_use_sha256=None,
                notes={
                    "detail": f"run used session {session}",
                    "items": [f"tool {tool}"],
                },
            )
        )
        rendered = json.dumps(record)
        self.assertNotIn(session, rendered)
        self.assertNotIn(tool, rendered)
        self.assertEqual(record["session_sha256"], sha256_text(session))
        self.assertEqual(record["tool_use_sha256"], sha256_text(tool))
        self.assertIn(record["session_sha256"], rendered)

    def test_identifier_redaction_preserves_nonce_and_path_behavior(self) -> None:
        session = "sess-REALID-12345"
        nonce = "EVIDLINE-P13-TESTONLY-ID-REDACT"
        cleaned = sanitize_document(
            {
                "session_id": session,
                "note": f"session {session} nonce={nonce} path=/home/user/x.txt",
                "relative_target": contract.GOVERNED_PROBE,
            },
            nonce=nonce,
        )
        rendered = json.dumps(cleaned)
        self.assertNotIn(session, rendered)
        self.assertNotIn(nonce, rendered)
        self.assertNotIn("/home/user/x.txt", rendered)
        self.assertIn("[REDACTED_NONCE]", cleaned["note"])
        self.assertIn("[REDACTED_ABSOLUTE_PATH]", cleaned["note"])
        self.assertEqual(cleaned["relative_target"], contract.GOVERNED_PROBE)
        self.assertEqual(cleaned["session_sha256"], sha256_text(session))
        self.assertIn(cleaned["session_sha256"], rendered)

    def test_not_executed_harness_result_cannot_be_verified(self) -> None:
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="DENIED",
                target_changed=False,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "VERIFIED",
        )
        self.assertEqual(
            classify_denial(
                core_decision="BLOCK",
                adapter_transport="deny",
                harness_tool_result="NOT_EXECUTED",
                target_changed=False,
                positive_control_succeeded=True,
                selected_tool_used=True,
            ),
            "INCONCLUSIVE",
        )
        with self.assertRaises(Phase13Error) as ctx:
            generate_evidence_record(
                verified_payload(harness_tool_result="NOT_EXECUTED")
            )
        self.assertIn("INCONCLUSIVE", str(ctx.exception))
        self.assertNotIn("VERIFIED", generate_evidence_record(
            verified_payload(
                verdict="INCONCLUSIVE",
                harness_tool_result="NOT_EXECUTED",
            )
        )["verdict"])
        record = generate_evidence_record(
            verified_payload(
                verdict="INCONCLUSIVE",
                harness_tool_result="NOT_EXECUTED",
            )
        )
        self.assertEqual(record["verdict"], "INCONCLUSIVE")
        denied = generate_evidence_record(verified_payload())
        self.assertEqual(denied["verdict"], "VERIFIED")


def _create_windows_junction(link: Path, target: Path) -> bool:
    completed = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0 and link.exists()


if __name__ == "__main__":
    unittest.main()
