from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from evidline import paths
from evidline.state import (
    Claim,
    ClaimFreshness,
    Evidence,
    EvidenceProvenance,
    Execution,
    Project,
    StateDocument,
    Verification,
    VerifierRule,
)
from evidline.verification import (
    VerificationInputError,
    VerificationReason,
    verify_claim,
    verify_evidence,
)


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


class VerificationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.sandbox = Path(self.temporary.name)
        self.root = self.sandbox / "project"
        self.root.mkdir()
        (self.root / ".evidline").mkdir()

    def evidence(
        self,
        evidence_id: str = "evidence-1",
        *,
        source_path: object = None,
        digest: object = None,
    ) -> Evidence:
        return Evidence(
            id=evidence_id,
            description="Synthetic evidence",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path=source_path,  # type: ignore[arg-type]
            digest=digest,  # type: ignore[arg-type]
        )

    def bound_evidence(
        self,
        evidence_id: str,
        source_path: str,
        data: bytes,
        *,
        expected: bytes | None = None,
    ) -> Evidence:
        target = self.root / source_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return self.evidence(
            evidence_id,
            source_path=source_path,
            digest=_digest(data if expected is None else expected),
        )

    def claim(
        self,
        evidence_ids: tuple[str, ...],
        **changes: object,
    ) -> Claim:
        claim = Claim(
            id="claim-1",
            description="Synthetic byte-binding claim",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=evidence_ids,
        )
        return replace(claim, **changes)

    def state(self, evidence: tuple[Evidence, ...]) -> StateDocument:
        return StateDocument(
            schema_version=4,
            revision=7,
            project=Project("project", "Verification tests", (), 8000),
            invariants=(),
            decisions=(),
            tasks=(),
            claims=(),
            evidence=evidence,
            counters={},
            scope_semantics=paths.host_scope_semantics(),
        )

    def assert_result(
        self,
        result: object,
        verification: Verification,
        reason: VerificationReason,
    ) -> None:
        self.assertEqual(result.verification, verification)  # type: ignore[attr-defined]
        self.assertEqual(result.reason, reason)  # type: ignore[attr-defined]


class EvidenceVerificationTests(VerificationTestCase):
    def test_binding_absent(self) -> None:
        self.assert_result(
            verify_evidence(self.root, self.evidence()),
            Verification.UNVERIFIED,
            VerificationReason.BINDING_ABSENT,
        )

    def test_digest_without_source(self) -> None:
        self.assert_result(
            verify_evidence(self.root, self.evidence(digest=_digest(b"x"))),
            Verification.UNVERIFIED,
            VerificationReason.BINDING_DIGEST_WITHOUT_SOURCE,
        )

    def test_source_without_digest(self) -> None:
        self.assert_result(
            verify_evidence(self.root, self.evidence(source_path="source.bin")),
            Verification.UNVERIFIED,
            VerificationReason.BINDING_SOURCE_WITHOUT_DIGEST,
        )

    def test_malformed_digest_forms(self) -> None:
        malformed = (
            "sha256:" + "A" * 64,
            "sha256:" + "a" * 63,
            "sha512:" + "a" * 64,
            "sha256:" + "g" * 64,
            1,
        )
        for digest in malformed:
            with self.subTest(digest=digest):
                result = verify_evidence(
                    self.root,
                    self.evidence(source_path="source.bin", digest=digest),
                )
                self.assert_result(
                    result,
                    Verification.UNVERIFIED,
                    VerificationReason.DIGEST_MALFORMED,
                )

    def test_matching_text_empty_and_binary_bytes(self) -> None:
        cases = (
            ("src/text.txt", b"plain text\n"),
            ("src/empty.bin", b""),
            ("src/binary.bin", b"\x00\xff\x10binary\x00"),
        )
        for index, (source_path, data) in enumerate(cases):
            with self.subTest(source_path=source_path):
                evidence = self.bound_evidence(
                    f"evidence-{index}", source_path, data
                )
                self.assert_result(
                    verify_evidence(self.root, evidence),
                    Verification.VERIFIED,
                    VerificationReason.DIGEST_MATCH,
                )

    def test_one_byte_mismatch(self) -> None:
        evidence = self.bound_evidence(
            "evidence-mismatch", "src/value.bin", b"value-2", expected=b"value-1"
        )
        self.assert_result(
            verify_evidence(self.root, evidence),
            Verification.FAILED,
            VerificationReason.DIGEST_MISMATCH,
        )

    def test_raw_bytes_are_not_normalized_or_canonicalized(self) -> None:
        cases = (
            ("src/newlines.txt", b"line\r\n", b"line\n"),
            ("src/space.txt", b"value \n", b"value\n"),
            ("src/value.json", b'{"a": 1}\n', b'{"a":1}\n'),
        )
        for index, (source_path, actual, expected) in enumerate(cases):
            with self.subTest(source_path=source_path):
                evidence = self.bound_evidence(
                    f"evidence-raw-{index}",
                    source_path,
                    actual,
                    expected=expected,
                )
                self.assert_result(
                    verify_evidence(self.root, evidence),
                    Verification.FAILED,
                    VerificationReason.DIGEST_MISMATCH,
                )

    def test_missing_source(self) -> None:
        result = verify_evidence(
            self.root,
            self.evidence(
                source_path="src/missing.bin",
                digest=_digest(b"missing"),
            ),
        )
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.SOURCE_MISSING,
        )

    def test_directory_source(self) -> None:
        (self.root / "src").mkdir()
        result = verify_evidence(
            self.root,
            self.evidence(source_path="src", digest=_digest(b"")),
        )
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.SOURCE_IS_DIRECTORY,
        )

    def test_unreadable_source(self) -> None:
        evidence = self.bound_evidence("evidence-1", "src/value.bin", b"value")
        with mock.patch(
            "evidline.verification.open",
            side_effect=PermissionError("denied"),
            create=True,
        ):
            result = verify_evidence(self.root, evidence)
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.SOURCE_UNREADABLE,
        )

    def test_open_or_read_os_error_is_read_failed(self) -> None:
        evidence = self.bound_evidence("evidence-1", "src/value.bin", b"value")
        with mock.patch(
            "evidline.verification.open",
            side_effect=OSError("read failed"),
            create=True,
        ):
            result = verify_evidence(self.root, evidence)
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.SOURCE_READ_FAILED,
        )

    def test_bounded_internal_error_is_verifier_error(self) -> None:
        evidence = self.bound_evidence("evidence-1", "src/value.bin", b"value")
        with mock.patch(
            "evidline.verification.os.stat",
            side_effect=RuntimeError("internal"),
        ):
            result = verify_evidence(self.root, evidence)
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.VERIFIER_ERROR,
        )

    def test_wrong_top_level_types_raise_input_error(self) -> None:
        with self.assertRaises(VerificationInputError):
            verify_evidence(self.root, object())  # type: ignore[arg-type]
        with self.assertRaises(VerificationInputError):
            verify_evidence(object(), self.evidence())  # type: ignore[arg-type]


class PathSecurityVerificationTests(VerificationTestCase):
    def assert_unsafe(
        self,
        source_path: str,
        reason: VerificationReason,
    ) -> None:
        result = verify_evidence(
            self.root,
            self.evidence(source_path=source_path, digest=_digest(b"value")),
        )
        self.assertIsNot(result.verification, Verification.VERIFIED)
        self.assertEqual(result.reason, reason)

    def test_absolute_and_parent_traversal_sources_are_invalid(self) -> None:
        for source_path in (str(self.sandbox / "outside.bin"), "../outside.bin"):
            with self.subTest(source_path=source_path):
                self.assert_unsafe(
                    source_path,
                    VerificationReason.SOURCE_PATH_INVALID,
                )

    def test_root_source_is_unsafe_after_grammar_validation(self) -> None:
        self.assert_unsafe(".", VerificationReason.SOURCE_UNSAFE)

    def test_protected_metadata_sources_are_unsafe(self) -> None:
        (self.root / ".git").mkdir()
        for source_path in (".git/config", ".evidline/state.json"):
            with self.subTest(source_path=source_path):
                self.assert_unsafe(source_path, VerificationReason.SOURCE_UNSAFE)

    def test_out_of_root_resolution_is_unsafe(self) -> None:
        outside = self.sandbox / "outside"
        outside.mkdir()
        link = self.root / "outside-link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self.assert_unsafe("outside-link/value.bin", VerificationReason.SOURCE_UNSAFE)

    def test_symlink_file_escape_is_unsafe(self) -> None:
        outside = self.sandbox / "outside.bin"
        outside.write_bytes(b"value")
        link = self.root / "escape.bin"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self.assert_unsafe("escape.bin", VerificationReason.SOURCE_UNSAFE)

    @unittest.skipUnless(os.name == "nt", "Windows-only junction behavior")
    def test_junction_escape_is_unsafe(self) -> None:
        outside = self.sandbox / "junction-outside"
        outside.mkdir()
        link = self.root / "junction-escape"
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.skipTest(
                f"junction creation unavailable: {completed.stderr.strip()}"
            )
        self.assert_unsafe("junction-escape/value.bin", VerificationReason.SOURCE_UNSAFE)

    def test_unsafe_windows_form_is_invalid_under_folded_semantics(self) -> None:
        if paths.host_scope_semantics() is not paths.ScopePathSemantics.CASE_FOLDED:
            self.skipTest("host does not use CASE_FOLDED path semantics")
        self.assert_unsafe("CON", VerificationReason.SOURCE_PATH_INVALID)

    @unittest.skipUnless(
        os.name != "nt" and hasattr(os, "mkfifo"),
        "FIFO creation unavailable",
    )
    def test_fifo_is_not_a_regular_file(self) -> None:
        fifo = self.root / "source.fifo"
        os.mkfifo(fifo)
        self.assert_unsafe(
            "source.fifo",
            VerificationReason.SOURCE_NOT_REGULAR_FILE,
        )


class ClaimVerificationTests(VerificationTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.verified = self.bound_evidence(
            "evidence-verified", "src/verified.bin", b"verified"
        )
        self.failed = self.bound_evidence(
            "evidence-failed",
            "src/failed.bin",
            b"different",
            expected=b"expected",
        )
        self.unverified = self.evidence("evidence-unverified")

    def verify(
        self,
        evidence: tuple[Evidence, ...],
        evidence_ids: tuple[str, ...],
        **claim_changes: object,
    ) -> object:
        return verify_claim(
            self.root,
            self.state(evidence),
            self.claim(evidence_ids, **claim_changes),
        )

    def test_not_reproducible_and_no_evidence(self) -> None:
        self.assert_result(
            self.verify((self.verified,), ("evidence-verified",), reproducible=False),
            Verification.UNVERIFIED,
            VerificationReason.CLAIM_NOT_REPRODUCIBLE,
        )
        self.assert_result(
            self.verify((), ()),
            Verification.UNVERIFIED,
            VerificationReason.CLAIM_NO_EVIDENCE,
        )

    def test_missing_evidence_id(self) -> None:
        self.assert_result(
            self.verify((), ("evidence-missing",)),
            Verification.UNVERIFIED,
            VerificationReason.CLAIM_EVIDENCE_UNRESOLVED,
        )

    def test_wrong_evidence_ids_field_fails_closed(self) -> None:
        claim = replace(
            self.claim(("evidence-verified",)),
            evidence_ids=1,  # type: ignore[arg-type]
        )
        result = verify_claim(
            self.root,
            self.state((self.verified,)),
            claim,
        )
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.CLAIM_EVIDENCE_UNRESOLVED,
        )

    def test_one_or_multiple_verified_evidence(self) -> None:
        second = self.bound_evidence(
            "evidence-second", "src/second.bin", b"second"
        )
        for evidence, ids in (
            ((self.verified,), ("evidence-verified",)),
            (
                (self.verified, second),
                ("evidence-verified", "evidence-second"),
            ),
        ):
            with self.subTest(ids=ids):
                self.assert_result(
                    self.verify(evidence, ids),
                    Verification.VERIFIED,
                    VerificationReason.ALL_EVIDENCE_VERIFIED,
                )

    def test_verified_plus_unverified(self) -> None:
        self.assert_result(
            self.verify(
                (self.verified, self.unverified),
                ("evidence-verified", "evidence-unverified"),
            ),
            Verification.UNVERIFIED,
            VerificationReason.EVIDENCE_UNVERIFIED,
        )

    def test_failed_precedence_combinations(self) -> None:
        cases = (
            (
                (self.verified, self.failed),
                ("evidence-verified", "evidence-failed"),
            ),
            (
                (self.failed, self.unverified),
                ("evidence-failed", "evidence-unverified"),
            ),
            (
                (self.failed,),
                ("evidence-missing", "evidence-failed"),
            ),
        )
        for evidence, ids in cases:
            with self.subTest(ids=ids):
                self.assert_result(
                    self.verify(evidence, ids),
                    Verification.FAILED,
                    VerificationReason.EVIDENCE_FAILED,
                )

    def test_multiple_failed_evidence(self) -> None:
        second = self.bound_evidence(
            "evidence-failed-2",
            "src/failed-2.bin",
            b"two",
            expected=b"expected-two",
        )
        self.assert_result(
            self.verify(
                (self.failed, second),
                ("evidence-failed", "evidence-failed-2"),
            ),
            Verification.FAILED,
            VerificationReason.EVIDENCE_FAILED,
        )

    def test_historical_verifying_ids_do_not_narrow_fresh_evidence(self) -> None:
        result = self.verify(
            (self.verified, self.failed),
            ("evidence-verified", "evidence-failed"),
            verifier_rule=VerifierRule.R1_DIGEST_MATCH,
            verified_at="2026-08-17T00:00:00+04:00",
            verifying_evidence_ids=("evidence-verified",),
        )
        self.assert_result(
            result,
            Verification.FAILED,
            VerificationReason.EVIDENCE_FAILED,
        )

    def test_historical_rule_presence_does_not_gate_fresh_result(self) -> None:
        for verifier_rule in (None, VerifierRule.R1_DIGEST_MATCH):
            with self.subTest(verifier_rule=verifier_rule):
                self.assert_result(
                    self.verify(
                        (self.verified,),
                        ("evidence-verified",),
                        verifier_rule=verifier_rule,
                    ),
                    Verification.VERIFIED,
                    VerificationReason.ALL_EVIDENCE_VERIFIED,
                )

    def test_persisted_failed_provenance_does_not_gate_fresh_result(self) -> None:
        self.assert_result(
            self.verify(
                (self.verified,),
                ("evidence-verified",),
                verification=Verification.FAILED,
                verifier_rule=VerifierRule.R1_DIGEST_MATCH,
                verified_at="2026-08-17T00:00:00+04:00",
                verifying_evidence_ids=("evidence-verified",),
            ),
            Verification.VERIFIED,
            VerificationReason.ALL_EVIDENCE_VERIFIED,
        )

    def test_foreign_scope_semantics_fails_closed(self) -> None:
        foreign = (
            paths.ScopePathSemantics.CASE_SENSITIVE
            if paths.host_scope_semantics() is paths.ScopePathSemantics.CASE_FOLDED
            else paths.ScopePathSemantics.CASE_FOLDED
        )
        state = replace(
            self.state((self.verified,)),
            scope_semantics=foreign,
        )
        result = verify_claim(
            self.root,
            state,
            self.claim(("evidence-verified",)),
        )
        self.assert_result(
            result,
            Verification.UNVERIFIED,
            VerificationReason.SCOPE_SEMANTICS_INCOMPATIBLE,
        )

    def test_claim_description_is_not_inspected(self) -> None:
        class ExplodingDescription:
            def __str__(self) -> str:
                raise AssertionError("claim prose was inspected")

        result = self.verify(
            (self.verified,),
            ("evidence-verified",),
            description=ExplodingDescription(),
        )
        self.assert_result(
            result,
            Verification.VERIFIED,
            VerificationReason.ALL_EVIDENCE_VERIFIED,
        )

    def test_freshness_classes_do_not_gate_or_change_freshness(self) -> None:
        for freshness in ClaimFreshness:
            with self.subTest(freshness=freshness):
                claim = self.claim(
                    ("evidence-verified",),
                    freshness=freshness,
                )
                result = verify_claim(
                    self.root,
                    self.state((self.verified,)),
                    claim,
                )
                self.assert_result(
                    result,
                    Verification.VERIFIED,
                    VerificationReason.ALL_EVIDENCE_VERIFIED,
                )
                self.assertIs(claim.freshness, freshness)

    def test_verification_has_no_state_or_source_side_effects(self) -> None:
        state = self.state((self.verified,))
        claim = self.claim(("evidence-verified",))
        source = self.root / "src" / "verified.bin"
        state_path = self.root / ".evidline" / "state.json"
        state_path.write_bytes(b'{"revision": 7}\n')
        state_before = copy.deepcopy(state)
        claim_before = copy.deepcopy(claim)
        evidence_before = copy.deepcopy(self.verified)
        source_before = source.read_bytes()
        state_bytes_before = state_path.read_bytes()

        result = verify_claim(self.root, state, claim)

        self.assert_result(
            result,
            Verification.VERIFIED,
            VerificationReason.ALL_EVIDENCE_VERIFIED,
        )
        self.assertEqual(source.read_bytes(), source_before)
        self.assertEqual(state, state_before)
        self.assertEqual(claim, claim_before)
        self.assertEqual(self.verified, evidence_before)
        self.assertEqual(state_path.read_bytes(), state_bytes_before)
        self.assertEqual(state.revision, 7)

    def test_wrong_top_level_types_raise_input_error(self) -> None:
        state = self.state((self.verified,))
        claim = self.claim(("evidence-verified",))
        with self.assertRaises(VerificationInputError):
            verify_claim(self.root, object(), claim)  # type: ignore[arg-type]
        with self.assertRaises(VerificationInputError):
            verify_claim(self.root, state, object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
