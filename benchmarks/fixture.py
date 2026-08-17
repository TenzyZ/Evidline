"""Disposable deterministic fixture for the synthetic benchmark."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import tempfile
from typing import Any

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
    Task,
    TaskStatus,
    Verification,
    serialize_state,
    validate_state,
)


APPROVED_AT = "2026-08-17T00:00:00+04:00"
APPROVAL_CHANNEL = "phase-7-fixture"
VERIFIED_SOURCE_BYTES = b"VERIFIED = True\n"
MISMATCHED_SOURCE_BYTES = b"ACTUAL = 'different'\n"
EMPTY_SOURCE_BYTES = b""
BINARY_SOURCE_BYTES = b"\x00\xff\x10evidline\x00"
VERIFIED_SOURCE_DIGEST = (
    "sha256:8f8551a931f842c9b5c6f45860b02ae935c0d62254223e4d91cfba1d03a165e8"
)
MISMATCH_EXPECTED_DIGEST = (
    "sha256:fb0b29f79a6c00620b0ce04134c44172c04a7881815fff5b97ae5264bc8289de"
)
EMPTY_SOURCE_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
BINARY_SOURCE_DIGEST = (
    "sha256:04166a656a4f859ecc91d52208afc20b22f26d39e02947aaeb0c486e1e1a9086"
)


class SandboxContainmentError(RuntimeError):
    """A benchmark path escaped the disposable sandbox."""


def _contains(base: Path, candidate: Path) -> bool:
    base_text = os.path.normcase(os.path.realpath(base, strict=False))
    candidate_text = os.path.normcase(os.path.realpath(candidate, strict=False))
    try:
        return os.path.commonpath((base_text, candidate_text)) == base_text
    except ValueError:
        return False


def build_state() -> StateDocument:
    """Return the fixed valid state used by every fresh fixture."""

    evidence = (
        Evidence(
            id="evidence-direct",
            description="Direct synthetic benchmark observation",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
        ),
        Evidence(
            id="evidence-tool",
            description="Tool output for synthetic benchmark digest",
            provenance=EvidenceProvenance.TOOL_OUTPUT,
            execution=Execution.EXECUTED,
        ),
        Evidence(
            id="evidence-agent",
            description="Agent assertion requiring independent verification",
            provenance=EvidenceProvenance.AGENT_ASSERTION,
            execution=Execution.NOT_RUN,
        ),
        Evidence(
            id="evidence-failed",
            description="Failed synthetic benchmark evidence",
            provenance=EvidenceProvenance.TOOL_OUTPUT,
            execution=Execution.FAILED,
        ),
    )
    claims = (
        Claim(
            id="claim-durable",
            description="Synthetic benchmark architecture is local first",
            freshness=ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
            verification=Verification.UNVERIFIED,
            reproducible=False,
        ),
        Claim(
            id="claim-volatile",
            description="Synthetic benchmark working state is current",
            freshness=ClaimFreshness.PERSISTED_VOLATILE,
            verification=Verification.UNVERIFIED,
            reproducible=False,
        ),
        Claim(
            id="claim-digest",
            description="Synthetic benchmark fixture digest matches",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=("evidence-tool",),
        ),
        Claim(
            id="claim-failed",
            description="Synthetic benchmark failed verification must revalidate",
            freshness=ClaimFreshness.DURABLE_UNTIL_SUPERSEDED,
            verification=Verification.FAILED,
            reproducible=False,
            evidence_ids=("evidence-agent",),
        ),
        Claim(
            id="claim-high-support",
            description="Synthetic benchmark high risk support",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=("evidence-direct",),
        ),
        Claim(
            id="claim-high-failed",
            description="Synthetic benchmark failed high risk support",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=("evidence-failed",),
        ),
    )
    state = StateDocument(
        schema_version=4,
        revision=7,
        project=Project(
            name="Evidline synthetic benchmark",
            purpose="Measure deterministic cross-harness behavior",
            ignore_globs=("*.pyc",),
            default_budget_chars=12000,
        ),
        invariants=(
            Invariant(
                id="inv-block",
                description="Block asserted unsupported synthetic architecture changes",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
            ),
            Invariant(
                id="inv-advise",
                description="Advise on synthetic benchmark documentation",
                enforcement=InvariantEnforcement.ADVISE,
                status=InvariantStatus.ACTIVE,
            ),
            Invariant(
                id="inv-current",
                description="Current synthetic benchmark invariant",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.ACTIVE,
            ),
            Invariant(
                id="inv-superseded",
                description="Superseded synthetic benchmark invariant",
                enforcement=InvariantEnforcement.BLOCK,
                status=InvariantStatus.SUPERSEDED,
                superseded_by="inv-current",
                approved_at=APPROVED_AT,
                approval_channel=APPROVAL_CHANNEL,
                asserted_actor="human",
            ),
        ),
        decisions=(
            Decision(
                id="dec-authorized",
                description="Authorize the synthetic benchmark phase",
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                approved_at=APPROVED_AT,
                approval_channel=APPROVAL_CHANNEL,
                asserted_actor="human",
            ),
            Decision(
                id="dec-denied",
                description="Deny live benchmark activation",
                intent=Intent.DENIED,
                execution=Execution.BLOCKED,
            ),
            Decision(
                id="dec-proposed",
                description="Propose future benchmark expansion",
                intent=Intent.PROPOSED,
                execution=Execution.NOT_RUN,
            ),
        ),
        tasks=(
            Task(
                id="task-active",
                description="Implement synthetic cross harness benchmark",
                status=TaskStatus.ACTIVE,
                intent=Intent.AUTHORIZED,
                execution=Execution.NOT_RUN,
                related_ids=(
                    "dec-authorized",
                    "claim-durable",
                    "claim-volatile",
                    "claim-digest",
                    "claim-failed",
                    "claim-high-support",
                    "claim-high-failed",
                    "task-done",
                ),
                approved_at=APPROVED_AT,
                approval_channel=APPROVAL_CHANNEL,
                asserted_actor="human",
            ),
            Task(
                id="task-done",
                description="Preserve synthetic benchmark continuity",
                status=TaskStatus.DONE,
                intent=Intent.AUTHORIZED,
                execution=Execution.EXECUTED,
            ),
            Task(
                id="task-draft",
                description="Draft live benchmark activation",
                status=TaskStatus.DRAFT,
                intent=Intent.PROPOSED,
                execution=Execution.NOT_RUN,
            ),
        ),
        claims=claims,
        evidence=evidence,
        counters={"claim": len(claims), "evidence": len(evidence)},
    )
    validate_state(state)
    return state


def build_verification_state() -> StateDocument:
    """Return isolated records for the Phase 9B library verifier scenarios."""

    evidence = (
        Evidence(
            id="evidence-verify-good",
            description="Deterministic matching verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path="src/verified.py",
            digest=VERIFIED_SOURCE_DIGEST,
        ),
        Evidence(
            id="evidence-verify-failed",
            description="Deterministic mismatching verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path="src/mismatched.py",
            digest=MISMATCH_EXPECTED_DIGEST,
        ),
        Evidence(
            id="evidence-verify-missing",
            description="Deterministic missing verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path="src/missing.py",
            digest=VERIFIED_SOURCE_DIGEST,
        ),
        Evidence(
            id="evidence-verify-protected",
            description="Protected verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path=".evidline/state.json",
            digest=VERIFIED_SOURCE_DIGEST,
        ),
        Evidence(
            id="evidence-verify-empty",
            description="Deterministic empty verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path="src/empty.bin",
            digest=EMPTY_SOURCE_DIGEST,
        ),
        Evidence(
            id="evidence-verify-binary",
            description="Deterministic binary verification source",
            provenance=EvidenceProvenance.DIRECT_OBSERVATION,
            execution=Execution.EXECUTED,
            source_path="src/binary.bin",
            digest=BINARY_SOURCE_DIGEST,
        ),
    )
    claims = (
        Claim(
            id="claim-verify-good",
            description="All current byte bindings reproduce",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=(
                "evidence-verify-good",
                "evidence-verify-empty",
                "evidence-verify-binary",
            ),
        ),
        Claim(
            id="claim-verify-failed-precedence",
            description="A mismatch outranks an unverifiable binding",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=(
                "evidence-verify-missing",
                "evidence-verify-failed",
            ),
        ),
        Claim(
            id="claim-verify-unverified-precedence",
            description="An unverifiable binding prevents verification",
            freshness=ClaimFreshness.DIGEST_BOUND,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=(
                "evidence-verify-good",
                "evidence-verify-missing",
            ),
        ),
        Claim(
            id="claim-verify-volatile",
            description="Freshness is orthogonal to byte reproduction",
            freshness=ClaimFreshness.PERSISTED_VOLATILE,
            verification=Verification.UNVERIFIED,
            reproducible=True,
            evidence_ids=("evidence-verify-good",),
        ),
    )
    state = StateDocument(
        schema_version=4,
        revision=11,
        project=Project(
            name="Evidline verification benchmark",
            purpose="Measure deterministic library verification",
            ignore_globs=(),
            default_budget_chars=12000,
        ),
        invariants=(),
        decisions=(),
        tasks=(),
        claims=claims,
        evidence=evidence,
        counters={"claim": len(claims), "evidence": len(evidence)},
    )
    validate_state(state)
    return state


@dataclass(slots=True)
class BenchmarkFixture:
    """One independently located benchmark fixture."""

    _temporary: tempfile.TemporaryDirectory[str]
    sandbox: Path
    root: Path
    outside: Path
    no_root: Path
    state: StateDocument
    verification_state: StateDocument

    @classmethod
    def create(cls) -> "BenchmarkFixture":
        temporary = tempfile.TemporaryDirectory()
        sandbox = Path(temporary.name)
        root = sandbox / "project"
        outside = sandbox / "outside.py"
        no_root = sandbox / "uninitialized" / "nested"
        fixture = cls(
            temporary,
            sandbox,
            root,
            outside,
            no_root,
            build_state(),
            build_verification_state(),
        )
        try:
            fixture._materialize()
        except Exception:
            temporary.cleanup()
            raise
        return fixture

    def close(self) -> None:
        self._temporary.cleanup()

    def __enter__(self) -> "BenchmarkFixture":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def assert_sandbox_path(self, path: Path) -> Path:
        if not _contains(self.sandbox, path):
            raise SandboxContainmentError("benchmark path escaped disposable sandbox")
        return path

    def target(self, relative: str) -> Path:
        return self.assert_sandbox_path(self.root / relative)

    def write_state(self, state: StateDocument | None = None) -> None:
        document = self.state if state is None else state
        state_path = self.target(".evidline/state.json")
        state_path.write_text(serialize_state(document), encoding="utf-8")

    def write_invalid_state(self) -> None:
        self.target(".evidline/state.json").write_text("{invalid\n", encoding="utf-8")

    def remove_state(self) -> None:
        self.target(".evidline/state.json").unlink()

    def state_without_active_task(self) -> StateDocument:
        tasks = tuple(
            replace(task, status=TaskStatus.DONE)
            if task.status is TaskStatus.ACTIVE
            else task
            for task in self.state.tasks
        )
        return replace(self.state, tasks=tasks)

    def normalize(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, tuple):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            root = os.path.realpath(self.root, strict=False)
            sandbox = os.path.realpath(self.sandbox, strict=False)
            return (
                value.replace(root, "<root>")
                .replace(sandbox, "<sandbox>")
                .replace("\\", "/")
            )
        return value

    def _materialize(self) -> None:
        repository = Path.cwd().resolve()
        if _contains(self.sandbox, repository):
            raise SandboxContainmentError("real repository is inside benchmark sandbox")
        for directory in (
            self.root / ".evidline",
            self.root / ".git",
            self.root / "src" / ".git",
            self.root / "src" / "governed",
            self.root / "docs",
            self.no_root,
        ):
            self.assert_sandbox_path(directory).mkdir(parents=True, exist_ok=True)
        files = {
            self.outside: "outside = True\n",
            self.root / ".git" / "config": "[core]\n\trepositoryformatversion = 0\n",
            self.root / "src" / "app.py": "VALUE = 1\n",
            self.root / "src" / "governed" / "app.py": "VALUE = 1\n",
            self.root / "src" / ".git" / "hook": "synthetic hook target\n",
            self.root / "docs" / "note.md": "Synthetic benchmark note.\n",
        }
        for path, text in files.items():
            self.assert_sandbox_path(path).write_text(text, encoding="utf-8")
        verification_files = {
            self.root / "src" / "verified.py": VERIFIED_SOURCE_BYTES,
            self.root / "src" / "mismatched.py": MISMATCHED_SOURCE_BYTES,
            self.root / "src" / "empty.bin": EMPTY_SOURCE_BYTES,
            self.root / "src" / "binary.bin": BINARY_SOURCE_BYTES,
        }
        for path, data in verification_files.items():
            self.assert_sandbox_path(path).write_bytes(data)
        self.write_state()
