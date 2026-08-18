"""Ephemeral reproduction of persisted evidence byte bindings.

The verifier reuses Evidline's existing path grammar and canonical containment
checks.  The ``stat -> open -> fstat`` sequence does not eliminate replacement
races, and this module claims neither TOCTOU nor hardlink protection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import stat
from types import MappingProxyType
from typing import Final, Mapping

from evidline import paths
from evidline import state as _state
from evidline.state import Claim, Evidence, StateDocument, Verification


_READ_CHUNK_BYTES: Final = 65536


class VerificationReason(str, Enum):
    DIGEST_MATCH = "DIGEST_MATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    BINDING_ABSENT = "BINDING_ABSENT"
    BINDING_DIGEST_WITHOUT_SOURCE = "BINDING_DIGEST_WITHOUT_SOURCE"
    BINDING_SOURCE_WITHOUT_DIGEST = "BINDING_SOURCE_WITHOUT_DIGEST"
    DIGEST_MALFORMED = "DIGEST_MALFORMED"
    SOURCE_PATH_INVALID = "SOURCE_PATH_INVALID"
    SOURCE_UNSAFE = "SOURCE_UNSAFE"
    SOURCE_MISSING = "SOURCE_MISSING"
    SOURCE_IS_DIRECTORY = "SOURCE_IS_DIRECTORY"
    SOURCE_NOT_REGULAR_FILE = "SOURCE_NOT_REGULAR_FILE"
    SOURCE_UNREADABLE = "SOURCE_UNREADABLE"
    SOURCE_READ_FAILED = "SOURCE_READ_FAILED"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    SCOPE_SEMANTICS_INCOMPATIBLE = "SCOPE_SEMANTICS_INCOMPATIBLE"
    CLAIM_NOT_REPRODUCIBLE = "CLAIM_NOT_REPRODUCIBLE"
    CLAIM_NO_EVIDENCE = "CLAIM_NO_EVIDENCE"
    CLAIM_EVIDENCE_UNRESOLVED = "CLAIM_EVIDENCE_UNRESOLVED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"
    EVIDENCE_UNVERIFIED = "EVIDENCE_UNVERIFIED"
    ALL_EVIDENCE_VERIFIED = "ALL_EVIDENCE_VERIFIED"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verification: Verification
    reason: VerificationReason
    detail: str = ""


class VerificationInputError(Exception):
    """A caller supplied an argument of the wrong top-level type."""


def _require_project_root(project_root: str | os.PathLike[str]) -> None:
    try:
        root_text = os.fspath(project_root)
    except TypeError as exc:
        raise VerificationInputError("project_root must be a text path") from exc
    if not isinstance(root_text, str):
        raise VerificationInputError("project_root must be a text path")


def _unverified(
    reason: VerificationReason,
    detail: str = "",
) -> VerificationResult:
    return VerificationResult(Verification.UNVERIFIED, reason, detail)


def verify_evidence(
    project_root: str | os.PathLike[str],
    evidence: Evidence,
) -> VerificationResult:
    """Re-read and verify one evidence source without persisting a verdict."""

    if type(evidence) is not Evidence:
        raise VerificationInputError("evidence must be an Evidence record")
    _require_project_root(project_root)

    source_path = evidence.source_path
    digest = evidence.digest
    if source_path is None and digest is None:
        return _unverified(VerificationReason.BINDING_ABSENT)
    if source_path is None:
        return _unverified(VerificationReason.BINDING_DIGEST_WITHOUT_SOURCE)
    if digest is None:
        return _unverified(VerificationReason.BINDING_SOURCE_WITHOUT_DIGEST)
    if type(digest) is not str or _state._DIGEST_PATTERN.fullmatch(digest) is None:
        return _unverified(VerificationReason.DIGEST_MALFORMED)

    try:
        normalized_source = paths.normalize_root_relative_scope(source_path)
    except ValueError as exc:
        return _unverified(VerificationReason.SOURCE_PATH_INVALID, str(exc))
    except (OSError, RuntimeError) as exc:
        return _unverified(VerificationReason.VERIFIER_ERROR, str(exc))
    if normalized_source != source_path:
        return _unverified(
            VerificationReason.SOURCE_PATH_INVALID,
            "source_path is not normalized",
        )

    try:
        evaluation = paths.evaluate_mutation_path(project_root, source_path)
    except (OSError, RuntimeError, ValueError) as exc:
        return _unverified(VerificationReason.VERIFIER_ERROR, str(exc))
    if not evaluation.safe or evaluation.canonical_target is None:
        return _unverified(
            VerificationReason.SOURCE_UNSAFE,
            evaluation.reason or "source path is unsafe",
        )
    target = evaluation.canonical_target

    try:
        target_stat = os.stat(target)
    except (FileNotFoundError, NotADirectoryError) as exc:
        return _unverified(VerificationReason.SOURCE_MISSING, str(exc))
    except PermissionError as exc:
        return _unverified(VerificationReason.SOURCE_UNREADABLE, str(exc))
    except OSError as exc:
        return _unverified(VerificationReason.SOURCE_READ_FAILED, str(exc))
    except (RuntimeError, ValueError) as exc:
        return _unverified(VerificationReason.VERIFIER_ERROR, str(exc))

    if stat.S_ISDIR(target_stat.st_mode):
        return _unverified(VerificationReason.SOURCE_IS_DIRECTORY)
    if not stat.S_ISREG(target_stat.st_mode):
        return _unverified(VerificationReason.SOURCE_NOT_REGULAR_FILE)

    try:
        with open(target, "rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if stat.S_ISDIR(opened_stat.st_mode):
                return _unverified(VerificationReason.SOURCE_IS_DIRECTORY)
            if not stat.S_ISREG(opened_stat.st_mode):
                return _unverified(VerificationReason.SOURCE_NOT_REGULAR_FILE)
            hasher = hashlib.sha256()
            while True:
                chunk = handle.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                hasher.update(chunk)
    except (FileNotFoundError, NotADirectoryError) as exc:
        return _unverified(VerificationReason.SOURCE_MISSING, str(exc))
    except PermissionError as exc:
        return _unverified(VerificationReason.SOURCE_UNREADABLE, str(exc))
    except OSError as exc:
        return _unverified(VerificationReason.SOURCE_READ_FAILED, str(exc))
    except (RuntimeError, ValueError) as exc:
        return _unverified(VerificationReason.VERIFIER_ERROR, str(exc))

    observed_digest = f"sha256:{hasher.hexdigest()}"
    if observed_digest == digest:
        return VerificationResult(
            Verification.VERIFIED,
            VerificationReason.DIGEST_MATCH,
        )
    return VerificationResult(
        Verification.FAILED,
        VerificationReason.DIGEST_MISMATCH,
    )


def verify_claim(
    project_root: str | os.PathLike[str],
    state: StateDocument,
    claim: Claim,
) -> VerificationResult:
    """Derive one claim verdict from every currently referenced binding."""

    if type(state) is not StateDocument:
        raise VerificationInputError("state must be a StateDocument")
    if type(claim) is not Claim:
        raise VerificationInputError("claim must be a Claim record")
    _require_project_root(project_root)

    if state.scope_semantics is not paths.host_scope_semantics():
        return _unverified(VerificationReason.SCOPE_SEMANTICS_INCOMPATIBLE)
    if claim.reproducible is not True:
        return _unverified(VerificationReason.CLAIM_NOT_REPRODUCIBLE)
    if not claim.evidence_ids:
        return _unverified(VerificationReason.CLAIM_NO_EVIDENCE)
    if not isinstance(claim.evidence_ids, tuple):
        return _unverified(VerificationReason.CLAIM_EVIDENCE_UNRESOLVED)

    evidence_by_id: dict[str, Evidence] = {}
    ambiguous_ids: set[str] = set()
    records = state.evidence if isinstance(state.evidence, tuple) else ()
    for item in records:
        if type(item) is not Evidence or type(item.id) is not str:
            continue
        if item.id in evidence_by_id:
            ambiguous_ids.add(item.id)
        else:
            evidence_by_id[item.id] = item

    any_failed = False
    any_unresolved = False
    any_unverified = False
    for evidence_id in claim.evidence_ids:
        if (
            type(evidence_id) is not str
            or evidence_id in ambiguous_ids
            or evidence_id not in evidence_by_id
        ):
            any_unresolved = True
            continue
        result = verify_evidence(project_root, evidence_by_id[evidence_id])
        if result.verification is Verification.FAILED:
            any_failed = True
        elif result.verification is not Verification.VERIFIED:
            any_unverified = True

    if any_failed:
        return VerificationResult(
            Verification.FAILED,
            VerificationReason.EVIDENCE_FAILED,
        )
    if any_unresolved:
        return _unverified(VerificationReason.CLAIM_EVIDENCE_UNRESOLVED)
    if any_unverified:
        return _unverified(VerificationReason.EVIDENCE_UNVERIFIED)
    return VerificationResult(
        Verification.VERIFIED,
        VerificationReason.ALL_EVIDENCE_VERIFIED,
    )


def verify_state(
    project_root: str | os.PathLike[str],
    state: StateDocument,
) -> Mapping[str, VerificationResult]:
    """Derive current verdicts for every verifiable record without writing."""

    if type(state) is not StateDocument:
        raise VerificationInputError("state must be a StateDocument")
    _require_project_root(project_root)

    results: dict[str, VerificationResult] = {}
    if state.scope_semantics is not paths.host_scope_semantics():
        incompatible = _unverified(
            VerificationReason.SCOPE_SEMANTICS_INCOMPATIBLE
        )
        for evidence in state.evidence:
            results[evidence.id] = incompatible
        for claim in state.claims:
            results[claim.id] = incompatible
        return MappingProxyType(results)

    for evidence in state.evidence:
        results[evidence.id] = verify_evidence(project_root, evidence)
    for claim in state.claims:
        results[claim.id] = verify_claim(project_root, state, claim)
    return MappingProxyType(results)
