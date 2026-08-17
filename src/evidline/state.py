"""Typed V1 state, strict validation, and local optimistic persistence.

The write lock serializes cooperating local Evidline writers.  It is not an OS
sandbox and does not protect against TOCTOU replacement, hardlink aliasing,
non-cooperating writers, or mutations outside Evidline hook coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Final, Mapping, NoReturn

from evidline import paths as _paths


SCHEMA_VERSION: Final = 3
STATE_DIRECTORY: Final = ".evidline"
STATE_FILENAME: Final = "state.json"
LOCK_FILENAME: Final = ".state.lock"
TRUSTED_APPROVAL_CHANNEL: Final = "evidline-cli-interactive"
TRUSTED_ASSERTED_ACTOR: Final = "interactive-cli-operator"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID_PATTERN = re.compile(r"[a-z]+-[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class Intent(str, Enum):
    PROPOSED = "PROPOSED"
    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"


class Execution(str, Enum):
    NOT_RUN = "NOT_RUN"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class Verification(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    STALE = "STALE"


class InvariantEnforcement(str, Enum):
    BLOCK = "BLOCK"
    ADVISE = "ADVISE"


class InvariantStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"


class TaskStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DONE = "DONE"


class ClaimFreshness(str, Enum):
    DURABLE_UNTIL_SUPERSEDED = "DURABLE_UNTIL_SUPERSEDED"
    DIGEST_BOUND = "DIGEST_BOUND"
    PERSISTED_VOLATILE = "PERSISTED_VOLATILE"


class EvidenceProvenance(str, Enum):
    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    HUMAN_ASSERTION = "HUMAN_ASSERTION"
    AGENT_ASSERTION = "AGENT_ASSERTION"
    DOCUMENT_REFERENCE = "DOCUMENT_REFERENCE"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"


class VerifierRule(str, Enum):
    R1_DIGEST_MATCH = "R1_DIGEST_MATCH"


@dataclass(frozen=True, slots=True)
class Project:
    name: str
    purpose: str
    ignore_globs: tuple[str, ...]
    default_budget_chars: int


@dataclass(frozen=True, slots=True)
class Invariant:
    id: str
    description: str
    enforcement: InvariantEnforcement
    status: InvariantStatus
    superseded_by: str | None = None
    approved_at: str | None = None
    approval_channel: str | None = None
    asserted_actor: str | None = None
    governed_scope: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Decision:
    id: str
    description: str
    intent: Intent
    execution: Execution
    approved_at: str | None = None
    approval_channel: str | None = None
    asserted_actor: str | None = None


@dataclass(frozen=True, slots=True)
class Task:
    id: str
    description: str
    status: TaskStatus
    intent: Intent
    execution: Execution
    related_ids: tuple[str, ...] = ()
    authorized_scope: tuple[str, ...] = ()
    approved_at: str | None = None
    approval_channel: str | None = None
    asserted_actor: str | None = None
    acknowledged_invariant_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Claim:
    id: str
    description: str
    freshness: ClaimFreshness
    verification: Verification
    reproducible: bool
    evidence_ids: tuple[str, ...] = ()
    verifier_rule: VerifierRule | None = None
    verified_at: str | None = None
    verifying_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    description: str
    provenance: EvidenceProvenance
    execution: Execution
    digest: str | None = None


@dataclass(frozen=True, slots=True)
class StateDocument:
    schema_version: int
    revision: int
    project: Project
    invariants: tuple[Invariant, ...]
    decisions: tuple[Decision, ...]
    tasks: tuple[Task, ...]
    claims: tuple[Claim, ...]
    evidence: tuple[Evidence, ...]
    counters: Mapping[str, int]
    scope_semantics: _paths.ScopePathSemantics = field(
        default_factory=_paths.host_scope_semantics
    )


class StateError(Exception):
    """Base class for stable state API failures."""


class StateNotInitializedError(StateError):
    """The state directory or durable state file is absent."""


class StateAlreadyInitializedError(StateError):
    """Exclusive initialization found an existing durable state file."""


class StateValidationError(StateError):
    """The complete state document is structurally invalid."""


class IncompatibleScopeSemanticsError(StateValidationError):
    """Persisted non-empty scopes use a foreign normalization discipline."""


class StateJSONError(StateValidationError):
    """The durable state is not valid JSON."""


class UnsupportedSchemaError(StateValidationError):
    """The state uses a schema version this runtime cannot load."""


class StateConflictError(StateError):
    """The expected revision is stale or another writer holds the lock."""


class StateIOError(StateError):
    """State could not be accessed safely."""


def resolve_initialization_root(project_root: str | os.PathLike[str]) -> Path:
    """Return a canonical existing directory suitable for initialization."""

    try:
        root_text = os.fspath(project_root)
    except TypeError as exc:
        raise StateIOError("project root is not a path") from exc
    if not isinstance(root_text, str) or "\0" in root_text:
        raise StateIOError("project root is not a safe text path")
    try:
        root = Path(os.path.realpath(root_text, strict=True))
        if not stat.S_ISDIR(root.stat().st_mode):
            raise StateIOError("project root is not a directory")
        anchor = Path(root.anchor)
        if _paths.has_protected_component(anchor, root):
            raise StateValidationError(
                "project root contains a protected path component"
            )
    except StateError:
        raise
    except FileNotFoundError as exc:
        raise StateIOError("project root is absent") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise StateIOError("project root cannot be resolved") from exc
    return root


def initialize_project(
    project_root: str | os.PathLike[str],
    *,
    project: Project,
) -> StateDocument:
    """Create the initial durable state exactly once."""

    root = resolve_initialization_root(project_root)
    document = StateDocument(
        schema_version=SCHEMA_VERSION,
        revision=0,
        project=project,
        invariants=(),
        decisions=(),
        tasks=(),
        claims=(),
        evidence=(),
        counters={},
        scope_semantics=_paths.host_scope_semantics(),
    )
    payload = serialize_state(document).encode("utf-8")

    lexical_directory = root / STATE_DIRECTORY
    try:
        lexical_directory.mkdir(exist_ok=True)
    except OSError as exc:
        raise StateIOError("state directory cannot be created") from exc
    try:
        state_directory, state_path = _state_locations(root, require_file=False)
    except StateNotInitializedError as exc:
        raise StateIOError("state directory cannot be accessed safely") from exc

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        file_descriptor = os.open(state_path, flags, 0o644)
    except FileExistsError as exc:
        raise StateAlreadyInitializedError("state file already exists") from exc
    except OSError as exc:
        raise StateIOError("state file cannot be created") from exc

    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            written = stream.write(payload)
            if written != len(payload):
                raise OSError("incomplete state write")
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(state_directory)
    except OSError as exc:
        raise StateIOError("initial state write failed") from exc
    return document


def get_state_path(project_root: str | os.PathLike[str]) -> Path:
    """Return the canonical durable state path for an initialized root."""

    _, state_path = _state_locations(project_root, require_file=False)
    return state_path


def _incompatible_scope_semantics(
    state: StateDocument,
    host_semantics: _paths.ScopePathSemantics,
) -> bool:
    """Return whether non-empty persisted scopes cannot be read on this host."""

    if state.scope_semantics is host_semantics:
        return False
    tasks = state.tasks if isinstance(state.tasks, tuple) else ()
    invariants = state.invariants if isinstance(state.invariants, tuple) else ()
    return any(
        type(task) is Task and bool(task.authorized_scope)
        for task in tasks
    ) or any(
        type(invariant) is Invariant and bool(invariant.governed_scope)
        for invariant in invariants
    )


def validate_state(state: StateDocument) -> None:
    """Fully validate a typed state document, failing closed on any defect."""

    if type(state) is not StateDocument:
        _invalid("state must be a StateDocument")
    if type(state.schema_version) is not int:
        _invalid("schema_version must be an integer")
    if state.schema_version != SCHEMA_VERSION:
        raise UnsupportedSchemaError(f"unsupported schema_version: {state.schema_version}")
    _non_negative_integer(state.revision, "revision")
    _enum_instance(
        state.scope_semantics,
        _paths.ScopePathSemantics,
        "scope_semantics",
    )
    if _incompatible_scope_semantics(state, _paths.host_scope_semantics()):
        raise IncompatibleScopeSemanticsError(
            "scope_semantics is incompatible with non-empty persisted scopes"
        )
    _validate_project(state.project)

    collections: tuple[tuple[str, tuple[Any, ...], type[Any], str], ...] = (
        ("invariants", state.invariants, Invariant, "inv-"),
        ("decisions", state.decisions, Decision, "dec-"),
        ("tasks", state.tasks, Task, "task-"),
        ("claims", state.claims, Claim, "claim-"),
        ("evidence", state.evidence, Evidence, "evidence-"),
    )
    all_records: dict[str, Any] = {}
    for name, records, expected_type, prefix in collections:
        if not isinstance(records, tuple):
            _invalid(f"{name} must be a tuple")
        for record in records:
            if type(record) is not expected_type:
                _invalid(f"{name} contains the wrong record type")
            _record_id(record.id, prefix)
            if record.id in all_records:
                _invalid(f"duplicate record id: {record.id}")
            all_records[record.id] = record

    evidence_by_id = {item.id: item for item in state.evidence}
    invariant_ids = {item.id for item in state.invariants}
    for item in state.invariants:
        _validate_invariant(item, invariant_ids)
    for item in state.decisions:
        _validate_decision(item)
    active_tasks = 0
    for item in state.tasks:
        _validate_task(item, all_records)
        if item.status is TaskStatus.ACTIVE:
            active_tasks += 1
    if active_tasks > 1:
        _invalid("no more than one task may be ACTIVE")
    for item in state.evidence:
        _validate_evidence(item)
    for item in state.claims:
        _validate_claim(item, evidence_by_id)

    if not isinstance(state.counters, Mapping):
        _invalid("counters must be an object")
    for name, value in state.counters.items():
        _non_empty_string(name, "counter name")
        _non_negative_integer(value, f"counter {name}")


def serialize_state(state: StateDocument) -> str:
    """Return canonical UTF-8-compatible JSON text with one trailing newline."""

    validate_state(state)
    return json.dumps(
        _state_to_dict(state), ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def parse_state(text: str) -> StateDocument:
    """Parse and fully validate one state document."""

    if not isinstance(text, str):
        raise StateJSONError("state JSON must be text")
    try:
        raw = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise StateJSONError("state file contains invalid JSON") from exc
    except StateJSONError:
        raise
    return _state_from_object(raw)


def load_state(project_root: str | os.PathLike[str]) -> StateDocument:
    """Load the complete validated durable state or return no document."""

    _, state_path = _state_locations(project_root, require_file=True)
    try:
        text = state_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise StateNotInitializedError("state file is absent") from exc
    except (OSError, UnicodeError) as exc:
        raise StateIOError("state file is inaccessible") from exc
    return parse_state(text)


def write_state(
    project_root: str | os.PathLike[str],
    proposed: StateDocument,
    *,
    expected_revision: int,
) -> StateDocument:
    """Validate and replace state with ``os.replace`` under a writer lock.

    The state directory must already exist.  The lock is never waited on or
    auto-broken; an existing lock fails closed.
    """

    _non_negative_integer(expected_revision, "expected_revision")
    state_directory, state_path = _state_locations(project_root, require_file=True)
    lock_path = state_directory / LOCK_FILENAME
    lock_fd: int | None = None
    temp_path: Path | None = None
    completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            raise StateConflictError("state write lock is already held") from exc
        except OSError as exc:
            raise StateIOError("state write lock cannot be acquired") from exc

        validate_state(proposed)
        if proposed.revision != expected_revision:
            raise StateConflictError("proposed revision does not match expected revision")
        current = load_state(project_root)
        if current.revision != expected_revision:
            raise StateConflictError(
                f"state revision conflict: expected {expected_revision}, "
                f"found {current.revision}"
            )

        updated = replace(proposed, revision=expected_revision + 1)
        payload = serialize_state(updated).encode("utf-8")
        try:
            temp_fd, temp_name = tempfile.mkstemp(
                prefix=".state.", suffix=".tmp", dir=state_directory
            )
            temp_path = Path(temp_name)
            with os.fdopen(temp_fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, state_path)
            temp_path = None
            _fsync_directory(state_directory)
        except OSError as exc:
            raise StateIOError("state replacement failed") from exc
        completed = True
        return updated
    finally:
        cleanup_error: OSError | None = None
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError as exc:
                cleanup_error = exc
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if lock_fd is not None:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if completed and cleanup_error is not None:
            raise StateIOError("state was written but writer cleanup failed") from cleanup_error


def _state_locations(
    project_root: str | os.PathLike[str], *, require_file: bool
) -> tuple[Path, Path]:
    try:
        root_text = os.fspath(project_root)
    except TypeError as exc:
        raise StateIOError("project root is not a path") from exc
    if not isinstance(root_text, str) or "\0" in root_text:
        raise StateIOError("project root is not a safe text path")
    try:
        root = Path(os.path.realpath(root_text, strict=True))
        if not stat.S_ISDIR(root.stat().st_mode):
            raise StateNotInitializedError("project root is absent")
        lexical_directory = Path(root_text) / STATE_DIRECTORY
        try:
            directory_mode = lexical_directory.stat().st_mode
        except FileNotFoundError as exc:
            raise StateNotInitializedError("state directory is absent") from exc
        if not stat.S_ISDIR(directory_mode):
            raise StateNotInitializedError("state directory is absent")
        state_directory = Path(os.path.realpath(lexical_directory, strict=True))
        common = os.path.commonpath(
            (os.path.normcase(str(root)), os.path.normcase(str(state_directory)))
        )
        if common != os.path.normcase(str(root)) or state_directory == root:
            raise StateIOError("state directory resolves outside project root")
        state_path = state_directory / STATE_FILENAME
        if require_file:
            try:
                state_mode = state_path.stat().st_mode
            except FileNotFoundError as exc:
                raise StateNotInitializedError("state file is absent") from exc
            if not stat.S_ISREG(state_mode):
                raise StateNotInitializedError("state file is absent")
            canonical_file = Path(os.path.realpath(state_path, strict=True))
            file_common = os.path.commonpath(
                (
                    os.path.normcase(str(state_directory)),
                    os.path.normcase(str(canonical_file)),
                )
            )
            if file_common != os.path.normcase(str(state_directory)):
                raise StateIOError("state file resolves outside state directory")
    except StateError:
        raise
    except FileNotFoundError as exc:
        raise StateNotInitializedError("project root is absent") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise StateIOError("state location cannot be resolved") from exc
    return state_directory, state_path


def _state_from_object(raw: Any) -> StateDocument:
    if not isinstance(raw, dict):
        _invalid("top-level state must be an object")
    if "schema_version" in raw:
        schema_version = raw["schema_version"]
        if type(schema_version) is not int:
            _invalid("schema_version must be an integer")
        if schema_version != SCHEMA_VERSION:
            raise UnsupportedSchemaError(
                f"unsupported schema_version: {schema_version}"
            )
    expected = {
        "schema_version",
        "revision",
        "project",
        "invariants",
        "decisions",
        "tasks",
        "claims",
        "evidence",
        "counters",
        "scope_semantics",
    }
    _exact_keys(raw, expected, "state")
    schema_version = raw["schema_version"]

    state = StateDocument(
        schema_version=schema_version,
        revision=raw["revision"],
        project=_project_from_object(raw["project"]),
        invariants=tuple(
            _invariant_from_object(value)
            for value in _object_list(raw["invariants"], "invariants")
        ),
        decisions=tuple(
            _decision_from_object(value)
            for value in _object_list(raw["decisions"], "decisions")
        ),
        tasks=tuple(
            _task_from_object(value) for value in _object_list(raw["tasks"], "tasks")
        ),
        claims=tuple(
            _claim_from_object(value)
            for value in _object_list(raw["claims"], "claims")
        ),
        evidence=tuple(
            _evidence_from_object(value)
            for value in _object_list(raw["evidence"], "evidence")
        ),
        counters=_counter_object(raw["counters"]),
        scope_semantics=_enum(
            _paths.ScopePathSemantics,
            raw["scope_semantics"],
            "scope_semantics",
        ),
    )
    validate_state(state)
    return state


def _project_from_object(raw: Any) -> Project:
    value = _strict_object(raw, "project")
    _exact_keys(
        value,
        {"name", "purpose", "ignore_globs", "default_budget_chars"},
        "project",
    )
    return Project(
        name=value["name"],
        purpose=value["purpose"],
        ignore_globs=_string_tuple(value["ignore_globs"], "project.ignore_globs"),
        default_budget_chars=value["default_budget_chars"],
    )


def _invariant_from_object(raw: Any) -> Invariant:
    value = _strict_object(raw, "invariant")
    _exact_keys(
        value,
        {
            "id", "description", "enforcement", "status", "superseded_by",
            "approved_at", "approval_channel", "asserted_actor",
            "governed_scope",
        },
        "invariant",
    )
    return Invariant(
        id=value["id"],
        description=value["description"],
        enforcement=_enum(InvariantEnforcement, value["enforcement"], "enforcement"),
        status=_enum(InvariantStatus, value["status"], "status"),
        superseded_by=_optional_string(value["superseded_by"], "superseded_by"),
        approved_at=_optional_string(value["approved_at"], "approved_at"),
        approval_channel=_optional_string(value["approval_channel"], "approval_channel"),
        asserted_actor=_optional_string(value["asserted_actor"], "asserted_actor"),
        governed_scope=_string_tuple(value["governed_scope"], "governed_scope"),
    )


def _decision_from_object(raw: Any) -> Decision:
    value = _strict_object(raw, "decision")
    _exact_keys(
        value,
        {"id", "description", "intent", "execution", "approved_at", "approval_channel", "asserted_actor"},
        "decision",
    )
    return Decision(
        id=value["id"],
        description=value["description"],
        intent=_enum(Intent, value["intent"], "intent"),
        execution=_enum(Execution, value["execution"], "execution"),
        approved_at=_optional_string(value["approved_at"], "approved_at"),
        approval_channel=_optional_string(value["approval_channel"], "approval_channel"),
        asserted_actor=_optional_string(value["asserted_actor"], "asserted_actor"),
    )


def _task_from_object(raw: Any) -> Task:
    value = _strict_object(raw, "task")
    _exact_keys(
        value,
        {
            "id", "description", "status", "intent", "execution",
            "related_ids", "authorized_scope", "approved_at",
            "approval_channel", "asserted_actor",
            "acknowledged_invariant_ids",
        },
        "task",
    )
    return Task(
        id=value["id"],
        description=value["description"],
        status=_enum(TaskStatus, value["status"], "status"),
        intent=_enum(Intent, value["intent"], "intent"),
        execution=_enum(Execution, value["execution"], "execution"),
        related_ids=_string_tuple(value["related_ids"], "related_ids"),
        authorized_scope=_string_tuple(
            value["authorized_scope"], "authorized_scope"
        ),
        approved_at=_optional_string(value["approved_at"], "approved_at"),
        approval_channel=_optional_string(value["approval_channel"], "approval_channel"),
        asserted_actor=_optional_string(value["asserted_actor"], "asserted_actor"),
        acknowledged_invariant_ids=_string_tuple(
            value["acknowledged_invariant_ids"],
            "acknowledged_invariant_ids",
        ),
    )


def _claim_from_object(raw: Any) -> Claim:
    value = _strict_object(raw, "claim")
    _exact_keys(
        value,
        {"id", "description", "freshness", "verification", "reproducible", "evidence_ids", "verifier_rule", "verified_at", "verifying_evidence_ids"},
        "claim",
    )
    rule = value["verifier_rule"]
    return Claim(
        id=value["id"],
        description=value["description"],
        freshness=_enum(ClaimFreshness, value["freshness"], "freshness"),
        verification=_enum(Verification, value["verification"], "verification"),
        reproducible=value["reproducible"],
        evidence_ids=_string_tuple(value["evidence_ids"], "evidence_ids"),
        verifier_rule=None if rule is None else _enum(VerifierRule, rule, "verifier_rule"),
        verified_at=_optional_string(value["verified_at"], "verified_at"),
        verifying_evidence_ids=_string_tuple(value["verifying_evidence_ids"], "verifying_evidence_ids"),
    )


def _evidence_from_object(raw: Any) -> Evidence:
    value = _strict_object(raw, "evidence")
    _exact_keys(value, {"id", "description", "provenance", "execution", "digest"}, "evidence")
    return Evidence(
        id=value["id"],
        description=value["description"],
        provenance=_enum(EvidenceProvenance, value["provenance"], "provenance"),
        execution=_enum(Execution, value["execution"], "execution"),
        digest=_optional_string(value["digest"], "digest"),
    )


def _state_to_dict(state: StateDocument) -> dict[str, Any]:
    return {
        "schema_version": state.schema_version,
        "revision": state.revision,
        "project": {
            "name": state.project.name,
            "purpose": state.project.purpose,
            "ignore_globs": list(state.project.ignore_globs),
            "default_budget_chars": state.project.default_budget_chars,
        },
        "invariants": [_record_to_dict(item) for item in state.invariants],
        "decisions": [_record_to_dict(item) for item in state.decisions],
        "tasks": [_record_to_dict(item) for item in state.tasks],
        "claims": [_record_to_dict(item) for item in state.claims],
        "evidence": [_record_to_dict(item) for item in state.evidence],
        "counters": dict(state.counters),
        "scope_semantics": state.scope_semantics.value,
    }


def _record_to_dict(record: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field_name in record.__dataclass_fields__:
        value = getattr(record, field_name)
        if isinstance(value, Enum):
            result[field_name] = value.value
        elif isinstance(value, tuple):
            result[field_name] = list(value)
        else:
            result[field_name] = value
    return result


def _validate_project(project: Project) -> None:
    if type(project) is not Project:
        _invalid("project must be a Project")
    _non_empty_string(project.name, "project.name")
    _non_empty_string(project.purpose, "project.purpose")
    if not isinstance(project.ignore_globs, tuple):
        _invalid("project.ignore_globs must be a tuple")
    for value in project.ignore_globs:
        _non_empty_string(value, "project.ignore_globs item")
    _positive_integer(project.default_budget_chars, "project.default_budget_chars")


def _validate_invariant(item: Invariant, invariant_ids: set[str]) -> None:
    _non_empty_string(item.description, f"{item.id}.description")
    _enum_instance(item.enforcement, InvariantEnforcement, "enforcement")
    _enum_instance(item.status, InvariantStatus, "status")
    _optional_string(item.superseded_by, f"{item.id}.superseded_by")
    _metadata_strings(item.approved_at, item.approval_channel, item.asserted_actor)
    _validate_scope_tuple(item.id, "governed_scope", item.governed_scope)
    if item.status is InvariantStatus.SUPERSEDED:
        if item.superseded_by is None or item.superseded_by not in invariant_ids:
            _invalid(f"{item.id} has an unresolved superseded_by reference")
        if item.superseded_by == item.id:
            _invalid(f"{item.id} cannot supersede itself")
        _required_transition_metadata(item.id, item.approved_at, item.approval_channel)
    elif item.superseded_by is not None:
        _invalid(f"{item.id} is ACTIVE but has superseded_by")


def _validate_decision(item: Decision) -> None:
    _non_empty_string(item.description, f"{item.id}.description")
    _enum_instance(item.intent, Intent, "intent")
    _enum_instance(item.execution, Execution, "execution")
    _metadata_strings(item.approved_at, item.approval_channel, item.asserted_actor)
    if item.intent is Intent.AUTHORIZED:
        _required_transition_metadata(item.id, item.approved_at, item.approval_channel)


def _validate_task(item: Task, all_records: Mapping[str, Any]) -> None:
    _non_empty_string(item.description, f"{item.id}.description")
    _enum_instance(item.status, TaskStatus, "status")
    _enum_instance(item.intent, Intent, "intent")
    _enum_instance(item.execution, Execution, "execution")
    if not isinstance(item.related_ids, tuple):
        _invalid(f"{item.id}.related_ids must be a tuple")
    for related_id in item.related_ids:
        _non_empty_string(related_id, f"{item.id}.related_ids item")
        if related_id not in all_records:
            _invalid(f"{item.id} has unresolved related id: {related_id}")
    _validate_scope_tuple(item.id, "authorized_scope", item.authorized_scope)
    _validate_acknowledged_invariant_ids(item, all_records)
    _metadata_strings(item.approved_at, item.approval_channel, item.asserted_actor)
    if item.status is TaskStatus.ACTIVE:
        if item.intent is not Intent.AUTHORIZED:
            _invalid(f"{item.id} must be AUTHORIZED before becoming ACTIVE")
        _required_transition_metadata(item.id, item.approved_at, item.approval_channel)


def _validate_scope_tuple(
    record_id: str,
    field_name: str,
    values: tuple[str, ...],
) -> None:
    if not isinstance(values, tuple):
        _invalid(f"{record_id}.{field_name} must be a tuple")
    seen: set[str] = set()
    for scope in values:
        try:
            normalized = _paths.normalize_root_relative_scope(scope)
        except ValueError as exc:
            _invalid(f"{record_id}.{field_name} invalid: {exc}")
        if normalized != scope:
            _invalid(
                f"{record_id}.{field_name} entries must be normalized: {scope}"
            )
        if scope in seen:
            _invalid(f"{record_id}.{field_name} contains duplicate: {scope}")
        seen.add(scope)


def _validate_acknowledged_invariant_ids(
    item: Task,
    all_records: Mapping[str, Any],
) -> None:
    values = item.acknowledged_invariant_ids
    if not isinstance(values, tuple):
        _invalid(f"{item.id}.acknowledged_invariant_ids must be a tuple")
    seen: set[str] = set()
    for invariant_id in values:
        _non_empty_string(
            invariant_id,
            f"{item.id}.acknowledged_invariant_ids item",
        )
        if invariant_id in seen:
            _invalid(
                f"{item.id}.acknowledged_invariant_ids contains duplicate: "
                f"{invariant_id}"
            )
        record = all_records.get(invariant_id)
        if record is None:
            _invalid(f"{item.id} has unresolved invariant id: {invariant_id}")
        if type(record) is not Invariant:
            _invalid(
                f"{item.id} acknowledgement does not resolve to an Invariant: "
                f"{invariant_id}"
            )
        seen.add(invariant_id)


def _validate_claim(item: Claim, evidence_by_id: Mapping[str, Evidence]) -> None:
    _non_empty_string(item.description, f"{item.id}.description")
    _enum_instance(item.freshness, ClaimFreshness, "freshness")
    _enum_instance(item.verification, Verification, "verification")
    if type(item.reproducible) is not bool:
        _invalid(f"{item.id}.reproducible must be a boolean")
    if item.verifier_rule is not None:
        _enum_instance(item.verifier_rule, VerifierRule, "verifier_rule")
    _optional_string(item.verified_at, f"{item.id}.verified_at")
    if item.verification is Verification.STALE:
        _invalid("STALE is computed and cannot be persisted as current truth")
    if item.verification is Verification.UNVERIFIED and (
        item.verifier_rule is not None
        or item.verified_at is not None
        or item.verifying_evidence_ids
    ):
        _invalid(f"{item.id} UNVERIFIED cannot carry verification provenance")
    for field_name, references in (
        ("evidence_ids", item.evidence_ids),
        ("verifying_evidence_ids", item.verifying_evidence_ids),
    ):
        if not isinstance(references, tuple):
            _invalid(f"{item.id}.{field_name} must be a tuple")
        for evidence_id in references:
            _non_empty_string(evidence_id, f"{item.id}.{field_name} item")
            if evidence_id not in evidence_by_id:
                _invalid(f"{item.id} has unresolved evidence id: {evidence_id}")
    if not set(item.verifying_evidence_ids).issubset(item.evidence_ids):
        _invalid(f"{item.id} verifying evidence must also be supporting evidence")
    if item.verification is Verification.VERIFIED:
        _invalid(
            f"{item.id} VERIFIED cannot be persisted until Evidline performs "
            "reproducible verification"
        )


def _validate_evidence(item: Evidence) -> None:
    _non_empty_string(item.description, f"{item.id}.description")
    _enum_instance(item.provenance, EvidenceProvenance, "provenance")
    _enum_instance(item.execution, Execution, "execution")
    if item.digest is not None:
        _non_empty_string(item.digest, f"{item.id}.digest")
        if not _DIGEST_PATTERN.fullmatch(item.digest):
            _invalid(f"{item.id}.digest must be sha256 followed by 64 lowercase hex characters")


def _required_transition_metadata(
    record_id: str, approved_at: str | None, approval_channel: str | None
) -> None:
    _non_empty_string(approved_at, f"{record_id}.approved_at")
    _non_empty_string(approval_channel, f"{record_id}.approval_channel")


def _metadata_strings(*values: str | None) -> None:
    for value in values:
        if value is not None:
            _non_empty_string(value, "authority metadata")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StateJSONError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_object(raw: Any, name: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        _invalid(f"{name} must be an object")
    return raw


def _object_list(raw: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        _invalid(f"{name} must be an array")
    for value in raw:
        if not isinstance(value, dict):
            _invalid(f"{name} entries must be objects")
    return raw


def _counter_object(raw: Any) -> dict[str, int]:
    value = _strict_object(raw, "counters")
    result: dict[str, int] = {}
    for key, count in value.items():
        _non_empty_string(key, "counter name")
        _non_negative_integer(count, f"counter {key}")
        result[key] = count
    return result


def _string_tuple(raw: Any, name: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        _invalid(f"{name} must be an array")
    for value in raw:
        _non_empty_string(value, f"{name} item")
    return tuple(raw)


def _optional_string(raw: Any, name: str) -> str | None:
    if raw is not None:
        _non_empty_string(raw, name)
    return raw


def _exact_keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        _invalid(f"{name} keys invalid; missing={missing}, unknown={unknown}")


def _enum(enum_type: type[Enum], raw: Any, name: str) -> Any:
    if not isinstance(raw, str):
        _invalid(f"{name} must be a string")
    try:
        return enum_type(raw)
    except ValueError as exc:
        raise StateValidationError(f"invalid {name}: {raw}") from exc


def _enum_instance(value: Any, enum_type: type[Enum], name: str) -> None:
    if not isinstance(value, enum_type):
        _invalid(f"{name} must be {enum_type.__name__}")


def _record_id(value: Any, prefix: str) -> None:
    _non_empty_string(value, "record id")
    if not _ID_PATTERN.fullmatch(value) or not value.startswith(prefix):
        _invalid(f"record id must use {prefix} prefix: {value}")


def _non_empty_string(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        _invalid(f"{name} must be a non-empty string")


def _non_negative_integer(value: Any, name: str) -> None:
    if type(value) is not int or value < 0:
        _invalid(f"{name} must be a non-negative integer")


def _positive_integer(value: Any, name: str) -> None:
    if type(value) is not int or value <= 0:
        _invalid(f"{name} must be a positive integer")


def _invalid(message: str) -> NoReturn:
    raise StateValidationError(message)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
