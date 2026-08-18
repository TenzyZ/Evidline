"""Read-only local project diagnostics and deterministic renderers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import sys
from typing import Final

from evidline import __version__
from evidline import context as _context
from evidline import paths as _paths
from evidline import state as _state


DOCTOR_SCHEMA_VERSION: Final = 1


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class OverallStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class DoctorReason(str, Enum):
    CHECK_PASSED = "CHECK_PASSED"
    PYTHON_UNSUPPORTED = "PYTHON_UNSUPPORTED"
    PROJECT_ROOT_NOT_FOUND = "PROJECT_ROOT_NOT_FOUND"
    STATE_FILE_ABSENT = "STATE_FILE_ABSENT"
    STATE_UNREADABLE = "STATE_UNREADABLE"
    STATE_JSON_INVALID = "STATE_JSON_INVALID"
    SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"
    SCOPE_SEMANTICS_INCOMPATIBLE = "SCOPE_SEMANTICS_INCOMPATIBLE"
    STATE_STRUCTURE_INVALID = "STATE_STRUCTURE_INVALID"
    BUDGET_BELOW_PROFILE_MINIMUM = "BUDGET_BELOW_PROFILE_MINIMUM"
    BUDGET_BELOW_ALL_PROFILES = "BUDGET_BELOW_ALL_PROFILES"
    NOT_REACHED = "NOT_REACHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    label: str
    status: CheckStatus
    reason: DoctorReason
    message: str
    remediation: str | None


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]
    overall_status: OverallStatus
    evidline_version: str
    python_version: str
    host_scope_semantics: str
    supported_schema_version: int
    search_origin: str
    project_root: str | None
    state_path: str | None
    state_schema_version: int | None
    state_revision: int | None


_CHECKS: Final = (
    ("D001", "runtime.python_supported"),
    ("D002", "project.root_discovered"),
    ("D003", "project.state_present"),
    ("D004", "state.readable"),
    ("D005", "state.json_valid"),
    ("D006", "state.schema_supported"),
    ("D007", "state.scope_semantics_compatible"),
    ("D008", "state.structure_valid"),
    ("D009", "state.context_budget_sufficient"),
)


def _check(
    index: int,
    status: CheckStatus,
    reason: DoctorReason,
    message: str,
    remediation: str | None = None,
) -> DoctorCheck:
    check_id, label = _CHECKS[index]
    return DoctorCheck(check_id, label, status, reason, message, remediation)


def _skip(index: int) -> DoctorCheck:
    return _check(
        index,
        CheckStatus.SKIP,
        DoctorReason.NOT_REACHED,
        "not reached because an earlier diagnostic layer did not pass",
        "resolve the earlier failed diagnostic check and run evidline doctor again",
    )


def _overall(checks: tuple[DoctorCheck, ...]) -> OverallStatus:
    if any(check.status is CheckStatus.FAIL for check in checks):
        return OverallStatus.UNHEALTHY
    if any(check.status is CheckStatus.WARN for check in checks):
        return OverallStatus.DEGRADED
    return OverallStatus.HEALTHY


def _diagnose_loaded_state(document: _state.StateDocument) -> DoctorCheck:
    minimums = {
        profile: _context.minimum_budget_chars(profile)
        for profile in _context.ContextProfile
    }
    budget = document.project.default_budget_chars
    lowest = min(minimums.values())
    highest = max(minimums.values())
    affected = ", ".join(
        profile.value for profile, minimum in minimums.items() if budget < minimum
    )
    if budget >= highest:
        return _check(
            8, CheckStatus.PASS, DoctorReason.CHECK_PASSED,
            f"default budget {budget} satisfies all context profile minimums",
        )
    remediation = (
        f"default budget is {budget}; pass an explicit --budget or raise the "
        f"project default through a supported workflow (profile minimums: "
        f"{lowest}-{highest})"
    )
    if budget >= lowest:
        return _check(
            8, CheckStatus.WARN, DoctorReason.BUDGET_BELOW_PROFILE_MINIMUM,
            f"default budget {budget} is below required minimums for: {affected}",
            remediation,
        )
    return _check(
        8, CheckStatus.FAIL, DoctorReason.BUDGET_BELOW_ALL_PROFILES,
        f"default budget {budget} is below every context profile minimum ({lowest}-{highest})",
        remediation,
    )


def run_diagnostics(project_root: str | os.PathLike[str] | None = None) -> DoctorReport:
    """Return a complete, read-only diagnostic report for one local project."""

    origin_value = project_root if project_root is not None else os.curdir
    search_origin = str(Path(os.path.realpath(os.fspath(origin_value), strict=False)))
    checks: list[DoctorCheck] = []
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info >= (3, 11):
        checks.append(_check(0, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "Python 3.11 or newer is running"))
    else:
        checks.append(_check(0, CheckStatus.FAIL, DoctorReason.PYTHON_UNSUPPORTED, f"Python {python_version} is unsupported", "install Evidline on Python 3.11 or newer"))

    root = _paths.discover_project_root(origin_value)
    host_semantics = _paths.host_scope_semantics().value
    if root is None:
        checks.append(_check(1, CheckStatus.FAIL, DoctorReason.PROJECT_ROOT_NOT_FOUND, "no Evidline project root was discovered", "run evidline init, or pass --root PATH"))
        checks.extend(_skip(index) for index in range(2, 9))
        return DoctorReport(tuple(checks), _overall(tuple(checks)), __version__, python_version, host_semantics, _state.SCHEMA_VERSION, search_origin, None, None, None, None)

    checks.append(_check(1, CheckStatus.PASS, DoctorReason.CHECK_PASSED, f"project root discovered: {root}"))
    state_path: str | None = None
    try:
        state_path = str(_state.get_state_path(root))
    except _state.StateError:
        pass

    document: _state.StateDocument | None = None
    try:
        document = _state.load_state(root)
    except _state.StateNotInitializedError:
        checks.append(_check(2, CheckStatus.FAIL, DoctorReason.STATE_FILE_ABSENT, "state file is absent", "run evidline init"))
        checks.extend(_skip(index) for index in range(3, 9))
    except _state.StateIOError as exc:
        checks.append(_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state location is present"))
        checks.append(_check(3, CheckStatus.FAIL, DoctorReason.STATE_UNREADABLE, str(exc), "check permissions on .evidline/state.json; do not symlink state outside the project"))
        checks.extend(_skip(index) for index in range(4, 9))
    except _state.StateJSONError as exc:
        checks.extend((_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state file is present"), _check(3, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state bytes are readable"), _check(4, CheckStatus.FAIL, DoctorReason.STATE_JSON_INVALID, str(exc), "restore .evidline/state.json from version control; Evidline will not repair it")))
        checks.extend(_skip(index) for index in range(5, 9))
    except _state.UnsupportedSchemaError as exc:
        checks.extend((_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state file is present"), _check(3, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state bytes are readable"), _check(4, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state JSON is valid"), _check(5, CheckStatus.FAIL, DoctorReason.SCHEMA_UNSUPPORTED, str(exc), "state was written by a different Evidline version; no migration exists — use a matching version")))
        checks.extend(_skip(index) for index in range(6, 9))
    except _state.IncompatibleScopeSemanticsError as exc:
        checks.extend((_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state file is present"), _check(3, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state bytes are readable"), _check(4, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state JSON is valid"), _check(5, CheckStatus.PASS, DoctorReason.CHECK_PASSED, f"state schema {_state.SCHEMA_VERSION} is supported"), _check(6, CheckStatus.FAIL, DoctorReason.SCOPE_SEMANTICS_INCOMPATIBLE, str(exc), "use a host compatible with the persisted scope semantics; do not restamp state")))
        checks.extend(_skip(index) for index in range(7, 9))
    except _state.StateValidationError as exc:
        checks.extend((_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state file is present"), _check(3, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state bytes are readable"), _check(4, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state JSON is valid"), _skip(5), _skip(6), _check(7, CheckStatus.FAIL, DoctorReason.STATE_STRUCTURE_INVALID, str(exc), "restore from version control; Evidline will not repair state"), _skip(8)))
    else:
        checks.extend((_check(2, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state file is present"), _check(3, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state bytes are readable"), _check(4, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state JSON is valid"), _check(5, CheckStatus.PASS, DoctorReason.CHECK_PASSED, f"state schema {document.schema_version} is supported"), _check(6, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state scope semantics are compatible"), _check(7, CheckStatus.PASS, DoctorReason.CHECK_PASSED, "state structure is valid"), _diagnose_loaded_state(document)))

    return DoctorReport(tuple(checks), _overall(tuple(checks)), __version__, python_version, host_semantics, _state.SCHEMA_VERSION, search_origin, str(root), state_path, document.schema_version if document else None, document.revision if document else None)


def _as_dict(report: DoctorReport) -> dict[str, object]:
    return {
        "checks": [{"id": item.id, "label": item.label, "status": item.status.value, "reason": item.reason.value, "message": item.message, "remediation": item.remediation} for item in report.checks],
        "doctor_schema_version": DOCTOR_SCHEMA_VERSION,
        "evidline_version": report.evidline_version,
        "host_scope_semantics": report.host_scope_semantics,
        "overall_status": report.overall_status.value,
        "project_root": report.project_root,
        "python_version": report.python_version,
        "search_origin": report.search_origin,
        "state_path": report.state_path,
        "state_revision": report.state_revision,
        "state_schema_version": report.state_schema_version,
        "supported_schema_version": report.supported_schema_version,
    }


def render_doctor_json(report: DoctorReport) -> str:
    if type(report) is not DoctorReport:
        raise TypeError("report must be a DoctorReport")
    return json.dumps(_as_dict(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_doctor_text(report: DoctorReport) -> str:
    if type(report) is not DoctorReport:
        raise TypeError("report must be a DoctorReport")
    payload = _as_dict(report)
    lines = ["Evidline doctor"]
    for key in ("doctor_schema_version", "evidline_version", "python_version", "host_scope_semantics", "supported_schema_version", "search_origin", "project_root", "state_path", "state_schema_version", "state_revision", "overall_status"):
        lines.append(f"{key}: {payload[key] if payload[key] is not None else '-'}")
    for check in report.checks:
        lines.append(f"[{check.status.value}] {check.id} {check.label} ({check.reason.value})  {check.message}")
        if check.remediation is not None:
            lines.append(f"  remediation: {check.remediation}")
    return "\n".join(lines) + "\n"
