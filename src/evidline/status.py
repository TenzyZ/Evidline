"""Deterministic project status summary and renderers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Final

from evidline import paths as _paths
from evidline import state as _state


STATUS_SCHEMA_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class ProjectStatus:
    """State-derived status values with no ambient inputs."""

    state_schema_version: int
    state_revision: int
    project_name: str
    default_budget_chars: int
    active_task_id: str | None
    active_invariants: int
    invariants: int
    decisions: int
    tasks: int
    claims: int
    evidence: int


@dataclass(frozen=True, slots=True)
class StatusReport:
    """A state summary bound to its canonical local paths."""

    status: ProjectStatus
    root: str
    state_path: str


def summarize_state(state: _state.StateDocument) -> ProjectStatus:
    """Summarize one validated state document without side effects."""

    _state.validate_state(state)
    active_task_id = next(
        (
            task.id
            for task in state.tasks
            if task.status is _state.TaskStatus.ACTIVE
        ),
        None,
    )
    return ProjectStatus(
        state_schema_version=state.schema_version,
        state_revision=state.revision,
        project_name=state.project.name,
        default_budget_chars=state.project.default_budget_chars,
        active_task_id=active_task_id,
        active_invariants=sum(
            invariant.status is _state.InvariantStatus.ACTIVE
            for invariant in state.invariants
        ),
        invariants=len(state.invariants),
        decisions=len(state.decisions),
        tasks=len(state.tasks),
        claims=len(state.claims),
        evidence=len(state.evidence),
    )


def load_status(project_root: str | os.PathLike[str] | None = None) -> StatusReport:
    """Discover an initialized root, load its state, and summarize it."""

    root = _paths.discover_project_root(project_root or os.curdir)
    if root is None:
        raise _state.StateNotInitializedError("project root could not be discovered")
    state = _state.load_state(root)
    status = summarize_state(state)
    return StatusReport(
        status=status,
        root=str(root),
        state_path=str(_state.get_state_path(root)),
    )


def render_status_text(report: StatusReport) -> str:
    """Render the stable line-oriented status contract."""

    if type(report) is not StatusReport:
        raise TypeError("report must be a StatusReport")
    status = report.status
    active_task = status.active_task_id if status.active_task_id is not None else "-"
    return (
        "Evidline status\n"
        f"root: {report.root}\n"
        f"state: {report.state_path}\n"
        f"status_schema_version: {STATUS_SCHEMA_VERSION}\n"
        f"state_schema_version: {status.state_schema_version}\n"
        f"state_revision: {status.state_revision}\n"
        f"project: {status.project_name}\n"
        f"default_budget_chars: {status.default_budget_chars}\n"
        f"active_task: {active_task}\n"
        f"invariants: {status.invariants} (active {status.active_invariants})\n"
        f"decisions: {status.decisions}\n"
        f"tasks: {status.tasks}\n"
        f"claims: {status.claims}\n"
        f"evidence: {status.evidence}\n"
    )


def render_status_json(report: StatusReport) -> str:
    """Render the stable status JSON contract."""

    if type(report) is not StatusReport:
        raise TypeError("report must be a StatusReport")
    status = report.status
    payload = {
        "status_schema_version": STATUS_SCHEMA_VERSION,
        "state_schema_version": status.state_schema_version,
        "state_revision": status.state_revision,
        "root": report.root,
        "state_path": report.state_path,
        "project_name": status.project_name,
        "default_budget_chars": status.default_budget_chars,
        "active_task_id": status.active_task_id,
        "active_invariants": status.active_invariants,
        "counts": {
            "invariants": status.invariants,
            "decisions": status.decisions,
            "tasks": status.tasks,
            "claims": status.claims,
            "evidence": status.evidence,
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
