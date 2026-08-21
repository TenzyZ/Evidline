"""Command-line interface for Evidline."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import TextIO

from evidline import __version__
from evidline import doctor
from evidline import mutation
from evidline import paths
from evidline import state
from evidline import status
from evidline import transport
from evidline.context import (
    PAYLOAD_CHROME_CHARS,
    ContextInputError,
    ContextProfile,
    load_and_compile,
    render_json,
    render_payload,
    render_report,
)


# Exit codes: 0 success/policy ALLOW, 2 argparse usage,
# 3 state not initialized, 4 invalid/unsupported state, 5 state I/O failure,
# 6 invalid input, 7 internal decision-path failure, 10 ASK, 11 BLOCK.
_EXIT_USAGE = 2
_EXIT_NOT_INITIALIZED = 3
_EXIT_INVALID_STATE = 4
_EXIT_STATE_IO = 5
_EXIT_INVALID_INPUT = 6
_EXIT_INTERNAL_FAILURE = 7
_EXIT_POLICY_ASK = 10
_EXIT_POLICY_BLOCK = 11
_EXIT_DOCTOR_UNHEALTHY = 20

_CONTEXT_FORMATS = ("payload", "report", "json")
_STATUS_FORMATS = ("text", "json")
_DOCTOR_FORMATS = ("text", "json")
_DEFAULT_PURPOSE = "Purpose not yet stated."
_DEFAULT_BUDGET = 8000
_INSPECTION_NOTICE = (
    "evidline: inspection only — not permission, not execution, not enforcement; "
    "ALLOW means justified under Evidline policy, not permitted by the harness or OS."
)


def _print_stdout(text: str, *, end: str = "\n", flush: bool = False) -> None:
    transport.write_stdout(text + end, flush=flush)


def _print_stderr(
    text: object,
    *,
    file: TextIO | None = None,
    end: str = "\n",
    flush: bool = False,
) -> None:
    if file is not None and file is not sys.stderr:
        raise ValueError("CLI diagnostics may only be written to stderr")
    try:
        transport.write_stderr(str(text) + end, flush=flush)
    except Exception:
        pass


class _Utf8ArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message: str, file=None) -> None:
        if not message:
            return
        if file is None or file is sys.stderr:
            _print_stderr(message, end="", flush=True)
            return
        if file is sys.stdout:
            transport.write_stdout(message, flush=True)
            return
        super()._print_message(message, file)


def _positive_integer(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("budget must be a positive integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("budget must be a positive integer")
    return value


def _initialization_budget(text: str) -> int:
    value = _positive_integer(text)
    minimum = max(PAYLOAD_CHROME_CHARS.values())
    if value < minimum:
        raise argparse.ArgumentTypeError(f"budget must be at least {minimum}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = _Utf8ArgumentParser(prog="evidline")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="initialize local Evidline state")
    init_parser.add_argument("--root", default=os.curdir, metavar="PATH")
    init_parser.add_argument("--name", metavar="NAME")
    init_parser.add_argument("--purpose", default=_DEFAULT_PURPOSE, metavar="TEXT")
    init_parser.add_argument(
        "--budget",
        type=_initialization_budget,
        default=_DEFAULT_BUDGET,
        metavar="CHARS",
    )

    status_parser = subparsers.add_parser("status", help="summarize local state")
    status_parser.add_argument("--root", metavar="PATH")
    status_parser.add_argument(
        "--format", choices=_STATUS_FORMATS, default="text"
    )

    doctor_parser = subparsers.add_parser("doctor", help="diagnose local project health")
    doctor_parser.add_argument("--root", metavar="PATH")
    doctor_parser.add_argument("--format", choices=_DOCTOR_FORMATS, default="text")

    approve_parser = subparsers.add_parser(
        "approve", help="interactively authorize one task for bounded paths"
    )
    approve_parser.add_argument("task_id", metavar="TASK_ID")
    approve_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        metavar="ROOT_RELATIVE_PATH",
    )
    approve_parser.add_argument(
        "--acknowledge",
        action="append",
        metavar="INVARIANT_ID",
    )
    approve_parser.add_argument("--root", metavar="PATH")

    add_task_parser = subparsers.add_parser(
        "add-task", help="create an unapproved Task"
    )
    add_task_parser.add_argument("--id", required=True, metavar="TASK_ID")
    add_task_parser.add_argument("--description", required=True, metavar="TEXT")
    add_task_parser.add_argument("--related-id", action="append", metavar="RECORD_ID")
    add_task_parser.add_argument("--root", metavar="PATH")

    add_invariant_parser = subparsers.add_parser(
        "add-invariant", help="create an active Invariant"
    )
    add_invariant_parser.add_argument("--id", required=True, metavar="INVARIANT_ID")
    add_invariant_parser.add_argument(
        "--description", required=True, metavar="TEXT"
    )
    add_invariant_parser.add_argument(
        "--enforcement",
        required=True,
        choices=[item.value for item in state.InvariantEnforcement],
    )
    add_invariant_parser.add_argument(
        "--governed-scope",
        action="append",
        metavar="ROOT_RELATIVE_PATH",
    )
    add_invariant_parser.add_argument("--root", metavar="PATH")

    context_parser = subparsers.add_parser(
        "context", help="compile bounded context from local state"
    )
    context_parser.add_argument(
        "--profile",
        choices=[profile.value for profile in ContextProfile],
        default=ContextProfile.SESSION.value,
        help="output profile (default: session)",
    )
    context_parser.add_argument(
        "--budget",
        type=_positive_integer,
        metavar="CHARS",
        help="payload character budget (positive integer)",
    )
    context_parser.add_argument(
        "--format",
        choices=_CONTEXT_FORMATS,
        default="payload",
        help="output format (default: payload)",
    )
    context_parser.add_argument(
        "--root",
        metavar="PATH",
        help="project root (default: nearest ancestor with .evidline)",
    )

    check_parser = subparsers.add_parser(
        "check-mutation", help="inspect one proposed mutation"
    )
    check_parser.add_argument("--target", required=True, metavar="PATH")
    check_parser.add_argument(
        "--risk",
        required=True,
        choices=[risk.value for risk in mutation.MutationRisk],
    )
    check_parser.add_argument(
        "--intent",
        choices=[intent.value for intent in state.Intent],
        default=state.Intent.PROPOSED.value,
    )
    check_parser.add_argument(
        "--operation",
        choices=[operation.value for operation in mutation.MutationOperation],
    )
    check_parser.add_argument("--authorizing-id", action="append")
    check_parser.add_argument("--scope", action="append")
    check_parser.add_argument("--supporting-claim-id", action="append")
    check_parser.add_argument("--ephemeral-evidence-id", action="append")
    check_parser.add_argument("--conflicting-invariant-id", action="append")
    check_parser.add_argument("--root", metavar="PATH")
    check_parser.add_argument(
        "--format", choices=_STATUS_FORMATS, default="text"
    )
    return parser


def _run_init(args: argparse.Namespace) -> int:
    try:
        root = state.resolve_initialization_root(args.root)
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid initialization input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    name = args.name if args.name is not None else root.name
    if not name:
        _print_stderr("evidline: invalid initialization input: project name is empty", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    project = state.Project(
        name=name,
        purpose=args.purpose,
        ignore_globs=(),
        default_budget_chars=args.budget,
    )
    try:
        state.initialize_project(root, project=project)
    except state.StateAlreadyInitializedError:
        try:
            state.load_state(root)
            state_path = state.get_state_path(root)
        except state.StateNotInitializedError as exc:
            _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
            return _EXIT_NOT_INITIALIZED
        except state.StateValidationError as exc:
            _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
            return _EXIT_INVALID_STATE
        except state.StateIOError as exc:
            _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
            return _EXIT_STATE_IO
        _print_stdout(f"already initialized: {state_path} (unchanged)")
        return 0
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid initialization input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    try:
        state_path = state.get_state_path(root)
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    _print_stdout(f"initialized: {state_path}")
    return 0


def _run_status(args: argparse.Namespace) -> int:
    try:
        report = status.load_status(args.root or os.curdir)
    except state.StateNotInitializedError as exc:
        _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    renderer = (
        status.render_status_json
        if args.format == "json"
        else status.render_status_text
    )
    transport.write_stdout(renderer(report), flush=True)
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    try:
        report = doctor.run_diagnostics(args.root or os.curdir)
        renderer = doctor.render_doctor_json if args.format == "json" else doctor.render_doctor_text
        transport.write_stdout(renderer(report), flush=True)
        return _EXIT_DOCTOR_UNHEALTHY if report.overall_status is doctor.OverallStatus.UNHEALTHY else 0
    except Exception as exc:
        _print_stderr(f"evidline: doctor internal failure: {exc}", file=sys.stderr)
        return _EXIT_INTERNAL_FAILURE


def _discover_root_or_error(root_argument: str | None) -> Path | None:
    root = paths.discover_project_root(root_argument or os.curdir)
    if root is None:
        _print_stderr("evidline: state not initialized: project root not found", file=sys.stderr)
    return root


def _load_current_state_or_error(
    root: Path,
) -> tuple[state.StateDocument | None, int]:
    try:
        return state.load_state(root), 0
    except state.StateNotInitializedError as exc:
        _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return None, _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return None, _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return None, _EXIT_STATE_IO


def _commit_proposed_state(
    root: Path,
    current: state.StateDocument,
    proposed: state.StateDocument,
) -> tuple[state.StateDocument | None, int]:
    try:
        state.validate_state(proposed)
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid proposed state: {exc}", file=sys.stderr)
        return None, _EXIT_INVALID_INPUT
    try:
        return state.write_state(root, proposed, expected_revision=current.revision), 0
    except state.StateConflictError as exc:
        _print_stderr(f"evidline: state write conflict: {exc}", file=sys.stderr)
        return None, _EXIT_STATE_IO
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid proposed state: {exc}", file=sys.stderr)
        return None, _EXIT_INVALID_INPUT
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return None, _EXIT_STATE_IO


def _print_scope_lines(label: str, values: tuple[str, ...]) -> None:
    _print_stdout(f"{label}:")
    if not values:
        _print_stdout("- (none)")
        return
    for value in values:
        _print_stdout(f"- {value}")


def _run_add_task(args: argparse.Namespace) -> int:
    related_ids = tuple(args.related_id or ())
    if any(not record_id for record_id in related_ids):
        _print_stderr("evidline: invalid related id: id must be non-empty", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    if len(set(related_ids)) != len(related_ids):
        _print_stderr("evidline: invalid related id: duplicate record id", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    root = _discover_root_or_error(args.root)
    if root is None:
        return _EXIT_NOT_INITIALIZED
    current, error_code = _load_current_state_or_error(root)
    if current is None:
        return error_code
    all_record_ids = {
        item.id
        for records in (
            current.invariants,
            current.decisions,
            current.tasks,
            current.claims,
            current.evidence,
        )
        for item in records
    }
    if args.id in all_record_ids:
        _print_stderr(f"evidline: duplicate record id: {args.id}", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    record = state.Task(
        id=args.id,
        description=args.description,
        status=state.TaskStatus.DRAFT,
        intent=state.Intent.PROPOSED,
        execution=state.Execution.NOT_RUN,
        related_ids=related_ids,
    )
    updated, error_code = _commit_proposed_state(
        root,
        current,
        replace(current, tasks=current.tasks + (record,)),
    )
    if updated is None:
        return error_code

    _print_stdout(f"created: {record.id}")
    _print_stdout(f"state_revision: {updated.revision}")
    _print_stdout(f"status: {record.status.value}")
    _print_stdout(f"intent: {record.intent.value}")
    _print_stdout(f"execution: {record.execution.value}")
    _print_scope_lines("related_ids", record.related_ids)
    _print_scope_lines("authorized_scope", record.authorized_scope)
    _print_scope_lines(
        "acknowledged_invariant_ids", record.acknowledged_invariant_ids
    )
    _print_stdout("approval: (none)")
    _print_stdout(f"next: evidline approve {record.id} --scope ROOT_RELATIVE_PATH")
    return 0


def _run_add_invariant(args: argparse.Namespace) -> int:
    try:
        governed_scope = tuple(
            paths.normalize_root_relative_scope(value)
            for value in (args.governed_scope or ())
        )
    except ValueError as exc:
        _print_stderr(f"evidline: invalid governed scope: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    if len(set(governed_scope)) != len(governed_scope):
        _print_stderr(
            "evidline: invalid governed scope: duplicate normalized scope",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT

    root = _discover_root_or_error(args.root)
    if root is None:
        return _EXIT_NOT_INITIALIZED
    current, error_code = _load_current_state_or_error(root)
    if current is None:
        return error_code
    if (
        governed_scope
        and current.scope_semantics is not paths.host_scope_semantics()
    ):
        _print_stderr(
            "evidline: invalid governed scope: cannot author native scope under "
            "foreign scope_semantics; use the interactive approve ceremony to restamp",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT
    all_record_ids = {
        item.id
        for records in (
            current.invariants,
            current.decisions,
            current.tasks,
            current.claims,
            current.evidence,
        )
        for item in records
    }
    if args.id in all_record_ids:
        _print_stderr(f"evidline: duplicate record id: {args.id}", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    record = state.Invariant(
        id=args.id,
        description=args.description,
        enforcement=state.InvariantEnforcement(args.enforcement),
        status=state.InvariantStatus.ACTIVE,
        governed_scope=governed_scope,
    )
    updated, error_code = _commit_proposed_state(
        root,
        current,
        replace(current, invariants=current.invariants + (record,)),
    )
    if updated is None:
        return error_code

    scope_meaning = (
        "NO_TARGET_BINDING"
        if not record.governed_scope
        else "WHOLE_REPOSITORY"
        if "." in record.governed_scope
        else "GOVERNED_PREFIXES"
    )
    _print_stdout(f"created: {record.id}")
    _print_stdout(f"state_revision: {updated.revision}")
    _print_stdout(f"enforcement: {record.enforcement.value}")
    _print_stdout(f"status: {record.status.value}")
    _print_scope_lines("governed_scope", record.governed_scope)
    _print_stdout(f"governed_scope_meaning: {scope_meaning}")
    _print_stdout("approval: (none)")
    return 0


def _print_acknowledgements(
    acknowledged_ids: tuple[str, ...],
    invariants_by_id: dict[str, state.Invariant],
) -> None:
    _print_stdout("acknowledged_invariant_ids:")
    if not acknowledged_ids:
        _print_stdout("- (none)")
        return
    for invariant_id in acknowledged_ids:
        invariant = invariants_by_id[invariant_id]
        inert = (
            invariant.enforcement is state.InvariantEnforcement.ADVISE
            or invariant.status is state.InvariantStatus.SUPERSEDED
        )
        annotation = ", inert" if inert else ""
        _print_stdout(
            f"- {invariant_id} (enforcement={invariant.enforcement.value}, "
            f"status={invariant.status.value}{annotation})"
        )


def _run_approve(args: argparse.Namespace) -> int:
    try:
        normalized_scope = tuple(
            paths.normalize_root_relative_scope(value) for value in args.scope
        )
    except ValueError as exc:
        _print_stderr(f"evidline: invalid approval scope: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    if len(set(normalized_scope)) != len(normalized_scope):
        _print_stderr(
            "evidline: invalid approval scope: duplicate normalized scope",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT
    acknowledged_ids = tuple(args.acknowledge or ())
    if any(not invariant_id for invariant_id in acknowledged_ids):
        _print_stderr(
            "evidline: invalid approval acknowledgement: id must be non-empty",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT
    if len(set(acknowledged_ids)) != len(acknowledged_ids):
        _print_stderr(
            "evidline: invalid approval acknowledgement: duplicate invariant id",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        _print_stderr(
            "evidline: approval requires interactive TTY input and output; "
            "TTY is defense-in-depth, not proof of human identity",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT

    root = paths.discover_project_root(args.root or os.curdir)
    if root is None:
        _print_stderr("evidline: state not initialized: project root not found", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    try:
        current = state.load_state(root)
    except state.StateNotInitializedError as exc:
        _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    invariants_by_id = {item.id: item for item in current.invariants}
    all_record_ids = {
        item.id
        for records in (
            current.invariants,
            current.decisions,
            current.tasks,
            current.claims,
            current.evidence,
        )
        for item in records
    }
    for invariant_id in acknowledged_ids:
        if invariant_id in invariants_by_id:
            continue
        if invariant_id in all_record_ids:
            _print_stderr(
                "evidline: invalid approval acknowledgement: id does not "
                f"resolve to an Invariant: {invariant_id}",
                file=sys.stderr,
            )
        else:
            _print_stderr(
                "evidline: invalid approval acknowledgement: unknown "
                f"invariant id: {invariant_id}",
                file=sys.stderr,
            )
        return _EXIT_INVALID_INPUT

    selected = next((task for task in current.tasks if task.id == args.task_id), None)
    if selected is None:
        _print_stderr(f"evidline: approval task not found: {args.task_id}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    if selected.status is state.TaskStatus.DONE:
        _print_stderr("evidline: DONE task cannot be approved", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    if selected.intent is state.Intent.DENIED:
        _print_stderr("evidline: DENIED task cannot be approved", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    existing_active = next(
        (
            task
            for task in current.tasks
            if task.status is state.TaskStatus.ACTIVE and task.id != selected.id
        ),
        None,
    )
    if existing_active is not None:
        _print_stderr(
            f"evidline: another task is already ACTIVE: {existing_active.id}",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT

    host_semantics = paths.host_scope_semantics()
    semantics_changed = current.scope_semantics is not host_semantics
    if semantics_changed and (
        any(task.authorized_scope for task in current.tasks)
        or any(invariant.governed_scope for invariant in current.invariants)
    ):
        _print_stderr(
            "evidline: approval cannot reinterpret foreign non-empty scopes",
            file=sys.stderr,
        )
        return _EXIT_INVALID_INPUT

    approved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    approved_task = replace(
        selected,
        status=state.TaskStatus.ACTIVE,
        intent=state.Intent.AUTHORIZED,
        authorized_scope=normalized_scope,
        approved_at=approved_at,
        approval_channel=state.TRUSTED_APPROVAL_CHANNEL,
        asserted_actor=state.TRUSTED_ASSERTED_ACTOR,
        acknowledged_invariant_ids=acknowledged_ids,
    )
    proposed = replace(
        current,
        tasks=tuple(
            approved_task if task.id == selected.id else task
            for task in current.tasks
        ),
        scope_semantics=host_semantics if semantics_changed else current.scope_semantics,
    )
    try:
        state.validate_state(proposed)
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: approval transition is invalid: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    _print_stdout("Evidline bounded task approval")
    _print_stdout(f"task: {approved_task.id}")
    _print_stdout(f"task_description: {approved_task.description}")
    _print_stdout("authorized_scope:")
    for scope in approved_task.authorized_scope:
        _print_stdout(f"- {scope}")
    _print_acknowledgements(acknowledged_ids, invariants_by_id)
    if semantics_changed:
        _print_stdout(
            "scope_semantics: "
            f"{current.scope_semantics.value} -> {host_semantics.value}"
        )
    _print_stdout("TTY interactivity is defense-in-depth, not proof of human identity.")
    _print_stdout(
        f"Type {approved_task.id} to approve, or anything else to cancel: ",
        end="",
        flush=True,
    )
    confirmation = sys.stdin.readline()
    if confirmation.rstrip("\r\n") != approved_task.id:
        _print_stdout("approval cancelled; state unchanged")
        return _EXIT_INVALID_INPUT

    try:
        updated = state.write_state(
            root, proposed, expected_revision=current.revision
        )
    except state.StateConflictError as exc:
        _print_stderr(f"evidline: state write conflict: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid approval state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    _print_stdout(f"approved: {approved_task.id}")
    _print_stdout(f"state_revision: {updated.revision}")
    _print_stdout("authorized_scope:")
    for scope in approved_task.authorized_scope:
        _print_stdout(f"- {scope}")
    _print_acknowledgements(acknowledged_ids, invariants_by_id)
    return 0


def _run_context(args: argparse.Namespace) -> int:
    try:
        profile = ContextProfile(args.profile)
        budget = args.budget
        if budget is None:
            context = load_and_compile(args.root, profile=profile)
        else:
            context = load_and_compile(args.root, profile=profile, budget_chars=budget)
    except state.StateNotInitializedError as exc:
        _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    except ContextInputError as exc:
        _print_stderr(f"evidline: invalid compiler input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    if args.format == "report":
        transport.write_stdout(render_report(context), flush=True)
    elif args.format == "json":
        transport.write_stdout(render_json(context), flush=True)
    else:
        transport.write_stdout(render_payload(context), flush=True)
    return 0


def _run_check_mutation(args: argparse.Namespace) -> int:
    request = mutation.MutationRequest(
        request_intent=state.Intent(args.intent),
        risk=mutation.MutationRisk(args.risk),
        operation=(
            mutation.MutationOperation(args.operation)
            if args.operation is not None
            else None
        ),
        authorizing_ids=tuple(args.authorizing_id or ()),
        declared_scope=tuple(args.scope or ()),
        supporting_claim_ids=tuple(args.supporting_claim_id or ()),
        ephemeral_evidence_ids=tuple(args.ephemeral_evidence_id or ()),
        asserted_conflicting_invariant_ids=tuple(
            args.conflicting_invariant_id or ()
        ),
    )
    _print_stderr(_INSPECTION_NOTICE, file=sys.stderr)
    try:
        decision = mutation.load_and_decide(
            args.root or os.curdir,
            request,
            args.target,
        )
    except state.StateNotInitializedError as exc:
        _print_stderr(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        _print_stderr(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        _print_stderr(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    except mutation.MutationInputError as exc:
        _print_stderr(f"evidline: invalid mutation input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except Exception:
        _print_stderr("evidline: internal failure; treat as BLOCK", file=sys.stderr)
        return _EXIT_INTERNAL_FAILURE

    if args.format == "json":
        transport.write_stdout(mutation.render_decision_json(decision), flush=True)
    else:
        transport.write_stdout(mutation.explain(decision) + "\n", flush=True)
    return {
        mutation.MutationOutcome.ALLOW: 0,
        mutation.MutationOutcome.ASK: _EXIT_POLICY_ASK,
        mutation.MutationOutcome.BLOCK: _EXIT_POLICY_BLOCK,
    }[decision.outcome]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        _print_stderr(parser.format_help(), end="")
        return _EXIT_USAGE
    if args.command == "init":
        return _run_init(args)
    if args.command == "status":
        return _run_status(args)
    if args.command == "doctor":
        return _run_doctor(args)
    if args.command == "approve":
        return _run_approve(args)
    if args.command == "add-task":
        return _run_add_task(args)
    if args.command == "add-invariant":
        return _run_add_invariant(args)
    if args.command == "context":
        return _run_context(args)
    if args.command == "check-mutation":
        return _run_check_mutation(args)
    return _EXIT_USAGE
