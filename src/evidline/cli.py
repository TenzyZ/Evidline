"""Command-line interface for Evidline."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import os
import sys

from evidline import __version__
from evidline import mutation
from evidline import state
from evidline import status
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

_CONTEXT_FORMATS = ("payload", "report", "json")
_STATUS_FORMATS = ("text", "json")
_DEFAULT_PURPOSE = "Purpose not yet stated."
_DEFAULT_BUDGET = 8000
_INSPECTION_NOTICE = (
    "evidline: inspection only — not permission, not execution, not enforcement; "
    "ALLOW means justified under Evidline policy, not permitted by the harness or OS."
)


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
    parser = argparse.ArgumentParser(prog="evidline")
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
        print(f"evidline: invalid initialization input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    name = args.name if args.name is not None else root.name
    if not name:
        print("evidline: invalid initialization input: project name is empty", file=sys.stderr)
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
            print(f"evidline: state not initialized: {exc}", file=sys.stderr)
            return _EXIT_NOT_INITIALIZED
        except state.StateValidationError as exc:
            print(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
            return _EXIT_INVALID_STATE
        except state.StateIOError as exc:
            print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
            return _EXIT_STATE_IO
        print(f"already initialized: {state_path} (unchanged)")
        return 0
    except state.StateValidationError as exc:
        print(f"evidline: invalid initialization input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO

    try:
        state_path = state.get_state_path(root)
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    print(f"initialized: {state_path}")
    return 0


def _run_status(args: argparse.Namespace) -> int:
    try:
        report = status.load_status(args.root or os.curdir)
    except state.StateNotInitializedError as exc:
        print(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        print(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    renderer = (
        status.render_status_json
        if args.format == "json"
        else status.render_status_text
    )
    sys.stdout.write(renderer(report))
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
        print(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        print(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    except ContextInputError as exc:
        print(f"evidline: invalid compiler input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT

    if args.format == "report":
        sys.stdout.write(render_report(context))
    elif args.format == "json":
        sys.stdout.write(render_json(context))
    else:
        sys.stdout.write(render_payload(context))
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
    print(_INSPECTION_NOTICE, file=sys.stderr)
    try:
        decision = mutation.load_and_decide(
            args.root or os.curdir,
            request,
            args.target,
        )
    except state.StateNotInitializedError as exc:
        print(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except state.StateValidationError as exc:
        print(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except state.StateIOError as exc:
        print(f"evidline: state I/O failure: {exc}", file=sys.stderr)
        return _EXIT_STATE_IO
    except mutation.MutationInputError as exc:
        print(f"evidline: invalid mutation input: {exc}", file=sys.stderr)
        return _EXIT_INVALID_INPUT
    except Exception:
        print("evidline: internal failure; treat as BLOCK", file=sys.stderr)
        return _EXIT_INTERNAL_FAILURE

    if args.format == "json":
        sys.stdout.write(mutation.render_decision_json(decision))
    else:
        sys.stdout.write(mutation.explain(decision) + "\n")
    return {
        mutation.MutationOutcome.ALLOW: 0,
        mutation.MutationOutcome.ASK: _EXIT_POLICY_ASK,
        mutation.MutationOutcome.BLOCK: _EXIT_POLICY_BLOCK,
    }[decision.outcome]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        sys.stderr.write(parser.format_help())
        return _EXIT_USAGE
    if args.command == "init":
        return _run_init(args)
    if args.command == "status":
        return _run_status(args)
    if args.command == "context":
        return _run_context(args)
    if args.command == "check-mutation":
        return _run_check_mutation(args)
    return _EXIT_USAGE
