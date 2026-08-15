"""Foundation command-line interface for Evidline."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

from evidline import __version__
from evidline.context import (
    ContextInputError,
    ContextProfile,
    load_and_compile,
    render_json,
    render_payload,
    render_report,
)
from evidline.state import (
    StateIOError,
    StateNotInitializedError,
    StateValidationError,
)

# Exit codes: 0 success (including explicitly reported invariant overflow),
# 2 argparse usage, 3 state not initialized, 4 invalid/unsupported state,
# 5 state I/O failure, 6 invalid compiler input.
_EXIT_USAGE = 2
_EXIT_NOT_INITIALIZED = 3
_EXIT_INVALID_STATE = 4
_EXIT_STATE_IO = 5
_EXIT_INVALID_INPUT = 6

_FORMATS = ("payload", "report", "json")


def _positive_integer(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("budget must be a positive integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("budget must be a positive integer")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evidline")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
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
        choices=_FORMATS,
        default="payload",
        help="output format (default: payload)",
    )
    context_parser.add_argument(
        "--root",
        metavar="PATH",
        help="project root (default: nearest ancestor with .evidline)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "context":
        return 0

    try:
        profile = ContextProfile(args.profile)
        budget = args.budget
        if budget is None:
            context = load_and_compile(args.root, profile=profile)
        else:
            context = load_and_compile(args.root, profile=profile, budget_chars=budget)
    except StateNotInitializedError as exc:
        print(f"evidline: state not initialized: {exc}", file=sys.stderr)
        return _EXIT_NOT_INITIALIZED
    except StateValidationError as exc:
        print(f"evidline: invalid or unsupported state: {exc}", file=sys.stderr)
        return _EXIT_INVALID_STATE
    except StateIOError as exc:
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
