"""Parameterized command-line entry for Phase 13 helpers."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys
from typing import Any

from .common import Phase13Error, dump_json, load_json, sha256_file, sha256_text, write_json
from .digest import capture_digest
from .evidence import generate_evidence_record
from .preflight import capture_preflight
from .probes import capture_probes, compare_probes
from .rollback import apply_rollback, inspect_rollback
from .sanitize import sanitize_document


def main(argv: Sequence[str] | None = None) -> int:
    """Run one Phase 13 helper command."""

    parser = _build_parser()
    arguments = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = _dispatch(arguments)
    except Phase13Error as error:
        print(f"phase13: {error}", file=sys.stderr)
        return 1
    rendered = dump_json(document)
    if arguments.output:
        write_json(arguments.output, document)
    else:
        sys.stdout.write(rendered)
    return 0


def _dispatch(arguments: argparse.Namespace) -> dict[str, Any]:
    command = arguments.command
    if command == "preflight":
        return capture_preflight(arguments.repo_root)
    if command == "digest":
        probes = tuple(arguments.probe or ())
        return capture_digest(
            arguments.root,
            probes=probes or None,
        )
    if command == "probes":
        return capture_probes(arguments.root, tuple(arguments.probe))
    if command == "compare-probes":
        return compare_probes(load_json(arguments.before), load_json(arguments.after))
    if command == "sanitize":
        nonce = None
        if arguments.nonce_file is not None:
            nonce = arguments.nonce_file.read_text(encoding="utf-8").rstrip("\r\n")
        homes = tuple(arguments.home_prefix or ())
        sanitized = sanitize_document(
            load_json(arguments.input),
            nonce=nonce,
            root=arguments.root,
            home_prefixes=homes,
        )
        if not isinstance(sanitized, dict):
            raise Phase13Error("sanitize input must be a JSON object")
        return sanitized
    if command == "evidence":
        loaded = load_json(arguments.input)
        if not isinstance(loaded, dict):
            raise Phase13Error("evidence input must be a JSON object")
        document = dict(loaded)
        _apply_evidence_bindings(document, arguments)
        nonce = None
        if arguments.nonce_file is not None:
            nonce = arguments.nonce_file.read_text(encoding="utf-8").rstrip("\r\n")
        return generate_evidence_record(document, nonce=nonce)
    if command == "rollback":
        plan = load_json(arguments.plan)
        if not isinstance(plan, dict):
            raise Phase13Error("rollback plan must be a JSON object")
        if arguments.apply:
            if not arguments.sandbox_root:
                raise Phase13Error("--apply requires --sandbox-root")
            return apply_rollback(
                plan,
                sandbox_root=arguments.sandbox_root,
                dry_run=False,
            )
        if arguments.sandbox_root:
            return apply_rollback(
                plan,
                sandbox_root=arguments.sandbox_root,
                dry_run=True,
            )
        return inspect_rollback(plan, sandbox_root=arguments.sandbox_root)
    raise Phase13Error(f"unknown command: {command}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phase13",
        description="Deterministic Phase 13 live-verification helpers.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight", help="capture a read-only repo checkpoint")
    preflight.add_argument("--repo-root", required=True)
    _add_output(preflight)

    digest = subparsers.add_parser("digest", help="digest sandbox state and probes")
    digest.add_argument("--root", required=True)
    digest.add_argument("--probe", action="append")
    _add_output(digest)

    probes = subparsers.add_parser("probes", help="capture probe before/after state")
    probes.add_argument("--root", required=True)
    probes.add_argument("--probe", action="append", required=True)
    _add_output(probes)

    compare = subparsers.add_parser("compare-probes", help="compare two probe captures")
    compare.add_argument("--before", required=True, type=_existing_file)
    compare.add_argument("--after", required=True, type=_existing_file)
    _add_output(compare)

    sanitize = subparsers.add_parser("sanitize", help="sanitize a raw event document")
    sanitize.add_argument("--input", required=True, type=_existing_file)
    sanitize.add_argument("--nonce-file", type=_existing_file)
    sanitize.add_argument("--root")
    sanitize.add_argument("--home-prefix", action="append")
    _add_output(sanitize)

    evidence = subparsers.add_parser("evidence", help="build a sanitized evidence record")
    evidence.add_argument("--input", required=True, type=_existing_file)
    evidence.add_argument("--nonce-file", type=_existing_file)
    evidence.add_argument("--claim")
    evidence.add_argument("--raw-capture", type=_existing_file)
    evidence.add_argument("--context-payload", type=_existing_file)
    evidence.add_argument("--session-id-file", type=_existing_file)
    evidence.add_argument("--tool-use-id-file", type=_existing_file)
    evidence.add_argument("--enabled-raw-capture", type=_existing_file)
    evidence.add_argument("--control-raw-capture", type=_existing_file)
    evidence.add_argument("--enabled-answer-file", type=_existing_file)
    evidence.add_argument("--control-answer-file", type=_existing_file)
    evidence.add_argument("--enabled-session-id-file", type=_existing_file)
    evidence.add_argument("--control-session-id-file", type=_existing_file)
    _add_output(evidence)

    rollback = subparsers.add_parser(
        "rollback",
        help="inspect or dry-run sandbox rollback; apply is explicit",
    )
    rollback.add_argument("--plan", required=True, type=_existing_file)
    rollback.add_argument("--sandbox-root")
    rollback.add_argument(
        "--apply",
        action="store_true",
        help="delete sandbox_paths under --sandbox-root (never user-level paths)",
    )
    _add_output(rollback)
    return parser


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output")


def _existing_file(value: str):
    from pathlib import Path

    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"not a file: {value}")
    return path


def _digest_file_text(path) -> str:
    return sha256_text(path.read_text(encoding="utf-8").rstrip("\r\n"))


def _apply_evidence_bindings(document: dict[str, Any], arguments: argparse.Namespace) -> None:
    """Merge privacy-safe digests from files. Never echo identifier or capture text."""

    if getattr(arguments, "claim", None):
        document["claim"] = arguments.claim
    bindings = (
        ("raw_capture", "raw_capture_sha256", sha256_file),
        ("context_payload", "context_payload_sha256", sha256_file),
        ("session_id_file", "session_sha256", _digest_file_text),
        ("tool_use_id_file", "tool_use_sha256", _digest_file_text),
        ("enabled_raw_capture", "enabled_raw_capture_sha256", sha256_file),
        ("control_raw_capture", "control_raw_capture_sha256", sha256_file),
        ("enabled_answer_file", "enabled_answer_sha256", _digest_file_text),
        ("control_answer_file", "control_answer_sha256", _digest_file_text),
        ("enabled_session_id_file", "enabled_session_sha256", _digest_file_text),
        ("control_session_id_file", "control_session_sha256", _digest_file_text),
    )
    for attr, field, hasher in bindings:
        path = getattr(arguments, attr, None)
        if path is None:
            continue
        document[field] = hasher(path)
        if attr == "context_payload":
            document["context_payload_length"] = path.stat().st_size


if __name__ == "__main__":
    raise SystemExit(main())
