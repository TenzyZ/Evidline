"""Read-only repository and runtime preflight capture."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from .common import Phase13Error, utc_now


_GIT_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("git", "branch", "--show-current"),
    ("git", "rev-parse", "HEAD"),
    ("git", "rev-parse", "main"),
    ("git", "rev-parse", "origin/main"),
    ("git", "status", "--short"),
    ("git", "diff", "--check"),
)


def capture_preflight(repo_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Capture a read-only checkpoint for *repo_root*.

    Git commands are executed only inside the supplied root. This function
    never runs fetch, pull, reset, checkout, switch, or merge.
    """

    root = Path(repo_root)
    if not root.is_dir():
        raise Phase13Error(f"repo root is not a directory: {root}")

    commands: dict[str, Mapping[str, Any]] = {}
    for arguments in _GIT_COMMANDS:
        commands[" ".join(arguments)] = _run_git(root, arguments)

    return {
        "captured_at_utc": utc_now(),
        "live_status": "NOT_EXECUTED",
        "repo_root_kind": "parameter",
        "python_executable_kind": "sys.executable",
        "python_version": sys.version.split()[0],
        "git": commands,
    }


def _run_git(root: Path, arguments: tuple[str, ...]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            arguments,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        return {
            "exit_code": None,
            "stdout": "",
            "stderr": str(error),
            "error": "git_unavailable",
        }
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
