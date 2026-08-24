"""Before/after capture for parameterized probe paths."""

from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path
from typing import Any

from .common import Phase13Error, sha256_file, utc_now


def capture_probes(
    root: str | os.PathLike[str],
    relative_paths: Sequence[str],
) -> dict[str, Any]:
    """Capture existence and content digest for each relative probe path.

    This function never creates probe files.
    """

    base = Path(root)
    if not base.is_dir():
        raise Phase13Error(f"probe root is not a directory: {base}")
    if not relative_paths:
        raise Phase13Error("at least one relative probe path is required")

    captured: list[dict[str, Any]] = []
    for relative in relative_paths:
        captured.append(_capture_one(base, relative))
    return {
        "captured_at_utc": utc_now(),
        "live_status": "NOT_EXECUTED",
        "probes": captured,
    }


def compare_probes(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Compare two probe captures by relative path."""

    before_map = {
        item["relative_path"]: item for item in before.get("probes", ())
    }
    after_map = {item["relative_path"]: item for item in after.get("probes", ())}
    names = sorted(set(before_map) | set(after_map))
    comparisons: list[dict[str, Any]] = []
    for name in names:
        previous = before_map.get(name)
        current = after_map.get(name)
        existed_before = bool(previous and previous.get("exists"))
        existed_after = bool(current and current.get("exists"))
        comparisons.append(
            {
                "relative_path": name,
                "existed_before": existed_before,
                "existed_after": existed_after,
                "changed": previous != current,
                "digest_before": None if previous is None else previous.get("sha256"),
                "digest_after": None if current is None else current.get("sha256"),
            }
        )
    return {
        "captured_at_utc": utc_now(),
        "comparisons": comparisons,
    }


def _capture_one(root: Path, relative: str) -> dict[str, Any]:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise Phase13Error(f"probe path must be a root-relative file: {relative}")
    path = root.joinpath(*Path(relative).parts)
    exists = path.exists()
    is_file = path.is_file()
    digest = sha256_file(path) if is_file else None
    size = path.stat().st_size if is_file else None
    return {
        "relative_path": Path(relative).as_posix(),
        "exists": exists,
        "is_file": is_file,
        "sha256": digest,
        "size": size,
    }
