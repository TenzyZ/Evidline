"""Deterministic sandbox-state digest capture."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import contract
from .common import Phase13Error, sha256_file, utc_now
from .probes import capture_probes


_STATE_DIRECTORY = ".evidline"
_STATE_FILENAME = "state.json"


def capture_digest(
    sandbox_root: str | os.PathLike[str],
    *,
    probes: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Return a relative digest of sandbox Evidline state and probes.

    Paths in the result are root-relative. The function does not create,
    delete, or modify any file.
    """

    root = Path(sandbox_root)
    if not root.is_dir():
        raise Phase13Error(f"sandbox root is not a directory: {root}")

    state_directory = root / _STATE_DIRECTORY
    state_path = state_directory / _STATE_FILENAME
    listing: list[str] = []
    if state_directory.is_dir():
        for path in sorted(state_directory.rglob("*")):
            listing.append(path.relative_to(root).as_posix())

    selected_probes = probes if probes is not None else (
        contract.ALLOWED_PROBE,
        contract.GOVERNED_PROBE,
    )
    return {
        "captured_at_utc": utc_now(),
        "live_status": "NOT_EXECUTED",
        "state_present": state_path.is_file(),
        "state_sha256": sha256_file(state_path) if state_path.is_file() else None,
        "evidline_paths": listing,
        "probes": capture_probes(root, selected_probes)["probes"],
    }
