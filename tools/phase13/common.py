"""Shared deterministic helpers for Phase 13 tooling."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


class Phase13Error(ValueError):
    """A Phase 13 tool received invalid input or could not complete safely."""


def utc_now() -> str:
    """Return a second-precision UTC timestamp."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of *data*."""

    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return the hex SHA-256 digest of UTF-8 *text*."""

    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of an existing file."""

    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> Any:
    """Load a JSON document from *path*."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise Phase13Error(f"input not found: {path}") from error
    except json.JSONDecodeError as error:
        raise Phase13Error(f"invalid JSON: {path}: {error}") from error


def dump_json(document: Mapping[str, Any] | list[Any]) -> str:
    """Render deterministic JSON with a trailing newline."""

    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def write_json(
    path: str | Path, document: Mapping[str, Any] | list[Any]
) -> None:
    """Write deterministic JSON to *path*."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_json(document), encoding="utf-8")


def as_mapping(value: Any, *, what: str) -> Mapping[str, Any]:
    """Require a JSON object."""

    if not isinstance(value, Mapping):
        raise Phase13Error(f"{what} must be a JSON object")
    return value


def require_text(value: Any, *, what: str) -> str:
    """Require a non-empty string."""

    if not isinstance(value, str) or not value:
        raise Phase13Error(f"{what} must be a non-empty string")
    return value
