"""Inspection and dry-run rollback verification.

Apply is limited to paths under an explicit sandbox root. User-level
configuration is inspect-only in this pre-live tooling. This module does not
edit ``~/.codex/config.toml`` or Claude user settings.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import stat
from typing import Any

from . import contract
from .common import Phase13Error, as_mapping, utc_now

_UNSAFE_REPO_MARKERS: tuple[str, ...] = (".git", "pyproject.toml", "AGENTS.md")


def inspect_rollback(
    plan: Mapping[str, Any],
    *,
    sandbox_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Report whether planned rollback paths currently exist.

    This is inspection only. It never deletes.
    """

    document = as_mapping(plan, what="rollback plan")
    sandbox = Path(sandbox_root) if sandbox_root is not None else None
    if sandbox is not None and not sandbox.is_dir():
        raise Phase13Error(f"sandbox root is not a directory: {sandbox}")

    items: list[dict[str, Any]] = []
    for relative in _string_list(document.get("sandbox_paths"), what="sandbox_paths"):
        items.append(_inspect_sandbox_path(sandbox, relative))
    for label in _string_list(document.get("user_level_paths"), what="user_level_paths"):
        items.append(
            {
                "kind": "user_level",
                "label": label,
                "apply_supported": False,
                "note": "inspect-only; user-level apply is not implemented",
            }
        )
    result = {
        "captured_at_utc": utc_now(),
        "mode": "inspect",
        "live_status": "NOT_EXECUTED",
        "items": items,
    }
    if sandbox is not None:
        result["sandbox_guard"] = describe_sandbox_guard(sandbox)
    return result


def apply_rollback(
    plan: Mapping[str, Any],
    *,
    sandbox_root: str | os.PathLike[str],
    dry_run: bool = True,
) -> dict[str, Any]:
    """Remove planned sandbox paths, or describe that removal.

    *dry_run* defaults to True. User-level paths are never modified.
    """

    document = as_mapping(plan, what="rollback plan")
    sandbox = Path(sandbox_root)
    if not sandbox.is_dir():
        raise Phase13Error(f"sandbox root is not a directory: {sandbox}")

    if not dry_run:
        require_safe_destructive_sandbox(sandbox)

    results: list[dict[str, Any]] = []
    for relative in _string_list(document.get("sandbox_paths"), what="sandbox_paths"):
        results.append(_apply_sandbox_path(sandbox, relative, dry_run=dry_run))
    for label in _string_list(document.get("user_level_paths"), what="user_level_paths"):
        results.append(
            {
                "kind": "user_level",
                "label": label,
                "action": "skipped",
                "reason": "user-level apply is not implemented",
            }
        )
    return {
        "captured_at_utc": utc_now(),
        "mode": "dry_run" if dry_run else "apply",
        "live_status": "NOT_EXECUTED",
        "sandbox_guard": describe_sandbox_guard(sandbox),
        "items": results,
    }


def describe_sandbox_guard(sandbox: str | os.PathLike[str]) -> dict[str, Any]:
    """Report destructive-root guard status without deleting anything."""

    try:
        resolved = Path(sandbox).resolve()
    except OSError as error:
        return {
            "resolvable": False,
            "safe_for_apply": False,
            "marker_present": False,
            "reasons": [f"cannot resolve sandbox root: {error}"],
        }
    reasons = _unsafe_root_reasons(resolved)
    marker_present = (resolved / contract.SANDBOX_MARKER).exists()
    if not marker_present:
        reasons = [*reasons, f"missing {contract.SANDBOX_MARKER} marker"]
    return {
        "resolvable": True,
        "safe_for_apply": not reasons,
        "marker_present": marker_present,
        "reasons": reasons,
    }


def require_safe_destructive_sandbox(sandbox: str | os.PathLike[str]) -> Path:
    """Refuse deletion unless *sandbox* is a marked disposable Phase 13 root."""

    try:
        resolved = Path(sandbox).resolve()
    except OSError as error:
        raise Phase13Error(f"cannot resolve sandbox root: {error}") from error
    reasons = _unsafe_root_reasons(resolved)
    if reasons:
        raise Phase13Error(
            "refusing destructive rollback: " + "; ".join(reasons)
        )
    marker = resolved / contract.SANDBOX_MARKER
    if not marker.exists():
        raise Phase13Error(
            f"refusing destructive rollback: missing {contract.SANDBOX_MARKER} marker"
        )
    return resolved


def _unsafe_root_reasons(resolved: Path) -> list[str]:
    reasons: list[str] = []
    if resolved == resolved.parent or resolved == Path(resolved.anchor):
        reasons.append("filesystem root")
    try:
        home = Path.home().resolve()
    except OSError:
        home = None
    if home is not None and resolved == home:
        reasons.append("user home directory")
    for name in _UNSAFE_REPO_MARKERS:
        candidate = resolved / name
        if name == ".git" and candidate.exists():
            reasons.append("contains .git")
        elif name != ".git" and candidate.is_file():
            reasons.append(f"contains {name}")
    return reasons


def _string_list(value: Any, *, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise Phase13Error(f"{what} must be a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise Phase13Error(f"{what} entries must be non-empty strings")
        items.append(item)
    return tuple(items)


def _inspect_sandbox_path(
    sandbox: Path | None,
    relative: str,
) -> dict[str, Any]:
    _validate_relative(relative)
    if sandbox is None:
        return {
            "kind": "sandbox",
            "relative_path": relative,
            "exists": None,
            "note": "sandbox_root not supplied; path not resolved",
        }
    path = sandbox.joinpath(*Path(relative).parts)
    return {
        "kind": "sandbox",
        "relative_path": Path(relative).as_posix(),
        "exists": path.exists(),
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
    }


def _apply_sandbox_path(sandbox: Path, relative: str, *, dry_run: bool) -> dict[str, Any]:
    _validate_relative(relative)
    path = sandbox.joinpath(*Path(relative).parts)
    try:
        root = sandbox.resolve()
    except OSError as error:
        raise Phase13Error(f"cannot resolve rollback path: {relative}: {error}") from error
    try:
        path.lstat()
    except FileNotFoundError:
        return {
            "kind": "sandbox",
            "relative_path": Path(relative).as_posix(),
            "action": "absent",
            "dry_run": dry_run,
        }
    except OSError as error:
        raise Phase13Error(f"cannot inspect rollback path: {relative}: {error}") from error
    redirect = _is_redirect_entry(path)
    if not redirect:
        try:
            resolved = path.resolve()
        except OSError as error:
            raise Phase13Error(
                f"cannot resolve rollback path: {relative}: {error}"
            ) from error
        if root not in resolved.parents and resolved != root:
            raise Phase13Error(f"rollback path escapes sandbox: {relative}")
    if dry_run:
        return {
            "kind": "sandbox",
            "relative_path": Path(relative).as_posix(),
            "action": "would_delete",
            "dry_run": True,
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
        }
    if redirect:
        _remove_redirect_leaf(path)
    elif path.is_file():
        path.unlink()
    elif path.is_dir():
        _remove_directory(path, sandbox_root=root)
    else:
        raise Phase13Error(f"refusing to remove special path: {relative}")
    return {
        "kind": "sandbox",
        "relative_path": Path(relative).as_posix(),
        "action": "deleted",
        "dry_run": False,
    }


def _is_redirect_entry(path: Path) -> bool:
    """Return True for a symlink, junction, or other reparse point.

    Uses non-following metadata. Ambiguous inspection fails closed.
    """

    try:
        info = path.lstat()
    except OSError as error:
        raise Phase13Error(
            f"refusing rollback: cannot inspect {path}: {error}"
        ) from error
    try:
        if path.is_symlink():
            return True
    except OSError as error:
        raise Phase13Error(
            f"refusing rollback: cannot inspect symlink state {path}: {error}"
        ) from error
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError as error:
            raise Phase13Error(
                f"refusing rollback: cannot inspect junction state {path}: {error}"
            ) from error
    if hasattr(os.path, "isjunction"):
        try:
            if os.path.isjunction(path):
                return True
        except OSError as error:
            raise Phase13Error(
                f"refusing rollback: cannot inspect junction state {path}: {error}"
            ) from error
    attributes = getattr(info, "st_file_attributes", None)
    if attributes is not None:
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attributes & flag:
            return True
    return False


def _remove_redirect_leaf(path: Path) -> None:
    """Remove a link/junction entry without enumerating its target."""

    try:
        path.unlink()
        return
    except OSError:
        pass
    try:
        os.rmdir(path)
    except OSError as error:
        raise Phase13Error(
            "refusing rollback: cannot remove reparse/link without "
            f"traversing: {path}: {error}"
        ) from error


def _remove_directory(path: Path, *, sandbox_root: Path) -> None:
    """Delete an ordinary directory tree without following redirects.

    Each child is inspected before descent. Symlinks, junctions, and other
    reparse points are leaves. Recursion is only for ordinary directories
    confirmed to remain inside *sandbox_root*.
    """

    if _is_redirect_entry(path):
        raise Phase13Error(
            f"refusing rollback: will not recurse through reparse/link: {path}"
        )
    try:
        children = sorted(path.iterdir(), reverse=True)
    except OSError as error:
        raise Phase13Error(
            f"refusing rollback: cannot list directory {path}: {error}"
        ) from error
    for child in children:
        if _is_redirect_entry(child):
            _remove_redirect_leaf(child)
            continue
        try:
            child_resolved = child.resolve()
        except OSError as error:
            raise Phase13Error(
                f"refusing rollback: cannot resolve child {child}: {error}"
            ) from error
        if (
            sandbox_root not in child_resolved.parents
            and child_resolved != sandbox_root
        ):
            raise Phase13Error(
                f"refusing rollback: child escapes sandbox: {child}"
            )
        try:
            is_file = child.is_file()
            is_dir = child.is_dir()
        except OSError as error:
            raise Phase13Error(
                f"refusing rollback: cannot classify {child}: {error}"
            ) from error
        if is_file:
            try:
                child.unlink()
            except OSError as error:
                raise Phase13Error(
                    f"refusing rollback: cannot delete file {child}: {error}"
                ) from error
        elif is_dir:
            _remove_directory(child, sandbox_root=sandbox_root)
        else:
            raise Phase13Error(
                f"refusing rollback: refusing to remove special path: {child}"
            )
    try:
        path.rmdir()
    except OSError as error:
        raise Phase13Error(
            f"refusing rollback: cannot remove directory {path}: {error}"
        ) from error


def _validate_relative(relative: str) -> None:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not relative:
        raise Phase13Error(
            f"rollback sandbox path must be root-relative and may not contain ..: {relative}"
        )
