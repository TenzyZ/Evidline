"""Deterministic project-root discovery and mutation-path evaluation.

These checks are a project justification boundary, not an OS sandbox.  They do
not prevent TOCTOU replacement after evaluation, hardlink aliasing, mutations
outside Evidline hook coverage, or OS-level attacks.
"""

from __future__ import annotations

from dataclasses import dataclass
import ntpath
import os
from pathlib import Path
import posixpath
import re
from typing import Final


PROTECTED_DIRECTORIES: Final = (".git", ".evidline")
ROOT_RELATIVE_SCOPE: Final = "."
_WINDOWS_DEVICE_NAMES: Final = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_WINDOWS_FORBIDDEN_CHARS = re.compile(r'[<>"|?*]')


@dataclass(frozen=True, slots=True)
class PathEvaluation:
    """A fail-closed result for one proposed mutation target."""

    safe: bool
    canonical_root: Path | None
    canonical_target: Path | None
    reason: str | None


def discover_project_root(start: str | os.PathLike[str]) -> Path | None:
    """Return the nearest ancestor containing a ``.evidline`` directory.

    Discovery reads the filesystem and never creates state or consults Git.
    ``None`` means that an initialized root could not be established.
    """

    text = _path_text(start)
    if text is None or "\0" in text:
        return None
    try:
        current = Path(os.path.realpath(text, strict=False))
        if current.is_file():
            current = current.parent
        while True:
            if (current / ".evidline").is_dir():
                return current
            parent = current.parent
            if parent == current:
                return None
            current = parent
    except (OSError, RuntimeError, ValueError):
        return None


def evaluate_mutation_path(
    root: str | os.PathLike[str], target: str | os.PathLike[str]
) -> PathEvaluation:
    """Evaluate canonical containment for a proposed project mutation.

    Relative targets are interpreted from ``root``.  Nonexistent leaf paths
    are accepted only when their resolved existing prefix establishes safe
    containment.  This evaluation does not eliminate post-check races.
    """

    root_text = _path_text(root)
    target_text = _path_text(target)
    if root_text is None or target_text is None:
        return _unsafe(None, None, "path must be text or a text path-like object")
    if "\0" in root_text or "\0" in target_text:
        return _unsafe(None, None, "path contains NUL")

    canonical_root: Path | None = None
    try:
        root_path = Path(root_text)
        if not root_path.is_dir() or not (root_path / ".evidline").is_dir():
            return _unsafe(None, None, "project root is not initialized")
        canonical_root = Path(os.path.realpath(root_path, strict=True))
        if not canonical_root.is_dir():
            return _unsafe(canonical_root, None, "project root is not a directory")
    except (OSError, RuntimeError, ValueError):
        return _unsafe(canonical_root, None, "project root cannot be resolved")

    if os.name == "nt":
        windows_reason = _unsafe_windows_path(target_text)
        if windows_reason is not None:
            return _unsafe(canonical_root, None, windows_reason)

    try:
        if os.path.isabs(target_text):
            candidate = target_text
        else:
            if os.name == "nt":
                drive, _ = os.path.splitdrive(target_text)
                if drive or target_text.startswith(("\\", "/")):
                    return _unsafe(
                        canonical_root, None, "ambiguous Windows relative path"
                    )
            candidate = os.path.join(str(canonical_root), target_text)
        canonical_target = Path(_realpath_allow_missing(candidate))
    except (OSError, RuntimeError, ValueError):
        return _unsafe(canonical_root, None, "target cannot be resolved safely")

    root_comparison = os.path.normcase(str(canonical_root))
    target_comparison = os.path.normcase(str(canonical_target))
    try:
        common = os.path.commonpath((root_comparison, target_comparison))
    except ValueError:
        return _unsafe(canonical_root, canonical_target, "root and target are incomparable")
    if common != root_comparison:
        return _unsafe(canonical_root, canonical_target, "target resolves outside project root")
    if target_comparison == root_comparison:
        return _unsafe(canonical_root, canonical_target, "project root is not a file target")

    if has_protected_component(canonical_root, canonical_target):
        return _unsafe(canonical_root, canonical_target, "target is protected project metadata")

    return PathEvaluation(True, canonical_root, canonical_target, None)


def has_protected_component(root: Path, target: Path) -> bool:
    """Return True when any root-relative path component is protected metadata.

    Comparison is exact component equality after casefold.  ``root`` and
    ``target`` are normalized with the same ``os.path.normcase`` discipline as
    path containment; ``target`` must be contained in ``root``.  A ``.git`` or
    ``.evidline`` component at any depth is protected.
    """

    root_text = os.path.normcase(os.fspath(root))
    target_text = os.path.normcase(os.fspath(target))
    try:
        common = os.path.commonpath((root_text, target_text))
    except ValueError:
        return False
    if common != root_text:
        return False
    relative = os.path.relpath(target_text, root_text)
    protected = {name.casefold() for name in PROTECTED_DIRECTORIES}
    return any(part.casefold() in protected for part in Path(relative).parts)


def normalize_root_relative_scope(value: str) -> str:
    """Return one canonical root-relative scope prefix or raise ``ValueError``.

    ``.`` is the only whole-project representation.  The result uses forward
    slashes and the host platform's existing ``normcase`` discipline.
    """

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("scope must be non-empty text without surrounding whitespace")
    if "\0" in value:
        raise ValueError("scope contains NUL")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("scope contains a control character")
    if value.startswith("!"):
        raise ValueError("scope negation is not allowed")
    if any(character in value for character in "*?[]"):
        raise ValueError("scope glob syntax is not allowed")
    if ntpath.isabs(value) or ntpath.splitdrive(value)[0] or posixpath.isabs(value):
        raise ValueError("scope must be root-relative")

    separated = value.replace("\\", "/") if os.name == "nt" else value
    components = separated.split("/")
    if any(component == ".." for component in components):
        raise ValueError("scope parent traversal is not allowed")
    normalized_components = [
        component for component in components if component not in ("", ".")
    ]
    normalized = "/".join(normalized_components) or ROOT_RELATIVE_SCOPE
    if os.name == "nt":
        windows_reason = _unsafe_windows_path(normalized)
        if windows_reason is not None:
            raise ValueError(windows_reason)
        normalized = os.path.normcase(normalized).replace("\\", "/")
    return normalized


def path_is_within(scope: str | os.PathLike[str], target: str | os.PathLike[str]) -> bool:
    """Return component-aware containment using the canonical path discipline."""

    scope_text = os.path.normcase(os.path.normpath(os.fspath(scope)))
    target_text = os.path.normcase(os.path.normpath(os.fspath(target)))
    try:
        return os.path.commonpath((scope_text, target_text)) == scope_text
    except ValueError:
        return False


def canonical_target_in_authorized_scope(
    root: Path, target: Path, authorized_scope: tuple[str, ...]
) -> bool:
    """Match an already-canonical target to validated root-relative prefixes.

    This function performs no filesystem access.  Invalid or non-canonical
    scope state fails closed.
    """

    if not authorized_scope or not path_is_within(root, target) or target == root:
        return False
    try:
        relative = normalize_root_relative_scope(os.path.relpath(target, root))
    except (OSError, ValueError):
        return False
    for scope in authorized_scope:
        try:
            normalized_scope = normalize_root_relative_scope(scope)
        except ValueError:
            return False
        if normalized_scope != scope:
            return False
        if normalized_scope == ROOT_RELATIVE_SCOPE:
            return True
        if relative == normalized_scope or relative.startswith(normalized_scope + "/"):
            return True
    return False


def _path_text(value: str | os.PathLike[str]) -> str | None:
    try:
        result = os.fspath(value)
    except TypeError:
        return None
    return result if isinstance(result, str) else None


def _realpath_allow_missing(path: str) -> str:
    allow_missing = getattr(os.path, "ALLOW_MISSING", None)
    if allow_missing is not None:
        return os.path.realpath(path, strict=allow_missing)

    try:
        return os.path.realpath(path, strict=True)
    except FileNotFoundError:
        pass

    # Python 3.11 releases before ALLOW_MISSING need a conservative fallback.
    # Reject unresolved parent traversal rather than pretending it was resolved.
    if ".." in Path(path).parts:
        raise OSError("missing path with parent traversal is ambiguous")

    probe = Path(path)
    missing: list[str] = []
    while True:
        try:
            os.lstat(probe)
            break
        except FileNotFoundError:
            parent = probe.parent
            if parent == probe:
                raise
            missing.append(probe.name)
            probe = parent
    if missing and not probe.is_dir():
        raise NotADirectoryError(str(probe))
    resolved = Path(os.path.realpath(probe, strict=True))
    for component in reversed(missing):
        resolved /= component
    return str(resolved)


def _unsafe_windows_path(path: str) -> str | None:
    lowered = path.lower()
    if lowered.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        return "Windows namespace path is ambiguous"

    isreserved = getattr(os.path, "isreserved", None)
    if isreserved is not None:
        try:
            if isreserved(path):
                return "Windows reserved path"
        except OSError:
            return "Windows path cannot be classified"
        return None

    drive, tail = os.path.splitdrive(path)
    del drive
    for component in re.split(r"[\\/]", tail):
        if component in ("", ".", ".."):
            continue
        if component.endswith((" ", ".")):
            return "Windows path component ends with dot or space"
        if ":" in component:
            return "Windows alternate-stream path is not allowed"
        if _WINDOWS_FORBIDDEN_CHARS.search(component):
            return "Windows reserved path character"
        base = component.split(".", 1)[0].rstrip(" .").upper()
        if base in _WINDOWS_DEVICE_NAMES:
            return "Windows reserved device name"
    return None


def _unsafe(
    root: Path | None, target: Path | None, reason: str
) -> PathEvaluation:
    return PathEvaluation(False, root, target, reason)
