"""Deterministic sanitization of raw harness-event documents."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any

from .common import Phase13Error, sha256_text


REDACTED_FIELD = "[REDACTED_FIELD]"
REDACTED_NONCE = "[REDACTED_NONCE]"
REDACTED_ABSOLUTE_PATH = "[REDACTED_ABSOLUTE_PATH]"

_REDACTED_FIELD = REDACTED_FIELD
_REDACTED_NONCE = REDACTED_NONCE
_REDACTED_PATH = REDACTED_ABSOLUTE_PATH
_SHA256_HEX = re.compile(r"\b[0-9a-f]{64}\b")

_SENSITIVE_KEYS = frozenset(
    {
        "nonce",
        "challenge",
        "challenge_nonce",
        "challengetoken",
        "transcript",
        "transcripts",
        "message",
        "messages",
        "content",
        "thinking",
        "reasoning",
        "thoughts",
        "private_thoughts",
        "api_key",
        "apikey",
        "authorization",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "session_id",
        "sessionid",
        "tool_use_id",
        "tool_useid",
        "conversation_id",
        "conversationid",
        "home",
        "homedir",
        "userprofile",
        "raw_prompt",
        "prompt_text",
        "prompt",
        "text",
        "tool_response",
        "tool_result",
        "old_string",
        "new_string",
        "file_text",
        "installation_id",
        "machine_id",
        "device_id",
        "account_id",
        "user_id",
        "email",
        "user_email",
        "env",
        "environment",
    }
)

_SENSITIVE_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "authorization",
)

_WINDOWS_ABS = re.compile(r"(?i)(?:[a-z]:[\\/]|\\\\)[^\s\"']+")
_POSIX_ABS = re.compile(r"(?:/Users|/home|/tmp|/var|/opt|/root)/[^\s\"']+")


_IDENTIFIER_DIGESTS = (
    ("session_id", "session_sha256"),
    ("tool_use_id", "tool_use_sha256"),
    ("enabled_session_id", "enabled_session_sha256"),
    ("control_session_id", "control_session_sha256"),
)


def sanitize_document(
    document: Any,
    *,
    nonce: str | None = None,
    root: str | Path | None = None,
    home_prefixes: Sequence[str] = (),
    emit_nonce_digest: bool = True,
    redact_literals: Sequence[str] = (),
) -> Any:
    """Return a sanitized copy of *document*.

    Removes challenge nonce text, transcript/message fields, absolute machine
    paths, and known sensitive keys. Raw session/tool identifiers are replaced
    with sha256 correlators. Exact identifier literals observed for digest
    promotion are also scrubbed from surviving free-text. If *nonce* is
    supplied and *emit_nonce_digest* is true, the result carries
    ``challenge_nonce_sha256`` at the top level when *document* is an object.
    """

    if nonce is not None and nonce == "":
        raise Phase13Error("nonce, if supplied, must be non-empty")

    derived: dict[str, str] = {}
    identifier_literals: list[str] = []
    if isinstance(document, Mapping):
        for raw_key, digest_key in _IDENTIFIER_DIGESTS:
            value = document.get(raw_key)
            if isinstance(value, str) and value:
                derived[digest_key] = sha256_text(value)
                identifier_literals.append(value)
    for extra in redact_literals:
        if isinstance(extra, str) and extra:
            identifier_literals.append(extra)
    literals = _unique_longest_first(identifier_literals)

    sanitized = _walk(
        document,
        nonce=nonce,
        root=root,
        homes=tuple(home_prefixes),
        literals=literals,
    )
    if isinstance(document, Mapping) and isinstance(sanitized, dict):
        for digest_key, digest in derived.items():
            if sanitized.get(digest_key) in {None, "", _REDACTED_FIELD}:
                sanitized[digest_key] = digest
        if nonce and emit_nonce_digest:
            sanitized["challenge_nonce_sha256"] = sha256_text(nonce)
            sanitized.pop("nonce", None)
            sanitized.pop("challenge_nonce", None)
    return sanitized


def _unique_longest_first(values: Sequence[str]) -> tuple[str, ...]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in sorted(values, key=len, reverse=True):
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return tuple(unique)


def _walk(
    value: Any,
    *,
    nonce: str | None,
    root: str | Path | None,
    homes: tuple[str, ...],
    literals: tuple[str, ...],
) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                cleaned[key_text] = _REDACTED_FIELD
                continue
            if key_text.endswith("_sha256") and isinstance(item, str):
                cleaned[key_text] = item
                continue
            cleaned[key_text] = _walk(
                item,
                nonce=nonce,
                root=root,
                homes=homes,
                literals=literals,
            )
        return cleaned
    if isinstance(value, list):
        return [
            _walk(
                item,
                nonce=nonce,
                root=root,
                homes=homes,
                literals=literals,
            )
            for item in value
        ]
    if isinstance(value, str):
        return _sanitize_text(
            value,
            nonce=nonce,
            root=root,
            homes=homes,
            literals=literals,
        )
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    if normalized in _SENSITIVE_KEYS:
        return True
    return any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _sanitize_text(
    text: str,
    *,
    nonce: str | None,
    root: str | Path | None,
    homes: tuple[str, ...],
    literals: tuple[str, ...] = (),
) -> str:
    result = text
    if nonce:
        result = result.replace(nonce, _REDACTED_NONCE)
    result = _replace_literals_preserving_digests(result, literals)
    if root is not None:
        result = _relativize_root(result, Path(root))
    for home in homes:
        if home:
            result = _replace_prefix(result, home, _REDACTED_PATH)
    result = _WINDOWS_ABS.sub(_REDACTED_PATH, result)
    result = _POSIX_ABS.sub(_REDACTED_PATH, result)
    return result


def _replace_literals_preserving_digests(text: str, literals: Sequence[str]) -> str:
    if not literals:
        return text
    protected: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        protected.append(match.group(0))
        return f"\x00DIGEST{len(protected) - 1}\x00"

    result = _SHA256_HEX.sub(_stash, text)
    for literal in literals:
        if literal:
            result = result.replace(literal, _REDACTED_FIELD)
    for index, digest in enumerate(protected):
        result = result.replace(f"\x00DIGEST{index}\x00", digest)
    return result


def _relativize_root(text: str, root: Path) -> str:
    candidates = (
        str(root),
        root.as_posix(),
        str(PureWindowsPath(root)),
        str(PurePosixPath(root.as_posix())),
    )
    result = text
    for candidate in candidates:
        if candidate and candidate in result:
            result = result.replace(candidate, "[SANDBOX_ROOT]")
    return result


def _replace_prefix(text: str, prefix: str, token: str) -> str:
    result = text
    for candidate in {prefix, prefix.replace("\\", "/"), prefix.replace("/", "\\")}:
        if candidate:
            result = result.replace(candidate, token)
    return result
