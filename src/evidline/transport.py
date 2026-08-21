"""Deterministic UTF-8 transport for machine-readable output."""

from __future__ import annotations

import sys
from enum import Enum
from typing import BinaryIO, TextIO


class OutputContamination(Enum):
    """How confidently a failed write can classify escaped output bytes."""

    CLEAN = "clean"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


class OutputWriteError(OSError):
    """Output failure carrying known bytes and contamination confidence."""

    def __init__(
        self,
        message: str,
        *,
        bytes_written: int,
        contamination: OutputContamination,
    ) -> None:
        super().__init__(message)
        self.bytes_written = bytes_written
        self.contamination = contamination

    @property
    def fallback_safe(self) -> bool:
        """Whether zero escaped bytes were positively established."""

        return self.contamination is OutputContamination.CLEAN


def encode_utf8(text: str) -> bytes:
    """Return the canonical UTF-8 bytes for logical output text."""

    if not isinstance(text, str):
        raise TypeError("transport output must be text")
    return text.encode("utf-8")


def write_stdout(text: str, *, flush: bool = False) -> None:
    """Write logical text as UTF-8 bytes to the binary stdout boundary."""

    _write_bytes(sys.stdout, encode_utf8(text), flush=flush)


def write_stderr(text: str, *, flush: bool = False) -> None:
    """Write logical text as UTF-8 bytes to the binary stderr boundary."""

    _write_bytes(sys.stderr, encode_utf8(text), flush=flush)


def diagnose(message: str) -> None:
    """Write one deterministic best-effort diagnostic without propagating errors."""

    try:
        logical = message + "\n"
        try:
            raw = encode_utf8(logical)
        except UnicodeEncodeError:
            raw = logical.encode("ascii", errors="backslashreplace")
        _write_bytes(sys.stderr, raw, flush=True)
    except Exception:
        pass


def _write_bytes(stream: TextIO, raw: bytes, *, flush: bool) -> None:
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        _write_binary(binary, raw, flush=flush)
        return
    raise OutputWriteError(
        "binary output stream is unavailable",
        bytes_written=0,
        contamination=OutputContamination.CLEAN,
    )


def _write_binary(stream: BinaryIO, raw: bytes, *, flush: bool) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = stream.write(raw[offset:])
        except Exception as exc:
            known_written = offset
            if isinstance(exc, BlockingIOError):
                characters_written = getattr(exc, "characters_written", None)
                remaining = len(raw) - offset
                if (
                    isinstance(characters_written, int)
                    and not isinstance(characters_written, bool)
                    and 0 < characters_written <= remaining
                ):
                    known_written += characters_written
            raise OutputWriteError(
                "binary output write failed",
                bytes_written=known_written,
                contamination=(
                    OutputContamination.DIRTY
                    if known_written
                    else OutputContamination.UNKNOWN
                ),
            ) from exc
        remaining = len(raw) - offset
        if (
            isinstance(written, bool)
            or not isinstance(written, int)
            or written <= 0
            or written > remaining
        ):
            raise OutputWriteError(
                "binary output writer returned an invalid byte count",
                bytes_written=offset,
                contamination=(
                    OutputContamination.DIRTY
                    if offset
                    else OutputContamination.UNKNOWN
                ),
            )
        offset += written
    if flush:
        try:
            stream.flush()
        except Exception as exc:
            raise OutputWriteError(
                "binary output flush failed",
                bytes_written=offset,
                contamination=(
                    OutputContamination.DIRTY
                    if offset
                    else OutputContamination.UNKNOWN
                ),
            ) from exc
