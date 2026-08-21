from __future__ import annotations

import errno
import io
from typing import BinaryIO, cast
import unittest

from evidline import transport


def _write_binary(stream: object, raw: bytes, *, flush: bool) -> None:
    transport._write_binary(cast(BinaryIO, stream), raw, flush=flush)


class _ScriptedBinaryWriter:
    def __init__(
        self,
        *actions: object,
        flush_error: BaseException | None = None,
    ) -> None:
        self.sink = io.BytesIO()
        self._actions = list(actions)
        self._flush_error = flush_error

    def write(self, data: bytes) -> object:
        if not self._actions:
            return self.sink.write(data)
        action = self._actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(data, self.sink)
        if (
            isinstance(action, int)
            and not isinstance(action, bool)
            and 0 < action <= len(data)
        ):
            self.sink.write(data[:action])
        return action

    def flush(self) -> None:
        if self._flush_error is not None:
            raise self._flush_error
        self.sink.flush()


class _PartialThenRaiseRaw(io.RawIOBase):
    def __init__(self, prefix_length: int) -> None:
        super().__init__()
        self.sink = io.BytesIO()
        self._prefix_length = prefix_length

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        prefix = bytes(data[: self._prefix_length])
        self.sink.write(prefix)
        raise OSError("raw write failed after emitting bytes")


class TransportTests(unittest.TestCase):
    def assert_fallback_safe(
        self,
        error: transport.OutputWriteError,
        expected: bool,
    ) -> None:
        actual = getattr(error, "fallback_safe", error.bytes_written == 0)
        self.assertEqual(actual, expected)

    def test_full_write_emits_each_byte_once(self) -> None:
        writer = _ScriptedBinaryWriter()

        _write_binary(writer, b"abcdef", flush=True)

        self.assertEqual(writer.sink.getvalue(), b"abcdef")

    def test_multiple_short_writes_emit_each_byte_once(self) -> None:
        writer = _ScriptedBinaryWriter(2, 1, 3)

        _write_binary(writer, b"abcdef", flush=True)

        self.assertEqual(writer.sink.getvalue(), b"abcdef")

    def test_invalid_counts_are_not_fallback_safe(self) -> None:
        for label, count in (
            ("none", None),
            ("true", True),
            ("false", False),
            ("negative", -1),
            ("zero", 0),
        ):
            with self.subTest(label=label):
                writer = _ScriptedBinaryWriter(count)
                with self.assertRaises(transport.OutputWriteError) as caught:
                    _write_binary(writer, b"abc", flush=False)
                self.assertEqual(writer.sink.getvalue(), b"")
                self.assertEqual(caught.exception.bytes_written, 0)
                self.assert_fallback_safe(caught.exception, False)

    def test_oversized_count_after_consuming_bytes_is_not_reported_clean(self) -> None:
        def consume_then_overreport(data: bytes, sink: io.BytesIO) -> int:
            sink.write(data)
            return len(data) + 1

        writer = _ScriptedBinaryWriter(consume_then_overreport)

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abc", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"abc")
        self.assertEqual(caught.exception.bytes_written, 0)
        self.assert_fallback_safe(caught.exception, False)

    def test_returned_partial_count_then_exception_is_dirty(self) -> None:
        writer = _ScriptedBinaryWriter(2, OSError("later write failed"))

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"ab")
        self.assertEqual(caught.exception.bytes_written, 2)
        self.assert_fallback_safe(caught.exception, False)

    def test_same_call_emit_then_generic_exception_is_not_reported_clean(self) -> None:
        def emit_then_raise(data: bytes, sink: io.BytesIO) -> int:
            sink.write(data[:3])
            raise OSError("write failed after emitting bytes")

        writer = _ScriptedBinaryWriter(emit_then_raise)

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"abc")
        self.assertEqual(caught.exception.bytes_written, 0)
        self.assert_fallback_safe(caught.exception, False)

    def test_blocking_error_characters_written_updates_known_bytes(self) -> None:
        def emit_then_block(data: bytes, sink: io.BytesIO) -> int:
            sink.write(data[:3])
            raise BlockingIOError(errno.EAGAIN, "blocked", 3)

        writer = _ScriptedBinaryWriter(emit_then_block)

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"abc")
        self.assertEqual(caught.exception.bytes_written, 3)
        self.assert_fallback_safe(caught.exception, False)

    def test_zero_characters_written_does_not_claim_cleanliness(self) -> None:
        writer = _ScriptedBinaryWriter(
            BlockingIOError(errno.EAGAIN, "blocked", 0)
        )

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"")
        self.assertEqual(caught.exception.bytes_written, 0)
        self.assert_fallback_safe(caught.exception, False)

    def test_zero_characters_written_preserves_prior_dirty_evidence(self) -> None:
        writer = _ScriptedBinaryWriter(
            2,
            BlockingIOError(errno.EAGAIN, "blocked", 0),
        )

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=False)

        self.assertEqual(writer.sink.getvalue(), b"ab")
        self.assertEqual(caught.exception.bytes_written, 2)
        self.assert_fallback_safe(caught.exception, False)

    def test_flush_failure_after_write_is_dirty(self) -> None:
        writer = _ScriptedBinaryWriter(flush_error=OSError("flush failed"))

        with self.assertRaises(transport.OutputWriteError) as caught:
            _write_binary(writer, b"abcdef", flush=True)

        self.assertEqual(writer.sink.getvalue(), b"abcdef")
        self.assertEqual(caught.exception.bytes_written, 6)
        self.assert_fallback_safe(caught.exception, False)

    def test_missing_binary_stream_boundary_is_proven_clean(self) -> None:
        with self.assertRaises(transport.OutputWriteError) as caught:
            transport._write_bytes(io.StringIO(), b"abc", flush=True)

        self.assertEqual(caught.exception.bytes_written, 0)
        self.assert_fallback_safe(caught.exception, True)

    def test_real_buffered_writer_preserves_possible_contamination(self) -> None:
        raw = _PartialThenRaiseRaw(prefix_length=3)
        buffered = io.BufferedWriter(raw, buffer_size=8)

        with self.assertRaises(transport.OutputWriteError) as caught:
            transport._write_binary(buffered, b"abcdefghijk", flush=True)

        self.assertEqual(raw.sink.getvalue(), b"abc")
        self.assertEqual(caught.exception.bytes_written, 0)
        self.assert_fallback_safe(caught.exception, False)


if __name__ == "__main__":
    unittest.main()
