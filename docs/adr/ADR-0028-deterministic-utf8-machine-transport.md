# ADR-0028 — Deterministic UTF-8 Machine Transport

Status: Accepted

## Context

Evidline adapters and CLI payload commands produce logical Unicode text. A
machine or hook protocol cannot delegate byte encoding to the ambient stdout
text encoding: on Windows a redirected stream may use a legacy code page, so
valid Unicode can be lost or emitted as bytes that are not valid UTF-8.

Strict UTF-8 decoding by a hook wrapper or evidence capture is correct. The
producer owns deterministic serialization and byte encoding.

## Decision

Machine and hook protocol output is encoded explicitly as UTF-8 and written to
the binary stdout boundary. The ambient locale, console code page, and text
stream encoding are not part of the protocol.

Binary writes advance by the accepted byte count until the complete document
is emitted. Zero progress, `None`, invalid counts, write failure, and flush
failure terminate deterministically. A stream without a binary boundary is an
output failure; there is no `StringIO` or locale-dependent text fallback.

Canonical JSON retains Unicode with `ensure_ascii=False` and preserves the
existing schema and serialization options. Canonical context text is not
rewritten to remove non-ASCII characters.

PreToolUse denial output uses a fail-safe ladder:

1. emit the canonical denial JSON as UTF-8 bytes and flush;
2. if canonical serialization, encoding, or output fails before any byte is
   emitted, emit a minimal ASCII-safe denial document with the existing hook
   schema and a fixed transport-failure reason;
3. if the fail-safe denial also cannot be emitted, write a best-effort
   deterministic diagnostic and return a nonzero failure exit.

If canonical denial bytes have already escaped, stdout is contaminated. The
adapter must not append fallback JSON; it writes a best-effort diagnostic and
returns exit 2 so malformed stdout cannot be reported as successful denial.

An ALLOW result remains successful empty stdout. A SessionStart output failure
does not manufacture degraded context and must remain detectable as failure.

Adapter diagnostics and product-owned CLI stderr use explicit UTF-8 bytes. A
best-effort adapter diagnostic uses a deterministic escaped form for otherwise
unencodable logical text and never hides the primary failure by raising a
second exception.

Tests for this contract observe emitted bytes, perform strict UTF-8 decoding,
include hostile ambient text encodings, and assert LF-only context payload
capture. `StringIO`-only assertions do not establish the machine transport
contract.

## Rejected alternatives

The following are not correctness mechanisms:

- `PYTHONUTF8`, `PYTHONIOENCODING`, or locale mutation
- `chcp 65001` or global console-code-page changes
- switching canonical output to ASCII escaping
- replacement, ignore, cp1252 fallback, or locale guessing in consumers
- weakening strict UTF-8 decoding in the wrapper

Environment encoding overrides may be used only to create adversarial tests.

## Consequences

Logical payloads and public schemas remain unchanged. UTF-8 bytes are stable
across redirected and interactive environments. A denial transport failure
cannot become successful empty stdout, and wrapper strict decoding continues to
detect invalid producer output.

This decision adds no dependency, state or schema change, hook activation,
runtime propagation, or live-verification result.
