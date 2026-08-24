# ADR-0027 — VAB-7 Live Verification Contract

Status: Accepted

Live status: CONTRACT ACCEPTED; CLAUDE RUNS 1-3 EXECUTED ON UNCOMMITTED RUNTIME; EVIDENCE FORENSIC ONLY; CODEX FOUR-SESSION CAMPAIGN EXECUTED 2026-08-21 ON UNCOMMITTED RUNTIME; S_CONTROL / S_ENABLED / S_POS OBSERVED; S_DENY = INCONCLUSIVE (NO TOOL ATTEMPT); NO CAMPAIGN RAN ON A COMMITTED RUNTIME; ALL PRIOR LIVE EVIDENCE REMAINS FORENSIC; CLEAN COMMITTED-BASELINE CAMPAIGN REQUIRED FOR BOTH HARNESSES; VAB-7 REMAINS OPEN

## Amends / supersession boundary

This ADR freezes the accepted VAB-7 live-verification contract. It does not
close VAB-7. It does not amend the V1 acceptance-ledger literals in ADR-0018
or later ledger-closure ADRs. No historical ADR is rewritten.

## Decision purpose

Phase 13 must produce a narrow, reproducible live proof that Evidline can be
dispatched by installed harness hooks, inject compiled context, and deny a
governed mutation on the selected tool paths. The contract is deliberately
smaller than complete harness enforcement.

```text
VAB_7_HARNESS_DECISION = CLAUDE_AND_CODEX
```

VAB-7 remains `OPEN` until a later, independent closure phase evaluates
sanitized live evidence. This ADR records the contract only.

```text
CONTRACT ACCEPTED
CLAUDE RUNS 1-3 EXECUTED ON UNCOMMITTED RUNTIME;
EVIDENCE FORENSIC ONLY
CODEX FOUR-SESSION CAMPAIGN EXECUTED 2026-08-21
ON UNCOMMITTED RUNTIME
S_CONTROL / S_ENABLED / S_POS OBSERVED
S_DENY = INCONCLUSIVE (NO TOOL ATTEMPT)
NO CAMPAIGN RAN ON A COMMITTED RUNTIME;
ALL PRIOR LIVE EVIDENCE REMAINS FORENSIC
CLEAN COMMITTED-BASELINE CAMPAIGN REQUIRED
FOR BOTH HARNESSES
VAB-7 REMAINS OPEN
```

A later Claude execution occurred. Its committed artifacts are not accepted
proof. They remain rejected historical output until a separately authorized
rerun produces claim-specific capture-bound evidence.

## Proving paths

The only selected proving paths are:

```text
Claude Code
  SessionStart
  PreToolUse
  actual proving tool: Write
  matcher: Edit|Write|NotebookEdit

Codex
  SessionStart
  PreToolUse
  actual proving tool: apply_patch
  matcher: apply_patch
```

Claude `Edit` and `NotebookEdit` remain recognized adapter tools. They are
not the Phase 13 proving tools. Codex proving is limited to canonical
`apply_patch`. A Codex session that mutates through `Bash` instead of
`apply_patch` is `NOT_COVERED`.

## Required live claims

A later live-verification stage must produce independent evidence for all
three claims, on both proving harnesses:

```text
INSTALLED_HARNESS_DISPATCH
LIVE_CONTEXT_INJECTION
LIVE_MUTATION_DENIAL
```

These claims are not established by this ADR. They remain unexecuted.

## Four-layer denial proof

A final mutation-denial proof requires all four layers:

```text
CORE_DECISION       = BLOCK
ADAPTER_TRANSPORT   = DENY
HARNESS_TOOL_RESULT = DENIED
TARGET_STATE        = UNCHANGED
```

`LIVE_MUTATION_DENIAL = VERIFIED` requires an actual harness denial
result (`DENIED`). `NOT_EXECUTED` does not prove the harness blocked
the attempted mutation and cannot classify as `VERIFIED`. When the
other denial layers would otherwise hold, `NOT_EXECUTED` is
`INCONCLUSIVE`.

Vocabulary remains distinct:

```text
permission != authorization != evidence != execution != verification
EXECUTED never means VERIFIED
adapter ALLOW != harness execution
adapter BLOCK != harness denial
hook configured != hook dispatched
dispatch != context injection
context injection != enforcement
CORE_DECISION = BLOCK
does not imply
HARNESS_TOOL_RESULT = DENIED
```

Any target mutation after an expected BLOCK is `FAILED_OPEN`. That outcome
is a critical blocker and must not be relabeled as success.

## Deterministic BLOCK used by Phase 13

The selected BLOCK is the existing mutation-engine result:

```text
ACTIVE invariant
enforcement = BLOCK
governed_scope contains target
trusted ACTIVE task exists
invariant NOT acknowledged by that task
reason = INVARIANT_UNACKNOWLEDGED
```

Both adapters continue to submit:

```text
request_intent = PROPOSED
risk = NORMAL
```

Those semantics must not be weakened to make the live test easier.

Expected offline decisions for the disposable sandbox:

```text
allowed/probe-allow.txt   -> ALLOW
governed/probe-deny.txt   -> BLOCK / INVARIANT_UNACKNOWLEDGED
```

The positive control (`allowed/probe-allow.txt`) must succeed on the same
selected tool path. Without it, an absent governed target is not strongly
attributable to Evidline.

`PHASE13` remains the single logical positive-control payload. Exact serialized
target bytes are fixed by the selected proving mechanism: Claude `Write`
produces `PHASE13`, while Codex `apply_patch` Add File produces `PHASE13\n`.
Phase 13 derives the expected digest internally from the `(harness, proving
tool)` pair; the operator records observations and cannot select the expected
digest. The accepted Claude digest remains unchanged.

## Context-injection challenge

`tools/phase13/contract.py` is the canonical machine-readable nonce contract:

```text
prefix                  = EVIDLINE-P13-
generator               = secrets.token_hex(16)
random bytes            = 16
entropy                 = 128-bit entropy
random encoding         = lowercase hexadecimal
random characters       = 32
total length            = 45 total characters
UTF-8 length            = 45 UTF-8 bytes
exact regex             = ^EVIDLINE-P13-[0-9a-f]{32}$
comparison              = case-sensitive exact comparison
```

The nonce is ASCII only. Generate one nonce per separately authorized live
attempt and never reuse it. A retry or failed attempt spends the prior nonce
and requires a fresh nonce for the new attempt.

The canonical PRELIVE placeholder is:

```text
EVIDLINE-P13-00000000000000000000000000000000
```

It is constructed as `NONCE_PREFIX + ("0" * NONCE_RANDOM_CHARS)`, has the
same 45-character and 45-byte lexical grammar as a live nonce, and is a
reserved non-live sentinel. Exact-value rejection prevents it from being a
live nonce candidate. It must never be presented as live proof.

The live nonce is generated only at separately authorized activation time,
written only through supported Evidline authoring, and carried in the
invariant description. It must be absent from the user prompt, CLI arguments
where practical, environment variables, commits, and sanitized repository
evidence. This contract remediation does not authorize challenge generation.

Committed evidence may retain only `challenge_nonce_sha256 = sha256(nonce)`,
never the plaintext nonce. `challenge_nonce_sha256` can be independently recomputed only while
the corresponding nonce plaintext is retained.
Therefore the private nonce file remains with the private review material
until independent evidence review completes and explicit human cleanup
authorization is given.

A negative-control session without Evidline injection must not return the
nonce.

## Phase 13 deterministic context-payload amendment

ADR-0028 establishes UTF-8 bytes as the machine-output transport. For a future
P7 attempt, the invalid comparison

```text
adapter raw stdout bytes == direct CLI raw payload bytes
```

is explicitly superseded. The adapter stdout is a JSON envelope while the
direct CLI output is the payload itself. The required comparison is exact
logical string equality:

```python
adapter_json = json.loads(adapter_stdout_bytes.decode("utf-8"))
additional_context = adapter_json["hookSpecificOutput"]["additionalContext"]
direct_payload = direct_payload_bytes.decode("utf-8")

additional_context == direct_payload
```

No Unicode normalization, newline normalization, whitespace trimming, or case
folding is permitted. If equality requires normalization, the upstream output
is still incorrect.

The canonical P7 payload measurement is:

```python
canonical_bytes = additional_context.encode("utf-8")
context_payload_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
context_payload_length = len(canonical_bytes)  # bytes
budget_measurement = len(additional_context)   # characters
```

Direct CLI payload capture must be binary and deterministic. Do not use
PowerShell or text redirection that may re-encode bytes or translate newlines:

```python
completed = subprocess.run(
    [...],
    capture_output=True,
    text=False,
    check=True,
)
raw = completed.stdout
path.write_bytes(raw)
```

The capture has no BOM, newline translation, or locale conversion. For the
previously diagnosed PRELIVE fixture, 282 logical characters, 286 UTF-8 bytes,
and SHA-256
`f99b4b47c1f0a74f1e2225ad8c5456a1b9d3af4cfe7c9951e4b65d97570a64af`
are predictions for a future authorized rerun, not P7 PASS evidence.

Historical failed P7 artifacts remain preserved as failed evidence. They must
not be normalized, rewritten, or relabeled to manufacture a PASS. P7 remains
blocked until separately authorized execution and review.

## Evidence and sanitization

Each committed live artifact must declare exactly one claim:

```text
INSTALLED_HARNESS_DISPATCH
LIVE_CONTEXT_INJECTION
LIVE_MUTATION_DENIAL
```

`VERIFIED` is validated only against that claim. Denial-layer fields must be
absent from dispatch and injection records. `challenge_nonce_sha256` is an
injection field only. `operator_summary` / `notes` never satisfy a
`VERIFIED` gate.

Committed artifacts store privacy-preserving bindings, not raw execution
material. Required digest classes include:

- `raw_capture_sha256` or claim-specific capture digests
- `session_sha256` / `enabled_session_sha256` / `control_session_sha256`
- `tool_use_sha256` when a proving tool was attempted
- `context_payload_sha256` and `context_payload_length` for SessionStart
- `enabled_answer_sha256` / `control_answer_sha256` for injection
- structured positive-control existence and `PHASE13` content digests
  for denial

Raw `session_id`, `tool_use_id`, nonce, model answers, and capture bytes
must not appear in committed artifacts. SessionStart output is plain
context text; represent it by digest and length, not as
`sanitized_hook_decision`. Reserve structured hook-decision fields for
actual PreToolUse adapter JSON.

A caller-supplied `verdict` cannot override the derived denial
classification. `classify_denial` and `generate_evidence_record` share one
classification path.

Raw live harness captures remain outside the repository but MUST be
retained until independent evidence review and explicit human cleanup
authorization. Immediate sandbox rollback must not destroy the only raw
evidence that binds a committed digest. A later live procedure copies or
moves raw captures to a private temporary review location outside Git
before sandbox deletion. That directory is not created by this ADR and
must not be committed.

Independent review must recompute SHA-256 from those retained capture
bytes and compare each recomputed digest to the matching committed
field (`raw_capture_sha256`, `enabled_raw_capture_sha256`,
`control_raw_capture_sha256`, `positive_control_raw_capture_sha256`,
`context_payload_sha256`). A missing retained capture, an ambiguous
capture-to-field mapping, or a digest mismatch means that claim cannot
be accepted as `VERIFIED` and is `INCONCLUSIVE`. The operational
recompute steps live in `docs/live-verification.md`.

They must not contain private transcripts, thinking, API keys, tokens,
credentials, full user config, absolute home paths, the nonce itself,
unrelated environment, installation identifiers, raw session histories,
Serena data, or Assets.

Result files under `docs/evidence/phase-13/` may be created only from actual
sanitized captures after authorized live execution. Existing Claude run-1
artifacts in that directory are rejected historical output, not accepted
proof.

## Explicit uncovered paths

This contract does **not** claim:

- complete harness enforcement
- Bash coverage
- PowerShell coverage
- Monitor coverage
- MCP mutation coverage
- hosted-tool coverage
- a global fail-closed security boundary
- production deployment

## Known fail-open boundaries

Selected-path denial is demonstrated only when the hook dispatches, the
adapter runs successfully, the output is accepted by the harness, and the
selected supported tool path is used.

Known fail-open categories include:

- interpreter or process missing
- adapter crash before a valid denial
- malformed hook output
- unsupported hook output
- timeout
- untrusted or skipped Codex hook
- untrusted Codex project
- tool outside adapter coverage
- conflicting or multiple Codex hooks

A distinct class is `FAIL_CLOSED_MISATTRIBUTION` / `INCONCLUSIVE`:

```text
wrong adapter invocation
-> exit 2
-> selected harness blocks PreToolUse
-> target remains unchanged
```

Current Claude Code and Codex hook documentation treat PreToolUse exit
code 2 as a blocking hook outcome. That harness block is not Evidline
denial evidence. `CORE_DECISION = BLOCK` and a valid structured
`permissionDecision: deny` were never established. Exit 2 must not
become `VERIFIED`.

`NOT_COVERED` is not success and is not automatically `FAILED_OPEN`.

## Disposable environment

Live state must be authored only in a disposable sandbox outside this
repository. The repository itself must not receive `.evidline/`, `.claude/`,
or `.codex/` live state. Probe files must initially not exist. State must be
authored through supported Evidline CLI surfaces, not by hand-editing
`state.json`. Destructive rollback apply requires a `.phase13-sandbox`
marker directly in the selected sandbox root and must refuse filesystem
root, the user home directory, and a directory that itself looks like a
repository project root.

## Acceptance-ledger boundary

```text
VAB-7 remains OPEN
v1_acceptance remains BLOCKED
LIVE_VERIFICATION remains unexecuted
```

Phase 13 may capture evidence. A later independent VAB-7 closure phase owns
any ledger change. This ADR does not start VAB-8.

## Explicit non-goals

This ADR does not:

- modify product-core source
- install or activate hooks
- generate a challenge nonce
- create a sandbox or control directory
- run Claude Code or Codex
- claim that any live proof already succeeded
- close VAB-7
