# ADR-0014 — Codex Adapter (V1 Phase 6)

Status: Accepted

## Amends

ADR-0008 — Claude and Codex Adapters

## Context

Phase 6 needs a thin Codex transport over the existing context compiler,
project-root discovery, state loader, path boundary, and mutation decision
engine. The adapter must not become a second policy implementation or confuse a
Codex tool proposal with human intent, authority, evidence, permission,
execution, or verification.

Codex exposes `SessionStart` context output and deny-capable `PreToolUse` output,
but it does not safely support native interactive
`permissionDecision: "ask"`. Unsupported output can fail the hook and allow the
tool call to continue. `PermissionRequest` runs only when Codex independently
needs approval, so it cannot transport every Evidline ASK.

The canonical direct file-edit surface is `apply_patch`. Its hook payload names
the tool `apply_patch` and carries raw patch text in `tool_input.command`. That
patch can contain multiple file operations and a rename can affect both source
and destination.

## Decision

Phase 6 adds the dedicated, stateless command transport
`python -m evidline.adapters.codex`. It supports `session-start` and
`pre-tool-use`, reads hook JSON from stdin, performs no network or subprocess
work, and writes no state, journal, cache, or configuration. It adds no package
entry point or Evidline CLI command.

Normal hook results use exit 0. Invalid adapter commands and structured stdout
write failures use exit 2. The adapter does not invent enforcement semantics
from an exit code.

### Thin adapter and unchanged core

Project-root discovery, state validation, context compilation, path safety, and
mutation policy remain in the existing core modules. The adapter performs only
Codex transport validation, patch target extraction, cwd-relative anchoring,
multi-target orchestration, and output translation. No core API, persisted
schema, mutation schema, dependency, or CLI surface changes.

### SessionStart

Every documented source (`startup`, `resume`, `clear`, and `compact`) and an
unknown source compile the current SESSION profile with `budget_chars=None`.
The adapter renders the existing payload and emits it only as
`hookSpecificOutput.additionalContext`. It does not rely on plain-text stdout,
cache context, or persist context.

No discoverable Evidline root is outside adapter jurisdiction and produces
silence. Malformed input, state failure, and context failure remain advisory:
they emit no context, exit 0, and produce one concise stderr diagnostic. They do
not become mutation decisions.

### PreToolUse jurisdiction

Phase 6 covers only the canonical `tool_name: "apply_patch"`. `Bash`,
shell-invoked patches, PowerShell, MCP tools, `spawn_agent`, unknown local
functions, and all other tools are silent and do not call mutation evaluation.
The adapter contains no heuristic shell parser.

### Intent and risk

Every covered target uses `request_intent = PROPOSED`, `risk = NORMAL`,
`operation = None`, and empty authority, scope, support, evidence, and asserted
conflict IDs. A Codex tool call proves only an agent proposal. `NORMAL` is the
required declared non-assessment, not semantic risk classification.

Codex permission mode, model, agent metadata, patch operation, patch size,
target count, filename, and extension cannot promote intent or infer risk.

### Parser and path translation

The adapter implements the frozen target-extraction subset rather than the full
Codex patch engine. It accepts direct Begin/End Patch envelopes and the three
frozen EOF heredoc wrappers. It recognizes Add, Delete, Update, and one Move-to
immediately attached to an Update, plus only the frozen hunk/body lines. It
denies environment IDs because their jurisdiction relationship cannot be
established locally.

Unsupported, malformed, ambiguous, or parser-divergent input fails closed as an
adapter failure. The parser does not semantically interpret patch bodies or
claim complete equivalence with all patches Codex may accept.

Relative marker paths are translated with `os.path.join(cwd, path)` because
Codex patch paths are cwd-relative while the core evaluates from the project
root. Absolute paths pass through unchanged. The adapter performs no path
normalization, canonicalization, case folding, separator conversion, protected
path detection, or manual `..` collapse.

Targets preserve first appearance order and are de-duplicated by exact anchored
string equality. Rename source and destination are both evaluated.

### Atomic decision

Every unique target is evaluated independently through the unchanged
`evaluate_and_decide(...)` core API against one freshly loaded state document.
The tool call receives one atomic disposition using `BLOCK > ASK > ALLOW`. The
first target wins a same-severity tie. No partial application decision exists.

### Outcomes and failures

An existing-core ALLOW maps to silence. The adapter never emits
`permissionDecision: "allow"` because Evidline policy does not grant Codex
permission.

An existing-core ASK maps to Codex `permissionDecision: "deny"`, with a reason
starting `evidline ASK:` that requires stronger human authorization or evidence
and retry only after Evidline state changes. Native Codex ASK is rejected because
it is not safely supported. `PermissionRequest` is rejected as a universal ASK
transport because it does not run for every tool proposal.

An existing-core BLOCK maps to Codex `permissionDecision: "deny"`, with a reason
starting `evidline BLOCK:`.

Malformed covered input, parser failure, state-loading failure,
`MutationInputError`, unexpected core failure, and unknown outcomes map to a
Codex deny whose reason starts `evidline adapter failure:` and states that no
`MutationDecision` was produced. Adapter failure is not represented as an
Evidline policy BLOCK.

### Usability ceiling

The frozen request contract makes real covered requests reach at least ASK.
Because Codex cannot safely express that ASK interactively, activation under the
current architecture would deny covered `apply_patch` calls rather than permit
interactive approval. Phase 6 therefore verifies deterministic transport, not a
usable live authorization workflow.

Target-bound human authority, declared scope, and evidence architecture remain
deferred. Phase 6 does not invent an approval or task-authoring mechanism.

### Activation and runtime limits

No `.codex/**` file is created. Hook configuration, trust review, activation,
command quoting, and live enforcement testing require separate human-authorized
gates.

If the adapter successfully starts, it can translate covered failures to deny.
If the hook is absent, untrusted, not dispatched, cannot start, fails before the
adapter runs, or times out, no Evidline decision reaches Codex. Current live
dispatch and deny behavior remains unverified and may vary by installed version
or tool path.

## Consequences

Phase 6 provides bounded SessionStart context transport and deterministic,
apply_patch-only target enforcement over the existing core. It adds no runtime
dependency, schema change, CLI expansion, core mutation, hook activation, live
enforcement claim, Bash coverage, MCP coverage, or interactive ASK workflow.
