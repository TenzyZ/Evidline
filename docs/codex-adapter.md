# Codex adapter

Evidline Phase 6 provides a local, stateless Codex transport over the existing
context, path, state, and mutation-policy cores. It does not install or activate
a hook, grant Codex permission, or prove live Codex enforcement.

## Architecture

The adapter is invoked directly as:

```text
python -m evidline.adapters.codex session-start
python -m evidline.adapters.codex pre-tool-use
```

Both commands read one JSON object from stdin. The adapter has no runtime
dependencies, network access, subprocess use, persistence, or cache. It does not
change the Evidline CLI or package entry points.

Session context follows this path:

```text
Codex SessionStart
→ validate transport
→ discover_project_root(cwd)
→ load_and_compile(root, SESSION, budget_chars=None)
→ render_payload(...)
→ hookSpecificOutput.additionalContext
```

Mutation handling follows this path:

```text
Codex PreToolUse for canonical apply_patch
→ validate transport
→ extract the complete target set for the frozen parser subset
→ anchor relative targets at cwd
→ evaluate every target through evaluate_and_decide(...)
→ collapse BLOCK > ASK > ALLOW atomically
→ emit deny or silence
```

Core path and mutation policy remain in `evidline.paths` and
`evidline.mutation`. The adapter only translates Codex transport into those
existing APIs.

## SessionStart

`SessionStart` requires an object input, `hook_event_name: "SessionStart"`, and
a non-empty string `cwd`. The documented `startup`, `resume`, `clear`, and
`compact` sources all compile the same fresh SESSION context. An unknown source
does the same because source metadata does not establish policy.

Successful output is structured JSON:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "<current rendered SESSION payload>"
  }
}
```

The project's current `default_budget_chars` applies through
`budget_chars=None`. No context is persisted or cached. If no initialized
Evidline root can be discovered, the command exits successfully with empty
stdout. Invalid input, unavailable state, or context compilation failure also
produces empty stdout and one concise stderr diagnostic; those advisory failures
do not become mutation decisions.

Codex controls its own handling of large `additionalContext`. Its current hook
runtime can spill oversized context to a temporary file and provide a shorter
preview according to `additionalContextLimit` and runtime behavior. Phase 6 does
not configure, suppress, or verify that behavior.

## apply_patch coverage

`PreToolUse` enforcement is intentionally limited to the canonical
`tool_name: "apply_patch"` input with raw patch text in
`tool_input.command`. All other tools are silent and do not call the mutation
core. Uncovered surfaces include:

- `Bash`, including shell-invoked `apply_patch`;
- PowerShell and other shell payloads;
- MCP tools;
- `spawn_agent` and other agent orchestration;
- unknown or arbitrary local functions; and
- any future tool not named exactly `apply_patch`.

The adapter does not parse shell commands or infer file mutation from tool
content.

## Frozen parser boundary

The parser extracts targets only. It does not interpret patch content or claim
equivalence with every patch Codex may accept.

Supported envelopes are a direct `*** Begin Patch` / `*** End Patch` patch and
the exact `<<EOF`, `<<'EOF'`, or `<<"EOF"` wrappers accepted by the frozen
contract. Supported target markers are `*** Add File:`, `*** Delete File:`,
`*** Update File:`, and one immediately attached `*** Move to:` for an update.
It accepts only the frozen hunk and body line forms: `@@`, `@@ ...`,
`*** End of File`, lines beginning `+`, `-`, or one literal space, and empty
lines.

An environment ID, malformed envelope, empty target, orphan or repeated move,
zero-operation patch, or unclassified residual line is an adapter failure. The
adapter fails closed because it cannot prove target completeness.

For a supported rename, both source and destination are evaluated. Relative
targets are anchored with `os.path.join(cwd, path)`; absolute targets pass
through unchanged. The adapter performs no normalization, realpath resolution,
case folding, separator conversion, `..` collapse, or protected-path detection.
Those checks remain the responsibility of the existing path core.

Targets preserve first appearance order and are de-duplicated by exact anchored
string equality. Every unique target is evaluated once. One disposition covers
the complete patch: `BLOCK` outranks `ASK`, which outranks `ALLOW`; the first
target wins a same-severity tie. There is no partial application decision.

The precise product claim is:

> For patch forms accepted by Evidline's frozen parser, the adapter extracts the
> complete mutation-target set. Unsupported, malformed, ambiguous, or
> parser-divergent forms are denied as adapter failure.

## Outcomes

The adapter uses the immutable request contract
`request_intent = PROPOSED`, `risk = NORMAL`, `operation = None`, and empty
authority, scope, claim, evidence, and asserted-conflict IDs. A Codex tool call
is only a proposal. Permission mode, model, agent metadata, operation marker,
patch size, file count, filename, and extension do not strengthen intent or
classify risk.

| Evidline result | Codex transport |
| --- | --- |
| `ALLOW` | Exit 0 with empty stdout |
| `ASK` | `permissionDecision: "deny"`; reason starts `evidline ASK:` |
| `BLOCK` | `permissionDecision: "deny"`; reason starts `evidline BLOCK:` |
| Adapter failure | `permissionDecision: "deny"`; reason starts `evidline adapter failure:` and states that no `MutationDecision` was produced |

The adapter never emits Codex `allow` or `ask`. An Evidline ALLOW is not a Codex
permission grant. An adapter failure is not fabricated as an Evidline policy
BLOCK.

Current Codex hook behavior does not safely represent Evidline ASK as an
interactive approval. Native `permissionDecision: "ask"` is unsupported and can
fail the hook while the tool call continues. `PermissionRequest` is not a
universal substitute because it runs only when Codex independently decides to
request approval.

Every real covered request remains `PROPOSED`. The core may derive bounded
authority from a trusted, ACTIVE Task whose `authorized_scope` contains the
canonical target; an otherwise permitted NORMAL target can then reach ALLOW and
the adapter stays silent. Without that exact binding, the request reaches at
least ASK and Codex transport denies it. This does not make the adapter a live
authorization workflow or a complete shell-security boundary.

## Runtime boundary

After a successfully started adapter receives covered input, malformed patch
transport, state failures, core input failures, unknown outcomes, and unexpected
evaluation failures produce a structured adapter-failure deny. That local
behavior does not make hooks an unconditional security boundary.

No Evidline decision reaches Codex if the hook is not configured, not trusted,
not dispatched, cannot start, fails before the adapter runs, or times out.
Unsupported hook output can also fail open. Current Codex versions and tool paths
have had version-sensitive dispatch and enforcement behavior, so Phase 6 makes
no claim that a live installed build invokes or enforces this adapter.

## Verification status

**INACTIVE / NOT INSTALLED / NOT VERIFIED**

Phase 6 creates no `.codex/**` configuration and performs no live Codex hook
test. Synthetic unit tests verify only this claim: given a synthetic valid hook
payload delivered to a successfully running adapter process, the adapter
deterministically produces the frozen Evidline-derived transport output.

Phase 6 does not verify:

- installed Codex dispatch for every expected `apply_patch`;
- hook startup, trust, hash review, timeout, or synchronous execution;
- Windows command quoting;
- live deny enforcement;
- project or user configuration; or
- production enforcement.

Hook activation and live runtime verification require separate, explicitly
authorized future gates. See the
[current official Codex hook documentation](https://learn.chatgpt.com/codex/hooks)
for the upstream transport contract; do not treat that reference as authority to
create configuration in this phase.
