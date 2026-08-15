# AGENTS.md — Evidline

Canonical, cross-agent guidance for this repository. Codex reads this file directly;
Claude Code reads it through the import in `CLAUDE.md`. Both agents follow it identically.

## Scope of this file

This file holds **durable** project guidance only: what this product is, the doctrine
it enforces, what V1 includes and excludes, and how work is bounded and approved.

This file is **not** a state store. It must never record current branch, working-tree
status, test results, task progress, session history, or a map of the codebase. That
information is derived from fresh evidence at the time it is needed, and is the domain
of Evidline itself. If you are tempted to write volatile state here, that is
a signal the state belongs somewhere else — stop and raise it.

## What Evidline is

A standalone, public, local-first developer tool for AI coding agents such as Claude Code
and OpenAI Codex.

AI agents are the workers. The repository is the house. Evidline is the
architect, inspector, context compiler, and evidence gate.

Its purpose is to:

* preserve verified engineering continuity across fresh sessions;
* supply only the minimum relevant project context;
* distinguish claims from verified facts;
* model architecture, decisions, constraints, evidence, and freshness;
* block unjustified or out-of-scope mutations even when the harness technically permits them.

Evidline **supplements** sandboxing, harness approvals, Git review, OS security,
and human judgment. It replaces none of them and must never be described as if it does.

## Core doctrine

These statements define the product. Code, docs, and behavior are judged against them.

* **Persistent state, selective context.** Retaining a fact and injecting it are separate
  decisions.
* **Permission ≠ authorization ≠ evidence ≠ execution ≠ verification.** These are five
  distinct things and must stay distinct in the model, the code, and the vocabulary.
* **Never silently promote to truth.** Proposals, prior handoffs, agent statements, memory,
  and unsupported inference are not current truth and must not be converted into it without
  an explicit, recorded step.
* **Fresh evidence outranks memory.** Direct disk and tool evidence gathered now outranks
  persisted or remembered state.
* **Volatile facts are re-derived, not recalled.** Branch, working tree, tests, dependency
  state, and PR state must normally be checked again rather than read from stored state.
* **EXECUTED never means VERIFIED.** A command that ran is not a result that holds.

## Established V1 identifiers

These are durable design decisions; they do not imply that a public repository or PyPI
release currently exists.

* Product: Evidline
* Distribution: `evidline`
* Python package: `evidline`
* CLI: `evidline`
* Local state directory: `.evidline/`
* Python: `>=3.11`
* Runtime dependencies: zero
* License: MIT
* Copyright holder: Tenzy Lama

## V1 target

V1 must demonstrate that a small local state and evidence layer measurably improves
cross-session continuity and prevents unsupported project mutations, across both Claude Code
and Codex.

Capabilities in scope for V1 (direction, not yet a frozen design):

* Python package and CLI
* project-local state and evidence layer
* typed and validated state and evidence
* architecture and invariant representation
* current-task and constraint tracking
* selective context compilation with budget reporting
* verified handoff
* mutation decision engine
* Claude Code adapter
* Codex adapter
* doctor / validation
* tests
* controlled benchmark
* public documentation and demo

Nothing above is settled beyond this list. Module layout, data formats, schemas, command
names, dependencies, and test tooling are open decisions. Do not assume any of them exist,
and do not treat a name used in discussion as an established interface.

## V1 non-goals

Do not introduce any of the following by default. Each requires an explicit, separately
approved decision:

embeddings; vector databases; knowledge graphs; Graphify or Serena as required dependencies;
LLM API calls; cloud backend or storage; telemetry; authentication; web dashboard; Docker;
autonomous execution; raw-conversation storage; hidden long-term memory; heavy frameworks.

Prefer deterministic, simple architecture over clever abstraction. Local-first is a product
constraint, not a default that convenience may override.

## How work is bounded

* One bounded phase, one branch, one pull request, once a Git workflow is established.
* Human verification before merge.
* Do not commit, push, merge, open pull requests, release, publish, install or upgrade
  dependencies, create environments, or take any external or public action without explicit
  approval in the current session.
* Finish the phase you were given. Do not widen scope opportunistically; propose follow-on
  work instead of performing it.

## Stop conditions

Stop and surface the issue rather than proceeding when you encounter:

* conflicts, or repository state you cannot confirm;
* privacy ambiguity;
* a path or scope that may be unsafe to touch;
* evidence that contradicts the active plan.

A contradiction between evidence and plan is a finding worth reporting, not an obstacle to
work around.

## Never invent

Do not state unsupported claims as fact.

Volatile current-state facts — including branch, working tree, test status,
dependency state, and PR state — must normally be established from fresh
direct evidence.

Durable accepted project decisions, constraints, architecture, and verified
handoffs may be relied on according to their recorded provenance, verification,
freshness, and supersession status.

If evidence is missing, stale, contradictory, or insufficient for the claim,
report the uncertainty instead of guessing.

Never invent repository state, files, dependencies, commands, test results,
hook behavior, model IDs, or completed actions.

## Source discipline

Facts about Claude Code, Codex, packaging, hooks, security behavior, and integration surfaces
change upstream. Verify them against current primary vendor documentation before implementing
against them. Do not rely on recollection, on this file, or on prior sessions for those facts.
