# Evidline

Evidline is a local-first context compiler, engineering-state/evidence layer, and
evidence-gated mutation boundary for AI coding agents.

The coding agent is the worker, the repository is the house, and Evidline is the
architect, inspector, context compiler, and evidence gate.

* Persistent state, selective context.
* Permission != authorization != evidence != execution != verification.

## Current status

* V1 foundation only; runtime implementation has not started.
* Claude/Codex adapters are not installed.
* `.evidline/` state is not created by this phase.
* No package has been published.
* No public repository is implied by this local checkout.

## V1 proof

1. A fresh coding-agent session receives compact, relevant, explainable verified context.
2. An unsupported mutation is blocked while an explicit low-risk authorized edit is allowed without bureaucracy.

## V1 non-goals

* Cloud backend; LLM API dependency; embeddings/vector DB; knowledge graph.
* Telemetry; authentication; autonomous execution; raw conversation storage.
* Graphify/Serena as required dependencies.

## Development

* Python `>=3.11`
* Zero runtime dependencies
* Package/import/CLI: `evidline`

## License

License decision pending. Do not publish or redistribute as an open-source release until a license is explicitly selected.
