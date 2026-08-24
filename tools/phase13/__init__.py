"""Phase 13 live-verification helpers.

These modules implement preflight, digest, probe capture, sanitization,
evidence-record generation, and rollback inspection. They do not activate
hooks, generate a challenge nonce, or claim that live verification ran.
"""

from .contract import (
    BLOCK_REASON,
    CLAUDE_PROVING_TOOL,
    CODEX_PROVING_TOOL,
    LIVE_STATUS,
    is_selected_proving_tool,
    is_uncovered_tool,
)
from .digest import capture_digest
from .evidence import classify_denial, generate_evidence_record
from .preflight import capture_preflight
from .probes import capture_probes, compare_probes
from .rollback import apply_rollback, inspect_rollback
from .sanitize import sanitize_document

__all__ = [
    "BLOCK_REASON",
    "CLAUDE_PROVING_TOOL",
    "CODEX_PROVING_TOOL",
    "LIVE_STATUS",
    "apply_rollback",
    "capture_digest",
    "capture_preflight",
    "capture_probes",
    "classify_denial",
    "compare_probes",
    "generate_evidence_record",
    "inspect_rollback",
    "is_selected_proving_tool",
    "is_uncovered_tool",
    "sanitize_document",
]
