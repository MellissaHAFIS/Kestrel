"""Compatibility shim for the pre-freeze PolicyGuard contract.

WHY THIS EXISTS
---------------
`types.py` is a FROZEN CONTRACT and was reshaped after several modules had
already been written against an earlier version of it. The earlier version
exported `Source` (enum), `Decision`, an enum-style `Verdict` and an
`Evidence(kind, detail)`; the frozen contract exports none of those. The result
was that `invariants.py`, `provenance.py`, `middleware.py` and
`investigator/graph.py` all raised ImportError, which in turn made
`pipeline.run_pipeline` fail closed and block every action.

Rather than rewrite `invariants.py` (a large, well-tested guarantee layer owned
by another developer), this module re-publishes the old vocabulary so that
module keeps working verbatim. Nothing here changes `types.py`.

INTEROP
-------
`Source` and `Verdict` subclass `str`, so they compare equal to the frozen
contract's string literals: `Source.USER == "user"` and
`Verdict.BLOCK == "block"` are both True. That lets legacy code and
frozen-contract code exchange values without a translation table.

Use `as_legacy_action()` at the boundary to feed a frozen `Action` into
legacy code that expects `.tool` / `.server`.

NEW CODE SHOULD IMPORT FROM `policyguard.types`, NOT FROM HERE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from policyguard.types import Action as FrozenAction

# ── Legacy enums (str-backed so they interoperate with the frozen literals) ──


class Source(str, Enum):
    """Provenance of content, mirroring the frozen `SourceLabel` literals."""

    USER = "user"
    INTERNAL_REPO = "internal_repo"
    MCP_DESCRIPTION = "mcp_description"
    TOOL_RESULT = "tool_result"


class Verdict(str, Enum):
    """Outcome of a guard layer, mirroring the frozen `Verdict.decision` literals.

    NOTE: the frozen contract also calls its *model* `Verdict`. Inside legacy
    modules this enum shadows that name; that is intentional and contained.
    """

    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"


# ── Legacy data carriers ────────────────────────────────────────────────────


@dataclass
class Evidence:
    """One finding from a deterministic layer.

    Mutable on purpose: `invariants.check_invariants` assigns `id` after the
    fact so ids are deterministic (`inv-1`, `inv-2`, ...) in rule order.
    """

    id: str
    kind: str
    detail: str


@dataclass
class Decision:
    """A layer's ruling, with the evidence that produced it."""

    verdict: Verdict
    layer: str
    reason: str
    score: float = 0.0
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict view, used to assert that two runs are byte-identical."""
        return {
            "verdict": self.verdict.value,
            "layer": self.layer,
            "reason": self.reason,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "evidence": [
                {"id": e.id, "kind": e.kind, "detail": e.detail} for e in self.evidence
            ],
        }


@dataclass
class Action:
    """The pre-freeze Action shape, with `tool` and `server` split apart."""

    session_id: str
    tool: str
    server: str
    args: dict[str, Any]
    sources: list[Source] = field(default_factory=list)
    history_ref: str | None = None
    ts: float = 0.0

    @property
    def qualified_tool(self) -> str:
        """``"server.tool"``, the form used by `allowed_tools` in the policy."""
        return f"{self.server}.{self.tool}" if self.server else self.tool


# ── Boundary adapter ───────────────────────────────────────────────────────


def as_legacy_action(action: FrozenAction) -> Action:
    """Adapt a frozen `Action` for legacy code that wants `.tool` / `.server`.

    The frozen contract carries a single `tool_name`. By convention it is
    fully qualified as ``"server.tool"`` (matching `allowed_tools` in
    `policy/devassist.yaml`). An unqualified name yields an empty server,
    which `Policy.is_trusted` treats as untrusted -- the safe direction.
    """
    server, _, tool = action.tool_name.rpartition(".")
    return Action(
        session_id=action.session_id,
        tool=tool or action.tool_name,
        server=server,
        args=dict(action.args),
        sources=[Source(s) for s in action.sources],
        history_ref=action.session_id,
        ts=action.timestamp.timestamp() if action.timestamp else 0.0,
    )
