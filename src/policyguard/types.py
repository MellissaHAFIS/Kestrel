"""PolicyGuard shared contract: Source, Verdict, Action, Evidence, Decision.

# =====================================================================
# FROZEN CONTRACT: changing this needs all owners to agree.
# =====================================================================

Every component builds against these types. Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Source(str, Enum):
    """Where a piece of content came from (provenance tag)."""

    USER = "user"
    INTERNAL_REPO = "internal_repo"
    MCP_DESCRIPTION = "mcp_description"
    TOOL_RESULT = "tool_result"

    @property
    def is_trusted(self) -> bool:
        """USER and INTERNAL_REPO are trusted; MCP_DESCRIPTION and TOOL_RESULT are not."""
        return self in (Source.USER, Source.INTERNAL_REPO)


class Verdict(str, Enum):
    """Final outcome of a review. Values equal their names."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    QUARANTINE = "QUARANTINE"


@dataclass
class Action:
    """A tool call about to be executed by the agent.

    `sources` lists the provenance of content that preceded this action in the
    session (what could have influenced it). `history_ref` points to the session
    history (e.g. a session id or audit row id) for the Investigator.
    """

    session_id: str
    tool: str
    server: str
    args: dict[str, Any]
    sources: list[Source]
    history_ref: str | None
    ts: float

    @property
    def qualified_tool(self) -> str:
        """Fully-qualified tool name: ``server.tool``."""
        return f"{self.server}.{self.tool}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tool": self.tool,
            "server": self.server,
            "args": dict(self.args),
            "sources": [s.value for s in self.sources],
            "history_ref": self.history_ref,
            "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Action:
        return cls(
            session_id=d["session_id"],
            tool=d["tool"],
            server=d["server"],
            args=dict(d.get("args", {})),
            sources=[Source(s) for s in d.get("sources", [])],
            history_ref=d.get("history_ref"),
            ts=float(d["ts"]),
        )


@dataclass
class Evidence:
    """A single observation that justifies a Decision.

    `kind` is a short machine-readable tag (e.g. ``canary_match``). `detail`
    is human-readable and MUST NOT contain the raw matched secret. `source_tool`
    names the component that produced the evidence.
    """

    id: str
    kind: str
    detail: str
    source_tool: str = "invariants"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "detail": self.detail,
            "source_tool": self.source_tool,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        return cls(
            id=d["id"],
            kind=d["kind"],
            detail=d["detail"],
            source_tool=d.get("source_tool", "invariants"),
        )


@dataclass
class Decision:
    """Outcome of a review layer. `layer` names who decided (invariants, gate, ...)."""

    verdict: Verdict
    layer: str
    reason: str
    score: float | None = None
    confidence: float | None = None
    evidence_ids: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "layer": self.layer,
            "reason": self.reason,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Decision:
        return cls(
            verdict=Verdict(d["verdict"]),
            layer=d["layer"],
            reason=d.get("reason", ""),
            score=d.get("score"),
            confidence=d.get("confidence"),
            evidence_ids=list(d.get("evidence_ids", [])),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
        )
