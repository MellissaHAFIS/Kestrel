"""PolicyGuard shared contract: Source, Verdict, Action, Evidence, Decision.

# =====================================================================
# FROZEN CONTRACT: changing this needs all four owners to agree.
# =====================================================================

Every component builds against these types. The single integration seam is
`policyguard.pipeline.review(action: Action) -> Decision`.

Stdlib only. Everything is JSON-serializable through to_dict()/from_dict().
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
    """Final outcome of a review."""

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
    """An observation collected by an Investigator tool. Reports may only cite these ids."""

    id: str
    tool: str
    observation: str
    source: Source | None
    ts: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "observation": self.observation,
            "source": self.source.value if self.source is not None else None,
            "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        src = d.get("source")
        return cls(
            id=d["id"],
            tool=d["tool"],
            observation=d["observation"],
            source=Source(src) if src is not None else None,
            ts=float(d["ts"]),
        )


@dataclass
class Decision:
    """Outcome of pipeline.review(). `layer` names who decided (registry, invariants, gate, investigator, ...)."""

    verdict: Verdict
    layer: str
    score: float | None = None
    confidence: float | None = None
    evidence_ids: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "layer": self.layer,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Decision:
        return cls(
            verdict=Verdict(d["verdict"]),
            layer=d["layer"],
            score=d.get("score"),
            confidence=d.get("confidence"),
            evidence_ids=list(d.get("evidence_ids", [])),
            reason=d.get("reason", ""),
        )
