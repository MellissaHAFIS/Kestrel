"""PolicyGuard shared contract: SourceLabel, Action, Evidence, Verdict, AuditEntry.

# =====================================================================
# FROZEN CONTRACT: do not change without updating every consumer.
# =====================================================================

Every component builds against these types.

Pydantic v2 models. Pure data: no I/O, no business logic, no validation rules
beyond the field types themselves. Serialize with `model_dump()` /
`model_dump_json()`, deserialize with `model_validate()` /
`model_validate_json()`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# ── Source provenance ──────────────────────────────────────────────────────

SourceLabel = Literal["user", "internal_repo", "mcp_description", "tool_result"]

# ── One intercepted agent action ───────────────────────────────────────────


class Action(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool_name: str
    args: dict  # raw tool arguments
    sources: list[SourceLabel]  # provenance of content in args
    gate_score: float | None = None  # filled after the ML gate runs


# ── Evidence collected by the Investigator ─────────────────────────────────


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4()}")
    tool_name: str  # which investigation tool produced this
    observation: str  # raw text output from the tool
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ── Final verdict from the Investigator ───────────────────────────────────


class Verdict(BaseModel):
    action_id: str
    decision: Literal["allow", "block", "sanitize", "escalate"]
    confidence: float  # 0.0–1.0
    gate_score: float  # passed in from the gate
    evidence: list[Evidence]
    # report: every factual claim MUST be followed by [EVD-<id>]
    report: str
    sources: list[SourceLabel]
    steps_used: int
    latency_ms: float
    verified: bool = False  # set by EvidenceVerifier


# ── One row in the audit log ───────────────────────────────────────────────


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: Literal[
        "registry_scan", "tool_call", "investigation", "human_decision", "session_kill"
    ]
    action: str  # short human-readable description
    source_labels: list[SourceLabel]
    layer: Literal["registry", "invariant", "ml_gate", "investigator", "human"]
    gate_score: float | None = None
    model_hash: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    violation: bool = False
    severity: Literal["low", "medium", "high", "critical"] = "low"
    confidence: float | None = None
    reasoning: str = ""
    decision: Literal[
        "allow", "block", "sanitize", "quarantine", "escalate", "pending", "killed"
    ] = "pending"
    decided_by: Literal["system", "investigator", "human"] = "system"
    steps_used: int = 0
    latency_ms: float = 0.0
