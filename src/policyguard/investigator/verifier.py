"""Grounding, confidence and the deterministic verdict floor.

Three jobs, all deterministic and all outside the model's control:

1. **Grounding** -- every claim must cite evidence, every cited id must exist,
   AND the cited evidence must come from a tool capable of supporting that kind
   of claim. A "secret in args" claim citing a `check_destination` result is
   ungrounded even though the id exists.
2. **Confidence** -- computed from the evidence, never self-reported. The model
   may only *lower* it.
3. **Verdict floor** -- applied after the model has spoken. The model can only
   ever tighten the outcome; it can never talk its way to ALLOW.

This is the module that has to hold even when the model is hostile, because the
Investigator reads attacker-controlled text. Nothing here trusts the model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from policyguard.types import Evidence

#: Default floor for returning ALLOW. Overridden from
#: `thresholds.investigator_min_confidence` in policy/devassist.yaml.
DEFAULT_MIN_CONFIDENCE = 0.70


# ── Claims ─────────────────────────────────────────────────────────────────


@dataclass
class Claim:
    """One claim in the report and the evidence ids that support it."""

    text: str
    evidence_ids: list[str] = field(default_factory=list)


#: Which tools can support which kind of claim. A claim whose kind is not
#: recognised carries no tool constraint (it still has to cite something).
KIND_TOOLS: dict[str, set[str]] = {
    "secret": {"scan_secrets"},
    "canary": {"scan_secrets", "check_canary"},
    "destination": {"check_destination"},
    "provenance": {"get_provenance", "get_session_history"},
    "sensitive_path": {"classify_path"},
    "tool_integrity": {"inspect_tool"},
    "policy": {"read_policy"},
}

_KIND_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("canary", re.compile(r"\bcanary|honeytoken\b", re.I)),
    ("secret", re.compile(r"\bsecret|credential|api[ _-]?key|token|password\b", re.I)),
    ("destination", re.compile(r"\bdestination|domain|host|url|exfiltrat|untrusted server\b", re.I)),
    ("provenance", re.compile(r"\bprovenance|source|originated|injected|history\b", re.I)),
    ("sensitive_path", re.compile(r"\bsensitive path|\.env|private key|file path\b", re.I)),
    ("tool_integrity", re.compile(r"\btool description|registry|quarantin|pinned hash\b", re.I)),
    ("policy", re.compile(r"\bpolicy|mandate|allowed tools\b", re.I)),
]


def infer_claim_kind(text: str) -> str | None:
    """Best-effort classification of what a claim asserts. Order matters:
    canary is checked before secret because a canary hit is the stronger,
    more specific finding."""
    for kind, pattern in _KIND_PATTERNS:
        if pattern.search(text):
            return kind
    return None


# ── Grounding ──────────────────────────────────────────────────────────────


@dataclass
class VerifierResult:
    grounded: bool
    missing_ids: list[str] = field(default_factory=list)  # cited but never collected
    ungrounded_claims: list[str] = field(default_factory=list)  # claims citing nothing
    mismatched_claims: list[str] = field(default_factory=list)  # cited the wrong kind of tool

    @property
    def reason(self) -> str:
        parts = []
        if self.missing_ids:
            parts.append(f"fabricated evidence ids: {', '.join(self.missing_ids)}")
        if self.ungrounded_claims:
            parts.append(f"{len(self.ungrounded_claims)} claim(s) cite no evidence")
        if self.mismatched_claims:
            parts.append(f"{len(self.mismatched_claims)} claim(s) cite the wrong kind of evidence")
        return "; ".join(parts) or "grounded"


def verify(report_claims: list[Claim], evidence: list[Evidence]) -> VerifierResult:
    """Grounded iff every claim cites at least one existing id AND at least one
    cited id comes from a tool that can support that kind of claim.

    An empty claim list is NOT grounded: a report that asserts nothing cannot
    justify a verdict.
    """
    by_id = {e.id: e for e in evidence}
    missing: list[str] = []
    ungrounded: list[str] = []
    mismatched: list[str] = []

    for claim in report_claims:
        if not claim.evidence_ids:
            ungrounded.append(claim.text)
            continue

        unknown = [eid for eid in claim.evidence_ids if eid not in by_id]
        for eid in unknown:
            if eid not in missing:
                missing.append(eid)

        known = [by_id[eid] for eid in claim.evidence_ids if eid in by_id]
        if not known:
            continue

        kind = infer_claim_kind(claim.text)
        allowed = KIND_TOOLS.get(kind) if kind else None
        if allowed and not any(e.tool_name in allowed for e in known):
            mismatched.append(claim.text)

    grounded = bool(report_claims) and not missing and not ungrounded and not mismatched
    return VerifierResult(
        grounded=grounded,
        missing_ids=missing,
        ungrounded_claims=ungrounded,
        mismatched_claims=mismatched,
    )


# ── Signals extracted from evidence ────────────────────────────────────────


@dataclass
class Signals:
    """What the evidence actually establishes. Derived from tool output only."""

    secret_hit: bool = False
    canary_hit: bool = False
    untrusted_destination: bool = False
    sensitive_path: bool = False
    untrusted_source: bool = False
    clean_checks: int = 0

    @property
    def violating(self) -> bool:
        return (
            self.secret_hit
            or self.canary_hit
            or self.untrusted_destination
            or self.sensitive_path
        )


def _payload(observation: str) -> dict[str, Any]:
    try:
        parsed = json.loads(observation)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def extract_signals(evidence: list[Evidence], sources: list[str] | None = None) -> Signals:
    """Reduce raw tool observations to the handful of facts that drive the verdict."""
    s = Signals()
    for item in evidence:
        data = _payload(item.observation)
        if item.tool_name == "scan_secrets":
            if data.get("secrets_found"):
                s.secret_hit = True
            if data.get("canary_hit"):
                s.canary_hit = True
            if not data.get("secrets_found") and not data.get("canary_hit"):
                s.clean_checks += 1
        elif item.tool_name == "check_canary":
            if data.get("hit"):
                s.canary_hit = True
            else:
                s.clean_checks += 1
        elif item.tool_name == "check_destination":
            # Absence of trust is itself a signal: unknown hosts are untrusted.
            if data.get("blocked") or not data.get("trusted", False):
                s.untrusted_destination = True
            else:
                s.clean_checks += 1
        elif item.tool_name == "classify_path":
            if data.get("sensitive"):
                s.sensitive_path = True
            else:
                s.clean_checks += 1
        elif item.tool_name in {"get_provenance", "get_session_history", "inspect_tool"}:
            s.clean_checks += 1

    for label in sources or []:
        if label in {"mcp_description", "tool_result"}:
            s.untrusted_source = True
    return s


# ── Confidence ─────────────────────────────────────────────────────────────

#: Weights for violating evidence. Ordered strongest first.
_VIOLATION_WEIGHTS: list[tuple[str, float]] = [
    ("canary_hit", 0.45),
    ("secret_hit", 0.35),
    ("sensitive_path", 0.10),
    ("untrusted_destination", 0.15),
    ("untrusted_source", 0.05),
]

_BLOCK_BASE = 0.30
_ALLOW_BASE = 0.40
_ALLOW_PER_CLEAN_CHECK = 0.15
_ALLOW_CAP = 0.95
_UNTRUSTED_SOURCE_PENALTY = 0.20


def compute_confidence(signals: Signals, decision: str) -> float:
    """Confidence in the RETURNED VERDICT, computed from evidence alone.

    This is deliberately not symmetric, because the two directions mean
    different things:

    * **block / escalate** -- confidence rises with the strength of the
      violating evidence. Starts at 0.30 and adds, strongest first:
      canary hit 0.45, secret hit 0.35, untrusted destination 0.15,
      sensitive path 0.10, untrusted source 0.05. A canary reaching an
      untrusted destination therefore scores 0.30+0.45+0.15 = 0.90.

    * **allow** -- confidence rises with the number of checks that ran and
      found nothing, because an ALLOW is only as trustworthy as the breadth of
      the search behind it. Starts at 0.40, adds 0.15 per clean check, caps at
      0.95, and loses 0.20 if any content came from an untrusted source.
      One clean check gives 0.55, which is below the 0.70 ALLOW floor on
      purpose: a single check is not enough to clear an action.

    Any violating signal forces an allow-confidence of 0.0, so the floor in
    `apply_verdict_floor` cannot be satisfied by an allow that contradicts its
    own evidence.

    Returns a value in [0.0, 1.0]. The model never supplies this; it may only
    lower the result via `apply_model_confidence`.
    """
    if decision in {"block", "escalate", "sanitize"}:
        score = _BLOCK_BASE
        for name, weight in _VIOLATION_WEIGHTS:
            if getattr(signals, name):
                score += weight
        return round(min(score, 1.0), 4)

    if signals.violating:
        return 0.0

    score = _ALLOW_BASE + _ALLOW_PER_CLEAN_CHECK * signals.clean_checks
    if signals.untrusted_source:
        score -= _UNTRUSTED_SOURCE_PENALTY
    return round(max(0.0, min(score, _ALLOW_CAP)), 4)


def apply_model_confidence(computed: float, model_confidence: float | None) -> float:
    """The model may only lower confidence, never raise it."""
    if model_confidence is None:
        return computed
    try:
        reported = float(model_confidence)
    except (TypeError, ValueError):
        return computed
    return round(min(computed, max(0.0, min(reported, 1.0))), 4)


# ── Verdict floor ──────────────────────────────────────────────────────────


@dataclass
class FloorResult:
    decision: str
    reason: str
    tightened: bool = False


def apply_verdict_floor(
    model_decision: str,
    signals: Signals,
    grounded: bool,
    confidence: float,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> FloorResult:
    """Clamp the model's proposal to what the evidence permits.

    Applied in order, first match wins:

    1. A secret or canary heading for an untrusted destination is BLOCK. No
       report, however confident, can allow it.
    2. An ungrounded report is ESCALATE and marked unverified.
    3. An unrecognised decision is ESCALATE (malformed model output).
    4. ALLOW requires confidence >= `min_confidence`; below that, ESCALATE.
    5. ALLOW is impossible while any violating signal stands; ESCALATE.
    6. Otherwise the model's decision stands -- it may always tighten.

    Never lifts a hard-invariant BLOCK: invariants run before the Investigator
    in `pipeline.run_pipeline`, so a blocked action never reaches this code.
    """
    proposed = (model_decision or "").strip().lower()

    if (signals.secret_hit or signals.canary_hit) and signals.untrusted_destination:
        what = "canary token" if signals.canary_hit else "secret"
        return FloorResult(
            "block",
            f"floor: {what} bound for an untrusted destination can never be allowed",
            tightened=proposed != "block",
        )

    if not grounded:
        return FloorResult(
            "escalate", "floor: report is unverified (ungrounded)", tightened=proposed != "escalate"
        )

    if proposed not in {"allow", "block", "sanitize", "escalate"}:
        return FloorResult(
            "escalate",
            f"floor: unrecognised verdict {model_decision!r}; escalating",
            tightened=True,
        )

    if proposed == "allow" and signals.violating:
        return FloorResult(
            "escalate", "floor: allow contradicts violating evidence", tightened=True
        )

    if proposed == "allow" and confidence < min_confidence:
        return FloorResult(
            "escalate",
            f"floor: confidence {confidence:.2f} below the {min_confidence:.2f} allow threshold",
            tightened=True,
        )

    return FloorResult(proposed, "model verdict stands", tightened=False)
