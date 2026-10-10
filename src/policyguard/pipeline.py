"""Pipeline: the single integration seam, review(action) -> Decision.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.

Order of layers (first final decision wins):
    registry -> invariants -> gate -> investigator

Rules:
- Registry: quarantined tools are never reviewed further (QUARANTINE).
- Invariants: a violation is a final BLOCK.
- Gate: score < gate_low -> ALLOW, score > gate_high -> BLOCK, else Investigator.
- Investigator: may ESCALATE / BLOCK / ALLOW with confidence.
- AI can only tighten, never lift a hard-invariant block. Nothing downstream of
  `invariants` may turn a BLOCK into an ALLOW.

Every decision should be written to audit.py by the caller (middleware).
"""

from __future__ import annotations

from policyguard.types import Action, Decision, Verdict


def review(action: Action) -> Decision:
    """Review one action and return the Decision. STUB: allows everything."""
    # TODO(person2): 1) registry quarantine check for (action.server, action.tool)
    # TODO(person2): 2) invariants.check(action, policy) -> return if not None
    # TODO(person2): 3) gate.score(action) and apply thresholds
    # TODO(person3): 4) investigator.graph.investigate(action, gate_score) in the uncertain band
    return Decision(
        verdict=Verdict.ALLOW,
        layer="stub",
        score=None,
        confidence=None,
        evidence_ids=[],
        reason="stub pipeline: no checks implemented",
    )
