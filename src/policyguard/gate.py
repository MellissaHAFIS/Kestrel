"""ML gate: cheap, fast, fixed-weight score for every action.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.
"""

from __future__ import annotations

from policyguard.types import Action, Verdict

# Placeholders. TUNE ON VALIDATION ONLY; the real values live in policy/devassist.yaml.
GATE_LOW = 0.20
GATE_HIGH = 0.80


def score(action: Action) -> float:
    """Risk score in [0, 1].

    Ladder step 1: pretrained HF injection classifier; MUST fall back to a
    deterministic heuristic if model load fails.
    """
    # TODO(person2): load the classifier lazily (extra 'ml'); on any load error use
    #   _heuristic_score(action). Log the model hash with every decision.
    return 0.0


def _heuristic_score(action: Action) -> float:
    """Deterministic fallback (keywords, untrusted sources, arg size)."""
    # TODO(person2)
    return 0.0


def route(gate_score: float, low: float = GATE_LOW, high: float = GATE_HIGH) -> Verdict | None:
    """score < low -> ALLOW, score > high -> BLOCK, in between -> None (Investigator)."""
    if gate_score < low:
        return Verdict.ALLOW
    if gate_score > high:
        return Verdict.BLOCK
    return None
