"""Eval variants 0, R, M, A, I, H behind one common interface.


Each variant maps an Action to a Decision. `evaluate_chain` runs a chain's steps
and the harness decides whether the attack succeeded (an attack step was ALLOWed).
"""

from __future__ import annotations

from typing import Protocol

from policyguard.compat import Decision, Verdict  # pre-freeze names, see policyguard/compat.py
from policyguard.types import Action


class Variant(Protocol):
    """Common interface for every variant."""

    name: str
    description: str

    def decide(self, action: Action) -> Decision: ...


class _Base:
    name = "?"
    description = ""

    def decide(self, action: Action) -> Decision:
        return Decision(Verdict.ALLOW, f"variant-{self.name}", reason="stub")


class NoGuard(_Base):
    name, description = "0", "No guard: DevAssist alone (baseline ASR)"

    def decide(self, action: Action) -> Decision:
        return Decision(Verdict.ALLOW, "variant-0", reason="no guard")


class RulesOnly(_Base):
    name, description = "R", "Regex / deny-list gate"


class MLGateOnly(_Base):
    name, description = "M", "Fixed-weight ML gate, thresholds tuned on validation"


class OneShotJudge(_Base):
    name, description = "A", "One LLM verdict per action"


class InvestigatorOnly(_Base):
    name, description = "I", "Agent loop on every action, no gate"


class Hybrid(_Base):
    name, description = "H", "Registry + invariants + ML gate + Investigator + human"


VARIANTS: dict[str, type[_Base]] = {
    "0": NoGuard,
    "R": RulesOnly,
    "M": MLGateOnly,
    "A": OneShotJudge,
    "I": InvestigatorOnly,
    "H": Hybrid,
}


def get_variant(key: str) -> _Base:
    return VARIANTS[key]()
