"""Investigator LangGraph skeleton: reason <-> tools -> verify -> verdict -> human_interrupt.

Owner: Person 3 (investigator).
First deliverable: loop resolves the paraphrased-leak case with a grounded report.

Flow:
    reason --(needs evidence & steps left)--> tools --> reason
    reason --(done or out of steps)--------> verify --> verdict
    verdict --(low confidence / ungrounded)--> human_interrupt --> END
    verdict --(confident & grounded)---------> END
The Investigator can only tighten (BLOCK/ESCALATE), never lift an invariant block.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from policyguard.types import Action, Decision, Evidence, Source, Verdict


class InvestigatorState(TypedDict):
    action_under_review: Action
    evidence: list[Evidence]
    confidence: float
    steps_used: int
    gate_score: float
    sources: list[Source]
    # Filled by `verdict`:
    decision: Decision | None


def initial_state(action: Action, gate_score: float) -> InvestigatorState:
    return InvestigatorState(
        action_under_review=action,
        evidence=[],
        confidence=0.0,
        steps_used=0,
        gate_score=gate_score,
        sources=list(action.sources),
        decision=None,
    )


# --- Nodes (all stubs) -----------------------------------------------------
def reason(state: InvestigatorState) -> dict[str, Any]:
    """LLM decides: call a tool (which?) or finish with a draft report."""
    # TODO(person3): LLM call with tool-calling; honor policy max_steps; MOCK_LLM canned path
    return {"steps_used": state["steps_used"] + 1}


def tools(state: InvestigatorState) -> dict[str, Any]:
    """Execute requested investigator tools and append Evidence."""
    # TODO(person3): dispatch to investigator.tools, assign evidence ids (E1, E2, ...)
    return {}


def verify(state: InvestigatorState) -> dict[str, Any]:
    """Check every cited evidence id exists (verifier.verify)."""
    # TODO(person3): call verifier.verify(report_claims, state["evidence"])
    return {}


def verdict(state: InvestigatorState) -> dict[str, Any]:
    """Turn the grounded report into a Decision with confidence."""
    # TODO(person3): map to ALLOW/BLOCK/ESCALATE; abstain -> ESCALATE
    d = Decision(
        verdict=Verdict.ESCALATE,
        layer="investigator",
        score=state["gate_score"],
        confidence=state["confidence"],
        evidence_ids=[e.id for e in state["evidence"]],
        reason="not implemented",
    )
    return {"decision": d}


def human_interrupt(state: InvestigatorState) -> dict[str, Any]:
    """Pause for the analyst (langgraph.types.interrupt) with the incident card."""
    # TODO(person3): interrupt({...}) and resume with the analyst's Approve/Block
    return {}


# --- Routing ---------------------------------------------------------------
def route_after_reason(state: InvestigatorState) -> str:
    # TODO(person3): "tools" while the LLM requests tools and steps_used < policy.max_steps
    return "verify"


def route_after_verdict(state: InvestigatorState) -> str:
    d = state["decision"]
    # TODO(person3): also interrupt when the report is ungrounded or confidence < threshold
    return "human_interrupt" if d is not None and d.verdict is Verdict.ESCALATE else END


def build_graph() -> Any:
    """Compile the LangGraph state machine."""
    g = StateGraph(InvestigatorState)
    g.add_node("reason", reason)
    g.add_node("tools", tools)
    g.add_node("verify", verify)
    g.add_node("verdict", verdict)
    g.add_node("human_interrupt", human_interrupt)
    g.add_edge(START, "reason")
    g.add_conditional_edges("reason", route_after_reason, {"tools": "tools", "verify": "verify"})
    g.add_edge("tools", "reason")
    g.add_edge("verify", "verdict")
    g.add_conditional_edges("verdict", route_after_verdict, {"human_interrupt": "human_interrupt", END: END})
    g.add_edge("human_interrupt", END)
    return g.compile()


def investigate(action: Action, gate_score: float) -> Decision:
    """Investigate an uncertain action. STUB: always ESCALATE, graph is not run yet."""
    # TODO(person3): return build_graph().invoke(initial_state(action, gate_score))["decision"]
    return Decision(
        verdict=Verdict.ESCALATE,
        layer="investigator",
        score=gate_score,
        confidence=0.0,
        evidence_ids=[],
        reason="not implemented",
    )
