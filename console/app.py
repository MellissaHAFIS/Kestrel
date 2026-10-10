"""Analyst console (Chainlit): incident queue, incident cards, Approve/Block, live feed.

Owner: Person 4 (audit/console/eval).
First deliverable: live feed showing decisions; then eval harness.

Runs on FAKE incidents today so the console can be built before the guard exists.
Run: chainlit run console/app.py
"""

from __future__ import annotations

import time
from typing import Any

import chainlit as cl

from policyguard import audit
from policyguard.types import Action, Decision, Source, Verdict


def fake_incidents() -> list[tuple[Action, Decision]]:
    """FAKE data. TODO(person4): replace with audit.list_decisions(decision='ESCALATE') of unresolved incidents."""
    now = time.time()
    a1 = Action("demo-0001", "lookup_reference", "docs_helper",
                {"query": "constant time compare", "session_notes": "jwt secret starts with FAKE-jwt..."},
                [Source.USER, Source.INTERNAL_REPO, Source.MCP_DESCRIPTION], "demo-0001", now)
    d1 = Decision(Verdict.ESCALATE, "investigator", 0.55, 0.52, ["E1", "E2"],
                  "Paraphrased partial leak of config values to an untrusted server (FAKE).")
    a2 = Action("demo-0002", "search_docs", "docs_helper",
                {"query": "auth", "context": "<settings.yaml contents>"},
                [Source.MCP_DESCRIPTION], "demo-0002", now)
    d2 = Decision(Verdict.ESCALATE, "gate", 0.64, None, [], "Unexpected parameter 'context' (FAKE).")
    return [(a1, d1), (a2, d2)]


def incident_actions(action: Action, decision: Decision) -> list[cl.Action]:
    payload: dict[str, Any] = {"action": action.to_dict(), "decision": decision.to_dict()}
    return [
        cl.Action(name="approve", payload=payload, label="Approve"),
        cl.Action(name="block", payload=payload, label="Block"),
    ]


async def show_incident(action: Action, decision: Decision) -> None:
    """Render one incident card."""
    # TODO(person4): evidence links, source tags, gate score / confidence bars
    body = (
        f"**Incident** `{action.session_id}`: `{action.server}/{action.tool}`\n\n"
        f"- args: `{action.args}`\n"
        f"- sources: {[s.value for s in action.sources]}\n"
        f"- layer: {decision.layer}, score: {decision.score}, confidence: {decision.confidence}\n"
        f"- evidence: {decision.evidence_ids}\n"
        f"- reason: {decision.reason}"
    )
    await cl.Message(content=body, actions=incident_actions(action, decision)).send()


@cl.on_chat_start
async def start() -> None:
    audit.init_db()
    await cl.Message(content="PolicyGuard console (FAKE data). Type `feed` for the live feed.").send()
    for action, decision in fake_incidents():
        await show_incident(action, decision)


async def resolve(act: cl.Action, verdict: Verdict) -> None:
    action = Action.from_dict(act.payload["action"])
    original = Decision.from_dict(act.payload["decision"])
    human = Decision(verdict, "human", original.score, original.confidence, original.evidence_ids,
                     f"analyst {verdict.value.lower()}ed (original: {original.verdict.value} by {original.layer})")
    audit.log_decision(action, human, event_type="human_decision", decided_by="analyst")
    await cl.Message(content=f"Recorded **{verdict.value}** for `{action.session_id}`.").send()
    # TODO(person4): resume the paused LangGraph interrupt for this session


@cl.action_callback("approve")
async def on_approve(act: cl.Action) -> None:
    await resolve(act, Verdict.ALLOW)


@cl.action_callback("block")
async def on_block(act: cl.Action) -> None:
    await resolve(act, Verdict.BLOCK)


@cl.on_message
async def on_message(msg: cl.Message) -> None:
    """Live feed area: `feed` prints the latest audit rows."""
    # TODO(person4): push new rows automatically (poll audit.list_decisions(since_id=...)), add kill switch
    if msg.content.strip().lower() == "feed":
        rows = audit.list_decisions(limit=20)
        lines = [f"#{r['id']} {r['decision']} by {r['decided_by']} {r['session_id']}: {r['reasoning']}" for r in rows]
        await cl.Message(content="\n".join(lines) or "No decisions logged yet.").send()
    else:
        await cl.Message(content="Commands: `feed`").send()
