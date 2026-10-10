"""Middleware: wraps MCP/LangChain tools, builds an Action per call, calls pipeline.review, enforces the Decision.

Owner: Person 1 (demo env).
First deliverable: attack works with no guard; every call produces an Action.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from langchain_core.tools import BaseTool

from policyguard import pipeline, provenance
from policyguard.types import Action, Decision, Verdict


class ToolBlocked(Exception):
    """Raised when the pipeline refuses a tool call."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"{decision.verdict.value} by {decision.layer}: {decision.reason}")
        self.decision = decision


def build_action(session_id: str, tool: str, server: str, args: dict[str, Any]) -> Action:
    """Build the Action for one tool call, with provenance sources from the session."""
    return Action(
        session_id=session_id,
        tool=tool,
        server=server,
        args=dict(args),
        sources=provenance.sources_for(session_id),
        history_ref=session_id,
        ts=time.time(),
    )


def enforce(decision: Decision, on_escalate: Callable[[Action, Decision], Verdict] | None = None) -> None:
    """Raise ToolBlocked unless the decision lets the call proceed."""
    # TODO(person1): ESCALATE -> wait for the analyst (LangGraph interrupt / console); QUARANTINE -> hide tool
    if decision.verdict is not Verdict.ALLOW:
        raise ToolBlocked(decision)


def guard_tool(tool: BaseTool, server: str, session_id: str) -> BaseTool:
    """Return `tool` wrapped so every call goes through pipeline.review first.

    STUB: returns the tool unchanged (no interception yet).
    """
    # TODO(person1): wrap tool.coroutine / tool.func:
    #   action = build_action(...); decision = pipeline.review(action)
    #   audit.log_decision(...); enforce(decision); then call the original tool and
    #   provenance.tag(session_id, result, Source.TOOL_RESULT)
    return tool


def guard_tools(tools: list[BaseTool], server_of: Callable[[BaseTool], str], session_id: str) -> list[BaseTool]:
    """Wrap a list of tools."""
    return [guard_tool(t, server_of(t), session_id) for t in tools]
