"""Middleware: wraps MCP/LangChain tools, builds an Action per call, runs the pipeline, enforces the Verdict.


CORRECTED against the frozen contract in types.py, which no longer exports
`Source` or `Decision` and whose `Action` carries a single `tool_name` plus a
dict of `args`. This module previously imported `Decision` and called
`pipeline.review`, neither of which exists, so importing it raised ImportError.

Flow for one guarded tool call:
    build_action -> pipeline.run_pipeline -> enforce -> run the real tool
                                                     -> tag the result's provenance

The pipeline writes its own audit rows, so this layer does not duplicate them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langchain_core.tools import BaseTool

from policyguard import pipeline, provenance
from policyguard.compat import Source
from policyguard.types import Action, Verdict

#: Decisions that let the call proceed. Everything else raises ToolBlocked.
_PROCEED = {"allow"}


class ToolBlocked(Exception):
    """Raised when the pipeline refuses a tool call."""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__(f"{verdict.decision} by PolicyGuard: {_first_line(verdict.report)}")
        self.verdict = verdict


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0] if (text or "").strip() else "no reason recorded"


def qualified_name(server: str, tool: str) -> str:
    """``"server.tool"``, the form the policy's `allowed_tools` uses."""
    return f"{server}.{tool}" if server else tool


def build_action(session_id: str, tool: str, server: str, args: dict[str, Any]) -> Action:
    """Build the Action for one tool call, with provenance sources from the session."""
    return Action(
        session_id=session_id,
        tool_name=qualified_name(server, tool),
        args=dict(args),
        sources=[str(s) for s in provenance.sources_for(session_id)] or ["user"],
    )


def enforce(verdict: Verdict) -> None:
    """Raise ToolBlocked unless the verdict lets the call proceed.

    `escalate` does NOT proceed. The human-in-the-loop path (open an incident
    and wait for an analyst, failing closed to BLOCK on timeout) is task 6; until
    it lands, an escalation is refused rather than silently allowed.
    """
    if verdict.decision not in _PROCEED:
        raise ToolBlocked(verdict)


def guard_tool(tool: BaseTool, server: str, session_id: str, llm: Any = None) -> BaseTool:
    """Return `tool` wrapped so every call goes through the pipeline first."""
    original_coroutine = getattr(tool, "coroutine", None)
    original_func = getattr(tool, "func", None)
    if original_coroutine is None and original_func is None:
        return tool

    async def _guarded(*args: Any, **kwargs: Any) -> Any:
        action = build_action(session_id, tool.name, server, kwargs)
        verdict = await pipeline.run_pipeline(action, llm)
        enforce(verdict)

        if original_coroutine is not None:
            result = await original_coroutine(*args, **kwargs)
        else:
            result = original_func(*args, **kwargs)

        # A tool result is untrusted input to whatever the agent does next.
        provenance.tag(session_id, str(result), Source.TOOL_RESULT)
        return result

    tool.coroutine = _guarded
    # A sync entry point would bypass the guard, so remove it.
    if hasattr(tool, "func"):
        tool.func = None
    return tool


def guard_tools(
    tools: list[BaseTool],
    server_of: Callable[[BaseTool], str],
    session_id: str,
    llm: Any = None,
) -> list[BaseTool]:
    """Wrap a list of tools."""
    return [guard_tool(t, server_of(t), session_id, llm) for t in tools]
