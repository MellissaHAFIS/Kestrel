"""LLM providers for the Investigator: a narrow interface, MockLLM, and DeepSeek.

MockLLM is the DEFAULT in tests and the AUTOMATIC FALLBACK whenever no API key
is present. Tests never reach the network: `openai` is imported lazily inside
`DeepSeekLLM`, so a test run that only touches MockLLM cannot even construct an
HTTP client.

DeepSeek facts, verified against https://api-docs.deepseek.com/ :
  - OpenAI-compatible endpoint at https://api.deepseek.com
  - tool calling is supported (send `tools`, receive `tool_calls`, reply with
    role="tool" messages carrying `tool_call_id`)
  - thinking mode is ON by default and is disabled via
    extra_body={"thinking": {"type": "disabled"}}
  - thinking mode silently ignores `temperature`, so determinism requires
    thinking to stay disabled

SECRETS: the API key is read from the env var named in the config and is never
logged, echoed or included in any error message raised from here.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from policyguard.config import Config, LLMConfig, load_config

logger = logging.getLogger(__name__)

#: Keys issued by "Claude Platform on AWS" start with this prefix. That is a different service from
#: Amazon Bedrock and from the first-party Claude API; keys do not work across them.
_AWS_KEY_PREFIX = "aws-external-anthropic-api-key-"

#: Delimiter the Investigator wraps the action in. MockLLM parses it; the real
#: model is told everything inside it is untrusted DATA, never instructions.
ACTION_OPEN = "<ACTION_UNDER_REVIEW>"
ACTION_CLOSE = "</ACTION_UNDER_REVIEW>"

_ACTION_BLOCK = re.compile(
    re.escape(ACTION_OPEN) + r"\s*(?P<json>\{.*?\})\s*" + re.escape(ACTION_CLOSE),
    re.DOTALL,
)
_EVIDENCE_ID = re.compile(r"\bE\d+\b")


# ── Wire types ─────────────────────────────────────────────────────────────


@dataclass
class ToolCall:
    """One tool the model wants run."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMReply:
    """One assistant turn: either tool calls, or final content, or both."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class LLMClient(Protocol):
    """The only thing the Investigator needs from a model."""

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> LLMReply: ...


# ── MockLLM ────────────────────────────────────────────────────────────────


class MockLLM:
    """Deterministic stand-in for a tool-calling model.

    Two modes:

    * **Scripted** -- pass `script=[LLMReply, ...]` and each `chat()` returns the
      next one. Used by tests, including the hostile-model test, where the
      script tries to talk the Investigator into an ALLOW.
    * **Default policy** -- with no script, it behaves like a competent
      investigator: first turn requests `scan_secrets` and `check_destination`
      for the action under review, then writes a report citing every evidence
      id it was handed. It reads the action out of the delimited block, so it
      never needs to be told about the case under test.
    """

    def __init__(self, script: list[LLMReply] | None = None) -> None:
        self.script = list(script) if script else None
        self.calls = 0
        self.seen_messages: list[list[dict[str, Any]]] = []

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> LLMReply:
        self.calls += 1
        self.seen_messages.append(list(messages))

        if self.script is not None:
            if not self.script:
                # Script exhausted: say nothing useful rather than inventing a
                # verdict. The graph treats that as ungrounded and escalates.
                return LLMReply(content="{}")
            return self.script.pop(0)

        return self._default_policy(messages)

    # -- default policy ---------------------------------------------------

    def _default_policy(self, messages: list[dict[str, Any]]) -> LLMReply:
        evidence_ids = self._evidence_ids_seen(messages)
        if not evidence_ids:
            return self._request_tools(messages)
        return self._write_report(messages, evidence_ids)

    @staticmethod
    def _evidence_ids_seen(messages: list[dict[str, Any]]) -> list[str]:
        """Evidence ids handed back in tool messages, in order, deduplicated."""
        found: list[str] = []
        for m in messages:
            if m.get("role") != "tool":
                continue
            for eid in _EVIDENCE_ID.findall(str(m.get("content", ""))):
                if eid not in found:
                    found.append(eid)
        return found

    @staticmethod
    def _action_under_review(messages: list[dict[str, Any]]) -> dict[str, Any]:
        for m in messages:
            match = _ACTION_BLOCK.search(str(m.get("content", "")))
            if match:
                try:
                    return json.loads(match.group("json"))
                except json.JSONDecodeError:
                    return {}
        return {}

    def _request_tools(self, messages: list[dict[str, Any]]) -> LLMReply:
        """Pick the checks a competent investigator would run for this action.

        Breadth matters: an ALLOW is only as trustworthy as the number of checks
        behind it (see verifier.compute_confidence), so a benign action still
        needs several clean checks before it can clear the allow floor.
        """
        action = self._action_under_review(messages)
        args = action.get("args") or {}
        blob = json.dumps(args, default=str)

        calls = [ToolCall(id="mock-1", name="scan_secrets", arguments={"text": blob})]

        destination = _guess_destination(action)
        if destination:
            calls.append(
                ToolCall(id="mock-2", name="check_destination", arguments={"url": destination})
            )

        path = _guess_path(args)
        if path:
            calls.append(ToolCall(id="mock-3", name="classify_path", arguments={"path": path}))

        session_id = action.get("session_id")
        if session_id:
            calls.append(
                ToolCall(
                    id="mock-4",
                    name="get_session_history",
                    arguments={"session_id": str(session_id)},
                )
            )
        return LLMReply(content="Gathering evidence before ruling.", tool_calls=calls)

    def _write_report(
        self, messages: list[dict[str, Any]], evidence_ids: list[str]
    ) -> LLMReply:
        """Claim one finding per evidence item, citing it. Verdict is advisory:
        the deterministic floor in `verifier` has the final say."""
        observations = " ".join(
            str(m.get("content", "")) for m in messages if m.get("role") == "tool"
        ).lower()
        risky = any(
            marker in observations
            for marker in ('"secrets_found": true', '"canary_hit": true', '"blocked": true')
        )
        claims = [
            {
                "text": f"Evidence {eid} was collected for the action under review.",
                "evidence_ids": [eid],
            }
            for eid in evidence_ids
        ]
        return LLMReply(
            content=json.dumps(
                {
                    "verdict": "block" if risky else "allow",
                    "confidence": 0.9 if risky else 0.8,
                    "claims": claims,
                }
            )
        )


_URL = re.compile(r"https?://[^\s\"\'<>]+")
_BARE_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_PATHISH = re.compile(r"[/\\]|^~|\.[A-Za-z0-9]{1,6}$")

#: Suffixes that mean "this is a filename", not a domain.
_CODE_SUFFIXES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".md", ".txt", ".json", ".yaml", ".yml",
    ".env", ".pem", ".key", ".go", ".rs", ".java", ".rb", ".sh", ".toml", ".cfg",
    ".ini", ".lock", ".sql", ".csv", ".log", ".html", ".css", ".xml",
)


def _guess_destination(action: dict[str, Any]) -> str | None:
    """Find a real network destination in the args, or None.

    Deliberately does NOT fall back to the MCP server name: an MCP server is
    not a hostname, and `check_destination` treats any unrecognised host as
    untrusted. Guessing here would flag every call to a trusted local server.
    """
    for value in (action.get("args") or {}).values():
        text = str(value)
        match = _URL.search(text)
        if match:
            return match.group(0)
    for value in (action.get("args") or {}).values():
        text = str(value)
        # A path is not a hostname. "src/auth/login.py" matches a naive
        # host pattern ("login" + ".py"), and check_destination treats every
        # unrecognised host as untrusted, which would flag benign file reads.
        if "/" in text or "\\" in text or text.startswith("~"):
            continue
        match = _BARE_HOST.search(text)
        if match and not match.group(0).lower().endswith(_CODE_SUFFIXES):
            return match.group(0)
    return None


def _guess_path(args: dict[str, Any]) -> str | None:
    """Find a filesystem-path-looking argument worth classifying."""
    for key, value in args.items():
        if not isinstance(value, str) or _URL.search(value):
            continue
        if key.lower() in {"path", "file", "filename", "filepath"} or _PATHISH.search(value):
            if len(value) <= 300:
                return value
    return None


# ── DeepSeek ───────────────────────────────────────────────────────────────


class DeepSeekLLM:
    """DeepSeek through its OpenAI-compatible API.

    `openai` is imported lazily so neither this module nor the test suite needs
    the SDK installed unless a real call is actually made.
    """

    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        key = cfg.api_key
        if not key:
            raise ValueError(
                f"no API key: environment variable {cfg.api_key_env} is unset or empty"
            )
        try:
            from openai import AsyncOpenAI
        except ModuleNotFoundError as exc:  # pragma: no cover - needs the real dep
            raise ModuleNotFoundError(
                "the 'openai' package is required for the DeepSeek provider; "
                "install it or set mock_mode: true in config/policyguard.yaml"
            ) from exc
        self._client = AsyncOpenAI(
            api_key=key,
            base_url=cfg.base_url,
            timeout=cfg.request_timeout,
        )

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> LLMReply:
        request: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            # Thinking must be disabled for `temperature` to take effect at all.
            "extra_body": {"thinking": {"type": self.cfg.thinking}},
        }
        if tools:
            request["tools"] = tools
            request["tool_choice"] = "auto"
        response = await self._client.chat.completions.create(**request)
        message = response.choices[0].message
        return LLMReply(
            content=message.content or "",
            tool_calls=[
                ToolCall(id=tc.id, name=tc.function.name, arguments=_safe_json(tc.function.arguments))
                for tc in (message.tool_calls or [])
            ],
        )


def _safe_json(raw: str | None) -> dict[str, Any]:
    """Parse model-supplied tool arguments without ever raising."""
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


# ── Claude ─────────────────────────────────────────────────────────────────


class ClaudeLLM:
    """Anthropic's Claude through its native Messages API.

    NOT OpenAI-compatible: this is a different wire format from DeepSeekLLM,
    verified against https://platform.claude.com/docs/ :
      - POST https://api.anthropic.com/v1/messages, auth header `x-api-key`,
        required header `anthropic-version`.
      - System prompt is a top-level `system` field, not a "system" message.
      - Tools are declared with `input_schema` (not `parameters`).
      - A tool-calling turn ends with `stop_reason: "tool_use"` and one or
        more `tool_use` content blocks (each with its own `id`); the next
        request replies with a `user` message containing `tool_result` blocks
        keyed by `tool_use_id`.
      - There is no separate "tool" role: tool_use and tool_result both ride
        inside ordinary `assistant` / `user` messages as content blocks.

    `anthropic` is imported lazily, matching DeepSeekLLM, so the test suite
    never needs the SDK installed unless a real call is made.
    """

    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        key = cfg.api_key
        if not key:
            raise ValueError(
                f"no API key: environment variable {cfg.api_key_env} is unset or empty"
            )
        try:
            from anthropic import AsyncAnthropic
        except ModuleNotFoundError as exc:  # pragma: no cover - needs the real dep
            raise ModuleNotFoundError(
                "the 'anthropic' package is required for the Claude provider; "
                "install it or set mock_mode: true in config/policyguard.yaml"
            ) from exc
        if key.startswith(_AWS_KEY_PREFIX):
            # Claude Platform on AWS: the Anthropic Messages API behind an AWS endpoint. It needs a
            # region (picks the endpoint) and a workspace id (wrkspc_...).
            region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
            workspace = os.environ.get("ANTHROPIC_AWS_WORKSPACE_ID")
            if not region or not workspace:
                raise ValueError(
                    "this is a Claude Platform on AWS key: set AWS_REGION and "
                    "ANTHROPIC_AWS_WORKSPACE_ID (wrkspc_...) in .env"
                )
            from anthropic import AsyncAnthropicAWS

            self._client = AsyncAnthropicAWS(
                api_key=key,
                aws_region=region,
                workspace_id=workspace,
                timeout=cfg.request_timeout,
            )
            return
        self._client = AsyncAnthropic(
            api_key=key,
            base_url=cfg.base_url,
            timeout=cfg.request_timeout,
        )

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> LLMReply:
        system, claude_messages = self._to_claude_messages(messages)
        request: dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            # anthropic 1.13 messages.create() takes no temperature; sending it raised TypeError on every call.
            "messages": claude_messages,
        }
        if system:
            request["system"] = system
        if tools:
            request["tools"] = [_to_claude_tool(t) for t in tools]
        response = await self._client.messages.create(**request)

        content_text = []
        tool_calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                content_text.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=block.input if isinstance(block.input, dict) else {},
                    )
                )
        return LLMReply(content="".join(content_text), tool_calls=tool_calls)

    @staticmethod
    def _to_claude_messages(
        messages: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]]]:
        """Translate the OpenAI-shaped transcript this codebase builds into
        Claude's shape: pull the system message out, fold assistant tool_calls
        and tool-role replies into content blocks on ordinary turns."""
        system = ""
        claude_messages: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role")
            if role == "system":
                system = (system + "\n" + str(m.get("content", ""))).strip()
            elif role == "tool":
                claude_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.get("tool_call_id"),
                                "content": str(m.get("content", "")),
                            }
                        ],
                    }
                )
            elif role == "assistant" and m.get("tool_calls"):
                blocks: list[dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": str(m["content"])})
                for tc in m["tool_calls"]:
                    fn = tc.get("function", {})
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.get("id"),
                            "name": fn.get("name"),
                            "input": _safe_json(fn.get("arguments")),
                        }
                    )
                claude_messages.append({"role": "assistant", "content": blocks})
            else:
                claude_messages.append({"role": role, "content": str(m.get("content", ""))})
        return system, claude_messages


def _to_claude_tool(openai_tool: dict[str, Any]) -> dict[str, Any]:
    """OpenAI-style `{"type":"function","function":{...}}` -> Claude's flatter shape."""
    fn = openai_tool.get("function", openai_tool)
    return {
        "name": fn.get("name"),
        "description": fn.get("description", ""),
        "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
    }



class BedrockClaudeLLM(ClaudeLLM):
    """Claude through Amazon Bedrock (SigV4 via boto3). Used in the hackathon account.

    Reuses ClaudeLLM's OpenAI->Claude message translation; only the client and the
    request differ. Credentials come from the standard AWS chain (env vars, shared
    config, or a named profile). Region defaults to us-east-1, the hackathon region.
    """

    def __init__(self, cfg: LLMConfig) -> None:
        # Skip ClaudeLLM.__init__ (it wants an Anthropic api key); set up a Bedrock client instead.
        self.cfg = cfg
        try:
            from anthropic import AsyncAnthropicBedrock
        except ModuleNotFoundError as exc:  # pragma: no cover - needs the real dep
            raise ModuleNotFoundError(
                "the 'anthropic' package is required for the Bedrock provider"
            ) from exc
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._client = AsyncAnthropicBedrock(aws_region=region, timeout=cfg.request_timeout)


# ── Factory ────────────────────────────────────────────────────────────────


def build_llm(config: Config | None = None) -> LLMClient:
    """Return the configured provider, falling back to MockLLM.

    Falls back when mock mode is on, when the provider is unknown, when the API
    key is absent, or when the SDK is missing. Logs exactly one line saying
    which fallback fired and why. Never logs key material.
    """
    cfg = config or load_config()

    if cfg.mock_mode:
        logger.warning("PolicyGuard Investigator: using MockLLM (mock_mode enabled in config)")
        return MockLLM()

    if cfg.llm.provider == "bedrock":
        try:
            return BedrockClaudeLLM(cfg.llm)
        except Exception as exc:  # noqa: BLE001 - never let provider setup break the guard
            logger.warning("PolicyGuard Investigator: using MockLLM (%s)", exc)
            return MockLLM()

    if cfg.llm.api_key is None:
        logger.warning(
            "PolicyGuard Investigator: using MockLLM (no API key in $%s)", cfg.llm.api_key_env
        )
        return MockLLM()

    provider_classes: dict[str, type] = {
        "deepseek": DeepSeekLLM,
        "anthropic": ClaudeLLM,
        "bedrock": BedrockClaudeLLM,
    }
    provider_cls = provider_classes.get(cfg.llm.provider)
    if provider_cls is None:
        logger.warning(
            "PolicyGuard Investigator: using MockLLM (unknown provider %r)", cfg.llm.provider
        )
        return MockLLM()

    try:
        return provider_cls(cfg.llm)
    except Exception as exc:  # noqa: BLE001 - never let provider setup break the guard
        logger.warning("PolicyGuard Investigator: using MockLLM (%s)", exc)
        return MockLLM()


if __name__ == "__main__":  # pragma: no cover - manual check: python -m policyguard.investigator.llm [model ...]
    import asyncio
    import dataclasses
    import sys

    async def _check(models: list[str]) -> int:
        cfg = load_config()
        print(
            f"provider={cfg.llm.provider} key env {cfg.llm.api_key_env} "
            f"set={cfg.llm.api_key is not None} mock_mode={cfg.mock_mode}"
        )
        for model in models or [cfg.llm.model]:
            trial = dataclasses.replace(cfg, llm=dataclasses.replace(cfg.llm, model=model))
            client = build_llm(trial)
            if isinstance(client, MockLLM):
                print(f"{model}: fell back to MockLLM (see the warning above); no real model was called")
                return 2
            try:
                reply = await client.chat([{"role": "user", "content": "Reply with the single word OK."}])
            except Exception as exc:  # noqa: BLE001
                print(f"{model}: FAILED {exc!r}")
                continue
            print(f"{model}: OK -> {reply.content.strip()[:40]!r}")
            return 0
        return 1

    raise SystemExit(asyncio.run(_check(sys.argv[1:])))
