"""Loader for `config/policyguard.yaml` (non-secret runtime settings).

Split of responsibilities:
  - `policy/devassist.yaml`  -- the agent mandate and every security threshold.
  - `config/policyguard.yaml` -- operational knobs (model, timeouts, budgets).

Every setting has a default here, so the whole system still runs if the YAML is
missing or partial. Importing this module never performs I/O, never needs an
API key and never touches the network.

SECRETS: this module resolves the *name* of the env var holding the API key
(`llm.api_key_env`) and reads that var on request. It never logs the value and
never writes it anywhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

#: Used when neither an explicit path nor $POLICYGUARD_CONFIG is set.
DEFAULT_CONFIG_PATH = "config/policyguard.yaml"

_dotenv_loaded = False


def _ensure_dotenv_loaded() -> None:
    """Load `.env` once, if python-dotenv is available.

    Existing environment variables win, so an exported value always beats the
    file. Secrets are read into the process environment only; nothing here
    logs, copies or persists a value.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return
    _dotenv_loaded = True
    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return
    load_dotenv(override=False)


#: Per-provider defaults. Looked up when the YAML/env name a provider but do
#: not override its base_url / model / api_key_env explicitly.
#:
#: DeepSeek facts verified against https://api-docs.deepseek.com/ : OpenAI-
#: compatible endpoint, `deepseek-chat` RETIRED 2026-07-24 (use deepseek-flash).
#:
#: Anthropic facts verified against https://platform.claude.com/docs/ :
#: native Messages API at /v1/messages (NOT OpenAI-compatible -- different
#: request/response shape, see ClaudeLLM in investigator/llm.py), auth header
#: x-api-key, model id "claude-sonnet-5" is a pinned 4.6-generation snapshot
#: (dateless IDs from that generation on are fixed, not moving aliases).
PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-flash",
        "api_key_env": "DEEPSEEK_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-5",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
}

#: Accepted spellings that mean "anthropic". Used because .env commonly says
#: LLM_PROVIDER=claude, which is not Anthropic's own provider name.
_PROVIDER_ALIASES: dict[str, str] = {"claude": "anthropic"}


def normalize_provider(name: str) -> str:
    name = (name or "").strip().lower()
    return _PROVIDER_ALIASES.get(name, name)


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "deepseek"
    base_url: str = "https://api.deepseek.com"
    api_key_env: str = "DEEPSEEK_API_KEY"
    model: str = "deepseek-flash"
    thinking: str = "disabled"
    temperature: float = 0.0
    max_tokens: int = 1024
    request_timeout: float = 30.0
    strict_tools: bool = False

    @property
    def api_key(self) -> str | None:
        """The key from the environment (or `.env`), or None. Never logged."""
        _ensure_dotenv_loaded()
        value = os.environ.get(self.api_key_env, "").strip()
        return value or None


@dataclass(frozen=True)
class HITLConfig:
    wait_timeout: float = 300.0
    poll_interval: float = 0.5


@dataclass(frozen=True)
class Config:
    llm: LLMConfig
    step_budget: int = 6
    hitl: HITLConfig = HITLConfig()
    mock_mode: bool = False


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name)
    return value if isinstance(value, dict) else {}


def config_from_dict(raw: dict[str, Any] | None) -> Config:
    """Build a Config from a parsed YAML mapping, ignoring unknown keys."""
    _ensure_dotenv_loaded()
    raw = raw or {}
    llm_raw = _section(raw, "llm")
    inv_raw = _section(raw, "investigator")
    hitl_raw = _section(raw, "human_in_the_loop")

    defaults = LLMConfig()
    # LLM_PROVIDER in the environment / .env can switch providers without
    # touching the committed YAML. The YAML's `llm.provider` is the fallback.
    provider = normalize_provider(
        os.environ.get("LLM_PROVIDER") or llm_raw.get("provider", defaults.provider)
    )
    provider_defaults = PROVIDER_DEFAULTS.get(provider, {})
    llm = LLMConfig(
        provider=provider,
        base_url=str(llm_raw.get("base_url") or provider_defaults.get("base_url", defaults.base_url)),
        api_key_env=str(
            llm_raw.get("api_key_env") or provider_defaults.get("api_key_env", defaults.api_key_env)
        ),
        model=str(llm_raw.get("model") or provider_defaults.get("model", defaults.model)),
        thinking=str(llm_raw.get("thinking", defaults.thinking)),
        temperature=float(llm_raw.get("temperature", defaults.temperature)),
        max_tokens=int(llm_raw.get("max_tokens", defaults.max_tokens)),
        request_timeout=float(llm_raw.get("request_timeout", defaults.request_timeout)),
        strict_tools=bool(llm_raw.get("strict_tools", defaults.strict_tools)),
    )
    hitl_defaults = HITLConfig()
    hitl = HITLConfig(
        wait_timeout=float(hitl_raw.get("wait_timeout", hitl_defaults.wait_timeout)),
        poll_interval=float(hitl_raw.get("poll_interval", hitl_defaults.poll_interval)),
    )
    return Config(
        llm=llm,
        step_budget=int(inv_raw.get("step_budget", 6)),
        hitl=hitl,
        mock_mode=bool(raw.get("mock_mode", False)) or _mock_from_env(),
    )


def _mock_from_env() -> bool:
    """Honour MOCK_LLM=1 from the environment / .env.

    Either source can turn mock mode ON; neither can turn it off once the
    other has enabled it. Forcing the offline path is always the safe
    direction, so it is never overridden.
    """
    _ensure_dotenv_loaded()
    return os.environ.get("MOCK_LLM", "").strip().lower() in {"1", "true", "yes"}


def load_config(path: str | Path | None = None) -> Config:
    """Read the YAML and return a Config. Falls back to defaults if unreadable."""
    target = Path(path or os.environ.get("POLICYGUARD_CONFIG") or DEFAULT_CONFIG_PATH)
    try:
        with target.open("r", encoding="utf-8") as fh:
            return config_from_dict(yaml.safe_load(fh))
    except (OSError, yaml.YAMLError):
        return config_from_dict({})


class ConfigStore:
    """Lazy, cached accessor so callers share one parsed config."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = path
        self._config: Config | None = None

    @property
    def config(self) -> Config:
        if self._config is None:
            self._config = load_config(self._path)
        return self._config

    def load(self, path: str | Path | None = None) -> Config:
        """Point the store at `path` and re-read it now."""
        self._path = path
        self._config = None
        return self.config

    def reload(self) -> None:
        self._config = None


#: Module-level singleton.
config_store = ConfigStore()
