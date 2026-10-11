"""Policy loader: YAML -> typed Policy dataclass.

The policy is the single source of truth for the hard-invariants layer:
which servers are trusted, which tools are allowed, which paths are sensitive,
and what honeytokens / secret patterns to screen for. Unknown YAML keys are
ignored so the schema can grow without breaking older loaders.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Used when neither an explicit path nor $POLICYGUARD_POLICY is set.
DEFAULT_POLICY_PATH = "policy/devassist.yaml"


@dataclass
class Policy:
    """Typed view of ``policy/devassist.yaml``.

    `servers` maps a server name to its config dict (currently ``{trusted: bool}``).
    Any server not listed is untrusted. `allowed_tools` holds fully-qualified
    ``"server.tool"`` strings; an empty list means "allow all". `tool_schemas`
    maps ``"server.tool"`` to ``{"allowed_params": [...]}``.
    """

    agent: str
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    allowed_tools: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    canaries: list[str] = field(default_factory=list)
    secret_patterns: list[str] = field(default_factory=list)
    tool_schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    suspicious_param_names: list[str] = field(default_factory=list)

    def is_trusted(self, server: str) -> bool:
        """True only if the server is explicitly declared trusted. Unknown servers are untrusted."""
        cfg = self.servers.get(server)
        return bool(cfg) and bool(cfg.get("trusted", False))


def policy_from_dict(raw: dict[str, Any]) -> Policy:
    """Build a Policy from a parsed YAML mapping, ignoring unknown keys."""
    raw = raw or {}
    return Policy(
        agent=raw.get("agent", "unknown"),
        servers=dict(raw.get("servers", {}) or {}),
        allowed_tools=list(raw.get("allowed_tools", []) or []),
        sensitive_paths=list(raw.get("sensitive_paths", []) or []),
        canaries=list(raw.get("canaries", []) or []),
        secret_patterns=list(raw.get("secret_patterns", []) or []),
        tool_schemas=dict(raw.get("tool_schemas", {}) or {}),
        suspicious_param_names=list(raw.get("suspicious_param_names", []) or []),
    )


def load_policy(path: str | Path) -> Policy:
    """Load and parse a policy YAML file with ``yaml.safe_load``."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        return policy_from_dict(yaml.safe_load(fh))


# =====================================================================
# PolicyStore: read-only accessor used by the Investigator tools.
# =====================================================================


class PolicyStore:
    """Lazy, cached, read-only view over the policy YAML.

    Exposes the accessors the Investigator tools need. Loading is lazy so
    importing this module never fails when the YAML is missing.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = path
        self._raw: dict[str, Any] | None = None

    # --- loading ---------------------------------------------------------
    @property
    def raw(self) -> dict[str, Any]:
        """The parsed YAML as a plain dict (cached). Empty dict if unreadable."""
        if self._raw is None:
            p = Path(self._path or os.environ.get("POLICYGUARD_POLICY") or DEFAULT_POLICY_PATH)
            try:
                with p.open("r", encoding="utf-8") as fh:
                    self._raw = yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError):
                self._raw = {}
        return self._raw

    def load(self, path: str | Path | None = None) -> None:
        """Point the store at `path` and read it now (replacing any cached policy)."""
        self._path = path
        self._raw = None
        _ = self.raw  # force the read so errors surface at startup, not mid-investigation

    def reload(self) -> None:
        """Drop the cache so the next access re-reads the file."""
        self._raw = None

    def summary(self) -> str:
        """One-line human-readable description of the loaded policy (for the console header)."""
        raw = self.raw
        if not raw:
            return "no policy loaded"
        return (
            f"`{raw.get('agent', 'unknown')}` — "
            f"{len(raw.get('allowed_tools', []))} allowed tools, "
            f"{len(raw.get('untrusted_servers', []))} untrusted servers, "
            f"{len(raw.get('trusted_hosts', []))} trusted hosts, "
            f"{len(raw.get('sensitive_paths', []))} sensitive paths, "
            f"{len(raw.get('canaries', []))} canaries"
        )

    @property
    def policy(self) -> Policy:
        """The typed Policy dataclass."""
        return policy_from_dict(self.raw)

    # --- accessors -------------------------------------------------------
    def get_section(self, section: str) -> Any:
        """Return a sub-section by dot-notation key (e.g. 'thresholds.max_steps').

        Raises KeyError if any part of the path is missing.
        """
        node: Any = self.raw
        for part in section.split("."):
            if not isinstance(node, dict) or part not in node:
                raise KeyError(section)
            node = node[part]
        return node

    def get_sensitive_paths(self) -> list[str]:
        """Glob patterns for files the agent must not read without approval."""
        return list(self.raw.get("sensitive_paths", []))

    def get_trusted_destinations(self) -> list[str]:
        """Hosts the agent may send data to."""
        return list(self.raw.get("trusted_hosts", []))

    def get_blocked_destinations(self) -> list[str]:
        """Untrusted/third-party servers. Anything sent here is screened."""
        return list(self.raw.get("untrusted_servers", []))

    def canary_tokens(self) -> list[str]:
        """Canary tokens planted in the fixture repo."""
        return list(self.raw.get("canaries", []))


#: Module-level singleton used by the Investigator tools.
policy_store = PolicyStore()
