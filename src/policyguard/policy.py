"""Policy loader: YAML -> typed Policy dataclass.

The policy is the single source of truth for the hard-invariants layer:
which servers are trusted, which tools are allowed, which paths are sensitive,
and what honeytokens / secret patterns to screen for. Unknown YAML keys are
ignored so the schema can grow without breaking older loaders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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
