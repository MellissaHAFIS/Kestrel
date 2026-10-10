"""Policy loader: YAML -> typed Policy dataclass.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY_PATH = "policy/devassist.yaml"


@dataclass
class AllowedTool:
    tool: str
    server: str
    params: list[str] = field(default_factory=list)


@dataclass
class ApprovalRule:
    tool: str
    when: str


@dataclass
class Thresholds:
    """Placeholders. TUNE ON VALIDATION ONLY, then freeze."""

    gate_low: float = 0.20
    gate_high: float = 0.80
    investigator_min_confidence: float = 0.70
    max_steps: int = 6


@dataclass
class Policy:
    agent: str
    description: str = ""
    allowed_tools: list[AllowedTool] = field(default_factory=list)
    untrusted_servers: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    trusted_hosts: list[str] = field(default_factory=list)
    require_approval: list[ApprovalRule] = field(default_factory=list)
    canaries: list[str] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)

    def is_untrusted(self, server: str) -> bool:
        return server in self.untrusted_servers


def policy_from_dict(raw: dict[str, Any]) -> Policy:
    return Policy(
        agent=raw["agent"],
        description=str(raw.get("description", "")).strip(),
        allowed_tools=[AllowedTool(**t) for t in raw.get("allowed_tools", [])],
        untrusted_servers=list(raw.get("untrusted_servers", [])),
        sensitive_paths=list(raw.get("sensitive_paths", [])),
        trusted_hosts=list(raw.get("trusted_hosts", [])),
        require_approval=[ApprovalRule(**r) for r in raw.get("require_approval", [])],
        canaries=list(raw.get("canaries", [])),
        thresholds=Thresholds(**raw.get("thresholds", {})),
    )


def load_policy(path: str | Path | None = None) -> Policy:
    """Load the policy from `path`, $POLICYGUARD_POLICY, or the default location."""
    p = Path(path or os.environ.get("POLICYGUARD_POLICY") or DEFAULT_POLICY_PATH)
    with p.open("r", encoding="utf-8") as fh:
        return policy_from_dict(yaml.safe_load(fh))


# =====================================================================
# PolicyStore: read-only accessor used by the Investigator tools.
# Additive shim (Person 3). Does not change load_policy/Policy above.
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
