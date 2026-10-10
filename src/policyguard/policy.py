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
