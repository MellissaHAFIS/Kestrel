"""Tool registry scan: description/schema rules + SHA-256 pinning + quarantine store.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RegistryResult:
    """Outcome of scanning one tool at connection time."""

    tool: str
    pinned_hash: str
    suspicious: bool = False
    findings: list[str] = field(default_factory=list)
    score: float | None = None  # optional ML score, later


def pin_hash(name: str, description: str, schema: dict[str, Any]) -> str:
    """SHA-256 over description + schema (and name). Deterministic: keys sorted, compact JSON."""
    payload = json.dumps(
        {"name": name, "description": description, "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def scan_tool(name: str, description: str, schema: dict[str, Any]) -> RegistryResult:
    """Scan a tool description/schema for poisoning. STUB: flags nothing."""
    # TODO(person2): rules: imperative instructions to the model, "do not tell the user",
    #   references to files/paths/config, extra free-form params like `context`,
    #   hidden unicode, very long descriptions.
    return RegistryResult(tool=name, pinned_hash=pin_hash(name, description, schema))


# --- Quarantine store (in memory for now) ---------------------------------
_QUARANTINED: dict[str, str] = {}  # "server/tool" -> reason
_PINS: dict[str, str] = {}  # "server/tool" -> pinned hash


def quarantine(server: str, tool: str, reason: str) -> None:
    # TODO(person2): persist (SQLite or JSON) and log to audit.py
    _QUARANTINED[f"{server}/{tool}"] = reason


def is_quarantined(server: str, tool: str) -> bool:
    return f"{server}/{tool}" in _QUARANTINED


def check_pin(server: str, tool: str, current_hash: str) -> bool:
    """True if the hash matches the pin (or none is pinned yet, in which case it pins)."""
    # TODO(person2): rug-pull detection: description changed after approval -> quarantine
    return _PINS.setdefault(f"{server}/{tool}", current_hash) == current_hash
