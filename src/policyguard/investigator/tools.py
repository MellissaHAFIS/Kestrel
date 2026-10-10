"""Investigator tools. Each returns an Evidence the report may cite by id.

Owner: Person 3 (investigator).
First deliverable: loop resolves the paraphrased-leak case with a grounded report.

MVP wires the first four; inspect_tool and check_canary are stubs.
"""

from __future__ import annotations

import time
from itertools import count

from policyguard.types import Action, Evidence, Source

_ids = count(1)


def _evidence(tool: str, observation: str, source: Source | None = None) -> Evidence:
    """Create an Evidence with a fresh id (E1, E2, ...)."""
    return Evidence(id=f"E{next(_ids)}", tool=tool, observation=observation, source=source, ts=time.time())


def get_session_history(session_id: str, last_n: int = 20) -> Evidence:
    """Return the last `last_n` tagged items / tool calls of the session."""
    # TODO(person3): read provenance.history(session_id) and/or audit.list_decisions
    return _evidence("get_session_history", "not implemented")


def get_provenance(action: Action) -> Evidence:
    """Report which sources (trusted/untrusted) preceded the action and which content carried which tag."""
    # TODO(person3)
    return _evidence("get_provenance", "not implemented")


def scan_secrets(text: str) -> Evidence:
    """Scan `text` for secrets (detect-secrets, canary match, high-entropy strings), including partial/paraphrased leaks."""
    # TODO(person3)
    return _evidence("scan_secrets", "not implemented")


def check_destination(server: str, host: str | None = None) -> Evidence:
    """Say whether the destination server/host is trusted per policy.trusted_hosts / untrusted_servers."""
    # TODO(person3)
    return _evidence("check_destination", "not implemented")


def inspect_tool(server: str, tool: str) -> Evidence:
    """Return the tool's description, schema and pinned hash from the registry."""
    # TODO(person3): stub in MVP
    return _evidence("inspect_tool", "not implemented")


def check_canary(text: str) -> Evidence:
    """Check whether `text` contains (or paraphrases) a planted canary token."""
    # TODO(person3): stub in MVP
    return _evidence("check_canary", "not implemented")


TOOLS = {
    "get_session_history": get_session_history,
    "get_provenance": get_provenance,
    "scan_secrets": scan_secrets,
    "check_destination": check_destination,
    "inspect_tool": inspect_tool,
    "check_canary": check_canary,
}
