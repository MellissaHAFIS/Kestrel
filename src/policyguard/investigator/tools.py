"""Read-only investigation tools for the Investigator agent.


SECURITY CONTRACT
-----------------
Every tool treats its input as DATA, never as instructions. Tool inputs routinely
carry attacker-controlled text (poisoned MCP tool descriptions, tool results), so:

- No tool interprets, executes or follows text found in its input.
- No tool uses a shell. The one subprocess call passes text on stdin to an
  argv-list command, so input can never be interpreted as a command.
- Every tool is read-only: nothing here mutates policy, registry or audit state.
- Every tool returns a string (JSON or YAML) and never raises; failures are
  reported as structured data so the agent loop cannot be derailed by an error.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import subprocess
import sys
import urllib.parse
from typing import Any

import yaml
from langchain_core.tools import tool

from policyguard.audit import audit_log
from policyguard.policy import policy_store

#: Max audit entries returned by get_session_history.
HISTORY_LIMIT = 20

#: Timeout (seconds) for the detect-secrets subprocess.
_SCAN_TIMEOUT = 20

#: detect-secrets prints "PluginName : True (details)" lines, not JSON.
_PLUGIN_LINE = re.compile(r"^\s*(?P<plugin>[A-Za-z0-9_]+)\s*:\s*(?P<verdict>True|False)\s*(?P<detail>.*)$")


def _json(payload: dict[str, Any]) -> str:
    """Serialize a tool result, never raising on odd values."""
    return json.dumps(payload, indent=2, default=str)


# ── 1. Session history ─────────────────────────────────────────────────────


@tool
async def get_session_history(session_id: str) -> str:
    """Return the last 20 audit entries for session_id as a YAML-formatted string."""
    try:
        entries = await audit_log.get_session(session_id)
    except Exception as exc:  # noqa: BLE001 - read-only tool must not raise
        return f"error: could not read session history: {exc!r}"
    recent = entries[-HISTORY_LIMIT:]
    if not recent:
        return f"# no audit entries for session {session_id}"
    return "\n".join(
        f"- [{e.timestamp}] {e.layer} | {e.action} | {e.decision}" for e in recent
    )


# ── 2. Provenance ──────────────────────────────────────────────────────────


@tool
async def get_provenance(action_id: str, session_id: str) -> str:
    """Return the source labels and action text for the given action_id."""
    try:
        entries = await audit_log.get_session(session_id)
    except Exception as exc:  # noqa: BLE001
        return _json({"error": f"could not read session history: {exc!r}", "action_id": action_id})
    for e in entries:
        if e.id == action_id:
            return _json(
                {
                    "action_id": e.id,
                    "action": e.action,
                    "source_labels": list(e.source_labels),
                    "layer": e.layer,
                    "timestamp": e.timestamp,
                }
            )
    return _json(
        {
            "error": "action_id not found in session",
            "action_id": action_id,
            "session_id": session_id,
        }
    )


# ── 3. Policy ──────────────────────────────────────────────────────────────


@tool
async def read_policy(section: str) -> str:
    """Return the policy sub-section as a YAML string (dot-notation key, e.g. 'tools.trusted')."""
    try:
        result = policy_store.get_section(section)
    except KeyError:
        return f"error: policy section '{section}' not found"
    except Exception as exc:  # noqa: BLE001
        return f"error: could not read policy section '{section}': {exc!r}"
    return yaml.dump(result, default_flow_style=False, sort_keys=False)


# ── 4. Secret scanning ─────────────────────────────────────────────────────


def _parse_detect_secrets(stdout: str) -> dict[str, Any]:
    """Parse the plugin verdict table into {plugin: bool} plus details."""
    plugins: dict[str, bool] = {}
    details: dict[str, str] = {}
    for line in stdout.splitlines():
        m = _PLUGIN_LINE.match(line)
        if not m:
            continue
        name = m.group("plugin")
        plugins[name] = m.group("verdict") == "True"
        detail = m.group("detail").strip()
        if detail:
            details[name] = detail
    return {
        "plugins": plugins,
        "details": details,
        "triggered": sorted(p for p, hit in plugins.items() if hit),
    }


def _run_detect_secrets(text: str) -> dict[str, Any]:
    """Run detect-secrets over `text` via stdin. No shell: input is never interpreted."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", "--string"],
            input=text,
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": "detect-secrets timed out", "plugins": {}, "triggered": []}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"detect-secrets failed: {exc!r}", "plugins": {}, "triggered": []}
    parsed = _parse_detect_secrets(proc.stdout)
    if not parsed["plugins"]:
        parsed["error"] = (
            f"detect-secrets produced no verdicts (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()[:300]}"
        )
    return parsed


@tool
async def scan_secrets(text: str) -> str:
    """Scan text for secrets and canary tokens. Return JSON."""
    # 1. Canary tokens (exact, case-sensitive).
    canary_hit = False
    canary_token: str | None = None
    try:
        for token in policy_store.canary_tokens():
            if token and token in text:
                canary_hit = True
                canary_token = token
                break
    except Exception:  # noqa: BLE001 - never let policy IO break the scan
        pass

    # 2. detect-secrets, off-thread so the agent loop is not blocked.
    output = await asyncio.to_thread(_run_detect_secrets, text)
    secrets_found = bool(output.get("triggered"))

    return _json(
        {
            "secrets_found": secrets_found or canary_hit,
            "canary_hit": canary_hit,
            "canary_token": canary_token,
            "detect_secrets_output": output,
        }
    )


# ── 5. Destination ─────────────────────────────────────────────────────────


def _host_matches(host: str, pattern: str) -> bool:
    """Exact match, or `host` is a subdomain of `pattern`."""
    host, pattern = host.lower().strip("."), pattern.lower().strip(".")
    return bool(pattern) and (host == pattern or host.endswith("." + pattern))


@tool
async def check_destination(url: str) -> str:
    """Check if a URL's domain is trusted or blocked per policy. Return JSON."""
    try:
        parsed = urllib.parse.urlparse(url if "//" in url else f"//{url}")
        domain = (parsed.hostname or parsed.netloc or url).lower()
    except Exception:  # noqa: BLE001
        domain = url.lower()

    try:
        trusted_list = policy_store.get_trusted_destinations()
        blocked_list = policy_store.get_blocked_destinations()
    except Exception as exc:  # noqa: BLE001
        return _json(
            {
                "domain": domain,
                "trusted": False,
                "blocked": False,
                "reason": f"policy unavailable, treating as untrusted: {exc!r}",
            }
        )

    trusted_match = next((p for p in trusted_list if _host_matches(domain, p)), None)
    blocked_match = next((p for p in blocked_list if _host_matches(domain, p)), None)

    if blocked_match:
        reason = f"'{domain}' matches blocked/untrusted destination '{blocked_match}'"
    elif trusted_match:
        reason = f"'{domain}' matches trusted destination '{trusted_match}'"
    else:
        reason = f"'{domain}' is not in the trusted list; treat as untrusted by default"

    return _json(
        {
            "domain": domain,
            "trusted": trusted_match is not None and blocked_match is None,
            "blocked": blocked_match is not None,
            "reason": reason,
        }
    )


# ── 6. Path classification ─────────────────────────────────────────────────


@tool
async def classify_path(path: str) -> str:
    """Check whether a file path is sensitive or read-only per policy. Return JSON."""
    try:
        patterns = policy_store.get_sensitive_paths()
    except Exception as exc:  # noqa: BLE001
        return _json(
            {
                "path": path,
                "sensitive": False,
                "matched_pattern": None,
                "error": f"policy unavailable: {exc!r}",
            }
        )
    normalized = path.lstrip("./")
    for pattern in patterns:
        if (
            fnmatch.fnmatch(path, pattern)
            or fnmatch.fnmatch(normalized, pattern)
            or fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern)
        ):
            return _json({"path": path, "sensitive": True, "matched_pattern": pattern})
    return _json({"path": path, "sensitive": False, "matched_pattern": None})


# ── 7. Registry ────────────────────────────────────────────────────────────


@tool
async def inspect_tool(tool_name: str) -> str:
    """Return the registry scan result and pinned hash for a tool. Return JSON."""
    try:
        from policyguard.registry import TOOL_REGISTRY
    except Exception as exc:  # noqa: BLE001
        return _json({"error": f"registry unavailable: {exc!r}", "tool_name": tool_name})
    entry = TOOL_REGISTRY.get(tool_name)
    if entry is None:
        return _json({"error": "tool not in registry", "tool_name": tool_name})
    return _json({"tool_name": tool_name, **entry})


# ── 8. Canary ──────────────────────────────────────────────────────────────


@tool
async def check_canary(text: str) -> str:
    """Check if any canary token appears in text. Return JSON."""
    try:
        tokens = policy_store.canary_tokens()
    except Exception as exc:  # noqa: BLE001
        return _json({"hit": False, "token": None, "error": f"policy unavailable: {exc!r}"})
    for token in tokens:
        if token and token in text:
            return _json({"hit": True, "token": token})
    return _json({"hit": False, "token": None})


# Exported list — import this in graph.py
INVESTIGATION_TOOLS = [
    get_session_history,
    get_provenance,
    read_policy,
    scan_secrets,
    check_destination,
    classify_path,
    inspect_tool,
    check_canary,
]
