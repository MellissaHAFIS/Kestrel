"""Analyst console (Chainlit): escalation queue, incident cards, Approve/Block, kill switch.

Owner: Person 4 (audit/console/eval).
This is the human-in-the-loop interface. The analyst reviews escalations and acts on them.

Run: chainlit run console/app.py

Commands: queue | log | approve <id> | block <id> | kill
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

# Make `policyguard` importable even when the editable install is not in effect.
# Why this is needed: `pip install -e .` drops a .pth file into site-packages that
# adds <repo>/src to sys.path. On macOS that file can end up with the UF_HIDDEN
# file flag set, and CPython's site.addpackage() silently SKIPS hidden .pth files.
# The result is a package that `pip show` reports as installed but that fails to
# import, with no error anywhere. Clear it with:
#     chflags nohidden .venv/lib/python3.12/site-packages/__editable__*.pth
# This block makes the console work regardless. It is a no-op on a healthy install.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import chainlit as cl  # noqa: E402  (import after the sys.path fix above)

from policyguard.audit import audit_log  # noqa: E402
from policyguard.policy import policy_store  # noqa: E402
from policyguard.types import AuditEntry  # noqa: E402

POLICY_PATH = "policy/devassist.yaml"

#: Max escalations shown by `queue`.
QUEUE_LIMIT = 50

HELP = (
    "Unknown command. Try: `queue` | `tools` | `log` | `verify` | `kill` "
    "| `approve <id>` | `block <id>`"
)


# ── Incident card ──────────────────────────────────────────────────────────


def incident_card(entry: AuditEntry) -> str:
    """Render one escalation as an incident card."""
    evidence = ", ".join(entry.evidence_ids) or "(none)"
    sources = ", ".join(entry.source_labels) or "(none)"
    return (
        f"🚨 **ESCALATION** — `{entry.id}`\n\n"
        f"```\n"
        f"Session:     {entry.session_id}\n"
        f"Time:        {entry.timestamp}\n"
        f"Action:      {entry.action}\n"
        f"Sources:     {sources}\n"
        f"Gate score:  {entry.gate_score}   Confidence: {entry.confidence}\n"
        f"Steps used:  {entry.steps_used}\n"
        f"Severity:    {entry.severity}\n"
        f"Layer:       {entry.layer}\n"
        f"```\n"
        f"**Evidence IDs:** {evidence}\n\n"
        f"**Reasoning:** {entry.reasoning or '(none recorded)'}\n\n"
        f"→ `approve {entry.id}`   or   `block {entry.id}`"
    )


# ── Startup ────────────────────────────────────────────────────────────────


@cl.on_chat_start
async def start() -> None:
    await audit_log.init()
    policy_store.load(POLICY_PATH)
    session_id = str(uuid.uuid4())
    cl.user_session.set("session_id", session_id)
    cl.user_session.set("killed", False)
    await cl.Message(
        content=(
            f"🛡️  **PolicyGuard Analyst Console**\n\n"
            f"Console session: `{session_id}`\n\n"
            f"Policy: {policy_store.summary()}\n\n"
            f"Commands:\n"
            f"```\n"
            f"queue            — show pending escalations\n"
            f"tools            — tool registry: which tools are quarantined and why\n"
            f"log              — full session audit log\n"
            f"verify           — replay the audit hash chain: has the log been tampered with?\n"
            f"approve <id>     — approve an escalated action\n"
            f"block <id>       — block an escalated action\n"
            f"kill             — kill the session immediately\n"
            f"```"
        )
    ).send()


# ── Command handlers ───────────────────────────────────────────────────────


async def _show_queue() -> None:
    """Send one incident card per pending escalation, across all agent sessions."""
    escalations = await audit_log.get_all_escalations(QUEUE_LIMIT)
    if not escalations:
        await cl.Message(content="✅ No pending escalations.").send()
        return
    await cl.Message(content=f"**{len(escalations)} pending escalation(s):**").send()
    for entry in escalations:
        await cl.Message(content=incident_card(entry)).send()


async def _show_log(session_id: str) -> None:
    """Send the audit log as a plain-text table in a code block."""
    entries = await audit_log.get_session(session_id)
    if not entries:
        entries = await audit_log.get_all_escalations(QUEUE_LIMIT)
        header = "No entries for this console session; showing recent escalations instead."
    else:
        header = f"Audit log for `{session_id}`:"
    if not entries:
        await cl.Message(content="Audit log is empty.").send()
        return
    rows = [f"{'TIMESTAMP':<26} {'LAYER':<13} {'ACTION':<42} DECISION", "-" * 95]
    rows += [
        f"{str(e.timestamp):<26} {e.layer:<13} {e.action[:42]:<42} {e.decision}" for e in entries
    ]
    await cl.Message(content=f"{header}\n```\n" + "\n".join(rows) + "\n```").send()


async def _show_tools() -> None:
    """Registry layer: show every tool's scan status (clean / suspicious / quarantined) and why.

    This is the first PolicyGuard layer. It scans each MCP tool's description and schema at
    connection time, before the agent is allowed to call it, and quarantines poisoned tools.
    """
    try:
        from policyguard.registry import TOOL_REGISTRY
    except Exception as exc:  # noqa: BLE001
        await cl.Message(content=f"Could not load the tool registry: {exc!r}").send()
        return

    badge = {"quarantined": "QUARANTINED", "suspicious": "suspicious", "clean": "clean"}
    order = {"quarantined": 0, "suspicious": 1, "clean": 2, "unscanned": 3}
    names = sorted(TOOL_REGISTRY, key=lambda n: (order.get(TOOL_REGISTRY[n].get("status"), 9), n))

    n_quar = sum(e.get("status") == "quarantined" for e in TOOL_REGISTRY.values())
    n_susp = sum(e.get("status") == "suspicious" for e in TOOL_REGISTRY.values())
    header = (
        f"**Tool registry (layer 1: scan at connection)** - "
        f"{len(names)} tools, {n_quar} quarantined, {n_susp} suspicious\n"
    )
    await cl.Message(content=header).send()

    for name in names:
        entry = TOOL_REGISTRY[name]
        status = entry.get("status", "unscanned")
        findings = entry.get("scan_result", {}).get("findings", [])
        mark = badge.get(status, status)
        lines = [f"`{name}` - **{mark}**"]
        if findings:
            lines.append("```")
            lines += [f"- {f}" for f in findings]
            lines.append("```")
        else:
            lines.append("_no suspicious findings_")
        await cl.Message(content="\n".join(lines)).send()


async def _verify_chain() -> None:
    """Replay the audit log's hash chain and report whether it is intact.

    Every row stores the hash of the row before it, so editing, deleting or
    reordering any row breaks every digest after it. This is the control an
    auditor cares about: not "the log says X", but "the log can be shown not to
    have been rewritten since X was written".

    Deliberately states the limit alongside the result. The chain makes
    tampering *detectable*, not impossible: whoever can write the database can
    recompute the chain, and truncating the newest rows leaves a consistent
    chain. Closing that needs a digest published where the attacker has no
    write access, which is roadmap, not shipped.
    """
    report = await audit_log.verify_chain()
    # Three outcomes, not two. A row written before the chain existed cannot be
    # attested, but it is not evidence of tampering either -- calling it
    # tampering would cry wolf on any pre-existing database, including on
    # stage. Only a broken link or an unexplained edit is an alarm.
    if report["broken_links"] or report["tampered"]:
        status = "🚨 TAMPERING DETECTED"
    elif report["unhashed"]:
        status = "⚠️ intact, but partly predates the chain"
    else:
        status = "✅ intact"
    lines = [
        f"**Audit chain: {status}**",
        "",
        f"Rows checked: {report['rows']}",
    ]
    for label, key in (
        ("Broken links (insert / delete / reorder)", "broken_links"),
        ("Rows altered with no amendment on record", "tampered"),
        ("Rows not covered by the chain", "unhashed"),
    ):
        if report[key]:
            lines.append(f"- {label}: `{'`, `'.join(report[key][:10])}`")
    if report["amended"]:
        lines.append(
            f"- Analyst overrides on record (legitimate): {len(report['amended'])}"
        )
    lines += [
        "",
        "_Each row commits to the hash of the previous one, so any edit, deletion or "
        "reordering invalidates every hash after it. This makes tampering detectable, "
        "not impossible: anyone who can write the database can recompute the chain, and "
        "deleting the newest rows leaves a consistent chain. Publishing a periodic "
        "digest externally would close both gaps — that is roadmap, not shipped._",
    ]
    await cl.Message(content="\n".join(lines)).send()


async def _kill(session_id: str) -> None:
    """Flip the kill switch and record it so the guard process can see it."""
    cl.user_session.set("killed", True)
    await audit_log.log(
        AuditEntry(
            session_id=session_id,
            event_type="session_kill",
            action="analyst activated the kill switch",
            source_labels=["user"],
            layer="human",
            decision="killed",
            decided_by="human",
            severity="critical",
            violation=True,
            reasoning="Analyst killed the session from the console.",
        )
    )
    await cl.Message(content="⛔ Session killed. All further agent actions are blocked.").send()


async def _resolve(entry_id: str, session_id: str, decision: str) -> None:
    """Apply the analyst's Approve/Block to an escalated entry and log the override."""
    original = next(
        (e for e in await audit_log.get_all_escalations(QUEUE_LIMIT) if e.id == entry_id), None
    )
    verb = "approved" if decision == "allow" else "blocked"
    reason = f"Analyst {verb}"

    await audit_log.update_decision(entry_id, decision, "human", reason)
    await audit_log.log(
        AuditEntry(
            session_id=original.session_id if original else session_id,
            event_type="human_decision",
            action=f"analyst {verb} {entry_id}"
            + (f" ({original.action})" if original else ""),
            source_labels=original.source_labels if original else ["user"],
            layer="human",
            gate_score=original.gate_score if original else None,
            confidence=original.confidence if original else None,
            evidence_ids=original.evidence_ids if original else [],
            severity=original.severity if original else "low",
            decision=decision,
            decided_by="human",
            violation=decision == "block",
            reasoning=reason,
        )
    )

    if original is None:
        await cl.Message(
            content=(
                f"⚠️ No pending escalation found with id `{entry_id}` — "
                f"the override was still logged. Run `queue` to see valid ids."
            )
        ).send()
    elif decision == "allow":
        await cl.Message(content=f"✅ Action `{entry_id}` approved and logged.").send()
    else:
        await cl.Message(content=f"🚫 Action `{entry_id}` blocked and logged.").send()


# ── Message router ─────────────────────────────────────────────────────────


@cl.on_message
async def handle(message: cl.Message) -> None:
    session_id = cl.user_session.get("session_id")
    killed = cl.user_session.get("killed", False)
    cmd = message.content.strip()

    if killed and not cmd.startswith("log"):
        await cl.Message(content="⛔ Session is killed. Only `log` is available.").send()
        return

    if cmd == "queue":
        await _show_queue()
    elif cmd == "tools":
        await _show_tools()
    elif cmd == "log":
        await _show_log(session_id)
    elif cmd == "verify":
        await _verify_chain()
    elif cmd == "kill":
        await _kill(session_id)
    elif cmd.startswith("approve "):
        entry_id = cmd.split(" ", 1)[1].strip()
        await _resolve(entry_id, session_id, "allow")
    elif cmd.startswith("block "):
        entry_id = cmd.split(" ", 1)[1].strip()
        await _resolve(entry_id, session_id, "block")
    else:
        await cl.Message(content=HELP).send()


# ── Real-time alert (called by the Investigator when an escalation fires) ──


async def send_escalation_alert(entry: AuditEntry) -> None:
    """Push an incident card immediately when the Investigator escalates.

    Only works in-process: `cl.Message` needs an active Chainlit session context.
    When the guard runs as a separate process (the normal demo setup) there is no
    context, so this logs a warning and returns instead of raising -- the incident
    is already durable in the audit log and will appear via `queue`.
    """
    try:
        await cl.Message(content=incident_card(entry)).send()
    except Exception as exc:  # noqa: BLE001 - never break the guard on a UI push
        print(f"[console] could not push escalation {entry.id} ({exc!r}); use `queue` in the console")
