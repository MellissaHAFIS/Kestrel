"""Pipeline: the single integration seam, run_pipeline(action, llm) -> Verdict.


Order of layers (first final decision wins):
    kill switch -> registry -> invariants -> gate -> investigator

Rules:
- Kill switch: once the analyst kills a session, nothing else runs.
- Registry: quarantined tools are never reviewed further.
- Invariants: a violation is a final BLOCK.
- Gate: score <= gate_low -> allow, score >= gate_high -> block, else Investigator.
- Investigator: may escalate / block / allow with confidence.
- AI can only tighten, never lift a hard-invariant block. Nothing downstream of
  `invariants` may turn a block into an allow.

FAIL CLOSED: if a deterministic guarantee layer (registry, invariants) cannot be
loaded or raises, the action is blocked rather than allowed. Set
FAIL_CLOSED_ON_LAYER_ERROR = False to degrade to `escalate` instead, which keeps
a demo running while still putting every affected action in front of a human.
"""

from __future__ import annotations

import time
from typing import Any

from policyguard.audit import audit_log
from policyguard.policy import policy_store
from policyguard.types import Action, AuditEntry, Verdict

#: A broken guarantee layer blocks (True) or escalates to a human (False).
FAIL_CLOSED_ON_LAYER_ERROR = True

#: Fallback thresholds, used only if the policy cannot be read.
_DEFAULT_GATE_LOW = 0.20
_DEFAULT_GATE_HIGH = 0.80


def _thresholds() -> tuple[float, float]:
    """(gate_low, gate_high) from policy, with safe fallbacks.

    Read lazily: importing the pipeline must never fail on a missing policy file.
    """
    try:
        section = policy_store.get_section("thresholds")
        return (
            float(section.get("gate_low", _DEFAULT_GATE_LOW)),
            float(section.get("gate_high", _DEFAULT_GATE_HIGH)),
        )
    except Exception:  # noqa: BLE001 - policy unreadable; use conservative defaults
        return (_DEFAULT_GATE_LOW, _DEFAULT_GATE_HIGH)


GATE_LOW, GATE_HIGH = _thresholds()

#: Which audit event_type each layer records.
_EVENT_TYPE = {
    "registry": "registry_scan",
    "invariant": "tool_call",
    "ml_gate": "tool_call",
    "investigator": "investigation",
    "human": "human_decision",
}

#: Severity per outcome, for the console queue ordering.
_SEVERITY = {"allow": "low", "sanitize": "medium", "escalate": "high", "block": "critical"}


async def _instant_verdict(
    action: Action,
    decision: str,
    confidence: float,
    reasoning: str,
    layer: str,
) -> Verdict:
    """
    Build a Verdict instantly (no LLM call) for clear-cut gate decisions.
    Log to audit_log as a non-investigation event.
    latency_ms is 0.0 (synchronous layers).
    verified = True (no evidence to check).

    NOTE: async (not sync as originally specified) because audit_log.log is async.
    """
    verdict = Verdict(
        action_id=action.id,
        decision=decision,  # type: ignore[arg-type]
        confidence=confidence,
        gate_score=action.gate_score if action.gate_score is not None else 0.0,
        evidence=[],
        report=reasoning,
        sources=list(action.sources),
        steps_used=0,
        latency_ms=0.0,
        verified=True,
    )
    await audit_log.log(
        AuditEntry(
            id=action.id,
            session_id=action.session_id,
            event_type=_EVENT_TYPE.get(layer, "tool_call"),  # type: ignore[arg-type]
            action=f"{action.tool_name}({', '.join(action.args)})",
            source_labels=list(action.sources),
            layer=layer,  # type: ignore[arg-type]
            gate_score=action.gate_score,
            evidence_ids=[],
            violation=decision == "block",
            severity=_SEVERITY.get(decision, "low"),  # type: ignore[arg-type]
            confidence=confidence,
            reasoning=reasoning,
            decision=decision,  # type: ignore[arg-type]
            decided_by="system",
            steps_used=0,
            latency_ms=0.0,
        )
    )
    return verdict


async def _layer_unavailable(action: Action, layer: str, detail: str) -> Verdict:
    """Fail-closed verdict for a guarantee layer that could not run."""
    decision = "block" if FAIL_CLOSED_ON_LAYER_ERROR else "escalate"
    return await _instant_verdict(
        action,
        decision,
        1.0,
        f"FAIL CLOSED: {layer} layer unavailable ({detail})",
        layer=layer,
    )


# ── 1. Registry ────────────────────────────────────────────────────────────


async def _check_registry(action: Action) -> Verdict | None:
    """Quarantined tools never reach any later layer."""
    try:
        from policyguard.registry import TOOL_REGISTRY
    except Exception as exc:  # noqa: BLE001
        return await _layer_unavailable(action, "registry", repr(exc))
    entry = TOOL_REGISTRY.get(action.tool_name)
    if entry and entry.get("status") == "quarantined":
        findings = entry.get("scan_result", {}).get("findings", [])
        detail = f": {findings[0]}" if findings else ""
        return await _instant_verdict(
            action, "block", 1.0, f"Tool quarantined by registry{detail}", layer="registry"
        )
    return None


# ── 2. Hard invariants ─────────────────────────────────────────────────────


async def _check_invariants(action: Action) -> Verdict | None:
    """A violation here is a final block no later layer may lift."""
    try:
        from policyguard import invariants
    except Exception as exc:  # noqa: BLE001 - invariants is a guarantee layer
        return await _layer_unavailable(action, "invariant", repr(exc))
    try:
        # invariants.py predates the frozen contract: it wants `.qualified_tool`
        # and `.server`, which the frozen Action does not have. Adapt at the
        # boundary rather than rewriting that layer. See policyguard/compat.py.
        from policyguard.compat import as_legacy_action

        result = invariants.check_invariants(as_legacy_action(action), policy_store.policy)
    except Exception as exc:  # noqa: BLE001
        return await _layer_unavailable(action, "invariant", repr(exc))
    if result is None:
        return None
    reason = getattr(result, "reason", None) or getattr(result, "report", "hard invariant violated")
    return await _instant_verdict(action, "block", 1.0, reason, layer="invariant")


# ── 3. ML gate ─────────────────────────────────────────────────────────────


async def _check_gate(action: Action) -> tuple[Verdict | None, float]:
    """Score the action and apply the thresholds. Returns (verdict_or_None, score)."""
    try:
        from policyguard import gate

        gate_score = float(gate.score(action))
    except Exception as exc:  # noqa: BLE001 - the gate is advisory, not a guarantee
        # A broken gate must not allow anything: hand the action to the Investigator.
        print(f"[pipeline] WARNING: gate unavailable ({exc!r}); routing to Investigator")
        return None, 0.5

    action.gate_score = gate_score
    low, high = _thresholds()
    if gate_score <= low:
        return (
            await _instant_verdict(
                action, "allow", 1.0 - gate_score, "Gate: below low threshold", layer="ml_gate"
            ),
            gate_score,
        )
    if gate_score >= high:
        return (
            await _instant_verdict(
                action, "block", gate_score, "Gate: above high threshold", layer="ml_gate"
            ),
            gate_score,
        )
    return None, gate_score


# ── 4. Investigator ────────────────────────────────────────────────────────


async def _run_investigator(action: Action, llm: Any) -> Verdict:
    """Uncertain band: the agent loop. Escalates if it cannot be loaded or run."""
    started = time.perf_counter()
    try:
        from policyguard.investigator.graph import Investigator
    except Exception as exc:  # noqa: BLE001
        return await _instant_verdict(
            action,
            "escalate",
            0.0,
            f"Investigator unavailable ({exc!r}); escalating to a human",
            layer="investigator",
        )
    try:
        investigator = Investigator(llm)
        # Investigator.investigate() is responsible for its own audit logging.
        return await investigator.investigate(action)
    except Exception as exc:  # noqa: BLE001 - never let the agent loop crash the guard
        elapsed = (time.perf_counter() - started) * 1000
        print(f"[pipeline] WARNING: Investigator raised ({exc!r}); escalating")
        verdict = await _instant_verdict(
            action, "escalate", 0.0, f"Investigator error: {exc!r}", layer="investigator"
        )
        verdict.latency_ms = elapsed
        return verdict


# ── Entry point ────────────────────────────────────────────────────────────


async def run_pipeline(action: Action, llm: Any = None) -> Verdict:
    """
    Full pipeline: registry → invariants → gate → () AI agent )investigator → audit.
    Returns a Verdict for every action.
    """
    # ── 0. Kill switch ────────────────────────────────────────────────────
    # The analyst's console writes a session_kill row; nothing runs after that.
    try:
        if await audit_log.is_session_killed(action.session_id):
            return await _instant_verdict(
                action, "block", 1.0, "Session killed by analyst", layer="human"
            )
    except Exception as exc:  # noqa: BLE001
        print(f"[pipeline] WARNING: kill-switch check failed ({exc!r})")

    # ── 1. Registry scan ──────────────────────────────────────────────────
    verdict = await _check_registry(action)
    if verdict is not None:
        return verdict

    # ── 2. Hard invariants ────────────────────────────────────────────────
    verdict = await _check_invariants(action)
    if verdict is not None:
        return verdict

    # ── 3. ML gate ────────────────────────────────────────────────────────
    verdict, _gate_score = await _check_gate(action)
    if verdict is not None:
        return verdict

    # ── 4. Investigator (uncertain band) ──────────────────────────────────
    return await _run_investigator(action, llm)
