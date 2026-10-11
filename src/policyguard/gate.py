"""ML gate: cheap, fast, fixed-weight score for every action.

"""

from __future__ import annotations

import json
import re

from policyguard.compat import Verdict  # enum-style verdict for route()
from policyguard.types import Action

# Placeholders. TUNE ON VALIDATION ONLY; the real values live in policy/devassist.yaml.
GATE_LOW = 0.20
GATE_HIGH = 0.80


def score(action: Action) -> float:
    """Risk score in [0, 1].

    Ladder step 1 is a pretrained HF injection classifier (extra 'ml'), which is
    not wired up yet. Until it is, this delegates to the deterministic heuristic
    so the gate produces a real spread of scores: returning a constant 0.0 made
    every action fall below `gate_low`, which silently allowed everything and
    meant the Investigator was never reached.
    """
    #   _heuristic_score on any load error. Log the model hash with every decision.
    return _heuristic_score(action)


#: Phrases that commonly appear in injected instructions.
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the",
    "you must now",
    "new instructions",
    "system prompt",
    "do not tell",
    "without telling",
)

#: Exfiltration phrasing. Scored lower than an injection marker because the
#: untrusted-destination signal already covers most of this, and double
#: counting pushed ordinary suspicious calls past `gate_high`, blocking them
#: outright instead of sending them to the Investigator.
_EXFIL_MARKERS = ("exfiltrat", "send it to", "upload it to", "post the contents")

#: Words that suggest the value beside them is a credential.
_SECRET_WORDS = ("api key", "api_key", "apikey", "secret", "token", "password", "passwd",
                 "credential", "private key")

_URL_RE = re.compile(r"https?://([^\s/\"']+)", re.I)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")

#: Weights. Tuned so a benign call scores ~0 and a plausible exfiltration lands
#: in the uncertain band, where the Investigator takes over.
_W_UNTRUSTED_SOURCE = 0.30
_W_UNTRUSTED_HOST = 0.20
_W_SECRET_WORD = 0.15
_W_INJECTION_MARKER = 0.15
_W_EXFIL_MARKER = 0.05
_W_BIG_PAYLOAD = 0.10
_W_BASE64_BLOB = 0.10
_BIG_PAYLOAD_CHARS = 500
_SCORE_CAP = 0.95


def _arg_text(action: Action) -> str:
    """All string content in the args, flattened and lowercased."""
    try:
        return json.dumps(action.args, default=str).lower()
    except (TypeError, ValueError):
        return str(action.args).lower()


def _heuristic_score(action: Action) -> float:
    """Deterministic fallback: untrusted provenance, keywords, destinations, size.

    Additive and intentionally coarse. It only has to decide *whether an action
    deserves a closer look*, not what the answer is. Anything it is unsure
    about lands between `gate_low` and `gate_high` and goes to the Investigator.
    """
    text = _arg_text(action)
    total = 0.0

    if any(s in ("mcp_description", "tool_result") for s in action.sources):
        total += _W_UNTRUSTED_SOURCE

    hosts = _URL_RE.findall(text)
    if hosts:
        try:
            from policyguard.policy import policy_store

            trusted = [h.lower() for h in policy_store.get_trusted_destinations()]
        except Exception:  # noqa: BLE001 - policy unreadable; treat hosts as unknown
            trusted = []
        for host in hosts:
            host = host.lower()
            if not any(host == t or host.endswith("." + t) for t in trusted):
                total += _W_UNTRUSTED_HOST
                break

    if any(word in text for word in _SECRET_WORDS):
        total += _W_SECRET_WORD
    if any(marker in text for marker in _INJECTION_MARKERS):
        total += _W_INJECTION_MARKER
    if any(marker in text for marker in _EXFIL_MARKERS):
        total += _W_EXFIL_MARKER
    if len(text) > _BIG_PAYLOAD_CHARS:
        total += _W_BIG_PAYLOAD
    if _B64_RE.search(text):
        total += _W_BASE64_BLOB

    return round(min(total, _SCORE_CAP), 4)


def route(gate_score: float, low: float = GATE_LOW, high: float = GATE_HIGH) -> Verdict | None:
    """score < low -> ALLOW, score > high -> BLOCK, in between -> None (Investigator)."""
    if gate_score < low:
        return Verdict.ALLOW
    if gate_score > high:
        return Verdict.BLOCK
    return None
