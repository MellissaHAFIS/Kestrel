"""ML gate: cheap, fast, fixed-weight score for every action.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.
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
    # TODO(person2): load the classifier lazily (extra 'ml') and fall back to
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

#: A run of alphanumerics long enough, and mixed enough, to be an opaque
#: identifier rather than a word: >= 12 characters containing at least one
#: digit and at least one letter. This is the shape of an API key, a token, a
#: hash or a session id. Prose does not look like this, and a path like
#: `config/settings.yaml` does not either.
#:
#: Deliberately conservative. It does not fire on letters-only strings, however
#: suspicious they read, because that is where the false positives live.
_OPAQUE_TOKEN_RE = re.compile(r"(?=[a-z0-9]{12,})(?=[a-z0-9]*\d)[a-z0-9]*[a-z][a-z0-9]*")

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

#: Weight for an action whose *destination server* is not trusted by the policy.
#:
#: This closed a structural gap rather than a specific miss: the gate inspected
#: URLs inside the argument text but never looked at where the call itself was
#: going, so it was the only layer blind to the trust boundary the rest of the
#: system is built on. An MCP tool on an untrusted server is exactly the channel
#: a tool-poisoning chain uses.
#:
#: Both new weights are 0.15, derived from the existing `GATE_LOW` of 0.20 and
#: NOT from looking at which chains failed:
#:   * alone, 0.15 < 0.20, so the action is still allowed. Calling an external
#:     documentation server must not by itself cost an analyst's attention, or
#:     the system is unusable and alert fatigue does the attacker's work.
#:   * combined with any other signal (the smallest is 0.05) it clears 0.20 and
#:     goes to the Investigator. Co-occurrence is the thing worth a closer look.
#: No threshold was changed.
_W_UNTRUSTED_DEST = 0.15
_W_OPAQUE_TOKEN = 0.15


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

    Signals, in rough order of weight: untrusted provenance, an untrusted host
    in the argument text, an untrusted destination *server*, credential-adjacent
    words, injection phrasing, an opaque identifier, a large payload, a base64
    blob, exfiltration phrasing.
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

    if not _destination_trusted(action):
        total += _W_UNTRUSTED_DEST
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
    if _OPAQUE_TOKEN_RE.search(text):
        total += _W_OPAQUE_TOKEN

    return round(min(total, _SCORE_CAP), 4)


def _destination_trusted(action: Action) -> bool:
    """Whether the policy trusts the server this action is calling.

    Fails *safe for availability* rather than safe for security, on purpose: an
    unreadable policy returns True, so a broken config cannot silently turn
    every action into an escalation and drown the analyst. The guarantee layers
    (registry, invariants) already fail closed on policy errors, and the gate is
    only deciding whether something deserves a closer look.

    `Action.tool_name` is fully qualified as "server.tool"; a bare name has no
    server to judge and is treated as trusted for the same reason.
    """
    server, _, tool = action.tool_name.rpartition(".")
    if not server or not tool:
        return True
    try:
        from policyguard.policy import policy_store

        return policy_store.policy.is_trusted(server)
    except Exception:  # noqa: BLE001 - policy unreadable; do not manufacture alerts
        return True


def route(gate_score: float, low: float = GATE_LOW, high: float = GATE_HIGH) -> Verdict | None:
    """score < low -> ALLOW, score > high -> BLOCK, in between -> None (Investigator)."""
    if gate_score < low:
        return Verdict.ALLOW
    if gate_score > high:
        return Verdict.BLOCK
    return None
