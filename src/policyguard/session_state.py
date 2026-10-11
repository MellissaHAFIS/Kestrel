"""Per-session memory of what actually left the agent, for chain-level checks.

Why this module exists
----------------------
`invariants.py` is deliberately pure: the same Action plus the same Policy must
always yield the same Decision. That purity is what lets us call it a
*guarantee* layer, and it must not be broken.

But a canary split across two calls defeats any single-action check by
construction: "ref part one: CANARY-PG-7f3a9" then "part two: c0d-FAKE-DO-NOT-USE".
Each fragment is individually clean. Only the *chain* is a leak, and supervising
the chain is this project's headline claim.

So the state lives here, outside the pure layer, and the pipeline feeds it. The
invariant that consumes it (`invariants.check_cross_call_canary`) is still a
deterministic function of (action, policy, prior) -- it just takes the prior
explicitly instead of reaching for a global.

What is recorded
----------------
Only the squashed (lowercased, alphanumeric-only) text of arguments for calls
that were **allowed to proceed to an untrusted destination**. A blocked call
never left the process, so it cannot contribute to an exfiltration and must not
contribute to a later block either -- otherwise one attempted leak would poison
the rest of the session with false positives.

Nothing here is a secret store: the squashed text is already in the audit trail
in a richer form, the buffers are in-memory only, bounded, and never persisted.
"""

from __future__ import annotations

from collections import OrderedDict

#: Most recent fragments kept per session. A canary reassembles from a handful
#: of calls; keeping twenty is generous and bounds the work.
MAX_FRAGMENTS_PER_SESSION = 20

#: Per-fragment character cap. Long payloads are truncated from the *end* kept,
#: because a token smuggled into a long blob tends to sit near a boundary we
#: cannot predict; we keep the head, which is what short fragments are.
MAX_FRAGMENT_CHARS = 4_000

#: Sessions tracked at once. Oldest is evicted. Prevents unbounded growth in a
#: long-lived process.
MAX_SESSIONS = 256

#: session_id -> list of squashed fragments, oldest first.
_FRAGMENTS: OrderedDict[str, list[str]] = OrderedDict()


def note_allowed_outgoing(session_id: str, squashed_text: str) -> None:
    """Record that ``squashed_text`` was allowed to leave, for session ``session_id``."""
    if not session_id or not squashed_text:
        return
    fragment = squashed_text[:MAX_FRAGMENT_CHARS]
    fragments = _FRAGMENTS.get(session_id)
    if fragments is None:
        fragments = []
        _FRAGMENTS[session_id] = fragments
        while len(_FRAGMENTS) > MAX_SESSIONS:
            _FRAGMENTS.popitem(last=False)
    _FRAGMENTS.move_to_end(session_id)
    fragments.append(fragment)
    del fragments[:-MAX_FRAGMENTS_PER_SESSION]


def prior_outgoing(session_id: str) -> list[str]:
    """Every fragment previously allowed out of this session, oldest first.

    Returned as a list, not a concatenation. Concatenating was the first thing
    we tried and it does not work: an attacker who pads each call
    ("ref b: 7f3a9c0d") breaks the token across filler text, so the canary is
    never contiguous in the joined string. Each fragment has to be compared
    against the canary on its own -- see `invariants.canary_coverage`.
    """
    return list(_FRAGMENTS.get(session_id, ()))


def reset(session_id: str | None = None) -> None:
    """Forget one session, or all of them when ``session_id`` is None."""
    if session_id is None:
        _FRAGMENTS.clear()
    else:
        _FRAGMENTS.pop(session_id, None)
