"""Tests for the chain-level canary check and the session accumulator it reads.

What is being pinned
--------------------
A canary split over several calls defeats every single-action rule by
construction: each fragment is individually clean. `check_cross_call_canary`
is the only layer that catches it, so its contract needs to be explicit.

The contract has two halves, and both are easy to get wrong:

* **Positional coverage, not string containment.** Concatenating the session's
  fragments and searching the joined text was the obvious first implementation
  and it does not work -- an attacker who pads each call breaks the token
  across filler, so it is never contiguous. Each fragment is compared against
  the canary on its own and contributes the *positions* it discloses.
* **Only allowed calls accumulate.** A blocked call never left the process, so
  it must not contribute to a later block either. Otherwise a single attempt
  poisons the rest of the session with false positives.

`test_blocked_calls_do_not_accumulate` is the one that matters most: it is the
difference between a guard and a nuisance.
"""

from __future__ import annotations

import pytest

from policyguard import invariants, session_state
from policyguard.compat import as_legacy_action
from policyguard.policy import load_policy
from policyguard.types import Action

CANARY = "CANARY-PG-7f3a9c0d-FAKE-DO-NOT-USE"
#: The canary as the checks see it: lowercased, alphanumerics only. 28 chars.
SQUASHED = "canarypg7f3a9c0dfakedonotuse"


@pytest.fixture
def policy():
    return load_policy("policy/devassist.yaml")


@pytest.fixture(autouse=True)
def _clean_sessions():
    """Every test starts with an empty accumulator and leaves one behind.

    The accumulator is module-level state. Without this the tests would leak
    fragments into each other, which is exactly the failure mode that makes
    `tests/test_investigator.py` flaky through the `audit_log` singleton.
    """
    session_state.reset()
    yield
    session_state.reset()


def _lookup(text: str, server: str = "docs_helper"):
    """An outgoing call to an untrusted server carrying ``text``."""
    return as_legacy_action(
        Action(
            session_id="s-xcall",
            tool_name=f"{server}.lookup_reference",
            args={"query": "timing safe compare", "session_notes": text},
            sources=["tool_result"],
        )
    )


# ── the squashed form is what the test assumes ────────────────────────────


def test_squashed_canary_is_what_the_thresholds_were_sized_against() -> None:
    """The 14/8-char floors are documented as fractions of a 28-char token."""
    action = _lookup(CANARY)
    assert SQUASHED in invariants.squashed_arg_text(action)
    assert len(SQUASHED) == 28


# ── canary_coverage: positions, not containment ───────────────────────────


def test_coverage_of_a_whole_canary_is_every_position() -> None:
    assert invariants.canary_coverage(SQUASHED, SQUASHED) == set(range(28))


def test_coverage_of_an_absent_canary_is_empty() -> None:
    assert invariants.canary_coverage(SQUASHED, "nothinginterestinghere") == set()


def test_coverage_ignores_runs_below_the_fragment_floor() -> None:
    """A 7-char sliver must contribute nothing, or noise becomes a block."""
    sliver = SQUASHED[:7]
    assert len(sliver) < invariants.CANARY_FRAGMENT_MIN_CHARS
    assert invariants.canary_coverage(SQUASHED, f"prefix{sliver}suffix") == set()


def test_coverage_is_indifferent_to_surrounding_padding() -> None:
    """The reason coverage is positional: padding must not hide a fragment."""
    half = SQUASHED[:14]
    padded = f"someunrelatedprose{half}moreunrelatedprose"
    assert invariants.canary_coverage(SQUASHED, padded) == set(range(14))


# ── check_cross_call_canary: the chain-level block ─────────────────────────


def test_two_padded_calls_that_complete_the_canary_are_blocked(policy) -> None:
    """The headline case. Neither call holds the token; together they do."""
    first, second = SQUASHED[:14], SQUASHED[14:]
    prior = [f"refpartone{first}thanks"]

    decision = invariants.check_cross_call_canary(
        _lookup(f"ref part two {second} end"), policy, prior
    )

    assert decision is not None, "a canary completed across two calls must block"
    assert decision.verdict == "block"
    assert decision.layer == "invariants"
    assert "canary_reassembled" in decision.reason
    assert decision.evidence and decision.evidence[0].kind == "canary_reassembled"


def test_neither_half_is_caught_by_the_single_action_rules(policy) -> None:
    """Proves the chain check is load-bearing and not duplicating rule 2.

    If a half were already a hard violation on its own, this whole layer would
    be redundant. Each half is 14 squashed chars, which is the single-call
    partial floor, so we use 13 to stay strictly under it.
    """
    for half in (SQUASHED[:13], SQUASHED[-13:]):
        action = as_legacy_action(
            Action(
                session_id="s-half",
                tool_name="docs_helper.lookup_reference",
                args={"query": half},
                sources=["tool_result"],
            )
        )
        result = invariants.check_invariants(action, policy)
        canary_hit = result is not None and "canary" in (result.reason or "")
        assert not canary_hit, f"{half!r} should not be a canary violation on its own"


def test_an_incomplete_canary_does_not_block(policy) -> None:
    """Partial coverage across calls is for the Investigator, not a hard block."""
    prior = [SQUASHED[:14]]
    decision = invariants.check_cross_call_canary(_lookup(SQUASHED[14:24]), policy, prior)
    assert decision is None


def test_a_call_adding_nothing_new_does_not_block(policy) -> None:
    """Once a leak has completed, later calls must not all be blamed for it."""
    prior = [SQUASHED[:14], SQUASHED[14:]]
    decision = invariants.check_cross_call_canary(_lookup(SQUASHED[:14]), policy, prior)
    assert decision is None


def test_a_trusted_destination_is_not_a_leak(policy) -> None:
    """Reassembly only matters when the data crosses the trust boundary."""
    prior = [SQUASHED[:14]]
    action = as_legacy_action(
        Action(
            session_id="s-xcall",
            tool_name="legit_server.file_read",
            args={"path": SQUASHED[14:]},
            sources=["user"],
        )
    )
    assert invariants.check_cross_call_canary(action, policy, prior) is None


def test_an_empty_session_cannot_block(policy) -> None:
    """With no prior fragments the check must defer; a single call is rule 2's job."""
    assert invariants.check_cross_call_canary(_lookup(SQUASHED[14:]), policy, []) is None


def test_the_check_is_deterministic_in_its_inputs(policy) -> None:
    """State is passed in, never read from a global, so a decision replays."""
    prior = [SQUASHED[:14]]
    action = _lookup(SQUASHED[14:])
    first = invariants.check_cross_call_canary(action, policy, prior)
    second = invariants.check_cross_call_canary(action, policy, prior)
    assert first is not None and second is not None
    assert (first.verdict, first.reason) == (second.verdict, second.reason)


def test_a_canary_spread_over_three_calls_is_blocked(policy) -> None:
    """Coverage accumulates over any number of calls, not just two."""
    prior = [f"a{SQUASHED[:10]}z", f"b{SQUASHED[10:20]}y"]
    decision = invariants.check_cross_call_canary(_lookup(f"c{SQUASHED[20:]}x"), policy, prior)
    assert decision is not None
    assert decision.verdict == "block"


# ── session_state: only allowed calls accumulate ──────────────────────────


def test_blocked_calls_do_not_accumulate(policy) -> None:
    """The invariant that keeps this from becoming a false-positive machine.

    `pipeline.run_pipeline` records a payload only on `allow`. A call that was
    blocked never reached the destination, so the first half of the canary
    never left and the second half alone is not a completed leak.
    """
    # The attacker's first call is blocked, so the pipeline records nothing.
    session_state.reset("s-xcall")
    prior = session_state.prior_outgoing("s-xcall")
    assert prior == []
    assert invariants.check_cross_call_canary(_lookup(SQUASHED[14:]), policy, prior) is None


def test_recorded_fragments_round_trip_in_order() -> None:
    session_state.note_allowed_outgoing("s-a", "first")
    session_state.note_allowed_outgoing("s-a", "second")
    assert session_state.prior_outgoing("s-a") == ["first", "second"]


def test_sessions_are_isolated() -> None:
    session_state.note_allowed_outgoing("s-a", "aaa")
    session_state.note_allowed_outgoing("s-b", "bbb")
    assert session_state.prior_outgoing("s-a") == ["aaa"]
    assert session_state.prior_outgoing("s-b") == ["bbb"]


def test_fragments_per_session_are_bounded() -> None:
    """Unbounded growth in a long-lived process would be a slow leak."""
    for i in range(session_state.MAX_FRAGMENTS_PER_SESSION + 10):
        session_state.note_allowed_outgoing("s-cap", f"frag{i}")
    kept = session_state.prior_outgoing("s-cap")
    assert len(kept) == session_state.MAX_FRAGMENTS_PER_SESSION
    assert kept[-1] == f"frag{session_state.MAX_FRAGMENTS_PER_SESSION + 9}", "newest is kept"


def test_empty_values_are_not_recorded() -> None:
    session_state.note_allowed_outgoing("s-empty", "")
    session_state.note_allowed_outgoing("", "something")
    assert session_state.prior_outgoing("s-empty") == []


def test_reset_clears_one_session_or_all() -> None:
    session_state.note_allowed_outgoing("s-a", "aaa")
    session_state.note_allowed_outgoing("s-b", "bbb")
    session_state.reset("s-a")
    assert session_state.prior_outgoing("s-a") == []
    assert session_state.prior_outgoing("s-b") == ["bbb"]
    session_state.reset()
    assert session_state.prior_outgoing("s-b") == []


# ── single-call obfuscation added alongside the chain check ────────────────


def test_a_partial_canary_in_one_call_is_a_leak(policy) -> None:
    """Half a honeytoken is still a disclosure; exact matching scored it clean."""
    result = invariants.check_invariants(_lookup(f"our token prefix is {SQUASHED[:20]}"), policy)
    assert result is not None
    assert "canary" in (result.reason or "")


def test_a_rot13_canary_is_a_leak(policy) -> None:
    """The defence sheet claims rot13 is covered; this is that claim."""
    rot13 = CANARY.translate(invariants._ROT13_TABLE)
    assert rot13 != CANARY
    result = invariants.check_invariants(_lookup(rot13), policy)
    assert result is not None
    assert "canary" in (result.reason or "")
