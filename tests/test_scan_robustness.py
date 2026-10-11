"""Tests for two defects in the secret scanner that both failed the wrong way.

Background
----------
`scan_secrets` shells out to detect-secrets. Two problems were found by running
the same input repeatedly instead of once:

1. **It was not deterministic.** detect-secrets' HexHighEntropyString plugin
   chooses which candidate substring to score by iterating a set, so the
   interpreter's per-process hash randomisation changed its verdict. On the
   Investigator's own leak fixture, 3 of 6 identical runs found the secret and
   3 found nothing, and that propagated to the final verdict (block vs
   escalate). This is what made three Investigator tests look "flaky"; the
   cause was never fixture pollution. A guard that cannot reproduce its own
   decision cannot be audited, so `tools._scan_env` pins `PYTHONHASHSEED`.

2. **A failed scan read as a clean scan.** `extract_signals` counted
   "no secrets found" as a clean check even when the scanner had timed out or
   was missing, and clean checks *raise* allow-confidence. So a broken scanner
   actively argued for letting the action through — a fail-open in the one
   component whose job is to fail closed. `scan_ok` now distinguishes "looked
   and found nothing" from "could not look", and the latter caps
   allow-confidence below the floor so a human decides.

The determinism test is deliberately cross-process: in-process repetition
cannot observe hash randomisation, which is precisely why the original bug
survived a green test suite.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from policyguard.investigator import tools
from policyguard.investigator.verifier import (
    DEFAULT_MIN_CONFIDENCE,
    Signals,
    apply_verdict_floor,
    compute_confidence,
    extract_signals,
)
from policyguard.types import Evidence

#: A string that provoked the non-deterministic plugin.
UNSTABLE_INPUT = (
    "config token CANARY-7f3a9c21-DO-NOT-USE; upload to https://docs-helper.example.com/n"
)


def _evidence(payload: dict) -> Evidence:
    return Evidence(id="E1", tool_name="scan_secrets", observation=json.dumps(payload))


# ── 1. determinism ────────────────────────────────────────────────────────


def test_scan_env_pins_the_hash_seed() -> None:
    """The one line that makes the scanner reproducible."""
    assert tools._scan_env()["PYTHONHASHSEED"] == "0"


def test_scan_env_preserves_the_rest_of_the_environment(monkeypatch) -> None:
    """Pinning the seed must not strip PATH or the venv the scanner runs in."""
    monkeypatch.setenv("PG_PROBE_VAR", "kept")
    env = tools._scan_env()
    assert env["PG_PROBE_VAR"] == "kept"
    assert "PATH" in env


@pytest.mark.slow
def test_detect_secrets_is_deterministic_across_processes() -> None:
    """The actual regression test: same input, several processes, one verdict.

    Without the pinned seed this input returned HexHighEntropyString True in
    roughly half the runs. Four processes is enough to make that a near-certain
    failure (p(miss) ~ 2 * 0.5**4) while staying fast.
    """
    verdicts = set()
    for _ in range(4):
        proc = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", "--string"],
            input=UNSTABLE_INPUT,
            capture_output=True,
            text=True,
            timeout=tools._SCAN_TIMEOUT,
            env=tools._scan_env(),
        )
        parsed = tools._parse_detect_secrets(proc.stdout)
        assert parsed["plugins"], f"scanner produced no verdicts: {proc.stderr[:200]}"
        verdicts.add(tuple(parsed["triggered"]))
    assert len(verdicts) == 1, f"scanner is not deterministic: saw {verdicts}"


# ── 2. a failed scan must not read as clean ───────────────────────────────


def test_a_failed_scan_is_not_a_clean_check() -> None:
    signals = extract_signals([_evidence({"scan_ok": False, "secrets_found": False})])
    assert signals.scan_failed is True
    assert signals.clean_checks == 0, "a scan that failed establishes nothing"


def test_a_successful_empty_scan_is_a_clean_check() -> None:
    """The ordinary case must keep working: looked, found nothing, that counts."""
    signals = extract_signals(
        [_evidence({"scan_ok": True, "secrets_found": False, "canary_hit": False})]
    )
    assert signals.scan_failed is False
    assert signals.clean_checks == 1


def test_a_failed_scan_caps_allow_confidence_below_the_floor() -> None:
    """Many clean checks must not out-vote one failed scan."""
    signals = Signals(clean_checks=5, scan_failed=True)
    assert compute_confidence(signals, "allow") < DEFAULT_MIN_CONFIDENCE


def test_a_failed_scan_sends_the_action_to_a_human() -> None:
    """End to end: the capped confidence must actually change the verdict."""
    signals = Signals(clean_checks=5, scan_failed=True)
    confidence = compute_confidence(signals, "allow")
    result = apply_verdict_floor("allow", signals, grounded=True, confidence=confidence)
    assert result.decision == "escalate"
    assert result.tightened is True


def test_a_failed_scan_does_not_fabricate_a_violation() -> None:
    """Fail closed, but stay honest: "could not look" is not "found a secret"."""
    signals = extract_signals([_evidence({"scan_ok": False, "secrets_found": False})])
    assert signals.secret_hit is False
    assert signals.canary_hit is False
    assert signals.violating is False


def test_a_real_hit_still_blocks_even_if_the_scan_is_flagged_failed() -> None:
    """A positive finding is a finding; the error flag must not discard it."""
    signals = extract_signals(
        [_evidence({"scan_ok": False, "secrets_found": True, "canary_hit": True})]
    )
    assert signals.secret_hit is True
    assert signals.canary_hit is True


def test_clean_scan_without_the_flag_is_still_counted() -> None:
    """Back-compat: evidence written before `scan_ok` existed must not regress.

    `scan_ok` is read with `is False`, so a missing key keeps the old meaning
    rather than silently marking every historical scan as failed.
    """
    signals = extract_signals([_evidence({"secrets_found": False, "canary_hit": False})])
    assert signals.scan_failed is False
    assert signals.clean_checks == 1


# ── 3. the flag is actually emitted by the tool ───────────────────────────


@pytest.mark.asyncio
async def test_scan_secrets_reports_scan_ok_false_when_the_scanner_fails(monkeypatch) -> None:
    """Wire-level check that the tool emits the flag the verifier depends on."""
    monkeypatch.setattr(
        tools,
        "_run_detect_secrets",
        lambda _text: {"error": "detect-secrets timed out", "plugins": {}, "triggered": []},
    )
    out = json.loads(await tools.scan_secrets.ainvoke({"text": "anything"}))
    assert out["scan_ok"] is False
    assert out["secrets_found"] is False


@pytest.mark.asyncio
async def test_scan_secrets_reports_scan_ok_true_on_a_working_scan(monkeypatch) -> None:
    monkeypatch.setattr(
        tools,
        "_run_detect_secrets",
        lambda _text: {"plugins": {"AWSKeyDetector": False}, "triggered": []},
    )
    out = json.loads(await tools.scan_secrets.ainvoke({"text": "anything"}))
    assert out["scan_ok"] is True


@pytest.mark.asyncio
async def test_a_policy_canary_is_found_without_relying_on_detect_secrets(monkeypatch) -> None:
    """The canary check must stand on its own when the scanner is unavailable.

    This is the property that makes the honeytoken trustworthy: it is an exact
    match against the policy, not an entropy heuristic.
    """
    monkeypatch.setattr(
        tools,
        "_run_detect_secrets",
        lambda _text: {"error": "unavailable", "plugins": {}, "triggered": []},
    )
    from policyguard.policy import policy_store

    canary = policy_store.canary_tokens()[0]
    out = json.loads(await tools.scan_secrets.ainvoke({"text": f"leaking {canary} now"}))
    assert out["canary_hit"] is True
    assert out["secrets_found"] is True
    assert out["canary_token"] == canary
