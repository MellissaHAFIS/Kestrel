"""Tests for the hard-invariants layer.

Run from the repo root: ``pytest tests -q``.
"""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from policyguard.invariants import check_invariants
from policyguard.policy import load_policy
from policyguard.types import Action, Source, Verdict

CANARY = "CANARY-7f3a9c21-DO-NOT-USE"


@pytest.fixture(scope="module")
def policy():
    return load_policy("policy/devassist.yaml")


def make_action(server: str, tool: str, args: dict, *, trusted_source: bool = True) -> Action:
    src = Source.USER if trusted_source else Source.MCP_DESCRIPTION
    return Action(
        session_id="s1",
        tool=tool,
        server=server,
        args=args,
        sources=[src],
        history_ref=None,
        ts=0.0,
    )


def kinds(decision) -> set[str]:
    return {e.kind for e in decision.evidence}


# ---------------------------------------------------------------------------
# 1. Benign actions -> None
# ---------------------------------------------------------------------------
def test_benign_file_read(policy):
    a = make_action("legit_server", "file_read", {"path": "src/auth/login.py"})
    assert check_invariants(a, policy) is None


def test_benign_open_pr(policy):
    a = make_action(
        "legit_server",
        "open_pr",
        {"title": "Fix login bug", "body": "Handles empty passwords.", "branch": "fix/login"},
    )
    assert check_invariants(a, policy) is None


def test_benign_search(policy):
    a = make_action("docs_helper", "search", {"query": "how to use oauth"})
    assert check_invariants(a, policy) is None


# ---------------------------------------------------------------------------
# 2. Canary: untrusted blocks, trusted not blocked by canary rule
# ---------------------------------------------------------------------------
def test_canary_untrusted_blocks(policy):
    a = make_action("docs_helper", "search", {"query": CANARY})
    d = check_invariants(a, policy)
    assert d is not None and d.verdict is Verdict.BLOCK
    assert "canary_match" in kinds(d)


def test_canary_trusted_not_blocked_by_canary_rule(policy):
    # Sent to a trusted server via an allowed tool/param: no canary block.
    a = make_action("legit_server", "file_read", {"path": CANARY})
    d = check_invariants(a, policy)
    if d is not None:
        assert "canary_match" not in kinds(d)


# ---------------------------------------------------------------------------
# 3. Canary obfuscations still block
# ---------------------------------------------------------------------------
def test_canary_lowercase(policy):
    a = make_action("docs_helper", "search", {"query": CANARY.lower()})
    assert "canary_match" in kinds(check_invariants(a, policy))


def test_canary_spaced_out(policy):
    spaced = " ".join(CANARY)
    a = make_action("docs_helper", "search", {"query": spaced})
    assert "canary_match" in kinds(check_invariants(a, policy))


def test_canary_base64(policy):
    enc = base64.b64encode(CANARY.encode()).decode()
    a = make_action("docs_helper", "search", {"query": enc})
    assert "canary_match" in kinds(check_invariants(a, policy))


def test_canary_urlencoded(policy):
    enc = urllib.parse.quote(CANARY)
    a = make_action("docs_helper", "search", {"query": enc})
    assert "canary_match" in kinds(check_invariants(a, policy))


def test_canary_nested_in_list_in_dict(policy):
    a = make_action(
        "docs_helper",
        "search",
        {"query": {"inner": ["safe", ["also safe", CANARY]]}},
    )
    assert "canary_match" in kinds(check_invariants(a, policy))


# ---------------------------------------------------------------------------
# 4. Secrets: AWS key, private-key header, password block.
#    The secret value must never appear in any Evidence.detail.
# ---------------------------------------------------------------------------
def test_secret_aws_key(policy):
    secret = "AKIAIOSFODNN7EXAMPLE"
    a = make_action("docs_helper", "search", {"query": f"use {secret} here"})
    d = check_invariants(a, policy)
    assert "secret_pattern" in kinds(d)
    assert all(secret not in e.detail for e in d.evidence)


def test_secret_private_key(policy):
    secret = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n-----END RSA PRIVATE KEY-----"
    a = make_action("docs_helper", "save_note", {"title": "k", "text": secret})
    d = check_invariants(a, policy)
    assert "secret_pattern" in kinds(d)
    assert all("PRIVATE KEY" not in e.detail for e in d.evidence)


def test_secret_password_assignment(policy):
    secret = "password = hunter2hunter2hunter2"
    a = make_action("docs_helper", "search", {"query": secret})
    d = check_invariants(a, policy)
    assert "secret_pattern" in kinds(d)
    assert all("hunter2" not in e.detail for e in d.evidence)


# ---------------------------------------------------------------------------
# 5. Sensitive paths block even on the trusted server
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "./.env",
        "app/.env.production",
        "keys/server.pem",
        "/home/dev/.ssh/id_rsa",
        "repo/secrets/db.txt",
        "src/../.env",
        "config/credentials.json",
    ],
)
def test_sensitive_paths_block(policy, path):
    a = make_action("legit_server", "file_read", {"path": path})
    d = check_invariants(a, policy)
    assert d is not None and d.verdict is Verdict.BLOCK
    assert "sensitive_path" in kinds(d)


# ---------------------------------------------------------------------------
# 6. Unknown tool / extra param / suspicious param / unknown server
# ---------------------------------------------------------------------------
def test_unknown_tool_blocks(policy):
    a = make_action("legit_server", "delete_everything", {"path": "x"})
    d = check_invariants(a, policy)
    assert "tool_not_allowed" in kinds(d)


def test_extra_param_blocks(policy):
    a = make_action("docs_helper", "search", {"query": "auth", "context": "stuff"})
    d = check_invariants(a, policy)
    assert "unexpected_param" in kinds(d)


def test_suspicious_param_untrusted_no_schema(policy):
    # A tool with no schema on an untrusted server. Unknown tool also trips the
    # allow-list, but the suspicious-param rule must fire too.
    a = make_action("unknown_server", "freeform", {"payload": "data"})
    d = check_invariants(a, policy)
    assert "suspicious_param" in kinds(d)


def test_unknown_server_is_untrusted(policy):
    a = make_action("unknown_server", "search", {"query": CANARY})
    d = check_invariants(a, policy)
    # Treated as untrusted -> canary rule applies.
    assert "canary_match" in kinds(d)


# ---------------------------------------------------------------------------
# 7. Demo chain: canary + unexpected param together
# ---------------------------------------------------------------------------
def test_demo_chain_canary_and_unexpected_param(policy):
    a = make_action(
        "docs_helper",
        "search",
        {"query": "auth", "context": f"API_KEY={CANARY}"},
    )
    d = check_invariants(a, policy)
    assert d is not None and d.verdict is Verdict.BLOCK
    assert "canary_match" in kinds(d)
    assert "unexpected_param" in kinds(d)


# ---------------------------------------------------------------------------
# 8. Paraphrased leak with no canary / secret / bad param -> None
# ---------------------------------------------------------------------------
def test_paraphrased_leak_not_caught(policy):
    a = make_action(
        "docs_helper",
        "search",
        {"query": "the signing credential begins with seven f three a nine c"},
    )
    assert check_invariants(a, policy) is None


# ---------------------------------------------------------------------------
# 9. Determinism
# ---------------------------------------------------------------------------
def test_determinism(policy):
    a = make_action(
        "docs_helper",
        "search",
        {"query": "auth", "context": f"leak {CANARY}"},
    )
    d1 = check_invariants(a, policy)
    d2 = check_invariants(a, policy)
    assert d1 == d2
    assert d1.to_dict() == d2.to_dict()
