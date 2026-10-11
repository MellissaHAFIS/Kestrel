"""Shared pytest fixtures.

The most important one is `_isolated_llm_env`: it strips every LLM-related
environment variable before each test and prevents `.env` from being loaded,
so test behavior never depends on whatever provider or key a developer
happens to have configured locally. Without this, `test_config_defaults_*`
passed or failed depending on the contents of a file that is explicitly
gitignored and different on every machine.
"""

from __future__ import annotations

import pytest

_ENV_VARS = (
    "LLM_PROVIDER",
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
    "MOCK_LLM",
    "POLICYGUARD_POLICY",
    "POLICYGUARD_CONFIG",
)


@pytest.fixture(autouse=True)
def _isolated_llm_env(monkeypatch):
    """Every test starts with a clean slate: no .env, no inherited provider env."""
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    # Pretend .env has already been "loaded" (as a no-op) so no test can
    # accidentally pull in the developer's real secrets from disk.
    monkeypatch.setattr("policyguard.config._dotenv_loaded", True)
    yield
