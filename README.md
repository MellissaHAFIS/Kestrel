# Kestrel (formerly PolicyGuard)

**A bodyguard for AI agents.** One poisoned tool can hijack a tool-using agent into leaking secrets while every action looks legitimate. Kestrel supervises what the agent _does_ across its tool chain (including the MCP tool supply chain), blocks known leaks deterministically, and escalates the uncertain cases to a human analyst.

Built at **Secure Horizons 2026** (x AWS). Protected agent: DevAssist.

> **Headline result (live on Claude Haiku 4.5 via Amazon Bedrock):** attack success **dropped from 100% to 14%**, while benign tasks still completed **71%** of the time.

---

## The five layers

Every agent action passes through, in order:

1. **Registry scan** – scans each MCP tool's description/schema at connection and quarantines poisoned tools.
2. **Hard invariants** – deterministic, non-overridable rules (canary match, secret patterns, sensitive paths, tool allow-list).
3. **ML gate** – a cheap risk score; clear-cut cases allow/block, the uncertain band goes up.
4. **Investigator** – an LLM agent (Claude on Bedrock) that gathers evidence and rules with a confidence floor.
5. **Human console** – an analyst reviews escalations, approves/blocks, and can kill the session; every decision is audit-logged.

**Core rule: the AI can only tighten a decision, never lift a hard-invariant block.**

---

## Quickstart

Python 3.11+ (built on 3.12). Run everything from the repo root.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -e '.[bench]'    # core + chart/Bedrock deps (matplotlib, boto3)
```

Everything below runs **fully offline** (MockLLM, no API key needed). All secrets in testing are FAKE canaries.

### 1. The two-act demo
```bash
python -m demo.run_no_guard   # Act 1: the attack succeeds, the canary leaks
python -m demo.run_guarded    # Act 2: same task behind Kestrel, the leak is blocked
```

### 2. The benchmark (with vs without the guard)
```bash
python -m eval.run_eval              # offline mock; writes results JSON + chart to eval/results/
```
Real numbers on the hackathon account (Claude on Bedrock, us-east-1): copy `.env.aws.example` to `.env.aws`, fill in the temporary AWS creds, then run `python -m eval.run_eval --mode bedrock`. In AWS CloudShell no `.env.aws` is needed (credentials are ambient).

### 3. The analyst console (web UI)
```bash
python -m chainlit run console/app.py
```
Commands in the console: `tools` (registry scan), `queue` (escalations), `approve <id>` / `block <id>`, `log`, `kill`.

To populate the console with real escalations: `python -m eval.seed_console` (add `--mode bedrock` for real Claude reasoning).

---

## Results

Real run, 28 chains / 56 steps, Claude Haiku 4.5 on Amazon Bedrock:

| Metric | Without guard | With Kestrel |
|---|---|---|
| Attack success | 100% (14/14) | **14.3%** (2/14) |
| Benign tasks completed | 100% (14/14) | 71.4% (10/14) |
| Harmful steps stopped | 0% (0/15) | 80% (12/15) |

Which layer stopped the attacks: invariants 7, Investigator 5 (3 block, 2 escalate), ML gate let 2 through. Charts and the full results JSON are in `eval/results/`.

**Honest scope:** the test set is small, custom, and scripted; the "without-guard" 100% holds by construction. We did not tune thresholds on it. Two obfuscated attacks (a truncated and a split canary) slip the ML gate; that is our documented next hardening step.

---

## For judges

- Start with **`docs/defence-sheet.md`** (one page: threat scenario, NIST CSF / ATT&CK / ATLAS / OWASP mapping, metrics, limits) and the demo video.
- The demo and console run offline with no credentials, so they reproduce immediately.
- Every reported number traces to `eval/results/20261010T225704Z-2c9a9aa-bedrock.json`.
- The Python package is named `policyguard` internally (the project was renamed to Kestrel late); imports and paths use `policyguard` by design.
- `ledger_1/` is a built-but-optional Avalanche audit-anchoring proof of concept, kept off the live demo path.

---

## Layout

```
src/policyguard/      types, policy, pipeline, registry, invariants, gate, audit, investigator/
demo/                 DevAssist agent, MCP servers (legit + poisoned), fixture repo, run_*.py
console/app.py        Chainlit analyst console
eval/                 benchmark: cases, run_eval, chart, results/
policy/devassist.yaml  allowed tools, sensitive paths, trusted hosts, canaries, thresholds
docs/                 defence sheet, demo run-sheet, architecture diagram
tests/                pytest suite (invariants, registry, investigator, audit chain, scan robustness)
ledger_1/             optional Avalanche audit-anchoring PoC
```

## Notes

- All demo secrets are deliberate FAKE canaries (e.g. `CANARY-PG-7f3a9c0d-FAKE-DO-NOT-USE`). Real `.env` / `.env.aws` files and `*.db` are git-ignored.
- Dependencies are pinned with `==` in `pyproject.toml`. The Investigator LLM is swappable (Bedrock / Anthropic / DeepSeek) via `.env`; `MOCK_LLM=1` runs fully offline.
- Tests: `python -m pytest -q`.
