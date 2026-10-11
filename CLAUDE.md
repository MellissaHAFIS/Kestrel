# CLAUDE.md — PolicyGuard (Secure Horizons hackathon)

## What this project is
PolicyGuard is a security layer that supervises another AI agent's tool use (including the MCP
tool supply chain) in real time, decides automatically when it can, and hands a grounded,
uncertainty-scored case to a human analyst when it cannot. The supervised agent is DevAssist.
The question it answers: "Is this agent doing exactly what we asked it to do, and nothing else,
and can a human prove and control it?"

Event: Secure Horizons (UTOPIA x KRYPTOSPHERE x ESSEC MetaLab), ESSEC Cergy, 36h.
Track 2 - Defenders Augmented. Jury: GitGuardian, ESSEC MetaLab, KPMG.

## Which document wins
The project pivoted twice. Later documents supersede earlier ones:

1. `docs/devlopment_plan.md`  — **v4, locked build scope. Wins on what to ship.**
2. `docs/ideas.md`            — v3, full architecture and evaluation design. Wins on design intent.
3. `docs/handoff/hackathon_project_plan.txt` — v2, **historical only**. Its demo (poisoned README),
   its variants (0/A/B) and its benchmarks (InjecAgent, R-Judge, AgentDojo) are NOT what we built.
4. `docs/handoff/CONTEXT_HANDOFF.md` — history of an earlier claude.ai conversation, also v2-era.

Where the repo and v4 disagree, the repo wins and is the thing to document: v4 specified
React + FastAPI, we shipped a **Chainlit** console. Live state is in `docs/defence-sheet.md`
(what we claim to the jury) and `docs/demo-runsheet.md` (what we run on camera).

## Architecture in one screen
Five layers, each with a visible job. `src/policyguard/pipeline.py` is the single seam:

```
MCP servers (legit + poisoned) -> tool descriptions/results = UNTRUSTED
User -> DevAssist (LangGraph) -> every tool call becomes an Action
   kill switch -> registry -> invariants -> ML gate -> Investigator -> human console
```

- **Registry** (`registry.py`): scans each tool description + schema at connection, pins a
  SHA-256, quarantines poisoned tools. Deterministic rules, no model.
- **Hard invariants** (`invariants.py`): canary match, secret patterns, sensitive paths, tool
  allow-list, unexpected parameters. A violation is a final BLOCK.
- **ML gate** (`gate.py`): cheap risk score. Currently the deterministic heuristic, not a
  classifier — the pretrained HF model is not wired up. Do not call it "deterministic" in the
  pitch; call it fixed-weight and reproducible.
- **Investigator** (`investigator/`): LangGraph agent, reason <-> tools loop, step budget 6,
  every claim must cite an evidence id, `verifier.py` checks it, abstains below the confidence
  floor. Read-only tools only.
- **Human console** (`console/app.py`): Chainlit. `queue`, `tools`, `block <id>`, `kill`.

Rule that matters: **the AI can only tighten a decision, never lift a hard-invariant block.**
Guarantee layers fail closed (`FAIL_CLOSED_ON_LAYER_ERROR = True`).

Policy = `policy/devassist.yaml` (mandate + every threshold). Operational knobs =
`config/policyguard.yaml`. Audit log = SQLite, async, exportable.

## The one demo use case
"DevAssist finishes the auth module" — an **MCP tool-poisoning** chain ending in secret
exfiltration. Not the poisoned README from v2. Do not build extra demos.

`python -m demo.run_no_guard` (Act 1: canary reaches `demo/leak_log.jsonl`) then
`python -m demo.run_guarded` (Act 2: each layer catches something different).
The chain is scripted (`SCRIPTED_PLAN`), not LLM-driven — say so; `run(scripted=False)` raises.

Act 2 must show one layer per step: gate-allow, Investigator-escalate, **registry-block**,
invariant-block, invariant-block. If step 3 reports an invariant instead of the registry, the
registry lookup regression is back (see `pipeline._registry_entry`).

## Stack
LangGraph + LangChain, MCP via `langchain-mcp-adapters` (`MultiServerMCPClient`; the newer
`langchain.mcp` needs `fastmcp` and is beta), FastMCP test servers, YAML policy, SQLite audit log,
Chainlit console, detect-secrets, matplotlib for the eval chart.
Models: **Claude Haiku 4.5 on Amazon Bedrock, us-east-1** (confirmed, this is what the event
provides). Temperature 0 for verdicts. Offline default is `MOCK_LLM=1`.
Cut and staying cut: LangSmith, DeepEval, Giskard, Bandit/Semgrep, fine-tuning, privilege report.
No vector DB, no embeddings, by design.

## Environment
Pins in `pyproject.toml` were resolved on Python 3.12. **`chainlit==2.12.0` requires `<3.14`**, so
on a Python-3.14-only box (e.g. current Fedora) `pip install -e '.[dev,bench]'` fails on chainlit.
Everything except the console works on 3.14; install `python3.12` for the console.
`.venv-pg/` is a working 3.14 env (no chainlit). Do not touch `.venv/` — it belongs to another
project. Bedrock runs need `.env.aws` (copy `.env.aws.example`, git-ignored).

## Evaluation
`python -m eval.run_eval` replays the 28 labelled chains in `eval/cases.py`.
Variants actually measured: **0 (no guard) vs H (full system)**. R/M/A/I were cut — mention them
narratively, never as measured numbers. `--mode mock` is offline MockLLM (and the chart says so),
`--mode bedrock` is the real run and refuses to silently fall back.
Metrics: attack success, benign utility, harmful steps stopped, per-layer attribution,
escalations per 100 steps, Wilson intervals.
`eval/splits.json` was written before tuning. **Never re-tune thresholds or edit the chains after
seeing results** — it voids the "no tuning" claim, which is a selling point.

Known state: **146 tests, stable green** (verified 5 consecutive runs with random ordering).

The 3 previously "flaky" tests in `tests/test_investigator.py` are fixed, and the cause recorded
here before was **wrong**: it was not fixture pollution through the `audit_log` singleton (each
test already gets its own `tmp_path` database, and the failures reproduced in full isolation).
The real cause was non-determinism in the secret scanner: detect-secrets' HexHighEntropyString
plugin selects its candidate substring by iterating a set, so per-process hash randomisation
flipped its verdict — 3 of 6 identical runs found the secret, 3 did not — which propagated to
block-vs-escalate. Fixed by pinning `PYTHONHASHSEED` in `investigator/tools.py::_scan_env`.
`test_paraphrased_leak_ends_in_grounded_block` was additionally asserting on a canary that the
policy does not declare, so it was really testing the entropy plugin; it now uses the policy's
canary.

Found alongside it: a failed scan (timeout, scanner missing) was counted as a *clean check*, and
clean checks raise allow-confidence — a fail-open. `scan_ok` now separates "looked and found
nothing" from "could not look"; the latter caps allow-confidence below the floor and escalates.
Both are locked by `tests/test_scan_robustness.py`. Lesson worth keeping: run a security check
several times in separate processes before believing a green suite.

## Non-negotiables
- Never cut: the Act 1 / Act 2 demo chain, hard invariants, registry quarantine, the Investigator
  producing a grounded escalation, the analyst Approve/Block, the audit log, the human-control slide.
- Cut order if late: privilege report > fine-tuning > bonus scenarios > second benchmark >
  extra telemetry > dashboard polish.
- The guard must be safe from the content it inspects: read-only tools, inspected content passed
  strictly as data, step budget, human escalation.

## Honesty rules
- All numbers shown to the jury must come from actual runs. Never use placeholder values.
  If the code changed since the last real run, the saved numbers are stale — say so or re-run.
- Do not claim "nobody has done this". Claim: "we focus on multi-step behavioral drift and tool
  poisoning in tool-using agents". Existing tools: Guardrails AI, NeMo Guardrails, LangSmith, and
  the acquired prompt-security vendors (Lakera -> Check Point ~$300M, Prompt Security ->
  SentinelOne ~$250M, both 2025).
- Verified and citable: OWASP Top 10 for Agentic Applications (Dec 2025, ASI01 goal hijack,
  ASI02 tool misuse, ASI03 identity abuse); EchoLeak = CVE-2025-32711, M365 Copilot, CVSS 9.3;
  MCPTox arxiv 2508.14925; R-Judge arxiv 2401.10019 (569 records, v3); InjecAgent (1,054 cases).
  Still unverified: pretrained injection-classifier details, DeepEval/Giskard features.
- Say out loud: the test set is small, custom and written by us; the chain is scripted so the
  without-guard numbers hold by construction; the registry rules are hand-written and will miss
  reworded poisoning; the ML gate is the weakest layer.
- If the Investigator does not beat the one-shot judge, report it honestly.

## Decisions already taken
- NO blockchain / Avalanche. A smart contract cannot intercept an off-chain HTTP call, logs
  hold sensitive data (and conflict with GDPR erasure), and on-chain writes add cost and latency.
  Do not reopen this unless the team asks. The only defensible idea: a hash-chained audit log
  (each row stores the hash of the previous one) so tampering is detectable; publishing a
  periodic digest on-chain is a roadmap mention only.
  **The hash chain IS now implemented** (`audit.py`: `compute_row_hash`, `verify_chain`, `verify`
  in the console, 19 tests in `tests/test_audit_chain.py`). It needed no change to the frozen
  contract: `prev_hash`/`row_hash` are storage columns, and an amendment reuses the existing
  `human_decision` event type. Note for anyone extending it: `update_decision` legitimately
  mutates an already-hashed row, so the amendment is appended as its own chained event and
  `verify_chain` separates "explained by an amendment" from "tampered". Do not try to re-sign a
  mutated row — that breaks the next row's link, and a test pins it. Two limits are also pinned
  by tests and must stay in the pitch: a writer can recompute the whole chain, and truncating the
  newest rows is undetectable without an external anchor.
- Frozen contract in `src/policyguard/types.py` (Action, Evidence, Verdict, AuditEntry,
  SourceLabel). Changing it needs all four owners to agree.
- `Action.tool_name` is fully qualified as `"server.tool"`. Anything reading it must handle both
  that and the bare name (see `compat.as_legacy_action`, `pipeline._registry_entry`).
- Architecture diagram (draw.io) and a sales video already exist: see CONTEXT_HANDOFF.md. Both are
  v2-era — the video says "poisoned README" and "evaluated on public benchmarks"; neither is true
  of what we shipped. Fix or drop those claims before showing it.

## Open decision
Quarantine semantics. A quarantined tool is unavailable to everyone, so the 7 benign chains that
legitimately call `search_docs` no longer complete (benign utility 71% -> 36% offline). Correct per
`ideas.md` §4.1, bad for the headline. Three options written up in `docs/defence-sheet.md` §5.
Team's call. Do not resolve it by editing the chains after seeing the results.

## How to work with me
- Talk to me in French. Code, comments, identifiers, commit messages and UI strings in English
  (change this line if the team prefers otherwise).
- Be direct and honest, including when my idea is weak. Explain trade-offs briefly.
- Before big changes, state the plan in a few lines. Prefer the smallest thing that works:
  the hackathon is time-boxed.
- Check what already exists in the repo before proposing to build something. The repo is further
  along than the planning documents suggest; read the code, not just the plans.
