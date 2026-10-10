# secure-horizons-hackathon
AI-powered cybersecurity solution built at Secure Horizons 2026. Exploring intelligent, proactive, and secure AI systems.

## PolicyGuard

PolicyGuard supervises an AI agent's tool use (including the MCP tool supply chain) and hands a grounded, uncertainty-scored case to a human analyst when it cannot decide. The protected agent is DevAssist. Architecture: `docs/ideas.md`. This repo layout supersedes `docs/devlopment_plan.md` (Python-only stack, Chainlit console).

Status: **skeleton**. Every module is a stub with the final signatures so four people can build in parallel. Search for `TODO(person1..4)`.

## Quickstart

```bash
python3.12 -m venv .venv          # Python >= 3.11
source .venv/bin/activate
pip install -e '.[dev]'           # add '.[ml]' later for torch/transformers/scikit-learn
cp .env.example .env              # MOCK_LLM=1 runs fully offline

chainlit run console/app.py       # analyst console (fake incidents for now)

python -m demo.run_no_guard       # Act 1: the attack works, see demo/leak_log.jsonl
python -m demo.run_guarded        # Act 2: same task behind PolicyGuard
python -m eval.run_eval              # benchmark: with vs without the guard (see Benchmark below)
```

Run the demo commands from the repo root.

## Benchmark

`python -m eval.run_eval` replays the labelled attack and benign chains in `eval/cases.py` through the guard and prints attack success and benign task completion with and without it. It writes `eval/results/<run>.json` and the two-panel chart (`.png`) next to it. Re-draw a chart from a stored run with `python -m eval.chart eval/results/<run>.json --out chart.png`.

- Default is offline: the Investigator runs on MockLLM and the chart says so. `--mode real` uses the LLM from `.env` and sends the chains (fake secrets only) to that provider.
- Real numbers on the hackathon account: `python -m eval.run_eval --mode bedrock`. Put the temporary AWS creds from the Workshop Studio event page into `.env.aws` (copy `.env.aws.example`; it is git-ignored). This calls Claude Haiku 4.5 on Amazon Bedrock in us-east-1 and paces calls to about 1/second.
- `pip install -e '.[bench]'` installs the chart dependency (matplotlib).
- The set is small, custom and scripted, and was written by the team that built the guard. Say that when you show the numbers. The without-guard bars hold by construction.
- Edit chains in `eval/cases.py`, then run `python -m eval.cases` to refresh `eval/data/chains.jsonl`.

## CONTRACT (frozen)

Defined in `src/policyguard/types.py`. Changing it needs all four owners to agree.

- `Source`: `USER`, `INTERNAL_REPO` (trusted); `MCP_DESCRIPTION`, `TOOL_RESULT` (untrusted). `Source.is_trusted`.
- `Verdict`: `ALLOW`, `BLOCK`, `ESCALATE`, `QUARANTINE`.
- `Action(session_id, tool, server, args, sources[], history_ref, ts)`
- `Evidence(id, tool, observation, source, ts)`
- `Decision(verdict, layer, score, confidence, evidence_ids, reason)`
- Integration seam: `policyguard.pipeline.review(action: Action) -> Decision` (the stub returns ALLOW).
- All types have `to_dict()` / `from_dict()` and are JSON-serializable.

Rule: the AI can only tighten, never lift a hard-invariant block.

## OWNERSHIP

| Person | Owns | First deliverable |
|---|---|---|
| 1. Demo env | `demo/`, `middleware.py`, `provenance.py` | Attack works with no guard; every call produces an `Action` |
| 2. Guard core | `registry.py`, `invariants.py`, `gate.py`, `pipeline.py`, `policy.py`, `policy/` | Tool A quarantined; canary-in-args blocked |
| 3. Investigator | `investigator/*` | Loop resolves the paraphrased-leak case with a grounded report |
| 4. Audit, console, eval, slides | `audit.py`, `console/`, `eval/`, slides | Live feed showing decisions; then the eval harness |

Person 1 also writes the tool-description and chain datasets (`eval/data/`) once the attack works.

## Demo design rule

Each layer must have a visible job, otherwise the architecture is invisible to the jury:

- Tool A (obviously poisoned) is caught by the **registry** scan.
- Tool B's exact leak (canary in args to an untrusted server) is caught by the **invariant**.
- A paraphrased partial leak goes to the **Investigator**, which escalates with a grounded report.
- The analyst clicks Block in the console; the decision is logged.

## Layout

```
policy/devassist.yaml        allowed tools, sensitive paths, trusted hosts, thresholds
src/policyguard/             types, policy, middleware, pipeline, registry, provenance,
                             invariants, gate, audit, investigator/
demo/                        devassist.py, mcp_servers/, fixture_repo/, run_*.py
console/app.py               Chainlit console
eval/                        splits.json, data/, variants.py, metrics.py, run_eval.py
```

## Notes

- `demo/fixture_repo/.env` and `config/settings.yaml` hold deliberately FAKE secrets and a fake canary (`CANARY-PG-7f3a9c0d-FAKE-DO-NOT-USE`). They are tracked on purpose. Real `.env` files are git-ignored.
- `demo/leak_log.jsonl` (what the poisoned server received) and `*.db` are git-ignored.
- `eval/splits.json` is written before tuning. Split by server/template, not random rows. Tune thresholds on validation only, then run test once.
- Dependencies are pinned with `==` in `pyproject.toml`. MCP tools are loaded with `langchain-mcp-adapters` (see the comment in `demo/devassist.py`).
