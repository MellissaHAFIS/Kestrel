# PolicyGuard — Locked build scope (v4, deadline-driven)

**Deadline: working demo by tomorrow 12:00.** This document is the source of truth for the build.
It supersedes `ideas.md` wherever they conflict — `ideas.md` is the full research-grade vision,
this file is what we are actually shipping in the time left.

## Decisions locked (no longer open questions)

1. **Stack:** React + Vite + TypeScript frontend (Tailwind for speed/polish) talking to a Python
   FastAPI backend over REST + WebSocket (live incident feed). Chosen over Streamlit because the
   analyst console *is* the "operational value" (20%) and "pitch & demo" (15%) evidence — a crafted
   live feed and incident cards read better live than a Streamlit script.
2. **MCP:** build two local FastMCP servers (`legit_server`, a `docs_helper` server carrying Tool A =
   obviously poisoned, Tool B = subtly poisoned). Check installed `langchain`/`langchain-mcp-adapters`
   version first: if LangChain ships the new `langchain.mcp.MCPAdapter`, use that; otherwise fall back
   to the standalone `langchain-mcp-adapters` package. Don't guess — `pip show` first.
3. **ML gate:** no fine-tuning, no training split. Try a pretrained HF injection classifier
   (`transformers` pipeline, e.g. a Prompt-Guard-family model) as the scorer; wrap it in a try/except
   that falls back to a deterministic keyword/entropy heuristic if the model fails to load or is too
   slow — the live demo must never depend on a model download succeeding on event wifi.
4. **Investigator:** real LLM agent loop (reason → act → observe), capped at 6 tool-call tools:
   `get_session_history`, `get_provenance`, `scan_secrets` (use `detect-secrets`, not `ggshield`, to
   avoid an external binary dependency), `check_destination`, `check_canary`, `inspect_tool`. Drop
   `read_policy` and `classify_path` as separate tools — fold their logic into the invariants/gate
   instead of giving the agent more tool surface to debug.
5. **LLM provider:** read from env vars, support OpenAI and Anthropic behind a single interface
   (`LLM_PROVIDER=openai|anthropic`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`). Default to whichever key
   is present. Confirm with organizers/mentors on-site which credits are provided and set `.env`
   accordingly — don't block the build on this, the interface just needs to be swappable.
6. **Evaluation — drastically cut:** no InjecAgent / AgentDojo / R-Judge / MCPTox integration (too
   much integration risk for the time left). Build one custom scripted test set instead:
   ~15–20 scenarios (obvious tool poisoning, subtle tool poisoning, paraphrased/obfuscated injection,
   multi-step read-secret-then-leak chains, and benign control tasks). Run only two variants end to
   end and show them live: **0 (no guard)** vs **H (full system)**. Add **M (gate only)** as a third
   column only if time remains after H is solid — do not attempt R/A/I as separate measured variants,
   mention them narratively in the pitch as "we also isolated the gate-only and rules-only cases
   internally" if asked, but don't spend build time wiring them up.
7. **Cut entirely for this deadline:** LangSmith tracing, DeepEval/Giskard, Bandit/Semgrep bonus scan,
   fine-tuning, the privilege-report bonus, Avalanche/blockchain anchoring. These stay in `ideas.md`
   as future work, mentioned verbally in the pitch if asked, not built.
8. **Audit log:** SQLite with the schema from `ideas.md` section 7, plus a JSON export endpoint. No
   external SIEM integration.
9. **No worktree / branch isolation needed** — this is the only active work on the repo right now;
   build directly in a feature branch off `main` and merge when the demo is stable, to keep `main`
   always in a known-good state in case something breaks close to the deadline.

## What "done" looks like by 12:00

- `backend/` (FastAPI + LangGraph): DevAssist agent, two MCP servers, registry scanner, hard
  invariants, ML gate (with fallback), Investigator loop, policy YAML loader, SQLite audit log,
  WebSocket live feed, REST endpoints for incident queue / approve / block / kill switch / registry
  view / audit export / eval run + results.
- `frontend/` (React + Vite + TS): incident queue, incident card (evidence list, provenance, gate
  score, Investigator confidence, Approve/Block), tool registry view (trusted/quarantined + scan
  reason), live feed panel, session kill switch, results panel (ASR with/without guard, calibration
  if time allows).
- A scripted end-to-end demo: Act 1 (no guard, secret leaks, canary fires) → Act 2 (guard on, each
  layer visibly catches something, analyst clicks Block) → Act 3 (audit trail + results numbers).
- `README.md` updated with setup/run instructions (backend venv + requirements, frontend
  npm install/dev, env vars needed, how to run the demo script).

## Cut order if still behind at any checkpoint

Gate-only M column → paraphrased/obfuscation scenarios beyond 2–3 examples → calibration plot →
tool registry hash-pinning UI polish → kill switch → anything in section 7's "cut entirely" list
(must stay cut, don't resurrect under time pressure).

**Never cut:** the Act 1/Act 2 demo chain itself, hard invariants, registry scan quarantining Tool A,
the Investigator producing at least one grounded escalation, the analyst Approve/Block action, the
audit log, and a frontend that runs without crashing.
