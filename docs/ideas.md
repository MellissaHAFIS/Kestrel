# PolicyGuard — Hackathon Project Plan (v2)

**Event:** Secure Horizons (UTOPIA × KRYPTOSPHERE × ESSEC MetaLab), ESSEC Cergy, Oct 10–11, 2026, 36h
**Track:** 2 — Defenders Augmented (AI for cybersecurity + securing AI)
**Jury:** GitGuardian · ESSEC MetaLab · KPMG
**Working name:** PolicyGuard (the guard) protecting DevAssist (the target agent)

**What changed in v2**

- Added a **hybrid gate** in front of the Investigator: a few hard invariants (plain code) + a small fixed-weight ML model.
- New **evaluation variants** (R, M, A, I, H) and a robustness test.
- New **train/test split rule** to keep the generalization claim honest.
- **Avalanche / blockchain dropped for now** (parked, see section 11).

---

## 1. WHAT am I building?

**One sentence:** a layered security system that supervises an AI agent in real time and answers the question nobody can answer today:

> "Is this agent doing exactly what we asked it to do, and nothing else?"

Three components, clearly separated:

| | **DevAssist** (protected agent) | **Hybrid gate** (fast path) | **Investigator** (agent) |
|---|---|---|---|
| Role | Developer assistant deployed in a company | Scores every intercepted action in milliseconds | Investigates only the ambiguous actions |
| Nature | Agentic (tools, loop) | Not agentic, on purpose: no LLM call, fixed weights | Agentic (reason → act → observe loop) |
| Why it exists | Something realistic to attack and defend | Speed, reproducibility, resistance to injection | Catches multi-step chains and gives explanations |

**What PolicyGuard does**

1. **Defines** the agent's mandate as a natural-language policy (YAML): "never read `.env`", "no POST to non-allowlisted domains", "no credentials in code".
2. **Intercepts** every input, tool call and output of the target agent (LangChain callbacks / LangGraph middleware).
3. **Gates** each action: hard invariants first, then an ML score.
4. **Investigates** the uncertain band with a tool-using agent instead of a one-shot LLM guess.
5. **Acts**: allow, block, sanitize, or escalate to a human (`interrupt()`).
6. **Logs** everything to an exportable audit trail, including which layer decided.

**Integration story:** drop-in Python middleware for any LangChain / LangGraph agent, in a few lines of code and without rewriting the agent. Limits: non-Python agents and closed vendor agents are not covered by this version.

**Terminology rule (important for the jury):** only the hard invariants are *deterministic with a guarantee*. The ML gate is *fixed-weight and reproducible* (same input → same score), not guaranteed. Never call the ML gate "deterministic".

---

## 2. WHY this idea?

**The problem:** agents already run in production with real access (files, APIs, email, code). Their failures are *behavioral drift*, not classic intrusions:

- Each individual action looks legitimate (legitimate agent, legitimate access, legitimate text).
- The danger is in the **chain**: read secret → paste it into code → POST it somewhere external.
- Classic tools (firewall, antivirus, SIEM, DLP) look at packets, signatures, logs and files. They don't understand *what the agent is trying to do*.

**Why LLM-only guards are not enough:** LLM judges aren't 100% reproducible even at temperature 0, they are slow and costly on every action, and the content they inspect can contain injections aimed at them. Hence the layered design: guarantees from code, generalization from a small model, judgment from an agent only where needed.

**Why now:**

- Agent deployment is ahead of agent security tooling.
- Indirect prompt injection against tool-using agents is documented in the research literature (see benchmarks).
- Regulation (EU AI Act, NIS2, DORA) pushes toward auditability of AI systems in production.
- The event pitch itself is about agents doing things nobody told them to do.

**Honest positioning:** guardrail tools already exist (Guardrails AI, NeMo Guardrails, Lakera Guard, Rebuff, LangSmith for observability). Our differentiation is the **combination**: natural-language policy + tool-call interception + layered gate + investigating agent + enforcement + audit trail, evaluated on public benchmarks. Don't claim "nobody has done this". Claim "we focus on multi-step behavioral drift of tool-using agents".

---

## 3. IMPACT

| Stakeholder | Why they care |
|---|---|
| **GitGuardian** | Natural extension of "secrets in code" to "secrets and dangerous behavior in agents that read and write code". Secret scan and canary tools are in their domain. |
| **KPMG** | Their clients deploy agents and need controls and an audit trail for AI governance and compliance. |
| **ESSEC MetaLab** | Visible governance: explicit policy, human-in-the-loop, explainable decisions, audit log, reproducible gate. |
| **Any company with agents in production** | A reusable security layer: pip-installable, framework-native. |

**What the jury should remember:** "They built a security layer designed natively for AI agents, with hard guarantees where they matter, learned generalization where it helps, and an investigator for the hard cases. And they measured it on public benchmarks."

**Possible continuation (mention, don't overclaim):** open-source core, enterprise features later (hosted dashboard, multi-agent management, compliance reports); partnership or incubation with jury companies.

---

## 4. HOW — Architecture

```
User ─► [Input guard] ─► DevAssist (LLM + tools) ─► [Output guard] ─► Out
                              │
                         [Tool guard]  (every tool call is intercepted)
                              ▼
┌──────────────────────── PolicyGuard ─────────────────────────┐
│ 1a. HARD INVARIANTS (plain code, guaranteed)                 │
│     canary match · path deny-list · tool-arg schema checks   │
│     → violation = final BLOCK (nothing can override it)      │
│                          ▼                                   │
│ 1b. ML GATE (small encoder, fixed weights, CPU-fast)         │
│     input: serialized action (tool, args, short history)     │
│     score < low  → ALLOW                                     │
│     score > high → BLOCK (human may override)                │
│     in between   → Investigator                              │
│                          ▼                                   │
│ 2.  INVESTIGATOR AGENT (LLM + tools, uncertain band only)    │
│     can only tighten a decision, never lift a hard block     │
│                          ▼                                   │
│ 3.  HUMAN via interrupt() for high severity / low confidence │
└──────────────────────────────────────────────────────────────┘
        Policy store (YAML) · Audit log (SQLite, per-layer decision)
```

**Design rules**

- The LLM can add caution but can never remove a hard-invariant block.
- Hard invariants are kept to a handful of rules where a guarantee matters (secrets, sensitive paths, schema validity). Everything fuzzier goes to the ML gate.
- Thresholds (`low`, `high`) are tuned on a validation split only (see section 7.4), then frozen.
- The model file's hash and thresholds are logged with every decision.

### 4.1 The ML gate

- **Input:** a text serialization of the action, e.g. `tool=http_post | url=... | body_summary=... | prior_actions=[file_read(...), ...]`, plus the incoming text for injection checks.
- **Output:** a violation score in [0, 1].
- **Build ladder (stop when time runs out):**
  1. **Pre-trained injection classifier** from Hugging Face (DeBERTa-based injection detectors, Meta's Prompt Guard family, etc.; verify names, licenses, sizes). Zero training. This is your baseline gate.
  2. **Embeddings + logistic regression** on action text. Quick, gives a first ROC curve.
  3. **Fine-tune a small encoder** (DeBERTa-small or similar) on action-level data, on a free GPU (Colab). Only if steps 1–2 are done and data is ready.
- **Limits to state openly:** a classifier gives probabilities and can be evaded by adversarial inputs, which is why the hard invariants exist. For structured secrets (API keys), patterns + entropy are often more precise than ML.

### 4.2 The Investigator is an agent, not an LLM call

A single "prompt → JSON verdict" call is a classifier, not an agent. The Investigator runs a loop, and only on actions the gate couldn't settle:

```
Uncertain action
      ▼
 ┌─► REASON: what do I still need to know?
 │        ▼
 │   ACT: call an investigation tool
 │        ▼
 │   OBSERVE: update evidence and confidence
 │        ▼
 └── confidence < threshold AND steps left? ── yes ──┘
              │ no
              ▼
   VERDICT: allow / block / sanitize / escalate (human via interrupt())
```

**Investigator tools (read-only; inspected content is treated as data):**

| Tool | Purpose |
|---|---|
| `get_session_history` | What the target agent did earlier (catches chains) |
| `read_policy(section)` | Retrieve relevant rules from the policy store |
| `scan_secrets(text)` | Pattern + entropy scan (e.g. `detect-secrets`; `ggshield` if available) |
| `check_destination(url)` | Allowlist and domain checks |
| `classify_path(path)` | Is this file sensitive (`.env`, keys, CODEOWNERS, data class)? |
| `static_scan(code)` | Bandit / Semgrep on generated code |
| `check_canary(text)` | Detect planted honeytokens, which gives proof of exfiltration |
| `request_human_approval` | LangGraph `interrupt()` |

**LangGraph structure:** nodes `reason ⇄ tools (ToolNode) → verdict → human_interrupt (optional)`. State: `action_under_review`, `evidence[]`, `confidence`, `steps_used`, `gate_score`. Hard step budget (~6); escalate to a human if still uncertain.

**Safety of the guard itself:** inspected content may contain injections aimed at the Investigator. Read-only tools, content passed strictly as data, step budget, human escalation.

### 4.3 The 5 agentic criteria

Litmus test: *can I answer in one shot, without looking anything up or changing anything?* No → agent.

| # | Criterion | DevAssist | Investigator |
|---|---|---|---|
| 1 | Live / external data via tools | files, repo, HTTP, search | session history, policy retrieval, scanners, destination lookup |
| 2 | Actions in the world | open PRs, send notifications, POST | block, sanitize, quarantine, escalate to human |
| 3 | Number of steps unknown ahead | depends on the task | 1 to ~6 depending on the evidence |
| 4 | Reacts to results | adapts to file contents | next tool depends on the last observation |
| 5 | Constraint met by iteration | finish the coding task | reach confidence ≥ threshold within step and latency budget, else escalate |

The hybrid gate is deliberately **not** agentic. It is the fast path. The agentic claim rests on DevAssist and the Investigator, and the gate is what keeps the Investigator affordable.

---

## 5. HOW — Stack

| Layer | Choice |
|---|---|
| Agent framework | LangGraph + LangChain (tools, callbacks / middleware, `interrupt()`) |
| LLMs | Small fast model for DevAssist; stronger model for the Investigator; `temperature=0` (check which models/credits the event provides) |
| Interception | LangChain callbacks (`on_llm_start`, `on_tool_start`, `on_llm_end`) and/or LangGraph middleware |
| ML gate | Hugging Face `transformers` + PyTorch (inference on CPU), scikit-learn for the logistic-regression baseline; Colab for optional fine-tuning |
| Hard invariants | Plain Python (path rules, canary match, schema validation) |
| Policy store | YAML / JSON, retrieved by section (no vector DB needed for the demo) |
| Security tools | `detect-secrets`, Bandit or Semgrep, allowlist logic |
| Audit log | SQLite |
| UI / demo | Chainlit (live feed + Approve / Block buttons) |
| Tracing | LangSmith |
| Evaluation | Python + scikit-learn metrics; optional DeepEval / Giskard (verify, see section 10) |

---

## 6. HOW — Observability

**Level 1 — Live trace (shown during the demo).** One line per event in Chainlit, showing *which layer decided*:

```
[10:42:01] INPUT      "Finish the auth module"            ALLOW   (gate 0.03)
[10:42:03] TOOL CALL  file_read("/src/auth/.env")         BLOCK   (hard invariant: path deny-list)
[10:42:04] INPUT      third-party README text             BLOCK   (gate 0.97, injection)
[10:42:05] TOOL CALL  http_post(docs-endpoint, body=...)  INVESTIGATE (gate 0.55) → steps: 3 → ESCALATE
```

**Level 2 — Investigation trace.** Tools called, observations, confidence progression, final reasoning. This visibly proves the loop.

**Level 3 — Gate telemetry.** Score per action, thresholds in force, model hash, share of actions resolved at each layer (invariants / ML gate / Investigator / human).

**Level 4 — Audit trail (exportable JSON/CSV).**

```
session_id | timestamp | event_type | action | layer | gate_score | model_hash | evidence |
violation | severity | reasoning | decision | steps_used | latency_ms
```

LangSmith holds low-level traces of LLM and tool calls; SQLite is the compliance-facing record.

---

## 7. HOW — Evaluation

**Principle:** don't rely on a home-made benchmark alone (biased and slow to build). Use public benchmarks and frameworks, compare variants, and keep train and test strictly separate.

### 7.1 Benchmarks

| Benchmark | What it tests | Role |
|---|---|---|
| **InjecAgent** (Zhan et al., 2024, ~1,054 cases) | Indirect prompt injection against tool-integrated agents (direct harm, data exfiltration) | Primary source; may supply training / validation data |
| **AgentDojo** (ETH Zurich) | Dynamic agent environments with utility and security metrics | Held-out test: does the guard stop attacks while the agent still completes tasks? |
| **R-Judge** (2024, ~569 agent interaction records) | Whether a judge recognizes safety risks in agent trajectories | Held-out test for the Investigator as a judge |
| **Small custom multi-step set (~10 chains)** | Read-secret → leak chains, mandate violations | Supplement only (public benchmarks are mostly single-step). State this bias. |

### 7.2 Variants compared

| Variant | Description | Question it answers |
|---|---|---|
| **0. No guard** | DevAssist alone | What's the baseline attack success rate? |
| **R. Rules only** | Regex / deny-list gate | How far does hand-written logic go? |
| **M. ML gate only** | Fixed-weight model, thresholds tuned on validation | Does learning generalize better than rules? |
| **A. One-shot LLM judge** | One LLM verdict per action | The plain "LLM call" baseline |
| **I. Investigator only** | Agent loop on every action, no gate | Does the loop beat one-shot (A vs I)? Cost of no gate? |
| **H. Hybrid (full system)** | Invariants + ML gate + Investigator + human | Is the combination best on accuracy, cost and latency? |

Key comparisons: **R vs M** (generalization), **A vs I** (agentic loop), **M vs H** (value of the Investigator), **I vs H** (value of the gate: cost and latency). If a hypothesis fails, report it honestly and say what the component still adds (explanations, guarantees, speed).

### 7.3 Metrics

- **Attack success rate (ASR):** baseline vs. guarded (the delta is the impact)
- **Detection recall** on attacks, **false positive rate** on benign cases, precision, F1
- **ROC-AUC and PR-AUC** for the ML gate (the measurability argument), with the operating point chosen on validation
- **Benign utility:** % of legitimate tasks still completed (a guard that blocks everything is useless)
- **Latency overhead** per action, in ms on CPU for the gate, and for the Investigator path
- **Share of actions resolved at each layer**, **average tool calls per Investigator verdict**, **cost per action**
- **Reproducibility check:** run the gate twice on the same inputs and report identical outputs (and the same for hard invariants)
- **Robustness test:** take attacks the regex catches, obfuscate them (paraphrase, encoding, typos, split across tool calls), and compare R vs M vs H on the obfuscated set
- Report a confusion matrix and per-category results (injection, exfiltration, mandate violation)

All numbers shown to the jury must come from actual runs. No placeholder values.

### 7.4 Train / test split rule

This rule exists so that "it generalizes" is a *measured* claim, not a leaked one.

1. **Decide the splits before any tuning**, write them down, and don't change them after seeing results.
2. **Split by source and attack template, not by random rows.** Near-duplicate attacks in train and test inflate scores.
3. **Three roles:**
   - *Train:* data used to fit the gate (e.g. a portion of InjecAgent-style cases + synthetic examples).
   - *Validation:* used only to choose thresholds (`low`, `high`), the best ladder step, and prompts. Held out by attack type from train.
   - *Test:* **never used for fitting or tuning**, evaluated once for the final numbers. Prefer a different source from train: AgentDojo, R-Judge, and the custom multi-step chains.
4. **Synthetic (LLM-generated) data is train-only**, hand-checked, never in validation or test.
5. **Check contamination.** Pre-trained classifiers and LLMs may have seen public benchmarks; note it, and prefer held-out and custom cases for the headline claim.
6. **Thresholds and weights are frozen** before the test run. Log the model hash and thresholds used.
7. **Log data provenance** (source, size, label origin) for every dataset in the report.
8. If you only use a pre-trained classifier (ladder step 1), there's no training split, but the same test discipline applies: tune thresholds on validation only.

---

## 8. THE one demo use case

**"DevAssist finishes the auth module" — poisoned context leads to a secret-exfiltration chain.**

Why this one: one run shows indirect injection (public benchmark relevance), behavioral drift (the event pitch), secrets (GitGuardian), audit and compliance (KPMG), and human control (ESSEC MetaLab).

**Setup:** DevAssist has simulated tools and a repo with planted secrets and a canary token. While working, it reads a third-party file (README or ticket comment) containing a hidden instruction.

**Act 1 — Without PolicyGuard (~1 min).** Task: "Help me finish the authentication module." DevAssist reads secrets, embeds one in generated code, POSTs "documentation" to an external endpoint. No alert anywhere. The canary proves the leak.

**Act 2 — Same task, PolicyGuard on (~2 min).** Each layer visibly catches something different:
- a hard invariant blocks the direct sensitive-path read,
- the ML gate flags the injected instruction in the third-party text,
- the Investigator loop (history → secret scan → destination check) resolves the ambiguous POST and escalates to the human Approve / Block button.

Design the chain while building so that each layer has a visible job. If one layer catches everything, the demo hides the architecture.

**Act 3 — Audit and numbers (~1 min).** Show the audit trail (including which layer decided), then the results slide: ASR without vs. with the guard, the R/M/A/I/H comparison, the obfuscation robustness result, and latency overhead.

**Bonus (30 seconds, only if time):** vulnerable generated code caught by the static scan, and an out-of-mandate action. No separate demos.

---

## 9. 36-hour plan

| Block | Time | Deliverable |
|---|---|---|
| Team formation, policy YAML, scope freeze, split plan | 2h | Agreed scope, roles, dataset splits written down |
| DevAssist + simulated tools + canary repo | 3h | Attack reproducible without the guard |
| Interception layer (callbacks / middleware) | 3h | Every action reaches the guard |
| Hard invariants + ML gate (ladder steps 1–2) | 5h | Gate scoring actions, first ROC curve |
| Investigator agent (LangGraph + tools) | 5h | Loop works on the demo chain |
| Audit log + Chainlit dashboard + HITL | 4h | Live demo UI with per-layer decisions |
| Evaluation harness (variants 0/R/M/A/I/H, benchmarks, robustness test) | 6h | Results table and plots |
| Slides + demo rehearsal (x3) | 3h | 5 slides, 4-minute script |
| Buffer (bugs, sleep) | ~5h | |
| *Optional:* fine-tune the encoder (ladder step 3) | only if ahead | Learned gate on action-level data |

**Cut order if late:** bonus scenarios → fine-tuning (keep the pre-trained classifier or embeddings + LR) → second benchmark → extra telemetry → dashboard polish.
**Never cut:** the demo chain, the hard invariants, the gate-vs-baseline comparison, the A vs I comparison, the audit log, the train/test discipline.

---

## 10. Risks, limits and verification

**Risks and honest limits**

- **ML gate can be evaded** (adversarial inputs) → hard invariants for guarantees, Investigator and human for the rest.
- **Training data for action-level violations is scarce** → start with pre-trained classifiers; fine-tuning is a stretch goal.
- **Data leakage / contamination** → split rule in 7.4.
- **Latency and cost of the Investigator** → the gate resolves most actions first; report share per layer.
- **The Investigator can be attacked** (injections in inspected content) → read-only tools, content as data, step budget.
- **False positives** make the agent unusable → measure benign utility explicitly.
- **Wording risk:** calling the ML gate "deterministic" invites a fair challenge. Use "fixed-weight, reproducible".
- **Scope creep** → one demo chain, one stack.
- **Integration scope:** Python / LangChain / LangGraph first.
- **Benchmark fit:** public benchmarks don't perfectly match multi-step chains; say what they do and don't cover.

**Verification checklist before building** (names and details came from memory)

- [ ] InjecAgent: exact paper, repo, license, dataset size, format.
- [ ] R-Judge: exact paper, repo, number of records and labels.
- [ ] AgentDojo: repo, how to plug in a defense, which suites to use.
- [ ] Pre-trained injection classifiers (Hugging Face / Prompt Guard family): exact names, licenses, input length limits, CPU latency, training data (contamination).
- [ ] DeepEval: which metrics actually exist; fall back to scikit-learn if needed.
- [ ] Giskard: LangChain / LangGraph support, and whether it's worth the time.
- [ ] Models and API credits provided by the organizers; GPU access (Colab) if fine-tuning.
- [ ] Hackathon rules: reuse of public benchmarks, open-source libraries and pre-built code.
- [ ] Current products of the jury companies (my knowledge may be outdated).

---

## 11. Parked ideas

- **Avalanche / blockchain** (dropped for now, maybe later): anchoring the audit-log hash and the active policy hash on-chain for tamper evidence. The hash chain alone already gives most of the tamper evidence. Avalanche only adds an independent timestamp. A wallet-holding agent with on-chain spending limits would fit Track 1, not this project.
- API-gateway and sidecar integration modes.
- Open-source core + enterprise features.

---

## 12. 30-second pitch

> "Companies are deploying AI agents with real access to code, files and APIs, but nobody can verify that an agent is doing only what it was told to do. The danger isn't an obvious attack; it's a chain of individually legitimate actions. PolicyGuard wraps any LangChain or LangGraph agent in layers: hard rules where we need guarantees, a small fixed-weight model that generalizes to reworded attacks, and an investigating agent for the hard cases, with a human in the loop and a full audit trail. We evaluated every layer against public agent-security benchmarks, on data it never saw in training, and it installs in a few lines of code."