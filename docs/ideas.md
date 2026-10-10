# PolicyGuard — Hackathon Project Plan (v3, aligned with the organizers' Track 2 brief)

**Event:** Secure Horizons (UTOPIA × KRYPTOSPHERE × ESSEC MetaLab), ESSEC Cergy, Oct 10–11, 2026, 36h
**Track:** 2 — Defenders Augmented (AI for security & secure AI)
**Jury:** GitGuardian · ESSEC MetaLab · KPMG
**Working name:** PolicyGuard (the guard) protecting DevAssist (the target agent)

**What changed in v3**

- Added **section 0**: the organizers' brief and scoring grid, mapped to the plan.
- **Positioning:** PolicyGuard is explicitly *not* a prompt filter. The headline is now MCP tool-poisoning defense + chain-level supervision of tool calls + grounded investigation for the human analyst.
- **Demo changed (recommended, to confirm):** an MCP tool-poisoning chain instead of a poisoned README.
- **New components:** tool registry scanner, provenance (source) tags, analyst console, a dedicated "human control" section.
- **ML gate demoted** to a cheap fast path. Fine-tuning is the first thing to cut.
- **Evaluation extended** with tool-poisoning tests and reliability / analyst-value metrics.
- Avalanche stays parked.

---

## 0. What the organizers said (Track 2 slides)

**The brief**

- "AI can make every analyst ten times more effective, if it can be trusted. And the AI agents deployed in companies need watching too."
- **What wins:** "Another prompt filter won't impress the jury: Lakera and Prompt Security were acquired in 2025. Go deeper."
- **SOCs under pressure:** a copilot that hallucinates is worse than none. Reliability is the challenge: *uncertainty scores, source checks, human in the loop*.
- **AI agents without supervision:** agents plan and call tools, often via MCP. Malicious instructions can hide in a tool description ("tool poisoning"). OWASP ranks goal hijack and tool misuse first.
- **Identities and data out of control:** most agents run with over-privileged accounts and nobody knows which exist. EchoLeak showed one booby-trapped e-mail could exfiltrate data with no click needed.
- **Deliverables on top of the common ones:** a working PoC, defensive metrics, and "how the human stays in control".

**Scoring grid, mapped to the plan**

| Criterion | Weight | What we do | Evidence we show |
|---|---|---|---|
| **Defensive effectiveness** | 30% | Layered defense (registry scan → hard invariants → ML gate → Investigator) against MCP tool poisoning and multi-step exfiltration | Attack success rate with vs. without guard; recall / FPR / benign utility; held-out tests; obfuscation robustness; variants R/M/A/I/H |
| **Operational value for the analyst** | 20% | Analyst console: a short prioritized incident queue, a grounded incident report per escalation, one-click approve / block; most actions resolved automatically so analysts don't drown in alerts | Escalations per 100 actions; share of actions auto-resolved; incident report with evidence links; comparison with the one-shot judge |
| **AI reliability & control** | 20% | Uncertainty scores (gate score, Investigator confidence), source checks (provenance tags + evidence from tools), human in the loop, hard invariants the AI can't override | Calibration plot / ECE; groundedness rate of reports; reproducibility check; the human-control slide |
| **Technical integration** | 15% | MCP-native (tool-call wrapper + tool registry scan), LangChain / LangGraph middleware, secret scanning tools, SIEM-friendly JSON export | Works against a real MCP server; integration in a few lines of code |
| **Pitch & demo** | 15% | One clear story, live before/after, a visible human-control moment | Rehearsed 4-minute demo |

Two consequences drive the rest of this plan:

1. A prompt-injection classifier is a prompt filter. It can stay as a fast path, but it cannot be the contribution.
2. The "analyst" is a **security analyst supervising agents**. The Investigator is effectively a SOC copilot for agent incidents, so it must be reliable: every claim it makes must be backed by a tool observation.

---

## 1. WHAT am I building?

**One sentence:** a security layer that supervises AI agents' tool use in real time (including the MCP tool supply chain), decides automatically when it can, and hands a *grounded, uncertainty-scored* case to a human analyst when it can't.

> The question it answers: "Is this agent doing exactly what we asked it to do, and nothing else, and can a human prove and control it?"

| Component | Role | Nature |
|---|---|---|
| **DevAssist** | The protected agent: a developer assistant using MCP tools (files, PRs, docs search, notifications) | Agentic (tools, loop) |
| **Tool registry scanner** | At MCP connection time, scans tool descriptions and schemas for poisoning, pins their hashes, quarantines suspicious tools | Deterministic rules + ML score |
| **Hybrid gate** | Scores every intercepted action in milliseconds: hard invariants, then a small fixed-weight ML model | Not agentic, on purpose |
| **Investigator** | Investigates only the uncertain cases with tools; outputs a grounded verdict with confidence | Agentic (reason → act → observe loop) |
| **Analyst console** | Chainlit UI: incident queue, evidence, approve / block, session kill switch, audit log | Human control |

**What PolicyGuard does**

1. **Defines** the agent's mandate as a natural-language policy (YAML): allowed tools, sensitive paths, trusted destinations, what needs approval.
2. **Checks the tool supply chain:** MCP tool descriptions are untrusted input; scan them, pin them, quarantine suspicious ones.
3. **Intercepts** every input, tool call and output of the agent, and tags content by **source** (user, internal repo, third-party tool description, tool result).
4. **Gates** each action with hard invariants and an ML score.
5. **Investigates** the uncertain band with a tool-using agent.
6. **Acts:** allow, block, sanitize, quarantine a tool, or escalate to a human (`interrupt()`).
7. **Logs** everything, including which layer decided and why.

**Integration story:** drop-in Python middleware for LangChain / LangGraph agents, with MCP tools wrapped at the tool-call layer. Limits: non-Python agents, closed vendor agents, and a full network-level MCP gateway are not in this version.

**Terminology rule:** only the hard invariants are *deterministic with a guarantee*. The ML gate is *fixed-weight and reproducible*, not guaranteed. Don't call the ML gate "deterministic".

---

## 2. WHY this idea?

**The problem:** agents already run in production with real access (files, APIs, email, code), often through MCP servers written by third parties. Their failures are *behavioral*, not classic intrusions:

- A **tool description** can carry hidden instructions (tool poisoning). The agent follows them because they look like part of the tool's documentation.
- Each individual action looks legitimate (legitimate agent, legitimate access, legitimate text). The danger is in the **chain**: read a secret → pass it as a "context" parameter → it leaves for a third party.
- Goal hijack and tool misuse are the top risks in OWASP's agent ranking (verify exact names).
- Agents often run with over-privileged accounts, and nobody has an inventory of what they can do.
- Real precedent: EchoLeak (a booby-trapped e-mail exfiltrating data with no click).
- Classic tools (firewall, antivirus, SIEM, DLP) don't understand *what the agent is trying to do*.

**Why not "another prompt filter":** per the organizers, that space has already consolidated. A prompt filter inspects text going into one model. PolicyGuard supervises the *actions* of an agent across a tool chain, including the tool supply chain, with provenance, privilege awareness, evidence-grounded investigation and human control.

**Why layers:** guarantees from code, generalization from a small model, judgment from an agent only where needed. LLM judges alone aren't reproducible, are slow and costly on every action, and can be attacked by the content they inspect.

**Honest positioning:** guardrail tools exist (Guardrails AI, NeMo Guardrails, LangSmith for observability, and the acquired prompt-security vendors). Our differentiation is the **combination**: MCP tool-supply-chain scanning + provenance + layered gate + grounded Investigator + analyst console, evaluated on public and custom tests. Don't claim "nobody has done this"; claim a specific focus: *multi-step behavioral drift and tool poisoning in tool-using agents*.

---

## 3. IMPACT

| Stakeholder | Why they care |
|---|---|
| **GitGuardian** | Secrets leaving through agents and tool calls is their domain: our secret scan and canary tools extend "secrets in code" to "secrets in agent behavior". |
| **KPMG** | Clients deploy agents and need controls, an audit trail, and human oversight for AI governance and compliance. |
| **ESSEC MetaLab** | Visible governance: explicit policy, human control, explainable and reproducible decisions. |
| **Security analysts / SOCs** | A short queue of grounded, prioritized agent incidents instead of raw logs. |
| **Any company with agents + MCP tools** | A reusable layer to vet tools and supervise agents. |

**What the jury should remember:** "They didn't build another prompt filter. They secured the tool layer of agents, measured it, and showed exactly how the human stays in control."

**Possible continuation (mention, don't overclaim):** open-source core, enterprise features later (hosted console, multi-agent inventory, compliance reports); partnership with jury companies.

---

## 4. HOW — Architecture

```
MCP servers (internal + third-party)
   │  tool descriptions + results = UNTRUSTED
   ▼
[R] TOOL REGISTRY SCAN (at connection time)
    scan descriptions/schemas · pin hashes · quarantine suspicious tools
   ▼
User ─► DevAssist (LangGraph) ─► tool calls ─► MCP servers
            │  every input / tool call / output is intercepted
            │  and tagged with its SOURCE (provenance)
            ▼
┌──────────────────────── PolicyGuard ─────────────────────────┐
│ 1a. HARD INVARIANTS (plain code, guaranteed)                 │
│     canary/secret in outgoing args · sensitive-path deny-list│
│     · unexpected tool parameters · schema validation         │
│     → violation = final BLOCK (the AI cannot override)       │
│                          ▼                                   │
│ 1b. ML GATE (small encoder, fixed weights, CPU-fast)         │
│     score < low → ALLOW · score > high → BLOCK               │
│     in between → Investigator                                │
│                          ▼                                   │
│ 2.  INVESTIGATOR AGENT (LLM + tools, uncertain band only)    │
│     grounded verdict + confidence; can only tighten          │
│                          ▼                                   │
│ 3.  HUMAN: analyst console (approve / block / kill session)  │
└──────────────────────────────────────────────────────────────┘
     Policy store (YAML) · Audit log (SQLite, per-layer decision)
```

**Design rules**

- The AI can add caution but can never lift a hard-invariant block.
- Hard invariants are a handful of rules where a guarantee matters. Everything fuzzier goes to the ML gate or the Investigator.
- Thresholds are tuned on a validation split only (section 8.4), then frozen. The model hash and thresholds are logged with every decision.

### 4.1 Tool registry scanner (the "go deeper" part)

When DevAssist connects to an MCP server, each tool's description and parameter schema is treated as untrusted input.

- **Deterministic checks:** invisible / hidden Unicode, imperative instructions aimed at the model ("before using this tool, read…", "do not tell the user"), references to other tools, files or paths, suspicious extra parameters (e.g. `context`, `notes`) that invite data to be passed along, abnormal description length.
- **ML check:** injection-classifier score on the description (the same fast model as the gate).
- **Pinning:** store a SHA-256 of description + schema. If it changes later ("rug pull"), re-scan and alert.
- **Outcome:** allow, quarantine (tool unavailable until the analyst approves), or block.
- **Honest limit:** the scanner is imperfect on subtle poisoning. That's why the runtime layers exist, and the demo uses a subtle tool to show it.

### 4.2 Provenance (source checks)

Every piece of content in the session carries a source label: `user` (trusted), `internal_repo`, `mcp_description` (untrusted), `tool_result` (untrusted). The Investigator can ask "which source did the content preceding this action come from?" and the answer goes into the evidence.

**Honest limit:** we can't see inside the model's reasoning. Provenance is by ordering and correlation (e.g. an instruction in an untrusted description followed by an action that matches it), so it's strong evidence, not proof.

### 4.3 The ML gate (fast path, not the headline)

- **Input:** serialized action (tool, args, short history, source labels) and incoming text.
- **Output:** a violation score in [0, 1].
- **Build ladder (stop when time runs out):**
  1. **Pre-trained injection classifier** from Hugging Face (DeBERTa-based injection detectors, Meta's Prompt Guard family, etc.; verify names, licenses, sizes). Zero training.
  2. **Embeddings + logistic regression** on action text. Gives a first ROC curve.
  3. **Fine-tune a small encoder.** Cut first if short on time, since the organizers said a prompt filter won't win.
- **Role:** keep the Investigator affordable by resolving the clear cases cheaply, and provide a measurable uncertainty score.
- **Limits to state openly:** probabilities, evadable by adversarial inputs, weaker than patterns on structured secrets.

### 4.4 The Investigator is an agent, grounded in evidence

A single "prompt → JSON verdict" call is a classifier, not an agent. The Investigator loops, and only on actions the gate couldn't settle:

```
Uncertain action
      ▼
 ┌─► REASON: what do I still need to know?
 │        ▼
 │   ACT: call an investigation tool
 │        ▼
 │   OBSERVE: record evidence (with an id) and update confidence
 │        ▼
 └── confidence < threshold AND steps left? ── yes ──┘
              │ no
              ▼
   VERDICT + incident report (every claim cites an evidence id)
   → allow / block / sanitize / escalate to the analyst
```

**Investigator tools (read-only; inspected content is treated as data):**

| Tool | Purpose |
|---|---|
| `get_session_history` | What the agent did earlier (catches chains) |
| `get_provenance(action)` | Which source the preceding content came from |
| `read_policy(section)` | Relevant rules from the policy store |
| `scan_secrets(text)` | Pattern + entropy scan (e.g. `detect-secrets`; `ggshield` if available) |
| `check_destination(url)` | Allowlist and domain checks |
| `classify_path(path)` | Is this file sensitive (`.env`, keys, data class)? |
| `inspect_tool(tool_name)` | Registry scan result and pinned hash of the tool involved |
| `check_canary(text)` | Detect planted honeytokens (proof of exfiltration) |
| `request_human_approval` | LangGraph `interrupt()` |

**Reliability mechanisms (the "hallucinating copilot is worse than none" problem):**

- Every claim in the incident report must cite an **evidence id** from a tool observation.
- A **deterministic verifier** checks that every cited id exists and that the report only lists evidence actually collected. Reports failing the check are marked "unverified" and escalated.
- The verdict carries a **confidence** value, and below a threshold the Investigator **abstains** and escalates.
- Hard step budget (~6), read-only tools.

**LangGraph structure:** nodes `reason ⇄ tools (ToolNode) → verify → verdict → human_interrupt (optional)`. State: `action_under_review`, `evidence[]`, `confidence`, `steps_used`, `gate_score`, `sources`.

### 4.5 The 5 agentic criteria

Litmus test: *can I answer in one shot, without looking anything up or changing anything?* No → agent.

| # | Criterion | DevAssist | Investigator |
|---|---|---|---|
| 1 | Live / external data via tools | MCP tools: files, repo, docs search, HTTP | session history, provenance, scanners, destination lookup, tool registry |
| 2 | Actions in the world | open PRs, send notifications, call tools | block, sanitize, quarantine a tool, escalate to a human |
| 3 | Number of steps unknown ahead | depends on the task | 1 to ~6 depending on the evidence |
| 4 | Reacts to results | adapts to tool results | the next tool depends on the last observation |
| 5 | Constraint met by iteration | finish the coding task | reach confidence ≥ threshold within the step and latency budget, else escalate |

The registry scanner and the ML gate are deliberately **not** agentic. They're the fast path that keeps the agentic Investigator affordable.

---

## 5. How the human stays in control (required deliverable)

| Decision | Who decides | Mechanism |
|---|---|---|
| What the agent may do (policy) | Human security owner | YAML policy, versioned; the AI may suggest changes but never applies them |
| Which MCP tools are trusted | Human analyst | New or changed tools are quarantined until approved; hashes pinned |
| Hard-invariant violations | Automatic block | The AI cannot override. Only a human editing the policy lifts a rule, and that change is logged |
| ML-gate blocks | Automatic, human can override | Analyst override requires a logged reason |
| Ambiguous or high-severity actions | Investigator recommends, **human decides** | `interrupt()` pauses the agent until the analyst approves or blocks |
| Low-risk actions | Autonomous | Fully logged and reviewable |
| Emergency stop | Human | Session kill switch in the console |
| Accountability | Everyone | Audit trail with per-layer decision, reasoning, model hash, thresholds |

Principle for the slide: **AI proposes, rules guarantee, humans decide.**

---

## 6. HOW — Stack

| Layer | Choice |
|---|---|
| Agent framework | LangGraph + LangChain (tools, callbacks / middleware, `interrupt()`) |
| MCP | Python MCP SDK (FastMCP) to build a legit and a poisoned test server; `langchain-mcp-adapters` to load MCP tools into LangGraph (verify both) |
| LLMs | Small fast model for DevAssist; stronger model for the Investigator; `temperature=0` (check which models/credits the event provides) |
| Interception | Wrap MCP tools at the tool-call layer + LangChain callbacks |
| ML gate | Hugging Face `transformers` + PyTorch (CPU inference), scikit-learn for the logistic-regression baseline |
| Hard invariants | Plain Python (path rules, canary / secret match, schema checks) |
| Policy store | YAML / JSON |
| Security tools | `detect-secrets` (and `ggshield` if available), Bandit or Semgrep (bonus), allowlist logic |
| Audit log | SQLite, with JSON export in a SIEM-friendly shape |
| UI / demo | Chainlit analyst console |
| Tracing | LangSmith |
| Evaluation | Python + scikit-learn; optional DeepEval / Giskard (verify) |

---

## 7. HOW — Observability and the analyst console

**Analyst console (Chainlit)**

- **Incident queue:** only escalations, sorted by severity and uncertainty.
- **Incident card:** what happened, the evidence list (each item linked to its tool observation), provenance of the triggering content, gate score, Investigator confidence and **uncertainty**, recommended action, Approve / Block buttons.
- **Tool registry view:** MCP tools with status (trusted / quarantined), scan result, pinned hash.
- **Session controls:** kill switch.
- **Live feed:** one line per event showing which layer decided.

```
[10:42:00] REGISTRY   docs_helper.search            QUARANTINE (hidden instruction in description)
[10:42:03] TOOL CALL  file_read("config/settings")  ALLOW      (gate 0.12)
[10:42:04] TOOL CALL  notes_helper.save(context=…)  INVESTIGATE (gate 0.55) → 3 steps → ESCALATE (conf 0.91)
[10:42:05] ANALYST    Block                          logged with reason
```

**Audit trail (exportable JSON/CSV)**

```
session_id | timestamp | event_type | action | source_labels | layer | gate_score | model_hash |
evidence_ids | violation | severity | confidence | reasoning | decision | decided_by | steps_used | latency_ms
```

LangSmith holds low-level traces of LLM and tool calls; SQLite is the compliance-facing record.

---

## 8. HOW — Evaluation

**Principle:** use public benchmarks where they fit, add a small custom set where they don't (and say so), compare variants, report reliability and analyst-value metrics, and keep train and test strictly separate.

### 8.1 Benchmarks and test sets

| Set | What it tests | Role |
|---|---|---|
| **InjecAgent** (Zhan et al., 2024, ~1,054 cases) | Indirect prompt injection against tool-integrated agents | Source for training / validation; also a sanity check |
| **AgentDojo** (ETH Zurich) | Dynamic agent environments with utility and security metrics | Held-out test: security while keeping task utility |
| **R-Judge** (2024, ~569 records) | Whether a judge recognizes safety risks in agent trajectories | Held-out test for the Investigator as a judge |
| **MCP tool-poisoning benchmark** (e.g. MCPTox; verify it exists and is usable) | Poisoned MCP tool descriptions | Held-out test for the registry scanner |
| **Custom tool-description set** (~30 poisoned variants + ~30 benign real-world descriptions) | Registry scanner precision / recall | Fallback if the benchmark isn't usable. State the bias. |
| **Custom multi-step chains (~10)** | Read-secret → leak chains through MCP tools | Supplement only; public benchmarks are mostly single-step |

Use a representative subset (a few hundred cases), chosen *before* tuning.

### 8.2 Variants compared

| Variant | Description | Question it answers |
|---|---|---|
| **0. No guard** | DevAssist alone | Baseline attack success rate |
| **R. Rules only** | Regex / deny-list gate | How far does hand-written logic go? |
| **M. ML gate only** | Fixed-weight model, thresholds tuned on validation | Does learning generalize better than rules? |
| **A. One-shot LLM judge** | One LLM verdict per action | The plain "LLM call" baseline |
| **I. Investigator only** | Agent loop on every action, no gate | Does the loop beat one-shot (A vs I)? |
| **H. Hybrid (full system)** | Registry scan + invariants + ML gate + Investigator + human | Is the combination best on accuracy, cost, latency and analyst load? |

Key comparisons: **R vs M** (generalization), **A vs I** (agentic loop), **M vs H** (value of the Investigator), **I vs H** (value of the gate in cost and latency). If a hypothesis fails, report it and say what the component still adds.

### 8.3 Metrics, grouped by scoring criterion

**Defensive effectiveness (30%)**
- Attack success rate (ASR), baseline vs. guarded
- Recall on attacks, false positive rate, precision, F1
- **Benign utility:** % of legitimate tasks still completed
- Registry scanner: precision / recall on poisoned vs. benign descriptions
- Robustness: obfuscate attacks that rules catch (paraphrase, encoding, typos, split across calls) and compare R vs M vs H
- Per-category results (tool poisoning, injection, exfiltration, mandate violation)

**AI reliability & control (20%)**
- **Calibration** of the gate score and the Investigator confidence (reliability diagram, ECE or Brier score)
- **Abstention / escalation behavior:** accuracy on the cases the system decides vs. the cases it escalates
- **Groundedness rate:** % of report claims backed by a collected evidence id (checked by the verifier)
- **Reproducibility:** run the gate and the hard invariants twice on the same inputs and report identical outputs
- ROC-AUC / PR-AUC for the ML gate

**Operational value for the analyst (20%)**
- **Escalations per 100 actions** (alert load), compared with the one-shot judge
- **Share of actions resolved at each layer**
- Average tool calls per Investigator verdict, latency (ms) per path, cost per action
- Incident report completeness (evidence items, provenance present)

All numbers shown to the jury must come from actual runs.

### 8.4 Train / test split rule

1. **Decide the splits before any tuning**, write them down, don't change them after seeing results.
2. **Split by source and attack template, not by random rows.** Near-duplicates across splits inflate scores. For tool descriptions, split by *server / template*, not by individual description.
3. **Three roles:**
   - *Train:* used to fit the gate (e.g. part of InjecAgent-style cases + synthetic examples).
   - *Validation:* only for thresholds (`low`, `high`), choosing the ladder step, and prompts. Held out by attack type.
   - *Test:* never used for fitting or tuning, evaluated once. Prefer a different source from train: AgentDojo, R-Judge, the tool-poisoning set, the custom chains.
4. **Synthetic (LLM-generated) data is train-only**, hand-checked, never in validation or test.
5. **Check contamination.** Pre-trained classifiers and LLMs may have seen public benchmarks; note it and prefer held-out and custom cases for the headline claim.
6. **Freeze** thresholds and weights before the test run, and log the model hash and thresholds.
7. **Log data provenance** (source, size, label origin) for every dataset.
8. If you only use a pre-trained classifier (ladder step 1), there's no training split, but the same test discipline applies: tune thresholds on validation only.

---

## 9. THE one demo use case

**"DevAssist finishes the auth module" — an MCP tool-poisoning chain ending in secret exfiltration.**

Why this one: it uses the organizers' own threat language (MCP tool poisoning, goal hijack, tool misuse, data exfiltration, EchoLeak-style leakage) while staying inside one coherent story, and it shows the layers, the analyst and the human control.

**Setup:** DevAssist connects to two MCP servers: a legit internal one (file read, PRs) and a third-party "docs helper" server. The repo contains planted secrets and a canary token.
- **Tool A (obviously poisoned):** its description tells the model to read a config file and pass the contents in an extra `context` parameter.
- **Tool B (subtly poisoned):** reworded and less obvious, so it passes registration.

**Act 1 — Without PolicyGuard (~1 min).** Task: "Help me finish the authentication module." DevAssist follows the hidden instructions, reads the config and sends the secret to the third-party server via the tool parameter. No alert anywhere. The canary proves the leak.

**Act 2 — Same task, PolicyGuard on (~2 min).** Each layer visibly catches something different:
1. **Registry scan** quarantines Tool A at connection time. The analyst sees the highlighted hidden instruction.
2. Tool B slips through registration (the scanner isn't perfect). At runtime, a **hard invariant** blocks any call where a canary or secret appears in arguments to an untrusted server.
3. For a paraphrased or partial leak the invariants miss, the **ML gate** is uncertain, so the **Investigator** loops (history → provenance: the instruction came from an untrusted tool description → destination check → secret scan) and **escalates** with a grounded report.
4. **The analyst clicks Block** in the console. The decision is logged.

Design the chain while building so each layer has a visible job. If one layer catches everything, the demo hides the architecture.

**Act 3 — Audit and numbers (~1 min).** Show the audit trail with per-layer decisions, then the results slide: ASR without vs. with the guard, R/M/A/I/H comparison, calibration, escalations per 100 actions, latency. End on the human-control slide (section 5).

**Optional 15-second bonus:** a privilege report showing the agent's token has write access to all repos while the task needs read-only, addressing the "over-privileged agents" point. Only if time allows.

*Change from v2: the poisoned README was replaced by MCP tool poisoning to match the organizers' brief. The rest of the chain and the architecture still apply. Confirm or revert.*

---

## 10. 36-hour plan

Assumes parallel work across teammates; adjust if you're solo.

| Block | Time | Deliverable |
|---|---|---|
| Scope freeze, policy YAML, split plan, ask organizers about deliverables | 1.5h | Agreed scope and roles, dataset splits written down |
| DevAssist + MCP servers (legit + poisoned A/B) + canary repo | 4h | Attack reproducible without the guard |
| Interception (MCP tool wrapper, callbacks) + provenance tags | 3h | Every action reaches the guard with source labels |
| Tool registry scanner + hash pinning | 2h | Tool A quarantined |
| Hard invariants + ML gate (ladder steps 1–2) | 3h | Gate scoring actions, first ROC curve |
| Investigator (grounded, verifier, confidence) | 5h | Loop works on the demo chain |
| Analyst console + audit log + HITL + kill switch | 5h | Live demo UI |
| Evaluation harness (variants, benchmarks, calibration, robustness) | 6h | Results table and plots |
| Slides + human-control slide + rehearsal (x3) | 3h | 5 slides, 4-minute script |
| Buffer (bugs, sleep) | ~3.5h | |
| *Optional:* fine-tune the encoder, privilege report | only if ahead | |

**Cut order if late:** privilege report → fine-tuning → bonus scenarios → second benchmark → extra telemetry → dashboard polish.
**Never cut:** the demo chain, the hard invariants, the registry scan, the analyst console with Approve / Block, the A vs I comparison, the audit log, the human-control slide, the train/test discipline.

---

## 11. Risks, limits and verification

**Risks and honest limits**

- **Looking like "another prompt filter"** → lead with tool poisoning, chain supervision and the analyst workflow in all material; the ML gate is the fast path.
- **Scope creep** (MCP + provenance + console + eval is a lot) → build the demo chain first; use the cut order.
- **The Investigator can hallucinate** → grounded evidence ids, deterministic verifier, abstain and escalate.
- **ML gate can be evaded** → hard invariants for guarantees; Investigator and human for the rest.
- **Registry scanner misses subtle poisoning** → by design; runtime layers exist, and the demo shows this honestly.
- **Provenance is approximate** (correlation, not proof) → say so.
- **Training data for action-level violations is scarce** → start with pre-trained classifiers.
- **Data leakage / contamination** → split rule in 8.4.
- **Latency and cost of the Investigator** → the gate resolves most actions first; report share per layer.
- **False positives** make the agent unusable → measure benign utility and analyst alert load.
- **Wording risk:** don't call the ML gate "deterministic".
- **Integration scope:** Python / LangChain / LangGraph first; a real MCP gateway proxy is future work.

**Verification checklist before building** (names and details came from memory or from a blurry photo of the slides)

- [ ] **Ask the organizers:** what are the "common deliverables"? Must the demo be live? Is the "analyst" persona a SOC analyst? Any preferred MCP or tooling?
- [ ] OWASP agent risk ranking: exact list and category names (goal hijack, tool misuse).
- [ ] EchoLeak: details to cite accurately (vendor, CVE, mechanism).
- [ ] MCP tool-poisoning benchmark (e.g. MCPTox): exists, license, format, usable offline.
- [ ] MCP Python SDK and `langchain-mcp-adapters`: current versions and how to wrap tool calls.
- [ ] InjecAgent, R-Judge, AgentDojo: exact papers, repos, sizes, formats, how to plug in a defense.
- [ ] Pre-trained injection classifiers (Hugging Face / Prompt Guard family): names, licenses, input length limits, CPU latency, training data (contamination).
- [ ] DeepEval and Giskard: which features actually exist, LangGraph support, and whether they're worth the time.
- [ ] Models and API credits provided; GPU access if fine-tuning.
- [ ] Hackathon rules: reuse of public benchmarks, open-source libraries and pre-built code.
- [ ] Current products of the jury companies (my knowledge may be outdated).

---

## 12. Parked ideas

- **Avalanche / blockchain** (dropped for now, maybe later): anchoring the audit-log and policy hashes on-chain for tamper evidence. The hash chain alone gives most of the tamper evidence.
- A real MCP gateway / sidecar proxy, and an API-gateway mode.
- Agent inventory across the whole company (the "nobody knows which agents exist" problem).
- Open-source core + enterprise features.

---

## 13. 30-second pitch

> "Prompt filters are a solved, already-acquired market. The real risk is what agents *do* with their tools: a poisoned MCP tool description can make an agent leak a secret while every single action looks legitimate. PolicyGuard scans and pins the tools an agent can use, tags where every instruction came from, and supervises each action in layers: hard rules for guarantees, a small fixed-weight model for speed, and an investigating agent whose every claim is backed by evidence. When it isn't sure, it doesn't guess: it hands the analyst a short, grounded case with an uncertainty score. We measured every layer on held-out data, with and without the guard, and the human stays in control at every step."