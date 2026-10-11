# Context handoff: work done in the claude.ai conversation

This file summarizes a long conversation held in claude.ai (web) so that a Claude Code session
can continue with the same understanding. The user is on the team but is not the owner of the
GitHub repository, so the web session could not be linked to it.

## 1. Project (see CLAUDE.md and hackathon_project_plan.txt)
PolicyGuard supervises DevAssist. Plan, stack, evaluation, demo and 36-hour plan are in
hackathon_project_plan.txt. That file is the source of truth.

## 2. What was done, in order

### 2.1 Blockchain / Avalanche evaluation -> decision: do not use
The user first considered storing inputs or agent logs on Avalanche for traceability, and using
a smart contract to stop or flag an agent's POST that carries API keys. After analysis, the user
concluded it is irrelevant, and the analysis agreed:
- A smart contract only governs on-chain state. An agent's HTTP POST is off-chain, so the
  contract cannot intercept it. Interception must stay in the Python middleware
  (on_tool_start / interrupt()), which the plan already has.
- The logs contain sensitive data (file paths, code, possible secret fragments). On a public
  chain that is a leak, and immutability conflicts with GDPR erasure, while the pitch is about
  compliance (KPMG, EU AI Act, NIS2, DORA).
- On-chain writes add cost and latency, against the triage fast path.
- It would blur the one-sentence pitch and look like a buzzword.
Only legitimate idea: tamper-evident audit log. Implement a hash chain in SQLite (~30 min,
demonstrable: edit a row, verification fails). Optionally mention in the slides, as a future
step, anchoring a periodic digest on a blockchain. This is NOT in the "never cut" list.

### 2.2 Architecture diagram (draw.io)
File: assets/policyguard_architecture.drawio (2 pages), built from the template in
architecture_rules.txt (Interface / Orchestration / Intelligence / Data layers, agent
definitions in the Step 3 format, peer-review notes from Step 4). Later enlarged (x1.6 wide,
x1.7 tall, fonts x1.25) so nothing overlaps. Page 1 = architecture, page 2 = agent workflows.
The rules file targets AWS Bedrock; the diagram keeps its structure but uses this project's
stack (LangGraph, YAML, SQLite).
Items in the diagram that are PROPOSALS, not in the plan (team must confirm):
- Failure handling: retry once on tool/LLM error or timeout, then escalate to a human.
  The plan only says: escalate when the step budget is used up or confidence is low.
- "Fail closed": a guard or tool error escalates to a human instead of a silent allow.
- Simplest 90-minute version: rules triage + scan_secrets + check_destination + SQLite log,
  on the demo chain only.
- Models are marked "TBD (event credits)". "No embeddings / vector DB" is stated on purpose
  because the rules ask about the embedding strategy.
Known gaps: Input guard and Output guard are not linked to the Investigator (only the
tool-call path is drawn); the models and LangSmith boxes have no arrows.

### 2.3 Sales video (FR and EN)
A silent 83-second, 1080p, 24 fps explainer with a light generated soundtrack, for clients and
companies. Story: hook -> problem (poisoned README, three "legitimate" actions forming a
leak, classic tools silent) -> PolicyGuard -> 3 steps (mandate in plain language, interception
and investigation, decision) -> with/without split screen -> "a filter sees an action,
PolicyGuard sees the chain" -> audit trail -> integration + closing card.
Source: assets/video_src (Python + Pillow + ffmpeg; scenes_fr.py, scenes_en.py, audio.py,
chunk.py). Scene text is in the scene functions. Rendering notes: one CPU, ~0.18 s/frame;
render in chunks (chunk.py <start> <end> <file>), then concat and mux audio.wav with ffmpeg.
Caveats to resolve before showing it:
- The sentence "Evaluated on public benchmarks, with and without the guard" must be true by
  then, otherwise remove it. No numbers appear in the video.
- The on-screen examples are illustrative, not real outputs of the system (the log lines
  mirror section 6 of the plan).
- The closing card names the event; remove it if the video leaves the event.
No voice-over exists. A script was provided in the conversation (one line per scene).

## 3. Open items
- Confirm which models and credits the organizers provide.
- Walk through the section 11 verification checklist of the plan (InjecAgent, R-Judge,
  AgentDojo, DeepEval, Giskard, hackathon rules on reuse of open-source and pre-built code).
- Team decision on failure handling and fail-closed behavior (see 2.2).
- Decide whether to implement the hash-chained audit log.
- Optionally link Input/Output guards to the Investigator in the diagram.
- Check what code already exists in the repo versus the 36-hour plan blocks.

## 4. First thing to do in a new Claude Code session
1. Read CLAUDE.md, this file and hackathon_project_plan.txt, then summarize in French what you
   understood and which decisions are already taken, before touching any code.
2. Inspect the repo (structure, existing code, tests) and compare it with the plan's blocks.
3. Propose the next smallest step toward the demo chain. Do not reopen the blockchain question.
