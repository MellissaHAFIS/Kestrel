# Demo run-sheet (PolicyGuard)

Everything here runs on the laptop, offline. No AWS needed for the recording. Aim for ~3 minutes.
Record 2-3 takes. Start the video track EARLY, it is the only time-risky item.

## Before you hit record (one-time setup, ~2 min)
1. Open two terminals at the repo root.
2. Terminal A (the console) - start it and leave it running:
   .venv\Scripts\python.exe -m chainlit run console/app.py
   Browser opens locally. In the chat, test once: type `tools`, then `queue`. Confirm cards show.
   (If you changed the console since last launch, Ctrl+C and relaunch so it picks up `tools`.)
3. Terminal B (the demo) - leave at the prompt, ready to run the two acts.
4. Open the two charts in an image viewer, ready to show:
   - eval/results/20261010T225704Z-2c9a9aa-bedrock.png   (headline: with vs without)
   - eval/results/layers-bedrock.png                      (which layer stopped what)

## The script (what to run + what to say)

### [0:00-0:20] Frame it (talking head or title slide)
SAY: "AI agents call tools, often from third-party servers. A poisoned tool can make an agent
leak a secret while every call looks legitimate. PolicyGuard supervises what the agent DOES
across the tool chain, and hands the hard cases to a human."

### [0:20-1:00] ACT 1 - the attack works (Terminal B)
RUN: .venv\Scripts\python.exe -m demo.run_no_guard
SAY: "DevAssist is asked to fix an auth bug. A poisoned docs tool coaxes it into pasting the
config file, canary secret included, to an untrusted server. No guard: the canary lands in the
leak log. Attack succeeds."
POINT AT: the final "ATTACK SUCCEEDED" line.

### [1:00-1:45] ACT 2 - the guard stops it (Terminal B)
RUN: .venv\Scripts\python.exe -m demo.run_guarded
SAY, as the layers print: "Registry quarantines the poisoned tool at connection. The hard
invariant blocks the exact canary leak. The gate and the Investigator handle the subtler cases.
The canary never leaves."
POINT AT: the final "PASS: PolicyGuard blocked the leak" line.

### [1:45-2:25] The console - humans stay in control (Terminal A browser)
TYPE: tools   SAY: "Layer one. Every tool is scanned before use. search_docs is quarantined,
and here is exactly why."
TYPE: queue   SAY: "The cases the guard could not decide alone, graded live by Claude on
Amazon Bedrock, with a confidence score and a grounded reason."
TYPE: block <paste an id from a card>   SAY: "The analyst decides. It is logged."
TYPE: kill    SAY: "And one command stops the whole session. Fail closed."

### [2:25-3:00] The numbers (the two charts)
SHOW: the headline chart.
SAY: "Across 28 cases, run live on Claude Haiku on Bedrock: attack success drops from 100% to
14%. Benign tasks still complete 71% of the time, more with analyst approval."
SHOW: the layers chart.
SAY: "Invariants caught seven, the Investigator caught five more. Two slipped past the ML gate,
a truncated and a split canary. That is a real limit, and it is exactly where we would harden next.
Small, custom test set, and we say so."

## If something breaks on camera
- Console won't start: Ctrl+C, rerun the chainlit command. Port busy -> add --port 8001.
- A command errors: cut, fix, re-take that section. Do not debug on the recording.
- Live Bedrock flakes: you already have saved real results; show those and say the run was done live earlier.

## Do NOT, under deadline pressure
- Add features. The demo is complete.
- Re-tune thresholds after seeing results (it invalidates the "no tuning" honesty claim).
- Commit real AWS creds or the team access code. Canary/FAKE values only.
