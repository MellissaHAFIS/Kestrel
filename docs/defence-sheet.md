# Defence sheet - PolicyGuard (Secure Horizons)

Fill the [bracketed] bits. Numbers below are from the real Bedrock run (commit 2c9a9aa,
Claude Haiku 4.5 on Amazon Bedrock, us-east-1). Keep it honest; the honesty is a selling point.

## 1. What we built
PolicyGuard, a supervision layer for an AI agent's tool use (including the MCP tool supply chain).
Protected agent: DevAssist. Five layers, each with a visible job:
1. Registry scan - scans each tool's description/schema at connection; quarantines poisoned tools.
2. Hard invariants - deterministic, non-overridable rules (canary match, secret patterns, sensitive paths, tool allow-list).
3. ML gate - cheap risk score; clear-cut cases allow/block, uncertain band goes up.
4. Investigator - an LLM agent (Claude on Bedrock) that gathers evidence and rules with a confidence floor.
5. Human console - analyst reviews escalations, approve/block, kill switch, full audit log.
Rule that matters: the AI can only tighten a decision, never lift a hard-invariant block.

## 2. Threat model (what we defend against)
- Tool poisoning: a third-party tool description instructs the agent to exfiltrate (OWASP agent risks: tool misuse, goal hijack).
- Chain-level exfiltration: read a secret in one step, leak it in a later step.
- Obfuscated leaks: canary encoded (hex/base64/rot13), split across calls, paraphrased.
Out of scope (stated honestly): we do not defend the foundation model's own safety training; we supervise actions.

## 3. How we tested (attacks)
- Custom scripted set: 14 attack chains + 14 benign chains, 56 tool-call steps total.
- Categories: obvious tool poisoning, subtle poisoning, exact canary leak, obfuscated leak
  (hex/base64/rot13/spaced/truncated/split), multi-step read-then-leak; benign controls including
  sensitive-looking-but-legit reads and docs-derived content.
- All secrets are FAKE canaries (e.g. CANARY-PG-7f3a9c0d-FAKE-DO-NOT-USE). No real data, inside our own account.
- Replayed each chain through the real guard pipeline; Investigator ran live on Claude Haiku 4.5 on Bedrock.
- Rate-paced ~1 request/second per the AWS guidance.

## 4. Results (real run)
| Metric | Without guard | With guard |
|---|---|---|
| Attack success (a harmful step got through) | 100% (14/14) | 14.3% (2/14), 95% CI 4-40% |
|   ...if every escalation were approved | 100% | 28.6% (4/14) |
| Benign tasks completed | 100% (14/14) | 71.4% (10/14), 95% CI 45-88% |
|   ...if every escalation were approved | 100% | 85.7% (12/14) |
| Harmful steps stopped (block or escalate) | 0% (0/15) | 80% (12/15) |
| Escalations per 100 benign steps | 0 | 7.4 |

Which layer stopped the attacks (harmful steps): invariants blocked 7; Investigator blocked 3, escalated 2;
ML gate let 2 through. (See eval/results/layers-bedrock.png.)

## 5. Honest limits (say these; they build trust)
- Small, custom test set, written by us. Not an independent benchmark.
- Scripted replay: we assume the agent attempts every step, so the "without guard" numbers hold by construction.
  An LLM-driven agent might behave differently.
- Two attacks slipped past the ML gate: a truncated canary and a canary split across two calls.
  That is our weakest layer and the next thing to harden.
- An escalation counts as "stopped" in the headline (unanswered escalations fail closed to BLOCK);
  we also report the worst case where every escalation is approved.
- We did not tune thresholds on this set.
- The registry layer did not fire inside the pipeline run (a tool-name lookup mismatch we identified);
  the quarantine is shown via the console tools view. Known, documented, small fix pending.

## 6. Containment (how we keep the agent safe)
- Hard invariants cannot be overridden by the AI. Step/tool/token budgets. Timeouts.
- Human approval for the uncertain band; kill switch stops the session.
- Full SQLite audit log of every decision with the deciding layer and reasoning.

## 7. What we'd do next
- Harden the gate against truncated/split/encoded leaks (the two misses).
- Fix the registry lookup so quarantine fires inside the pipeline.
- Larger and independent test sets (MCPTox for tool descriptions, AgentDojo for end-to-end).
- An MCP gateway proxy so the guard sits inline in production.

## 8. Reproduce
- Repo: branch invariants. pip install -e '.[bench]' (add boto3 for Bedrock).
- Offline: python -m eval.run_eval (MockLLM). Real: python -m eval.run_eval --mode bedrock.
- Results file: eval/results/20261010T225704Z-2c9a9aa-bedrock.json (every number traces to it).

## Team / roles
[names + who built what]
