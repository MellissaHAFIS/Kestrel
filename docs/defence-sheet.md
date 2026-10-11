# Defence Sheet - Kestrel

Kestrel (formerly PolicyGuard). Protected agent: DevAssist. Results from a real run - Claude Haiku 4.5 on Amazon Bedrock (us-east-1), commit 2c9a9aa. Every number traces to `eval/results/20261010T225704Z-2c9a9aa-bedrock.json`.

## 1. Threat scenario addressed
An AI coding agent uses tools from a third-party (MCP) server. A poisoned tool description instructs the agent to read a secret (a canary in `config/settings.yaml`) and pass it to an untrusted server, while every individual tool call looks legitimate. Kestrel supervises what the agent DOES across the tool chain and stops the leak, including obfuscated variants (encoded, truncated, or split across calls) and multi-step read-then-leak chains. Precedent: EchoLeak (CVE-2025-32711, Microsoft 365 Copilot).

## 2. NIST CSF functions covered
- **Identify**: tool registry scan inventories and risk-rates every MCP tool at connection; policy declares trusted/untrusted servers, sensitive paths, and canaries.
- **Protect**: hard invariants (allow-list, canary/secret block, sensitive-path block), least-privilege tool policy, step/tool/token budgets.
- **Detect**: ML risk gate + LLM Investigator score each action; every decision written to an audit log with the deciding layer.
- **Respond**: block/quarantine/escalate; analyst console with approve/block; kill switch stops the session; unanswered escalations fail closed to BLOCK.
- **Recover** (partial): audit trail supports post-incident review; sessions are isolated and replayable. (Govern is out of scope for a prototype.)

## 3. Techniques / risks addressed
**OWASP Top 10 for LLM / Agentic Apps**
- LLM01 Prompt Injection (indirect, via poisoned tool description)
- LLM02 Sensitive Information Disclosure (canary exfiltration)
- LLM06 Excessive Agency (tool misuse, over-reaching calls)
- LLM05 Improper Output / unsafe tool args passed onward

**MITRE ATLAS (AI system)**
- AML.T0051 LLM Prompt Injection
- AML.T0057 LLM Data Leakage / exfiltration via model output
- AML.T0053 LLM Plugin / tool compromise (malicious third-party tool)

**MITRE ATT&CK (enterprise, mapped to agent behaviour)**
- TA10 Exfiltration - T1041 Exfiltration Over C2 / untrusted channel
- T1552 Unsecured Credentials (reading secrets from config files)

## 4. Metrics achieved (real run, 28 chains / 56 steps)
- **Detection rate (harmful steps stopped)**: 80% (12/15 blocked or escalated). At chain level, 85.7% (12/14) of attacks prevented.
- **Attack success**: 100% (14/14) without the guard -> 14.3% (2/14) with it. Worst case (every escalation approved): 28.6% (4/14).
- **False positives**: 14.8% of benign steps stopped (4/27); 0 hard-block false positives on benign steps from the gate (misses were escalations, recoverable by an analyst). Benign tasks completed 71.4% (10/14) strict, 85.7% (12/14) after approval.
- **Time to detect & respond**: per-action, inline (blocks before the tool runs). Median 9ms per action (deterministic layers); p95 ~5.1s when the LLM Investigator is invoked. 75% of actions resolved automatically; analyst load 7.4 escalations per 100 benign steps.
- **Which layer caught what (attacks)**: hard invariants 7; Investigator blocked 3 + escalated 2; ML gate let 2 through.

## 5. Known limitations
- Two attacks passed the ML gate: a 16-char truncated canary and a canary split across two calls. By design the gate is a cheap first filter, not a guarantee; later layers and a destination canary tripwire cover these. Scoped fix: a canary-fragment signal in the gate.
- Small, custom test set written by us; not an independent benchmark. Scripted replay, so the "without guard" 100% holds by construction.
- No threshold tuning on this set. Confidence intervals are wide (n is small): attack success 95% CI 4-40%.
- Registry quarantine is shown in the console but did not fire inside the pipeline run (tool-name lookup mismatch, known, small fix).
- We supervise agent ACTIONS, not the foundation model's own safety training.

_All secrets in testing are FAKE canaries; all work was inside our own team account._
