# Kestrel: 8-Slide Deck

**1. Title**
Kestrel (formerly PolicyGuard), a bodyguard for AI agents. Secure Horizons, Track 2. Tagline: AI proposes, rules guarantee, humans decide.

**2. The problem**
Agents call tools, often from third-party MCP servers. A poisoned tool description can make an agent leak a secret while every single call looks legitimate. Precedent: EchoLeak (CVE-2025-32711, Microsoft 365 Copilot). OWASP ranks goal hijack and tool misuse as top agent risks.

**3. Not another prompt filter**
That market is consolidated: Lakera (Check Point) and Prompt Security (SentinelOne) were both acquired in 2025. We supervise what agents DO across the tool chain, not the text going into one model.

**4. The solution**
Five layers, each with a visible job: registry scan, hard invariants, ML gate, Investigator agent, human console.

**5. Live demo**
DevAssist fixes the auth module. No guard: it reads settings.yaml, passes it in a hidden parameter, and the canary leaks. With guard: Tool A is quarantined at connection, the exact canary leak is blocked by an invariant, a paraphrased leak is investigated and escalated, and the analyst clicks Block.

**6. Humans stay in control**
Humans write the policy. Invariant blocks cannot be overridden by AI. Escalations wait for an analyst, and a timeout fails closed to BLOCK. Kill switch and a full audit trail.

**7. Results**
Real runs only: attack success with vs without the guard, benign tasks still completed, escalations per 100 actions. State plainly that the test set is small and custom. [Fill in numbers before presenting.]

**8. Limits and next steps**
Honest limits: the scanner can miss subtle poisoning, provenance is correlation, and the ML gate can be evaded. Next: an MCP gateway proxy, agent inventory, and public benchmarks (MCPTox, AgentDojo).