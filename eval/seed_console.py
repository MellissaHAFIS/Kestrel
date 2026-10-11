"""Populate the analyst console's audit DB with REAL escalations for the demo.

Replays the benchmark chains through the real guard pipeline and writes every
decision to policyguard_audit.db, the database console/app.py reads. Escalations
then show up as incident cards in the console `queue`.

    # offline (MockLLM reasoning, flat 0.35 confidence):
    python -m eval.seed_console

    # real Claude on Bedrock (varied, genuine reasoning) -- run where AWS creds work:
    export LLM_PROVIDER=bedrock AWS_REGION=us-east-1
    python -m eval.seed_console --mode bedrock

Safe to re-run: it clears policyguard_audit.db first so the queue is not a pile-up
of old runs. Every secret in the chains is FAKE.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DB = REPO / "policyguard_audit.db"
BEDROCK_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


async def _run(mode: str, throttle: float) -> int:
    os.chdir(REPO)
    os.environ.setdefault("POLICYGUARD_POLICY", str(REPO / "policy" / "devassist.yaml"))

    import dataclasses

    from policyguard.audit import audit_log
    from policyguard.config import load_config
    from policyguard.investigator.llm import MockLLM, build_llm
    from policyguard.pipeline import run_pipeline
    from policyguard.types import Action
    from eval.cases import CHAINS

    if mode == "bedrock":
        os.environ["MOCK_LLM"] = "0"
        os.environ["LLM_PROVIDER"] = "bedrock"
        os.environ.setdefault("AWS_REGION", "us-east-1")
        os.environ.pop("ANTHROPIC_API_KEY", None)
        cfg = load_config()
        cfg = dataclasses.replace(
            cfg, mock_mode=False,
            llm=dataclasses.replace(cfg.llm, provider="bedrock", model=BEDROCK_MODEL),
        )
        client = build_llm(cfg)
        if isinstance(client, MockLLM):
            print("ERROR: bedrock requested but fell back to MockLLM. Check AWS creds in this shell.", file=sys.stderr)
            return 2
        print(f"[seed] real mode: Claude on Bedrock ({os.environ['AWS_REGION']}); fake secrets only", flush=True)
    else:
        os.environ["MOCK_LLM"] = "1"
        client = MockLLM()
        print("[seed] mock mode: offline MockLLM reasoning", flush=True)

    if DB.exists():
        DB.unlink()  # start clean so the console queue reflects only this run
    await audit_log.init(str(DB))

    escalations = 0
    for n, c in enumerate(CHAINS, start=1):
        session_id = f"demo-{c['id']}"
        decisions = []
        for s in c["steps"]:
            a = Action(session_id=session_id, tool_name=f"{s['server']}.{s['tool']}",
                       args=dict(s["args"]), sources=list(s["sources"]))
            v = await run_pipeline(a, llm=client)
            decisions.append(v.decision)
            if v.decision == "escalate":
                escalations += 1
            if throttle:
                await asyncio.sleep(throttle)
        print(f"[{n:>2}/{len(CHAINS)}] {c['id']}: {' '.join(decisions)}", flush=True)

    rows = await audit_log.get_all_escalations(100)
    print(f"[seed] done: {escalations} escalations written, {len(rows)} queryable in {DB.name}", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Seed the console audit DB with escalations.")
    ap.add_argument("--mode", choices=["mock", "bedrock"], default="mock")
    ap.add_argument("--throttle", type=float, default=None, help="pause between calls (default 1.1 for bedrock)")
    args = ap.parse_args(argv)
    throttle = args.throttle if args.throttle is not None else (1.1 if args.mode == "bedrock" else 0.0)
    return asyncio.run(_run(args.mode, throttle))


if __name__ == "__main__":
    raise SystemExit(main())