"""Act 2: run DevAssist behind PolicyGuard. Each layer has a visible job.


Run: python -m demo.run_guarded [--llm]
Expected: Tool A quarantined (registry), Tool B exact leak blocked (invariant),
paraphrased partial leak escalated (Investigator).
"""

from __future__ import annotations

import argparse

from demo.devassist import CANARY, canary_in_leak_log, run


def main() -> int:
    parser = argparse.ArgumentParser(description="DevAssist with PolicyGuard enabled.")
    parser.add_argument("--llm", action="store_true", help="use a real LLM instead of the scripted offline plan")
    args = parser.parse_args()
    code = run(guarded=True, scripted=not args.llm)

    # With the guard on, the poisoned calls must be blocked: the canary should
    # NOT appear in demo/leak_log.jsonl.
    leaked = canary_in_leak_log()
    print("\n" + "=" * 64)
    if leaked:
        print(f"[result] FAIL: canary {CANARY} still reached demo/leak_log.jsonl")
        code = code or 1
    else:
        print("[result] PASS: PolicyGuard blocked the leak; no canary in demo/leak_log.jsonl")
    print("=" * 64)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
