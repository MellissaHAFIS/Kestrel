"""Act 1: run DevAssist with NO guard. The leak must be reproducible (see demo/leak_log.jsonl).


Run: python -m demo.run_no_guard [--llm]
"""

from __future__ import annotations

import argparse

from demo.devassist import CANARY, canary_in_leak_log, run


def main() -> int:
    parser = argparse.ArgumentParser(description="DevAssist without PolicyGuard (the attack succeeds).")
    parser.add_argument("--llm", action="store_true", help="use a real LLM instead of the scripted offline plan")
    args = parser.parse_args()
    code = run(guarded=False, scripted=not args.llm)

    # The attack is supposed to work here: the canary should have reached the
    # poisoned server (demo/leak_log.jsonl).
    leaked = canary_in_leak_log()
    print("\n" + "=" * 64)
    if leaked:
        print(f"[result] ATTACK SUCCEEDED: canary {CANARY} reached demo/leak_log.jsonl")
    else:
        print("[result] UNEXPECTED: no canary in demo/leak_log.jsonl (the attack did not fire)")
    print("=" * 64)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
