"""Act 1: run DevAssist with NO guard. The leak must be reproducible (see demo/leak_log.jsonl).

Owner: Person 1 (demo env).
First deliverable: attack works with no guard; every call produces an Action.

Run: python -m demo.run_no_guard [--llm]
"""

from __future__ import annotations

import argparse

from demo.devassist import run


def main() -> int:
    parser = argparse.ArgumentParser(description="DevAssist without PolicyGuard (the attack succeeds).")
    parser.add_argument("--llm", action="store_true", help="use a real LLM instead of the scripted offline plan")
    args = parser.parse_args()
    # TODO(person1): after the run, print whether the canary reached demo/leak_log.jsonl
    return run(guarded=False, scripted=not args.llm)


if __name__ == "__main__":
    raise SystemExit(main())
