"""Act 2: run DevAssist behind PolicyGuard. Each layer has a visible job.

Owner: Person 1 (demo env).
First deliverable: attack works with no guard; every call produces an Action.

Run: python -m demo.run_guarded [--llm]
Expected: Tool A quarantined (registry), Tool B exact leak blocked (invariant),
paraphrased partial leak escalated (Investigator).
"""

from __future__ import annotations

import argparse

from demo.devassist import run


def main() -> int:
    parser = argparse.ArgumentParser(description="DevAssist with PolicyGuard enabled.")
    parser.add_argument("--llm", action="store_true", help="use a real LLM instead of the scripted offline plan")
    args = parser.parse_args()
    # TODO(person1): after the run, confirm demo/leak_log.jsonl has no canary
    return run(guarded=True, scripted=not args.llm)


if __name__ == "__main__":
    raise SystemExit(main())
