"""Eval CLI: run variants on the frozen splits and print the headline table.

Owner: Person 4 (audit/console/eval).
First deliverable: live feed showing decisions; then eval harness.

Run: python -m eval.run_eval --variants 0 H --split validation
Rule: run --split test ONCE, on frozen thresholds.
"""

from __future__ import annotations

import argparse

from eval.variants import VARIANTS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PolicyGuard evaluation harness.")
    parser.add_argument("--variants", nargs="+", choices=sorted(VARIANTS), default=["0", "H"])
    parser.add_argument("--split", choices=["train", "validation", "test"], default="validation")
    parser.add_argument("--out", default=None, help="write results JSON here")
    args = parser.parse_args(argv)
    # TODO(person4): load eval/splits.json + eval/data/*.jsonl, run each variant over the split's
    #   chains/descriptions, compute eval.metrics, print the table (A vs H, 0 vs H on ASR).
    print(f"[eval] variants={args.variants} split={args.split}: TODO not implemented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
