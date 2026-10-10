"""Render the two-panel chart: attack success and benign tasks completed, without vs with the guard.

    python -m eval.chart eval/results/<run>.json --out chart.png

The chart is drawn only from a results file. A bar with no result shows [X]% and no fill.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

DARK, BLUE, TRACK, INK, AMBER, RED = "#14161f", "#2b4cff", "#eeece6", "#14161f", "#ff9f1c", "#c62828"


def _metric(res, variant, name):
    try:
        return res["variants"][variant]["metrics"][name]
    except (KeyError, TypeError):
        return None


def render_chart(res, out_path):
    """Draw the chart from a results dict (or None for the empty placeholder version)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    panels = [
        ("Attack success", "attack_success_rate", "asr_if_escalations_approved"),
        ("Benign tasks completed", "benign_completion_strict", "benign_completion_if_approved"),
    ]
    fig, axes = plt.subplots(2, 1, figsize=(13.33, 7.5), dpi=150)
    fig.subplots_adjust(left=0.17, right=0.80, top=0.72, bottom=0.17, hspace=0.95)

    for ax, (title, main, alt) in zip(axes, panels):
        ax.set_xlim(0, 100)
        ax.set_ylim(-0.6, 1.6)
        ax.set_yticks([1, 0])
        ax.set_yticklabels(["WITHOUT", "WITH GUARD"], fontfamily="monospace", fontsize=14, color="#555555")
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_xticklabels(["0", "25", "50", "75", "100%"])
        ax.tick_params(axis="x", labelsize=14, colors="#555555")
        ax.tick_params(axis="y", length=0)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color("#cccccc")
        ax.set_title(title, loc="left", fontsize=24, fontweight="bold", color=INK, pad=14)

        for y, variant, color in ((1, "0", DARK), (0, "H", BLUE)):
            ax.barh(y, 100, height=0.62, color=TRACK, zorder=1)
            p = _metric(res, variant, main)
            if p and p.get("value") is not None:
                v = 100 * p["value"]
                ax.barh(y, v, height=0.62, color=color, zorder=2)
                if variant == "H" and p.get("lo") is not None:
                    ax.errorbar(
                        v, y, xerr=[[max(0.0, v - 100 * p["lo"])], [max(0.0, 100 * p["hi"] - v)]],
                        fmt="none", ecolor=AMBER, elinewidth=3, capsize=7, capthick=3, zorder=4,
                    )
                label = f"{v:.1f}%  ({p['k']}/{p['n']})"
            else:
                label = "[X]%"
            ax.text(103, y, label, va="center", ha="left", fontsize=16, fontweight="bold", color=INK, clip_on=False)

        pa = _metric(res, "H", alt)
        if pa and pa.get("value") is not None:
            ax.plot([100 * pa["value"]], [0], marker="D", ms=13, mfc="white", mec=INK, mew=2,
                    linestyle="none", zorder=5)

    handles = [
        Line2D([0], [0], marker="s", color="none", mfc=DARK, mec=DARK, ms=14, label="without guard"),
        Line2D([0], [0], marker="s", color="none", mfc=BLUE, mec=BLUE, ms=14, label="with guard"),
        Line2D([0], [0], color=AMBER, lw=3, label="95% interval"),
        Line2D([0], [0], marker="D", color="none", mfc="white", mec=INK, ms=11, label="if escalations approved"),
    ]
    fig.legend(handles=handles, loc="upper right", bbox_to_anchor=(0.985, 0.985), ncol=2, frameon=False,
               prop={"family": "monospace", "size": 14}, columnspacing=1.5, handletextpad=0.4)

    stamp = (res or {}).get("stamp", {})
    counts = (res or {}).get("counts", {})
    has_results = bool(_metric(res, "H", "attack_success_rate"))
    if not has_results:
        banner = "NO RESULTS YET"
    elif stamp.get("headline_blockers"):
        banner = "NOT A HEADLINE RESULT: " + "; ".join(stamp["headline_blockers"])
    else:
        banner = ""
    if banner:
        fig.text(0.02, 0.88, textwrap.fill(banner, 70), color=RED, fontsize=15, fontweight="bold", va="top")

    dirty = " (uncommitted changes)" if stamp.get("dirty") else ""
    foot = (
        f"{counts.get('attack_chains', '?')} attack chains, {counts.get('benign_chains', '?')} benign chains, "
        f"{counts.get('steps', '?')} steps. Small custom set, scripted replay: the agent is assumed to attempt "
        "every step, so the without-guard bars hold by construction. "
        f"Investigator: {stamp.get('investigator', '?')}. "
        f"Commit {stamp.get('commit') or '?'}{dirty}, {str(stamp.get('started_utc', '?'))[:10]}."
    )
    fig.text(0.02, 0.02, textwrap.fill(foot, 112), fontsize=13, color="#444444", va="bottom")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, facecolor="white")
    plt.close(fig)
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Render the benchmark chart from a results JSON.")
    ap.add_argument("results", nargs="?", help="results JSON written by eval.run_eval (omit for placeholders)")
    ap.add_argument("--out", default="eval/results/chart.png")
    args = ap.parse_args(argv)
    res = json.loads(Path(args.results).read_text(encoding="utf-8")) if args.results else None
    try:
        path = render_chart(res, args.out)
    except ModuleNotFoundError as exc:
        print(f"matplotlib is required for the chart ({exc}). Install it with: pip install matplotlib", file=sys.stderr)
        return 2
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())