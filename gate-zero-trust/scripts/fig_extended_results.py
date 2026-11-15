"""Extended-corpus profile: recall by category and one-layer-removed cost.

Both panels are read from the full-pipeline evaluation artefact, so the figure
cannot drift from the numbers in the text.

    USE_TF=0 python scripts/fig_extended_results.py \
        --artifact target/audit_replay/evaluation.json \
        --out ../paper/build/fig_extended_261115.png
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

BLUE, AMBER, GREY = "#1f5bd6", "#f5a623", "#6b7280"
ORDER = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "X"]
REMOVED = [
    "contracts", "capability", "semantic", "ifc", "workflow", "hitl", "dcbf",
]
LABEL = {
    "contracts": "contracts", "capability": "capability", "semantic": "semantic",
    "ifc": "IFC", "workflow": "workflow (DFA)", "hitl": "HITL", "dcbf": "barrier (D-CBF)",
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    d = json.loads(args.artifact.read_text(encoding="utf-8"))
    full = d["configurations"]["full"]

    cats = [ORDER[i] for i in range(len(ORDER)) if ORDER[i] in d["per_category"]]
    y = list(range(len(cats)))
    fig, (ax, bx) = plt.subplots(
        1, 2, figsize=(6.8, 3.4), gridspec_kw={"width_ratios": [1.55, 1]}
    )

    for i, c in enumerate(cats):
        r = d["per_category"][c]
        colour = AMBER if c == "X" else BLUE
        ax.barh(i, r["recall"], color=colour, height=0.72)
        lo, hi = r["recall_ci95"]
        ax.plot([lo, hi], [i, i], color="#111827", lw=0.9, solid_capstyle="butt")
        ax.text(min(hi + 0.015, 1.06), i, f"{100*r['recall']:.0f}", va="center",
                ha="left", fontsize=7.5, color="#111827")

    ax.axvline(full["recall"], color=GREY, lw=1.0, ls="--")
    ax.text(full["recall"] - 0.01, -0.55,
            f"all {100*full['recall']:.1f}", ha="right", va="center",
            fontsize=7.5, color=GREY)
    ax.set_yticks(y)
    ax.set_yticklabels([f"{c}  ({d['per_category'][c]['attacks']})" for c in cats], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.12)
    ax.set_ylim(len(cats) - 0.4, -0.9)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0", ".25", ".50", ".75", "1.0"], fontsize=8)
    ax.set_xlabel("recall", fontsize=9)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)

    base = full["recall"]
    ry = list(range(len(REMOVED)))
    for i, stage in enumerate(REMOVED):
        a = d["ablations"][stage]
        drop = a["recall"] - base
        bx.barh(i, drop, color="#d62728", height=0.66)
        bx.text(drop - 0.004, i, f"{100*drop:+.0f}", va="center", ha="right",
                fontsize=7.5)
    bx.set_yticks(ry)
    bx.set_yticklabels([LABEL[s] for s in REMOVED], fontsize=8.5)
    bx.invert_yaxis()
    bx.axvline(0, color="#111827", lw=0.8)
    bx.set_xlim(-0.165, 0.012)
    bx.set_xticks([-0.15, -0.10, -0.05, 0])
    bx.set_xticklabels(["-15", "-10", "-5", "0"], fontsize=8)
    bx.set_xlabel("recall change (points)", fontsize=8.5)
    for side in ("top", "right"):
        bx.spines[side].set_visible(False)

    fig.tight_layout(w_pad=1.2)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, dpi=300)
    print("wrote", args.out)

    print("recall by category:", {c: round(d["per_category"][c]["recall"], 4) for c in cats})
    print("one-layer-removed:", {s: round(d["ablations"][s]["recall"] - base, 4) for s in REMOVED})


if __name__ == "__main__":
    main()
