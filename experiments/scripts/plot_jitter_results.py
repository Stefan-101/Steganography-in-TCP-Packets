#!/usr/bin/env python3
import csv
import math
import os
import sys
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import fisher_exact, mannwhitneyu

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../jitter_results")
CSV_PATH = os.path.join(RESULTS_DIR, "results.csv")

JITTER_COLORS = {0: "#d62728", 1: "#1f77b4"}   # red = disabled, blue = enabled
JITTER_LABELS = {0: "jitter disabled", 1: "jitter enabled"}


def load_rows(path):
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "reorder_pct": int(r["reorder_pct"]),
                "jitter_enabled": int(r["jitter_enabled"]),
                "run": int(r["run"]),
                "success": r["success"].strip().lower() == "true",
                "ber": float(r["ber"]),
            })
    return rows


def group(rows):
    """Returns dict[(reorder, jitter)] -> list of rows."""
    g = defaultdict(list)
    for r in rows:
        g[(r["reorder_pct"], r["jitter_enabled"])].append(r)
    return g


def grouped_bar(ax, reorders, vals_off, vals_on, err_off=None, err_on=None,
                ylabel="", title=""):
    x = np.arange(len(reorders))
    w = 0.38
    bars_off = ax.bar(x - w / 2, vals_off, w, color=JITTER_COLORS[0],
                      label=JITTER_LABELS[0],
                      yerr=err_off if err_off is not None else None,
                      capsize=4, ecolor="black")
    bars_on = ax.bar(x + w / 2, vals_on, w, color=JITTER_COLORS[1],
                     label=JITTER_LABELS[1],
                     yerr=err_on if err_on is not None else None,
                     capsize=4, ecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{r}%" for r in reorders])
    ax.set_xlabel("netem reorder percentage")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_ylim(bottom=0)
    ax.legend(loc="best")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    for bars, vals in ((bars_off, vals_off), (bars_on, vals_on)):
        for b, v in zip(bars, vals):
            ax.annotate(f"{v:.2f}", xy=(b.get_x() + b.get_width() / 2, v),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8)


def main():
    if not os.path.exists(CSV_PATH):
        print(f"results not found: {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    rows = load_rows(CSV_PATH)
    g = group(rows)
    reorders = sorted({r for r, _ in g.keys()})

    summary_rows = []
    mean_ber_off, mean_ber_on = [], []
    std_ber_off, std_ber_on = [], []

    for reorder in reorders:
        for jitter in (0, 1):
            cell = g.get((reorder, jitter), [])
            n = len(cell)
            successes = sum(1 for r in cell if r["success"])
            mean_ber = float(np.mean([r["ber"] for r in cell])) if cell else float("nan")
            summary_rows.append((reorder, jitter, n, successes, mean_ber))

    for reorder in reorders:
        cell_off = g.get((reorder, 0), [])
        cell_on = g.get((reorder, 1), [])
        bers_off = [r["ber"] for r in cell_off]
        bers_on = [r["ber"] for r in cell_on]
        mean_ber_off.append(float(np.mean(bers_off)) if bers_off else 0.0)
        mean_ber_on.append(float(np.mean(bers_on)) if bers_on else 0.0)
        std_ber_off.append(float(np.std(bers_off, ddof=1) / math.sqrt(len(bers_off)))
                           if len(bers_off) > 1 else 0.0)
        std_ber_on.append(float(np.std(bers_on, ddof=1) / math.sqrt(len(bers_on)))
                          if len(bers_on) > 1 else 0.0)

    # ---- Plot: BER ----
    fig, ax = plt.subplots(figsize=(8, 5))
    grouped_bar(
        ax, reorders, mean_ber_off, mean_ber_on,
        err_off=std_ber_off, err_on=std_ber_on,
        ylabel="mean BER",
        title="Jitter buffer ablation: byte error rate",
    )
    out = os.path.join(RESULTS_DIR, "ber.pdf")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)

    # ---- Summary table with significance tests ----
    print(f"\nLoaded {len(rows)} runs from {CSV_PATH}")
    print(f"Wrote {out}\n")

    header = ("reorder_pct", "jitter", "n", "successes", "success_rate", "mean_ber")
    print(f"{header[0]:>11} | {header[1]:>6} | {header[2]:>3} | "
          f"{header[3]:>9} | {header[4]:>12} | {header[5]:>9}")
    print("-" * 75)
    for (reorder, jitter, n, k, mb) in summary_rows:
        sr = (k / n) if n else float("nan")
        print(f"{reorder:>11} | {jitter:>6} | {n:>3} | {k:>9} | "
              f"{sr:>12.3f} | {mb:>9.4f}")

    # Per-reorder significance: jitter on vs off
    print("\nPer-reorder significance (jitter ON vs OFF):")
    print(f"{'reorder_pct':>11} | {'fisher_p (success)':>20} | {'mw_p (ber)':>12} | "
          f"{'success significant?':>22} | {'ber significant?':>18}")
    print("-" * 100)
    for reorder in reorders:
        cell_off = g.get((reorder, 0), [])
        cell_on = g.get((reorder, 1), [])
        k_off = sum(1 for r in cell_off if r["success"])
        k_on = sum(1 for r in cell_on if r["success"])
        n_off, n_on = len(cell_off), len(cell_on)
        table = [[k_on, n_on - k_on], [k_off, n_off - k_off]]
        try:
            _, fisher_p = fisher_exact(table)
        except Exception:
            fisher_p = float("nan")

        bers_off = [r["ber"] for r in cell_off]
        bers_on = [r["ber"] for r in cell_on]
        if bers_off and bers_on and (len(set(bers_off)) > 1 or len(set(bers_on)) > 1):
            try:
                _, mw_p = mannwhitneyu(bers_on, bers_off, alternative="two-sided")
            except ValueError:
                mw_p = float("nan")
        else:
            mw_p = float("nan") if bers_off == bers_on else 0.0

        sig_succ = "yes" if (not math.isnan(fisher_p)) and fisher_p < 0.05 else "no"
        sig_ber = "yes" if (not math.isnan(mw_p)) and mw_p < 0.05 else "no"
        print(f"{reorder:>11} | {fisher_p:>20.4g} | {mw_p:>12.4g} | "
              f"{sig_succ:>22} | {sig_ber:>18}")


if __name__ == "__main__":
    main()
