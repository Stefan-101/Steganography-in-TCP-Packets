"""GMM-only, single-panel version of the Scenario-4b dilution figure,
drawn from plot_data/plotF4b_dilution.csv."""
import pathlib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

HERE = pathlib.Path(__file__).parent
CSV = HERE / "plot_data" / "plotF4b_dilution.csv"
OUT = HERE / "plotF4b_extended_dilution_pcap_line_gmm.pdf"

df = pd.read_csv(CSV)

DETECTORS = ["GMM"]
VARIANTS = [("V1", "#1f77b4"), ("V2", "#ff7f0e"), ("V3", "#d62728")]
CONCS = ["10pct", "20pct", "33pct"]
XLABELS = ["10%", "20%", "30%"]
x = np.arange(len(CONCS))

# --- compute shared y-limits ---
lo, hi = 0.0, 0.3
for det in DETECTORS:
    for vk, _ in VARIANTS:
        for c in CONCS:
            row = df[(df.detector == det) & (df.variant == vk) & (df.concentration_label == c)]
            mn  = float(row.recall_mean.iloc[0])
            sd  = float(row.recall_std.iloc[0])
            lo  = min(lo, mn - sd)
            hi  = max(hi, mn + sd)
ylo = min(lo - 0.06, -0.12)
yhi = hi + 0.08

# --- figure: 1 row x 1 col ---
fig, axes = plt.subplots(1, 1, figsize=(7, 4), sharey=True)
axes = np.atleast_1d(axes)
fig.subplots_adjust(hspace=0.45)

for ax, det in zip(axes, DETECTORS):
    for vk, col in VARIANTS:
        means = np.array([
            float(df[(df.detector==det)&(df.variant==vk)&(df.concentration_label==c)].recall_mean.iloc[0])
            for c in CONCS
        ])
        stds = np.array([
            float(df[(df.detector==det)&(df.variant==vk)&(df.concentration_label==c)].recall_std.iloc[0])
            for c in CONCS
        ])
        ax.plot(x, means, "-o", color=col, lw=2, label=vk, zorder=3)
        ax.fill_between(x, means - stds, means + stds, color=col, alpha=0.15, zorder=1)
        for xi, mn in zip(x, means):
            ax.annotate(f"{mn:.3f}", (xi, mn),
                        textcoords="offset points", xytext=(0, 8),
                        ha="center", fontsize=8, color=col, fontweight="bold", zorder=4)

    # random baseline (diagonal through 3 points)
    baseline = np.array([
        float(df[(df.detector==det)&(df.variant=="V1")&(df.concentration_label==c)].random_baseline.iloc[0])
        for c in CONCS
    ])
    ax.plot(x, baseline, "k--", lw=1.5, label="random baseline", zorder=2)
    ax.axhline(0.0, color="gray", lw=0.8, alpha=0.6, zorder=0)

    ax.set_xticks(x)
    ax.set_xticklabels(XLABELS, fontsize=10)
    ax.set_xlim(-0.35, 2.35)
    ax.set_ylim(ylo, yhi)
    ax.set_title("Gaussian Mixture Model", fontsize=13, fontweight="bold")
    ax.set_ylabel("mean Recall@k", fontsize=9)
    ax.set_xlabel("covert-channel concentration", fontsize=9)
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.1f"))
    ax.grid(axis="y", alpha=0.4)
    if ax is axes[0]:
        ax.legend(fontsize=9, loc="upper left", framealpha=0.9)

fig.savefig(OUT, bbox_inches="tight", dpi=200)
print(f"Saved: {OUT}")
