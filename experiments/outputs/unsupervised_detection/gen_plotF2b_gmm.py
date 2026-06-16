"""GMM-only, single-panel version of the Scenario-2 score distributions.

Reads the histogram CSVs in plot_data/ (density_normal = bob_only + diverse clean
traffic, density_v3 = the V3 covert variant) and redraws the GMM panel of
plotF2b_extended_scenario2_score_distributions.pdf."""
import pathlib
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = pathlib.Path(__file__).parent
HIST = HERE / "plot_data" / "plotF2b_hist_GMM.csv"
SUMMARY = HERE / "plot_data" / "plotF2b_score_summary.csv"
OUT = HERE / "plotF2b_extended_scenario2_score_distributions_gmm.pdf"

DET = "GMM"

hist = pd.read_csv(HIST)
summ = pd.read_csv(SUMMARY).set_index("detector").loc[DET]
thr  = float(summ.threshold_5pctFPR)
tpr  = float(summ.tpr_v3)

left   = hist.bin_left.to_numpy()
width  = (hist.bin_right - hist.bin_left).to_numpy()

XMAX = 45.0   # clip the negligible GMM neg-log-likelihood tail past this point

fig, ax = plt.subplots(1, 1, figsize=(7, 4))

ax.bar(left, hist.density_normal.to_numpy(), width=width, align="edge",
       color="#1f77b4", alpha=0.6, label="normal traffic")
ax.bar(left, hist.density_v3.to_numpy(), width=width, align="edge",
       color="#d62728", alpha=0.6, label="traffic carrying covert channel")

ax.set_xlim(float(hist.bin_left.min()), XMAX)
ax.axvline(thr, color="k", ls="--", lw=1.4, label="5% FPR threshold")
ax.set_title("Gaussian Mixture Model", fontsize=12)
ax.set_xlabel("anomaly score")
ax.set_ylabel("Density")
ax.text(0.97, 0.95, f"covert traffic above thr\n(TPR@5%FPR) = {tpr:.3f}",
        transform=ax.transAxes, ha="right", va="top", fontsize=8,
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="0.6", alpha=0.85))
ax.legend(fontsize=8, loc="upper left")

fig.tight_layout()
fig.savefig(OUT)
print(f"Saved: {OUT}")
