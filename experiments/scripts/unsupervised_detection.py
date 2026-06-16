#!/usr/bin/env python3
"""
Fits IF, OCSVM, and GMM detectors on clean traffic (bob_only + diverse public
servers) and scores three covert variants (V1/V2/V3). Reports window-level AUROC
and per-pcap detection rate at 5% FPR (Scenario 2), and pcap-level Recall@k
across dilution pools (Scenario 4b). Outputs go to outputs/unsupervised_detection/.
"""
import os
import csv
import glob
import json
import warnings

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

import features as ft

FN = ft.FEATURE_NAMES
BASE = ft.BASE
MITIG_DIR = os.path.join(BASE, "../captures/mitigated")
NOSLEEP_DIR = os.path.join(BASE, "../captures/mitigated_no_sleep")
BPP1_DIR = os.path.join(BASE, "../captures/1bpp")
G_DIR = os.path.join(BASE, "../outputs", "unsupervised_detection")

METHODS = ["IF", "OCSVM", "GMM"]

# (variant key, condition, pcap dir, display label)
VARIANTS = [
    ("V1", "proxy_mitigated", MITIG_DIR, "V1 (n=2, +sleep)"),
    ("V2", "proxy_mitigated_no_sleep", NOSLEEP_DIR, "V2 (n=2)"),
    ("V3", "proxy_mitigated_no_sleep_1bpp", BPP1_DIR, "V3 (n=1)"),
]

# Diverse clean captures, kept as feature-array caches in classifier_cache/.
# One server per label; run1 + run2 of each (both > 50 MB in the original run).
DIVERSE_BASELINES = [
    "baseline_online_fr_run1.pcap",
    "baseline_online_fr_run2.pcap",
    "baseline_ovh_fr_run1.pcap",
    "baseline_ovh_fr_run2.pcap",
    "baseline_tele2_se_run1.pcap",
    "baseline_tele2_se_run2.pcap",
]

# pcap-level dilution pools: (label, n_stego, n_clean, max_random_combos)
S4B_CONFIGS = (("10pct", 1, 9, 500), ("20pct", 2, 8, 500), ("33pct", 3, 7, 500))


# ---- detectors + anomaly scoring ----
def _models():
    """The three unsupervised detectors. None of them ever receives a label."""
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.mixture import GaussianMixture
    return {
        "IF": IsolationForest(n_estimators=200, contamination="auto", random_state=0),
        "OCSVM": OneClassSVM(kernel="rbf", nu=0.05, gamma="scale"),
        "GMM": GaussianMixture(n_components=1, covariance_type="full", random_state=0),
    }


def _anomaly(model, Xs):
    """Higher = more anomalous (negated score_samples)."""
    return -model.score_samples(Xs)


def _fit_clean(clean_X):
    """StandardScaler + the three detectors, fit only on the clean training matrix."""
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler().fit(clean_X)
    Xs = scaler.transform(clean_X)
    models = _models()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for m in models.values():
            m.fit(Xs)
    return scaler, models, Xs


# ---- Scenario 2: window-level detection ----
def scenario2(clean_df, variants_dfs):
    """Window-level AUROC and per-pcap detection rate at 5% FPR for each variant."""
    from sklearn.metrics import roc_auc_score
    scaler, models, Xcs = _fit_clean(clean_df[FN].to_numpy())
    clean_scores = {name: _anomaly(m, Xcs) for name, m in models.items()}
    thr = {name: float(np.percentile(s, 95)) for name, s in clean_scores.items()}

    # clean per-pcap false-positive rate at the same threshold (sanity check)
    clean_pcap_fpr = {}
    for name in models:
        fp, pcs = 0, clean_df["pcap"].unique()
        for p in pcs:
            mask = (clean_df["pcap"] == p).to_numpy()
            fp += int(clean_scores[name][mask].mean() > thr[name])
        clean_pcap_fpr[name] = {"fp": fp, "n": int(len(pcs)), "rate": fp / len(pcs)}

    res = {"auroc": {}, "tpr_at_fpr5": {}, "per_pcap_detection": {},
           "threshold": thr, "clean_pcap_fpr": clean_pcap_fpr,
           "n_clean_windows": int(len(Xcs))}
    for vk, vdf in variants_dfs.items():
        Xv = scaler.transform(vdf[FN].to_numpy())
        res["auroc"][vk], res["tpr_at_fpr5"][vk], res["per_pcap_detection"][vk] = {}, {}, {}
        for name, m in models.items():
            sv = _anomaly(m, Xv)
            y = np.concatenate([np.zeros(len(Xcs)), np.ones(len(Xv))])
            sc = np.concatenate([clean_scores[name], sv])
            res["auroc"][vk][name] = float(roc_auc_score(y, sc))
            res["tpr_at_fpr5"][vk][name] = float((sv > thr[name]).mean())
            det, pcs = 0, vdf["pcap"].unique()
            for p in pcs:
                mask = (vdf["pcap"] == p).to_numpy()
                det += int(sv[mask].mean() > thr[name])
            res["per_pcap_detection"][vk][name] = {"detected": det, "n": int(len(pcs)),
                                                   "rate": det / len(pcs)}
    return res


# ---- Scenario 4b: pcap-level dilution ----
def scenario4b(clean_df, variants_dfs, configs=S4B_CONFIGS, seed=0):
    """Pcap-level Recall@k across dilution pools of 10 at 10/20/33% stego concentration."""
    import itertools
    scaler, models, Xclean = _fit_clean(clean_df[FN].to_numpy())

    def per_pcap_means(df, Xs, model):
        sc = _anomaly(model, Xs)
        return {p: float(sc[(df["pcap"] == p).to_numpy()].mean()) for p in df["pcap"].unique()}

    clean_means = {m: per_pcap_means(clean_df, Xclean, models[m]) for m in METHODS}
    variant_scaled = {vk: scaler.transform(vdf[FN].to_numpy()) for vk, vdf in variants_dfs.items()}
    stego_means = {m: {vk: per_pcap_means(vdf, variant_scaled[vk], models[m])
                       for vk, vdf in variants_dfs.items()} for m in METHODS}

    clean_pcaps = list(clean_df["pcap"].unique())
    out = {m: {} for m in METHODS}
    for vk, vdf in variants_dfs.items():
        stego_pcaps = list(vdf["pcap"].unique())
        for label, n_stego, n_clean, cap in configs:
            pool_size, k = n_stego + n_clean, n_stego
            pairs = list(itertools.product(itertools.combinations(stego_pcaps, n_stego),
                                           itertools.combinations(clean_pcaps, n_clean)))
            n_total = len(pairs)
            capped = bool(cap is not None and n_total > cap)
            if capped:
                rng = np.random.default_rng(seed)               # identical pools for every detector
                pairs = [pairs[i] for i in rng.choice(n_total, size=cap, replace=False)]
            for m in METHODS:
                cm, sm = clean_means[m], stego_means[m][vk]
                recalls, perfect = [], 0
                for S, C in pairs:
                    ranked = sorted([(sm[s], 1) for s in S] + [(cm[c], 0) for c in C],
                                    key=lambda t: t[0], reverse=True)
                    hit = sum(lbl for _, lbl in ranked[:k])
                    recalls.append(hit / k)
                    perfect += int(hit == k)
                recalls = np.array(recalls)
                out[m].setdefault(vk, {})[label] = {
                    "n_stego_pcaps": n_stego, "n_clean_pcaps": n_clean, "pool_size": pool_size, "k": k,
                    "stego_fraction": n_stego / pool_size,
                    "n_combinations_used": len(pairs), "n_combinations_total": n_total, "capped": capped,
                    "recall_at_k_mean": float(recalls.mean()), "recall_at_k_std": float(recalls.std()),
                    "perfect_detection_rate": float(perfect / len(pairs)),
                    "random_baseline": k / pool_size,
                }
    return out


# ---- data assembly ----
def _workers():
    return max(1, min(8, (os.cpu_count() or 2) - 2))


def _frame(paths, condition, label):
    """Per-window feature DataFrame for the given pcaps (cached on first run)."""
    ft.build_cache(paths, workers=_workers())
    frames = []
    for p in paths:
        name = os.path.basename(p)
        rows = ft.windows_of(name)
        if not rows:
            print(f"  [warn] {name}: no windows produced")
            continue
        df = pd.DataFrame(rows, columns=FN)
        df["pcap"] = name
        df["condition"] = condition
        df["label"] = label
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    out[FN] = np.nan_to_num(out[FN].to_numpy(), nan=0.0, posinf=0.0, neginf=0.0)
    return out


def _diverse_frame(name):
    """Per-window feature DataFrame for one diverse baseline, read from its npz cache."""
    cache = os.path.join(ft.CACHE_DIR, name + ".npz")
    if not os.path.exists(cache):
        raise SystemExit(f"missing cached baseline {cache}\n"
                         "the diverse captures ship as feature arrays only; "
                         "do not delete classifier_cache/baseline_*.npz")
    label = name[len("baseline_"):-len(".pcap")].rsplit("_run", 1)[0]
    df = pd.DataFrame(ft.windows_of(name), columns=FN)
    df["pcap"] = name
    df["condition"] = "diverse_" + label
    df["label"] = 0
    df[FN] = np.nan_to_num(df[FN].to_numpy(), nan=0.0, posinf=0.0, neginf=0.0)
    return df


def build_clean_baseline():
    """Extended clean baseline = bob_only + the diverse public-server captures."""
    bob_paths = sorted(glob.glob(os.path.join(ft.OVERHEAD_DIR, "*_bob_only.pcap")))
    if not bob_paths:
        raise SystemExit(f"no bob_only pcaps in {ft.OVERHEAD_DIR}")
    bob_only = _frame(bob_paths, "bob_only", 0)
    diverse = [_diverse_frame(n) for n in DIVERSE_BASELINES]
    extended = pd.concat([bob_only] + diverse, ignore_index=True)
    n_sources = 1 + len({d["condition"].iloc[0] for d in diverse})
    print(f"\n[clean baseline] {len(extended)} windows "
          f"(bob_only={len(bob_only)}, diverse={len(extended) - len(bob_only)} "
          f"over {len(diverse)} pcaps, {n_sources} clock sources)")
    return extended, bob_only


def build_variants():
    out = {}
    for vk, cond, d, _ in VARIANTS:
        paths = sorted(glob.glob(os.path.join(d, "*.pcap")))
        if not paths:
            raise SystemExit(f"no pcaps in {d}")
        out[vk] = _frame(paths, cond, 1)
    return out


# ---- figure: F2c operational heatmap (F2b and F4b are drawn from the CSVs by gen_plot*.py) ----
def plot_operational(s2, path):
    """Heatmap of per-pcap detection rate at 5% FPR, annotated with AUROC per cell."""
    vk = ["V1", "V2", "V3"]
    vlab = [v[3] for v in VARIANTS]
    det, auc = s2["per_pcap_detection"], s2["auroc"]
    M = np.array([[det[v][m]["rate"] for m in METHODS] for v in vk])
    cmap = LinearSegmentedColormap.from_list("white_green", ["white", "#006d2c"])
    fig, ax = plt.subplots(figsize=(7, 1.6 + 1.0 * len(vk)))
    im = ax.imshow(M, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")
    ax.set_xticks(range(len(METHODS))); ax.set_xticklabels(METHODS)
    ax.set_yticks(range(len(vk))); ax.set_yticklabels(vlab)
    for i, v in enumerate(vk):
        for j, m in enumerate(METHODS):
            d = det[v][m]
            col = "white" if d["rate"] >= 0.6 else "black"
            ax.text(j, i - 0.12, f"{d['detected']}/{d['n']}", ha="center", va="center",
                    fontsize=13, fontweight="bold", color=col)
            ax.text(j, i + 0.20, f"AUC={auc[v][m]:.3f}", ha="center", va="center",
                    fontsize=8, color=col)
    ax.set_title("Per-pcap detection rate at 5% FPR (extended baseline)")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="per-pcap detection rate (detected / 10)")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---- pgfplots-ready CSVs behind the figures ----
def export_plot_data(s2, s4b, clean_df, v3_df, outdir):
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, "plotF2c_operational.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["detector", "variant", "per_pcap_detected", "per_pcap_n", "per_pcap_rate",
                     "auroc", "tpr_at_fpr5"])
        for v in ("V1", "V2", "V3"):
            for det in METHODS:
                pp = s2["per_pcap_detection"][v][det]
                wr.writerow([det, v, pp["detected"], pp["n"], f"{pp['rate']:.6f}",
                             f"{s2['auroc'][v][det]:.6f}", f"{s2['tpr_at_fpr5'][v][det]:.6f}"])

    with open(os.path.join(outdir, "plotF4b_dilution.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["detector", "variant", "concentration_label", "concentration_pct", "k",
                     "pool_size", "recall_mean", "recall_std", "random_baseline"])
        for det in METHODS:
            for v in ("V1", "V2", "V3"):
                for c in ("10pct", "20pct", "33pct"):
                    r = s4b[det][v][c]
                    wr.writerow([det, v, c, round(r["stego_fraction"] * 100), r["k"], r["pool_size"],
                                 f"{r['recall_at_k_mean']:.6f}", f"{r['recall_at_k_std']:.6f}",
                                 f"{r['random_baseline']:.6f}"])

    # score-distribution histograms: refit on the clean baseline (same as the figure), score, bin
    scaler, models, Xclean = _fit_clean(clean_df[FN].to_numpy())
    Xv3 = scaler.transform(v3_df[FN].to_numpy())

    with open(os.path.join(outdir, "plotF2b_score_summary.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["detector", "threshold_5pctFPR", "auroc_v3", "tpr_v3",
                     "n_normal_windows", "n_v3_windows"])
        for det in METHODS:
            wr.writerow([det, f"{s2['threshold'][det]:.6f}", f"{s2['auroc']['V3'][det]:.6f}",
                         f"{s2['tpr_at_fpr5']['V3'][det]:.6f}", len(Xclean), len(Xv3)])

    for det in METHODS:
        n_s, v_s = _anomaly(models[det], Xclean), _anomaly(models[det], Xv3)
        thr = s2["threshold"][det]
        alls = np.concatenate([n_s, v_s])
        lo, hi = float(np.percentile(alls, 0.5)), float(np.percentile(alls, 99.0))
        lo, hi = min(lo, thr), max(hi, thr)
        pad = 0.03 * (hi - lo) or 1.0
        lo, hi = lo - pad, hi + pad
        bins = np.linspace(lo, hi, 81)
        dn, _ = np.histogram(n_s, bins=bins, density=True)
        dv, _ = np.histogram(v_s, bins=bins, density=True)
        with open(os.path.join(outdir, f"plotF2b_hist_{det}.csv"), "w", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(["bin_left", "bin_right", "bin_center", "density_normal", "density_v3"])
            for i in range(len(dn)):
                wr.writerow([f"{bins[i]:.6f}", f"{bins[i + 1]:.6f}", f"{(bins[i] + bins[i + 1]) / 2:.6f}",
                             f"{dn[i]:.6f}", f"{dv[i]:.6f}"])

    print(f"  wrote plot data to {outdir}")


def _json_safe(obj):
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    return obj


def main():
    os.makedirs(G_DIR, exist_ok=True)
    extended, bob_only = build_clean_baseline()
    variants = build_variants()

    print("\n[Scenario 2] fit IF/OCSVM/GMM on the extended baseline, score each variant")
    s2 = scenario2(extended, variants)
    print(f"  {'variant':<8}" + "".join(f"{m:>10}" for m in METHODS))
    for vk, _, _, _ in VARIANTS:
        print(f"  {vk:<8}" + "".join(f"{s2['auroc'][vk][m]:>10.3f}" for m in METHODS))

    print("\n[Scenario 4b] pcap-level dilution (pools of 10)")
    s4b = scenario4b(extended, variants)

    v3 = variants["V3"]
    plot_operational(s2, os.path.join(G_DIR, "plotF2c_extended_scenario2_operational.pdf"))
    export_plot_data(s2, s4b, extended, v3, os.path.join(G_DIR, "plot_data"))

    metrics = {
        "extended_baseline_composition": {
            "total_windows": int(len(extended)),
            "bob_only_windows": int(len(bob_only)),
            "diverse_windows": int(len(extended) - len(bob_only)),
            "n_clean_pcaps": int(extended["pcap"].nunique()),
            "diverse_baselines": DIVERSE_BASELINES,
        },
        "scenario2_extended_baseline": s2,
        "scenario4b_extended": s4b,
        "config": {
            "detectors": METHODS,
            "window": ft.WINDOW, "step": ft.STEP,
            "fpr_threshold_pct": 5,
            "scenario4b_pools": "10/20/33% stego, pools of 10, up to 500 random combos per config",
            "leakage_guard": "detectors fit on clean (bob_only + diverse) only; stego scored only",
            "random_state": 0,
        },
    }
    with open(os.path.join(G_DIR, "metrics_unsupervised_detection.json"), "w") as f:
        json.dump(_json_safe(metrics), f, indent=2)
    print(f"\n[done] outputs in {G_DIR}")


if __name__ == "__main__":
    main()
