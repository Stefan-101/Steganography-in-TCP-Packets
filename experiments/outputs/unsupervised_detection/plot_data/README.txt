Numerical data behind the unsupervised detection plots (LaTeX/pgfplots-ready CSVs).

plotF2c_operational.csv  -> plotF2c_extended_scenario2_operational.pdf (heatmap):
  per-detector x per-variant per-pcap detection rate, AUROC, TPR@5%FPR.
  Drawn directly by unsupervised_detection.py.

plotF4b_dilution.csv     -> plotF4b_extended_dilution_pcap_line_gmm.pdf, via gen_plotF4b_gmm.py:
  Recall@k mean/std and random baseline, per detector x variant x concentration.

plotF2b_hist_GMM.csv     -> plotF2b_extended_scenario2_score_distributions_gmm.pdf, via gen_plotF2b_gmm.py:
  80-bin density histograms; density_normal = bob_only+diverse clean, density_v3 = V3.
  plotF2b_hist_{IF,OCSVM}.csv hold the same histograms for the other two detectors.
plotF2b_score_summary.csv-> the 5% FPR threshold (vertical line) + V3 AUROC/TPR per detector.

anomaly score = -model.score_samples (higher = more anomalous); detectors fit on the
extended clean baseline (bob_only + diverse), V3 scored only. The CSVs are written by
../../scripts/analysis/unsupervised_detection.py with random_state=0.
