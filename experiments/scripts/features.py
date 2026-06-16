#!/usr/bin/env python3
"""
TSval covert-channel feature extraction.

Each pcap is parsed once: we keep the Bob->Alice (5.78.142.121 -> 62.238.11.80)
TCP packets that carry a TCP Timestamp option and cache the (tsval, is_data,
time) arrays to classifier_cache/<name>.npz, so later runs do not re-parse.

A 200-packet / 100-step sliding window over each flow's Bob->Alice stream is
turned into a 27-feature vector (see FEATURE_NAMES): 2-LSB symbol statistics,
per-bit probabilities, Cabuk regularity, TSval consecutive-difference stats and
inter-packet delay stats.
"""
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

import numpy as np

BOB = "5.78.142.121"      # server side, capture host
ALICE = "62.238.11.80"

BASE = os.path.dirname(os.path.abspath(__file__))
OVERHEAD_DIR = os.path.join(BASE, "../captures/overhead")
CACHE_DIR = os.path.join(BASE, "../classifier_cache")

WINDOW = 200          # packets per sliding window (Bob->Alice stream)
STEP = 100            # window step (50% overlap)
MAX_DIFF = 1000       # discard TSval consecutive diffs outside [0, MAX_DIFF]
N_BITS = 8            # P(bit=1) for bits 0..7

# Canonical 27-feature ordering and human-readable names.
FEATURE_NAMES = (
    ["freq_00", "freq_01", "freq_10", "freq_11"]          # 2-LSB symbol frequencies
    + ["chi2_2lsb"]                                        # chi2 of 2-LSB dist vs uniform
    + [f"p_bit{i}" for i in range(N_BITS)]                 # P(bit=1), bits 0..7
    + ["cabuk_eps_1ms", "cabuk_eps_5ms"]                  # Cabuk regularity at delta 1/5
    + ["chi2_bit0", "chi2_bit1"]                           # chi2 per-bit dist vs 50/50
    + ["tsdiff_mean", "tsdiff_std", "tsdiff_median",
       "tsdiff_p75", "tsdiff_p90", "tsdiff_p99", "tsdiff_mode"]
    + ["ipd_mean_ms", "ipd_std_ms", "ipd_cv"]
)
assert len(FEATURE_NAMES) == 27, len(FEATURE_NAMES)

# ---- Stage 1: pcap extraction (one pass, cached) ----
def _extract_raw(path):
    """
    Scan one pcap; return the Bob->Alice TCP packets that carry a Timestamp option.

    Returns (tsvals[int64], is_data[bool], times[float64], n_b2a, n_no_ts):
    n_b2a = total Bob->Alice TCP packets, n_no_ts = how many lacked a Timestamp option.
    """
    from scapy.all import PcapReader, IP, TCP  # imported in worker for spawn safety
    tsvals, is_data, times = [], [], []
    n_b2a = 0
    n_no_ts = 0
    with PcapReader(path) as pr:
        for pkt in pr:
            if IP not in pkt or TCP not in pkt:
                continue
            ip = pkt[IP]
            if ip.src != BOB or ip.dst != ALICE:
                continue
            tcp = pkt[TCP]
            n_b2a += 1
            ts = None
            for opt in tcp.options:
                if isinstance(opt, tuple) and opt[0] == "Timestamp":
                    ts = opt[1][0]
                    break
            if ts is None:
                n_no_ts += 1
                continue
            tsvals.append(int(ts))
            is_data.append(len(tcp.payload) > 0)
            times.append(float(pkt.time))
    return (np.asarray(tsvals, dtype=np.int64),
            np.asarray(is_data, dtype=bool),
            np.asarray(times, dtype=np.float64),
            n_b2a, n_no_ts)


def extract_to_cache(path):
    """Worker: extract one pcap and write its .npz cache. Returns a small summary."""
    name = os.path.basename(path)
    cache = os.path.join(CACHE_DIR, name + ".npz")
    if os.path.exists(cache):
        d = np.load(cache)
        return name, int(d["tsvals"].size), int(d["n_b2a"]), int(d["n_no_ts"]), True
    tsvals, is_data, times, n_b2a, n_no_ts = _extract_raw(path)
    np.savez_compressed(cache, tsvals=tsvals, is_data=is_data, times=times,
                        n_b2a=np.int64(n_b2a), n_no_ts=np.int64(n_no_ts))
    return name, int(tsvals.size), int(n_b2a), int(n_no_ts), False


def build_cache(pcap_paths, workers):
    """Extract every pcap to cache, in parallel where possible."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    todo = list(pcap_paths)
    print(f"[extract] {len(todo)} pcaps  (cache dir: {CACHE_DIR})")
    results = {}

    def record(r):
        name, n_kept, n_b2a, n_no_ts, cached = r
        tag = "cached" if cached else "parsed"
        print(f"  [{tag:>6}] {name:<28} kept={n_kept:>6}  b2a={n_b2a:>6}  no_ts={n_no_ts}")
        results[name] = (n_kept, n_b2a, n_no_ts)

    if workers and workers > 1:
        try:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(extract_to_cache, p): p for p in todo}
                for fut in as_completed(futs):
                    record(fut.result())
            return results
        except Exception as e:  # fall back to serial on any pool issue
            print(f"  [warn] parallel extraction failed ({e}); falling back to serial")
    for p in todo:
        record(extract_to_cache(p))
    return results


def load_cached(name):
    d = np.load(os.path.join(CACHE_DIR, name + ".npz"))
    return d["tsvals"], d["is_data"], d["times"]


# ---- Stage 2: window feature extraction ----
def _safe_std(a):
    return float(a.std(ddof=1)) if a.size > 1 else 0.0


def window_features(ts, is_data, times):
    """Compute the 27-feature vector for one window's Bob->Alice arrays."""
    n = ts.size
    feats = []

    # 2-LSB symbol frequencies + chi2 vs uniform
    sym = ts & 0b11
    counts4 = np.bincount(sym, minlength=4).astype(np.float64)
    feats.extend((counts4 / n).tolist())                  # freq_00,01,10,11
    exp4 = n / 4.0
    feats.append(float(((counts4 - exp4) ** 2 / exp4).sum()))   # chi2_2lsb (df=3)

    # P(bit=1) for bits 0..7
    bit_p = [float(((ts >> k) & 1).mean()) for k in range(N_BITS)]
    feats.extend(bit_p)

    # TSval consecutive diffs (shared by Cabuk + diff stats)
    if n >= 2:
        d = np.diff(ts)
        d = d[(d >= 0) & (d <= MAX_DIFF)]
    else:
        d = np.empty(0, dtype=np.int64)

    # Cabuk regularity eps at delta=1 and delta=5 (on TSval diff series)
    if d.size >= 2:
        s = np.sort(d)
        gaps = np.diff(s)
        eps1 = float(np.mean(gaps <= 1))
        eps5 = float(np.mean(gaps <= 5))
    else:
        eps1 = eps5 = 0.0
    feats.extend([eps1, eps5])

    # chi2 per-bit (bit0, bit1) vs 50/50 (df=1)
    for k in (0, 1):
        n1 = int(((ts >> k) & 1).sum())
        n0 = n - n1
        e = n / 2.0
        feats.append(float(((n0 - e) ** 2 + (n1 - e) ** 2) / e))

    # TSval consecutive-difference statistics
    if d.size:
        feats.append(float(d.mean()))
        feats.append(_safe_std(d.astype(np.float64)))
        feats.append(float(np.median(d)))
        feats.append(float(np.percentile(d, 75)))
        feats.append(float(np.percentile(d, 90)))
        feats.append(float(np.percentile(d, 99)))
        vals, cnts = np.unique(d, return_counts=True)
        feats.append(float(vals[int(np.argmax(cnts))]))   # mode (ties -> smallest)
    else:
        feats.extend([0.0] * 7)

    # inter-packet delay (ms) between consecutive data packets
    dtimes = times[is_data]
    if dtimes.size >= 2:
        ipd = np.diff(dtimes) * 1000.0
        m = float(ipd.mean())
        sd = _safe_std(ipd)
        feats.append(m)
        feats.append(sd)
        feats.append(sd / m if m != 0 else 0.0)
    else:
        feats.extend([0.0, 0.0, 0.0])

    return feats


def windows_of(name):
    """Per-window feature rows for one cached flow (full 200-packet windows, 100 step)."""
    ts, is_data, times = load_cached(name)
    n = ts.size
    rows = []
    if n < WINDOW:
        if n > 0:                                   # short flow -> one partial window
            rows.append(window_features(ts, is_data, times))
        return rows
    for start in range(0, n - WINDOW + 1, STEP):
        sl = slice(start, start + WINDOW)
        rows.append(window_features(ts[sl], is_data[sl], times[sl]))
    return rows
