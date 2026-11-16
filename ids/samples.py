"""Example network flows for the dashboard's quick-test buttons.

Each preset is described by a handful of flow-level properties (packet counts,
sizes, timings, flags). `build_flow` derives the full 77 CICFlowMeter features
from them so the values stay internally consistent (e.g. means, totals and
rates agree with each other).

These are synthetic flows shaped after the traffic patterns described in the
CICIDS 2017 paper; they are for demonstrating the system, not ground truth.
"""

import math


def _stats(sizes):
    if not sizes:
        return 0.0, 0.0, 0.0, 0.0
    n = len(sizes)
    mean = sum(sizes) / n
    std = math.sqrt(sum((s - mean) ** 2 for s in sizes) / (n - 1)) if n > 1 else 0.0
    return float(max(sizes)), float(min(sizes)), mean, std


def _iat(times):
    gaps = [b - a for a, b in zip(times, times[1:])]
    if not gaps:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    total = float(sum(gaps))
    mx, mn, mean, std = _stats(gaps)
    return total, mean, std, mx, mn


def build_flow(fwd_sizes, bwd_sizes, duration_us, init_win_fwd=-1, init_win_bwd=-1,
               flags=None, header_len=20, active=(0, 0, 0, 0), idle=(0, 0, 0, 0)):
    """Return a dict of the 77 model features for one flow.

    fwd_sizes / bwd_sizes: payload length of each packet in that direction.
    duration_us: flow duration in microseconds (CICFlowMeter's unit).
    """
    flags = flags or {}
    nf, nb = len(fwd_sizes), len(bwd_sizes)
    duration_us = max(float(duration_us), 1.0)

    # Spread packets evenly over the flow, alternating directions.
    total_pkts = nf + nb
    step = duration_us / max(total_pkts - 1, 1)
    fwd_times = [i * 2 * step for i in range(nf)]
    bwd_times = [(i * 2 + 1) * step for i in range(nb)]
    all_times = sorted(fwd_times + bwd_times)

    f_max, f_min, f_mean, f_std = _stats(fwd_sizes)
    b_max, b_min, b_mean, b_std = _stats(bwd_sizes)
    all_sizes = list(fwd_sizes) + list(bwd_sizes)
    p_max, p_min, p_mean, p_std = _stats(all_sizes)
    flow_iat = _iat(all_times)
    fwd_iat = _iat(fwd_times)
    bwd_iat = _iat(bwd_times)

    tot_f, tot_b = float(sum(fwd_sizes)), float(sum(bwd_sizes))
    seconds = duration_us / 1e6

    return {
        "Flow Duration": duration_us,
        "Total Fwd Packets": float(nf),
        "Total Backward Packets": float(nb),
        "Total Length of Fwd Packets": tot_f,
        "Total Length of Bwd Packets": tot_b,
        "Fwd Packet Length Max": f_max,
        "Fwd Packet Length Min": f_min,
        "Fwd Packet Length Mean": f_mean,
        "Fwd Packet Length Std": f_std,
        "Bwd Packet Length Max": b_max,
        "Bwd Packet Length Min": b_min,
        "Bwd Packet Length Mean": b_mean,
        "Bwd Packet Length Std": b_std,
        "Flow Bytes/s": (tot_f + tot_b) / seconds,
        "Flow Packets/s": total_pkts / seconds,
        "Flow IAT Mean": flow_iat[1],
        "Flow IAT Std": flow_iat[2],
        "Flow IAT Max": flow_iat[3],
        "Flow IAT Min": flow_iat[4],
        "Fwd IAT Total": fwd_iat[0],
        "Fwd IAT Mean": fwd_iat[1],
        "Fwd IAT Std": fwd_iat[2],
        "Fwd IAT Max": fwd_iat[3],
        "Fwd IAT Min": fwd_iat[4],
        "Bwd IAT Total": bwd_iat[0],
        "Bwd IAT Mean": bwd_iat[1],
        "Bwd IAT Std": bwd_iat[2],
        "Bwd IAT Max": bwd_iat[3],
        "Bwd IAT Min": bwd_iat[4],
        "Fwd PSH Flags": float(flags.get("fwd_psh", 0)),
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": float(header_len * nf),
        "Bwd Header Length": float(header_len * nb),
        "Fwd Packets/s": nf / seconds,
        "Bwd Packets/s": nb / seconds,
        "Min Packet Length": p_min,
        "Max Packet Length": p_max,
        "Packet Length Mean": p_mean,
        "Packet Length Std": p_std,
        "Packet Length Variance": p_std ** 2,
        "FIN Flag Count": float(flags.get("fin", 0)),
        "SYN Flag Count": float(flags.get("syn", 0)),
        "RST Flag Count": float(flags.get("rst", 0)),
        "PSH Flag Count": float(flags.get("psh", 0)),
        "ACK Flag Count": float(flags.get("ack", 0)),
        "URG Flag Count": float(flags.get("urg", 0)),
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": float(nb // nf) if nf else 0.0,
        "Average Packet Size": (tot_f + tot_b) / total_pkts if total_pkts else 0.0,
        "Avg Fwd Segment Size": f_mean,
        "Avg Bwd Segment Size": b_mean,
        "Fwd Header Length.1": float(header_len * nf),
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": float(nf),
        "Subflow Fwd Bytes": tot_f,
        "Subflow Bwd Packets": float(nb),
        "Subflow Bwd Bytes": tot_b,
        "Init_Win_bytes_forward": float(init_win_fwd),
        "Init_Win_bytes_backward": float(init_win_bwd),
        "act_data_pkt_fwd": float(sum(1 for s in fwd_sizes if s > 0)),
        "min_seg_size_forward": float(header_len),
        "Active Mean": float(active[0]),
        "Active Std": float(active[1]),
        "Active Max": float(active[2]),
        "Active Min": float(active[3]),
        "Idle Mean": float(idle[0]),
        "Idle Std": float(idle[1]),
        "Idle Max": float(idle[2]),
        "Idle Min": float(idle[3]),
    }


SAMPLES = {
    "benign_dns": {
        "name": "Benign DNS lookup",
        "description": "Single UDP query and response, typical name resolution.",
        "expected": "BENIGN",
        "features": build_flow([38], [104], duration_us=31_000, header_len=8),
    },
    "benign_web": {
        "name": "Benign HTTPS browsing",
        "description": "Short TLS session fetching a small page.",
        "expected": "BENIGN",
        "features": build_flow(
            [0, 517, 0, 126, 0, 389, 0, 0], [0, 1448, 1448, 0, 1215, 0, 0],
            duration_us=180_000, init_win_fwd=29200, init_win_bwd=28960,
            flags={"psh": 1, "ack": 1}, header_len=32),
    },
    "dos_hulk": {
        "name": "DoS Hulk",
        "description": "HTTP flood: small requests drawing large, uniform server responses.",
        "expected": "ATTACK",
        "features": build_flow(
            [0, 0, 348, 0, 0, 0, 0], [0, 0, 11595, 0, 0, 0],
            duration_us=98_000, init_win_fwd=29200, init_win_bwd=235,
            flags={"psh": 0, "ack": 1}, header_len=32),
    },
    "ddos": {
        "name": "DDoS (LOIC)",
        "description": "Many short HTTP connections with one large backward burst.",
        "expected": "ATTACK",
        "features": build_flow(
            [0, 0, 20, 0], [0, 5840, 5840, 0],
            duration_us=1_300_000, init_win_fwd=8192, init_win_bwd=229,
            flags={"ack": 1}, header_len=20),
    },
    "port_scan": {
        "name": "Port scan",
        "description": "Single SYN probe answered by a 6-byte RST, no payload sent.",
        "expected": "ATTACK",
        "features": build_flow(
            [0], [6], duration_us=45, init_win_fwd=1024, init_win_bwd=0,
            flags={"rst": 1}, header_len=24),
    },
}
