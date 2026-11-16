"""Generate static/sample_flows.csv for trying the batch-upload feature.

The file imitates the raw CICIDS 2017 CSV layout (leading spaces in column
names, a Destination Port column and a Label column with attack names) and
includes one row with an infinite value to show how invalid rows are handled.

Run from the project root:  python scripts/make_sample_csv.py
"""

import os
import random
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids.samples import SAMPLES  # noqa: E402

LABELS = {"benign_dns": "BENIGN", "benign_web": "BENIGN", "dos_hulk": "DoS Hulk",
          "ddos": "DDoS", "port_scan": "PortScan"}
PORTS = {"benign_dns": 53, "benign_web": 443, "dos_hulk": 80, "ddos": 80, "port_scan": 0}
COUNTS = {"benign_dns": 12, "benign_web": 12, "dos_hulk": 8, "ddos": 8, "port_scan": 8}


def main():
    rng = random.Random(42)
    rows = []
    for key, n in COUNTS.items():
        base = SAMPLES[key]["features"]
        for _ in range(n):
            # Small multiplicative jitter so rows are not identical.
            row = {k: (v * rng.uniform(0.9, 1.1) if v > 0 and "Flag" not in k else v)
                   for k, v in base.items()}
            row["Destination Port"] = PORTS[key] or rng.randint(1, 65535)
            row["Label"] = LABELS[key]
            rows.append(row)
    rng.shuffle(rows)

    bad = dict(rows[0])
    bad["Flow Bytes/s"] = float("inf")
    rows.append(bad)

    df = pd.DataFrame(rows)
    cols = ["Destination Port"] + [c for c in df.columns if c not in ("Destination Port", "Label")] + ["Label"]
    df = df[cols]
    df.columns = [" " + c if c != "Flow Bytes/s" else c for c in df.columns]  # mimic CICIDS spacing

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "static", "sample_flows.csv")
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows to {out}")


if __name__ == "__main__":
    main()
