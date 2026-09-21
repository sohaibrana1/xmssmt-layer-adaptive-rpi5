import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

in_path = Path(sys.argv[1])
stats_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])

rows = list(csv.DictReader(
    in_path.open(
        newline="",
        encoding="utf-8"
    )
))

if len(rows) != 4200:
    raise SystemExit(
        f"FAIL: input rows={len(rows)} expected=4200"
    )

by_config = defaultdict(list)

for r in rows:
    by_config[r["configuration"]].append(r)

if len(by_config) != 20:
    raise SystemExit(
        f"FAIL: configurations={len(by_config)} expected=20"
    )

def sample_stats(values):
    mean = statistics.mean(values)
    median = statistics.median(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    cv = (sd / mean * 100.0) if mean != 0 else 0.0

    return {
        "n": len(values),
        "mean_ms": mean,
        "median_ms": median,
        "sd_ms": sd,
        "cv_percent": cv,
        "min_ms": min(values),
        "max_ms": max(values),
    }

stats_rows = []
summary_rows = []

for config in sorted(by_config):
    config_rows = by_config[config]

    first = config_rows[0]

    h0 = int(first["h0"])
    h1 = int(first["h1"])
    w0 = int(first["w0"])
    w1 = int(first["w1"])

    sig = int(first["signature_bytes"])
    pk = int(first["public_key_bytes"])
    sk = int(first["secret_key_bytes"])

    source_phase = first["source_phase"]

    means = {}

    for operation in ("keygen", "sign", "verify"):
        values = [
            float(r["latency_ms"])
            for r in config_rows
            if r["operation"] == operation
        ]

        expected = 10 if operation == "keygen" else 100

        if len(values) != expected:
            raise SystemExit(
                f"FAIL: {config}/{operation}: "
                f"n={len(values)} expected={expected}"
            )

        s = sample_stats(values)

        means[operation] = s["mean_ms"]

        stats_rows.append({
            "configuration": config,
            "h0": h0,
            "h1": h1,
            "w0": w0,
            "w1": w1,
            "source_phase": source_phase,
            "operation": operation,
            "n": s["n"],
            "mean_ms": s["mean_ms"],
            "median_ms": s["median_ms"],
            "sd_ms": s["sd_ms"],
            "cv_percent": s["cv_percent"],
            "min_ms": s["min_ms"],
            "max_ms": s["max_ms"],
            "signature_bytes": sig,
            "public_key_bytes": pk,
            "secret_key_bytes": sk,
        })

    summary_rows.append({
        "configuration": config,
        "h0": h0,
        "h1": h1,
        "w0": w0,
        "w1": w1,
        "source_phase": source_phase,
        "keygen_mean_ms": means["keygen"],
        "sign_mean_ms": means["sign"],
        "verify_mean_ms": means["verify"],
        "signature_bytes": sig,
        "public_key_bytes": pk,
        "secret_key_bytes": sk,
    })

stats_fields = [
    "configuration",
    "h0",
    "h1",
    "w0",
    "w1",
    "source_phase",
    "operation",
    "n",
    "mean_ms",
    "median_ms",
    "sd_ms",
    "cv_percent",
    "min_ms",
    "max_ms",
    "signature_bytes",
    "public_key_bytes",
    "secret_key_bytes",
]

with stats_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=stats_fields,
        lineterminator="\n",
    )

    writer.writeheader()

    for r in stats_rows:
        out = r.copy()

        for field in (
            "mean_ms",
            "median_ms",
            "sd_ms",
            "cv_percent",
            "min_ms",
            "max_ms",
        ):
            out[field] = f"{out[field]:.9f}"

        writer.writerow(out)

summary_fields = [
    "configuration",
    "h0",
    "h1",
    "w0",
    "w1",
    "source_phase",
    "keygen_mean_ms",
    "sign_mean_ms",
    "verify_mean_ms",
    "signature_bytes",
    "public_key_bytes",
    "secret_key_bytes",
]

with summary_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=summary_fields,
        lineterminator="\n",
    )

    writer.writeheader()

    for r in summary_rows:
        writer.writerow({
            **r,
            "keygen_mean_ms":
                f"{r['keygen_mean_ms']:.9f}",
            "sign_mean_ms":
                f"{r['sign_mean_ms']:.9f}",
            "verify_mean_ms":
                f"{r['verify_mean_ms']:.9f}",
        })

print(f"configurations={len(summary_rows)}")
print(f"descriptive_rows={len(stats_rows)}")
print(f"summary_rows={len(summary_rows)}")
print(f"stats={stats_path}")
print(f"summary={summary_path}")
print("STAGE7G_DESCRIPTIVE_STATS_GATE=PASS")
