import csv
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

rows = list(csv.DictReader(
    src.open(
        newline="",
        encoding="utf-8"
    )
))

if len(rows) != 20:
    raise SystemExit(
        f"FAIL: rows={len(rows)} expected=20"
    )

lookup = {
    (
        int(r["h0"]),
        int(r["h1"]),
        int(r["w0"]),
        int(r["w1"]),
    ): r
    for r in rows
}

heights = [
    (10,10),
    (8,12),
    (12,8),
    (6,14),
    (14,6),
]

wots_pairs = [
    (16,16),
    (4,16),
    (16,4),
    (4,4),
]

baseline_h = (10,10)

out = []

for w0, w1 in wots_pairs:
    base = lookup[
        (
            baseline_h[0],
            baseline_h[1],
            w0,
            w1,
        )
    ]

    base_keygen = float(
        base["keygen_mean_ms"]
    )

    base_sign = float(
        base["sign_mean_ms"]
    )

    base_verify = float(
        base["verify_mean_ms"]
    )

    base_sk = int(
        base["secret_key_bytes"]
    )

    for h0, h1 in heights:
        r = lookup[
            (
                h0,
                h1,
                w0,
                w1,
            )
        ]

        keygen = float(
            r["keygen_mean_ms"]
        )

        sign = float(
            r["sign_mean_ms"]
        )

        verify = float(
            r["verify_mean_ms"]
        )

        sk = int(
            r["secret_key_bytes"]
        )

        out.append({
            "w0": w0,
            "w1": w1,
            "height_split":
                f"{h0}-{h1}",
            "configuration":
                r["configuration"],
            "keygen_mean_ms":
                f"{keygen:.9f}",
            "sign_mean_ms":
                f"{sign:.9f}",
            "verify_mean_ms":
                f"{verify:.9f}",
            "signature_bytes":
                r["signature_bytes"],
            "secret_key_bytes":
                r["secret_key_bytes"],
            "keygen_change_vs_10_10_percent":
                f"{((keygen-base_keygen)/base_keygen*100):.9f}",
            "sign_change_vs_10_10_percent":
                f"{((sign-base_sign)/base_sign*100):.9f}",
            "verify_change_vs_10_10_percent":
                f"{((verify-base_verify)/base_verify*100):.9f}",
            "sk_change_vs_10_10_bytes":
                str(sk-base_sk),
        })

fields = list(out[0].keys())

with dst.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fields,
        lineterminator="\n",
    )

    writer.writeheader()
    writer.writerows(out)

print(f"height_effect_rows={len(out)}")

if len(out) != 20:
    raise SystemExit(
        f"FAIL: rows={len(out)}"
    )

for w0, w1 in wots_pairs:
    group = [
        r for r in out
        if int(r["w0"]) == w0
        and int(r["w1"]) == w1
    ]

    if len(group) != 5:
        raise SystemExit(
            f"FAIL: W{w0}-{w1}: rows={len(group)}"
        )

    best_sign = min(
        group,
        key=lambda r:
            float(r["sign_mean_ms"])
    )

    best_keygen = min(
        group,
        key=lambda r:
            float(r["keygen_mean_ms"])
    )

    smallest_sk = min(
        group,
        key=lambda r:
            int(r["secret_key_bytes"])
    )

    print(
        f"W{w0}-{w1}|"
        f"best_sign={best_sign['configuration']}|"
        f"{best_sign['sign_mean_ms']}ms|"
        f"best_keygen={best_keygen['configuration']}|"
        f"{best_keygen['keygen_mean_ms']}ms|"
        f"smallest_sk={smallest_sk['configuration']}|"
        f"{smallest_sk['secret_key_bytes']}B"
    )

print("STAGE7J_HEIGHT_EFFECT_GATE=PASS")
