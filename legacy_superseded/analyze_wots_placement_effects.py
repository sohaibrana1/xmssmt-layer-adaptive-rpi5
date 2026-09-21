import csv
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

rows = list(csv.DictReader(
    src.open(newline="", encoding="utf-8")
))

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

out = []

for h0, h1 in heights:

    a = lookup[(h0,h1,4,16)]
    b = lookup[(h0,h1,16,4)]

    sign_a = float(a["sign_mean_ms"])
    sign_b = float(b["sign_mean_ms"])

    verify_a = float(a["verify_mean_ms"])
    verify_b = float(b["verify_mean_ms"])

    keygen_a = float(a["keygen_mean_ms"])
    keygen_b = float(b["keygen_mean_ms"])

    out.append({
        "height_split": f"{h0}-{h1}",
        "comparison": "W4-16_vs_W16-4",
        "w4_lower_sign_ms": f"{sign_a:.9f}",
        "w4_upper_sign_ms": f"{sign_b:.9f}",
        "sign_delta_ms":
            f"{sign_a-sign_b:.9f}",
        "lower_w4_sign_reduction_percent":
            f"{((sign_b-sign_a)/sign_b*100):.9f}",
        "w4_lower_keygen_ms":
            f"{keygen_a:.9f}",
        "w4_upper_keygen_ms":
            f"{keygen_b:.9f}",
        "keygen_delta_ms":
            f"{keygen_a-keygen_b:.9f}",
        "w4_lower_verify_ms":
            f"{verify_a:.9f}",
        "w4_upper_verify_ms":
            f"{verify_b:.9f}",
        "verify_delta_ms":
            f"{verify_a-verify_b:.9f}",
        "signature_bytes":
            a["signature_bytes"],
        "lower_w4_sk_bytes":
            a["secret_key_bytes"],
        "upper_w4_sk_bytes":
            b["secret_key_bytes"],
        "sk_saving_lower_w4_bytes":
            str(
                int(b["secret_key_bytes"]) -
                int(a["secret_key_bytes"])
            ),
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

for r in out:
    print(
        f"{r['height_split']}|"
        f"sign_reduction="
        f"{r['lower_w4_sign_reduction_percent']}%|"
        f"sk_saving="
        f"{r['sk_saving_lower_w4_bytes']}B"
    )

print(f"placement_rows={len(out)}")

if len(out) != 5:
    raise SystemExit("FAIL")

print("STAGE7I_WOTS_PLACEMENT_GATE=PASS")
