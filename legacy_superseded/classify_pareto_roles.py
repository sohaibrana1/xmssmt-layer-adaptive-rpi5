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

if len(rows) != 13:
    raise SystemExit(
        f"FAIL: Pareto rows={len(rows)} expected=13"
    )

def f(r, field):
    return float(r[field])

def i(r, field):
    return int(r[field])

min_keygen = min(
    f(r, "keygen_mean_ms")
    for r in rows
)

min_sign = min(
    f(r, "sign_mean_ms")
    for r in rows
)

min_verify = min(
    f(r, "verify_mean_ms")
    for r in rows
)

min_sig = min(
    i(r, "signature_bytes")
    for r in rows
)

min_sk = min(
    i(r, "secret_key_bytes")
    for r in rows
)

out = []

for r in rows:
    roles = []

    if f(r, "keygen_mean_ms") == min_keygen:
        roles.append("MIN_KEYGEN")

    if f(r, "sign_mean_ms") == min_sign:
        roles.append("MIN_SIGN")

    if f(r, "verify_mean_ms") == min_verify:
        roles.append("MIN_VERIFY")

    if i(r, "signature_bytes") == min_sig:
        roles.append("MIN_SIGNATURE")

    if i(r, "secret_key_bytes") == min_sk:
        roles.append("MIN_SECRET_KEY")

    # Operationally useful W4-16 frontier point:
    # one w=4 layer, no upper-layer WOTS storage penalty.
    if (
        int(r["w0"]) == 4
        and int(r["w1"]) == 16
    ):
        roles.append("LOWER_LAYER_W4")

    out.append({
        "configuration":
            r["configuration"],
        "h0":
            r["h0"],
        "h1":
            r["h1"],
        "w0":
            r["w0"],
        "w1":
            r["w1"],
        "keygen_mean_ms":
            r["keygen_mean_ms"],
        "sign_mean_ms":
            r["sign_mean_ms"],
        "verify_mean_ms":
            r["verify_mean_ms"],
        "signature_bytes":
            r["signature_bytes"],
        "secret_key_bytes":
            r["secret_key_bytes"],
        "empirical_roles":
            ";".join(roles)
            if roles
            else "PARETO_TRADEOFF",
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

print(f"pareto_rows={len(out)}")

for r in out:
    print(
        f"{r['configuration']}|"
        f"{r['empirical_roles']}"
    )

print("STAGE7K_EMPIRICAL_ROLE_GATE=PASS")
