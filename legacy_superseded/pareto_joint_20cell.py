import csv
import sys
from pathlib import Path

src = Path(sys.argv[1])
pareto_out = Path(sys.argv[2])
dominance_out = Path(sys.argv[3])

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

OBJECTIVES = [
    "keygen_mean_ms",
    "sign_mean_ms",
    "verify_mean_ms",
    "signature_bytes",
    "secret_key_bytes",
]

def values(row):
    return tuple(
        float(row[x])
        for x in OBJECTIVES
    )

def dominates(a, b):
    """
    a dominates b iff:
    - a is no worse than b in every objective
    - a is strictly better in at least one objective
    All objectives are minimized.
    """
    av = values(a)
    bv = values(b)

    no_worse = all(
        x <= y
        for x, y in zip(av, bv)
    )

    strictly_better = any(
        x < y
        for x, y in zip(av, bv)
    )

    return no_worse and strictly_better

pareto_rows = []
dominance_rows = []

for candidate in rows:
    dominators = [
        other
        for other in rows
        if other["configuration"] != candidate["configuration"]
        and dominates(other, candidate)
    ]

    dominates_list = [
        other
        for other in rows
        if other["configuration"] != candidate["configuration"]
        and dominates(candidate, other)
    ]

    is_pareto = len(dominators) == 0

    out = dict(candidate)

    out["pareto_nondominated"] = (
        "YES" if is_pareto else "NO"
    )

    out["dominator_count"] = str(
        len(dominators)
    )

    out["dominates_count"] = str(
        len(dominates_list)
    )

    out["dominators"] = ";".join(
        sorted(
            x["configuration"]
            for x in dominators
        )
    )

    out["dominates"] = ";".join(
        sorted(
            x["configuration"]
            for x in dominates_list
        )
    )

    dominance_rows.append(out)

    if is_pareto:
        pareto_rows.append(out)

if not pareto_rows:
    raise SystemExit(
        "FAIL: Pareto front empty"
    )

fields = list(rows[0].keys()) + [
    "pareto_nondominated",
    "dominator_count",
    "dominates_count",
    "dominators",
    "dominates",
]

with dominance_out.open(
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

    for r in dominance_rows:
        writer.writerow(r)

with pareto_out.open(
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

    for r in pareto_rows:
        writer.writerow(r)

print(f"total_configurations={len(rows)}")
print(f"pareto_nondominated={len(pareto_rows)}")
print(
    f"pareto_dominated="
    f"{len(rows) - len(pareto_rows)}"
)

print("PARETO_CONFIGURATIONS")

for r in sorted(
    pareto_rows,
    key=lambda x: (
        int(x["signature_bytes"]),
        float(x["sign_mean_ms"]),
        int(x["secret_key_bytes"]),
    )
):
    print(
        f"{r['configuration']}|"
        f"keygen={r['keygen_mean_ms']}|"
        f"sign={r['sign_mean_ms']}|"
        f"verify={r['verify_mean_ms']}|"
        f"sig={r['signature_bytes']}|"
        f"sk={r['secret_key_bytes']}"
    )

print("STAGE7H_PARETO_GATE=PASS")
