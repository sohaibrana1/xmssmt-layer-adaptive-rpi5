import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

source_map_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])

CANONICAL_FIELDS = [
    "configuration",
    "h0",
    "h1",
    "w0",
    "w1",
    "source_phase",
    "operation",
    "iteration",
    "latency_ns",
    "latency_ms",
    "verification_pass",
    "signature_bytes",
    "public_key_bytes",
    "secret_key_bytes",
    "source_csv",
]

def parse_verify(value):
    """
    Normalize historical verification encodings to:
      1 = pass
      0 = fail
      "" = not applicable
    """
    if value is None:
        return ""

    v = str(value).strip().lower()

    if v == "":
        return ""

    pass_values = {
        "1",
        "pass",
        "passed",
        "true",
        "ok",
        "success",
        "valid",
    }

    fail_values = {
        "0",
        "fail",
        "failed",
        "false",
        "error",
        "invalid",
    }

    if v in pass_values:
        return "1"

    if v in fail_values:
        return "0"

    raise ValueError(
        f"unrecognized verification value: {value!r}"
    )

def normalize_operation(value):
    v = str(value).strip().lower()

    aliases = {
        "keygen": "keygen",
        "key_generation": "keygen",
        "keypair": "keygen",
        "keypair_generation": "keygen",
        "sign": "sign",
        "signature": "sign",
        "signing": "sign",
        "verify": "verify",
        "verification": "verify",
    }

    if v not in aliases:
        raise ValueError(
            f"unrecognized operation: {value!r}"
        )

    return aliases[v]

source_map = list(csv.DictReader(
    source_map_path.open(
        newline="",
        encoding="utf-8"
    )
))

if len(source_map) != 20:
    raise SystemExit(
        f"FAIL: source-map rows={len(source_map)} expected=20"
    )

normalized = []
report = []

for entry in source_map:
    config = entry["configuration"]
    phase = entry["source_phase"]
    source_csv = Path(entry["source_csv"])

    if not source_csv.is_file():
        raise SystemExit(
            f"FAIL: missing source {config}: {source_csv}"
        )

    rows = list(csv.DictReader(
        source_csv.open(
            newline="",
            encoding="utf-8"
        )
    ))

    if not rows:
        raise SystemExit(
            f"FAIL: empty source {config}"
        )

    source_header = set(rows[0].keys())

    if phase in {"HEIGHT", "JOINT"}:
        required = {
            "configuration",
            "h0",
            "h1",
            "w0",
            "w1",
            "operation",
            "iteration",
            "latency_ns",
            "latency_ms",
            "verification_pass",
            "signature_bytes",
            "public_key_bytes",
            "secret_key_bytes",
        }

        missing = required - source_header

        if missing:
            raise SystemExit(
                f"FAIL: {config}: missing columns={sorted(missing)}"
            )

        for row in rows:
            op = normalize_operation(
                row["operation"]
            )

            latency_ns = int(
                row["latency_ns"]
            )

            if latency_ns <= 0:
                raise SystemExit(
                    f"FAIL: {config}: nonpositive latency"
                )

            normalized.append({
                "configuration": config,
                "h0": entry["h0"],
                "h1": entry["h1"],
                "w0": entry["w0"],
                "w1": entry["w1"],
                "source_phase": phase,
                "operation": op,
                "iteration": row["iteration"].strip(),
                "latency_ns": str(latency_ns),
                "latency_ms":
                    f"{latency_ns / 1_000_000.0:.9f}",
                "verification_pass":
                    parse_verify(
                        row["verification_pass"]
                    ),
                "signature_bytes":
                    row["signature_bytes"].strip(),
                "public_key_bytes":
                    row["public_key_bytes"].strip(),
                "secret_key_bytes":
                    row["secret_key_bytes"].strip(),
                "source_csv": str(source_csv),
            })

    elif phase == "WOTS":
        required = {
            "w0",
            "w1",
            "signature_bytes",
            "public_key_bytes",
            "secret_key_bytes",
            "run_number",
            "operation",
            "elapsed_ns",
            "verification_result",
        }

        missing = required - source_header

        if missing:
            raise SystemExit(
                f"FAIL: {config}: "
                f"missing WOTS columns={sorted(missing)}"
            )

        # The source-map values are authoritative for h0/h1
        # because historical WOTS CSVs predate per-layer height
        # fields and are fixed at h0=h1=10.
        per_op_counter = defaultdict(int)

        for row in rows:
            op = normalize_operation(
                row["operation"]
            )

            latency_ns = int(
                row["elapsed_ns"]
            )

            if latency_ns <= 0:
                raise SystemExit(
                    f"FAIL: {config}: nonpositive latency"
                )

            # Prefer run_number when it is numeric.
            # Otherwise generate a deterministic per-operation index.
            raw_iteration = str(
                row.get("run_number", "")
            ).strip()

            try:
                iteration = str(
                    int(raw_iteration)
                )
            except (ValueError, TypeError):
                iteration = str(
                    per_op_counter[op]
                )

            per_op_counter[op] += 1

            verify_value = ""

            if op == "verify":
                verify_value = parse_verify(
                    row["verification_result"]
                )

            normalized.append({
                "configuration": config,
                "h0": entry["h0"],
                "h1": entry["h1"],
                "w0": entry["w0"],
                "w1": entry["w1"],
                "source_phase": phase,
                "operation": op,
                "iteration": iteration,
                "latency_ns": str(latency_ns),
                "latency_ms":
                    f"{latency_ns / 1_000_000.0:.9f}",
                "verification_pass":
                    verify_value,
                "signature_bytes":
                    row["signature_bytes"].strip(),
                "public_key_bytes":
                    row["public_key_bytes"].strip(),
                "secret_key_bytes":
                    row["secret_key_bytes"].strip(),
                "source_csv": str(source_csv),
            })

    else:
        raise SystemExit(
            f"FAIL: unknown source phase {phase}"
        )

    config_rows = [
        r for r in normalized
        if r["configuration"] == config
    ]

    counts = Counter(
        r["operation"]
        for r in config_rows
    )

    if counts != {
        "keygen": 10,
        "sign": 100,
        "verify": 100,
    }:
        raise SystemExit(
            f"FAIL: {config}: counts={dict(counts)}"
        )

    verify_rows = [
        r for r in config_rows
        if r["operation"] == "verify"
    ]

    if any(
        r["verification_pass"] != "1"
        for r in verify_rows
    ):
        bad = Counter(
            r["verification_pass"]
            for r in verify_rows
        )

        raise SystemExit(
            f"FAIL: {config}: verification={dict(bad)}"
        )

    expected_h0 = entry["h0"]
    expected_h1 = entry["h1"]
    expected_w0 = entry["w0"]
    expected_w1 = entry["w1"]

    if any(
        r["h0"] != expected_h0 or
        r["h1"] != expected_h1 or
        r["w0"] != expected_w0 or
        r["w1"] != expected_w1
        for r in config_rows
    ):
        raise SystemExit(
            f"FAIL: {config}: parameter metadata"
        )

    sig_values = {
        r["signature_bytes"]
        for r in config_rows
    }

    pk_values = {
        r["public_key_bytes"]
        for r in config_rows
    }

    sk_values = {
        r["secret_key_bytes"]
        for r in config_rows
    }

    if len(sig_values) != 1:
        raise SystemExit(
            f"FAIL: {config}: signature-size inconsistency"
        )

    if pk_values != {"64"}:
        raise SystemExit(
            f"FAIL: {config}: PK={pk_values}"
        )

    if len(sk_values) != 1:
        raise SystemExit(
            f"FAIL: {config}: SK-size inconsistency"
        )

    report.append({
        "configuration": config,
        "source_phase": phase,
        "source_rows": len(rows),
        "normalized_rows": len(config_rows),
        "keygen_rows": counts["keygen"],
        "sign_rows": counts["sign"],
        "verify_rows": counts["verify"],
        "verification_passes": sum(
            r["verification_pass"] == "1"
            for r in verify_rows
        ),
        "signature_bytes":
            next(iter(sig_values)),
        "public_key_bytes":
            next(iter(pk_values)),
        "secret_key_bytes":
            next(iter(sk_values)),
        "status": "PASS",
    })

if len(normalized) != 20 * 210:
    raise SystemExit(
        f"FAIL: normalized rows={len(normalized)} "
        f"expected={20 * 210}"
    )

configs = {
    r["configuration"]
    for r in normalized
}

if len(configs) != 20:
    raise SystemExit(
        f"FAIL: normalized configurations={len(configs)}"
    )

with out_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=CANONICAL_FIELDS,
        lineterminator="\n",
    )

    writer.writeheader()
    writer.writerows(normalized)

report_fields = [
    "configuration",
    "source_phase",
    "source_rows",
    "normalized_rows",
    "keygen_rows",
    "sign_rows",
    "verify_rows",
    "verification_passes",
    "signature_bytes",
    "public_key_bytes",
    "secret_key_bytes",
    "status",
]

with report_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=report_fields,
        lineterminator="\n",
    )

    writer.writeheader()
    writer.writerows(report)

print(f"normalized_configurations={len(configs)}")
print(f"normalized_rows={len(normalized)}")
print(f"expected_rows={20 * 210}")
print(f"report_rows={len(report)}")
print(f"output={out_path}")
print(f"report={report_path}")
print("STAGE7F_NORMALIZATION_GATE=PASS")
