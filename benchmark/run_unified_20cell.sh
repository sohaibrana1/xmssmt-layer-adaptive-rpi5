#!/usr/bin/env bash
set -euo pipefail

RERUN="$HOME/PhD_HBS/Objective1/RPI5_Heterogeneous_XMSSMT_REVISION_2026-09-19"

MATRIX="$RERUN/00_protocol/UNIFIED_20CELL_MATRIX.csv"
EXE="$RERUN/02_build/unified_fullcycle_benchmark"
OUTROOT="$RERUN/03_raw/UNIFIED_20CELL_RUN01"
SUMMARY="$OUTROOT/RUN_SUMMARY.csv"

CPU=3

if [ ! -f "$MATRIX" ]; then
    echo "FAIL: matrix missing: $MATRIX"
    exit 1
fi

if [ ! -x "$EXE" ]; then
    echo "FAIL: executable missing: $EXE"
    exit 1
fi

GOVERNOR=$(cat "/sys/devices/system/cpu/cpu${CPU}/cpufreq/scaling_governor")

if [ "$GOVERNOR" != "performance" ]; then
    echo "FAIL: cpu${CPU} governor is '$GOVERNOR', expected 'performance'"
    exit 1
fi

THROTTLED_PREFLIGHT=$(vcgencmd get_throttled 2>/dev/null || true)

if [ "$THROTTLED_PREFLIGHT" != "throttled=0x0" ]; then
    echo "FAIL: preflight throttling state: $THROTTLED_PREFLIGHT"
    exit 1
fi

mkdir -p "$OUTROOT"

if [ -e "$SUMMARY" ]; then
    echo "FAIL: summary already exists: $SUMMARY"
    exit 1
fi

echo \
"configuration,h0,h1,w0,w1,expected_sign_rows,actual_keygen_rows,actual_sign_rows,actual_verify_rows,verification_passes,index_gate,cycle_gate,counter_gate,throttling_gate,manifest_gate,status" \
> "$SUMMARY"

while IFS=, read -r \
CONFIG H0 H1 W0 W1 SIG_BYTES PK_BYTES SK_BYTES SIGN_RUNS
do
    if [ "$CONFIG" = "configuration" ]; then
        continue
    fi

    RUN="$OUTROOT/$CONFIG"

    if [ -e "$RUN" ]; then
        echo "FAIL: output directory already exists: $RUN"
        exit 1
    fi

    mkdir -p "$RUN"

    {
        echo "configuration=$CONFIG"
        echo "timestamp_start=$(date --iso-8601=ns)"
        echo "hostname=$(hostname)"
        echo "kernel=$(uname -r)"
        echo "architecture=$(uname -m)"
        echo "gcc=$(gcc --version | head -n 1)"
        echo "perf=$(perf --version 2>/dev/null || echo unavailable)"
        echo "cpu_affinity=$CPU"
        echo "cpu_governor=$(cat /sys/devices/system/cpu/cpu${CPU}/cpufreq/scaling_governor)"
        echo "cpu_min_khz=$(cat /sys/devices/system/cpu/cpu${CPU}/cpufreq/scaling_min_freq)"
        echo "cpu_max_khz=$(cat /sys/devices/system/cpu/cpu${CPU}/cpufreq/scaling_max_freq)"
        echo "timer=CLOCK_MONOTONIC_RAW"
        echo "throttled_start=$(vcgencmd get_throttled 2>/dev/null || echo unavailable)"
        echo "temperature_start=$(vcgencmd measure_temp 2>/dev/null || echo unavailable)"
        echo "h0=$H0"
        echo "h1=$H1"
        echo "w0=$W0"
        echo "w1=$W1"
        echo "expected_signature_bytes=$SIG_BYTES"
        echo "expected_public_key_bytes=$PK_BYTES"
        echo "expected_secret_key_bytes=$SK_BYTES"
        echo "expected_sign_rows=$SIGN_RUNS"
    } > "$RUN/PRE_RUN.txt"

    echo "timestamp,temperature_c,throttled" > "$RUN/THERMAL.csv"

    (
        while true
        do
            TS=$(LC_ALL=C date '+%Y-%m-%dT%H:%M:%S.%N%:z')
            TEMP=$(
                vcgencmd measure_temp 2>/dev/null |
                sed -n "s/temp=\([0-9.]*\).*/\1/p"
            )
            THROT=$(
                vcgencmd get_throttled 2>/dev/null |
                sed -n 's/throttled=//p'
            )

            printf '%s,%s,%s\n' \
                "$TS" \
                "${TEMP:-NA}" \
                "${THROT:-NA}"

            sleep 1
        done
    ) >> "$RUN/THERMAL.csv" &

    THERMAL_PID=$!

    START=$(LC_ALL=C date '+%Y-%m-%dT%H:%M:%S.%N%:z')

    echo "Measurement start marker: $START" \
        > "$RUN/MEASUREMENT_MARKERS.txt"

    set +e

    taskset -c "$CPU" \
        "$EXE" \
        "$CONFIG" \
        "$H0" \
        "$H1" \
        "$W0" \
        "$W1" \
        "$SIG_BYTES" \
        "$SK_BYTES" \
        "$RUN/operations.csv" \
        2>&1 | tee "$RUN/CONSOLE.log"

    RUN_RC=${PIPESTATUS[0]}

    set -e

    END=$(LC_ALL=C date '+%Y-%m-%dT%H:%M:%S.%N%:z')

    echo "Measurement end marker: $END" \
        >> "$RUN/MEASUREMENT_MARKERS.txt"

    kill "$THERMAL_PID" 2>/dev/null || true
    wait "$THERMAL_PID" 2>/dev/null || true

    {
        echo "timestamp_end=$(date --iso-8601=ns)"
        echo "run_rc=$RUN_RC"
        echo "throttled_end=$(vcgencmd get_throttled 2>/dev/null || echo unavailable)"
        echo "temperature_end=$(vcgencmd measure_temp 2>/dev/null || echo unavailable)"
    } > "$RUN/POST_RUN.txt"

    if [ "$RUN_RC" -ne 0 ]; then
        echo "FAIL: benchmark returned $RUN_RC for $CONFIG"
        exit 1
    fi

    python3 - \
        "$RUN/operations.csv" \
        "$CONFIG" \
        "$H0" \
        "$H1" \
        "$W0" \
        "$W1" \
        "$SIG_BYTES" \
        "$PK_BYTES" \
        "$SK_BYTES" \
        "$SIGN_RUNS" \
        > "$RUN/VALIDATION.txt" <<'PY'
import csv
import sys
from collections import Counter

(
    path,
    config,
    h0,
    h1,
    w0,
    w1,
    sig_bytes,
    pk_bytes,
    sk_bytes,
    expected_sign_rows,
) = sys.argv[1:]

expected_sign_rows = int(expected_sign_rows)

with open(path, newline="") as f:
    rows = list(csv.DictReader(f))

counts = Counter(r["operation"] for r in rows)

keygen = [r for r in rows if r["operation"] == "keygen"]
sign = [r for r in rows if r["operation"] == "sign"]
verify = [r for r in rows if r["operation"] == "verify"]

def fail(msg):
    print("VALIDATION_GATE=FAIL")
    print("REASON=" + msg)
    raise SystemExit(1)

if len(keygen) != 10:
    fail(f"keygen rows={len(keygen)}, expected 10")

if len(sign) != expected_sign_rows:
    fail(
        f"sign rows={len(sign)}, "
        f"expected {expected_sign_rows}"
    )

if len(verify) != expected_sign_rows:
    fail(
        f"verify rows={len(verify)}, "
        f"expected {expected_sign_rows}"
    )

if not all(r["verification_pass"] == "1" for r in verify):
    fail("one or more verification rows failed")

for r in rows:
    if r["configuration"] != config:
        fail("configuration mismatch")

    if (
        r["h0"] != h0 or
        r["h1"] != h1 or
        r["w0"] != w0 or
        r["w1"] != w1
    ):
        fail("parameter metadata mismatch")

    if r["signature_bytes"] != sig_bytes:
        fail("signature size mismatch")

    if r["public_key_bytes"] != pk_bytes:
        fail("public-key size mismatch")

    if r["secret_key_bytes"] != sk_bytes:
        fail("secret-key size mismatch")

index_gate = all(
    int(r["iteration"]) == i
    and int(r["signature_index_before"]) == i
    and int(r["signature_index_after"]) == i + 1
    for i, r in enumerate(sign)
)

if not index_gate:
    fail("signature-index progression mismatch")

cycle_gate = all(int(r["cpu_cycles"]) > 0 for r in rows)

if not cycle_gate:
    fail("zero/nonpositive cpu_cycles detected")

counter_gate = all(
    int(r["logical_hash_calls"]) ==
    int(r["prf_calls"]) +
    int(r["hash_f_calls"]) +
    int(r["hash_h_calls"]) +
    int(r["hash_message_calls"])
    for r in rows
)

if not counter_gate:
    fail("logical hash identity mismatch")

print("VALIDATION_GATE=PASS")
print("KEYGEN_ROWS=10")
print(f"SIGN_ROWS={len(sign)}")
print(f"VERIFY_ROWS={len(verify)}")
print(f"VERIFICATION_PASSES={len(verify)}")
print("INDEX_GATE=PASS")
print("CPU_CYCLE_GATE=PASS")
print("COUNTER_GATE=PASS")
print(
    "FIRST_SIGN_INDEX="
    + sign[0]["signature_index_before"]
)
print(
    "LAST_SIGN_INDEX_BEFORE="
    + sign[-1]["signature_index_before"]
)
print(
    "LAST_SIGN_INDEX_AFTER="
    + sign[-1]["signature_index_after"]
)
PY

    VALIDATION_RC=$?

    if [ "$VALIDATION_RC" -ne 0 ]; then
        cat "$RUN/VALIDATION.txt"
        echo "FAIL: CSV validation for $CONFIG"
        exit 1
    fi

    THERMAL_GATE=PASS

    if awk -F, 'NR>1 && $3 != "0x0" {bad=1} END {exit bad}' \
        "$RUN/THERMAL.csv"; then
        :
    else
        THERMAL_GATE=FAIL
    fi

    THROTTLED_END=$(vcgencmd get_throttled 2>/dev/null || true)

    if [ "$THROTTLED_END" != "throttled=0x0" ]; then
        THERMAL_GATE=FAIL
    fi

    if [ "$THERMAL_GATE" != "PASS" ]; then
        echo "FAIL: throttling observed for $CONFIG"
        exit 1
    fi

    (
        cd "$RUN"
        sha256sum \
            PRE_RUN.txt \
            POST_RUN.txt \
            MEASUREMENT_MARKERS.txt \
            THERMAL.csv \
            CONSOLE.log \
            operations.csv \
            VALIDATION.txt \
            > SHA256_MANIFEST.txt

        sha256sum -c SHA256_MANIFEST.txt \
            > SHA256_CHECK.txt
    )

    MANIFEST_GATE=FAIL

    if grep -qv ': OK$' "$RUN/SHA256_CHECK.txt"; then
        MANIFEST_GATE=FAIL
    else
        MANIFEST_GATE=PASS
    fi

    if [ "$MANIFEST_GATE" != "PASS" ]; then
        echo "FAIL: checksum verification for $CONFIG"
        exit 1
    fi

    ACTUAL_KEYGEN=$(grep '^KEYGEN_ROWS=' "$RUN/VALIDATION.txt" | cut -d= -f2)
    ACTUAL_SIGN=$(grep '^SIGN_ROWS=' "$RUN/VALIDATION.txt" | cut -d= -f2)
    ACTUAL_VERIFY=$(grep '^VERIFY_ROWS=' "$RUN/VALIDATION.txt" | cut -d= -f2)
    VERIFY_PASS=$(grep '^VERIFICATION_PASSES=' "$RUN/VALIDATION.txt" | cut -d= -f2)

    echo \
"$CONFIG,$H0,$H1,$W0,$W1,$SIGN_RUNS,$ACTUAL_KEYGEN,$ACTUAL_SIGN,$ACTUAL_VERIFY,$VERIFY_PASS,PASS,PASS,PASS,PASS,PASS,PASS" \
        >> "$SUMMARY"

    echo "CELL_GATE=PASS configuration=$CONFIG"
done < "$MATRIX"

echo "UNIFIED_20CELL_CAMPAIGN=PASS"
