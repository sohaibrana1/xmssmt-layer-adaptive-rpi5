# Reproducibility Guide

This repository accompanies the Raspberry Pi 5 evaluation of
layer-adaptive / heterogeneous XMSSMT configurations.

The experimental configurations vary the two XMSSMT layer heights and
Winternitz parameters while keeping total tree height H = 20 and d = 2.

The heterogeneous configurations are experimental research
configurations. They are not standardized XMSS/XMSSMT parameter sets
and are not assigned standardized OIDs.

## 1. Platform

The benchmark campaign was executed on a Raspberry Pi 5 using:

- ARM Cortex-A76 / BCM2712
- 64-bit Linux
- GCC 14.2.0
- CPU affinity: CPU 3
- CPU governor: performance
- maximum configured frequency: 2.4 GHz
- timer: CLOCK_MONOTONIC_RAW
- PMU cycle counting
- OpenSSL libcrypto SHA backend

The benchmark source calls the OpenSSL SHA interfaces. This repository
does not claim a specific OpenSSL assembly implementation path.

## 2. Configuration space

The lower/upper layer-height allocations are:

- (6,14)
- (8,12)
- (10,10)
- (12,8)
- (14,6)

The ordered Winternitz parameter pairs are:

- (4,4)
- (4,16)
- (16,4)
- (16,16)

This gives 20 configurations.

## 3. Full-cycle measurement protocol

For a lower-layer height h0, the complete signing-cycle dataset contains:

    2^h0 + 1

signatures so that the lower-tree rollover transition is observed.

The original 20-cell campaign therefore used:

- h0 = 6: 65 signatures per configuration
- h0 = 8: 257 signatures per configuration
- h0 = 10: 1,025 signatures per configuration
- h0 = 12: 4,097 signatures per configuration
- h0 = 14: 16,385 signatures per configuration

Each configuration also used:

- 3 warm-up key generations
- 100 warm-up signatures
- 10 measured key generations
- one measured verification for every measured signature

The original campaign therefore contains:

- 87,316 signing observations
- 87,316 verification observations
- 87,316 successful verifications
- zero verification failures

Verification evidence is provided in:

    data/verification/VERIFICATION_EVIDENCE_20CELL.csv

## 4. Randomized h0 = 14 validation

The four h0 = 14 configurations were independently repeated three times
using three distinct randomized execution orders.

Each of the 12 configuration-runs contains:

- 10 measured key generations
- 16,385 measured signatures
- 16,385 measured verifications
- 16,385 successful verifications

Across the randomized validation campaign:

- configuration-runs: 12
- signing observations: 196,620
- verification observations: 196,620
- successful verifications: 196,620
- verification failures: 0

The raw randomized data are available under:

    data/validation_h14/

The randomized execution matrices and associated provenance are under:

    provenance/validation_h14/

## 5. h0 = 14 anomaly validation

The original h0 = 14 campaign exhibited approximately 10% higher
mean cycles for the two w1 = 4 cells despite nearly identical measured
logical-hash work.

This effect did not reproduce in the three randomized repetitions.

For w0 = 16, the randomized w1 = 4 versus w1 = 16 cycle differences were:

- Repeat 01: +0.104%
- Repeat 02: -0.057%
- Repeat 03: +1.068%
- mean: +0.372%

For w0 = 4:

- Repeat 01: +1.333%
- Repeat 02: -0.128%
- Repeat 03: +0.196%
- mean: +0.467%

Accordingly, the original approximately 10% observation is not
interpreted as a persistent algorithmic upper-layer-w effect.

Relevant files:

    analysis/validated/H14_ANOMALY_RESOLUTION.txt
    analysis/validated/H14_RANDOMIZED_REPEAT_ANALYSIS.csv
    analysis/validated/H14_W1_EFFECT_PAIRWISE.csv

## 6. Rollover analysis

Across all 20 original full-cycle configurations:

- rollover was never a P95-or-higher latency observation
- rollover was never a P95-or-higher cycle observation
- rollover was never the maximum-latency signature

The rollover latency percentile rank ranged from approximately:

    0.006% to 58.462%

The same non-tail conclusion was independently confirmed in all
12 randomized h0 = 14 configuration-runs.

Relevant files:

    analysis/validated/ROLLOVER_FULL20_ANALYSIS.csv
    analysis/validated/ROLLOVER_FULL20_SUMMARY.txt
    analysis/validated/H14_RANDOMIZED_ROLLOVER.csv
    analysis/validated/ROLLOVER_WOTS_PAIR_SUMMARY.csv

## 7. Mechanistic model

The validated model uses the original measurements for h0 = 6, 8, 10,
and 12, and pooled randomized measurements for the four h0 = 14 cells.

The key-generation model is:

    T_KG = c + N4 L4 + N16 L16

with:

- L4 = 1.342929 ms per leaf
- L16 = 2.402324 ms per leaf
- R^2 = 0.999932749

The FAST/BDS signing model is:

    T_sign = c(w0) + (h0 / 2) L'(w0)

For w0 = 4:

- L' = 1.324607 ms per leaf
- R^2 = 0.999718961

For w0 = 16:

- L' = 2.365887 ms per leaf
- R^2 = 0.999732288

The signing-derived and independently estimated key-generation leaf
costs differ by approximately:

- 1.364% for w = 4
- 1.517% for w = 16

These values are empirical Raspberry Pi 5 workload measurements and
must not be interpreted as universal primitive-operation costs.

Relevant files:

    analysis/validated/MECHANISTIC_MODEL_VALIDATED_20CELL_INPUT.csv
    analysis/validated/MECHANISTIC_MODEL_VALIDATED_FINAL.csv
    analysis/validated/MECHANISTIC_MODEL_VALIDATED_SUMMARY.txt
    analysis/validated/VALIDATED_MECHANISTIC_FINDING.txt

## 8. Pareto sensitivity

All Pareto objectives are minimized.

Scenario A includes:

- mean signing latency
- P95 signing latency
- signature size
- serialized secret/state size

Strict nondominated configurations: 3.

Scenario B adds mean key-generation latency.

Strict nondominated configurations: 10.

Scenario C additionally adds mean verification latency.

Strict nondominated configurations: 12.

Under the all-objective robust-dominance sensitivity rule:

    A_m * (1 + epsilon) <= B_m

for every objective m, the number of nondominated configurations is:

| Scenario | Strict | 2% | 5% | 10% |
|---|---:|---:|---:|---:|
| A | 3 | 12 | 12 | 12 |
| B | 10 | 16 | 16 | 16 |
| C | 12 | 20 | 20 | 20 |

These sets represent deployment trade-offs. They are not rankings and
no configuration is described as universally optimal.

Relevant files:

    analysis/validated/PARETO_VALIDATED_20CELL_INPUT.csv
    analysis/validated/PARETO_VALIDATED_MEMBERSHIP.csv
    analysis/validated/PARETO_VALIDATED_SUMMARY.txt
    analysis/validated/VALIDATED_PARETO_FINDING.txt

## 9. Build reproduction

The exact historical compiler shell command was not preserved because
the original build logs are empty.

The repository therefore provides a reconstructed Makefile using the
application compilation settings preserved in the experimental
documentation:

    -std=gnu11
    -O3
    -Wall
    -Wextra
    -Wpedantic
    -DNDEBUG
    -DXMSSMT
    -DFAST_IMPL

and links against:

    libcrypto

The exact source snapshot used for the measured binary is published in:

    source_full/

The benchmark harness and configuration matrix are in:

    benchmark/

The historical measured executable had SHA-256:

    fcc98259601c07540cce74b52850eb61ceaf6db9be49b83be223bc232730d83d

The reconstructed binary is not bit-for-bit or .text-byte identical to
the historical executable. Bitwise or instruction-level identity is
therefore not claimed.

Nevertheless, the historical and reconstructed executables had:

- identical .text size
- identical .data size
- identical .bss size
- identical .rodata contents
- 76 defined text functions in each binary
- identical function sizes for all 76 functions
- no functions present in only one binary

See:

    provenance/RECONSTRUCTED_BUILD_PROVENANCE.txt
    provenance/BINARY_SYMBOL_COMPARISON.txt
    provenance/RECONSTRUCTED_BUILD_SHA256.txt

## 10. Integrity manifests

Repository components are independently hashed in:

    provenance/BUILDABLE_SOURCE_SHA256.csv
    provenance/H14_RANDOMIZED_RAW_SHA256.csv
    provenance/VALIDATED_ANALYSIS_SHA256.csv
    provenance/VERIFICATION_EVIDENCE_SHA256.txt
    provenance/RECONSTRUCTED_BUILD_SHA256.txt

A repository-wide integrity manifest is generated before release.

## 11. Rebuilding

From the repository root:

    make clean
    make info
    make

The resulting executable is:

    build/unified_fullcycle_benchmark

Its interface is:

    CONFIG H0 H1 W0 W1 EXPECTED_SIG EXPECTED_SK OUTPUT.csv

For the complete campaign matrix, see:

    benchmark/UNIFIED_20CELL_MATRIX.csv

and:

    benchmark/run_unified_20cell.sh

## 12. Interpretation safeguards

- The heterogeneous XMSSMT configurations are experimental.
- They do not have standardized OIDs.
- Logical hash calls are instrumentation-level logical operations and
  are not equivalent to SHA compression-function calls.
- Serialized secret-key sizes include implementation state and cached
  material; they should not be interpreted as purely secret entropy.
- Full-cycle observations are serially structured by the BDS traversal
  state and should not be treated as independent identically
  distributed samples.
- Outliers were retained rather than removed.
- Pareto configurations represent trade-offs rather than a unique best
  parameter set.
