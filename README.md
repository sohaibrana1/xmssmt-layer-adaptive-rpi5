# Layer-Adaptive XMSSMT Parameterization on Raspberry Pi 5

Reproducibility materials for the manuscript:

**Layer-Adaptive XMSSMT Parameterization: A Multi-Objective Study of WOTS Placement, Tree-Height Allocation, and Serialized State**

Sohaib Rana, Mohd Najwadi Yusoff, Je Sen Teh, and Adnan Anwar
(Universiti Sains Malaysia; Deakin University)

The version cited in the manuscript is tag `jcen-submission-v1`.

## Study scope

The study evaluates ordered layer-specific tree-height and WOTS+ parameterization in a two-layer XMSSMT FAST/BDS implementation with total height H = 20, d = 2, n = 32, and BDS parameter k = 0.

- Height allocations (h0, h1): (6,14), (8,12), (10,10), (12,8), (14,6)
- Ordered WOTS+ placements (w0, w1): (16,16), (16,4), (4,16), (4,4)

Layer 0 is the lower (message-signing) layer. The Cartesian product gives 20 experimental configurations. These are research configurations only; they are not standardized XMSSMT parameter sets and have no standardized OIDs.

## Measurement protocol

All 20 configurations use one matched full-cycle protocol on a Raspberry Pi 5 (BCM2712, Cortex-A76, 2.4 GHz, performance governor, process pinned to CPU 3, `CLOCK_MONOTONIC_RAW`, per-operation hardware cycles via `perf_event_open()`):

- 10 key generations per configuration;
- signing over one complete lower-layer traversal cycle plus the first signature after rollover (2^h0 + 1 signatures; 87,316 in total);
- every signature verified immediately (87,316 verifications, 0 failures);
- per-operation logical-work counters (PRF, F, H, message-hash invocations, tree nodes).

The four h0 = 14 configurations were additionally repeated three times in independently randomized order (196,620 further signing and verification operations, 0 verification failures). Configuration-level modelling and Pareto analyses use the pooled randomized measurements for h0 = 14.

Full details: [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

## Main results

- **Lower-layer WOTS placement dominates routine signing cost.** With w1 = 16, changing w0 from 16 to 4 reduces mean full-cycle signing latency by approximately 44–46% at every height allocation. (4,16) and (16,4) produce identical 7075-byte signatures.
- **Artifact sizes follow exact formulas**, reproduced with zero-byte residuals for all 20 configurations:
  - signature: |σ| = 675 + W0 + W1 bytes
  - serialized state: |SK| = 2654 + 120·h0 + W1 bytes

  where W = 4256 B for w = 4 and 2144 B for w = 16. The serialized state includes the cached upper-layer WOTS signature, which is public material.
- **Rollover is never a tail-latency event.** In all 20 configurations and all 12 randomized h0 = 14 reruns, the rollover signature is below the configuration's P95 and is never the maximum-latency signature.
- **A single per-leaf cost explains key generation and signing.** Leaf costs fitted independently from key generation and from the slope of signing versus h0 agree within 1.6% (w = 4: 1.343 vs 1.325 ms/leaf; w = 16: 2.402 vs 2.366 ms/leaf).
- **Cycles per logical hash are nearly constant**: 1706.7–1745.9 cycles per logical-hash invocation across all 20 configurations.
- **Pareto analysis** (strict / relaxed ε / margin ε, ε ∈ {2, 5, 10}%): Scenario A (mean sign, P95 sign, signature, state) 3 / 2 / 12; Scenario B (+ key generation) 10 / 9 / 16; Scenario C (+ verification) 12 / 9 / 20. Under relaxed dominance, (6,14,4,16) and (6,14,16,16) remain on the Scenario A front.

An approximately 10% upper-layer effect seen in the original single run at h0 = 14 was not reproduced by the randomized repetitions and is not interpreted as an algorithmic effect (see `analysis/validated/H14_ANOMALY_RESOLUTION.txt`).

## Repository structure

| Path | Contents |
|---|---|
| `source_full/` | Complete buildable XMSSMT source snapshot used for the measurements |
| `source_xmssmt/` | The modified heterogeneous source files (`heterogeneous/` holds the verified snapshot with its license) |
| `benchmark/` | Full-cycle benchmark harness, run script, and 20-configuration matrix |
| `Makefile` | Reconstructed build (see REPRODUCIBILITY.md §9) |
| `data/` | `ALL_20CELL_SIGNING_ROWS.csv` (per-signature rows), `UNIFIED_20CELL_OPERATION_STATISTICS.csv` (per-configuration statistics), `verification/`, and raw randomized h0 = 14 runs in `validation_h14/` |
| `analysis/` | Aggregate workload model and analytical size model outputs |
| `analysis/validated/` | Validated h0 = 14, rollover, mechanistic-model, keygen, and Pareto analyses |
| `analysis/publication/` | Figure data and the figure-generation script |
| `tables/` | Publication tables (LaTeX and CSV) |
| `figures/` | Publication figures |
| `provenance/` | SHA-256 provenance records, build provenance, OpenSSL backend record, randomized-run logs |
| `legacy_superseded/` | Data, scripts, figures, and tables from an earlier exploratory campaign with a different signing-window protocol; superseded and **not used** in the manuscript |
| `SHA256_REPOSITORY_MANIFEST.txt` | SHA-256 of every tracked file |

## Reproducing

```bash
make clean && make info && make
# executable: build/unified_fullcycle_benchmark
# interface:  CONFIG H0 H1 W0 W1 EXPECTED_SIG EXPECTED_SK OUTPUT.csv
# full matrix: benchmark/run_unified_20cell.sh with benchmark/UNIFIED_20CELL_MATRIX.csv
```

The reconstructed build reproduces the source-level and functional workflow but is not claimed to be bitwise identical to the historical benchmark binary (see `provenance/RECONSTRUCTED_BUILD_PROVENANCE.txt`).

Integrity check:

```bash
sha256sum -c --quiet SHA256_REPOSITORY_MANIFEST.txt && echo OK
```

## Interpretation notes

- Logical-hash counts are XMSS/XMSSMT-level invocations, not SHA-256 compression-function calls.
- Fitted model coefficients are platform- and implementation-specific calibrations, not universal primitive costs.
- Pareto sets describe deployment trade-offs, not a ranking or a universally optimal configuration.

## Licensing and citation

The original source license is preserved in `source_xmssmt/heterogeneous/LICENSE`; see `LICENSES.md` for repository-level licensing. Citation metadata are in `CITATION.cff`.
