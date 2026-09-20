# Layer-Adaptive XMSSMT Parameterization on Raspberry Pi 5

Reproducibility materials for the manuscript:

**Layer-Adaptive XMSSMT Parameterization: A Multi-Objective Study of WOTS Placement, Tree-Height Allocation, and Serialized State**

Author: Sohaib Rana  
Affiliation: Universiti Sains Malaysia, Penang, Malaysia

## Study scope

This study evaluates layer-adaptive parameterization of a two-layer XMSSMT FAST/BDS implementation.

The total XMSSMT tree height is fixed at:

- H = 20
- d = 2

### WOTS placement block

Four ordered WOTS+ allocations are evaluated:

- (16,16)
- (4,16)
- (16,4)
- (4,4)

The configurations are used to evaluate the effect of layer-specific Winternitz placement on:

- key-generation latency
- signing latency
- verification latency
- signature size
- serialized secret-key size

### Tree-height allocation block

Five ordered layer-height allocations are evaluated:

- (10,10)
- (8,12)
- (12,8)
- (6,14)
- (14,6)

All allocations satisfy:

- h0 + h1 = 20

### Joint parameter space

The five height allocations are combined with the four ordered WOTS+ allocations, producing a 20-configuration empirical design space.

The evaluated heterogeneous configurations are experimental implementation-level parameterizations.

They are not standardized XMSSMT parameter sets and are not assigned standardized OIDs.

## Platform

Measurements were collected on:

- Raspberry Pi 5 Model B Rev. 1.1
- Broadcom BCM2712
- quad-core Arm Cortex-A76
- AArch64
- approximately 8 GB RAM
- Debian GNU/Linux 13 (trixie)
- GCC 14.2.0
- performance CPU-frequency governor
- benchmark process pinned to CPU 3
- CLOCK_MONOTONIC_RAW timing source
- boost disabled during controlled benchmarking

Standard benchmark protocol:

- 10 key generations
- 100 signatures
- 100 verifications
- 3 warm-up key generations
- 100 warm-up signatures

## Repository structure

- `analysis/` - publication-level analysis scripts
- `data/processed/` - normalized operation-level and summary datasets
- `data/provenance/` - source mapping and normalization provenance
- `build_metadata/` - build, platform, and source-provenance records
- `figures/` - publication figures
- `integrity/` - analysis closure and integrity records
- `manifests/` - SHA-256 manifests
- `manuscript/` - reference manuscript PDF
- `source_xmssmt/` - validated XMSSMT source modifications
- `supplementary/` - manuscript supplementary material
- `docs/` - reproducibility documentation
- `releases/` - frozen reproducibility releases

## Source provenance

### Heterogeneous XMSSMT source

Validated modified source files are provided under:

`source_xmssmt/heterogeneous/`

The source snapshot contains:

- `params.h`
- `params.c`
- `xmss_core_fast.c`
- `xmss_commons.c`
- `LICENSE`
- `README.md`
- `SHA256_SOURCE_MANIFEST.txt`

The four modified C/H files were copied from the validated correctness freeze:

`08_height_heterogeneity/FINAL_CORRECTNESS_FREEZE/source_snapshot`

Their SHA-256 values were independently verified before inclusion in this repository.

### Experimental modifications

The implementation supports:

- independent per-layer XMSSMT tree heights
- independent per-layer WOTS+ Winternitz parameters
- asymmetric FAST/BDS traversal-state handling
- serialized secret-key state accounting
- lower-layer rollover validation

For the two-layer FAST implementation, serialized BDS state contains:

- current state for layer 0
- current state for layer 1
- next state for layer 0

No next-state structure is required for the top layer.

## Main empirical findings

For configurations with identical 7075-byte signatures, placing w=4 in the lower layer rather than the upper layer reduced mean signing latency by approximately:

- 40.83% to 45.09%

The same placement reduced serialized secret-key state by:

- 2112 bytes

for every tested height allocation.

Relative to the balanced (10,10) allocation, serialized state changed by:

- (8,12): -240 B
- (12,8): +240 B
- (6,14): -480 B
- (14,6): +480 B

The five-objective empirical Pareto analysis identified:

- 13 nondominated configurations
- 7 dominated configurations

among the 20 evaluated configurations.

## Methodological note

The combined 20-configuration analysis reuses measurements from frozen HEIGHT, WOTS, and JOINT experimental phases.

It should therefore be interpreted as an empirical comparison and multi-objective analysis of frozen datasets rather than as a single-session matched full-factorial experiment.

## Experimental integrity

This repository is a derived reproducibility copy created from frozen experimental artifacts.

The authoritative benchmark, correctness, source, and analysis freeze directories were not modified during preparation of this repository.

The Stage 7L joint-analysis freeze passed SHA-256 integrity verification.

Stage 7L manifest SHA-256:

`9a4e19dff91be39cfdff5b5cb0a163d6c90b2b625f5ff603b7a00d3f749ae07a`

## Licensing

The repository contains source code and research artifacts with potentially different licensing and attribution requirements.

The original source license is preserved under:

`source_xmssmt/heterogeneous/LICENSE`

See `LICENSES.md` for repository-level licensing and attribution information.

## Citation

Citation metadata are provided in:

`CITATION.cff`

Repository:

https://github.com/sohaibrana1/xmssmt-layer-adaptive-rpi5

## Supplementary material

The journal supplementary package contains:

- processed operation-level benchmark data
- summary datasets
- Pareto-analysis outputs
- WOTS-placement analysis
- tree-height allocation analysis
- normalization provenance
- analysis scripts
- SHA-256 integrity records

## Data archive

A permanent archival DOI will be added after creation of the frozen public reproducibility release.

Until then, this GitHub repository serves as the reproducibility repository associated with the manuscript.

## Release

The first frozen public reproducibility release will be tagged:

`v1.0.0`

The release will contain:

- validated heterogeneous XMSSMT source
- processed benchmark datasets
- analysis scripts
- provenance records
- publication figures
- supplementary material
- SHA-256 integrity manifests
- reproducibility documentation

The corresponding Zenodo DOI will be added after archival.

## Reproducibility and validation update

The complete reproducibility protocol, reconstructed build procedure,
verification evidence, randomized `h0=14` validation, rollover
reanalysis, mechanistic model, Pareto sensitivity analysis, and
interpretation safeguards are documented in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

Key public evidence added in this update includes:

- complete buildable source snapshot under `source_full/`;
- benchmark harness and 20-cell matrix under `benchmark/`;
- verification evidence for all 87,316 original full-cycle signatures;
- three randomized repetitions of all four `h0=14` configurations,
  comprising 196,620 additional signing and verification observations;
- validated anomaly, rollover, mechanistic-model, and Pareto analyses
  under `analysis/validated/`;
- SHA-256 provenance manifests under `provenance/`.

The heterogeneous XMSSMT configurations used in this study are
experimental research configurations and are not standardized
XMSS/XMSSMT parameter sets or standardized OIDs.
