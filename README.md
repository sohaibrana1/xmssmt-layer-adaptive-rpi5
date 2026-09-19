# Layer-Adaptive XMSSMT Parameterization on Raspberry Pi 5

This repository contains the processed data, analysis scripts, supplementary material, figures, and reproducibility artifacts associated with the manuscript:

**Layer-Adaptive XMSSMT Parameterization: A Multi-Objective Study of WOTS Placement, Tree-Height Allocation, and Serialized State**

## Authors

- Sohaib Rana
- Mohd Najwadi Yusoff
- Je Sen Teh
- Adnan Anwar

## Overview

This study evaluates layer-adaptive parameterization of a two-layer XMSSMT FAST/BDS implementation.

The experimental design combines five tree-height allocations:

- (10,10)
- (8,12)
- (12,8)
- (6,14)
- (14,6)

and four ordered WOTS allocations:

- (16,16)
- (4,16)
- (16,4)
- (4,4)

This produces a 20-configuration empirical design space.

The evaluated configurations are experimental implementation-level parameterizations and are not standardized XMSSMT parameter sets or standardized OIDs.

## Experimental platform

- Raspberry Pi 5 Model B Rev 1.1
- ARM Cortex-A76 / AArch64
- Debian 13
- GCC 14.2.0
- CPU governor: performance
- CPU affinity: logical CPU 3
- Timer: CLOCK_MONOTONIC_RAW
- FAST/BDS XMSSMT implementation

Standard benchmark protocol:

- 10 key generations
- 100 signatures
- 100 verifications

## Main findings

For configurations with identical 7075-byte signatures, lower-layer placement of w=4 reduced mean signing latency by 40.83% to 45.09% relative to upper-layer placement.

The corresponding serialized secret-key reduction was 2112 bytes for every tested height allocation.

Relative to the balanced (10,10) allocation, serialized state changed by:

- (8,12): -240 B
- (12,8): +240 B
- (6,14): -480 B
- (14,6): +480 B

The five-objective empirical Pareto analysis identified 13 nondominated configurations among the 20 evaluated configurations.

## Repository structure

- `data/processed/` - processed benchmark and analysis datasets
- `data/provenance/` - source mapping and normalization provenance
- `analysis/` - scripts used for normalization and analysis
- `supplementary/` - LaTeX result and supplementary tables
- `figures/` - publication figures
- `manuscript/` - reference manuscript PDF
- `integrity/` - SHA-256 manifests and closure records

## Methodological note

The combined 20-configuration analysis reuses measurements from frozen HEIGHT, WOTS, and JOINT experimental phases. It should therefore be interpreted as an empirical comparison and multi-objective analysis of frozen datasets rather than as a single-session matched full-factorial experiment.

## Data availability

Processed benchmark datasets and analysis artifacts supporting the reported results are included in this repository.

## Code availability

The analysis scripts used to generate the reported results are included in the `analysis/` directory.

## Citation

Citation information will be updated when the associated manuscript receives a DOI.

## Integrity

The frozen Stage 7L analysis manifest has SHA-256:

`9a4e19dff91be39cfdff5b5cb0a163d6c90b2b625f5ff603b7a00d3f749ae07a`
