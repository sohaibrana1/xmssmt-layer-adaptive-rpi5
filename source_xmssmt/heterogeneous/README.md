# Heterogeneous XMSSMT Modified Source

This directory contains the validated modified source files used for the layer-adaptive XMSSMT experiments reported in:

**Layer-Adaptive XMSSMT Parameterization: A Multi-Objective Study of WOTS Placement, Tree-Height Allocation, and Serialized State**

## Included files

- `params.h` - parameter-structure definitions supporting layer-specific XMSSMT settings
- `params.c` - parameter parsing and initialization logic for heterogeneous layer configurations
- `xmss_core_fast.c` - FAST/BDS signing-state implementation adapted for asymmetric XMSSMT layer heights
- `xmss_commons.c` - common XMSS/XMSSMT functions used by the heterogeneous implementation
- `LICENSE` - original source license
- `SHA256_SOURCE_MANIFEST.txt` - SHA-256 integrity manifest for this source snapshot

## Experimental modifications

The implementation supports experimental layer-specific parameterization for a two-layer XMSSMT construction, including:

- independent tree heights for the two layers;
- independent WOTS+ Winternitz parameters for the two layers;
- asymmetric FAST/BDS traversal-state allocation;
- serialized secret-key state accounting;
- rollover validation across lower-layer subtree boundaries.

The evaluated parameter combinations are experimental implementation-level configurations.

They are not standardized XMSSMT parameter sets and are not assigned standardized OIDs.

## Source integrity

The four modified source files in this directory were copied from the validated correctness freeze:

`08_height_heterogeneity/FINAL_CORRECTNESS_FREEZE/source_snapshot`

The SHA-256 values are recorded in:

`SHA256_SOURCE_MANIFEST.txt`

Verification command:

`sha256sum -c SHA256_SOURCE_MANIFEST.txt`

## Reproducibility note

These four files represent the modified heterogeneous XMSSMT logic used in the study.

They are not, by themselves, a complete standalone implementation. The remaining unmodified XMSS/XMSSMT support files and benchmark harness should be preserved separately when preparing a fully buildable reproducibility release.
