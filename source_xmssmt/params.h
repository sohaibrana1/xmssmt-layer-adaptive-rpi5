#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* These are merely internal identifiers for the supported hash functions. */
#define XMSS_SHA2 0
#define XMSS_SHAKE128 1
#define XMSS_SHAKE256 2

/* This is a result of the OID definitions in the draft; needed for parsing. */
#define XMSS_OID_LEN 4

/*
 * Maximum XMSSMT layer count supported by the parameter sets in params.c.
 * Existing standardized configurations use d <= 12.
 */
#define XMSS_MAX_LAYERS 12

/* This structure will be populated when calling xmss[mt]_parse_oid. */
typedef struct {
    unsigned int func;
    unsigned int n;
    unsigned int padding_len;
    unsigned int wots_w;
    unsigned int wots_log_w;
    unsigned int wots_len1;
    unsigned int wots_len2;
    unsigned int wots_len;
    unsigned int wots_sig_bytes;

    /*
     * Layer-specific WOTS parameters.
     *
     * During the generalized-equivalence stage these are initialized
     * identically to the legacy scalar values. Later experimental XMSSMT
     * configurations may assign different WOTS parameters per layer.
     */
    unsigned int wots_w_layer[XMSS_MAX_LAYERS];
    unsigned int wots_log_w_layer[XMSS_MAX_LAYERS];
    unsigned int wots_len1_layer[XMSS_MAX_LAYERS];
    unsigned int wots_len2_layer[XMSS_MAX_LAYERS];
    unsigned int wots_len_layer[XMSS_MAX_LAYERS];
    unsigned int wots_sig_bytes_layer[XMSS_MAX_LAYERS];

    /*
     * Layer-specific XMSS tree heights.
     *
     * Standard homogeneous parameter sets initialize every active layer
     * to the legacy scalar tree_height value. Experimental XMSSMT
     * configurations may subsequently assign unequal heights while
     * preserving sum(tree_height_layer[i]) == full_height.
     */
    unsigned int tree_height_layer[XMSS_MAX_LAYERS];

    unsigned int full_height;
    unsigned int tree_height;
    unsigned int d;
    unsigned int index_bytes;
    unsigned int sig_bytes;
    unsigned int pk_bytes;
    unsigned long long sk_bytes;
    unsigned int bds_k;
} xmss_params;

/**
 * Accepts strings such as "XMSS-SHA2_10_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmss_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts takes strings such as "XMSSMT-SHA2_20/2_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmssmt_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmss_parse_oid(xmss_params *params, const uint32_t oid);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);


/* Given a params struct where the following properties have been initialized;
    - full_height; the height of the complete (hyper)tree
    - n; the number of bytes of hash function output
    - d; the number of layers (d > 1 implies XMSSMT)
    - func; one of {XMSS_SHA2, XMSS_SHAKE128, XMSS_SHAKE256}
    - wots_w; the Winternitz parameter
    - optionally, bds_k; the BDS traversal trade-off parameter,
    this function initializes the remainder of the params structure. */
int xmss_xmssmt_initialize_params(xmss_params *params);

/*
 * Build a temporary scalar parameter view for one XMSSMT layer.
 * Existing WOTS routines can consume this view without modification.
 */
int xmss_params_for_layer(const xmss_params *base,
                          unsigned int layer,
                          xmss_params *layer_params);

/*
 * Return the number of bytes occupied by stored upper-layer WOTS
 * signatures in the FAST XMSSMT secret key.
 *
 * Layer 0 is signed dynamically and is not stored here.
 */
unsigned long long xmss_upper_wots_storage_bytes(
    const xmss_params *params);

/*
 * Return the byte offset of a stored upper-layer WOTS signature
 * relative to the start of the FAST wots_sigs area.
 *
 * Valid only for layer >= 1.
 */
unsigned long long xmss_upper_wots_storage_offset(
    const xmss_params *params,
    unsigned int layer);

/*
 * Configure the WOTS parameter of one XMSSMT layer.
 *
 * This is an experimental parameterization API. It does not assign
 * or alter any standardized XMSS/XMSSMT OID.
 */
int xmss_set_layer_wots(xmss_params *params,
                        unsigned int layer,
                        unsigned int w);

/*
 * Recompute aggregate signature and serialized secret-key sizes
 * after one or more layer-specific WOTS parameters are changed.
 */
int xmss_recompute_layer_dependent_sizes(xmss_params *params);

/*
 * Atomically configure the XMSS tree height of every active XMSSMT layer.
 *
 * Experimental parameterization only. The supplied heights must:
 *   - contain exactly d entries;
 *   - each be greater than bds_k;
 *   - each satisfy an even (h_i - bds_k), as required by the
 *     traversal schedule used by this FAST implementation;
 *   - sum exactly to full_height.
 *
 * This function does not assign or alter any standardized OID.
 */
int xmss_set_layer_heights(xmss_params *params,
                           const unsigned int *heights,
                           unsigned int count);

#endif
