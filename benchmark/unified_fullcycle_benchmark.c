#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "params.h"
#include "xmss_core.h"
#include "instrumentation.h"

#define PARAMETER_SET "XMSSMT-SHA2_20/2_256"
#define MESSAGE_BYTES 32

#define KEYGEN_RUNS 10

#define WARMUP_KEYGENS 3
#define WARMUP_SIGNATURES 100

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return (uint64_t)ts.tv_sec * 1000000000ULL
         + (uint64_t)ts.tv_nsec;
}

static void prepare_message(
    unsigned char msg[MESSAGE_BYTES],
    unsigned int iteration)
{
    memset(msg, 0xA5, MESSAGE_BYTES);

    msg[0] = (unsigned char)(iteration & 0xFF);
    msg[1] = (unsigned char)((iteration >> 8) & 0xFF);
    msg[2] = (unsigned char)((iteration >> 16) & 0xFF);
    msg[3] = (unsigned char)((iteration >> 24) & 0xFF);
}

static int read_signature_index(const unsigned char *sk,
                                const xmss_params *params,
                                uint64_t *index_out)
{
    const unsigned char *index_bytes;
    uint64_t index = 0U;
    unsigned int i;

    if (params->index_bytes > sizeof(uint64_t)) {
        fprintf(stderr,
                "ERROR: The secret-key index uses %u bytes; "
                "this runner supports at most %zu bytes.\n",
                params->index_bytes,
                sizeof(uint64_t));

        return -1;
    }

    index_bytes = sk;

    for (i = 0U; i < params->index_bytes; i++) {
        index = (index << 8) | (uint64_t)index_bytes[i];
    }

    *index_out = index;
    return 0;
}

static int perf_event_open_wrapper(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return (int)syscall(
        __NR_perf_event_open,
        attr,
        pid,
        cpu,
        group_fd,
        flags);
}

static int open_cycle_counter(void)
{
    struct perf_event_attr attr;
    int fd;

    memset(&attr, 0, sizeof(attr));

    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    fd = perf_event_open_wrapper(
        &attr,
        0,
        -1,
        -1,
        0);

    if (fd == -1) {
        perror("perf_event_open(cpu-cycles)");
        return -1;
    }

    return fd;
}

static int begin_cycle_counter(int fd)
{
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1) {
        perror("PERF_EVENT_IOC_RESET");
        return -1;
    }

    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        perror("PERF_EVENT_IOC_ENABLE");
        return -1;
    }

    return 0;
}

static int end_cycle_counter(int fd, uint64_t *cycles)
{
    ssize_t nread;

    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        perror("PERF_EVENT_IOC_DISABLE");
        return -1;
    }

    nread = read(fd, cycles, sizeof(*cycles));

    if (nread != (ssize_t)sizeof(*cycles)) {
        perror("read(cpu-cycles)");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid;

    const char *config;
    const char *csv_path;

    unsigned int heights[2];

    unsigned int h0;
    unsigned int h1;
    unsigned int w0;
    unsigned int w1;

    unsigned long long expected_sig;
    unsigned long long expected_sk;

    unsigned char message[MESSAGE_BYTES];

    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    unsigned char *sm = NULL;
    unsigned char *recovered = NULL;

    unsigned long long smlen;
    unsigned long long recovered_len;

    unsigned int i;
    unsigned int verification_passes = 0;
    unsigned int sign_runs;

    uint64_t signature_index_before;
    uint64_t signature_index_after;

    hbs_counters_t operation_counters;
    uint64_t logical_hash_calls;
    uint64_t cpu_cycles = 0U;
    int cycle_fd = -1;

    FILE *csv = NULL;

    int rc = 1;

    if (argc != 9) {
        fprintf(stderr,
                "usage: %s CONFIG H0 H1 W0 W1 EXPECTED_SIG EXPECTED_SK OUTPUT.csv\n",
                argv[0]);
        return 2;
    }

    config = argv[1];

    h0 = (unsigned int)strtoul(argv[2], NULL, 10);
    h1 = (unsigned int)strtoul(argv[3], NULL, 10);

    w0 = (unsigned int)strtoul(argv[4], NULL, 10);
    w1 = (unsigned int)strtoul(argv[5], NULL, 10);

    expected_sig = strtoull(argv[6], NULL, 10);
    expected_sk = strtoull(argv[7], NULL, 10);

    csv_path = argv[8];

    heights[0] = h0;
    heights[1] = h1;

    if (h0 >= 31U) {
        fprintf(stderr, "FAIL: h0 too large for sign-run calculation\n");
        return 1;
    }

    sign_runs = (1U << h0) + 1U;

    if (xmssmt_str_to_oid(&oid, PARAMETER_SET) != 0) {
        fprintf(stderr, "FAIL: OID\n");
        return 1;
    }

    if (xmssmt_parse_oid(&params, oid) != 0) {
        fprintf(stderr, "FAIL: parse\n");
        return 1;
    }

    if (xmss_set_layer_heights(
            &params,
            heights,
            2) != 0) {

        fprintf(stderr, "FAIL: heights\n");
        return 1;
    }

    if (xmss_set_layer_wots(&params, 0, w0) != 0 ||
        xmss_set_layer_wots(&params, 1, w1) != 0) {

        fprintf(stderr, "FAIL: WOTS\n");
        return 1;
    }

    if (params.sig_bytes != expected_sig ||
        params.pk_bytes != 64 ||
        params.sk_bytes != expected_sk) {

        fprintf(stderr, "FAIL: size invariant\n");
        return 1;
    }

    pk = malloc(params.pk_bytes);
    sk = malloc(params.sk_bytes);

    sm = malloc(
        (size_t)params.sig_bytes + MESSAGE_BYTES);

    recovered = malloc(
        (size_t)params.sig_bytes + MESSAGE_BYTES);

    if (!pk || !sk || !sm || !recovered) {
        fprintf(stderr, "FAIL: allocation\n");
        goto cleanup;
    }

    cycle_fd = open_cycle_counter();

    if (cycle_fd == -1) {
        fprintf(stderr, "FAIL: CPU cycle counter unavailable\n");
        goto cleanup;
    }

    csv = fopen(csv_path, "w");

    if (!csv) {
        perror("fopen");
        goto cleanup;
    }

    fprintf(csv,
        "configuration,h0,h1,w0,w1,operation,iteration,"
        "signature_index_before,signature_index_after,"
        "latency_ns,latency_ms,cpu_cycles,verification_pass,"
        "logical_hash_calls,prf_calls,hash_f_calls,hash_h_calls,"
        "hash_message_calls,wots_chain_steps,tree_nodes,"
        "auth_path_nodes,bds_updates,"
        "signature_bytes,public_key_bytes,secret_key_bytes\n");

    for (i = 0; i < WARMUP_KEYGENS; i++) {
        memset(pk, 0, params.pk_bytes);
        memset(sk, 0, params.sk_bytes);

        if (xmssmt_core_keypair(
                &params,
                pk,
                sk) != 0) {

            fprintf(stderr,
                    "FAIL: warmup keygen %u\n",
                    i);
            goto cleanup;
        }
    }

    memset(pk, 0, params.pk_bytes);
    memset(sk, 0, params.sk_bytes);

    if (xmssmt_core_keypair(&params, pk, sk) != 0) {
        fprintf(stderr, "FAIL: warmup signing key\n");
        goto cleanup;
    }

    for (i = 0; i < WARMUP_SIGNATURES; i++) {
        prepare_message(message, i);

        smlen = 0;

        if (xmssmt_core_sign(
                &params,
                sk,
                sm,
                &smlen,
                message,
                MESSAGE_BYTES) != 0) {

            fprintf(stderr,
                    "FAIL: warmup sign %u\n",
                    i);
            goto cleanup;
        }
    }

    for (i = 0; i < KEYGEN_RUNS; i++) {
        uint64_t t0;
        uint64_t t1;
        uint64_t elapsed;

        memset(pk, 0, params.pk_bytes);
        memset(sk, 0, params.sk_bytes);

        counters_reset();

        if (begin_cycle_counter(cycle_fd) != 0) {
            goto cleanup;
        }

        t0 = now_ns();

        if (xmssmt_core_keypair(
                &params,
                pk,
                sk) != 0) {

            fprintf(stderr,
                    "FAIL: keygen %u\n",
                    i);
            goto cleanup;
        }

        t1 = now_ns();
        elapsed = t1 - t0;

        if (end_cycle_counter(cycle_fd, &cpu_cycles) != 0) {
            goto cleanup;
        }

        operation_counters = g_hbs_counters;

        logical_hash_calls =
            operation_counters.prf_calls +
            operation_counters.hash_f_calls +
            operation_counters.hash_h_calls +
            operation_counters.hash_message_calls;

        fprintf(csv,
            "%s,%u,%u,%u,%u,keygen,%u,,,"
            "%" PRIu64 ",%.9f,%" PRIu64 ",,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%u,%u,%llu\n",
            config,
            h0,
            h1,
            w0,
            w1,
            i,
            elapsed,
            (double)elapsed / 1000000.0,
            cpu_cycles,
            logical_hash_calls,
            operation_counters.prf_calls,
            operation_counters.hash_f_calls,
            operation_counters.hash_h_calls,
            operation_counters.hash_message_calls,
            operation_counters.wots_chain_steps,
            operation_counters.tree_nodes,
            operation_counters.auth_path_nodes,
            operation_counters.bds_updates,
            params.sig_bytes,
            params.pk_bytes,
            params.sk_bytes);
    }

    memset(pk, 0, params.pk_bytes);
    memset(sk, 0, params.sk_bytes);

    if (xmssmt_core_keypair(
            &params,
            pk,
            sk) != 0) {

        fprintf(stderr,
                "FAIL: signing keygen\n");
        goto cleanup;
    }

    for (i = 0; i < sign_runs; i++) {
        uint64_t t0;
        uint64_t t1;
        uint64_t elapsed;

        prepare_message(message, i);

        smlen = 0;

        if (read_signature_index(
                sk,
                &params,
                &signature_index_before) != 0) {

            fprintf(stderr,
                    "FAIL: could not read pre-sign index at iteration %u\n",
                    i);
            goto cleanup;
        }

        counters_reset();

        if (begin_cycle_counter(cycle_fd) != 0) {
            goto cleanup;
        }

        t0 = now_ns();

        if (xmssmt_core_sign(
                &params,
                sk,
                sm,
                &smlen,
                message,
                MESSAGE_BYTES) != 0) {

            fprintf(stderr,
                    "FAIL: sign %u\n",
                    i);
            goto cleanup;
        }

        t1 = now_ns();
        elapsed = t1 - t0;

        if (end_cycle_counter(cycle_fd, &cpu_cycles) != 0) {
            goto cleanup;
        }

        if (read_signature_index(
                sk,
                &params,
                &signature_index_after) != 0) {

            fprintf(stderr,
                    "FAIL: could not read post-sign index at iteration %u\n",
                    i);
            goto cleanup;
        }

        if (signature_index_after != signature_index_before + 1U) {
            fprintf(stderr,
                    "FAIL: signature index progression at iteration %u: "
                    "%" PRIu64 " -> %" PRIu64 ", expected %" PRIu64 "\n",
                    i,
                    signature_index_before,
                    signature_index_after,
                    signature_index_before + 1U);
            goto cleanup;
        }

        operation_counters = g_hbs_counters;

        logical_hash_calls =
            operation_counters.prf_calls +
            operation_counters.hash_f_calls +
            operation_counters.hash_h_calls +
            operation_counters.hash_message_calls;

        fprintf(csv,
            "%s,%u,%u,%u,%u,sign,%u,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%.9f,%" PRIu64 ",,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%u,%u,%llu\n",
            config,
            h0,
            h1,
            w0,
            w1,
            i,
            signature_index_before,
            signature_index_after,
            elapsed,
            (double)elapsed / 1000000.0,
            cpu_cycles,
            logical_hash_calls,
            operation_counters.prf_calls,
            operation_counters.hash_f_calls,
            operation_counters.hash_h_calls,
            operation_counters.hash_message_calls,
            operation_counters.wots_chain_steps,
            operation_counters.tree_nodes,
            operation_counters.auth_path_nodes,
            operation_counters.bds_updates,
            params.sig_bytes,
            params.pk_bytes,
            params.sk_bytes);

        recovered_len = 0;

        memset(
            recovered,
            0,
            (size_t)params.sig_bytes + MESSAGE_BYTES);

        counters_reset();

        if (begin_cycle_counter(cycle_fd) != 0) {
            goto cleanup;
        }

        t0 = now_ns();

        if (xmssmt_core_sign_open(
                &params,
                recovered,
                &recovered_len,
                sm,
                smlen,
                pk) != 0) {

            fprintf(stderr,
                    "FAIL: verify %u\n",
                    i);
            goto cleanup;
        }

        t1 = now_ns();
        elapsed = t1 - t0;

        if (end_cycle_counter(cycle_fd, &cpu_cycles) != 0) {
            goto cleanup;
        }

        if (recovered_len != MESSAGE_BYTES ||
            memcmp(
                recovered,
                message,
                MESSAGE_BYTES) != 0) {

            fprintf(stderr,
                    "FAIL: verify message %u\n",
                    i);
            goto cleanup;
        }

        verification_passes++;

        operation_counters = g_hbs_counters;

        logical_hash_calls =
            operation_counters.prf_calls +
            operation_counters.hash_f_calls +
            operation_counters.hash_h_calls +
            operation_counters.hash_message_calls;

        fprintf(csv,
            "%s,%u,%u,%u,%u,verify,%u,,,"
            "%" PRIu64 ",%.9f,%" PRIu64 ",1,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%u,%u,%llu\n",
            config,
            h0,
            h1,
            w0,
            w1,
            i,
            elapsed,
            (double)elapsed / 1000000.0,
            cpu_cycles,
            logical_hash_calls,
            operation_counters.prf_calls,
            operation_counters.hash_f_calls,
            operation_counters.hash_h_calls,
            operation_counters.hash_message_calls,
            operation_counters.wots_chain_steps,
            operation_counters.tree_nodes,
            operation_counters.auth_path_nodes,
            operation_counters.bds_updates,
            params.sig_bytes,
            params.pk_bytes,
            params.sk_bytes);
    }

    fflush(csv);

    printf("configuration=%s\n", config);
    printf("h0=%u\n", h0);
    printf("h1=%u\n", h1);
    printf("w0=%u\n", w0);
    printf("w1=%u\n", w1);
    printf("signature_bytes=%u\n", params.sig_bytes);
    printf("public_key_bytes=%u\n", params.pk_bytes);
    printf("secret_key_bytes=%llu\n", params.sk_bytes);
    printf("warmup_keygens=%d\n", WARMUP_KEYGENS);
    printf("warmup_signatures=%d\n", WARMUP_SIGNATURES);
    printf("keygen_rows=%d\n", KEYGEN_RUNS);
    printf("sign_rows=%u\n", sign_runs);
    printf("verify_rows=%u\n", sign_runs);
    printf("verification_passes=%u\n",
           verification_passes);
    printf("timer=CLOCK_MONOTONIC_RAW\n");

    if (verification_passes != sign_runs) {
        fprintf(stderr,
                "FAIL: verification count\n");
        goto cleanup;
    }

    printf("UNIFIED_FULLCYCLE_BENCHMARK=PASS\n");

    rc = 0;

cleanup:
    if (csv) {
        fclose(csv);
    }

    if (cycle_fd >= 0) {
        close(cycle_fd);
    }

    free(pk);
    free(sk);
    free(sm);
    free(recovered);

    return rc;
}
