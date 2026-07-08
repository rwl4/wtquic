#define _POSIX_C_SOURCE 200809L

/*
 * bench_proto — proto-plane microbenchmarks.
 *
 * Emits one JSON object per metric: {"name", "iters", "ns_per_op",
 * "mops"} — median of three timed repetitions on a monotonic clock,
 * with a volatile sink defeating dead-code elimination. Report-only:
 * thresholds live in the plan's performance contract and harden into
 * CI gates once nightly baselines stabilize.
 *
 * --smoke runs one tiny repetition so CTest keeps the binary honest
 * without spending benchmark time.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wtquic/error.h>

#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/preamble.h"
#include "proto/qpack_static.h"
#include "proto/varint.h"

static volatile uint64_t sink;

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef uint64_t (*bench_fn)(uint64_t iters);

static void report(const char *name, bench_fn fn, uint64_t iters,
                   int smoke)
{
    uint64_t ns[3];
    int reps = smoke ? 1 : 3;

    if (smoke)
        iters = 1000;

    for (int r = 0; r < reps; r++) {
        uint64_t t0 = now_ns();
        sink += fn(iters);
        ns[r] = now_ns() - t0;
    }
    /* median of three */
    uint64_t med = ns[0];
    if (reps == 3) {
        if ((ns[0] <= ns[1] && ns[1] <= ns[2]) ||
            (ns[2] <= ns[1] && ns[1] <= ns[0]))
            med = ns[1];
        else if ((ns[1] <= ns[0] && ns[0] <= ns[2]) ||
                 (ns[2] <= ns[0] && ns[0] <= ns[1]))
            med = ns[0];
        else
            med = ns[2];
    }

    double ns_per_op = (double)med / (double)iters;
    printf("{\"name\": \"%s\", \"iters\": %llu, \"ns_per_op\": %.2f, "
           "\"mops\": %.1f}\n",
           name, (unsigned long long)iters, ns_per_op,
           1000.0 / (ns_per_op > 0.0001 ? ns_per_op : 0.0001));
}

/* --- metric bodies ----------------------------------------------------- */

static uint64_t bench_varint_decode(uint64_t iters)
{
    /* the eight boundary encodings, cycled */
    static const uint8_t wire[] = {
        0x00, 0x3f, 0x40, 0x40, 0x7f, 0xff, 0x80, 0x00, 0x40, 0x00,
        0xbf, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    static const size_t offs[] = { 0, 1, 2, 4, 6, 10, 14, 22 };
    static const size_t lens[] = { 1, 1, 2, 2, 4, 4, 8, 8 };
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        size_t k = (size_t)(i & 7);
        uint64_t v = 0;
        size_t c = 0;
        (void)wtq_varint_decode(wire + offs[k], lens[k], &v, &c);
        acc += v + c;
    }
    return acc;
}

static uint64_t bench_preamble_parse(uint64_t iters)
{
    static const uint8_t wire[] = { 0x40, 0x41, 0x40, 0x40 }; /* sid 64 */
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        wtq_preamble_t p;
        (void)wtq_preamble_decode(WTQ_PREAMBLE_KIND_BIDI, wire,
                                  sizeof(wire), &p);
        acc += p.session_id + p.header_len;
    }
    return acc;
}

static uint64_t bench_capsule_header(uint64_t iters)
{
    /* CLOSE header + code, no reason: full capsule parse */
    static const uint8_t wire[] = { 0x68, 0x43, 0x04, 0x00, 0x00, 0x12,
                                    0x34 };
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        wtq_capsule_dec_t dec;
        wtq_capsule_t c;
        size_t consumed = 0;
        wtq_capsule_dec_init(&dec);
        (void)wtq_capsule_dec_feed(&dec, wire, sizeof(wire), &c,
                                   &consumed);
        acc += c.close_code + consumed;
    }
    return acc;
}

static uint8_t g_connect_section[256];
static size_t g_connect_section_len;

static void build_connect_section(void)
{
    wtq_sf_str_t offer[2] = { { "moqt-18", 7 }, { "moqt-16", 7 } };

    if (wtq_connect_encode_request("example.com", 11, "/moq", 4, NULL, 0,
                                   offer, 2, g_connect_section,
                                   sizeof(g_connect_section),
                                   &g_connect_section_len) !=
        WTQ_CONNECT_OK) {
        fprintf(stderr, "connect section build failed\n");
        g_connect_section_len = 0;
    }
}

static uint64_t bench_qpack_decode_connect(uint64_t iters)
{
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        wtq_qpack_field_t fields[16];
        size_t count = 0;
        char scratch[256];
        (void)wtq_qpack_decode_section(g_connect_section,
                                       g_connect_section_len, fields, 16,
                                       &count, scratch, sizeof(scratch));
        acc += count;
    }
    return acc;
}

static uint64_t bench_qpack_encode_connect(uint64_t iters)
{
    static const wtq_qpack_field_t fields[5] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "webtransport-h3", 15, false },
    };
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        uint8_t dst[128];
        size_t out_len = 0;
        (void)wtq_qpack_encode_section(fields, 5, dst, sizeof(dst),
                                       &out_len);
        acc += out_len;
    }
    return acc;
}

static uint64_t bench_errmap_roundtrip(uint64_t iters)
{
    uint64_t acc = 0;

    for (uint64_t i = 0; i < iters; i++) {
        uint32_t app = (uint32_t)(i * 2654435761u);
        uint32_t back = 0;
        (void)wtq_h3_error_to_app(wtq_app_error_to_h3(app), &back);
        acc += back;
    }
    return acc;
}

int main(int argc, char **argv)
{
    int smoke = (argc >= 2 && strcmp(argv[1], "--smoke") == 0);

    build_connect_section();
    if (g_connect_section_len == 0)
        return 1;

    printf("[\n");
    report("varint_decode", bench_varint_decode, 50000000, smoke);
    printf(",");
    report("preamble_parse", bench_preamble_parse, 20000000, smoke);
    printf(",");
    report("capsule_parse", bench_capsule_header, 20000000, smoke);
    printf(",");
    report("qpack_decode_connect", bench_qpack_decode_connect, 500000,
           smoke);
    printf(",");
    report("qpack_encode_connect", bench_qpack_encode_connect, 1000000,
           smoke);
    printf(",");
    report("errmap_roundtrip", bench_errmap_roundtrip, 100000000, smoke);
    printf("]\n");

    return (sink == UINT64_MAX) ? 1 : 0; /* keep the sink observable */
}
