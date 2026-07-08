#include <string.h>

#include "proto/h3_frame.h"

#include "test_support.h"

typedef struct known {
    uint64_t type;
    uint64_t length;
    size_t header_len;
    uint8_t wire[16];
} known_t;

static const known_t KNOWN[] = {
    { WTQ_H3_FRAME_DATA,     0, 2, { 0x00, 0x00 } },
    { WTQ_H3_FRAME_HEADERS,  1, 2, { 0x01, 0x01 } },
    { WTQ_H3_FRAME_SETTINGS, 0, 2, { 0x04, 0x00 } },
    { WTQ_H3_FRAME_GOAWAY,   8, 2, { 0x07, 0x08 } },
    /* grease-style unknown type (0x1f*0 + 0x21) with nonzero length */
    { 0x21, 5, 2, { 0x21, 0x05 } },
    /* multi-byte type and length varints */
    { 0x4d, 16384, 6, { 0x40, 0x4d, 0x80, 0x00, 0x40, 0x00 } },
    { 4611686018427387903u, 4611686018427387903u, 16,
      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};
#define N_KNOWN (sizeof(KNOWN) / sizeof(KNOWN[0]))

static const uint64_t BOUNDARIES[] = {
    0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903u,
};
#define N_BOUNDARIES (sizeof(BOUNDARIES) / sizeof(BOUNDARIES[0]))

/* roundtrip for known frame headers, byte-exact */
static void test_known_roundtrip(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        uint8_t buf[16] = { 0 };
        size_t out_len = 0;

        WTQ_TEST_CHECK_EQ_SIZE(wtq_h3_frame_header_len(k->type, k->length),
                               k->header_len);
        WTQ_TEST_CHECK(wtq_h3_frame_encode_header(k->type, k->length, buf,
                                                  sizeof(buf), &out_len) ==
                       WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_SIZE(out_len, k->header_len);
        WTQ_TEST_CHECK(memcmp(buf, k->wire, k->header_len) == 0);

        wtq_h3_frame_t f = { 0, 0, 0 };
        WTQ_TEST_CHECK(wtq_h3_frame_decode_header(k->wire, k->header_len,
                                                  &f) == WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_U64(f.type, k->type);
        WTQ_TEST_CHECK_EQ_U64(f.length, k->length);
        WTQ_TEST_CHECK_EQ_SIZE(f.header_len, k->header_len);
    }

    *fp += failures;
}

/* type and length swept over every varint boundary, both axes */
static void test_boundary_sweep(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_BOUNDARIES; i++) {
        for (size_t j = 0; j < N_BOUNDARIES; j++) {
            uint64_t type = BOUNDARIES[i];
            uint64_t length = BOUNDARIES[j];
            uint8_t buf[16];
            size_t out_len = 0;

            WTQ_TEST_CHECK(wtq_h3_frame_encode_header(type, length, buf,
                                                      sizeof(buf),
                                                      &out_len) ==
                           WTQ_H3_FRAME_OK);
            WTQ_TEST_CHECK_EQ_SIZE(out_len,
                                   wtq_varint_len(type) +
                                       wtq_varint_len(length));

            wtq_h3_frame_t f = { 0, 0, 0 };
            WTQ_TEST_CHECK(wtq_h3_frame_decode_header(buf, out_len, &f) ==
                           WTQ_H3_FRAME_OK);
            WTQ_TEST_CHECK_EQ_U64(f.type, type);
            WTQ_TEST_CHECK_EQ_U64(f.length, length);
            WTQ_TEST_CHECK_EQ_SIZE(f.header_len, out_len);
        }
    }

    *fp += failures;
}

/* encode bounds: too-small buffer untouched; out-of-range rejected */
static void test_encode_bounds(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t cap = 0; cap < k->header_len; cap++) {
            uint8_t buf[16];
            memset(buf, 0xEE, sizeof(buf));
            size_t out_len = 999;
            WTQ_TEST_CHECK(wtq_h3_frame_encode_header(k->type, k->length,
                                                      buf, cap, &out_len) ==
                           WTQ_H3_FRAME_BUFFER);
            for (size_t b = 0; b < sizeof(buf); b++)
                WTQ_TEST_CHECK(buf[b] == 0xEE);
        }
    }

    uint8_t buf[32];
    size_t out_len = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_VARINT_MAX + 1, 0, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_H3_FRAME_RANGE);
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(0, WTQ_VARINT_MAX + 1, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_H3_FRAME_RANGE);
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(UINT64_MAX, UINT64_MAX, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_H3_FRAME_RANGE);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_h3_frame_header_len(WTQ_VARINT_MAX + 1, 0),
                           0);

    *fp += failures;
}

/* decode incomplete for every byte prefix of representative headers */
static void test_incomplete(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t plen = 0; plen < k->header_len; plen++) {
            wtq_h3_frame_t f = { 0, 0, 0 };
            WTQ_TEST_CHECK(wtq_h3_frame_decode_header(k->wire, plen, &f) ==
                           WTQ_H3_FRAME_NEED_MORE);
        }
    }

    *fp += failures;
}

/* header stops exactly before payload: trailing bytes never consumed */
static void test_trailing_payload(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        uint8_t padded[24];
        memcpy(padded, k->wire, k->header_len);
        memset(padded + k->header_len, 0xAB, sizeof(padded) - k->header_len);

        wtq_h3_frame_t f = { 0, 0, 0 };
        WTQ_TEST_CHECK(wtq_h3_frame_decode_header(padded, sizeof(padded),
                                                  &f) == WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_SIZE(f.header_len, k->header_len);
        WTQ_TEST_CHECK_EQ_U64(f.type, k->type);
        WTQ_TEST_CHECK_EQ_U64(f.length, k->length);

        /* incremental: same input, consumed stops at the header */
        wtq_h3_frame_dec_t dec;
        wtq_h3_frame_dec_init(&dec);
        size_t consumed = 0;
        WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, padded, sizeof(padded),
                                             &f, &consumed) ==
                       WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, k->header_len);
    }

    *fp += failures;
}

/* incremental (every chunk size incl. mixed) == atomic */
static void test_incremental_equals_atomic(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t chunk = 1; chunk <= k->header_len; chunk++) {
            wtq_h3_frame_dec_t dec;
            wtq_h3_frame_dec_init(&dec);

            wtq_h3_frame_t f = { 0, 0, 0 };
            size_t off = 0;
            wtq_h3_frame_status_t st = WTQ_H3_FRAME_NEED_MORE;
            while (off < k->header_len && st == WTQ_H3_FRAME_NEED_MORE) {
                size_t n = k->header_len - off < chunk
                               ? k->header_len - off
                               : chunk;
                size_t consumed = 999;
                st = wtq_h3_frame_dec_feed(&dec, k->wire + off, n, &f,
                                           &consumed);
                if (st == WTQ_H3_FRAME_NEED_MORE)
                    WTQ_TEST_CHECK_EQ_SIZE(consumed, n); /* every return */
                off += consumed;
            }
            WTQ_TEST_CHECK(st == WTQ_H3_FRAME_OK);
            WTQ_TEST_CHECK_EQ_SIZE(off, k->header_len);
            WTQ_TEST_CHECK_EQ_U64(f.type, k->type);
            WTQ_TEST_CHECK_EQ_U64(f.length, k->length);
            WTQ_TEST_CHECK_EQ_SIZE(f.header_len, k->header_len);
        }

        /* mixed chunk sizes: 1, then 3, then the rest */
        wtq_h3_frame_dec_t dec;
        wtq_h3_frame_dec_init(&dec);
        wtq_h3_frame_t f = { 0, 0, 0 };
        size_t off = 0;
        wtq_h3_frame_status_t st = WTQ_H3_FRAME_NEED_MORE;
        const size_t plan[] = { 1, 3, 16 };
        for (size_t p = 0;
             p < sizeof(plan) / sizeof(plan[0]) &&
             st == WTQ_H3_FRAME_NEED_MORE && off < k->header_len;
             p++) {
            size_t n = k->header_len - off < plan[p] ? k->header_len - off
                                                     : plan[p];
            size_t consumed = 999;
            st = wtq_h3_frame_dec_feed(&dec, k->wire + off, n, &f,
                                       &consumed);
            off += consumed;
        }
        if (st == WTQ_H3_FRAME_OK) {
            WTQ_TEST_CHECK_EQ_U64(f.type, k->type);
            WTQ_TEST_CHECK_EQ_U64(f.length, k->length);
        } else {
            WTQ_TEST_CHECK(off == k->header_len || st ==
                           WTQ_H3_FRAME_NEED_MORE);
        }
    }

    *fp += failures;
}

/* auto-reset: concatenated frame headers through one decoder, 1 byte at
 * a time */
static void test_stream_reuse(int *fp)
{
    int failures = 0;
    uint8_t stream[128];
    size_t stream_len = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        memcpy(stream + stream_len, KNOWN[i].wire, KNOWN[i].header_len);
        stream_len += KNOWN[i].header_len;
    }

    wtq_h3_frame_dec_t dec;
    wtq_h3_frame_dec_init(&dec);
    size_t got = 0;
    for (size_t off = 0; off < stream_len; off++) {
        wtq_h3_frame_t f = { 0, 0, 0 };
        size_t consumed = 999;
        wtq_h3_frame_status_t st =
            wtq_h3_frame_dec_feed(&dec, stream + off, 1, &f, &consumed);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
        if (st == WTQ_H3_FRAME_OK) {
            WTQ_TEST_CHECK(got < N_KNOWN);
            WTQ_TEST_CHECK_EQ_U64(f.type, KNOWN[got].type);
            WTQ_TEST_CHECK_EQ_U64(f.length, KNOWN[got].length);
            WTQ_TEST_CHECK_EQ_SIZE(f.header_len, KNOWN[got].header_len);
            got++;
        } else {
            WTQ_TEST_CHECK(st == WTQ_H3_FRAME_NEED_MORE);
        }
    }
    WTQ_TEST_CHECK_EQ_SIZE(got, N_KNOWN);

    *fp += failures;
}

/* non-minimal varints accepted; header_len reflects wire length */
static void test_nonminimal(int *fp)
{
    int failures = 0;
    const struct {
        uint64_t type;
        uint64_t length;
        size_t wire_len;
        uint8_t wire[16];
    } nm[] = {
        /* DATA type in 2 bytes, length 0 minimal */
        { 0x00, 0, 3, { 0x40, 0x00, 0x00 } },
        /* SETTINGS minimal type, length 1 in 4 bytes */
        { 0x04, 1, 5, { 0x04, 0x80, 0x00, 0x00, 0x01 } },
        /* both non-minimal, 8-byte forms */
        { 0x01, 2, 16, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                         0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } },
    };

    for (size_t i = 0; i < sizeof(nm) / sizeof(nm[0]); i++) {
        wtq_h3_frame_t f = { 0, 0, 0 };
        WTQ_TEST_CHECK(wtq_h3_frame_decode_header(nm[i].wire, nm[i].wire_len,
                                                  &f) == WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_U64(f.type, nm[i].type);
        WTQ_TEST_CHECK_EQ_U64(f.length, nm[i].length);
        WTQ_TEST_CHECK_EQ_SIZE(f.header_len, nm[i].wire_len);

        /* canonical re-encode is shorter */
        WTQ_TEST_CHECK(wtq_h3_frame_header_len(f.type, f.length) <
                       nm[i].wire_len);

        /* incremental agrees, byte at a time */
        wtq_h3_frame_dec_t dec;
        wtq_h3_frame_dec_init(&dec);
        wtq_h3_frame_t g = { 0, 0, 0 };
        wtq_h3_frame_status_t st = WTQ_H3_FRAME_NEED_MORE;
        for (size_t off = 0; off < nm[i].wire_len &&
                             st == WTQ_H3_FRAME_NEED_MORE; off++) {
            size_t consumed = 999;
            st = wtq_h3_frame_dec_feed(&dec, nm[i].wire + off, 1, &g,
                                       &consumed);
            WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
        }
        WTQ_TEST_CHECK(st == WTQ_H3_FRAME_OK);
        WTQ_TEST_CHECK_EQ_U64(g.type, nm[i].type);
        WTQ_TEST_CHECK_EQ_U64(g.length, nm[i].length);
        WTQ_TEST_CHECK_EQ_SIZE(g.header_len, nm[i].wire_len);
    }

    *fp += failures;
}

/* NEED_MORE sets consumed on every return, including zero-length input */
static void test_need_more_consumed(int *fp)
{
    int failures = 0;
    wtq_h3_frame_dec_t dec;
    wtq_h3_frame_dec_init(&dec);

    wtq_h3_frame_t f = { 0, 0, 0 };
    size_t consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, NULL, 0, &f, &consumed) ==
                   WTQ_H3_FRAME_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    /* partial type varint */
    const uint8_t part_type[] = { 0xc0, 0x11 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, part_type, sizeof(part_type),
                                         &f, &consumed) ==
                   WTQ_H3_FRAME_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 2);

    /* reset, then complete type + partial length */
    wtq_h3_frame_dec_init(&dec);
    const uint8_t type_partlen[] = { 0x04, 0x80, 0x00 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, type_partlen,
                                         sizeof(type_partlen), &f,
                                         &consumed) ==
                   WTQ_H3_FRAME_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 3);

    /* finish it */
    const uint8_t rest[] = { 0x00, 0x07 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, rest, sizeof(rest), &f,
                                         &consumed) == WTQ_H3_FRAME_OK);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 2);
    WTQ_TEST_CHECK_EQ_U64(f.type, 0x04);
    WTQ_TEST_CHECK_EQ_U64(f.length, 7);
    WTQ_TEST_CHECK_EQ_SIZE(f.header_len, 5);

    /* zero-length probe while ALREADY IN LENGTH STATE: legal, NEED_MORE,
     * consumed 0, and no pointer arithmetic on NULL (UBSan-visible). */
    wtq_h3_frame_dec_init(&dec);
    const uint8_t settings_type = 0x04;
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, &settings_type, 1, &f,
                                         &consumed) ==
                   WTQ_H3_FRAME_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, NULL, 0, &f, &consumed) ==
                   WTQ_H3_FRAME_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    const uint8_t len0 = 0x00;
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&dec, &len0, 1, &f, &consumed) ==
                   WTQ_H3_FRAME_OK);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
    WTQ_TEST_CHECK_EQ_U64(f.type, WTQ_H3_FRAME_SETTINGS);
    WTQ_TEST_CHECK_EQ_U64(f.length, 0);

    /* zero-initialized state is a valid fresh decoder */
    wtq_h3_frame_dec_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    const uint8_t data0[] = { 0x00, 0x00 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_h3_frame_dec_feed(&zeroed, data0, sizeof(data0), &f,
                                         &consumed) == WTQ_H3_FRAME_OK);
    WTQ_TEST_CHECK_EQ_U64(f.type, 0);
    WTQ_TEST_CHECK_EQ_U64(f.length, 0);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_known_roundtrip(&failures);
    test_boundary_sweep(&failures);
    test_encode_bounds(&failures);
    test_incomplete(&failures);
    test_trailing_payload(&failures);
    test_incremental_equals_atomic(&failures);
    test_stream_reuse(&failures);
    test_nonminimal(&failures);
    test_need_more_consumed(&failures);

    WTQ_TEST_PASS("test_h3_frame");
    return failures;
}
