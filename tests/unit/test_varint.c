#include <string.h>

#include "proto/varint.h"

#include "test_support.h"

/* Every boundary value with its canonical wire encoding. */
typedef struct known {
    uint64_t value;
    size_t len;
    uint8_t wire[8];
} known_t;

static const known_t KNOWN[] = {
    { 0,                    1, { 0x00 } },
    { 63,                   1, { 0x3f } },
    { 64,                   2, { 0x40, 0x40 } },
    { 16383,                2, { 0x7f, 0xff } },
    { 16384,                4, { 0x80, 0x00, 0x40, 0x00 } },
    { 1073741823,           4, { 0xbf, 0xff, 0xff, 0xff } },
    { 1073741824,           8, { 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00,
                                 0x00, 0x00 } },
    { 4611686018427387903u, 8, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff } },
    /* RFC 9000 appendix A.1 example. */
    { 151288809941952652u,  8, { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14,
                                 0xe8, 0x8c } },
};
#define N_KNOWN (sizeof(KNOWN) / sizeof(KNOWN[0]))

/* varint_roundtrip_all_lengths + known encodings at every boundary */
static void test_known_encodings(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        uint8_t buf[8] = { 0 };
        size_t out_len = 0;

        WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len(k->value), k->len);
        WTQ_TEST_CHECK(wtq_varint_encode(k->value, buf, sizeof(buf),
                                         &out_len) == WTQ_VARINT_OK);
        WTQ_TEST_CHECK_EQ_SIZE(out_len, k->len);
        WTQ_TEST_CHECK(memcmp(buf, k->wire, k->len) == 0);

        uint64_t v = 0;
        size_t consumed = 0;
        WTQ_TEST_CHECK(wtq_varint_decode(k->wire, k->len, &v, &consumed) ==
                       WTQ_VARINT_OK);
        WTQ_TEST_CHECK_EQ_U64(v, k->value);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, k->len);

        /* Trailing bytes are not consumed. */
        uint8_t padded[10];
        memcpy(padded, k->wire, k->len);
        padded[k->len] = 0xAA;
        WTQ_TEST_CHECK(wtq_varint_decode(padded, k->len + 1, &v,
                                         &consumed) == WTQ_VARINT_OK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, k->len);
        WTQ_TEST_CHECK_EQ_U64(v, k->value);
    }

    *fp += failures;
}

/* varint_len_from_first_byte: length tag mapping across the tag space */
static void test_first_byte_lengths(int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0x00), 1);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0x3f), 1);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0x40), 2);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0x7f), 2);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0x80), 4);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0xbf), 4);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0xc0), 8);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len_from_first(0xff), 8);

    *fp += failures;
}

/* varint_encode_bounds: too-small buffer for every length; no writes */
static void test_encode_bounds(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t cap = 0; cap < k->len; cap++) {
            uint8_t buf[8];
            memset(buf, 0xEE, sizeof(buf));
            size_t out_len = 999;
            WTQ_TEST_CHECK(wtq_varint_encode(k->value, buf, cap,
                                             &out_len) == WTQ_VARINT_BUFFER);
            for (size_t j = 0; j < sizeof(buf); j++)
                WTQ_TEST_CHECK(buf[j] == 0xEE); /* untouched on error */
        }
    }

    /* max+1 rejected as RANGE regardless of capacity. */
    uint8_t buf[16];
    size_t out_len = 0;
    WTQ_TEST_CHECK(wtq_varint_encode(WTQ_VARINT_MAX + 1, buf, sizeof(buf),
                                     &out_len) == WTQ_VARINT_RANGE);
    WTQ_TEST_CHECK(wtq_varint_encode(UINT64_MAX, buf, sizeof(buf),
                                     &out_len) == WTQ_VARINT_RANGE);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_varint_len(WTQ_VARINT_MAX + 1), 0);

    *fp += failures;
}

/* varint_incomplete_needs_more: every proper prefix of every encoding */
static void test_incomplete(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t plen = 0; plen < k->len; plen++) {
            uint64_t v = 0;
            size_t consumed = 0;
            WTQ_TEST_CHECK(wtq_varint_decode(k->wire, plen, &v, &consumed) ==
                           WTQ_VARINT_NEED_MORE);
        }
    }

    *fp += failures;
}

/* varint_nonminimal_decode: legal wire format (RFC 9000 s16; both MsQuic
 * and picoquic accept) — decodes with correct value and reported length,
 * and wtq_varint_is_minimal() exposes canonicality for strict contexts. */
static void test_nonminimal(int *fp)
{
    int failures = 0;
    const struct {
        uint64_t value;
        size_t len;
        uint8_t wire[8];
    } nm[] = {
        { 63, 2, { 0x40, 0x3f } },
        { 63, 4, { 0x80, 0x00, 0x00, 0x3f } },
        { 63, 8, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f } },
        { 16383, 4, { 0x80, 0x00, 0x3f, 0xff } },
        { 0, 2, { 0x40, 0x00 } },
    };

    for (size_t i = 0; i < sizeof(nm) / sizeof(nm[0]); i++) {
        uint64_t v = 0;
        size_t consumed = 0;
        WTQ_TEST_CHECK(wtq_varint_decode(nm[i].wire, nm[i].len, &v,
                                         &consumed) == WTQ_VARINT_OK);
        WTQ_TEST_CHECK_EQ_U64(v, nm[i].value);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, nm[i].len);
        WTQ_TEST_CHECK(!wtq_varint_is_minimal(v, consumed));
        WTQ_TEST_CHECK(wtq_varint_is_minimal(v, wtq_varint_len(v)));
    }

    *fp += failures;
}

/* incremental byte-at-a-time == atomic, for every chunk size */
static void test_incremental_equals_atomic(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        for (size_t chunk = 1; chunk <= k->len; chunk++) {
            wtq_varint_dec_t dec;
            wtq_varint_dec_init(&dec);

            uint64_t v = 0;
            size_t total = 0;
            size_t off = 0;
            wtq_varint_status_t st = WTQ_VARINT_NEED_MORE;
            while (off < k->len) {
                size_t n = k->len - off < chunk ? k->len - off : chunk;
                size_t consumed = 0;
                st = wtq_varint_dec_feed(&dec, k->wire + off, n, &v,
                                         &consumed);
                if (st == WTQ_VARINT_OK) {
                    total += consumed;
                    off += consumed;
                    break;
                }
                WTQ_TEST_CHECK(st == WTQ_VARINT_NEED_MORE);
                total += n;
                off += n;
            }
            WTQ_TEST_CHECK(st == WTQ_VARINT_OK);
            WTQ_TEST_CHECK_EQ_U64(v, k->value);
            WTQ_TEST_CHECK_EQ_SIZE(total, k->len);
        }
    }

    *fp += failures;
}

/* auto-reset: a stream of concatenated varints through one decoder,
 * fed one byte at a time */
static void test_stream_reuse(int *fp)
{
    int failures = 0;
    uint8_t stream[64];
    size_t stream_len = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        memcpy(stream + stream_len, KNOWN[i].wire, KNOWN[i].len);
        stream_len += KNOWN[i].len;
    }

    wtq_varint_dec_t dec;
    wtq_varint_dec_init(&dec);
    size_t got = 0;
    for (size_t off = 0; off < stream_len; off++) {
        uint64_t v = 0;
        size_t consumed = 0;
        wtq_varint_status_t st =
            wtq_varint_dec_feed(&dec, stream + off, 1, &v, &consumed);
        if (st == WTQ_VARINT_OK) {
            WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
            WTQ_TEST_CHECK(got < N_KNOWN);
            WTQ_TEST_CHECK_EQ_U64(v, KNOWN[got].value);
            got++;
        } else {
            WTQ_TEST_CHECK(st == WTQ_VARINT_NEED_MORE);
        }
    }
    WTQ_TEST_CHECK_EQ_SIZE(got, N_KNOWN);

    *fp += failures;
}

/* explicit reset mid-parse discards partial state */
static void test_reset_mid_parse(int *fp)
{
    int failures = 0;
    wtq_varint_dec_t dec;
    wtq_varint_dec_init(&dec);

    /* Start an 8-byte varint, abandon it after 3 bytes. */
    const uint8_t partial[] = { 0xc0, 0x11, 0x22 };
    uint64_t v = 0;
    size_t consumed = 0;
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, partial, sizeof(partial), &v,
                                       &consumed) == WTQ_VARINT_NEED_MORE);
    wtq_varint_dec_init(&dec);

    /* Fresh 1-byte varint decodes cleanly with no leftover bits. */
    const uint8_t one = 0x2a;
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, &one, 1, &v, &consumed) ==
                   WTQ_VARINT_OK);
    WTQ_TEST_CHECK_EQ_U64(v, 42);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);

    /* Zero-initialized state is also a valid fresh decoder. */
    wtq_varint_dec_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&zeroed, &one, 1, &v, &consumed) ==
                   WTQ_VARINT_OK);
    WTQ_TEST_CHECK_EQ_U64(v, 42);

    /* Feeding zero bytes to a fresh decoder needs more and reports zero
     * consumed. */
    wtq_varint_dec_init(&dec);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, NULL, 0, &v, &consumed) ==
                   WTQ_VARINT_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    *fp += failures;
}

/* NEED_MORE reports consumed on every path: generic callers advance by
 * *consumed without special-casing the status. */
static void test_need_more_consumed(int *fp)
{
    int failures = 0;
    wtq_varint_dec_t dec;
    wtq_varint_dec_init(&dec);

    uint64_t v = 0;
    size_t consumed = 999;
    const uint8_t partial[] = { 0xc0, 0x11, 0x22 };
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, partial, sizeof(partial), &v,
                                       &consumed) == WTQ_VARINT_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 3);

    /* Continuing the same varint: each NEED_MORE call reports its own
     * consumption, and the final OK call reports only its own bytes. */
    consumed = 999;
    const uint8_t more[] = { 0x33, 0x44 };
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, more, sizeof(more), &v,
                                       &consumed) == WTQ_VARINT_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 2);

    consumed = 999;
    const uint8_t rest[] = { 0x55, 0x66, 0x77 };
    WTQ_TEST_CHECK(wtq_varint_dec_feed(&dec, rest, sizeof(rest), &v,
                                       &consumed) == WTQ_VARINT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 3);
    WTQ_TEST_CHECK_EQ_U64(v, 0x0011223344556677ull & WTQ_VARINT_MAX);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_known_encodings(&failures);
    test_first_byte_lengths(&failures);
    test_encode_bounds(&failures);
    test_incomplete(&failures);
    test_nonminimal(&failures);
    test_incremental_equals_atomic(&failures);
    test_stream_reuse(&failures);
    test_reset_mid_parse(&failures);
    test_need_more_consumed(&failures);

    WTQ_TEST_PASS("test_varint");
    return failures;
}
