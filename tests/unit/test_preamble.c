#include <string.h>

#include "proto/preamble.h"

#include "test_support.h"

/* Canonical wire vectors: 0x41/0x54 are > 63, so their minimal varint
 * form is TWO bytes. */
typedef struct known {
    wtq_preamble_kind_t kind;
    uint64_t sid;
    size_t len;
    uint8_t wire[12];
} known_t;

static const known_t KNOWN[] = {
    { WTQ_PREAMBLE_KIND_BIDI, 0, 3, { 0x40, 0x41, 0x00 } },
    { WTQ_PREAMBLE_KIND_UNI, 0, 3, { 0x40, 0x54, 0x00 } },
    { WTQ_PREAMBLE_KIND_BIDI, 63, 3, { 0x40, 0x41, 0x3f } },
    { WTQ_PREAMBLE_KIND_BIDI, 64, 4, { 0x40, 0x41, 0x40, 0x40 } },
    { WTQ_PREAMBLE_KIND_UNI, 16383, 4, { 0x40, 0x54, 0x7f, 0xff } },
    { WTQ_PREAMBLE_KIND_UNI, 16384, 6,
      { 0x40, 0x54, 0x80, 0x00, 0x40, 0x00 } },
    { WTQ_PREAMBLE_KIND_BIDI, 4611686018427387903u, 10,
      { 0x40, 0x41, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};
#define N_KNOWN (sizeof(KNOWN) / sizeof(KNOWN[0]))

/* byte-exact encode + atomic decode roundtrip */
static void test_encode_decode(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        uint8_t buf[12];
        size_t out_len = 0;

        WTQ_TEST_CHECK(wtq_preamble_encode(k->kind, k->sid, buf,
                                           sizeof(buf), &out_len) ==
                       WTQ_PREAMBLE_OK);
        WTQ_TEST_CHECK_EQ_SIZE(out_len, k->len);
        WTQ_TEST_CHECK(memcmp(buf, k->wire, k->len) == 0);

        wtq_preamble_t p;
        memset(&p, 0, sizeof(p));
        WTQ_TEST_CHECK(wtq_preamble_decode(k->kind, k->wire, k->len, &p) ==
                       WTQ_PREAMBLE_OK);
        WTQ_TEST_CHECK(p.kind == k->kind);
        WTQ_TEST_CHECK_EQ_U64(p.session_id, k->sid);
        WTQ_TEST_CHECK_EQ_SIZE(p.header_len, k->len);
    }

    *fp += failures;
}

/* encode bounds: BUFFER untouched at every short cap; RANGE for
 * oversize sid and bad kind */
static void test_encode_bounds(int *fp)
{
    int failures = 0;
    size_t out_len = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        for (size_t cap = 0; cap < KNOWN[i].len; cap++) {
            uint8_t buf[12];
            memset(buf, 0xEE, sizeof(buf));
            WTQ_TEST_CHECK(wtq_preamble_encode(KNOWN[i].kind, KNOWN[i].sid,
                                               buf, cap, &out_len) ==
                           WTQ_PREAMBLE_BUFFER);
            for (size_t b = 0; b < sizeof(buf); b++)
                WTQ_TEST_CHECK(buf[b] == 0xEE);
        }
    }

    uint8_t buf[16];
    memset(buf, 0xEE, sizeof(buf));
    WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_BIDI,
                                       WTQ_VARINT_MAX + 1, buf, sizeof(buf),
                                       &out_len) == WTQ_PREAMBLE_RANGE);
    WTQ_TEST_CHECK(wtq_preamble_encode((wtq_preamble_kind_t)0, 1, buf,
                                       sizeof(buf), &out_len) ==
                   WTQ_PREAMBLE_RANGE);
    for (size_t b = 0; b < sizeof(buf); b++)
        WTQ_TEST_CHECK(buf[b] == 0xEE);

    *fp += failures;
}

/* payload after the preamble is never consumed (atomic + incremental) */
static void test_trailing_payload(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];
        uint8_t padded[20];
        memcpy(padded, k->wire, k->len);
        memset(padded + k->len, 0xAB, sizeof(padded) - k->len);

        wtq_preamble_t p;
        WTQ_TEST_CHECK(wtq_preamble_decode(k->kind, padded, sizeof(padded),
                                           &p) == WTQ_PREAMBLE_OK);
        WTQ_TEST_CHECK_EQ_SIZE(p.header_len, k->len);

        wtq_preamble_dec_t dec;
        wtq_preamble_dec_init(&dec);
        size_t consumed = (size_t)-1;
        WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, k->kind, padded,
                                             sizeof(padded), &p,
                                             &consumed) ==
                       WTQ_PREAMBLE_OK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, k->len);
        WTQ_TEST_CHECK_EQ_U64(p.session_id, k->sid);
    }

    *fp += failures;
}

/* every chunk size equals atomic; truncation prefixes NEED_MORE with
 * consumed == offered */
static void test_chunks_and_truncation(int *fp)
{
    int failures = 0;

    for (size_t i = 0; i < N_KNOWN; i++) {
        const known_t *k = &KNOWN[i];

        for (size_t chunk = 1; chunk <= k->len; chunk++) {
            wtq_preamble_dec_t dec;
            wtq_preamble_dec_init(&dec);
            wtq_preamble_t p;
            size_t off = 0;
            wtq_preamble_status_t st = WTQ_PREAMBLE_NEED_MORE;
            while (off < k->len && st == WTQ_PREAMBLE_NEED_MORE) {
                size_t n = k->len - off < chunk ? k->len - off : chunk;
                size_t consumed = (size_t)-1;
                st = wtq_preamble_dec_feed(&dec, k->kind, k->wire + off, n,
                                           &p, &consumed);
                if (st == WTQ_PREAMBLE_NEED_MORE)
                    WTQ_TEST_CHECK_EQ_SIZE(consumed, n);
                off += consumed;
            }
            WTQ_TEST_CHECK(st == WTQ_PREAMBLE_OK);
            WTQ_TEST_CHECK_EQ_SIZE(off, k->len);
            WTQ_TEST_CHECK_EQ_U64(p.session_id, k->sid);
            WTQ_TEST_CHECK_EQ_SIZE(p.header_len, k->len);
        }

        for (size_t plen = 0; plen < k->len; plen++) {
            wtq_preamble_dec_t dec;
            wtq_preamble_dec_init(&dec);
            wtq_preamble_t p;
            size_t consumed = (size_t)-1;
            WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, k->kind, k->wire,
                                                 plen, &p, &consumed) ==
                           WTQ_PREAMBLE_NEED_MORE);
            WTQ_TEST_CHECK_EQ_SIZE(consumed, plen);
        }
    }

    *fp += failures;
}

/* concatenated preambles through one decoder, byte at a time */
static void test_concatenated(int *fp)
{
    int failures = 0;
    uint8_t stream[64];
    size_t stream_len = 0;

    /* two bidi preambles back-to-back (same expected direction) */
    memcpy(stream, KNOWN[0].wire, KNOWN[0].len);
    stream_len += KNOWN[0].len;
    memcpy(stream + stream_len, KNOWN[3].wire, KNOWN[3].len);
    stream_len += KNOWN[3].len;

    wtq_preamble_dec_t dec;
    wtq_preamble_dec_init(&dec);
    wtq_preamble_t p;
    size_t got = 0;
    for (size_t off = 0; off < stream_len; off++) {
        size_t consumed = (size_t)-1;
        wtq_preamble_status_t st = wtq_preamble_dec_feed(
            &dec, WTQ_PREAMBLE_KIND_BIDI, stream + off, 1, &p, &consumed);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
        if (st == WTQ_PREAMBLE_OK) {
            WTQ_TEST_CHECK_EQ_U64(p.session_id, got == 0 ? 0 : 64);
            got++;
        } else {
            WTQ_TEST_CHECK(st == WTQ_PREAMBLE_NEED_MORE);
        }
    }
    WTQ_TEST_CHECK_EQ_SIZE(got, 2);

    *fp += failures;
}

/* non-minimal varints accepted; header_len reflects wire bytes */
static void test_nonminimal(int *fp)
{
    int failures = 0;

    /* type 0x41 as 4-byte varint + sid 5 as 2-byte varint */
    const uint8_t nm[] = { 0x80, 0x00, 0x00, 0x41, 0x40, 0x05 };
    wtq_preamble_t p;
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_BIDI, nm,
                                       sizeof(nm), &p) == WTQ_PREAMBLE_OK);
    WTQ_TEST_CHECK_EQ_U64(p.session_id, 5);
    WTQ_TEST_CHECK_EQ_SIZE(p.header_len, 6);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x41);

    /* type minimal + sid 0 as 8-byte varint */
    const uint8_t nm2[] = { 0x40, 0x54, 0xc0, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00 };
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_UNI, nm2,
                                       sizeof(nm2), &p) ==
                   WTQ_PREAMBLE_OK);
    WTQ_TEST_CHECK_EQ_U64(p.session_id, 0);
    WTQ_TEST_CHECK_EQ_SIZE(p.header_len, 10);

    *fp += failures;
}

/* wrong-direction and unknown types are UNEXPECTED with wire_type
 * reported and no session consumed; latched until _init */
static void test_unexpected(int *fp)
{
    int failures = 0;
    wtq_preamble_t p;
    size_t consumed = (size_t)-1;

    /* 0x54 on a bidi stream */
    const uint8_t uni_wire[] = { 0x40, 0x54, 0x07 };
    wtq_preamble_dec_t dec;
    wtq_preamble_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         uni_wire, sizeof(uni_wire), &p,
                                         &consumed) ==
                   WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x54);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 2); /* only the type varint */

    /* latched until _init */
    consumed = (size_t)-1;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         uni_wire, 1, &p, &consumed) ==
                   WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    wtq_preamble_dec_init(&dec);
    size_t total = 0;
    (void)total;
    consumed = (size_t)-1;
    const uint8_t bidi_wire[] = { 0x40, 0x41, 0x07 };
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         bidi_wire, sizeof(bidi_wire), &p,
                                         &consumed) == WTQ_PREAMBLE_OK);

    /* 0x41 on a uni stream */
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_UNI, bidi_wire,
                                       sizeof(bidi_wire), &p) ==
                   WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x41);

    /* random other types rejected for both directions; wire_type is the
     * routing value (H3 control stream type 0x00 on a uni stream is
     * exactly how the engine classifier reroutes) */
    const uint8_t ctrl[] = { 0x00 };
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_UNI, ctrl, 1,
                                       &p) == WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x00);
    const uint8_t grease[] = { 0x40, 0x9f, 0xaa };
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_BIDI, grease,
                                       sizeof(grease), &p) ==
                   WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x9f);

    /* non-minimal encoding of the WRONG type is still UNEXPECTED */
    const uint8_t nm_wrong[] = { 0x80, 0x00, 0x00, 0x54, 0x00 };
    WTQ_TEST_CHECK(wtq_preamble_decode(WTQ_PREAMBLE_KIND_BIDI, nm_wrong,
                                       sizeof(nm_wrong), &p) ==
                   WTQ_PREAMBLE_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_U64(p.wire_type, 0x54);

    *fp += failures;
}

/* zero-length probes; zero-initialized state; _init mid-parse reset */
static void test_probes(int *fp)
{
    int failures = 0;
    wtq_preamble_t p;
    size_t consumed = 999;

    wtq_preamble_dec_t dec;
    wtq_preamble_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         NULL, 0, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    /* probe mid-type and mid-session */
    const uint8_t bidi64[] = { 0x40, 0x41, 0x40, 0x40 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         bidi64, 1, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         NULL, 0, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         bidi64 + 1, 2, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 2);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         NULL, 0, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_BIDI,
                                         bidi64 + 3, 1, &p, &consumed) ==
                   WTQ_PREAMBLE_OK);
    WTQ_TEST_CHECK_EQ_U64(p.session_id, 64);
    WTQ_TEST_CHECK_EQ_SIZE(p.header_len, 4);

    /* zero-initialized state is a valid fresh decoder */
    wtq_preamble_dec_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    consumed = 999;
    const uint8_t uni0[] = { 0x40, 0x54, 0x00 };
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&zeroed, WTQ_PREAMBLE_KIND_UNI,
                                         uni0, sizeof(uni0), &p,
                                         &consumed) == WTQ_PREAMBLE_OK);
    WTQ_TEST_CHECK(p.kind == WTQ_PREAMBLE_KIND_UNI);

    /* _init resets mid-parse */
    wtq_preamble_dec_init(&dec);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_UNI,
                                         uni0, 2, &p, &consumed) ==
                   WTQ_PREAMBLE_NEED_MORE);
    wtq_preamble_dec_init(&dec);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_preamble_dec_feed(&dec, WTQ_PREAMBLE_KIND_UNI, uni0,
                                         sizeof(uni0), &p, &consumed) ==
                   WTQ_PREAMBLE_OK);
    WTQ_TEST_CHECK_EQ_U64(p.session_id, 0);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_encode_decode(&failures);
    test_encode_bounds(&failures);
    test_trailing_payload(&failures);
    test_chunks_and_truncation(&failures);
    test_concatenated(&failures);
    test_nonminimal(&failures);
    test_unexpected(&failures);
    test_probes(&failures);

    WTQ_TEST_PASS("test_preamble");
    return failures;
}
