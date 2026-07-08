#include <string.h>

#include "proto/capsule.h"

#include "test_support.h"

/* Canonical wire vectors. */
static const uint8_t DRAIN_WIRE[] = { 0x80, 0x00, 0x78, 0xae, 0x00 };
static const uint8_t CLOSE_EMPTY_WIRE[] = {
    0x68, 0x43, 0x04, 0xff, 0xff, 0xff, 0xff,
};
static const uint8_t CLOSE_BYE_WIRE[] = {
    0x68, 0x43, 0x07, 0x00, 0x00, 0x12, 0x34, 'b', 'y', 'e',
};

/* Feed a whole buffer through the incremental decoder in fixed chunks;
 * returns the final status, sets *out and total consumed. */
static wtq_capsule_status_t feed_chunked(wtq_capsule_dec_t *dec,
                                         const uint8_t *wire, size_t len,
                                         size_t chunk, wtq_capsule_t *out,
                                         size_t *total)
{
    size_t off = 0;
    wtq_capsule_status_t st = WTQ_CAPSULE_NEED_MORE;

    *total = 0;
    while (off < len && st == WTQ_CAPSULE_NEED_MORE) {
        size_t n = len - off < chunk ? len - off : chunk;
        size_t consumed = (size_t)-1;
        st = wtq_capsule_dec_feed(dec, wire + off, n, out, &consumed);
        if (consumed == (size_t)-1)
            return -99; /* consumed not set — contract violation */
        off += consumed;
        *total += consumed;
    }
    return st;
}

/* encode: DRAIN and CLOSE byte-exact; RANGE; BUFFER untouched */
static void test_encode(int *fp)
{
    int failures = 0;
    uint8_t buf[1200];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_capsule_encode_drain(buf, sizeof(buf), &out_len) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(DRAIN_WIRE));
    WTQ_TEST_CHECK(memcmp(buf, DRAIN_WIRE, out_len) == 0);

    WTQ_TEST_CHECK(wtq_capsule_encode_close(0xffffffffu, NULL, 0, buf,
                                            sizeof(buf), &out_len) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(CLOSE_EMPTY_WIRE));
    WTQ_TEST_CHECK(memcmp(buf, CLOSE_EMPTY_WIRE, out_len) == 0);

    WTQ_TEST_CHECK(wtq_capsule_encode_close(0x1234, (const uint8_t *)"bye",
                                            3, buf, sizeof(buf),
                                            &out_len) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(CLOSE_BYE_WIRE));
    WTQ_TEST_CHECK(memcmp(buf, CLOSE_BYE_WIRE, out_len) == 0);

    /* max reason boundary: 1024 encodes, 1025 is RANGE */
    uint8_t reason[1025];
    memset(reason, 'r', sizeof(reason));
    WTQ_TEST_CHECK(wtq_capsule_encode_close(1, reason, 1024, buf,
                                            sizeof(buf), &out_len) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(wtq_capsule_encode_close(1, reason, 1025, buf,
                                            sizeof(buf), &out_len) ==
                   WTQ_CAPSULE_RANGE);

    /* BUFFER leaves output untouched at every short cap */
    for (size_t cap = 0; cap < sizeof(CLOSE_BYE_WIRE); cap++) {
        uint8_t small[16];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_capsule_encode_close(0x1234,
                                                (const uint8_t *)"bye", 3,
                                                small, cap, &out_len) ==
                       WTQ_CAPSULE_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == 0xEE);
    }
    for (size_t cap = 0; cap < sizeof(DRAIN_WIRE); cap++) {
        uint8_t small[8];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_capsule_encode_drain(small, cap, &out_len) ==
                       WTQ_CAPSULE_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == 0xEE);
    }

    /* generic header helpers share the h3_frame wire shape */
    WTQ_TEST_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_CLOSE_SESSION, 7,
                                             buf, sizeof(buf), &out_len) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 3);
    WTQ_TEST_CHECK(memcmp(buf, CLOSE_BYE_WIRE, 3) == 0);
    wtq_h3_frame_t hdr = { 0, 0, 0 };
    WTQ_TEST_CHECK(wtq_capsule_decode_header(CLOSE_BYE_WIRE,
                                             sizeof(CLOSE_BYE_WIRE),
                                             &hdr) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_U64(hdr.type, WTQ_CAPSULE_CLOSE_SESSION);
    WTQ_TEST_CHECK_EQ_U64(hdr.length, 7);

    *fp += failures;
}

/* decode happy paths: DRAIN, CLOSE empty, CLOSE with reason */
static void test_decode_known(int *fp)
{
    int failures = 0;
    wtq_capsule_dec_t dec;
    wtq_capsule_t c;
    size_t total = 0;

    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, DRAIN_WIRE, sizeof(DRAIN_WIRE), 64,
                                &c, &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_DRAIN);
    WTQ_TEST_CHECK_EQ_U64(c.type, WTQ_CAPSULE_DRAIN_SESSION);
    WTQ_TEST_CHECK_EQ_U64(c.length, 0);
    WTQ_TEST_CHECK_EQ_SIZE(c.header_len, 5);
    WTQ_TEST_CHECK_EQ_SIZE(total, sizeof(DRAIN_WIRE));

    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, CLOSE_EMPTY_WIRE,
                                sizeof(CLOSE_EMPTY_WIRE), 64, &c,
                                &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_CLOSE);
    WTQ_TEST_CHECK_EQ_HEX(c.close_code, 0xffffffffu);
    WTQ_TEST_CHECK_EQ_SIZE(c.reason_len, 0);

    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, CLOSE_BYE_WIRE,
                                sizeof(CLOSE_BYE_WIRE), 64, &c, &total) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_CLOSE);
    WTQ_TEST_CHECK_EQ_HEX(c.close_code, 0x1234);
    WTQ_TEST_CHECK_EQ_SIZE(c.reason_len, 3);
    WTQ_TEST_CHECK(memcmp(c.reason, "bye", 3) == 0);
    WTQ_TEST_CHECK_EQ_SIZE(c.header_len, 3);

    *fp += failures;
}

/* malformed shapes: DRAIN len 1, CLOSE len < 4, CLOSE reason > 1024;
 * error reported at header completion and latched until _init */
static void test_malformed(int *fp)
{
    int failures = 0;
    wtq_capsule_dec_t dec;
    wtq_capsule_t c;
    size_t consumed = (size_t)-1;

    const uint8_t drain_len1[] = { 0x80, 0x00, 0x78, 0xae, 0x01, 0xAA };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, drain_len1,
                                        sizeof(drain_len1), &c,
                                        &consumed) ==
                   WTQ_CAPSULE_MALFORMED);
    WTQ_TEST_CHECK(consumed != (size_t)-1);
    /* latched */
    consumed = (size_t)-1;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, drain_len1, 1, &c,
                                        &consumed) ==
                   WTQ_CAPSULE_MALFORMED);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    /* _init clears the poison */
    wtq_capsule_dec_init(&dec);
    size_t total = 0;
    WTQ_TEST_CHECK(feed_chunked(&dec, DRAIN_WIRE, sizeof(DRAIN_WIRE), 1,
                                &c, &total) == WTQ_CAPSULE_OK);

    /* CLOSE with payload length 3 (< 4) */
    const uint8_t close_short[] = { 0x68, 0x43, 0x03, 0x00, 0x00, 0x12 };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, close_short,
                                        sizeof(close_short), &c,
                                        &consumed) ==
                   WTQ_CAPSULE_MALFORMED);

    /* CLOSE with reason 1025 bytes: header announces 4 + 1025 */
    const uint8_t close_big_hdr[] = { 0x68, 0x43, 0x44, 0x05 };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, close_big_hdr,
                                        sizeof(close_big_hdr), &c,
                                        &consumed) ==
                   WTQ_CAPSULE_MALFORMED);

    /* CLOSE with reason exactly 1024 is fine (header 4 + 1024 = 0x404) */
    uint8_t big[3 + 4 + 1024 + 8];
    big[0] = 0x68;
    big[1] = 0x43;
    big[2] = 0x44; /* varint 0x404 = {0x44, 0x04} */
    big[3] = 0x04;
    memset(big + 4, 0, 4);
    memset(big + 8, 'r', 1024);
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, big, 4 + 4 + 1024, 97, &c,
                                &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK_EQ_SIZE(c.reason_len, 1024);
    WTQ_TEST_CHECK(c.reason[0] == 'r' && c.reason[1023] == 'r');

    *fp += failures;
}

/* unknown capsules skipped without buffering, empty and with payload */
static void test_unknown(int *fp)
{
    int failures = 0;
    wtq_capsule_dec_t dec;
    wtq_capsule_t c;
    size_t total = 0;

    const uint8_t unk_empty[] = { 0x1f, 0x00 };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, unk_empty, sizeof(unk_empty), 1, &c,
                                &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_UNKNOWN);
    WTQ_TEST_CHECK_EQ_U64(c.type, 0x1f);
    WTQ_TEST_CHECK_EQ_U64(c.length, 0);

    const uint8_t unk_payload[] = { 0x17, 0x05, 1, 2, 3, 4, 5 };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, unk_payload, sizeof(unk_payload), 2,
                                &c, &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_UNKNOWN);
    WTQ_TEST_CHECK_EQ_U64(c.type, 0x17);
    WTQ_TEST_CHECK_EQ_U64(c.length, 5);
    WTQ_TEST_CHECK_EQ_SIZE(total, sizeof(unk_payload));

    /* a WT flow-control-shaped capsule is just another unknown */
    const uint8_t flowctl[] = { 0x64, 0x30, 0x02, 0x40, 0x64 };
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, flowctl, sizeof(flowctl), 1, &c,
                                &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_UNKNOWN);

    *fp += failures;
}

/* two capsules concatenated; decoder auto-resets between them */
static void test_concatenated(int *fp)
{
    int failures = 0;
    uint8_t stream[64];
    size_t stream_len = 0;

    memcpy(stream, DRAIN_WIRE, sizeof(DRAIN_WIRE));
    stream_len += sizeof(DRAIN_WIRE);
    memcpy(stream + stream_len, CLOSE_BYE_WIRE, sizeof(CLOSE_BYE_WIRE));
    stream_len += sizeof(CLOSE_BYE_WIRE);

    /* one byte at a time through a single decoder */
    wtq_capsule_dec_t dec;
    wtq_capsule_dec_init(&dec);
    wtq_capsule_t c;
    size_t got = 0;
    for (size_t off = 0; off < stream_len; off++) {
        size_t consumed = (size_t)-1;
        wtq_capsule_status_t st =
            wtq_capsule_dec_feed(&dec, stream + off, 1, &c, &consumed);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
        if (st == WTQ_CAPSULE_OK) {
            if (got == 0)
                WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_DRAIN);
            if (got == 1) {
                WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_CLOSE);
                WTQ_TEST_CHECK_EQ_HEX(c.close_code, 0x1234);
                WTQ_TEST_CHECK_EQ_SIZE(c.reason_len, 3);
                WTQ_TEST_CHECK(memcmp(c.reason, "bye", 3) == 0);
            }
            got++;
        } else {
            WTQ_TEST_CHECK(st == WTQ_CAPSULE_NEED_MORE);
        }
    }
    WTQ_TEST_CHECK_EQ_SIZE(got, 2);

    *fp += failures;
}

/* every chunk size equals atomic decode, for each canonical vector */
static void test_chunk_equivalence(int *fp)
{
    int failures = 0;
    const struct {
        const uint8_t *wire;
        size_t len;
        wtq_capsule_kind_t kind;
    } vec[] = {
        { DRAIN_WIRE, sizeof(DRAIN_WIRE), WTQ_CAPSULE_KIND_DRAIN },
        { CLOSE_EMPTY_WIRE, sizeof(CLOSE_EMPTY_WIRE),
          WTQ_CAPSULE_KIND_CLOSE },
        { CLOSE_BYE_WIRE, sizeof(CLOSE_BYE_WIRE), WTQ_CAPSULE_KIND_CLOSE },
    };

    for (size_t v = 0; v < sizeof(vec) / sizeof(vec[0]); v++) {
        for (size_t chunk = 1; chunk <= vec[v].len; chunk++) {
            wtq_capsule_dec_t dec;
            wtq_capsule_dec_init(&dec);
            wtq_capsule_t c;
            size_t total = 0;
            WTQ_TEST_CHECK(feed_chunked(&dec, vec[v].wire, vec[v].len,
                                        chunk, &c, &total) ==
                           WTQ_CAPSULE_OK);
            WTQ_TEST_CHECK(c.kind == vec[v].kind);
            WTQ_TEST_CHECK_EQ_SIZE(total, vec[v].len);
        }
        /* every truncation prefix reports NEED_MORE, never MALFORMED */
        for (size_t plen = 0; plen < vec[v].len; plen++) {
            wtq_capsule_dec_t dec;
            wtq_capsule_dec_init(&dec);
            wtq_capsule_t c;
            size_t consumed = (size_t)-1;
            WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, vec[v].wire, plen,
                                                &c, &consumed) ==
                           WTQ_CAPSULE_NEED_MORE);
            WTQ_TEST_CHECK_EQ_SIZE(consumed, plen);
        }
    }

    *fp += failures;
}

/* non-minimal header varints accepted; header_len reflects wire bytes */
static void test_nonminimal(int *fp)
{
    int failures = 0;
    /* CLOSE type as 4-byte varint, length 4 as 2-byte varint */
    const uint8_t nm[] = { 0x80, 0x00, 0x28, 0x43, 0x40, 0x04,
                           0x00, 0x00, 0x00, 0x07 };
    wtq_capsule_dec_t dec;
    wtq_capsule_dec_init(&dec);
    wtq_capsule_t c;
    size_t total = 0;

    WTQ_TEST_CHECK(feed_chunked(&dec, nm, sizeof(nm), 3, &c, &total) ==
                   WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_CLOSE);
    WTQ_TEST_CHECK_EQ_SIZE(c.header_len, 6);
    WTQ_TEST_CHECK_EQ_HEX(c.close_code, 7);
    WTQ_TEST_CHECK_EQ_SIZE(c.reason_len, 0);

    *fp += failures;
}

/* zero-length probes and zero-initialized state */
static void test_probes(int *fp)
{
    int failures = 0;
    wtq_capsule_dec_t dec;
    wtq_capsule_t c;
    size_t consumed = 999;

    /* fresh decoder, zero-length feed */
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, NULL, 0, &c, &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    /* mid-header probe */
    const uint8_t half[] = { 0x68 };
    consumed = 999;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, half, 1, &c, &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, NULL, 0, &c, &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    /* mid-payload probe */
    wtq_capsule_dec_init(&dec);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, CLOSE_BYE_WIRE, 5, &c,
                                        &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 5);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, NULL, 0, &c, &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);

    /* zero-initialized state is a valid fresh decoder */
    wtq_capsule_dec_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    size_t total = 0;
    WTQ_TEST_CHECK(feed_chunked(&zeroed, DRAIN_WIRE, sizeof(DRAIN_WIRE), 1,
                                &c, &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_DRAIN);

    /* _init resets mid-parse */
    wtq_capsule_dec_init(&dec);
    consumed = 999;
    WTQ_TEST_CHECK(wtq_capsule_dec_feed(&dec, CLOSE_BYE_WIRE, 6, &c,
                                        &consumed) ==
                   WTQ_CAPSULE_NEED_MORE);
    wtq_capsule_dec_init(&dec);
    WTQ_TEST_CHECK(feed_chunked(&dec, DRAIN_WIRE, sizeof(DRAIN_WIRE), 2,
                                &c, &total) == WTQ_CAPSULE_OK);
    WTQ_TEST_CHECK(c.kind == WTQ_CAPSULE_KIND_DRAIN);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_encode(&failures);
    test_decode_known(&failures);
    test_malformed(&failures);
    test_unknown(&failures);
    test_concatenated(&failures);
    test_chunk_equivalence(&failures);
    test_nonminimal(&failures);
    test_probes(&failures);

    WTQ_TEST_PASS("test_capsule");
    return failures;
}
