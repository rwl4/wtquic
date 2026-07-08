#include <string.h>

#include "proto/h3_settings.h"

#include "test_support.h"

/* Default client/server payload (ECP on, no legacy), ascending IDs:
 * 0x01=0, 0x07=0, 0x08=1, 0x33=1, 0x2c7cf000=1. */
static const uint8_t DEFAULT_PAYLOAD[] = {
    0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
    0xac, 0x7c, 0xf0, 0x00, 0x01,
};

static void test_decode_empty(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    memset(&s, 0xEE, sizeof(s));
    WTQ_TEST_CHECK(wtq_h3_settings_decode(NULL, 0, &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(!s.has_wt_enabled);
    WTQ_TEST_CHECK(!s.has_h3_datagram);
    WTQ_TEST_CHECK(!s.has_enable_connect_protocol);
    WTQ_TEST_CHECK_EQ_SIZE(s.unknown_count, 0);

    *fp += failures;
}

/* byte-exact default encode + roundtrip through decode */
static void test_default_roundtrip(int *fp)
{
    int failures = 0;
    wtq_h3_settings_encode_cfg_t cfg = { true, false };
    uint8_t buf[64];
    size_t out_len = 0;

    WTQ_TEST_CHECK_EQ_SIZE(wtq_h3_settings_payload_len(&cfg),
                           sizeof(DEFAULT_PAYLOAD));
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cfg, buf, sizeof(buf),
                                                  &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(DEFAULT_PAYLOAD));
    WTQ_TEST_CHECK(memcmp(buf, DEFAULT_PAYLOAD, out_len) == 0);

    wtq_h3_settings_t s;
    WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, out_len, &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_qpack_max_table_capacity &&
                   s.qpack_max_table_capacity == 0);
    WTQ_TEST_CHECK(s.has_qpack_blocked_streams &&
                   s.qpack_blocked_streams == 0);
    WTQ_TEST_CHECK(s.has_enable_connect_protocol &&
                   s.enable_connect_protocol == 1);
    WTQ_TEST_CHECK(s.has_h3_datagram && s.h3_datagram == 1);
    WTQ_TEST_CHECK(s.has_wt_enabled && s.wt_enabled == 1);
    WTQ_TEST_CHECK(!s.has_wt_max_sessions_d13);
    WTQ_TEST_CHECK_EQ_SIZE(s.unknown_count, 0);

    /* Without ECP (client-minimal variant) the id disappears. */
    wtq_h3_settings_encode_cfg_t noecp = { false, WTQ_H3_WT_PROFILE_CURRENT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&noecp, buf, sizeof(buf),
                                                  &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, out_len, &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(!s.has_enable_connect_protocol);
    WTQ_TEST_CHECK(s.has_wt_enabled && s.wt_enabled == 1);

    /* RED-first #1: BYTE-EXACT current-profile SETTINGS payload — QPACK
     * zeros, ECP=1, H3_DATAGRAM=1, then WT_ENABLED (0x2c7cf000)=1 ONLY.
     * No WT_MAX_SESSIONS codepoint of either draft appears. */
    wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILE_CURRENT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cur, buf, sizeof(buf),
                                                  &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    const uint8_t cur_expect[] = {
        0x01, 0x00,                   /* QPACK_MAX_TABLE_CAPACITY=0 */
        0x07, 0x00,                   /* QPACK_BLOCKED_STREAMS=0    */
        0x08, 0x01,                   /* ENABLE_CONNECT_PROTOCOL=1  */
        0x33, 0x01,                   /* H3_DATAGRAM (RFC 0x33)=1   */
        0xac, 0x7c, 0xf0, 0x00, 0x01, /* WT_ENABLED 0x2c7cf000 = 1  */
    };
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(cur_expect));
    WTQ_TEST_CHECK(memcmp(buf, cur_expect, out_len) == 0);

    /* RED-first #2: BYTE-EXACT D13/14 compat-profile SETTINGS payload —
     * the same base, then WT_MAX_SESSIONS (0x14e9cd29)=1 ONLY. No
     * WT_ENABLED, and NEVER the D07 codepoint (0xc671706a). */
    wtq_h3_settings_encode_cfg_t compat = {
        true, WTQ_H3_WT_PROFILE_D13_14_COMPAT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&compat, buf, sizeof(buf),
                                                  &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    const uint8_t compat_expect[] = {
        0x01, 0x00,
        0x07, 0x00,
        0x08, 0x01,
        0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01, /* WT_MAX_SESSIONS 0x14e9cd29 = 1 */
    };
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(compat_expect));
    WTQ_TEST_CHECK(memcmp(buf, compat_expect, out_len) == 0);
    /* the D07 codepoint (0xc671706a -> wire c0 c6 71 70 6a) never appears */
    WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, out_len, &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_wt_max_sessions_d13 && s.wt_max_sessions_d13 == 1);
    WTQ_TEST_CHECK(!s.has_wt_max_sessions_d07);
    WTQ_TEST_CHECK(!s.has_wt_enabled);

    *fp += failures;
}

/* full SETTINGS frame helper */
static void test_frame_encode(int *fp)
{
    int failures = 0;
    wtq_h3_settings_encode_cfg_t cfg = { true, false };
    uint8_t buf[64];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&cfg, buf, sizeof(buf),
                                                &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    /* header: type 0x04, length 13 */
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 2 + sizeof(DEFAULT_PAYLOAD));
    WTQ_TEST_CHECK(buf[0] == 0x04);
    WTQ_TEST_CHECK(buf[1] == sizeof(DEFAULT_PAYLOAD));
    WTQ_TEST_CHECK(memcmp(buf + 2, DEFAULT_PAYLOAD,
                          sizeof(DEFAULT_PAYLOAD)) == 0);

    /* frame encode obeys BUFFER with untouched output */
    uint8_t small[8];
    memset(small, 0xEE, sizeof(small));
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&cfg, small, sizeof(small),
                                                &out_len) ==
                   WTQ_H3_SETTINGS_BUFFER);
    for (size_t i = 0; i < sizeof(small); i++)
        WTQ_TEST_CHECK(small[i] == 0xEE);

    *fp += failures;
}

/* duplicates: known id, unknown id */
static void test_duplicates(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    /* H3_DATAGRAM twice */
    const uint8_t dup_known[] = { 0x33, 0x01, 0x33, 0x01 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(dup_known, sizeof(dup_known),
                                          &s) == WTQ_H3_SETTINGS_ERR_SETTING);

    /* same value pair is still a duplicate id */
    const uint8_t dup_known2[] = { 0x08, 0x01, 0x33, 0x01, 0x08, 0x00 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(dup_known2, sizeof(dup_known2),
                                          &s) == WTQ_H3_SETTINGS_ERR_SETTING);

    /* unknown id 0x2442 twice */
    const uint8_t dup_unknown[] = { 0x64, 0x42, 0x00, 0x64, 0x42, 0x07 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(dup_unknown, sizeof(dup_unknown),
                                          &s) ==
                   WTQ_H3_SETTINGS_ERR_SETTING);

    *fp += failures;
}

/* reserved HTTP/2 ids 0x2..0x5 rejected; 0x6 is VALID (field section) */
static void test_reserved(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    for (uint8_t id = 0x02; id <= 0x05; id++) {
        const uint8_t wire[] = { id, 0x00 };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(wire, sizeof(wire), &s) ==
                       WTQ_H3_SETTINGS_ERR_SETTING);
    }

    const uint8_t fieldsec[] = { 0x06, 0x40, 0x64 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(fieldsec, sizeof(fieldsec), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_max_field_section_size &&
                   s.max_field_section_size == 100);

    *fp += failures;
}

/* unknown non-reserved settings ignored + counted (incl. grease) */
static void test_unknown(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    /* grease id 0x1f*1+0x21 = 0x40, and another unknown */
    const uint8_t wire[] = {
        0x40, 0x40, 0x07,       /* id 0x40 (2-byte varint), value 7 */
        0x64, 0x42, 0x00,       /* id 0x2442, value 0 */
        0x33, 0x01,             /* known amid unknowns */
    };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(wire, sizeof(wire), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK_EQ_SIZE(s.unknown_count, 2);
    WTQ_TEST_CHECK(s.has_h3_datagram && s.h3_datagram == 1);

    *fp += failures;
}

/* legacy WT codepoints recognized on receive */
static void test_legacy_receive(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    /* d13 max sessions = 4 (4-byte varint id) */
    const uint8_t d13[] = { 0x94, 0xe9, 0xcd, 0x29, 0x04 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(d13, sizeof(d13), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_wt_max_sessions_d13 && s.wt_max_sessions_d13 == 4);

    /* d07 max sessions = 1 (8-byte varint id) */
    const uint8_t d07[] = { 0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a,
                            0x01 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(d07, sizeof(d07), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_wt_max_sessions_d07 && s.wt_max_sessions_d07 == 1);

    /* Chrome legacy enable = 1 (4-byte varint id: 0x2b603742|0x80000000) */
    const uint8_t chrome[] = { 0xab, 0x60, 0x37, 0x42, 0x01 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(chrome, sizeof(chrome), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_enable_webtransport_leg &&
                   s.enable_webtransport_leg == 1);

    *fp += failures;
}

/* the PROFILE-AWARE WT-support predicate: only the selected profile's
 * WT setting satisfies it, and value-0 = unsupported. */
#define SUPP_CUR(pp, srv) \
    wtq_h3_settings_peer_supports_wt((pp), (srv), WTQ_H3_WT_PROFILE_CURRENT)
#define SUPP_COMPAT(pp, srv) \
    wtq_h3_settings_peer_supports_wt((pp), (srv), \
                                     WTQ_H3_WT_PROFILE_D13_14_COMPAT)

static void test_supports_wt(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s = { 0 };

    /* CURRENT profile: full server support (WT_ENABLED=1). */
    s.has_wt_enabled = true;
    s.wt_enabled = 1;
    s.has_h3_datagram = true;
    s.h3_datagram = 1;
    s.has_enable_connect_protocol = true;
    s.enable_connect_protocol = 1;
    WTQ_TEST_CHECK(SUPP_CUR(&s, true));
    WTQ_TEST_CHECK(SUPP_CUR(&s, false));
    /* the SAME settings do NOT satisfy the COMPAT profile (WT_ENABLED is
     * not the compat WT signal — cross-profile does not count). */
    WTQ_TEST_CHECK(!SUPP_COMPAT(&s, true));

    /* WT_ENABLED present but 0 => unsupported (current) */
    s.wt_enabled = 0;
    WTQ_TEST_CHECK(!SUPP_CUR(&s, true));
    s.wt_enabled = 1;

    /* H3_DATAGRAM present but 0 => unsupported */
    s.h3_datagram = 0;
    WTQ_TEST_CHECK(!SUPP_CUR(&s, true));
    s.h3_datagram = 1;

    /* server without ENABLE_CONNECT_PROTOCOL => unsupported as server,
     * fine as client */
    s.has_enable_connect_protocol = false;
    WTQ_TEST_CHECK(!SUPP_CUR(&s, true));
    WTQ_TEST_CHECK(SUPP_CUR(&s, false));
    s.has_enable_connect_protocol = true;

    /* COMPAT profile: WT_MAX_SESSIONS (0x14e9cd29) > 0 is the signal. */
    wtq_h3_settings_t compat = { 0 };
    compat.has_h3_datagram = true;
    compat.h3_datagram = 1;
    compat.has_enable_connect_protocol = true;
    compat.enable_connect_protocol = 1;
    compat.has_wt_max_sessions_d13 = true;
    compat.wt_max_sessions_d13 = 2;
    WTQ_TEST_CHECK(SUPP_COMPAT(&compat, true));
    WTQ_TEST_CHECK(SUPP_COMPAT(&compat, false));
    /* the compat signal does NOT satisfy the CURRENT profile. */
    WTQ_TEST_CHECK(!SUPP_CUR(&compat, true));
    compat.wt_max_sessions_d13 = 0; /* present but zero */
    WTQ_TEST_CHECK(!SUPP_COMPAT(&compat, true));
    /* the Chrome/D07 legacy signals do NOT satisfy EITHER profile now:
     * only WT_MAX_SESSIONS 0x14e9cd29 counts for compat. */
    compat.has_enable_webtransport_leg = true;
    compat.enable_webtransport_leg = 1;
    compat.has_wt_max_sessions_d07 = true;
    compat.wt_max_sessions_d07 = 1;
    WTQ_TEST_CHECK(!SUPP_COMPAT(&compat, true));
    WTQ_TEST_CHECK(!SUPP_CUR(&compat, true));

    /* nothing set */
    wtq_h3_settings_t empty = { 0 };
    WTQ_TEST_CHECK(!SUPP_CUR(&empty, true));
    WTQ_TEST_CHECK(!SUPP_CUR(&empty, false));
    WTQ_TEST_CHECK(!SUPP_COMPAT(&empty, true));

    *fp += failures;
}

/* truncation: mid-id and mid-value both NEED_MORE, at every prefix */
static void test_truncation(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    for (size_t plen = 1; plen < sizeof(DEFAULT_PAYLOAD); plen++) {
        wtq_h3_settings_status_t st =
            wtq_h3_settings_decode(DEFAULT_PAYLOAD, plen, &s);
        /* every proper prefix either ends exactly on a pair boundary
         * (OK) or mid-pair (NEED_MORE); never an error */
        WTQ_TEST_CHECK(st == WTQ_H3_SETTINGS_OK ||
                       st == WTQ_H3_SETTINGS_NEED_MORE);
    }

    /* explicitly: mid 4-byte id varint */
    const uint8_t mid_id[] = { 0xac, 0x7c };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(mid_id, sizeof(mid_id), &s) ==
                   WTQ_H3_SETTINGS_NEED_MORE);

    /* explicitly: complete id, missing value entirely */
    const uint8_t no_value[] = { 0x33 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(no_value, sizeof(no_value), &s) ==
                   WTQ_H3_SETTINGS_NEED_MORE);

    /* explicitly: complete id, mid 2-byte value varint */
    const uint8_t mid_value[] = { 0x33, 0x40 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(mid_value, sizeof(mid_value),
                                          &s) == WTQ_H3_SETTINGS_NEED_MORE);

    *fp += failures;
}

/* non-minimal varints accepted; canonical re-encode is shorter */
static void test_nonminimal(int *fp)
{
    int failures = 0;
    wtq_h3_settings_t s;

    /* H3_DATAGRAM id in 2 bytes, value 1 in 4 bytes */
    const uint8_t nm[] = { 0x40, 0x33, 0x80, 0x00, 0x00, 0x01 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(nm, sizeof(nm), &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_h3_datagram && s.h3_datagram == 1);
    WTQ_TEST_CHECK(wtq_varint_len(0x33) + wtq_varint_len(1) < sizeof(nm));

    /* duplicate detection sees through non-minimal encodings */
    const uint8_t nm_dup[] = { 0x33, 0x01, 0x40, 0x33, 0x00 };
    WTQ_TEST_CHECK(wtq_h3_settings_decode(nm_dup, sizeof(nm_dup), &s) ==
                   WTQ_H3_SETTINGS_ERR_SETTING);

    *fp += failures;
}

/* encode bounds: BUFFER leaves output untouched at every short cap */
static void test_encode_bounds(int *fp)
{
    int failures = 0;
    wtq_h3_settings_encode_cfg_t cfg = { true, true };
    size_t need = wtq_h3_settings_payload_len(&cfg);

    for (size_t cap = 0; cap < need; cap++) {
        uint8_t buf[64];
        memset(buf, 0xEE, sizeof(buf));
        size_t out_len = 999;
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cfg, buf, cap,
                                                      &out_len) ==
                       WTQ_H3_SETTINGS_BUFFER);
        for (size_t i = 0; i < sizeof(buf); i++)
            WTQ_TEST_CHECK(buf[i] == 0xEE);
    }

    *fp += failures;
}

/* H3_DATAGRAM (RFC 9297 s2.1.1) and ENABLE_CONNECT_PROTOCOL (RFC 8441
 * s3) are BOOLEAN: only 0 and 1 are legal; anything larger is a
 * SETTINGS error, whatever varint encoding carries it. */
static void test_boolean_settings(int *fp)
{
    int failures = 0;
    static const uint8_t IDS[] = { 0x08, 0x33 }; /* ECP, H3_DATAGRAM */

    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) {
        wtq_h3_settings_t s;

        /* 0 and 1 decode, in minimal and non-minimal encodings */
        static const struct {
            uint8_t bytes[9];
            size_t len;
        } good[] = {
            { { 0x00, 0x00 }, 2 },                   /* value 0, 1-byte */
            { { 0x00, 0x01 }, 2 },                   /* value 1, 1-byte */
            { { 0x00, 0x40, 0x01 }, 3 },             /* value 1, 2-byte */
            { { 0x00, 0x80, 0x00, 0x00, 0x01 }, 5 }, /* value 1, 4-byte */
            { { 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
              9 },                                   /* value 1, 8-byte */
            { { 0x00, 0x40, 0x00 }, 3 },             /* value 0, 2-byte */
        };
        for (size_t g = 0; g < sizeof(good) / sizeof(good[0]); g++) {
            uint8_t buf[16];
            memcpy(buf, good[g].bytes, good[g].len);
            buf[0] = IDS[i];
            WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, good[g].len, &s) ==
                           WTQ_H3_SETTINGS_OK);
        }

        /* anything > 1 is ERR_SETTING, in every encoding */
        static const struct {
            uint8_t bytes[9];
            size_t len;
        } bad[] = {
            { { 0x00, 0x02 }, 2 },                   /* 2, 1-byte */
            { { 0x00, 0x03 }, 2 },                   /* 3, 1-byte */
            { { 0x00, 0x40, 0x02 }, 3 },             /* 2, 2-byte */
            { { 0x00, 0x80, 0x00, 0x00, 0x02 }, 5 }, /* 2, 4-byte */
            { { 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 },
              9 },                                   /* 2, 8-byte */
            { { 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
              9 },                                   /* 2^62-1 (max) */
        };
        for (size_t b = 0; b < sizeof(bad) / sizeof(bad[0]); b++) {
            uint8_t buf[16];
            wtq_h3_settings_t before;

            memcpy(buf, bad[b].bytes, bad[b].len);
            buf[0] = IDS[i];
            memset(&s, 0xEE, sizeof(s));
            before = s;
            WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, bad[b].len, &s) ==
                           WTQ_H3_SETTINGS_ERR_SETTING);
            /* atomic: out untouched on error */
            WTQ_TEST_CHECK(memcmp(&s, &before, sizeof(s)) == 0);
        }
    }

    /* the invalid value may sit AFTER valid settings and still errors */
    {
        wtq_h3_settings_t s;
        const uint8_t buf[] = { 0x01, 0x00, 0x33, 0x07 };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, sizeof(buf), &s) ==
                       WTQ_H3_SETTINGS_ERR_SETTING);
    }

    /* NOT boolean: unknown ids, WT_ENABLED and legacy max-sessions keep
     * arbitrary values */
    {
        wtq_h3_settings_t s;
        /* unknown id 0x1f with a huge value */
        const uint8_t unk[] = { 0x1f, 0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(unk, sizeof(unk), &s) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK_EQ_SIZE(s.unknown_count, 1);

        /* RED-first #5: WT_ENABLED > 1 is H3_SETTINGS_ERROR (draft-16
         * WT_ENABLED is a 0/1 boolean). 42 must be rejected. */
        const uint8_t wt[] = { 0xac, 0x7c, 0xf0, 0x00, 0x2a };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(wt, sizeof(wt), &s) ==
                       WTQ_H3_SETTINGS_ERR_SETTING);
        /* WT_ENABLED = 1 is accepted */
        const uint8_t wt1[] = { 0xac, 0x7c, 0xf0, 0x00, 0x01 };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(wt1, sizeof(wt1), &s) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(s.has_wt_enabled);
        WTQ_TEST_CHECK_EQ_HEX(s.wt_enabled, 1);

        /* legacy WT_MAX_SESSIONS_D13 = 7 */
        const uint8_t leg[] = { 0x94, 0xe9, 0xcd, 0x29, 0x07 };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(leg, sizeof(leg), &s) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(s.has_wt_max_sessions_d13);
        WTQ_TEST_CHECK_EQ_HEX(s.wt_max_sessions_d13, 7);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_boolean_settings(&failures);

    test_decode_empty(&failures);
    test_default_roundtrip(&failures);
    test_frame_encode(&failures);
    test_duplicates(&failures);
    test_reserved(&failures);
    test_unknown(&failures);
    test_legacy_receive(&failures);
    test_supports_wt(&failures);
    test_truncation(&failures);
    test_nonminimal(&failures);
    test_encode_bounds(&failures);

    WTQ_TEST_PASS("test_h3_settings");
    return failures;
}
