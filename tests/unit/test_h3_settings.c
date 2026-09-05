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
    wtq_h3_settings_encode_cfg_t noecp = { false, WTQ_H3_WT_PROFILES_CURRENT };
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
    wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILES_CURRENT };
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
        true, WTQ_H3_WT_PROFILES_D13_14_COMPAT };
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

    /* BYTE-EXACT MULTI-VERSION advertisement: all three profiles in ONE payload,
     * in ascending identifier order (0x14e9cd29, 0x2b603742, 0x2c7cf000),
     * sharing the identical base prefix. This is a capability offer, not a
     * selection (draft-16 s7.1 and draft-02 s6 both say so). The D07
     * codepoint 0xc671706a and the legacy datagram codepoint 0xffd277
     * still never appear. */
    wtq_h3_settings_encode_cfg_t all = { true, WTQ_H3_WT_PROFILES_ALL };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&all, buf, sizeof(buf),
                                                  &out_len) ==
                   WTQ_H3_SETTINGS_OK);
    const uint8_t all_expect[] = {
        0x01, 0x00,
        0x07, 0x00,
        0x08, 0x01,
        0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01, /* WT_MAX_SESSIONS    0x14e9cd29 = 1 */
        0xab, 0x60, 0x37, 0x42, 0x01, /* ENABLE_WEBTRANSPORT 0x2b603742 = 1 */
        0xac, 0x7c, 0xf0, 0x00, 0x01, /* WT_ENABLED          0x2c7cf000 = 1 */
    };
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(all_expect));
    WTQ_TEST_CHECK(memcmp(buf, all_expect, out_len) == 0);
    /* The union is the single-profile base plus all three signals. The shared
     * 8-byte prefix is byte-identical to each single-profile payload */
    WTQ_TEST_CHECK(memcmp(all_expect, cur_expect, 8) == 0);
    WTQ_TEST_CHECK(memcmp(all_expect, compat_expect, 8) == 0);
    WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, out_len, &s) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(s.has_wt_enabled && s.wt_enabled == 1);
    WTQ_TEST_CHECK(s.has_wt_max_sessions_d13 && s.wt_max_sessions_d13 == 1);
    WTQ_TEST_CHECK(!s.has_wt_max_sessions_d07);

    /* TOTALITY. The codec never emits a WT-less advertisement. The set is
     * masked to the KNOWN profiles first, so the CURRENT-only fallback
     * covers BOTH an empty set and a non-zero set carrying only unknown
     * bits — the latter would slip past a bare `== 0` test and ship
     * SETTINGS with no WebTransport signal at all. Rejecting unknown
     * caller bits stays the engine's job at conn-create; this is defence
     * in depth. Both cases must be byte-identical to the CURRENT payload. */
    uint8_t ebuf[64];
    size_t elen = 0;
    const wtq_h3_wt_profile_set_t total_sets[] = {
        0,                                     /* empty                    */
        WTQ_H3_WT_PROFILES_ALL << 8,           /* unknown-only, disjoint   */
        UINT64_C(1) << 63,                     /* unknown-only, high bit   */
        ~WTQ_H3_WT_PROFILES_ALL,               /* every unknown bit set    */
    };
    for (size_t i = 0; i < sizeof(total_sets) / sizeof(total_sets[0]); i++) {
        wtq_h3_settings_encode_cfg_t tot = { true, total_sets[i] };
        elen = 0;
        WTQ_TEST_CHECK_EQ_SIZE(wtq_h3_settings_payload_len(&tot),
                               sizeof(cur_expect));
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&tot, ebuf,
                                                      sizeof(ebuf), &elen) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK_EQ_SIZE(elen, sizeof(cur_expect));
        WTQ_TEST_CHECK(memcmp(ebuf, cur_expect, elen) == 0);
    }
    /* A known bit accompanied by unknown bits still advertises exactly the
     * known member — masking must not swallow the real profile. */
    wtq_h3_settings_encode_cfg_t mixed = {
        true, WTQ_H3_WT_PROFILES_D13_14_COMPAT | (UINT64_C(1) << 40) };
    elen = 0;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&mixed, ebuf, sizeof(ebuf),
                                                  &elen) ==
                   WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK_EQ_SIZE(elen, sizeof(compat_expect));
    WTQ_TEST_CHECK(memcmp(ebuf, compat_expect, elen) == 0);

    *fp += failures;
}

/*
 * Profile SELECTION: the highest mutually supported profile, chosen from
 * the peer's advertisement intersected with our configured set. The token
 * plays no part here — SETTINGS alone select.
 */
static void test_select_profile(int *fp)
{
    int failures = 0;
    uint8_t buf[64];
    size_t n = 0;
    wtq_h3_settings_t peer;
    wtq_h3_wt_profile_t sel;

    /* Build a peer advertisement from a set, then decode it back. */
#define PEER_ADVERTISING(mask)                                            \
    do {                                                                  \
        wtq_h3_settings_encode_cfg_t c = { true, (mask) };                 \
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(                     \
                           &c, buf, sizeof(buf), &n) ==                    \
                       WTQ_H3_SETTINGS_OK);                                \
        WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, n, &peer) ==            \
                       WTQ_H3_SETTINGS_OK);                                \
    } while (0)

    /* --- the full pairwise matrix: our set x what the peer advertised --- */
    struct {
        wtq_h3_wt_profile_set_t peer_mask;
        wtq_h3_wt_profile_set_t our_set;
        bool expect;
        wtq_h3_wt_profile_t want;
    } cases[] = {
        /* single vs single: match */
        { WTQ_H3_WT_PROFILES_CURRENT, WTQ_H3_WT_PROFILES_CURRENT,
          true, WTQ_H3_WT_PROFILE_CURRENT },
        { WTQ_H3_WT_PROFILES_D13_14_COMPAT, WTQ_H3_WT_PROFILES_D13_14_COMPAT,
          true, WTQ_H3_WT_PROFILE_D13_14_COMPAT },
        { WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          true, WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT },
        /* single vs single: cross-profile has NO intersection */
        { WTQ_H3_WT_PROFILES_CURRENT, WTQ_H3_WT_PROFILES_D13_14_COMPAT,
          false, 0 },
        { WTQ_H3_WT_PROFILES_D13_14_COMPAT, WTQ_H3_WT_PROFILES_CURRENT,
          false, 0 },
        { WTQ_H3_WT_PROFILES_CURRENT,
          WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT, false, 0 },
        { WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          WTQ_H3_WT_PROFILES_CURRENT, false, 0 },
        { WTQ_H3_WT_PROFILES_D13_14_COMPAT,
          WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT, false, 0 },
        { WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          WTQ_H3_WT_PROFILES_D13_14_COMPAT, false, 0 },
        /* we offer all profiles, peer offers one: the peer decides */
        { WTQ_H3_WT_PROFILES_CURRENT, WTQ_H3_WT_PROFILES_ALL,
          true, WTQ_H3_WT_PROFILE_CURRENT },
        { WTQ_H3_WT_PROFILES_D13_14_COMPAT, WTQ_H3_WT_PROFILES_ALL,
          true, WTQ_H3_WT_PROFILE_D13_14_COMPAT },
        { WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          WTQ_H3_WT_PROFILES_ALL,
          true, WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT },
        /* peer offers all profiles, we offer one: we decide */
        { WTQ_H3_WT_PROFILES_ALL, WTQ_H3_WT_PROFILES_CURRENT,
          true, WTQ_H3_WT_PROFILE_CURRENT },
        { WTQ_H3_WT_PROFILES_ALL, WTQ_H3_WT_PROFILES_D13_14_COMPAT,
          true, WTQ_H3_WT_PROFILE_D13_14_COMPAT },
        { WTQ_H3_WT_PROFILES_ALL,
          WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
          true, WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT },
        /* Both offer all profiles: HIGHEST mutual wins — CURRENT. The winner is
         * fixed by the explicit newest-first PRECEDENCE TABLE, not by the
         * order the settings appear on the wire and not by any implicit
         * enum-iteration contract (the enum values carry no precedence
         * meaning of their own). The reverse-precedence neuter below is
         * what makes that load-bearing. */
        { WTQ_H3_WT_PROFILES_ALL, WTQ_H3_WT_PROFILES_ALL,
          true, WTQ_H3_WT_PROFILE_CURRENT },
        /* an empty set of ours can never select anything */
        { WTQ_H3_WT_PROFILES_ALL, 0, false, 0 },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        PEER_ADVERTISING(cases[i].peer_mask);
        sel = (wtq_h3_wt_profile_t)0x7f; /* poison: must stay on false */
        bool got = wtq_h3_settings_select_profile(&peer, true,
                                                  cases[i].our_set, &sel);
        WTQ_TEST_CHECK_EQ_INT((int)got, (int)cases[i].expect);
        if (cases[i].expect)
            WTQ_TEST_CHECK_EQ_INT((int)sel, (int)cases[i].want);
        else
            /* *out is UNTOUCHED when there is no mutual profile */
            WTQ_TEST_CHECK_EQ_INT((int)sel, 0x7f);
    }

    /* Exhaustive nonempty-set intersection: all 7 peer advertisements
     * crossed with all 7 local sets. This catches omissions when a new
     * profile is added to one side of the negotiation policy but not the
     * other. Expected precedence is computed independently from the public
     * mask constants, not by calling the production profile-bit helper. */
    for (uint64_t peer_mask = 1; peer_mask <= WTQ_H3_WT_PROFILES_ALL;
         peer_mask++) {
        PEER_ADVERTISING(peer_mask);
        for (uint64_t our_set = 1; our_set <= WTQ_H3_WT_PROFILES_ALL;
             our_set++) {
            const uint64_t mutual = peer_mask & our_set;
            const bool expect = mutual != 0;
            wtq_h3_wt_profile_t want = WTQ_H3_WT_PROFILE_CURRENT;

            if (mutual & WTQ_H3_WT_PROFILES_CURRENT)
                want = WTQ_H3_WT_PROFILE_CURRENT;
            else if (mutual & WTQ_H3_WT_PROFILES_D13_14_COMPAT)
                want = WTQ_H3_WT_PROFILE_D13_14_COMPAT;
            else if (mutual & WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT)
                want = WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT;

            sel = (wtq_h3_wt_profile_t)0x7f;
            const bool got = wtq_h3_settings_select_profile(
                &peer, true, our_set, &sel);
            WTQ_TEST_CHECK_EQ_INT((int)got, (int)expect);
            if (expect)
                WTQ_TEST_CHECK_EQ_INT((int)sel, (int)want);
            else
                WTQ_TEST_CHECK_EQ_INT((int)sel, 0x7f);
        }
    }

    /* --- D02/RFC9297 negative selection rows --- */
    {
        /* A peer advertising the D02 signal but NO RFC 9297 0x33 must not
         * select D02: 0xffd277 is never accepted as datagram capability,
         * because wtquic implements only RFC 9297 framing. */
        wtq_h3_settings_t p2;
        memset(&p2, 0, sizeof(p2));
        p2.has_enable_webtransport_leg = true;
        p2.enable_webtransport_leg = 1;
        /* deliberately no has_h3_datagram; a legacy-only peer is modelled
         * by the unknown-setting path, which never sets it */
        sel = (wtq_h3_wt_profile_t)0x7f;
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &p2, false, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel, 0x7f);

        /* value 0 never selects, even with datagrams present */
        wtq_h3_settings_t p3;
        memset(&p3, 0, sizeof(p3));
        p3.has_enable_webtransport_leg = true;
        p3.enable_webtransport_leg = 0;
        p3.has_h3_datagram = true;
        p3.h3_datagram = 1;
        sel = (wtq_h3_wt_profile_t)0x7f;
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &p3, false, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel, 0x7f);

        /* both present and 1 -> selects D02 */
        p3.enable_webtransport_leg = 1;
        WTQ_TEST_CHECK(wtq_h3_settings_select_profile(
            &p3, false, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel,
                              (int)WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT);
    }

    /* --- per-profile transport requirements --- */
    /* no ENABLE_CONNECT_PROTOCOL: fine for a server judging a client,
     * fatal for a client judging a server */
    {
        wtq_h3_settings_encode_cfg_t c = { false, WTQ_H3_WT_PROFILES_ALL };
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&c, buf, sizeof(buf),
                                                      &n) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, n, &peer) ==
                       WTQ_H3_SETTINGS_OK);
        /* CURRENT and D13/14 still require the peer server's 0x08, so a
         * set holding only those two selects nothing here. */
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &peer, true,
            WTQ_H3_WT_PROFILES_CURRENT | WTQ_H3_WT_PROFILES_D13_14_COMPAT,
            &sel));
        /* D02/RFC9297 deliberately does NOT require it (draft-02 s3.2:
         * ENABLE_WEBTRANSPORT implies extended CONNECT), so the full set
         * selects D02 rather than nothing. */
        WTQ_TEST_CHECK(wtq_h3_settings_select_profile(
            &peer, true, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel,
                              (int)WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT);
        WTQ_TEST_CHECK(wtq_h3_settings_select_profile(
            &peer, false, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel, (int)WTQ_H3_WT_PROFILE_CURRENT);
    }
    /* H3_DATAGRAM absent: no profile is selectable in either direction */
    {
        const uint8_t no_dgram[] = {
            0x08, 0x01,
            0xac, 0x7c, 0xf0, 0x00, 0x01,
        };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(no_dgram, sizeof(no_dgram),
                                              &peer) == WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &peer, true, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &peer, false, WTQ_H3_WT_PROFILES_ALL, &sel));
    }
    /* A D07-only peer matches no supported profile (0xc671706a is
     * receive-only and is never a member). A draft-02-signal peer WITHOUT
     * RFC 9297 0x33 = 1 also matches none, because D02/RFC9297 requires
     * that datagram signal — the missing 0x33 is what excludes it:
     * a signal outside our set never selects anything on its own */
    {
        const uint8_t d07_only[] = {
            0x33, 0x01,
            0x08, 0x01,
            /* 0xc671706a needs the 8-byte varint form (> 0x3fffffff) */
            0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01,
        };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(d07_only, sizeof(d07_only),
                                              &peer) == WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(peer.has_wt_max_sessions_d07);
        WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(
            &peer, true, WTQ_H3_WT_PROFILES_ALL, &sel));
    }
    /* h3zero sends BOTH 0x14e9cd29 and 0xc671706a: the D13 signal decides,
     * and the unsupported D07 codepoint alongside it changes nothing */
    {
        const uint8_t h3zero[] = {
            0x33, 0x01,
            0x08, 0x01,
            0x94, 0xe9, 0xcd, 0x29, 0x01, /* 0x14e9cd29 = 1 */
            0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01,
        };
        WTQ_TEST_CHECK(wtq_h3_settings_decode(h3zero, sizeof(h3zero),
                                              &peer) == WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(wtq_h3_settings_select_profile(
            &peer, true, WTQ_H3_WT_PROFILES_ALL, &sel));
        WTQ_TEST_CHECK_EQ_INT((int)sel, (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT);
    }

    /* NULL guards */
    WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(NULL, true,
                                                   WTQ_H3_WT_PROFILES_ALL,
                                                   &sel));
    WTQ_TEST_CHECK(!wtq_h3_settings_select_profile(&peer, true,
                                                   WTQ_H3_WT_PROFILES_ALL,
                                                   NULL));

#undef PEER_ADVERTISING
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
#define SUPP_D02(pp, srv) \
    wtq_h3_settings_peer_supports_wt( \
        (pp), (srv), WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT)

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
    /* D07 contributes no support. With D13 zero, the exact
     * ENABLE_WEBTRANSPORT + RFC 9297 H3_DATAGRAM pair selects D02. */
    compat.has_enable_webtransport_leg = true;
    compat.enable_webtransport_leg = 1;
    compat.has_wt_max_sessions_d07 = true;
    compat.wt_max_sessions_d07 = 1;
    WTQ_TEST_CHECK(!SUPP_COMPAT(&compat, true));
    WTQ_TEST_CHECK(!SUPP_CUR(&compat, true));
    WTQ_TEST_CHECK(SUPP_D02(&compat, true));
    /* Removing the D02 signal leaves D07 alone, which matches nothing. */
    compat.has_enable_webtransport_leg = false;
    WTQ_TEST_CHECK(!SUPP_D02(&compat, true));

    /* D02/RFC9297: exact enable value 1 plus RFC 9297 H3_DATAGRAM=1.
     * Unlike CURRENT and D13/14, peer servers need not send a separate
     * ENABLE_CONNECT_PROTOCOL because draft-02 makes it implicit. */
    wtq_h3_settings_t d02 = { 0 };
    d02.has_enable_webtransport_leg = true;
    d02.enable_webtransport_leg = 1;
    d02.has_h3_datagram = true;
    d02.h3_datagram = 1;
    WTQ_TEST_CHECK(SUPP_D02(&d02, true));
    WTQ_TEST_CHECK(SUPP_D02(&d02, false));
    WTQ_TEST_CHECK(!SUPP_CUR(&d02, true));
    WTQ_TEST_CHECK(!SUPP_COMPAT(&d02, true));
    d02.enable_webtransport_leg = 0;
    WTQ_TEST_CHECK(!SUPP_D02(&d02, true));
    d02.enable_webtransport_leg = 1;
    d02.h3_datagram = 0;
    WTQ_TEST_CHECK(!SUPP_D02(&d02, true));

    /* nothing set */
    wtq_h3_settings_t empty = { 0 };
    WTQ_TEST_CHECK(!SUPP_CUR(&empty, true));
    WTQ_TEST_CHECK(!SUPP_CUR(&empty, false));
    WTQ_TEST_CHECK(!SUPP_COMPAT(&empty, true));
    WTQ_TEST_CHECK(!SUPP_D02(&empty, true));

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
    /* The WIDEST advertisement (every known profile) gives the longest
     * payload, so the capacity sweep below covers the worst case. */
    wtq_h3_settings_encode_cfg_t cfg = { true, WTQ_H3_WT_PROFILES_ALL };
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

    /* Unknown ids and legacy max-sessions keep arbitrary values;
     * WT_ENABLED remains a strict boolean. */
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


/*
 * All eight profile-set shapes (masks 0..7), parsed by an INDEPENDENT
 * varint reader — not the production decoder and not the production
 * selector.
 */
static bool hs_varint(const uint8_t *p, size_t len, size_t *off,
                      uint64_t *out)
{
    if (*off >= len)
        return false;
    const uint8_t b = p[*off];
    const unsigned n = 1u << (b >> 6);
    if (*off + n > len)
        return false;
    uint64_t v = b & 0x3f;
    for (unsigned i = 1; i < n; i++)
        v = (v << 8) | p[*off + i];
    *off += n;
    *out = v;
    return true;
}

struct hs_scan {
    bool ok;
    unsigned n_cur, n_d13, n_d02, n_d07, n_legacy_dgram, n_dgram;
    uint64_t v_cur, v_d13, v_d02, v_dgram;
    bool ascending;
};

static struct hs_scan hs_scan_payload(const uint8_t *p, size_t len)
{
    struct hs_scan s;
    memset(&s, 0, sizeof(s));
    s.ascending = true;
    uint64_t prev = 0;
    bool first = true;
    size_t off = 0;
    while (off < len) {
        uint64_t id, val;
        if (!hs_varint(p, len, &off, &id) ||
            !hs_varint(p, len, &off, &val))
            return s;                      /* s.ok stays false */
        if (!first && id < prev)
            s.ascending = false;
        prev = id;
        first = false;
        switch (id) {
        case 0x2c7cf000: s.n_cur++;          s.v_cur = val;   break;
        case 0x14e9cd29: s.n_d13++;          s.v_d13 = val;   break;
        case 0x2b603742: s.n_d02++;          s.v_d02 = val;   break;
        case 0xc671706a: s.n_d07++;                            break;
        case 0xffd277:   s.n_legacy_dgram++;                   break;
        case 0x33:       s.n_dgram++;        s.v_dgram = val; break;
        default: break;
        }
    }
    s.ok = true;
    return s;
}

static void test_all_eight_profile_set_shapes(int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    size_t n = 0;

    for (uint64_t mask = 0; mask <= 7; mask++) {
        const bool want_cur = (mask & WTQ_H3_WT_PROFILES_CURRENT) != 0;
        const bool want_d13 =
            (mask & WTQ_H3_WT_PROFILES_D13_14_COMPAT) != 0;
        const bool want_d02 =
            (mask & WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT) != 0;
        /* mask 0 normalises to CURRENT: the codec is total. */
        const bool emit_cur = (mask == 0) ? true : want_cur;
        const bool emit_d13 = (mask == 0) ? false : want_d13;
        const bool emit_d02 = (mask == 0) ? false : want_d02;

        wtq_h3_settings_encode_cfg_t cfg = { true, mask };
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cfg, buf, sizeof(buf),
                                                      &n) ==
                       WTQ_H3_SETTINGS_OK);
        struct hs_scan s = hs_scan_payload(buf, n);
        WTQ_TEST_CHECK(s.ok);
        /* membership and cardinality: each signal at most once */
        WTQ_TEST_CHECK_EQ_INT((int)s.n_cur, emit_cur ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT((int)s.n_d13, emit_d13 ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT((int)s.n_d02, emit_d02 ? 1 : 0);
        if (emit_cur) WTQ_TEST_CHECK_EQ_U64(s.v_cur, 1);
        if (emit_d13) WTQ_TEST_CHECK_EQ_U64(s.v_d13, 1);
        if (emit_d02) WTQ_TEST_CHECK_EQ_U64(s.v_d02, 1);
        /* ascending setting-id order */
        WTQ_TEST_CHECK(s.ascending);
        /* local RFC 9297 datagram always present at 1 */
        WTQ_TEST_CHECK_EQ_INT((int)s.n_dgram, 1);
        WTQ_TEST_CHECK_EQ_U64(s.v_dgram, 1);
        /* D07 and the legacy datagram codepoint are NEVER emitted */
        WTQ_TEST_CHECK_EQ_INT((int)s.n_d07, 0);
        WTQ_TEST_CHECK_EQ_INT((int)s.n_legacy_dgram, 0);

        /* production decode round-trips the emitted shape */
        wtq_h3_settings_t back;
        WTQ_TEST_CHECK(wtq_h3_settings_decode(buf, n, &back) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(back.has_wt_enabled == emit_cur);
        WTQ_TEST_CHECK(back.has_wt_max_sessions_d13 == emit_d13);
        WTQ_TEST_CHECK(back.has_enable_webtransport_leg == emit_d02);

        /* precedence CURRENT > D13/14 > D02 for this shape */
        wtq_h3_wt_profile_t sel = (wtq_h3_wt_profile_t)0x7f;
        const uint64_t use = (mask == 0) ? WTQ_H3_WT_PROFILES_CURRENT : mask;
        WTQ_TEST_CHECK(wtq_h3_settings_select_profile(&back, false, use,
                                                      &sel));
        const int want_sel =
            emit_cur ? (int)WTQ_H3_WT_PROFILE_CURRENT
                     : (emit_d13 ? (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT
                                 : (int)WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT);
        WTQ_TEST_CHECK_EQ_INT((int)sel, want_sel);
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
    test_select_profile(&failures);
    test_truncation(&failures);
    test_nonminimal(&failures);
    test_encode_bounds(&failures);

    test_all_eight_profile_set_shapes(&failures);


    WTQ_TEST_PASS("test_h3_settings");
    return failures;
}
