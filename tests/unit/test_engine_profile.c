/*
 * End-to-end WebTransport wire-profile symmetry over the deterministic engine
 * pair. Each side is configured with a profile (current draft-16 vs D13/14
 * compat) and selects/latches from its peer's SETTINGS; a
 * matched pair establishes, a mismatched pair does not — the client rejects
 * the peer's SETTINGS as no-WT-support before it ever sends a CONNECT, because
 * one profile's WT signal never satisfies the other's predicate.
 */

#include <stdio.h>
#include <string.h>

#include <wtquic/session.h>

#include "wt_driver.h"

#include "proto/h3_settings.h"

#include "fake_driver.h"

#include "test_support.h"
#include "wtq_simpair.h"

static const char *const PROF_OFFER[] = { "moqt-18", "moqt-16" };
static const char *const PROF_SUPPORTED[] = { "moqt-16", "moqt-18" };

/* WT_ENABLED (0x2c7cf000) / WT_MAX_SESSIONS (0x14e9cd29) 4-byte varint ids. */
static const uint8_t WT_ENABLED_ID[] = { 0xac, 0x7c, 0xf0, 0x00 };
static const uint8_t WT_MAXSESS_ID[] = { 0x94, 0xe9, 0xcd, 0x29 };
/* ENABLE_WEBTRANSPORT (0x2b603742), the D02/RFC9297 signal. */
static const uint8_t ENABLE_WT_ID[] = { 0xab, 0x60, 0x37, 0x42 };

static bool ctrl_has(const struct wtq_dstream *ctrl, const uint8_t *pat,
                     size_t plen)
{
    if (ctrl == NULL || ctrl->len < plen)
        return false;
    for (size_t i = 0; i + plen <= ctrl->len; i++)
        if (memcmp(ctrl->bytes + i, pat, plen) == 0)
            return true;
    return false;
}

/* Run one client/server profile pairing to quiescence. */
static int run_pair(uint64_t seed, int c_prof, int s_prof, wtq_simpair_t *sp)
{
    int failures = 0;

    WTQ_TEST_CHECK(wtq_simpair_create_profiles(sp, seed, c_prof, s_prof) == 0);
    wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true, 0, NULL, 0 };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(sp, &path, 1) == WTQ_OK);
    /* The client re-states its requested profile here; it must match the
     * profile it was configured with so the CONNECT token matches its
     * emitted SETTINGS. */
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, PROF_OFFER, 2, true, c_prof,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(sp, 64);
    return failures;
}


/* ---- server-side negotiation over a capability SET ------------------- */

/* Run a MULTI-PROFILE server against a singleton client. */
static int run_multi(uint64_t seed, wtq_h3_wt_profile_set_t server_set,
                     int c_prof, wtq_simpair_t *sp)
{
    int failures = 0;

    WTQ_TEST_CHECK(wtq_simpair_create_profile_set(sp, seed, c_prof,
                                                  server_set) == 0);
    wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true, 0, NULL, 0 };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, PROF_OFFER, 2, true, c_prof,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(sp, 64);
    return failures;
}

/*
 * (1) A multi-profile server ADVERTISES the union before it can know the
 * peer's choice, and (2)/(3) latches exactly the one profile the singleton
 * client offered — the token never chose it, the peer's SETTINGS did.
 */
static void test_multi_server_union_and_latch(int *fp)
{
    int failures = 0;
    const wtq_h3_wt_profile_set_t BOTH =
        WTQ_H3_WT_PROFILES_CURRENT | WTQ_H3_WT_PROFILES_D13_14_COMPAT;

    /* multi server + CURRENT client */
    {
        static wtq_simpair_t sp;
        failures += run_multi(0xC0DE10, BOTH,
                              (int)WTQ_H3_WT_PROFILE_CURRENT, &sp);
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        /* the UNION is on the wire: both signals, one advertisement */
        WTQ_TEST_CHECK(ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
        int latched = -1;
        WTQ_TEST_CHECK(wtq_conn_wt_profile_latched(sp.s.conn, &latched));
        WTQ_TEST_CHECK_EQ_INT(latched, (int)WTQ_H3_WT_PROFILE_CURRENT);
        wtq_simpair_destroy(&sp);
    }

    /* multi server + D13/14 client: the SAME server binary latches compat */
    {
        static wtq_simpair_t sp;
        failures += run_multi(0xC0DE11, BOTH,
                              (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, &sp);
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        WTQ_TEST_CHECK(ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
        int latched = -1;
        WTQ_TEST_CHECK(wtq_conn_wt_profile_latched(sp.s.conn, &latched));
        WTQ_TEST_CHECK_EQ_INT(latched,
                              (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT);
        wtq_simpair_destroy(&sp);
    }

    /* A CURRENT-only server facing a compat client still has NO mutual
     * profile: nothing latches and nothing establishes. */
    {
        static wtq_simpair_t sp;
        failures += run_multi(0xC0DE12, WTQ_H3_WT_PROFILES_CURRENT,
                              (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 0);
        WTQ_TEST_CHECK(!wtq_conn_wt_profile_latched(sp.s.conn, NULL));
        WTQ_TEST_CHECK(!wtq_conn_peer_supports_wt(sp.s.conn));
        /* the callback itself observed no latch, and the sentinel stands */
        WTQ_TEST_CHECK(!sp.s.cb_profile_latched);
        WTQ_TEST_CHECK_EQ_INT(sp.s.cb_profile, WTQ_SIMPAIR_NO_PROFILE);
        wtq_simpair_destroy(&sp);
    }

    *fp += failures;
}

/*
 * (11) The latch exists BEFORE on_peer_settings observes support, and is
 * immutable afterwards. The simpair records support at callback time; the
 * latch must already be readable then, and unchanged at quiescence.
 */
static void test_latch_precedes_callback_and_is_immutable(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;
    const wtq_h3_wt_profile_set_t BOTH =
        WTQ_H3_WT_PROFILES_CURRENT | WTQ_H3_WT_PROFILES_D13_14_COMPAT;

    failures += run_multi(0xC0DE13, BOTH,
                          (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, &sp);
    WTQ_TEST_CHECK(wtq_conn_peer_settings_received(sp.s.conn));
    WTQ_TEST_CHECK(wtq_conn_peer_supports_wt(sp.s.conn));
    /* CAUSAL: the latch existed DURING on_peer_settings, sampled inside the
     * callback itself — reading it at quiescence could not distinguish a
     * latch written after the callback. */
    WTQ_TEST_CHECK_EQ_INT(sp.s.settings_events, 1);
    WTQ_TEST_CHECK(sp.s.wt_supported);
    WTQ_TEST_CHECK(sp.s.cb_profile_latched);
    WTQ_TEST_CHECK_EQ_INT(sp.s.cb_profile,
                          (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT);
    /* and the same value is still there afterwards */
    int latched = -1;
    WTQ_TEST_CHECK(wtq_conn_wt_profile_latched(sp.s.conn, &latched));
    WTQ_TEST_CHECK_EQ_INT(latched, (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT);
    WTQ_TEST_CHECK_EQ_INT(sp.s.cb_profile, latched);
    /* still the same after the session has fully established: immutable */
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
    int again = -1;
    WTQ_TEST_CHECK(wtq_conn_wt_profile_latched(sp.s.conn, &again));
    WTQ_TEST_CHECK_EQ_INT(again, latched);
    wtq_simpair_destroy(&sp);

    *fp += failures;
}

/*
 * (14) An invalid internal capability set is rejected at the engine
 * boundary, BEFORE any allocation or I/O — the codec's CURRENT-only
 * fallback is defence in depth, never acceptance.
 */
static void test_invalid_profile_set_rejected(int *fp)
{
    int failures = 0;
    struct wtq_driver drv;
    wtq_conn_t *conn = NULL;

    fake_driver_init(&drv, false);
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_SERVER,
        .enable_connect_protocol = true,
    };

    /* unknown bits alongside a known member */
    cfg.webtransport_profiles =
        WTQ_H3_WT_PROFILES_CURRENT | (UINT64_C(1) << 40);
    WTQ_TEST_CHECK_EQ_INT(
        (int)wtq_conn_create(&cfg, &drv, fake_driver_ops(), &conn),
        (int)WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(conn == NULL);

    /* unknown bits only — no known member at all */
    cfg.webtransport_profiles = UINT64_C(1) << 63;
    WTQ_TEST_CHECK_EQ_INT(
        (int)wtq_conn_create(&cfg, &drv, fake_driver_ops(), &conn),
        (int)WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(conn == NULL);

    /* a VALID set still builds, and nothing is latched at create */
    cfg.webtransport_profiles =
        WTQ_H3_WT_PROFILES_CURRENT | WTQ_H3_WT_PROFILES_D13_14_COMPAT;
    WTQ_TEST_CHECK_EQ_INT(
        (int)wtq_conn_create(&cfg, &drv, fake_driver_ops(), &conn),
        (int)WTQ_OK);
    if (conn != NULL) {
        WTQ_TEST_CHECK(!wtq_conn_wt_profile_latched(conn, NULL));
        wtq_conn_destroy(conn);
    }

    *fp += failures;
}

/* (1)/(2): matched profiles establish end to end; the server emits its own
 * profile's WT SETTINGS. */
static void test_matched_profiles_establish(int *fp)
{
    int failures = 0;

    /* current <-> current */
    {
        static wtq_simpair_t sp;
        failures += run_pair(0xC0DE01, (int)WTQ_H3_WT_PROFILE_CURRENT,
                             (int)WTQ_H3_WT_PROFILE_CURRENT, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
        /* both control streams speak the current WT signal, never compat */
        const struct wtq_dstream *cc = fake_driver_local(&sp.c.drv, 0);
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        WTQ_TEST_CHECK(ctrl_has(cc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        wtq_simpair_destroy(&sp);
    }

    /* compat <-> compat */
    {
        static wtq_simpair_t sp;
        failures += run_pair(0xC0DE02, (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT,
                             (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
        /* both control streams speak the compat WT signal, never current */
        const struct wtq_dstream *cc = fake_driver_local(&sp.c.drv, 0);
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        WTQ_TEST_CHECK(ctrl_has(cc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        WTQ_TEST_CHECK(!ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        wtq_simpair_destroy(&sp);
    }

    *fp += failures;
}

/* (3)/(4): mismatched profiles never establish — the client fails with
 * NO_WT_SUPPORT on the peer SETTINGS (its profile's predicate is not met) and
 * never opens a CONNECT stream, so the server never establishes either. */
static void test_mismatched_profiles_reject(int *fp)
{
    int failures = 0;

    /* current client <-> compat server */
    {
        static wtq_simpair_t sp;
        failures += run_pair(0xC0DE03, (int)WTQ_H3_WT_PROFILE_CURRENT,
                             (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_reason,
                              (int)WTQ_SESSION_FAIL_NO_WT_SUPPORT);
        WTQ_TEST_CHECK(!sp.c.wt_supported);
        WTQ_TEST_CHECK(!sp.s.wt_supported);
        wtq_simpair_destroy(&sp);
    }

    /* compat client <-> current server */
    {
        static wtq_simpair_t sp;
        failures += run_pair(0xC0DE04, (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT,
                             (int)WTQ_H3_WT_PROFILE_CURRENT, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.c.failed_reason,
                              (int)WTQ_SESSION_FAIL_NO_WT_SUPPORT);
        WTQ_TEST_CHECK(!sp.c.wt_supported);
        WTQ_TEST_CHECK(!sp.s.wt_supported);
        wtq_simpair_destroy(&sp);
    }

    *fp += failures;
}


/* ---- D02/RFC9297 client symmetry ------------------------------------ */

#define D02 WTQ_H3_WT_PROFILE_D02_RFC9297_COMPAT
#define D02_ORIGIN "https://example.com:443"

static void configure_d02_origin_policy(
    wtq_server_path_cfg_t *path, wtq_h3_wt_profile_set_t server_set)
{
    if ((server_set & WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT) == 0)
        return;
    path->origin_policy = WTQ_ORIGIN_POLICY_ALLOW_ANY_INCLUDING_NULL;
}

/* A D02 pairing needs an Origin (draft-02 s3.3), so it gets its own runner. */
static int run_pair_d02(uint64_t seed, int c_prof,
                        wtq_h3_wt_profile_set_t server_set,
                        const char *origin, wtq_simpair_t *sp)
{
    int failures = 0;
    WTQ_TEST_CHECK(wtq_simpair_create_profile_set(sp, seed, c_prof,
                                                  server_set) == 0);
    wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true, 0, NULL, 0 };
    configure_d02_origin_policy(&path, server_set);
    WTQ_TEST_CHECK(wtq_simpair_server_paths(sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", origin, PROF_OFFER, 2, true, c_prof,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(sp, 64);
    return failures;
}

/* D02 client against a D02-only server: a true self-pair establishes, and
 * both halves of the marker contract ran (request required by the server,
 * response required by the client). */
static void test_d02_self_pair_establishes(int *fp)
{
    int failures = 0;
    wtq_simpair_t sp;
    failures += run_pair_d02(0xD02A, D02, WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                             D02_ORIGIN, &sp);
    WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.c.failed_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
    /* both control streams carry the D02 signal, and NEITHER other one */
    {
        const struct wtq_dstream *cc = fake_driver_local(&sp.c.drv, 0);
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        WTQ_TEST_CHECK(ctrl_has(cc, ENABLE_WT_ID, sizeof(ENABLE_WT_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, ENABLE_WT_ID, sizeof(ENABLE_WT_ID)));
        WTQ_TEST_CHECK(!ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
    }
    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* D02 client against a UNION server: D02 is selected solely from SETTINGS. */
static void test_d02_selected_from_union(int *fp)
{
    int failures = 0;
    wtq_simpair_t sp;
    failures += run_pair_d02(0xD02B, D02, WTQ_H3_WT_PROFILES_ALL, D02_ORIGIN,
                             &sp);
    WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
    /* the union server advertised all three; the client offered only D02 */
    {
        const struct wtq_dstream *sc = fake_driver_local(&sp.s.drv, 0);
        WTQ_TEST_CHECK(ctrl_has(sc, ENABLE_WT_ID, sizeof(ENABLE_WT_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(ctrl_has(sc, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
    }
    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* Every cross-profile mismatch involving D02 must NOT establish. */
static void test_d02_cross_profile_mismatches(int *fp)
{
    int failures = 0;
    const struct { int c; wtq_h3_wt_profile_set_t s; } rows[] = {
        { D02, WTQ_H3_WT_PROFILES_CURRENT },
        { D02, WTQ_H3_WT_PROFILES_D13_14_COMPAT },
        { WTQ_H3_WT_PROFILE_CURRENT, WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT },
        { WTQ_H3_WT_PROFILE_D13_14_COMPAT,
          WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        wtq_simpair_t sp;
        failures += run_pair_d02(0xD02C + i, rows[i].c, rows[i].s,
                                 D02_ORIGIN, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 0);
        wtq_simpair_destroy(&sp);
    }
    *fp += failures;
}

/*
 * A D02 client REQUIRES an Origin, rejected BEFORE any effect; and a failed
 * D02 preflight must not poison a later CURRENT connect on the same engine.
 */
static void test_d02_client_origin_preflight_zero_effect(int *fp)
{
    int failures = 0;
    const char *bad[] = {
        NULL, "", "example.com:443",
        "https://example.com:0", "https://example.com:65536",
        "https://example.com:44a", "https://user@example.com:443",
        "https://example.com:443/p", "https://example.com:443?q",
        "https://example.com:443#f", "https://a.com:1 https://b.com:2",
        "https://exa mple.com:443",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        wtq_simpair_t sp;
        WTQ_TEST_CHECK(wtq_simpair_create_profile_set(
            &sp, 0xD02D + i, D02,
            WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT) == 0);
        wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true, 0, NULL, 0 };
        configure_d02_origin_policy(
            &path, WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT);
        WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
        wtq_client_connect_cfg_t ccfg = {
            "example.com", "/moq", bad[i], PROF_OFFER, 2, true, D02,
        };
        /* rejected before effect */
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) ==
                       WTQ_ERR_INVALID_ARG);
        /*
         * ZERO EFFECT on the same engine: the rejected attempt mutated
         * nothing, so a VALID D02 connect still succeeds. (A CURRENT
         * request here would be WTQ_ERR_STATE by design — a client's
         * profile is committed at create — so reuse is tested within the
         * configured profile, and cross-profile non-poisoning is covered
         * separately below.)
         */
        wtq_client_connect_cfg_t good = {
            "example.com", "/moq", D02_ORIGIN, PROF_OFFER, 2, true, D02,
        };
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &good) == WTQ_OK);
        wtq_simpair_destroy(&sp);
    }
    /*
     * Cross-profile non-poisoning: on a CURRENT-configured engine a D02
     * request is rejected, and the engine still completes a normal CURRENT
     * connect afterwards.
     */
    {
        wtq_simpair_t sp;
        WTQ_TEST_CHECK(wtq_simpair_create_profile_set(
            &sp, 0xD02CC, (int)WTQ_H3_WT_PROFILE_CURRENT,
            WTQ_H3_WT_PROFILES_CURRENT) == 0);
        wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true, 0, NULL, 0 };
        WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
        wtq_client_connect_cfg_t d02req = {
            "example.com", "/moq", D02_ORIGIN, PROF_OFFER, 2, true, D02,
        };
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &d02req) != WTQ_OK);
        wtq_client_connect_cfg_t cur = {
            "example.com", "/moq", NULL, PROF_OFFER, 2, true,
            (int)WTQ_H3_WT_PROFILE_CURRENT,
        };
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &cur) == WTQ_OK);
        (void)wtq_simpair_run_until_quiescent(&sp, 64);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        wtq_simpair_destroy(&sp);
    }

    /* the exact fixture origin is accepted */
    {
        wtq_simpair_t sp;
        failures += run_pair_d02(0xD02E, D02,
                                 WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                                 D02_ORIGIN, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        wtq_simpair_destroy(&sp);
    }
    *fp += failures;
}

static bool make_d02_origin_len(char *dst, size_t cap, size_t total)
{
    static const char prefix[] = "https://";

    if (total <= sizeof(prefix) - 1 || cap <= total)
        return false;
    memcpy(dst, prefix, sizeof(prefix) - 1);
    memset(dst + sizeof(prefix) - 1, 'a', total - (sizeof(prefix) - 1));
    dst[total] = '\0';
    return true;
}

static void test_d02_client_origin_valid_forms_and_limit(int *fp)
{
    int failures = 0;
    static const char *const valid[] = {
        "https://example.com",
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
        "null",
    };

    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        wtq_simpair_t sp;
        failures += run_pair_d02(0xD030 + i, D02,
                                 WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                                 valid[i], &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        wtq_simpair_destroy(&sp);
    }

    char max_origin[WTQ_CONN_ORIGIN_MAX_BYTES + 1];
    WTQ_TEST_CHECK(make_d02_origin_len(max_origin, sizeof(max_origin),
                                       WTQ_CONN_ORIGIN_MAX_BYTES));
    {
        wtq_simpair_t sp;
        failures += run_pair_d02(0xD034, D02,
                                 WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                                 max_origin, &sp);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        wtq_simpair_destroy(&sp);
    }

    /* The next byte fails before opening a stream, and does not poison a
     * valid retry on the same D02-configured engine. */
    {
        char too_long[WTQ_CONN_ORIGIN_MAX_BYTES + 2];
        wtq_simpair_t sp;
        WTQ_TEST_CHECK(make_d02_origin_len(too_long, sizeof(too_long),
                                           WTQ_CONN_ORIGIN_MAX_BYTES + 1));
        WTQ_TEST_CHECK(wtq_simpair_create_profile_set(
            &sp, 0xD035, D02,
            WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT) == 0);
        wtq_server_path_cfg_t path = {
            "/moq", PROF_SUPPORTED, 2, true,
            WTQ_ORIGIN_POLICY_ALLOW_ANY_NON_OPAQUE, NULL, 0,
        };
        WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
        wtq_client_connect_cfg_t bad = {
            "example.com", "/moq", too_long, PROF_OFFER, 2, true, D02,
        };
        const int opens_before = sp.c.drv.open_calls;
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &bad) ==
                       WTQ_ERR_TOO_LARGE);
        WTQ_TEST_CHECK_EQ_INT(sp.c.drv.open_calls, opens_before);
        wtq_client_connect_cfg_t good = {
            "example.com", "/moq", D02_ORIGIN, PROF_OFFER, 2, true, D02,
        };
        WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &good) == WTQ_OK);
        (void)wtq_simpair_run_until_quiescent(&sp, 64);
        WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
        wtq_simpair_destroy(&sp);
    }
    *fp += failures;
}

/* Axis 6 both directions of the cap, on the SAME stream, mutation-free. */
/* The newest local stream the fake driver has, i.e. the one just opened. */
static struct wtq_dstream *newest_local(struct wtq_driver *drv)
{
    struct wtq_dstream *last = NULL;
    for (size_t i = 0; ; i++) {
        struct wtq_dstream *s = fake_driver_local(drv, i);
        if (s == NULL)
            break;
        last = s;
    }
    return last;
}

/*
 * Outbound error-range policy, proved causally against the backend. A
 * return code alone is not evidence: a rejected code must make NO backend
 * call and leave the halves untouched, and an accepted one must make
 * exactly one call with the exact halves and the exact mapped wire code.
 */
static void test_d02_outbound_cap_mutation_free(int *fp)
{
    int failures = 0;
    wtq_simpair_t sp;
    failures += run_pair_d02(0xD02F, D02, WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                             D02_ORIGIN, &sp);
    WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);

    /* RESET: send half only, exact mapped code, zero backend calls when
     * rejected. */
    {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(sp.c.conn, &es) == WTQ_OK);
        struct wtq_dstream *ds = newest_local(&sp.c.drv);
        WTQ_TEST_CHECK(ds != NULL);
        const int before = ds->shutdown_count;
        WTQ_TEST_CHECK(wtq_conn_wt_reset(sp.c.conn, es, 256) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        WTQ_TEST_CHECK(wtq_conn_wt_reset(sp.c.conn, es, UINT32_MAX) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        /* same send half still usable -> the rejects mutated nothing */
        WTQ_TEST_CHECK(wtq_conn_wt_reset(sp.c.conn, es, 255) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before + 1);
        WTQ_TEST_CHECK_EQ_INT((int)ds->last_shutdown.mode,
                              (int)WTQ_SHUTDOWN_EXACT_HALVES);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
        WTQ_TEST_CHECK(!ds->last_shutdown.abort_recv);
        WTQ_TEST_CHECK(ds->last_shutdown.send_err ==
                       wtq_app_error_to_h3(255));
    }
    /* STOP: receive half only, same discipline. */
    {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(sp.c.conn, &es) == WTQ_OK);
        struct wtq_dstream *ds = newest_local(&sp.c.drv);
        WTQ_TEST_CHECK(ds != NULL);
        const int before = ds->shutdown_count;
        WTQ_TEST_CHECK(wtq_conn_wt_stop(sp.c.conn, es, 256) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        WTQ_TEST_CHECK(wtq_conn_wt_stop(sp.c.conn, es, UINT32_MAX) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        WTQ_TEST_CHECK(wtq_conn_wt_stop(sp.c.conn, es, 255) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before + 1);
        WTQ_TEST_CHECK_EQ_INT((int)ds->last_shutdown.mode,
                              (int)WTQ_SHUTDOWN_EXACT_HALVES);
        WTQ_TEST_CHECK(!ds->last_shutdown.abort_send);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_recv);
        WTQ_TEST_CHECK(ds->last_shutdown.recv_err ==
                       wtq_app_error_to_h3(255));
    }
    /* ABORT: whole stream, BOTH halves, identical mapped code. */
    {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(sp.c.conn, &es) == WTQ_OK);
        struct wtq_dstream *ds = newest_local(&sp.c.drv);
        WTQ_TEST_CHECK(ds != NULL);
        const int before = ds->shutdown_count;
        WTQ_TEST_CHECK(wtq_conn_wt_abort(sp.c.conn, es, 256) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        WTQ_TEST_CHECK(wtq_conn_wt_abort(sp.c.conn, es, UINT32_MAX) ==
                       WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before);
        WTQ_TEST_CHECK(wtq_conn_wt_abort(sp.c.conn, es, 255) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, before + 1);
        WTQ_TEST_CHECK_EQ_INT((int)ds->last_shutdown.mode,
                              (int)WTQ_SHUTDOWN_WHOLE_STREAM);
        WTQ_TEST_CHECK(ds->last_shutdown.send_err ==
                       wtq_app_error_to_h3(255));
        WTQ_TEST_CHECK(ds->last_shutdown.recv_err ==
                       ds->last_shutdown.send_err);
    }
    wtq_simpair_destroy(&sp);

    /* CURRENT records the full 32-bit range at the BACKEND, not merely in
     * the return code — so the cap is provably profile-specific. */
    {
        wtq_simpair_t cur;
        failures += run_pair(0xD02F1, (int)WTQ_H3_WT_PROFILE_CURRENT,
                             (int)WTQ_H3_WT_PROFILE_CURRENT, &cur);
        WTQ_TEST_CHECK_EQ_INT(cur.c.established_events, 1);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(cur.c.conn, &es) == WTQ_OK);
        struct wtq_dstream *d1 = newest_local(&cur.c.drv);
        WTQ_TEST_CHECK(wtq_conn_wt_reset(cur.c.conn, es, 256) == WTQ_OK);
        WTQ_TEST_CHECK(d1 != NULL &&
                       d1->last_shutdown.send_err ==
                           wtq_app_error_to_h3(256));
        wtq_estream_t *es2 = NULL;
        WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(cur.c.conn, &es2) == WTQ_OK);
        struct wtq_dstream *d2 = newest_local(&cur.c.drv);
        WTQ_TEST_CHECK(wtq_conn_wt_reset(cur.c.conn, es2, UINT32_MAX) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(d2 != NULL &&
                       d2->last_shutdown.send_err ==
                           wtq_app_error_to_h3(UINT32_MAX));
        wtq_simpair_destroy(&cur);
    }
    /*
     * INBOUND under D02 through the REAL engine path: inject wire codes for
     * 256, 70000 and UINT32_MAX via wtq_conn_on_stream_reset /
     * wtq_conn_on_stop_sending and assert the application callback sees the
     * exact full-width value exactly once. This drives the engine, not the
     * stateless mapper.
     */
    {
        wtq_simpair_t in;
        failures += run_pair_d02(0xD02F2, D02,
                                 WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT,
                                 D02_ORIGIN, &in);
        WTQ_TEST_CHECK_EQ_INT(in.c.established_events, 1);
        const uint32_t wide[] = { 256u, 70000u, UINT32_MAX };
        for (size_t i = 0; i < sizeof(wide) / sizeof(wide[0]); i++) {
            wtq_estream_t *es = NULL;
            WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(in.c.conn, &es) == WTQ_OK);
            const int rb = in.c.wt_reset_events;
            WTQ_TEST_CHECK(wtq_conn_on_stream_reset(
                in.c.conn, es, wtq_app_error_to_h3(wide[i]), 2000) == WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(in.c.wt_reset_events, rb + 1);
            WTQ_TEST_CHECK(in.c.last_wt_reset_code == wide[i]);

            wtq_estream_t *es2 = NULL;
            WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(in.c.conn, &es2) == WTQ_OK);
            const int sb = in.c.wt_stop_events;
            WTQ_TEST_CHECK(wtq_conn_on_stop_sending(
                in.c.conn, es2, wtq_app_error_to_h3(wide[i]), 2000) ==
                WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(in.c.wt_stop_events, sb + 1);
            WTQ_TEST_CHECK(in.c.last_wt_stop_code == wide[i]);
        }
        wtq_simpair_destroy(&in);
    }
    *fp += failures;
}

/*
 * Causal zero-effect discriminator. A failed D02 preflight
 * on an UNSTARTED default engine must leave the profile untouched, proved by
 * the SETTINGS the engine then emits — not by a later call's return code.
 * The earlier version of this test ran on an engine already created AND
 * started as D02, so it would have passed even if the rejected call had
 * assigned D02 early; it could not discriminate the bug it named.
 */
static void test_d02_failed_preflight_leaves_settings_current(int *fp)
{
    int failures = 0;
    const char *const bad_origins[] = {
        "not-an-origin",            /* malformed: no scheme */
        "https://example.com/path", /* malformed: path present */
    };
    for (size_t i = 0; i < sizeof(bad_origins) / sizeof(bad_origins[0]); i++) {
        struct wtq_driver drv;
        wtq_conn_t *conn = NULL;
        fake_driver_init(&drv, true /* client */);
        wtq_conn_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .enable_connect_protocol = true,
        };
        /* default/CURRENT seed, and deliberately NOT started */
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &drv, fake_driver_ops(),
                                       &conn) == WTQ_OK);

        wtq_client_connect_cfg_t d02 = {
            "example.com", "/moq", bad_origins[i], PROF_OFFER, 2, true, D02,
        };
        WTQ_TEST_CHECK(wtq_conn_client_connect(conn, &d02) ==
                       WTQ_ERR_INVALID_ARG);
        /* no driver effect from the rejected call */
        WTQ_TEST_CHECK(fake_driver_local(&drv, 0) == NULL);

        /* start WITHOUT any intervening successful connect */
        WTQ_TEST_CHECK(wtq_conn_start(conn, 1000) == WTQ_OK);
        const struct wtq_dstream *ctrl = fake_driver_local(&drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        /* the emitted SETTINGS must still be CURRENT-only */
        WTQ_TEST_CHECK(ctrl_has(ctrl, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_has(ctrl, ENABLE_WT_ID, sizeof(ENABLE_WT_ID)));
        WTQ_TEST_CHECK(!ctrl_has(ctrl, WT_MAXSESS_ID, sizeof(WT_MAXSESS_ID)));
        wtq_conn_destroy(conn);
    }

    /*
     * And a failed D02 preflight does not block a valid CURRENT connect on
     * that same unstarted default engine.
     */
    {
        struct wtq_driver drv;
        wtq_conn_t *conn = NULL;
        fake_driver_init(&drv, true);
        wtq_conn_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .enable_connect_protocol = true,
        };
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &drv, fake_driver_ops(),
                                       &conn) == WTQ_OK);
        wtq_client_connect_cfg_t d02 = {
            "example.com", "/moq", "bogus", PROF_OFFER, 2, true, D02,
        };
        WTQ_TEST_CHECK(wtq_conn_client_connect(conn, &d02) ==
                       WTQ_ERR_INVALID_ARG);
        wtq_client_connect_cfg_t cur = {
            "example.com", "/moq", NULL, PROF_OFFER, 2, true,
            (int)WTQ_H3_WT_PROFILE_CURRENT,
        };
        WTQ_TEST_CHECK(wtq_conn_client_connect(conn, &cur) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_start(conn, 1000) == WTQ_OK);
        const struct wtq_dstream *ctrl = fake_driver_local(&drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        WTQ_TEST_CHECK(ctrl_has(ctrl, WT_ENABLED_ID, sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_has(ctrl, ENABLE_WT_ID, sizeof(ENABLE_WT_ID)));
        wtq_conn_destroy(conn);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_matched_profiles_establish(&failures);
    test_mismatched_profiles_reject(&failures);
    test_d02_self_pair_establishes(&failures);
    test_d02_selected_from_union(&failures);
    test_d02_cross_profile_mismatches(&failures);
    test_d02_client_origin_preflight_zero_effect(&failures);
    test_d02_client_origin_valid_forms_and_limit(&failures);
    test_d02_outbound_cap_mutation_free(&failures);
    test_d02_failed_preflight_leaves_settings_current(&failures);
    test_multi_server_union_and_latch(&failures);
    test_latch_precedes_callback_and_is_immutable(&failures);
    test_invalid_profile_set_rejected(&failures);

    WTQ_TEST_PASS("test_engine_profile");
    return failures;
}
