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
    wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true };
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
    wtq_server_path_cfg_t path = { "/moq", PROF_SUPPORTED, 2, true };
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

int main(void)
{
    int failures = 0;

    test_matched_profiles_establish(&failures);
    test_mismatched_profiles_reject(&failures);
    test_multi_server_union_and_latch(&failures);
    test_latch_precedes_callback_and_is_immutable(&failures);
    test_invalid_profile_set_rejected(&failures);

    WTQ_TEST_PASS("test_engine_profile");
    return failures;
}
