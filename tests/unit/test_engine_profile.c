/*
 * End-to-end WebTransport wire-profile symmetry over the deterministic engine
 * pair. Each side latches a profile (current draft-16 vs D13/14 compat); a
 * matched pair establishes, a mismatched pair does not — the client rejects
 * the peer's SETTINGS as no-WT-support before it ever sends a CONNECT, because
 * one profile's WT signal never satisfies the other's predicate.
 */

#include <stdio.h>
#include <string.h>

#include "wt_driver.h"

#include "proto/h3_settings.h"

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
    /* The client re-latches its profile here; it must match the profile it
     * was created with so the CONNECT token matches its emitted SETTINGS. */
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, PROF_OFFER, 2, true, c_prof,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(sp, 64);
    return failures;
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

    WTQ_TEST_PASS("test_engine_profile");
    return failures;
}
