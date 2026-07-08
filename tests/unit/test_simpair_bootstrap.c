#include <string.h>

#include "wtq_simpair.h"

#include "test_support.h"

/* both sides bootstrap to "peer settings received, WT supported" */
static void test_pair_bootstrap(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, 0x1234) == 0);
    size_t steps = wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK(steps > 0 && steps < 32);

    WTQ_TEST_CHECK_EQ_INT(sp.c.settings_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.settings_events, 1);
    WTQ_TEST_CHECK(sp.c.wt_supported);
    WTQ_TEST_CHECK(sp.s.wt_supported);
    WTQ_TEST_CHECK_EQ_INT(sp.c.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 0);
    WTQ_TEST_CHECK(wtq_conn_peer_supports_wt(sp.c.conn));
    WTQ_TEST_CHECK(wtq_conn_peer_supports_wt(sp.s.conn));
    WTQ_TEST_CHECK(!sp.trace_overflow);
    WTQ_TEST_CHECK(sp.trace_len > 0);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);

    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* same seed twice: byte-identical trace, identical hash */
static void test_same_seed_same_trace(int *fp)
{
    int failures = 0;
    static wtq_simpair_t a;
    static wtq_simpair_t b;

    WTQ_TEST_CHECK(wtq_simpair_create(&a, 0xBEEF) == 0);
    WTQ_TEST_CHECK(wtq_simpair_create(&b, 0xBEEF) == 0);
    (void)wtq_simpair_run_until_quiescent(&a, 32);
    (void)wtq_simpair_run_until_quiescent(&b, 32);

    WTQ_TEST_CHECK_EQ_SIZE(a.trace_len, b.trace_len);
    WTQ_TEST_CHECK(memcmp(a.trace, b.trace, a.trace_len) == 0);
    WTQ_TEST_CHECK_EQ_HEX(wtq_simpair_trace_hash(&a),
                          wtq_simpair_trace_hash(&b));

    wtq_simpair_destroy(&a);
    wtq_simpair_destroy(&b);
    *fp += failures;
}

/* different seeds: traces may differ, semantic end state must match */
static void test_seed_independence(int *fp)
{
    int failures = 0;
    uint64_t hashes[4];
    const uint64_t seeds[4] = { 1, 2, 0xDEAD, 0xFFFFFFFFFFFFULL };

    for (size_t i = 0; i < 4; i++) {
        static wtq_simpair_t sp;
        WTQ_TEST_CHECK(wtq_simpair_create(&sp, seeds[i]) == 0);
        (void)wtq_simpair_run_until_quiescent(&sp, 32);
        WTQ_TEST_CHECK_EQ_INT(sp.c.settings_events, 1);
        WTQ_TEST_CHECK_EQ_INT(sp.s.settings_events, 1);
        WTQ_TEST_CHECK(sp.c.wt_supported && sp.s.wt_supported);
        WTQ_TEST_CHECK_EQ_INT(sp.c.error_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 0);
        WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
        hashes[i] = wtq_simpair_trace_hash(&sp);
        wtq_simpair_destroy(&sp);
    }
    /* at least two of the traces should differ (different chunking) —
     * not a hard protocol property, but if ALL seeds produce identical
     * traces the seeding is inert and the harness is lying */
    bool any_diff = false;
    for (size_t i = 1; i < 4; i++)
        if (hashes[i] != hashes[0])
            any_diff = true;
    WTQ_TEST_CHECK(any_diff);

    *fp += failures;
}

static void test_pair_connect(int *fp);
static void test_pair_full_session(int *fp);
static void test_pair_dgram_malformed(int *fp);
static void test_pair_reset_stop_propagation(int *fp);
static void test_pair_detach_mid_pass(int *fp);
static void test_pair_peer_pool_rejection(int *fp);

int main(void)
{
    int failures = 0;

    test_pair_bootstrap(&failures);
    test_same_seed_same_trace(&failures);
    test_seed_independence(&failures);
    test_pair_connect(&failures);
    test_pair_full_session(&failures);
    test_pair_dgram_malformed(&failures);
    test_pair_reset_stop_propagation(&failures);
    test_pair_detach_mid_pass(&failures);
    test_pair_peer_pool_rejection(&failures);

    WTQ_TEST_PASS("test_simpair_bootstrap");
    return failures;
}

/* NOTE: full scenarios live in this binary to share the rig. */

static const char *const SIM_OFFER[] = { "moqt-18", "moqt-16" };
static const char *const SIM_SUPPORTED[] = { "moqt-16", "moqt-18" };

/* full CONNECT establishment through the pair, with the deferred-send
 * proof: no CONNECT bytes exist before server SETTINGS are delivered */
static int scenario_connect(uint64_t seed, uint64_t *hash_out)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, seed) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);

    /* deferred: before any delivery, the client has no bidi stream */
    bool bidi_before = false;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (sp.c.drv.streams[i].in_use && sp.c.drv.streams[i].is_local &&
            sp.c.drv.streams[i].is_bidi)
            bidi_before = true;
    WTQ_TEST_CHECK(!bidi_before);

    size_t steps = wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK(steps > 0 && steps < 64);

    WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(sp.c.selected_len, 7);
    WTQ_TEST_CHECK_EQ_SIZE(sp.s.selected_len, 7);
    WTQ_TEST_CHECK(memcmp(sp.c.selected, "moqt-18", 7) == 0);
    WTQ_TEST_CHECK(memcmp(sp.s.selected, "moqt-18", 7) == 0);
    WTQ_TEST_CHECK_EQ_INT(sp.c.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
    WTQ_TEST_CHECK(wtq_conn_session_established(sp.c.conn));
    WTQ_TEST_CHECK(wtq_conn_session_established(sp.s.conn));

    if (hash_out != NULL)
        *hash_out = wtq_simpair_trace_hash(&sp);
    wtq_simpair_destroy(&sp);
    return failures;
}

static void test_pair_connect(int *fp)
{
    uint64_t h1 = 0;
    uint64_t h2 = 0;
    int failures = 0;

    failures += scenario_connect(0xC0FFEE, &h1);
    failures += scenario_connect(0xC0FFEE, &h2);
    WTQ_TEST_CHECK_EQ_HEX(h1, h2); /* same seed, identical trace */
    failures += scenario_connect(0x1CEB00DA, NULL); /* other seed */

    *fp += failures;
}

/* A malformed datagram on the wire must not vanish from the rail:
 * the receiving engine closes the connection (H3_DATAGRAM_ERROR) and
 * the simpair records the non-OK engine-input return. */
static void test_pair_dgram_malformed(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, 0xBAD) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);

    /* poke a truncated-varint datagram into the client's wire log */
    sp.c.drv.dgrams[sp.c.drv.dgram_count].bytes[0] = 0x40;
    sp.c.drv.dgrams[sp.c.drv.dgram_count].len = 1;
    sp.c.drv.dgram_count++;
    (void)wtq_simpair_run_until_quiescent(&sp, 8);

    WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 1);
    WTQ_TEST_CHECK_EQ_HEX(sp.s.last_error, 0x33);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 1);

    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* One whole session lifetime through the pair: establish, server
 * DRAIN, client WT bidi with a server echo, client WT uni one-way,
 * CLOSE capsule with byte-exact code/reason on the far side. The
 * semantic end state must hold on EVERY seed; the trace hash must be
 * identical for the same seed. */
static int scenario_full_session(uint64_t seed, uint64_t *hash_out)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, seed) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.c.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);

    /* the server asks for a graceful shutdown; traffic continues */
    WTQ_TEST_CHECK(wtq_simpair_session_drain(&sp, 's') == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_INT(sp.c.draining_events, 1);

    /* client bidi: ping over, pong back */
    wtq_estream_t *cb = NULL;
    WTQ_TEST_CHECK(wtq_simpair_wt_open(&sp, 'c', true, &cb) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 'c', cb, "ping", 4, false) ==
                   WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_opened_events, 1);
    WTQ_TEST_CHECK(sp.s.wt_last_bidi);
    WTQ_TEST_CHECK_EQ_SIZE(sp.s.wt_data_len, 4);
    WTQ_TEST_CHECK(memcmp(sp.s.wt_data, "ping", 4) == 0);
    WTQ_TEST_CHECK_EQ_INT(sp.c.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.c.send_cancels, 0);

    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 's', sp.s.wt_last_es, "pong",
                                       4, false) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_SIZE(sp.c.wt_data_len, 4);
    WTQ_TEST_CHECK(memcmp(sp.c.wt_data, "pong", 4) == 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.send_completions, 1);

    /* client uni: one-way payload with FIN */
    wtq_estream_t *cu = NULL;
    WTQ_TEST_CHECK(wtq_simpair_wt_open(&sp, 'c', false, &cu) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 'c', cu, "uni!", 4, true) ==
                   WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_opened_events, 2);
    WTQ_TEST_CHECK_EQ_SIZE(sp.s.wt_data_len, 8);
    WTQ_TEST_CHECK(memcmp(sp.s.wt_data, "pinguni!", 8) == 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_fin_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.c.send_completions, 2);

    /* datagrams flow both ways (the server is DRAINING: s4.7 says
     * traffic continues) */
    WTQ_TEST_CHECK(wtq_simpair_dgram_send(&sp, 'c', "dg-up", 5) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_dgram_send(&sp, 's', "dg-dn", 5) ==
                   WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_INT(sp.s.dgram_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(sp.s.dgram_data_len, 5);
    WTQ_TEST_CHECK(memcmp(sp.s.dgram_data, "dg-up", 5) == 0);
    WTQ_TEST_CHECK_EQ_INT(sp.c.dgram_events, 1);
    WTQ_TEST_CHECK(memcmp(sp.c.dgram_data, "dg-dn", 5) == 0);

    /* client closes the session; the far side sees the exact bytes */
    WTQ_TEST_CHECK(wtq_simpair_session_close(&sp, 'c', 7, "done") ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(sp.c.closed_events, 1);
    WTQ_TEST_CHECK(sp.c.closed_clean);
    (void)wtq_simpair_run_until_quiescent(&sp, 32);
    WTQ_TEST_CHECK_EQ_INT(sp.s.closed_events, 1);
    WTQ_TEST_CHECK(sp.s.closed_code == 7);
    WTQ_TEST_CHECK_EQ_SIZE(sp.s.closed_reason_len, 4);
    WTQ_TEST_CHECK(memcmp(sp.s.closed_reason, "done", 4) == 0);
    WTQ_TEST_CHECK(sp.s.closed_clean);

    /* after termination: sends refuse (s6 MUST NOT), and a late
     * inbound datagram for the dead session drops quietly */
    WTQ_TEST_CHECK(wtq_simpair_dgram_send(&sp, 'c', "late", 4) ==
                   WTQ_ERR_CLOSED);
    uint8_t late_dg[3] = { 0x00, 'z', 'z' };
    WTQ_TEST_CHECK(wtq_conn_on_datagram(sp.c.conn, late_dg, 3,
                                        999000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(sp.c.dgram_events, 1);
    WTQ_TEST_CHECK(wtq_conn_dgrams_dropped(sp.c.conn) == 1);

    WTQ_TEST_CHECK_EQ_INT(sp.c.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
    WTQ_TEST_CHECK(!sp.trace_overflow);

    if (hash_out != NULL)
        *hash_out = wtq_simpair_trace_hash(&sp);
    wtq_simpair_destroy(&sp);
    return failures;
}

static void test_pair_full_session(int *fp)
{
    uint64_t h1 = 0;
    uint64_t h2 = 0;
    int failures = 0;

    failures += scenario_full_session(0xD00DFEED, &h1);
    failures += scenario_full_session(0xD00DFEED, &h2);
    WTQ_TEST_CHECK_EQ_HEX(h1, h2); /* same seed, identical trace */
    /* different seeds: different chunking, same semantic end state */
    failures += scenario_full_session(0x5EEDFACE, NULL);
    failures += scenario_full_session(0xA5A5A5A5, NULL);

    *fp += failures;
}

/* Reset and STOP_SENDING cross the deterministic rail exactly once:
 * a client-side reset surfaces one on_wt_stream_reset at the server;
 * a server-side stop surfaces one on_wt_stream_stop at the client —
 * and extra steps deliver neither again. */
static void test_pair_reset_stop_propagation(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, 0xC10500) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);

    /* stream 1: client opens, sends, then resets its send side */
    wtq_estream_t *c_es = NULL;
    WTQ_TEST_CHECK(wtq_simpair_wt_open(&sp, 'c', false, &c_es) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 'c', c_es, "hi", 2, false) ==
                   WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_opened_events, 1);
    WTQ_TEST_CHECK(wtq_conn_wt_reset(sp.c.conn, c_es, 77) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_reset_events, 1);

    /* stream 2: client opens and sends; the server stops reading */
    wtq_estream_t *c_es2 = NULL;
    WTQ_TEST_CHECK(wtq_simpair_wt_open(&sp, 'c', false, &c_es2) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 'c', c_es2, "yo", 2,
                                       false) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_opened_events, 2);
    wtq_estream_t *s_es2 = sp.s.wt_last_es;
    WTQ_TEST_CHECK(s_es2 != NULL);
    WTQ_TEST_CHECK(wtq_conn_wt_stop(sp.s.conn, s_es2, 9) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.c.wt_stop_events, 1);

    /* exactly once: further steps re-deliver neither */
    (void)wtq_simpair_step(&sp);
    (void)wtq_simpair_step(&sp);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_reset_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.c.wt_stop_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);

    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* Detachment mid-pump-pass: the client's CLOSE capsule arrives with
 * garbage queued behind it on the same stream. The chunk that lands
 * after CLOSE poisons the session stream, which RELEASES (detaches)
 * the receiving estream — the still-queued chunks in the SAME pump
 * pass must then reach nobody: no invalid engine call, no stale-slot
 * delivery, exactly one terminal. */
static void test_pair_detach_mid_pass(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, 0xDE7AC4) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);

    /* the client closes; then poke garbage into its session-stream
     * wire log BEHIND the CLOSE capsule, before anything delivers —
     * more than three max-size chunks' worth */
    WTQ_TEST_CHECK(wtq_simpair_session_close(&sp, 'c', 0, NULL) ==
                   WTQ_OK);
    struct wtq_dstream *wire = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (sp.c.drv.streams[i].in_use && sp.c.drv.streams[i].is_local &&
            sp.c.drv.streams[i].is_bidi)
            wire = &sp.c.drv.streams[i];
    WTQ_TEST_CHECK(wire != NULL && wire->delivered < wire->len);
    if (wire == NULL) {
        wtq_simpair_destroy(&sp);
        *fp += failures + 1;
        return;
    }
    for (size_t i = 0; i < 24; i++)
        wire->bytes[wire->len + i] = 0xFF;
    wire->len += 24;

    (void)wtq_simpair_run_until_quiescent(&sp, 64);

    WTQ_TEST_CHECK_EQ_INT(sp.s.closed_events, 1); /* exactly once */
    WTQ_TEST_CHECK(sp.s.closed_clean);
    WTQ_TEST_CHECK_EQ_INT(sp.c.closed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.s.error_events, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.c.error_events, 0);

    /* nothing re-delivers on further steps */
    (void)wtq_simpair_step(&sp);
    (void)wtq_simpair_step(&sp);
    WTQ_TEST_CHECK_EQ_INT(sp.s.closed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 0);

    wtq_simpair_destroy(&sp);
    *fp += failures;
}

/* A peer stream the server engine cannot hold is rejected on the wire,
 * and the deterministic rail carries that rejection back to the opener
 * exactly once: the client sees a terminal stream event instead of
 * hanging on a silently blackholed stream. */
static void test_pair_peer_pool_rejection(int *fp)
{
    int failures = 0;
    static wtq_simpair_t sp;

    WTQ_TEST_CHECK(wtq_simpair_create(&sp, 0xC0FFEE) == 0);
    wtq_server_path_cfg_t path = { "/moq", SIM_SUPPORTED, 2, true };
    WTQ_TEST_CHECK(wtq_simpair_server_paths(&sp, &path, 1) == WTQ_OK);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, SIM_OFFER, 2, true, 0,
    };
    WTQ_TEST_CHECK(wtq_simpair_client_connect(&sp, &ccfg) == WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);
    WTQ_TEST_CHECK_EQ_INT(sp.s.established_events, 1);

    /* Occupy every remaining server slot with streams that never reach
     * the rail (no twin), simulating other traffic holding the pool. */
    size_t filled = 0;
    for (uint64_t i = 0; i < 64; i++) {
        uint64_t id = 1000 + 4 * i;
        struct wtq_dstream *ds =
            fake_driver_add_peer_stream(&sp.s.drv, id);
        wtq_estream_t *es = NULL;
        if (ds == NULL ||
            wtq_conn_on_peer_uni_opened(sp.s.conn, ds, id, &es) != WTQ_OK)
            break;
        ds->ectx = es;
        filled++;
    }
    WTQ_TEST_CHECK(filled > 0);

    /* the client opens a legitimate WT stream into the full pool */
    wtq_estream_t *c_es = NULL;
    WTQ_TEST_CHECK(wtq_simpair_wt_open(&sp, 'c', false, &c_es) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_simpair_wt_send(&sp, 'c', c_es, "hi", 2, false) ==
                   WTQ_OK);
    (void)wtq_simpair_run_until_quiescent(&sp, 64);

    /* the opener was told, exactly once, and nothing hangs */
    WTQ_TEST_CHECK_EQ_INT(sp.c.wt_stop_events, 1);
    WTQ_TEST_CHECK_EQ_INT(sp.s.wt_opened_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(sp.c.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(sp.s.conn));
    WTQ_TEST_CHECK_EQ_INT(sp.engine_errors, 1); /* the STREAM_LIMIT */

    (void)wtq_simpair_step(&sp);
    (void)wtq_simpair_step(&sp);
    WTQ_TEST_CHECK_EQ_INT(sp.c.wt_stop_events, 1);

    wtq_simpair_destroy(&sp);
    *fp += failures;
}
