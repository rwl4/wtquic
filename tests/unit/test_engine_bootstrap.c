#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/h3_err.h"
#include "proto/h3_settings.h"

#include "test_support.h"

/* Test app callbacks record what the engine reports. */
typedef struct app_state {
    int settings_events;
    bool wt_supported;
    int error_events;
    uint64_t last_error;
} app_state_t;

static void on_peer_settings(wtq_conn_t *conn, bool wt_supported,
                             void *ctx)
{
    app_state_t *st = ctx;

    (void)conn;
    st->settings_events++;
    st->wt_supported = wt_supported;
}

static void on_conn_error(wtq_conn_t *conn, uint64_t h3_err, void *ctx)
{
    app_state_t *st = ctx;

    (void)conn;
    st->error_events++;
    st->last_error = h3_err;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    app_state_t app;
} rig_t;

static void rig_up(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    fake_driver_init(&r->drv, persp == WTQ_PERSPECTIVE_CLIENT);

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = persp,
        .enable_connect_protocol = true,
        .callbacks = { .on_peer_settings = on_peer_settings,
                       .on_conn_error = on_conn_error,
                       .ctx = &r->app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r->drv, fake_driver_ops(),
                                   &r->conn) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r->conn, 1000) == WTQ_OK);
    *fp += failures;
}

static void rig_down(rig_t *r)
{
    wtq_conn_destroy(r->conn);
}

/* Build a peer control stream: [0x00 type][SETTINGS frame]. */
static size_t build_peer_control(uint8_t *dst, size_t cap, bool ecp,
                                 bool legacy)
{
    wtq_h3_settings_encode_cfg_t cfg = { ecp, legacy };
    size_t flen = 0;

    dst[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&cfg, dst + 1, cap - 1, &flen) != 0)
        return 0;
    return 1 + flen;
}

/* Feed bytes to a fresh peer uni stream in fixed-size chunks. */
static wtq_estream_t *open_peer(rig_t *r, uint64_t id, int *fp)
{
    int failures = 0;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, id);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(ds != NULL);
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, ds, id, &es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(es != NULL);
    *fp += failures;
    return es;
}

static void feed(rig_t *r, wtq_estream_t *es, const uint8_t *bytes,
                 size_t len, size_t chunk, bool fin)
{
    size_t off = 0;

    while (off < len) {
        size_t nn = len - off < chunk ? len - off : chunk;
        bool last = (off + nn == len);
        (void)wtq_conn_on_stream_bytes(r->conn, es, bytes + off, nn,
                                       fin && last, 2000);
        off += nn;
    }
    if (len == 0)
        (void)wtq_conn_on_stream_bytes(r->conn, es, NULL, 0, fin, 2000);
}

/* client bootstrap: local streams + peer settings + support flags */
static void test_bootstrap_happy(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);

    /* local control stream: type 0x00 + our SETTINGS frame */
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
    struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
    WTQ_TEST_CHECK(ctrl != NULL && ctrl->len > 2);
    WTQ_TEST_CHECK(ctrl->bytes[0] == 0x00);
    WTQ_TEST_CHECK(ctrl->bytes[1] == 0x04); /* SETTINGS frame type */
    WTQ_TEST_CHECK(!ctrl->fin);
    struct wtq_dstream *enc = fake_driver_local(&r.drv, 1);
    struct wtq_dstream *dec = fake_driver_local(&r.drv, 2);
    WTQ_TEST_CHECK(enc != NULL && enc->len == 1 && enc->bytes[0] == 0x02);
    WTQ_TEST_CHECK(dec != NULL && dec->len == 1 && dec->bytes[0] == 0x03);

    /* deliver a server peer control stream */
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    WTQ_TEST_CHECK(plen > 0);
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, peer, plen, 64, false);

    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    WTQ_TEST_CHECK(r.app.wt_supported);
    WTQ_TEST_CHECK(wtq_conn_peer_settings_received(r.conn));
    WTQ_TEST_CHECK(wtq_conn_peer_supports_wt(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(wtq_conn_peer_settings(r.conn)->has_wt_enabled);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    rig_down(&r);
    *fp += failures;
}

/* SETTINGS split across every byte boundary still lands */
static void test_split_settings(int *fp)
{
    int failures = 0;
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);

    WTQ_TEST_CHECK(plen > 0);
    for (size_t chunk = 1; chunk <= plen; chunk++) {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, peer, plen, chunk, false);
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
        WTQ_TEST_CHECK(r.app.wt_supported);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* a server engine evaluates a client peer (no ECP required) */
static void test_server_side(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), false, false);
    wtq_estream_t *es = open_peer(&r, 2, fp);
    feed(&r, es, peer, plen, 1, false);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    WTQ_TEST_CHECK(r.app.wt_supported);
    rig_down(&r);
    *fp += failures;
}

/* SERVER DEFERRAL: a server opens NO local streams at start — its
 * control/QPACK streams depart only after the peer's first inbound
 * event, so they can never race the client transport's readiness (the
 * measured Network.framework pending-stream drop). Exactly once. */
static void test_server_defers_locals(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);

    /* start: attempted and latched, but nothing on the wire */
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 0);
    WTQ_TEST_CHECK(wtq_conn_start(r.conn, 1500) == WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 0);

    /* the peer's first inbound event opens our locals, BEFORE the
     * peer's stream is processed */
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), false, false);
    wtq_estream_t *es = open_peer(&r, 2, fp);
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
    struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
    WTQ_TEST_CHECK(ctrl != NULL && ctrl->len > 2);
    WTQ_TEST_CHECK(ctrl->bytes[0] == 0x00);
    WTQ_TEST_CHECK(ctrl->bytes[1] == 0x04); /* SETTINGS frame type */

    /* exactly once: further inbound events do not re-open */
    feed(&r, es, peer, plen, 64, false);
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    rig_down(&r);
    *fp += failures;
}

/* Deferred bootstrap fires on the FIRST inbound event of EVERY kind —
 * uni, bidi, and datagram — exactly once, before the peer's event is
 * processed. */
static void test_server_defer_triggers(int *fp)
{
    int failures = 0;

    /* first inbound = peer BIDI stream */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 0);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 0);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0, &es) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(es != NULL);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
        /* exactly once: a second inbound does not re-open */
        struct wtq_dstream *ds2 = fake_driver_add_peer_stream(&r.drv, 4);
        wtq_estream_t *es2 = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds2, 4, &es2) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
        rig_down(&r);
    }
    /* first inbound = DATAGRAM */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 0);
        static const uint8_t dg[] = { 0x40, 0x41, 0x42 };
        (void)wtq_conn_on_datagram(r.conn, dg, sizeof(dg), 2000);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, 3);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* A deferred bootstrap that FAILS is connection-fatal, exactly once:
 * H3_INTERNAL_ERROR as the one terminal outcome, the triggering peer
 * event never processed, and the verdict stable across all SIX driver
 * boundaries (open ctrl / send SETTINGS / open enc / send enc preface /
 * open dec / send dec preface). */
static void test_server_defer_failure_fatal(int *fp)
{
    int failures = 0;

    /* boundaries by call index: opens are calls 1..3, sends 1..3 */
    static const struct { int open_at; int send_at; } fault[6] = {
        { 1, 0 }, /* open control            */
        { 0, 1 }, /* send SETTINGS           */
        { 2, 0 }, /* open QPACK encoder      */
        { 0, 2 }, /* send encoder preface    */
        { 3, 0 }, /* open QPACK decoder      */
        { 0, 3 }, /* send decoder preface    */
    };
    for (int b = 0; b < 6; b++) {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        r.drv.fail_open_at = fault[b].open_at;
        r.drv.fail_send_at = fault[b].send_at;

        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 2);
        wtq_estream_t *es = NULL;
        wtq_result_t rc = wtq_conn_on_peer_uni_opened(r.conn, ds, 2, &es);

        /* fatal, exactly once, triggering event NOT processed */
        WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_ERR_CLOSED);
        WTQ_TEST_CHECK(es == NULL);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);
        WTQ_TEST_CHECK_EQ_U64(r.app.last_error, WTQ_H3_INTERNAL_ERROR);
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 0);

        /* the terminal outcome is stable: later inbound events change
         * nothing (no second error, no late bootstrap) */
        r.drv.fail_open_at = 0;
        r.drv.fail_send_at = 0;
        struct wtq_dstream *ds2 = fake_driver_add_peer_stream(&r.drv, 6);
        wtq_estream_t *es2 = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds2, 6, &es2) ==
                       WTQ_ERR_CLOSED);
        WTQ_TEST_CHECK(es2 == NULL);
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);

        rig_down(&r);
    }
    *fp += failures;
}

/* multi-byte uni stream type varint split across deliveries drains */
static void test_unknown_uni_drained(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);

    /* grease type 0x9f (2-byte varint {0x40,0x9f}) + junk + FIN,
     * delivered one byte at a time */
    const uint8_t junk[] = { 0x40, 0x9f, 0xde, 0xad, 0xbe, 0xef };
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, junk, sizeof(junk), 1, true);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    /* the real control stream still works afterwards */
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    wtq_estream_t *es2 = open_peer(&r, 7, fp);
    feed(&r, es2, peer, plen, 3, false);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* error matrix: each condition must close with the exact H3 code */
static void expect_error(const uint8_t *stream_bytes, size_t len,
                         bool fin, uint64_t expect_code, int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, stream_bytes, len, 7, fin);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn), expect_code);
    WTQ_TEST_CHECK_EQ_HEX(r.drv.close_err, expect_code);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 0);
    rig_down(&r);
    *fp += failures;
}

static void test_error_matrix(int *fp)
{
    /* reserved H2 setting id inside SETTINGS -> SETTINGS_ERROR */
    const uint8_t reserved[] = { 0x00, 0x04, 0x02, 0x02, 0x00 };
    expect_error(reserved, sizeof(reserved), false, WTQ_H3_SETTINGS_ERROR,
                 fp);

    /* duplicate setting id -> SETTINGS_ERROR */
    const uint8_t dup[] = { 0x00, 0x04, 0x04, 0x33, 0x01, 0x33, 0x01 };
    expect_error(dup, sizeof(dup), false, WTQ_H3_SETTINGS_ERROR, fp);

    /* SETTINGS frame ending mid-pair -> FRAME_ERROR */
    const uint8_t midpair[] = { 0x00, 0x04, 0x01, 0x33 };
    expect_error(midpair, sizeof(midpair), false, WTQ_H3_FRAME_ERROR, fp);

    /* DATA frame before SETTINGS -> MISSING_SETTINGS */
    const uint8_t data_first[] = { 0x00, 0x00, 0x00 };
    expect_error(data_first, sizeof(data_first), false,
                 WTQ_H3_MISSING_SETTINGS, fp);

    /* HEADERS before SETTINGS -> MISSING_SETTINGS */
    const uint8_t hdr_first[] = { 0x00, 0x01, 0x01, 0xAA };
    expect_error(hdr_first, sizeof(hdr_first), false,
                 WTQ_H3_MISSING_SETTINGS, fp);

    /* control stream FIN -> CLOSED_CRITICAL_STREAM */
    const uint8_t just_type[] = { 0x00 };
    expect_error(just_type, sizeof(just_type), true,
                 WTQ_H3_CLOSED_CRITICAL_STREAM, fp);
}

/* second SETTINGS frame -> FRAME_UNEXPECTED (RFC 9114; h3zero agrees) */
static void test_second_settings(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    uint8_t peer[256];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    /* append a second SETTINGS frame (empty) */
    peer[plen++] = 0x04;
    peer[plen++] = 0x00;
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, peer, plen, 5, false);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1); /* first was fine */
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_FRAME_UNEXPECTED);
    rig_down(&r);
    *fp += failures;
}

/* duplicate control stream -> STREAM_CREATION_ERROR */
static void test_duplicate_control(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, peer, plen, 64, false);
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);

    /* a second stream announcing type 0x00 */
    const uint8_t ctrl2[] = { 0x00 };
    wtq_estream_t *es2 = open_peer(&r, 7, fp);
    feed(&r, es2, ctrl2, sizeof(ctrl2), 1, false);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_STREAM_CREATION_ERROR);
    rig_down(&r);
    *fp += failures;
}

/* a well-formed GOAWAY and a grease extension frame after SETTINGS
 * leave the connection healthy */
static void test_other_control_frames_skipped(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    uint8_t peer[256];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    /* GOAWAY frame (type 0x07, len 1, id 0) then a grease frame */
    peer[plen++] = 0x07;
    peer[plen++] = 0x01;
    peer[plen++] = 0x00;
    peer[plen++] = 0x21;
    peer[plen++] = 0x02;
    peer[plen++] = 0xAA;
    peer[plen++] = 0xBB;
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, peer, plen, 3, false);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* control stream reset -> CLOSED_CRITICAL_STREAM */
static void test_control_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    uint8_t peer[128];
    size_t plen = build_peer_control(peer, sizeof(peer), true, false);
    wtq_estream_t *es = open_peer(&r, 3, fp);
    feed(&r, es, peer, plen, 64, false);
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, es, 0, 3000) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_CLOSED_CRITICAL_STREAM);
    rig_down(&r);
    *fp += failures;
}

/* forbidden control-stream frames after SETTINGS -> FRAME_UNEXPECTED
 * (RFC 9114 Table 1: DATA/HEADERS/PUSH_PROMISE not allowed on control;
 * s7.2.8: types 0x02/0x06/0x08/0x09 are reserved and are errors) */
static void test_forbidden_control_frames(int *fp)
{
    int failures = 0;
    static const uint8_t forbidden_types[] = { 0x00, 0x01, 0x05, 0x02,
                                               0x06, 0x08, 0x09 };

    for (size_t i = 0; i < sizeof(forbidden_types); i++) {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        uint8_t peer[256];
        size_t plen = build_peer_control(peer, sizeof(peer), true, false);
        peer[plen++] = forbidden_types[i];
        peer[plen++] = 0x01; /* length 1 */
        peer[plen++] = 0xAA;
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, peer, plen, 9, false);
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_UNEXPECTED);
        rig_down(&r);
    }

    /* frames that remain healthy: a well-formed GOAWAY and opaque
     * grease extension frames (known push-control frames are NOT
     * grease — see test_known_control_frames) */
    static const uint8_t allowed_types[] = { 0x07, 0x21 };
    for (size_t i = 0; i < sizeof(allowed_types); i++) {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        uint8_t peer[256];
        size_t plen = build_peer_control(peer, sizeof(peer), true, false);
        peer[plen++] = allowed_types[i];
        peer[plen++] = 0x01;
        peer[plen++] = 0x00;
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, peer, plen, 9, false);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* known control frames carry defined one-varint payloads and must be
 * validated, never grease-skipped (RFC 9114 s7.2.3/6/7, s10.8) */
static void test_known_control_frames(int *fp)
{
    int failures = 0;

    /* helper: run one appended frame on a given perspective */
#define KNOWN_FRAME_CASE(persp, frame_bytes, expect_closed, expect_code) \
    do { \
        rig_t r; \
        rig_up(&r, (persp), fp); \
        uint8_t peer[256]; \
        size_t plen = build_peer_control(peer, sizeof(peer), true, \
                                         false); \
        memcpy(peer + plen, (frame_bytes), sizeof(frame_bytes)); \
        plen += sizeof(frame_bytes); \
        wtq_estream_t *es = open_peer( \
            &r, (persp) == WTQ_PERSPECTIVE_CLIENT ? 3 : 2, fp); \
        feed(&r, es, peer, plen, 5, false); \
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn) == (expect_closed)); \
        if (expect_closed) \
            WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn), \
                                  (expect_code)); \
        rig_down(&r); \
    } while (0)

    /* GOAWAY: exactly one varint. Valid forms stay healthy (semantics
     * deferred); layout violations are FRAME_ERROR. */
    const uint8_t goaway_2byte[] = { 0x07, 0x02, 0x40, 0x04 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, goaway_2byte, false, 0);
    const uint8_t goaway_two_varints[] = { 0x07, 0x02, 0x00, 0x00 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, goaway_two_varints, true,
                     WTQ_H3_FRAME_ERROR);
    const uint8_t goaway_trunc_varint[] = { 0x07, 0x01, 0x40 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, goaway_trunc_varint, true,
                     WTQ_H3_FRAME_ERROR);
    const uint8_t goaway_empty[] = { 0x07, 0x00 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, goaway_empty, true,
                     WTQ_H3_FRAME_ERROR);
    const uint8_t goaway_overlong[] = { 0x07, 0x09, 0xc0, 0, 0, 0, 0, 0,
                                        0, 0, 0 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, goaway_overlong, true,
                     WTQ_H3_FRAME_ERROR);

    /* CANCEL_PUSH: well-formed cancels reference a push that cannot
     * exist (wtquic never pushes or accepts pushes) -> ID_ERROR;
     * malformed payload -> FRAME_ERROR. Both perspectives. */
    const uint8_t cancel_ok[] = { 0x03, 0x01, 0x00 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, cancel_ok, true,
                     WTQ_H3_ID_ERROR);
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_SERVER, cancel_ok, true,
                     WTQ_H3_ID_ERROR);
    const uint8_t cancel_bad[] = { 0x03, 0x02, 0x00, 0x00 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, cancel_bad, true,
                     WTQ_H3_FRAME_ERROR);

    /* MAX_PUSH_ID: a client must never receive it (s7.2.7); a server
     * validates and ignores it; malformed payload -> FRAME_ERROR. */
    const uint8_t maxpush_ok[] = { 0x0d, 0x01, 0x07 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_CLIENT, maxpush_ok, true,
                     WTQ_H3_FRAME_UNEXPECTED);
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_SERVER, maxpush_ok, false, 0);
    const uint8_t maxpush_empty[] = { 0x0d, 0x00 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_SERVER, maxpush_empty, true,
                     WTQ_H3_FRAME_ERROR);

    /* MAX_PUSH_ID monotonicity (RFC 9114 s7.2.7): equal or growing
     * values are fine; a reduction is H3_ID_ERROR. */
    const uint8_t maxpush_grow_eq[] = { 0x0d, 0x01, 0x05,
                                        0x0d, 0x01, 0x07,
                                        0x0d, 0x01, 0x07 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_SERVER, maxpush_grow_eq, false, 0);
    const uint8_t maxpush_shrink[] = { 0x0d, 0x01, 0x07,
                                       0x0d, 0x01, 0x03 };
    KNOWN_FRAME_CASE(WTQ_PERSPECTIVE_SERVER, maxpush_shrink, true,
                     WTQ_H3_ID_ERROR);

#undef KNOWN_FRAME_CASE
    *fp += failures;
}

/* push stream (type 0x01): server -> STREAM_CREATION_ERROR (clients
 * cannot push); client that never sent MAX_PUSH_ID -> ID_ERROR
 * (RFC 9114 s4.6, s6.2.2) */
static void test_push_stream(int *fp)
{
    int failures = 0;

    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        const uint8_t push[] = { 0x01, 0x00 };
        wtq_estream_t *es = open_peer(&r, 2, fp);
        feed(&r, es, push, sizeof(push), 1, false);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_STREAM_CREATION_ERROR);
        rig_down(&r);
    }
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        const uint8_t push[] = { 0x01, 0x00 };
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, push, sizeof(push), 1, false);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_ID_ERROR);
        rig_down(&r);
    }
    *fp += failures;
}

/* a uni stream FINISHED before its stream header completes MUST be
 * tolerated (RFC 9114 s6.2) */
static void test_preface_fin_tolerated(int *fp)
{
    int failures = 0;

    {
        /* empty stream + FIN */
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, NULL, 0, 1, true);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        rig_down(&r);
    }
    {
        /* FIN mid stream-type varint: {0x40} announces 2 bytes */
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        const uint8_t half_type[] = { 0x40 };
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, half_type, sizeof(half_type), 1, true);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

        /* the engine stays fully functional afterwards */
        uint8_t peer[128];
        size_t plen = build_peer_control(peer, sizeof(peer), true, false);
        wtq_estream_t *es2 = open_peer(&r, 7, fp);
        feed(&r, es2, peer, plen, 5, false);
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
        rig_down(&r);
    }
    *fp += failures;
}

/* duplicate QPACK streams + QPACK stream termination */
static void test_qpack_critical_streams(int *fp)
{
    int failures = 0;
    static const uint8_t types[] = { 0x02, 0x03 };

    for (size_t t = 0; t < sizeof(types); t++) {
        /* duplicate -> STREAM_CREATION_ERROR */
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        const uint8_t preface[] = { types[t] };
        wtq_estream_t *es = open_peer(&r, 3, fp);
        feed(&r, es, preface, 1, 1, false);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        wtq_estream_t *es2 = open_peer(&r, 7, fp);
        feed(&r, es2, preface, 1, 1, false);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_STREAM_CREATION_ERROR);
        rig_down(&r);

        /* FIN on the (single) QPACK stream -> CLOSED_CRITICAL_STREAM */
        rig_t r2;
        rig_up(&r2, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_estream_t *esf = open_peer(&r2, 3, fp);
        feed(&r2, esf, preface, 1, 1, true);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r2.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r2.conn),
                              WTQ_H3_CLOSED_CRITICAL_STREAM);
        rig_down(&r2);

        /* reset on the QPACK stream -> CLOSED_CRITICAL_STREAM */
        rig_t r3;
        rig_up(&r3, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_estream_t *esr = open_peer(&r3, 3, fp);
        feed(&r3, esr, preface, 1, 1, false);
        WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r3.conn, esr, 0, 4000) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r3.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r3.conn),
                              WTQ_H3_CLOSED_CRITICAL_STREAM);
        rig_down(&r3);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_bootstrap_happy(&failures);
    test_split_settings(&failures);
    test_server_side(&failures);
    test_server_defers_locals(&failures);
    test_server_defer_triggers(&failures);
    test_server_defer_failure_fatal(&failures);
    test_unknown_uni_drained(&failures);
    test_error_matrix(&failures);
    test_second_settings(&failures);
    test_duplicate_control(&failures);
    test_other_control_frames_skipped(&failures);
    test_control_reset(&failures);
    test_forbidden_control_frames(&failures);
    test_known_control_frames(&failures);
    test_push_stream(&failures);
    test_preface_fin_tolerated(&failures);
    test_qpack_critical_streams(&failures);

    WTQ_TEST_PASS("test_engine_bootstrap");
    return failures;
}
