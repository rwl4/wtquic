/*
 * Asynchronous native stream ids (engine level).
 *
 * The fake driver's async_ids mode models a Network.framework-class
 * transport: open_* returns WTQ_STREAM_ID_UNKNOWN and the id arrives later
 * through wtq_conn_on_stream_native_id, delivered — like every other stream
 * event — through the dstream's CURRENT ectx. These tests pin:
 *   - client establishment gating on BOTH latches (id + response), either
 *     arrival order, exactly once;
 *   - byte-exact selected-subprotocol preservation across a parked
 *     response (escape-heavy offer included);
 *   - id validation (pending state, varint range, initiator/direction
 *     bits, collisions against KNOWN ids only, id zero VALID);
 *   - suppression of reports after detach and across slot reuse;
 *   - ectx-NULL critical streams needing no report;
 *   - send completions and terminal failure while the id is pending;
 *   - no establishment when the id never arrives.
 */
#include <stdio.h>
#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/varint.h"

#include "test_support.h"

typedef struct app_state {
    int established_events;
    char selected[512];
    size_t selected_len;
    int failed_events;
    int failed_reason;
    int error_events;
    uint64_t last_error;
    int send_completes;
    bool last_canceled;
} app_state_t;

static void cb_established(wtq_conn_t *c, const char *sel, size_t len,
                           void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->established_events++;
    st->selected_len = len < sizeof(st->selected) ? len : 0;
    if (st->selected_len > 0)
        memcpy(st->selected, sel, st->selected_len);
}

static void cb_failed(wtq_conn_t *c, wtq_session_fail_reason_t r,
                      void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->failed_events++;
    st->failed_reason = (int)r;
}

static void cb_error(wtq_conn_t *c, uint64_t e, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->error_events++;
    st->last_error = e;
}

static void cb_send_complete(wtq_conn_t *c, void *cookie, bool canceled,
                             void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)cookie;
    st->send_completes++;
    st->last_canceled = canceled;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    app_state_t app;
} rig_t;

static void rig_up_async(rig_t *r, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    fake_driver_init(&r->drv, true /* client */);
    r->drv.async_ids = true;

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .enable_connect_protocol = true,
        .callbacks = { .on_session_established = cb_established,
                       .on_session_failed = cb_failed,
                       .on_conn_error = cb_error,
                       .on_wt_send_complete = cb_send_complete,
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

/* "moqt-18" plus an escape-heavy offer: quotes and backslashes survive the
 * park only if establishment reads the persistent offered[] bytes. */
static const char ESCAPED[] = "a\"b\\c\"\"d\\\\e";
static const char *const OFFER[] = { "moqt-18", ESCAPED };

static wtq_result_t do_connect(rig_t *r)
{
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, true, 0 };
    return wtq_conn_client_connect(r->conn, &cfg);
}

static size_t build_settings(uint8_t *dst, size_t cap)
{
    uint8_t frame[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;

    if (wtq_h3_settings_encode_frame(&scfg, frame, sizeof(frame),
                                     &flen) != WTQ_H3_SETTINGS_OK ||
        flen + 1 > cap)
        return 0;
    dst[0] = 0x00;
    memcpy(dst + 1, frame, flen);
    return flen + 1;
}

static void deliver_peer_settings(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    size_t blen = build_settings(buf, sizeof(buf));

    WTQ_TEST_CHECK(blen > 0);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, ds, 3, &es) ==
                   WTQ_OK);
    ds->ectx = es;
    (void)wtq_conn_on_stream_bytes(r->conn, es, buf, blen, false, 1500);
    *fp += failures;
}

static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t sel = { proto, proto ? strlen(proto) : 0 };

    if (wtq_connect_encode_response(status, proto ? &sel : NULL, section,
                                    sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

static struct wtq_dstream *find_local_bidi(rig_t *r)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            return &r->drv.streams[i];
    return NULL;
}

static void feed_response(rig_t *r, const char *proto, int *fp)
{
    int failures = 0;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, proto);
    struct wtq_dstream *bidi = find_local_bidi(r);

    WTQ_TEST_CHECK(rlen > 0);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    if (bidi != NULL && bidi->ectx != NULL)
        (void)wtq_conn_on_stream_bytes(r->conn, bidi->ectx, resp, rlen,
                                       false, 2500);
    *fp += failures;
}

/* Up to the point where CONNECT is open with a PENDING id. */
static struct wtq_dstream *rig_to_pending_connect(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up_async(r, fp);
    WTQ_TEST_CHECK(do_connect(r) == WTQ_OK);
    deliver_peer_settings(r, fp);
    struct wtq_dstream *bidi = find_local_bidi(r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    /* The engine saw UNKNOWN at open: both queries say so. */
    if (bidi != NULL)
        WTQ_TEST_CHECK(wtq_estream_id(bidi->ectx) ==
                       WTQ_STREAM_ID_UNKNOWN);
    WTQ_TEST_CHECK(wtq_conn_session_id(r->conn) == UINT64_MAX);
    *fp += failures;
    return bidi;
}

/* --- establishment gating -------------------------------------------------- */

/* id first, then response: established exactly once at the response. */
static void test_id_then_response(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(wtq_estream_id(bidi->ectx) == bidi->id);
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_id(r.conn) == bidi->id);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, 7);
    WTQ_TEST_CHECK(memcmp(r.app.selected, "moqt-18", 7) == 0);
    rig_down(&r);
    *fp += failures;
}

/* response first (parked), then id: established exactly once at the id,
 * with the ESCAPE-HEAVY selection byte-exact from the persistent offer. */
static void test_response_then_id_escaped_proto(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    feed_response(&r, ESCAPED, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1700));
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, sizeof(ESCAPED) - 1);
    WTQ_TEST_CHECK(memcmp(r.app.selected, ESCAPED, sizeof(ESCAPED) - 1) ==
                   0);
    size_t sl = 0;
    const char *sel = wtq_conn_selected_protocol(r.conn, &sl);
    WTQ_TEST_CHECK(sl == sizeof(ESCAPED) - 1 &&
                   memcmp(sel, ESCAPED, sl) == 0);
    rig_down(&r);
    *fp += failures;
}

/* The id never arrives: no establishment, no spurious failure, and the
 * session/query surface stays coherent. */
static void test_id_never_arrives(int *fp)
{
    int failures = 0;
    rig_t r;

    (void)rig_to_pending_connect(&r, fp);
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(wtq_conn_session_id(r.conn) == UINT64_MAX);
    rig_down(&r);
    *fp += failures;
}

/* Stream id ZERO is a real id (MsQuic's first client bidi): session_id 0
 * establishes and the query returns 0, not the UNKNOWN sentinel. */
static void test_id_zero_valid(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(bidi->id == 0); /* fake client bidi ids: 0,4,8... */
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_id(r.conn) == 0);
    WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* --- report validation ----------------------------------------------------- */

/* Each invalid report is a backend defect: H3_INTERNAL connection error. */
static void expect_fatal_after(rig_t *r, int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK_EQ_INT(r->app.error_events, 1);
    WTQ_TEST_CHECK(r->app.last_error == 0x0102 /* H3_INTERNAL_ERROR */);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r->conn));
    *fp += failures;
}

static void test_report_duplicate(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1601));
    expect_fatal_after(&r, fp);
    rig_down(&r);
    *fp += failures;
}

static void test_report_for_sync_stream(int *fp)
{
    int failures = 0;
    rig_t r;

    /* sync mode: the open already carried the id, nothing is pending */
    memset(&r.app, 0, sizeof(r.app));
    fake_driver_init(&r.drv, true);
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .enable_connect_protocol = true,
        .callbacks = { .on_session_established = cb_established,
                       .on_session_failed = cb_failed,
                       .on_conn_error = cb_error,
                       .ctx = &r.app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r.drv, fake_driver_ops(),
                                   &r.conn) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r.conn, 1000) == WTQ_OK);
    WTQ_TEST_CHECK(do_connect(&r) == WTQ_OK);
    deliver_peer_settings(&r, fp);
    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    WTQ_TEST_CHECK(wtq_estream_id(bidi->ectx) == bidi->id);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    expect_fatal_after(&r, fp);
    rig_down(&r);
    *fp += failures;
}

static void test_report_bad_values(int *fp)
{
    int failures = 0;
    /* out-of-range, wrong initiator (server bit), wrong direction (uni
     * bit on the CONNECT bidi) */
    const uint64_t bad[] = { 1ull << 62, /* range */
                             5,          /* client conn: initiator bit 1 */
                             6 };        /* uni bit on a bidi */

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        rig_t r;
        struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);
        WTQ_TEST_CHECK(fake_driver_deliver_native_id_as(r.conn, bidi,
                                                        bad[i], 1600));
        expect_fatal_after(&r, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* Collision checks apply to KNOWN ids only. Two variants, each ending
 * fatal on a report equal to a KNOWN id:
 *   (a) the ESTABLISHED session_id, reported on a pending local WT BIDI
 *       (a bidi passes the direction check, so the collision arm — not a
 *       bit check — must be what fires);
 *   (b) another live stream's known id.
 * Two pending streams coexisting is legal (UNKNOWN never collides). */
static void test_report_collision_session_id(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    uint64_t sess_id = wtq_conn_session_id(r.conn);
    WTQ_TEST_CHECK(sess_id == bidi->id);

    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *dsa = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(dsa != NULL && dsa->is_bidi);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id_as(r.conn, dsa, sess_id,
                                                    1700));
    expect_fatal_after(&r, fp);
    rig_down(&r);
    *fp += failures;
}

static void test_report_collision_live_stream(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    /* two local WT unis, both pending: legal (UNKNOWN never collides) */
    wtq_estream_t *a = NULL;
    wtq_estream_t *b = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &b) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    struct wtq_dstream *dsa = fake_driver_local(&r.drv, 4);
    struct wtq_dstream *dsb = fake_driver_local(&r.drv, 5);
    WTQ_TEST_CHECK(dsa != NULL && dsb != NULL);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, dsa, 1700));
    /* same id again on the second stream: collision with a KNOWN id */
    WTQ_TEST_CHECK(fake_driver_deliver_native_id_as(r.conn, dsb, dsa->id,
                                                    1701));
    expect_fatal_after(&r, fp);
    rig_down(&r);
    *fp += failures;
}

/* A DIRECT report against a released (ES_FREE) slot — the buggy-backend
 * cached-pointer case that bypasses the ds->ectx suppression — must hit
 * the fatal path, never mutate the free slot. */
static void test_report_released_slot(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *dsa = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(dsa != NULL && dsa->ectx == a);
    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, a, 0) == WTQ_OK);
    WTQ_TEST_CHECK(dsa->ectx == NULL); /* released + detached */

    /* buggy backend: cached estream pointer, direct call */
    wtq_conn_on_stream_native_id(r.conn, a, dsa->id);
    expect_fatal_after(&r, fp);
    rig_down(&r);
    *fp += failures;
}

/* --- detach suppression / slot reuse --------------------------------------- */

static void test_report_after_detach_and_reuse(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    /* open a WT uni (pending id), then tear it down before the id
     * arrives: the estream releases and the fake's detach clears ectx */
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *dsa = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(dsa != NULL && dsa->ectx == a);
    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, a, 0) == WTQ_OK);
    WTQ_TEST_CHECK(dsa->ectx == NULL); /* detached */

    /* the slot may now be REUSED by a fresh stream */
    wtq_estream_t *b = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &b) == WTQ_OK);
    struct wtq_dstream *dsb = fake_driver_local(&r.drv, 5);
    WTQ_TEST_CHECK(dsb != NULL && dsb->ectx == b);

    /* the LATE report for the dead stream is suppressed at the backend */
    WTQ_TEST_CHECK(!fake_driver_deliver_native_id(r.conn, dsa, 1800));
    WTQ_TEST_CHECK(wtq_estream_id(b) == WTQ_STREAM_ID_UNKNOWN);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    /* and the reused slot's own report lands normally */
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, dsb, 1801));
    WTQ_TEST_CHECK(wtq_estream_id(b) == dsb->id);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

/* --- criticals, terminal-before-id, completions ----------------------------- */

/* H3 control/QPACK open with ectx == NULL under async ids: the engine
 * runs fine with their ids permanently unknown, and a delivery attempt
 * for EACH critical dstream is suppressed at the backend (ectx NULL —
 * there is nothing to report through). */
static void test_criticals_ectx_null(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up_async(&r, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    /* control + 2 QPACK streams opened, engine healthy */
    WTQ_TEST_CHECK(r.drv.open_count >= 3);
    for (size_t i = 0; i < 3; i++) {
        struct wtq_dstream *ds = fake_driver_local(&r.drv, i);
        WTQ_TEST_CHECK(ds != NULL && ds->ectx == NULL);
        WTQ_TEST_CHECK(!fake_driver_deliver_native_id(r.conn, ds, 1200));
    }
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* CONNECT reset while the id is pending: pre-establishment failure path,
 * and the late id report is suppressed by the detach. */
static void test_reset_before_id(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_reset(r.conn, bidi, 0x10c, 1600));
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 1);
    /* released -> detached -> the late report delivers nothing */
    WTQ_TEST_CHECK(bidi->ectx == NULL);
    WTQ_TEST_CHECK(!fake_driver_deliver_native_id(r.conn, bidi, 1700));
    rig_down(&r);
    *fp += failures;
}

/* Connection lost while the id is pending: CONNECTION failure, and a
 * post-mortem report is dropped silently (driver state is gone). */
static void test_conn_lost_before_id(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    wtq_conn_on_conn_closed(r.conn, 0, true, 1600);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                          WTQ_SESSION_FAIL_CONNECTION);
    /* post-mortem: harmless no-op, no new error events */
    int errs = r.app.error_events;
    if (bidi->ectx != NULL)
        (void)fake_driver_deliver_native_id(r.conn, bidi, 1700);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, errs);
    rig_down(&r);
    *fp += failures;
}

/* A rejection response resolves the session while the id is pending. */
static void test_rejected_before_id(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t resp[256];

    (void)rig_to_pending_connect(&r, fp);
    size_t rlen = build_response(resp, sizeof(resp), 404, NULL);
    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, resp, rlen, false,
                                   2500);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* Cookie send completions are legal while a WT stream's id is pending. */
static void test_completion_while_pending(int *fp)
{
    int failures = 0;
    rig_t r;
    struct wtq_dstream *bidi = rig_to_pending_connect(&r, fp);

    WTQ_TEST_CHECK(fake_driver_deliver_native_id(r.conn, bidi, 1600));
    feed_response(&r, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_estream_id(a) == WTQ_STREAM_ID_UNKNOWN);

    uint8_t payload[4] = { 1, 2, 3, 4 };
    wtq_span_t span = { payload, sizeof(payload) };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, a, &span, 1, false,
                                    &cookie) == WTQ_OK);
    WTQ_TEST_CHECK(fake_driver_complete_sends(&r.drv, r.conn) == 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.send_completes, 1);
    WTQ_TEST_CHECK(!r.app.last_canceled);
    /* still pending, still healthy */
    WTQ_TEST_CHECK(wtq_estream_id(a) == WTQ_STREAM_ID_UNKNOWN);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_id_then_response(&failures);
    test_response_then_id_escaped_proto(&failures);
    test_id_never_arrives(&failures);
    test_id_zero_valid(&failures);
    test_report_duplicate(&failures);
    test_report_for_sync_stream(&failures);
    test_report_bad_values(&failures);
    test_report_collision_session_id(&failures);
    test_report_collision_live_stream(&failures);
    test_report_released_slot(&failures);
    test_report_after_detach_and_reuse(&failures);
    test_criticals_ectx_null(&failures);
    test_reset_before_id(&failures);
    test_conn_lost_before_id(&failures);
    test_rejected_before_id(&failures);
    test_completion_while_pending(&failures);

    WTQ_TEST_PASS("test_engine_async_id");
    return failures;
}
