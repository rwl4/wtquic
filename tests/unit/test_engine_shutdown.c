/*
 * Structured half-stream shutdown (engine level).
 *
 * The driver pair reset_stream/stop_sending is replaced by ONE
 * shutdown_stream transaction. These tests pin:
 *   - WHOLE_STREAM aborts every still-open half with one code, in one
 *     transaction — uni, fully-open bidi, and half-closed bidi;
 *   - EXACT single halves on a fully-open bidi are capability-gated:
 *     supported executes exactly, unsupported returns UNSUPPORTED with
 *     ZERO effect (state unchanged, no op call);
 *   - a single half that is the only remaining open half is baseline;
 *   - split codes are one transaction under the cap, UNSUPPORTED without;
 *   - runtime failure (before effects, or after partial application)
 *     fails the connection — no rollback pretense;
 *   - internal call sites (session teardown, wtq_conn_wt_reject) emit
 *     one transaction with the exact wire code.
 */
#include <stdio.h>
#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

typedef struct app_state {
    int established_events;
    int error_events;
    uint64_t last_error;
    int closed_events;
    int send_completes;
} app_state_t;

static void cb_established(wtq_conn_t *c, const char *sel, size_t len,
                           void *ctx)
{
    (void)c;
    (void)sel;
    (void)len;
    ((app_state_t *)ctx)->established_events++;
}

static void cb_error(wtq_conn_t *c, uint64_t e, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->error_events++;
    st->last_error = e;
}

static void cb_closed(wtq_conn_t *c, uint32_t code, const uint8_t *reason,
                      size_t reason_len, bool clean, void *ctx)
{
    (void)c;
    (void)code;
    (void)reason;
    (void)reason_len;
    (void)clean;
    ((app_state_t *)ctx)->closed_events++;
}

static void cb_send_complete(wtq_conn_t *c, void *cookie, bool canceled,
                             void *ctx)
{
    (void)c;
    (void)cookie;
    (void)canceled;
    ((app_state_t *)ctx)->send_completes++;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_driver_ops_t ops; /* per-test copy: caps are configurable */
    wtq_conn_t *conn;
    app_state_t app;
} rig_t;

static const char *const OFFER[] = { "moqt-18" };

static size_t build_response(uint8_t *dst, size_t cap)
{
    uint8_t section[256];
    size_t slen = 0;
    wtq_sf_str_t sel = { "moqt-18", 7 };

    if (wtq_connect_encode_response(200, &sel, section, sizeof(section),
                                    &slen) != 0)
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

/* Bring a client rig to an ESTABLISHED session, with the given caps. */
static void rig_established(rig_t *r, uint32_t caps, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    fake_driver_init(&r->drv, true);
    r->ops = *fake_driver_ops();
    r->ops.caps = caps;

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .enable_connect_protocol = true,
        .callbacks = { .on_session_established = cb_established,
                       .on_conn_error = cb_error,
                       .on_session_closed = cb_closed,
                       .on_wt_send_complete = cb_send_complete,
                       .ctx = &r->app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r->drv, &r->ops, &r->conn) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r->conn, 1000) == WTQ_OK);

    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, OFFER, 1, true, 0,
    };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r->conn, &ccfg) == WTQ_OK);

    /* peer SETTINGS */
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    buf[0] = 0x00;
    struct wtq_dstream *pds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, pds, 3, &pes) ==
                   WTQ_OK);
    pds->ectx = pes;
    (void)wtq_conn_on_stream_bytes(r->conn, pes, buf, 1 + flen, false,
                                   1500);

    /* response */
    uint8_t resp[300];
    size_t rlen = build_response(resp, sizeof(resp));
    struct wtq_dstream *bidi = find_local_bidi(r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    (void)wtq_conn_on_stream_bytes(r->conn, bidi->ectx, resp, rlen, false,
                                   2000);
    WTQ_TEST_CHECK_EQ_INT(r->app.established_events, 1);
    *fp += failures;
}

#define ALL_CAPS                                                          \
    (WTQ_DCAP_SHUT_BIDI_SEND | WTQ_DCAP_SHUT_BIDI_RECV |                  \
     WTQ_DCAP_SHUT_SPLIT_CODES)

static void rig_down(rig_t *r)
{
    wtq_conn_destroy(r->conn);
}

/* ds for a just-opened WT stream (creation order after the criticals +
 * CONNECT: index 4 for the first WT stream). */
static struct wtq_dstream *wt_ds(rig_t *r, size_t nth)
{
    return fake_driver_local(&r->drv, 4 + nth);
}

/* --- whole-stream abort ----------------------------------------------------- */

static void test_whole_abort_uni(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);
    WTQ_TEST_CHECK(ds != NULL);

    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 7) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(!ds->last_shutdown.abort_recv); /* uni: no recv half */
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.send_err,
                          wtq_app_error_to_h3(7));
    /* the uni's only half is gone: slot released through detach */
    WTQ_TEST_CHECK(ds->ectx == NULL);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

static void test_whole_abort_full_bidi(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 9) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1); /* ONE transaction */
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_recv);
    WTQ_TEST_CHECK(ds->last_shutdown.send_err ==
                   ds->last_shutdown.recv_err);
    /* legacy pump fields both flipped by the one call */
    WTQ_TEST_CHECK(ds->reset && ds->stopped);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

static void test_whole_abort_half_closed_bidi(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    /* close the receive half first (exact, cap present) */
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, a, 3) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);

    /* whole abort now touches ONLY the remaining send half */
    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 9) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 2);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(!ds->last_shutdown.abort_recv);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

/* --- exact halves, capability-gated ------------------------------------------ */

static void test_exact_half_supported(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, a, 5) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_EXACT_HALVES);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(!ds->last_shutdown.abort_recv);
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.send_err,
                          wtq_app_error_to_h3(5));
    WTQ_TEST_CHECK(ds->reset && !ds->stopped);
    rig_down(&r);
    *fp += failures;
}

static void test_exact_half_unsupported_zero_effect(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, 0 /* NO caps */, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    /* fully-open bidi, single half, no cap: UNSUPPORTED, ZERO effect */
    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, a, 5) ==
                   WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, a, 5) ==
                   WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 0);
    WTQ_TEST_CHECK(!ds->reset && !ds->stopped);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    /* the send half is still fully usable after the refusal */
    uint8_t payload[3] = { 1, 2, 3 };
    wtq_span_t span = { payload, sizeof(payload) };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, a, &span, 1, false,
                                    &cookie) == WTQ_OK);
    WTQ_TEST_CHECK(fake_driver_complete_sends(&r.drv, r.conn) == 1);

    /* and the whole-stream abort remains available (baseline) */
    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 5) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    rig_down(&r);
    *fp += failures;
}

static void test_exact_half_on_half_closed_is_baseline(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, 0 /* NO caps */, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    /* peer FINs its half -> recv side closes -> bidi is half-closed */
    WTQ_TEST_CHECK(fake_driver_deliver_bytes(r.conn, ds, NULL, 0, true,
                                             3000));
    /* the exact send-half reset is now the only remaining half:
     * normalized to WHOLE_STREAM, supported without any cap */
    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, a, 5) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(!ds->last_shutdown.abort_recv);
    rig_down(&r);
    *fp += failures;
}

/* --- split codes -------------------------------------------------------------- */

static void test_split_codes(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_EXACT_HALVES,
                           .abort_send = true,
                           .abort_recv = true,
                           .send_err = 0x111,
                           .recv_err = 0x222 };
    WTQ_TEST_CHECK(wtq_conn_wt_shutdown(r.conn, a, &req) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1); /* ONE transaction */
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_EXACT_HALVES);
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.send_err, 0x111);
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.recv_err, 0x222);
    WTQ_TEST_CHECK_EQ_HEX(ds->reset_err, 0x111);
    WTQ_TEST_CHECK_EQ_HEX(ds->stop_err, 0x222);
    rig_down(&r);
    *fp += failures;
}

static void test_split_codes_unsupported(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, WTQ_DCAP_SHUT_BIDI_SEND | WTQ_DCAP_SHUT_BIDI_RECV,
                    fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_EXACT_HALVES,
                           .abort_send = true,
                           .abort_recv = true,
                           .send_err = 0x111,
                           .recv_err = 0x222 };
    WTQ_TEST_CHECK(wtq_conn_wt_shutdown(r.conn, a, &req) ==
                   WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 0); /* zero effect */
    WTQ_TEST_CHECK(!ds->reset && !ds->stopped);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    rig_down(&r);
    *fp += failures;
}

/* --- runtime failure ----------------------------------------------------------- */

static void test_failure_before_effects(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &a) == WTQ_OK);

    r.drv.fail_shutdown_before = true;
    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 1) == WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);
    WTQ_TEST_CHECK(r.app.last_error == 0x0102 /* H3_INTERNAL_ERROR */);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

static void test_failure_after_partial_application(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    r.drv.fail_shutdown_after_first = true;
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_EXACT_HALVES,
                           .abort_send = true,
                           .abort_recv = true,
                           .send_err = 0x111,
                           .recv_err = 0x222 };
    /* the send half was APPLIED, then the transaction failed: no
     * rollback pretense — the connection dies */
    WTQ_TEST_CHECK(wtq_conn_wt_shutdown(r.conn, a, &req) ==
                   WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(ds->reset && !ds->stopped); /* partial, by design */
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* An invalid mode is rejected before ANY backend call or state change. */
static void test_invalid_mode_zero_effect(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    wtq_shutdown_t req = { .mode = 7 /* invalid */,
                           .abort_send = true,
                           .send_err = 1,
                           .recv_err = 1 };
    WTQ_TEST_CHECK(wtq_conn_wt_shutdown(r.conn, a, &req) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 0);
    WTQ_TEST_CHECK(!ds->reset && !ds->stopped);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    /* the stream is untouched: a real abort still works */
    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, a, 1) == WTQ_OK);
    rig_down(&r);
    *fp += failures;
}

/* A RAW-path (no-estream) backend failure fails the connection: the
 * peer-uni pool rejection goes through shutdown_raw, whose runtime
 * failure must be connection-fatal, never silently dropped. */
static void test_raw_failure_is_fatal(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    /* fill the pool with peer streams until rejection territory */
    uint64_t id = 7;
    for (int i = 0; i < 32; i++) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, id);
        wtq_estream_t *es = NULL;
        wtq_result_t rc = wtq_conn_on_peer_uni_opened(r.conn, ds, id, &es);
        id += 4;
        if (rc == WTQ_ERR_STREAM_LIMIT)
            break; /* pool full: next rejection will hit shutdown_raw */
        WTQ_TEST_CHECK(rc == WTQ_OK);
        if (es != NULL)
            ds->ectx = es;
    }
    r.drv.fail_shutdown_before = true;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, id);
    wtq_estream_t *es = NULL;
    (void)wtq_conn_on_peer_uni_opened(r.conn, ds, id, &es);
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 1);
    WTQ_TEST_CHECK(r.app.last_error == 0x0102 /* H3_INTERNAL_ERROR */);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* --- internal call sites --------------------------------------------------------- */

static void test_reject_is_one_transaction(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *a = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &a) == WTQ_OK);
    struct wtq_dstream *ds = wt_ds(&r, 0);

    wtq_conn_wt_reject(r.conn, a);
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_recv);
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.send_err,
                          WTQ_WT_BUFFERED_STREAM_REJECTED);
    rig_down(&r);
    *fp += failures;
}

static void test_session_teardown_one_transaction_each(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_established(&r, ALL_CAPS, fp);
    wtq_estream_t *u = NULL;
    wtq_estream_t *b = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &u) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &b) == WTQ_OK);
    struct wtq_dstream *dsu = wt_ds(&r, 0);
    struct wtq_dstream *dsb = wt_ds(&r, 1);

    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
    /* one WHOLE transaction per stream, exact SESSION_GONE wire code */
    WTQ_TEST_CHECK_EQ_INT(dsu->shutdown_count, 1);
    WTQ_TEST_CHECK_EQ_INT(dsb->shutdown_count, 1);
    WTQ_TEST_CHECK(dsu->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(dsb->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK_EQ_HEX(dsu->last_shutdown.send_err,
                          WTQ_WT_SESSION_GONE);
    WTQ_TEST_CHECK_EQ_HEX(dsb->last_shutdown.send_err,
                          WTQ_WT_SESSION_GONE);
    WTQ_TEST_CHECK(dsb->last_shutdown.abort_send &&
                   dsb->last_shutdown.abort_recv);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_whole_abort_uni(&failures);
    test_whole_abort_full_bidi(&failures);
    test_whole_abort_half_closed_bidi(&failures);
    test_exact_half_supported(&failures);
    test_exact_half_unsupported_zero_effect(&failures);
    test_exact_half_on_half_closed_is_baseline(&failures);
    test_split_codes(&failures);
    test_split_codes_unsupported(&failures);
    test_failure_before_effects(&failures);
    test_failure_after_partial_application(&failures);
    test_invalid_mode_zero_effect(&failures);
    test_raw_failure_is_fatal(&failures);
    test_reject_is_one_transaction(&failures);
    test_session_teardown_one_transaction_each(&failures);

    WTQ_TEST_PASS("test_engine_shutdown");
    return failures;
}
