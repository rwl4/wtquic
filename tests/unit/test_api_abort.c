/*
 * Public whole-stream abort + capability-gated half-close semantics.
 *
 * Pins the API contract: state changes happen ONLY after an accepted
 * shutdown — wtq_stream_reset on a fully-open bidi over a backend
 * without independent half-abort returns WTQ_ERR_UNSUPPORTED and leaves
 * the handle fully usable, while wtq_stream_abort (whole stream, one
 * code) is baseline everywhere and drives the handle terminal.
 */
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

typedef struct log_state {
    int established;
    int stream_closed;
    int stream_resets;
    int send_completes;
    int send_canceled;
} log_state_t;

static void on_send_complete(wtq_session_t *s, void *send_ctx,
                             bool canceled, void *user)
{
    log_state_t *lg = user;

    (void)s;
    (void)send_ctx;
    lg->send_completes++;
    if (canceled)
        lg->send_canceled++;
}

static void on_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    (void)s;
    (void)sub;
    ((log_state_t *)user)->established++;
}

static void on_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    (void)s;
    (void)st;
    ((log_state_t *)user)->stream_closed++;
}

static void on_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *user)
{
    (void)s;
    (void)st;
    (void)code;
    ((log_state_t *)user)->stream_resets++;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_driver_ops_t ops;
    wtq_session_t *s;
    log_state_t lg;
} rig_t;

static const char *const OFFER[] = { "moqt-18" };

static struct wtq_dstream *find_local_bidi(rig_t *r)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            return &r->drv.streams[i];
    return NULL;
}

static void establish(rig_t *r, uint32_t caps, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(&r->lg, 0, sizeof(r->lg));
    fake_driver_init(&r->drv, true);
    r->ops = *fake_driver_ops();
    r->ops.caps = caps;
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
    ev.on_stream_closed = on_stream_closed;
    ev.on_stream_reset = on_stream_reset;
    ev.on_send_complete = on_send_complete;

    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &r->lg,
        .drv = &r->drv,
        .ops = &r->ops,
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r->s) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_api_session_start(r->s, 1000) == WTQ_OK);

    wtq_connect_config_t ccfg;
    wtq_connect_config_init(&ccfg);
    ccfg.authority = "example.com";
    ccfg.path = "/app";
    ccfg.subprotocols = OFFER;
    ccfg.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(r->s, &ccfg) == WTQ_OK);

    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);
    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    struct wtq_dstream *pds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, pds, 3, &pes) ==
                   WTQ_OK);
    pds->ectx = pes;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, pes, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);

    uint8_t section[256];
    uint8_t resp[300];
    size_t slen = 0;
    wtq_sf_str_t sel = { "moqt-18", 7 };
    WTQ_TEST_CHECK(wtq_connect_encode_response(200, &sel, section,
                                               sizeof(section),
                                               &slen) == 0);
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen,
                                              resp, sizeof(resp),
                                              &hl) == 0);
    memcpy(resp + hl, section, slen);
    struct wtq_dstream *bidi = find_local_bidi(r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, bidi->ectx, resp,
                                            hl + slen, false, 2000) ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r->lg.established, 1);
    *fp += failures;
}

static void rig_down(rig_t *r)
{
    wtq_session_release(r->s);
}

#define ALL_CAPS                                                          \
    (WTQ_DCAP_SHUT_BIDI_SEND | WTQ_DCAP_SHUT_BIDI_RECV |                  \
     WTQ_DCAP_SHUT_SPLIT_CODES)

/* wtq_stream_abort: baseline everywhere, handle goes terminal. */
static void test_public_abort_terminal(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0 /* even with NO caps */, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);
    wtq_stream_add_ref(st);

    WTQ_TEST_CHECK(wtq_stream_abort(st, 42) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    /* terminal: further operations report closed */
    WTQ_TEST_CHECK(wtq_stream_abort(st, 42) == WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wtq_stream_reset(st, 1) == WTQ_ERR_CLOSED);
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

/* Unsupported half-close: zero public state change; abort still works. */
static void test_public_reset_unsupported_zero_effect(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);

    WTQ_TEST_CHECK(wtq_stream_reset(st, 1) == WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK(wtq_stream_stop_sending(st, 1) ==
                   WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 0);

    /* both directions remain usable */
    uint8_t b[2] = { 1, 2 };
    wtq_span_t span = { b, sizeof(b) };
    size_t consumed = 0;
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &consumed) == WTQ_OK);

    WTQ_TEST_CHECK(wtq_stream_abort(st, 1) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    rig_down(&r);
    *fp += failures;
}

/* With capable transports the exact halves pass straight through. */
static void test_public_reset_supported(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, ALL_CAPS, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);

    WTQ_TEST_CHECK(wtq_stream_reset(st, 1) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 0); /* recv still open */
    WTQ_TEST_CHECK(wtq_stream_stop_sending(st, 2) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    rig_down(&r);
    *fp += failures;
}

/* An accepted (pending) send, then wtq_stream_abort: the completion
 * returns CANCELED, exactly once. */
static void test_abort_cancels_pending_send_once(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);

    uint8_t b[4] = { 1, 2, 3, 4 };
    wtq_span_t span = { b, sizeof(b) };
    WTQ_TEST_CHECK(wtq_stream_send(r.s != NULL ? st : NULL, &span, 1, 0,
                                   &b) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.send_completes, 0); /* still pending */

    WTQ_TEST_CHECK(wtq_stream_abort(st, 3) == WTQ_OK);
    /* the backend flushes its (canceled) completions */
    WTQ_TEST_CHECK(fake_driver_complete_sends(&r.drv,
                                              wtq_api_session_conn(r.s)) ==
                   1);
    WTQ_TEST_CHECK_EQ_INT(r.lg.send_completes, 1);
    WTQ_TEST_CHECK_EQ_INT(r.lg.send_canceled, 1);
    /* nothing further to complete: exactly once */
    WTQ_TEST_CHECK(fake_driver_complete_sends(&r.drv,
                                              wtq_api_session_conn(r.s)) ==
                   0);
    WTQ_TEST_CHECK_EQ_INT(r.lg.send_completes, 1);
    rig_down(&r);
    *fp += failures;
}

/* Find the app bidi's engine estream (NOT the CONNECT stream): its
 * fake dstream is the local bidi opened after establishment. */
static wtq_estream_t *app_bidi_es(rig_t *r, struct wtq_dstream *skip)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++) {
        struct wtq_dstream *d = &r->drv.streams[i];
        if (d->in_use && d->is_local && d->is_bidi && d != skip)
            return d->ectx;
    }
    return NULL;
}

/*
 * Whole-stream transport terminal against LIVE public handles: the
 * remaining halves close, exactly ONE on_stream_closed fires, no
 * reset/stop is fabricated, retained handles stay valid-but-dead
 * (operations return CLOSED, the native-id snapshot survives), and a
 * handle the app ALREADY terminaled (abort) never sees a duplicate.
 */
static void test_terminal_public_after_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0, fp);
    struct wtq_dstream *connect_ds = find_local_bidi(&r);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);
    wtq_stream_add_ref(st);
    wtq_estream_t *es = app_bidi_es(&r, connect_ds);
    WTQ_TEST_CHECK(es != NULL);
    if (es == NULL) {
        wtq_stream_release(st);
        rig_down(&r);
        *fp += failures;
        return;
    }
    wtq_conn_t *conn = wtq_api_session_conn(r.s);

    /* the peer's real reset closes the receive half only */
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(conn, es, 0x21, 5000) ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_resets, 1);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 0);

    /* the whole transport terminal closes the remaining send half:
     * exactly one closed event, no forged reset */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_resets, 1);

    /* the retained handle is dead-but-valid */
    static const uint8_t d[1] = { 1 };
    wtq_span_t sp = { d, 1 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &sp, 1, 0, NULL) ==
                   WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wtq_stream_abort(st, 1) == WTQ_ERR_CLOSED);
    (void)wtq_stream_id(st); /* snapshot queryable, whatever it holds */
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

static void test_terminal_public_both_open(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0, fp);
    struct wtq_dstream *connect_ds = find_local_bidi(&r);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);
    wtq_stream_add_ref(st);
    wtq_estream_t *es = app_bidi_es(&r, connect_ds);
    WTQ_TEST_CHECK(es != NULL);
    if (es == NULL) {
        wtq_stream_release(st);
        rig_down(&r);
        *fp += failures;
        return;
    }
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1); /* exactly once */
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_resets, 0); /* nothing forged */
    WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, NULL) ==
                   WTQ_ERR_CLOSED);
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

static void test_terminal_public_no_duplicate_after_abort(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, 0, fp);
    struct wtq_dstream *connect_ds = find_local_bidi(&r);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st) == WTQ_OK);
    wtq_stream_add_ref(st);
    wtq_estream_t *es = app_bidi_es(&r, connect_ds);
    WTQ_TEST_CHECK(es != NULL);
    if (es == NULL) {
        wtq_stream_release(st);
        rig_down(&r);
        *fp += failures;
        return;
    }
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    WTQ_TEST_CHECK(wtq_stream_abort(st, 9) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    /* the abort left a receive drain: the whole terminal resolves it
     * WITHOUT a second public terminal */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1); /* still one */
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_public_abort_terminal(&failures);
    test_terminal_public_after_reset(&failures);
    test_terminal_public_both_open(&failures);
    test_terminal_public_no_duplicate_after_abort(&failures);
    test_abort_cancels_pending_send_once(&failures);
    test_public_reset_unsupported_zero_effect(&failures);
    test_public_reset_supported(&failures);

    WTQ_TEST_PASS("test_api_abort");
    return failures;
}
