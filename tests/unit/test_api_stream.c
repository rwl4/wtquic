#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

#include "test_support.h"

/*
 * Public stream API: handle lifetime across every terminal path,
 * refcount exactly-once, per-direction closure, send-completion
 * ownership, zero-copy receive, zero-alloc steady state.
 */

#define MAX_COOKIES 8

typedef struct app {
    wtq_stream_t *opened;
    int opened_events;
    bool opened_bidi;
    int data_events;
    const uint8_t *data_ptr;
    uint8_t data_bytes[64];
    size_t data_len;
    bool data_fin;
    int reset_events;
    uint32_t reset_code;
    int stop_events;
    uint32_t stop_code;
    int closed_events;         /* per-stream terminal */
    wtq_stream_t *last_closed;
    int session_closed_events;
    int writable_events;
    wtq_stream_t *last_writable;
    struct {
        void *ctx;
        int completions;
        bool canceled;
    } cookies[MAX_COOKIES];
    size_t cookie_count;
    bool retain_in_opened;     /* add_ref from on_stream_opened */
    wtq_stream_t *retained[24]; /* handles kept alive by that add_ref */
    size_t retained_count;
    bool release_session_in_opened; /* the trap order: final session
                                       ref dropped FIRST, the stream
                                       pin taken after */
    bool send_in_data;         /* echo from the data callback */
    int send_in_data_rc;
    bool stop_and_open_in_data; /* reentrant terminal + slot reuse */
    wtq_stream_t *reused;      /* the bidi opened from the callback */
    bool release_unretained_in_data; /* release() a stream we never
                                        add_ref'd — must be a no-op */
    bool reset_then_open_in_reset;   /* reentrant terminal + reuse from
                                        the reset callback */
    wtq_stream_t *reused_in_reset;
    bool reset_then_open_in_stop;    /* reentrant terminal + reuse from
                                        the stop callback */
    wtq_stream_t *stop_stream;
    wtq_stream_t *reused_in_stop;
} app_t;

static void on_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                             bool bidi, void *user)
{
    app_t *a = user;

    (void)s;
    a->opened = st;
    a->opened_events++;
    a->opened_bidi = bidi;
    if (a->retain_in_opened) {
        wtq_stream_add_ref(st);
        if (a->retained_count < 24)
            a->retained[a->retained_count++] = st;
    }
    if (a->release_session_in_opened) {
        wtq_session_release(s); /* the only ref: destroy goes pending */
        wtq_stream_add_ref(st); /* the pin must cancel it */
    }
}

static void on_stream_data(wtq_session_t *s, wtq_stream_t *st,
                           const uint8_t *data, size_t len, bool fin,
                           void *user)
{
    app_t *a = user;

    (void)s;
    a->data_events++;
    a->data_ptr = data;
    a->data_len = len < sizeof(a->data_bytes) ? len : 0;
    if (a->data_len > 0)
        memcpy(a->data_bytes, data, a->data_len);
    a->data_fin = fin;
    if (a->send_in_data) {
        wtq_span_t span = { (const uint8_t *)"echo", 4 };
        a->send_in_data_rc =
            wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL);
    }
    if (a->stop_and_open_in_data && fin) {
        /* terminal THIS peer uni from inside its own callback (frees
         * its pooled slot), then open a new bidi that could reuse it */
        (void)wtq_stream_stop_sending(st, 5);
        (void)wtq_session_open_bidi(wtq_stream_session(st), &a->reused);
    }
    if (a->release_unretained_in_data)
        wtq_stream_release(st); /* never add_ref'd: must be a no-op */
}

static void on_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *user)
{
    app_t *a = user;

    (void)s;
    a->reset_events++;
    a->reset_code = code;
    if (a->reset_then_open_in_reset) {
        /* stop the (peer uni) receive side from inside on_stream_reset:
         * terminals it and frees its slot, then open a new bidi that
         * could reuse the slot underneath the still-unwinding adapter */
        (void)wtq_stream_stop_sending(st, 7);
        (void)wtq_session_open_bidi(wtq_stream_session(st),
                                    &a->reused_in_reset);
    }
}

static void on_stream_stop(wtq_session_t *s, wtq_stream_t *st,
                           uint32_t code, void *user)
{
    app_t *a = user;

    (void)s;
    a->stop_events++;
    a->stop_code = code;
    a->stop_stream = st;
    if (a->reset_then_open_in_stop) {
        /* reset the send-only local stream from inside on_stream_stop:
         * terminaling it frees its slot unless the adapter pins it
         * through the callback; then open a bidi that would otherwise
         * reuse the still-unwinding handle. */
        (void)wtq_stream_reset(st, 9);
        (void)wtq_session_open_bidi(wtq_stream_session(st),
                                    &a->reused_in_stop);
    }
}

static void on_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    app_t *a = user;

    (void)s;
    a->closed_events++;
    a->last_closed = st;
}

static void on_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t rlen, bool clean,
                      void *user)
{
    app_t *a = user;

    (void)s;
    (void)code;
    (void)reason;
    (void)rlen;
    (void)clean;
    a->session_closed_events++;
}

static void on_stream_writable(wtq_session_t *s, wtq_stream_t *st,
                               void *user)
{
    app_t *a = user;

    (void)s;
    a->writable_events++;
    a->last_writable = st;
}

static void on_send_complete(wtq_session_t *s, void *send_ctx,
                             bool canceled, void *user)
{
    app_t *a = user;

    (void)s;
    for (size_t i = 0; i < a->cookie_count; i++)
        if (a->cookies[i].ctx == send_ctx) {
            a->cookies[i].completions++;
            a->cookies[i].canceled = canceled;
            return;
        }
    if (a->cookie_count < MAX_COOKIES) {
        a->cookies[a->cookie_count].ctx = send_ctx;
        a->cookies[a->cookie_count].completions = 1;
        a->cookies[a->cookie_count].canceled = canceled;
        a->cookie_count++;
    }
}

static int completions_for(const app_t *a, void *ctx, bool *canceled)
{
    for (size_t i = 0; i < a->cookie_count; i++)
        if (a->cookies[i].ctx == ctx) {
            if (canceled != NULL)
                *canceled = a->cookies[i].canceled;
            return a->cookies[i].completions;
        }
    return 0;
}

typedef struct counting_alloc {
    int allocs;
    int frees;
} counting_alloc_t;

static void *count_alloc(size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    ca->allocs++;
    return malloc(size);
}

static void count_free(void *ptr, size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    (void)size;
    ca->frees++;
    free(ptr);
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_session_t *s;
    app_t app;
    counting_alloc_t ca;
    wtq_alloc_t alloc;
    wtq_estream_t *sess_es;
} rig_t;

static const char *const OFFER[] = { "moqt-18" };

static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[256];
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

static void establish_client(rig_t *r, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(&r->app, 0, sizeof(r->app));
    memset(&r->ca, 0, sizeof(r->ca));
    r->alloc = (wtq_alloc_t){ &r->ca, count_alloc, NULL, count_free };
    r->sess_es = NULL;
    fake_driver_init(&r->drv, true);

    wtq_session_events_init(&ev);
    ev.on_stream_opened = on_stream_opened;
    ev.on_stream_data = on_stream_data;
    ev.on_stream_reset = on_stream_reset;
    ev.on_stream_stop = on_stream_stop;
    ev.on_stream_closed = on_stream_closed;
    ev.on_closed = on_closed;
    ev.on_send_complete = on_send_complete;
    ev.on_stream_writable = on_stream_writable;

    wtq_api_session_cfg_t cfg = {
        .alloc = &r->alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &r->app,
        .drv = &r->drv,
        .ops = fake_driver_ops(),
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r->s) == WTQ_OK);
    if (r->s == NULL) {
        *fp += failures + 1;
        return;
    }
    WTQ_TEST_CHECK(wtq_api_session_start(r->s, 1000) == WTQ_OK);

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(r->s, &cc) == WTQ_OK);

    /* peer SETTINGS */
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    wtq_conn_t *conn = wtq_api_session_conn(r->s);
    if (conn == NULL) {
        *fp += failures + 1;
        return;
    }
    struct wtq_dstream *cds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *ces = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, cds, 3, &ces) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, ces, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);

    /* 200 response */
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            bidi = &r->drv.streams[i];
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    if (bidi == NULL) {
        *fp += failures + 1;
        return;
    }
    r->sess_es = bidi->ectx;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
    (void)wtq_conn_on_stream_bytes(conn, r->sess_es, resp, rlen, false,
                                   2000);
    WTQ_TEST_CHECK(wtq_session_status(r->s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    *fp += failures;
}

static void rig_down(rig_t *r, int *fp)
{
    int failures = 0;

    if (r->s != NULL)
        wtq_session_release(r->s);
    WTQ_TEST_CHECK(r->ca.allocs == r->ca.frees);
    *fp += failures;
}

/* Feed a peer WT stream into the session (via the engine seam). */
static wtq_estream_t *feed_peer_stream(rig_t *r, bool bidi, uint64_t id,
                                       const uint8_t *payload, size_t len,
                                       bool fin, int *fp)
{
    int failures = 0;
    uint8_t wire[128];
    size_t plen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);

    if (conn == NULL) {
        *fp += failures + 1;
        return NULL;
    }
    WTQ_TEST_CHECK(wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                            : WTQ_PREAMBLE_KIND_UNI,
                                       0, wire, sizeof(wire),
                                       &plen) == 0);
    if (len > 0)
        memcpy(wire + plen, payload, len);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, id);
    wtq_estream_t *es = NULL;
    wtq_result_t rc = bidi
                          ? wtq_conn_on_peer_bidi_opened(conn, ds, id, &es)
                          : wtq_conn_on_peer_uni_opened(conn, ds, id, &es);
    WTQ_TEST_CHECK(rc == WTQ_OK);
    (void)wtq_conn_on_stream_bytes(conn, es, wire, plen + len, fin, 3000);
    *fp += failures;
    return es;
}

/* --- basic open/data/queries ---------------------------------------------- */

static void test_peer_stream_lifecycle(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    feed_peer_stream(&r, false, 7, (const uint8_t *)"ping", 4, false, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    WTQ_TEST_CHECK(!r.app.opened_bidi);
    WTQ_TEST_CHECK(r.app.opened != NULL);
    WTQ_TEST_CHECK(r.app.data_events == 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.data_len, 4);
    WTQ_TEST_CHECK(memcmp(r.app.data_bytes, "ping", 4) == 0);
    WTQ_TEST_CHECK(!r.app.data_fin);

    wtq_stream_t *st = r.app.opened;
    WTQ_TEST_CHECK(wtq_stream_id(st) == 7);
    WTQ_TEST_CHECK(!wtq_stream_is_bidi(st));
    WTQ_TEST_CHECK(!wtq_stream_is_local(st));
    WTQ_TEST_CHECK(wtq_stream_session(st) == r.s);
    int marker = 0;
    wtq_stream_set_user(st, &marker);
    WTQ_TEST_CHECK(wtq_stream_get_user(st) == &marker);

    *fp += failures;
    rig_down(&r, fp);
}

/* Peer FIN on a uni stream: on_stream_closed exactly once, and an
 * unretained handle is gone afterwards (slot reusable). */
static void test_stream_fin_terminal(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    feed_peer_stream(&r, false, 7, (const uint8_t *)"x", 1, true, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    WTQ_TEST_CHECK(r.app.data_events == 1);
    WTQ_TEST_CHECK(r.app.data_fin);
    WTQ_TEST_CHECK(r.app.closed_events == 1);
    WTQ_TEST_CHECK(r.app.last_closed == r.app.opened);
    rig_down(&r, fp);
    *fp += failures;
}

/* Retained handle: dead-but-valid after terminal until release. */
static void test_stream_retained_after_terminal(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.retain_in_opened = true;
    feed_peer_stream(&r, false, 7, (const uint8_t *)"x", 1, true, fp);
    WTQ_TEST_CHECK(r.app.closed_events == 1);

    wtq_stream_t *st = r.app.opened;
    /* queries keep working on the retained handle */
    WTQ_TEST_CHECK(wtq_stream_id(st) == 7);
    WTQ_TEST_CHECK(wtq_stream_session(st) == r.s);
    /* operations refuse */
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) ==
                   WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wtq_stream_reset(st, 1) == WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wtq_stream_stop_sending(st, 1) == WTQ_ERR_CLOSED);
    wtq_stream_release(st);
    rig_down(&r, fp);
    *fp += failures;
}

/* Bidi: peer FIN leaves the outgoing direction usable; an echo sent
 * from inside the data callback lands on the wire; finishing our side
 * then fires the terminal. */
static void test_bidi_half_close_echo(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.send_in_data = true;
    feed_peer_stream(&r, true, 1, (const uint8_t *)"req", 3, true, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    WTQ_TEST_CHECK(r.app.opened_bidi);
    WTQ_TEST_CHECK(r.app.data_fin);
    WTQ_TEST_CHECK(r.app.send_in_data_rc == WTQ_OK); /* echo accepted */
    /* the echo (with FIN) closed our direction too: terminal fired */
    WTQ_TEST_CHECK(r.app.closed_events == 1);

    /* the echoed bytes are on the peer stream's fake wire */
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && !r.drv.streams[i].is_local &&
            r.drv.streams[i].id == 1)
            ds = &r.drv.streams[i];
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        WTQ_TEST_CHECK_EQ_SIZE(ds->len, 4);
        WTQ_TEST_CHECK(memcmp(ds->bytes, "echo", 4) == 0);
        WTQ_TEST_CHECK(ds->fin);
    }
    (void)fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.s));
    rig_down(&r, fp);
    *fp += failures;
}

/* Local streams: open, send-fin closes outgoing; a local uni is then
 * terminal (no incoming direction). */
static void test_local_stream_lifecycle(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    WTQ_TEST_CHECK(st != NULL);
    if (st == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    WTQ_TEST_CHECK(wtq_stream_is_local(st));
    WTQ_TEST_CHECK(!wtq_stream_is_bidi(st));

    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"bye", 3 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN,
                                   &cookie) == WTQ_OK);
    /* send-fin was the last direction: terminal fires */
    WTQ_TEST_CHECK(r.app.closed_events == 1);
    /* completion still reaches the app for the finished stream */
    WTQ_TEST_CHECK_EQ_SIZE(
        fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.s)),
        1);
    bool canceled = true;
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
    WTQ_TEST_CHECK(!canceled);
    rig_down(&r, fp);
    *fp += failures;
}

/* Peer reset closes incoming; local reset closes outgoing; stop
 * closes incoming locally. Terminal exactly once in each combination. */
static void test_stream_reset_stop_paths(int *fp)
{
    int failures = 0;

    /* local stop of a peer uni -> incoming closed locally, terminal */
    {
        rig_t r;
        establish_client(&r, fp);
        feed_peer_stream(&r, false, 7, (const uint8_t *)"z", 1, false,
                         fp);
        WTQ_TEST_CHECK(r.app.opened_events == 1);
        WTQ_TEST_CHECK(wtq_stream_stop_sending(r.app.opened, 9) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(r.app.closed_events == 1);
        rig_down(&r, fp);
    }
    /* local reset of a bidi keeps incoming until peer ends it */
    {
        rig_t r;
        establish_client(&r, fp);
        feed_peer_stream(&r, true, 1, (const uint8_t *)"a", 1, false, fp);
        WTQ_TEST_CHECK(r.app.opened_events == 1);
        WTQ_TEST_CHECK(wtq_stream_reset(r.app.opened, 3) == WTQ_OK);
        WTQ_TEST_CHECK(r.app.closed_events == 0); /* incoming open */
        wtq_span_t span = { (const uint8_t *)"x", 1 };
        WTQ_TEST_CHECK(wtq_stream_send(r.app.opened, &span, 1, 0,
                                       NULL) == WTQ_ERR_STATE);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* Peer reset arrives through the engine: on_stream_reset then
 * terminal (for a uni), with the mapped app code. */
static void test_peer_reset_event(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es =
        feed_peer_stream(&r, false, 7, NULL, 0, false, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    (void)wtq_conn_on_stream_reset(wtq_api_session_conn(r.s), es,
                                   wtq_app_error_to_h3(1234), 3100);
    WTQ_TEST_CHECK(r.app.reset_events == 1);
    WTQ_TEST_CHECK(r.app.reset_code == 1234);
    WTQ_TEST_CHECK(r.app.closed_events == 1);
    rig_down(&r, fp);
    *fp += failures;
}

/* Peer STOP_SENDING surfaces and the stream stays usable. */
static void test_peer_stop_event(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    /* find the engine estream for the local stream: it is the 5th
     * local (control, qpack x2, CONNECT, then this) */
    struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(uni != NULL && uni->ectx != NULL);
    if (uni == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    (void)wtq_conn_on_stop_sending(wtq_api_session_conn(r.s), uni->ectx,
                                   wtq_app_error_to_h3(42), 3100);
    WTQ_TEST_CHECK(r.app.stop_events == 1);
    WTQ_TEST_CHECK(r.app.stop_code == 42);
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_OK);
    (void)fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.s));
    rig_down(&r, fp);
    *fp += failures;
}

/* Send-completion ownership across teardown paths. */
static void test_send_completion_teardown(int *fp)
{
    int failures = 0;

    /* local reset cancels the pending completion */
    {
        rig_t r;
        establish_client(&r, fp);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
        int cookie = 0;
        wtq_span_t span = { (const uint8_t *)"pending", 7 };
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(wtq_stream_reset(st, 5) == WTQ_OK);
        (void)fake_driver_complete_sends(&r.drv,
                                         wtq_api_session_conn(r.s));
        bool canceled = false;
        WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
        WTQ_TEST_CHECK(canceled);
        rig_down(&r, fp);
    }
    /* session close cancels pending completions */
    {
        rig_t r;
        establish_client(&r, fp);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
        int cookie = 0;
        wtq_span_t span = { (const uint8_t *)"pending", 7 };
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(wtq_session_close(r.s, 0, NULL, 0) == WTQ_OK);
        WTQ_TEST_CHECK(r.app.closed_events == 1); /* stream terminal */
        WTQ_TEST_CHECK(r.app.session_closed_events == 1);
        (void)fake_driver_complete_sends(&r.drv,
                                         wtq_api_session_conn(r.s));
        bool canceled = false;
        WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
        WTQ_TEST_CHECK(canceled);
        /* sends on the dead stream refuse */
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
                       WTQ_ERR_CLOSED);
        rig_down(&r, fp);
    }
    /* connection failure cancels pending completions */
    {
        rig_t r;
        establish_client(&r, fp);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
        int cookie = 0;
        wtq_span_t span = { (const uint8_t *)"pending", 7 };
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
                       WTQ_OK);
        /* trailers on the session stream: connection error */
        uint8_t trailers[2] = { 0x01, 0x00 };
        (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s),
                                       r.sess_es, trailers, 2, false,
                                       3000);
        WTQ_TEST_CHECK(r.app.closed_events == 1);
        WTQ_TEST_CHECK(r.app.session_closed_events == 1);
        (void)fake_driver_complete_sends(&r.drv,
                                         wtq_api_session_conn(r.s));
        bool canceled = false;
        WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
        WTQ_TEST_CHECK(canceled);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* Releasing a stream the app never retained (from inside its data
 * callback) must be a no-op: it must NOT drop a session ref, must not
 * free anything early, and the stream still terminals normally. */
static void test_release_unretained_noop(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.release_unretained_in_data = true;
    feed_peer_stream(&r, false, 7, (const uint8_t *)"x", 1, true, fp);
    /* the stray release did nothing: the session is alive, the stream
     * ran its full lifecycle, and nothing was freed early */
    WTQ_TEST_CHECK(r.app.data_events == 1);
    WTQ_TEST_CHECK(r.app.closed_events == 1);
    WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    WTQ_TEST_CHECK(r.ca.frees == 0); /* creator's ref still held */
    rig_down(&r, fp); /* balances only here */
    *fp += failures;
}

/* Local-open handle-pool exhaustion: when the engine can open the
 * stream but the API pool is full (retained dead handles hold slots),
 * a bidi open must tear DOWN both engine directions — reset the send
 * side AND stop the receive side — not leak the receive side. */
static void test_local_bidi_pool_exhaustion(int *fp)
{
    int failures = 0;
    rig_t r;
    wtq_stream_t *held[16];

    establish_client(&r, fp);
    /* fill the 16-slot API pool with retained-but-terminal handles:
     * each local uni frees its ENGINE slot at terminal, so the engine
     * keeps free capacity while the API pool saturates */
    size_t n = 0;
    for (; n < 16; n++) {
        wtq_stream_t *st = NULL;
        if (wtq_session_open_uni(r.s, &st) != WTQ_OK || st == NULL)
            break;
        wtq_stream_add_ref(st);       /* app pin: holds the API slot */
        (void)wtq_stream_reset(st, 0); /* terminal: frees engine slot */
        held[n] = st;
    }
    WTQ_TEST_CHECK_EQ_SIZE(n, 16); /* API pool is now full */

    int bidi_before = r.drv.open_count;
    wtq_stream_t *extra = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &extra) ==
                   WTQ_ERR_STREAM_LIMIT);
    WTQ_TEST_CHECK(extra == NULL);
    /* the engine DID open a bidi (so its slot was free); find it */
    WTQ_TEST_CHECK(r.drv.open_count > bidi_before);
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && r.drv.streams[i].is_local &&
            r.drv.streams[i].is_bidi && r.drv.streams[i].reset)
            ds = &r.drv.streams[i];
    /* the just-opened bidi's BOTH directions were torn down */
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        WTQ_TEST_CHECK(ds->reset);
        WTQ_TEST_CHECK(ds->stopped);
        /* the no-handle cleanup is ONE whole-stream transaction */
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
        WTQ_TEST_CHECK(ds->last_shutdown.mode ==
                       WTQ_SHUTDOWN_WHOLE_STREAM);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_send &&
                       ds->last_shutdown.abort_recv);
    }

    for (size_t i = 0; i < n; i++)
        wtq_stream_release(held[i]);
    rig_down(&r, fp);
    *fp += failures;
}

/* A callback that terminals its own stream and immediately opens a new
 * one must not let the pooled slot be reused underneath the still-
 * unwinding adapter: the new stream's receive side must stay open. */
static void test_reentrant_terminal_reuse(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.stop_and_open_in_data = true;
    /* peer uni delivers "x" with FIN: the data callback stops it
     * (terminal) then opens a new bidi */
    feed_peer_stream(&r, false, 7, (const uint8_t *)"x", 1, true, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    WTQ_TEST_CHECK(r.app.reused != NULL);
    if (r.app.reused == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    /* the new bidi's receive side is UNTOUCHED: stop_sending is legal
     * (recv still open) and it has not terminaled early */
    WTQ_TEST_CHECK(wtq_stream_is_bidi(r.app.reused));
    WTQ_TEST_CHECK(wtq_stream_stop_sending(r.app.reused, 1) == WTQ_OK);
    rig_down(&r, fp);
    *fp += failures;
}

/* The same reentrant-reuse guard on the reset callback path: stopping
 * the stream from inside on_stream_reset frees its slot, and a bidi
 * opened right after must not be corrupted by the adapter's post-
 * callback recv update. */
static void test_reentrant_terminal_reuse_on_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.reset_then_open_in_reset = true;
    wtq_estream_t *es =
        feed_peer_stream(&r, false, 7, NULL, 0, false, fp);
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    (void)wtq_conn_on_stream_reset(wtq_api_session_conn(r.s), es,
                                   wtq_app_error_to_h3(3), 3100);
    WTQ_TEST_CHECK(r.app.reset_events == 1);
    WTQ_TEST_CHECK(r.app.reused_in_reset != NULL);
    if (r.app.reused_in_reset != NULL) {
        WTQ_TEST_CHECK(wtq_stream_is_bidi(r.app.reused_in_reset));
        WTQ_TEST_CHECK(wtq_stream_stop_sending(r.app.reused_in_reset,
                                               1) == WTQ_OK);
    }
    rig_down(&r, fp);
    *fp += failures;
}

/* The STOP_SENDING callback has the same handle-identity hazard: a
 * local uni can be reset from inside on_stream_stop, then a new bidi
 * opened before the adapter unwinds. */
static void test_reentrant_terminal_reuse_on_stop(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    if (st == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }

    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && r.drv.streams[i].is_local &&
            !r.drv.streams[i].is_bidi &&
            r.drv.streams[i].id == wtq_stream_id(st))
            ds = &r.drv.streams[i];
    WTQ_TEST_CHECK(ds != NULL && ds->ectx != NULL);
    if (ds == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }

    r.app.reset_then_open_in_stop = true;
    (void)wtq_conn_on_stop_sending(wtq_api_session_conn(r.s), ds->ectx,
                                   wtq_app_error_to_h3(4), 3100);
    WTQ_TEST_CHECK(r.app.stop_events == 1);
    WTQ_TEST_CHECK(r.app.closed_events == 1);
    WTQ_TEST_CHECK(r.app.reused_in_stop != NULL);
    WTQ_TEST_CHECK(r.app.reused_in_stop != r.app.stop_stream);
    if (r.app.reused_in_stop != NULL) {
        WTQ_TEST_CHECK(wtq_stream_is_bidi(r.app.reused_in_stop));
        WTQ_TEST_CHECK(wtq_stream_stop_sending(r.app.reused_in_stop,
                                               1) == WTQ_OK);
    }
    rig_down(&r, fp);
    *fp += failures;
}

/* Zero-copy receive: the data pointer is the transport's buffer. */
static void test_receive_zero_copy(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t wire[16];
    size_t plen = 0;
    WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 0, wire,
                                       sizeof(wire), &plen) == 0);
    memcpy(wire + plen, "zc", 2);
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(conn, es, wire, plen + 2, false,
                                   3000);
    WTQ_TEST_CHECK(r.app.data_events == 1);
    WTQ_TEST_CHECK(r.app.data_ptr == wire + plen);
    rig_down(&r, fp);
    *fp += failures;
}

/* The stream data path allocates nothing after session setup. */
static void test_stream_zero_alloc(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    int allocs = r.ca.allocs;
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(uni != NULL);
    wtq_span_t span = { (const uint8_t *)"0123456789abcdef", 16 };
    for (int i = 0; i < 100 && uni != NULL; i++) {
        uni->len = 0; /* recycle the fake wire log */
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_OK);
        (void)fake_driver_complete_sends(&r.drv,
                                         wtq_api_session_conn(r.s));
    }
    WTQ_TEST_CHECK(r.ca.allocs == allocs);
    rig_down(&r, fp);
    *fp += failures;
}

/* The writable edge crosses the whole stack: a send refused with
 * WOULD_BLOCK, then the backend's writable input, must surface as the
 * public on_stream_writable with the same handle — and only for WT
 * data streams (the CONNECT stream never gathers against a budget). */
static void test_stream_writable_edge(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    if (st == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }

    /* the driver refuses: WOULD_BLOCK surfaces to the caller, no
     * completion will fire */
    r.drv.fail_send = true;
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"blocked", 7 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
                   WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK(r.app.writable_events == 0);
    r.drv.fail_send = false;

    /* backend reports the stream writable: the public event fires with
     * the refused stream's handle */
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && r.drv.streams[i].is_local &&
            !r.drv.streams[i].is_bidi &&
            r.drv.streams[i].id == wtq_stream_id(st))
            ds = &r.drv.streams[i];
    WTQ_TEST_CHECK(ds != NULL && ds->ectx != NULL);
    if (ds != NULL) {
        wtq_conn_on_stream_writable(wtq_api_session_conn(r.s),
                                    ds->ectx);
        WTQ_TEST_CHECK(r.app.writable_events == 1);
        WTQ_TEST_CHECK(r.app.last_writable == st);
        /* the retried send goes through */
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN,
                                       &cookie) == WTQ_OK);
    }

    /* a non-WT stream (the CONNECT/session stream) never surfaces
     * writable */
    wtq_conn_on_stream_writable(wtq_api_session_conn(r.s), r.sess_es);
    WTQ_TEST_CHECK(r.app.writable_events == 1);

    (void)fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.s));
    rig_down(&r, fp);
    *fp += failures;
}

/* Releasing the final session ref inside on_stream_opened and THEN
 * retaining the stream: the pin must cancel the deferred destruction
 * and keep the session alive past the callback; releasing the retained
 * stream later frees the session exactly once. */
static void test_stream_pin_resurrects_session(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.release_session_in_opened = true;

    wtq_api_session_enter(r.s);
    (void)feed_peer_stream(&r, false, 7, NULL, 0, false, fp);
    bool destroyed = wtq_api_session_leave(r.s);
    WTQ_TEST_CHECK(!destroyed);
    WTQ_TEST_CHECK(r.ca.frees == 0);
    if (destroyed || r.ca.frees != 0) {
        /* freed despite the stream pin: do not touch it again */
        r.s = NULL;
        *fp += failures;
        return;
    }
    WTQ_TEST_CHECK(r.app.opened_events == 1);
    WTQ_TEST_CHECK(r.app.opened != NULL);
    /* the stream pin is now the only thing keeping the session: drop
     * it and everything frees exactly once */
    wtq_stream_release(r.app.opened);
    r.s = NULL;
    WTQ_TEST_CHECK(r.ca.allocs == r.ca.frees);
    *fp += failures;
}

/* Feed a peer WT stream and return its transport stream. */
static struct wtq_dstream *feed_peer_stream_ds(rig_t *r, bool bidi,
                                               uint64_t id,
                                               const uint8_t *payload,
                                               size_t len, bool fin,
                                               int *fp)
{
    int failures = 0;
    uint8_t wire[128];
    size_t plen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);

    WTQ_TEST_CHECK(conn != NULL);
    if (conn == NULL) {
        *fp += failures;
        return NULL;
    }
    WTQ_TEST_CHECK(wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                            : WTQ_PREAMBLE_KIND_UNI,
                                       0, wire, sizeof(wire),
                                       &plen) == 0);
    if (len > 0)
        memcpy(wire + plen, payload, len);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, id);
    wtq_estream_t *es = NULL;
    wtq_result_t rc = bidi
                          ? wtq_conn_on_peer_bidi_opened(conn, ds, id, &es)
                          : wtq_conn_on_peer_uni_opened(conn, ds, id, &es);
    WTQ_TEST_CHECK(rc == WTQ_OK);
    if (es != NULL)
        ds->ectx = es;
    (void)wtq_conn_on_stream_bytes(conn, es, wire, plen + len, fin, 3000);
    *fp += failures;
    return ds;
}

/* When the ADAPTER's handle pool is exhausted, the associated stream is
 * rejected with the exact WebTransport wire codepoint — not application
 * error 0 pushed through the normal mapper — and becomes a drain
 * tombstone, so bytes riding the same receive event never surface. */
static void test_adapter_pool_exhaustion(int *fp)
{
    int failures = 0;

    for (int bidi = 0; bidi < 2; bidi++) {
        rig_t r;

        establish_client(&r, fp);
        r.app.retain_in_opened = true;
        /* Fill every adapter handle: each stream ends with a FIN, so
         * its ENGINE slot is released while the retained handle keeps
         * its adapter slot occupied. */
        for (uint64_t i = 0; i < 16; i++)
            (void)feed_peer_stream_ds(&r, false, 3 + 4 * i, NULL, 0, true,
                                      fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.opened_events, 16);
        WTQ_TEST_CHECK_EQ_SIZE(r.app.retained_count, 16);

        /* one more peer stream, carrying payload in the SAME delivery */
        int data_before = r.app.data_events;
        static const uint8_t PAY[4] = { 'd', 'a', 't', 'a' };
        struct wtq_dstream *ds =
            feed_peer_stream_ds(&r, bidi != 0, 900, PAY, sizeof(PAY),
                                false, fp);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds == NULL) {
            rig_down(&r, fp);
            continue;
        }

        /* refused with the protocol's codepoint, no app-error mapping */
        WTQ_TEST_CHECK(ds->stopped);
        WTQ_TEST_CHECK_EQ_HEX(ds->stop_err,
                              WTQ_WT_BUFFERED_STREAM_REJECTED);
        WTQ_TEST_CHECK(ds->stop_err != wtq_app_error_to_h3(0));
        if (bidi) {
            WTQ_TEST_CHECK(ds->reset);
            WTQ_TEST_CHECK_EQ_HEX(ds->reset_err,
                                  WTQ_WT_BUFFERED_STREAM_REJECTED);
        }
        /* no handle, no callback, and the queued bytes were absorbed */
        WTQ_TEST_CHECK_EQ_INT(r.app.opened_events, 16);
        WTQ_TEST_CHECK_EQ_INT(r.app.data_events, data_before);

        /* more bytes on the rejected stream stay absorbed */
        WTQ_TEST_CHECK(ds->ectx != NULL);
        if (ds->ectx != NULL)
            (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s),
                                           ds->ectx, PAY, sizeof(PAY),
                                           false, 3100);
        WTQ_TEST_CHECK_EQ_INT(r.app.data_events, data_before);

        for (size_t i = 0; i < r.app.retained_count; i++)
            wtq_stream_release(r.app.retained[i]);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* A recycled adapter handle must be unreachable through an old
 * estream's backlink: after stream_terminal() severs a handle, a late
 * engine event on the surviving drain-tombstone estream must not
 * dispatch onto the slot's next occupant. */
static void test_stale_backlink_after_handle_reuse(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_stream_t *st1 = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st1) == WTQ_OK);
    /* 5th local fake stream: control, qpack x2, CONNECT, then this */
    struct wtq_dstream *ds1 = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(ds1 != NULL && ds1->ectx != NULL);
    if (ds1 == NULL || ds1->ectx == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    wtq_estream_t *es1 = ds1->ectx;

    /* the app finishes with the stream: terminal, handle slot free;
     * the ENGINE estream survives as a receive-drain tombstone */
    WTQ_TEST_CHECK(wtq_stream_reset(st1, 1) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_stop_sending(st1, 2) == WTQ_OK);
    WTQ_TEST_CHECK(r.app.closed_events == 1);

    wtq_stream_t *st2 = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.s, &st2) == WTQ_OK);
    WTQ_TEST_CHECK(st2 == st1); /* the handle slot was recycled */

    /* a late peer STOP_SENDING reaches the tombstone estream: it must
     * not dispatch onto the recycled handle */
    int stops_before = r.app.stop_events;
    (void)wtq_conn_on_stop_sending(wtq_api_session_conn(r.s), es1,
                                   wtq_app_error_to_h3(5), 4000);
    WTQ_TEST_CHECK(r.app.stop_events == stops_before);

    /* the new stream still works */
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    WTQ_TEST_CHECK(wtq_stream_send(st2, &span, 1, 0, NULL) == WTQ_OK);
    (void)fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.s));
    rig_down(&r, fp);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_peer_stream_lifecycle(&failures);
    test_stream_fin_terminal(&failures);
    test_stream_retained_after_terminal(&failures);
    test_bidi_half_close_echo(&failures);
    test_local_stream_lifecycle(&failures);
    test_stream_reset_stop_paths(&failures);
    test_peer_reset_event(&failures);
    test_peer_stop_event(&failures);
    test_send_completion_teardown(&failures);
    test_release_unretained_noop(&failures);
    test_local_bidi_pool_exhaustion(&failures);
    test_reentrant_terminal_reuse(&failures);
    test_reentrant_terminal_reuse_on_reset(&failures);
    test_reentrant_terminal_reuse_on_stop(&failures);
    test_receive_zero_copy(&failures);
    test_stream_zero_alloc(&failures);
    test_stream_writable_edge(&failures);
    test_adapter_pool_exhaustion(&failures);
    test_stream_pin_resurrects_session(&failures);
    test_stale_backlink_after_handle_reuse(&failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_api_stream (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_api_stream\n");
    return 0;
}
