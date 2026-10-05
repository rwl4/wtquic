/* Deterministic receive-only rig: include private implementations rather
 * than adding installed test hooks. No Apple connection is created/started.
 * Establishment is seeded; bytes, API callbacks, pause and replay are real. */
#include "../../src/engine/conn.c"
#include "../../backends/network/nw_conn.c"
#include "test_support.h"

static struct {
    wtq_stream_t *stream;
    bool pause_open;
    bool pause_data;
    size_t bytes;
    size_t maximum;
    int calls;
    int fins;
    int bad_bytes;
    int bad_pause;
    int action;
    int reentry_calls;
    wtq_result_t reentry_rc;
    int depth;
    int max_depth;
} capture;

static void opened(wtq_session_t *s, wtq_stream_t *st, bool bidi, void *u)
{
    (void)s; (void)bidi; (void)u;
    capture.stream = st;
    wtq_stream_add_ref(st);
    if (capture.pause_open && wtq_stream_pause_receive(st) != WTQ_OK)
        capture.bad_pause++;
}

static void bytes(wtq_session_t *s, wtq_stream_t *st, const uint8_t *p,
                  size_t n, bool fin, void *u)
{
    (void)s; (void)u;
    capture.depth++;
    if (capture.depth > capture.max_depth)
        capture.max_depth = capture.depth;
    capture.calls++;
    if (n > capture.maximum)
        capture.maximum = n;
    for (size_t i = 0; i < n; i++)
        if (p[i] != (uint8_t)((capture.bytes + i) % 251))
            capture.bad_bytes++;
    capture.bytes += n;
    capture.fins += fin;
    if ((capture.action == 1 || capture.action == 2) && capture.calls == 1) {
        wtq_result_t rc = capture.action == 1 ? wtq_stream_stop_sending(st, 42) :
            wtq_session_close(s, 42, NULL, 0);
        if (rc != WTQ_OK)
            capture.bad_pause++;
    }
    if (capture.pause_data && !fin && wtq_stream_pause_receive(st) != WTQ_OK)
        capture.bad_pause++;
    if (capture.action >= 4 && capture.calls == 1) {
        capture.reentry_calls++;
        if ((capture.action == 5 || capture.action == 6) &&
            wtq_stream_pause_receive(st) != WTQ_OK)
            capture.bad_pause++;
        capture.reentry_rc = wtq_stream_resume_receive(st);
        /* Leave nonterminal input paused so this receive-only rig does not
         * start an Apple receive. Resume above still traverses the real op. */
        if (capture.action == 6 && wtq_stream_pause_receive(st) != WTQ_OK)
            capture.bad_pause++;
    }
    capture.depth--;
}

static wtq_result_t no_shutdown(wtq_driver_t *drv, wtq_dstream_t *ds,
                                const wtq_shutdown_t *req)
{
    (void)drv; (void)req;
    ds_drop_deferred(ds);
    ds->cancel_deferred = true; /* stamped-cancel storage effect, no Apple I/O */
    return WTQ_OK;
}

static wtq_result_t no_send(wtq_driver_t *drv, wtq_dstream_t *ds,
                            const uint8_t *p, size_t n, bool fin)
{
    (void)drv; (void)ds; (void)p; (void)n; (void)fin;
    return WTQ_OK;
}

static wtq_result_t no_close(wtq_driver_t *drv, uint64_t code)
{
    (void)drv; (void)code;
    return WTQ_OK;
}

static int run_row(size_t payload, bool coalesced_pause, int action)
{
    int failures = 0;
    memset(&capture, 0, sizeof(capture));
    capture.pause_open = coalesced_pause;
    capture.pause_data = coalesced_pause || action == 3;
    capture.action = action;
    struct wtq_driver drv = { .alloc = *wtq_alloc_default(),
                              .shutdown_started = true };
    wtq_driver_ops_t ops = nw_driver_ops;
    ops.shutdown_stream = no_shutdown;
    ops.send = no_send;
    ops.conn_close = no_close;
    wtq_session_events_t events;
    wtq_session_events_init(&events);
    events.on_stream_opened = opened;
    events.on_stream_data = bytes;
    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(), .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &events, .drv = &drv, .ops = &ops,
    };
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_create(&cfg, &drv.session), WTQ_OK);
    if (drv.session == NULL)
        return failures;
    wtq_conn_t *ec = wtq_api_session_conn(drv.session);
    ec->session_established = true;
    ec->sess_state = SS_ESTABLISHED;
    ec->session_id = 0;
    struct wtq_dstream ds = { .drv = &drv, .recv_enabled = true,
                              .quarantined = true, .id = 7 };
    struct wtq_estream connect = { .kind = ES_CONNECT, .ds = &ds };
    ec->session_es = &connect;
    ds.conn = (nw_connection_t)(void *)&ds; /* never passed to Apple */
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_peer_uni_opened(ec, &ds, 7, &ds.ectx),
                          WTQ_OK);
    uint8_t *wire = malloc(payload + 8);
    WTQ_TEST_CHECK(wire != NULL);
    if (wire == NULL)
        return failures;
    size_t pre = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 0,
        wire, 8, &pre), WTQ_PREAMBLE_OK);
    for (size_t i = 0; i < payload; i++)
        wire[pre + i] = (uint8_t)(i % 251);
    bool multiregion = coalesced_pause && payload > 5;
    size_t first = multiregion ? pre + 2 : pre + payload;
    __block int disposed = 0;
    dispatch_queue_t disposal = dispatch_queue_create("wtq.accounted.dispose", NULL);
    dispatch_data_t a = action >= 4
        ? dispatch_data_create(wire, first, disposal, ^{ disposed++; })
        : dispatch_data_create(wire, first, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    dispatch_data_t all = a;
    if (multiregion) {
        dispatch_data_t b = dispatch_data_create(wire + first, 3, NULL,
                                                 DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        dispatch_data_t c = dispatch_data_create(wire + first + 3,
            payload - 5, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        dispatch_data_t ab = dispatch_data_create_concat(a, b);
        all = dispatch_data_create_concat(ab, c);
        dispatch_release(ab); dispatch_release(a);
        dispatch_release(b); dispatch_release(c);
        __block int regions = 0;
        dispatch_data_apply(all, ^bool(dispatch_data_t r, size_t off,
                                       const void *p, size_t n) {
            (void)r; (void)off; (void)p; (void)n; regions++; return true;
        });
        WTQ_TEST_CHECK_EQ_INT(regions, 3);
    }
    ds_receive_completed(&ds, all, action != 6 && action != 7, action == 7, false);
    if (action == 6) {
        WTQ_TEST_CHECK_EQ_INT(capture.reentry_rc, WTQ_OK);
        WTQ_TEST_CHECK(!ds.recv_enabled);
        WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, payload);
        ds_receive_completed(&ds, NULL, true, false, false);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(capture.stream), WTQ_OK);
    }
    if (action == 3 || action == 5) {
        WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, 65535);
        WTQ_TEST_CHECK_EQ_INT(capture.fins, 0);
        WTQ_TEST_CHECK(ds.recv_deferred);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(capture.stream), WTQ_OK);
    }
    if (coalesced_pause) {
        WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, 0);
        WTQ_TEST_CHECK_EQ_INT(capture.fins, 0);
        WTQ_TEST_CHECK(ds.recv_deferred);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(capture.stream), WTQ_OK);
    }
    if (multiregion) {
        WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, 2);
        WTQ_TEST_CHECK_EQ_INT(capture.fins, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(capture.stream), WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, 5);
        WTQ_TEST_CHECK_EQ_INT(capture.fins, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(capture.stream), WTQ_OK);
    }
    bool terminal_action = action == 1 || action == 2;
    WTQ_TEST_CHECK_EQ_SIZE(capture.bytes, terminal_action ? 65535 : payload);
    WTQ_TEST_CHECK_EQ_INT(capture.fins, terminal_action || action == 7 ? 0 : 1);
    WTQ_TEST_CHECK_EQ_INT(capture.bad_bytes, 0);
    WTQ_TEST_CHECK_EQ_INT(capture.bad_pause, 0);
    WTQ_TEST_CHECK(capture.maximum <= 65535);
    WTQ_TEST_CHECK(!ds.recv_deferred);
    WTQ_TEST_CHECK(ds.fin_delivered == (action != 7));
    if (action >= 4) {
        WTQ_TEST_CHECK_EQ_INT(capture.reentry_calls, 1);
        WTQ_TEST_CHECK_EQ_INT(capture.max_depth, 1);
        WTQ_TEST_CHECK_EQ_INT(capture.reentry_rc,
            action == 6 ? WTQ_OK : WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT(disposed, 0); /* caller still owns its borrow */
    }
    dispatch_release(all);
    dispatch_sync(disposal, ^{});
    if (action >= 4)
        WTQ_TEST_CHECK_EQ_INT(disposed, 1);
    dispatch_release(disposal);
    free(wire);
    if (capture.stream != NULL)
        wtq_stream_release(capture.stream);
    wtq_session_release(drv.session);
    return failures;
}

int main(void)
{
    int failures = run_row(7, true, 0);
    failures += run_row(0, true, 0);
    failures += run_row(65534, false, 0);
    failures += run_row(65535, false, 0);
    failures += run_row(65536, false, 0);
    failures += run_row(65536, false, 1);
    failures += run_row(65536, false, 2);
    failures += run_row(65536, false, 3);
    failures += run_row(3, true, 7);  /* held content+error, inner resume refused */
    failures += run_row(0, true, 4);  /* held pure FIN, inner resume refused */
    failures += run_row(65536, false, 5); /* terminal suffix survives inner pause */
    failures += run_row(7, false, 6); /* nonterminal pause/resume stays legal */
    return failures;
}
