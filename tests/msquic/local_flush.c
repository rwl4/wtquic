/* Fake provider, real driver/engine/API callbacks. No sockets or provider work. */
#include "msq_internal.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_err.h"
#include "proto/h3_settings.h"
#include "test_support.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct rig {
    QUIC_API_TABLE api;
    wtq_alloc_t alloc;
    pthread_mutex_t lane;
    struct wtq_driver *drv;
    wtq_session_t *session;
    struct { struct wtq_dstream *ds; void *ctx; } sends[128];
    size_t sent, completed, live;
    unsigned allocations, provider_calls, callbacks, entered, returned, commits;
    int errors;
    bool refuse, buffered, check_return;
    bool sync_complete, check_contention;
    bool shutdown_inline, shutdown_graceful, shutdown_borrow;
    bool shutdown_query;
    bool shutdown_nested;
    unsigned shutdown_calls, shutdown_refuse_at;
    wtq_stream_t *nested_reset;
    bool replace_after_reset;
    wtq_stream_t *replacement, *last_committed;
    struct wtq_dstream *replacement_ds;
    wtq_estream_t *replacement_es;
    uint64_t replacement_generation, replacement_id, original_id;
    unsigned original_closures, replacement_closures;
    bool terminal_loss;
    bool capture_terminal_detail;
    unsigned closed_count;
    wtq_result_t closed_flush;
    wtq_transport_error_t closed_detail;
    unsigned contention_attempts, contention_queries;
    void *dgram_ctx;
    QUIC_SETTINGS configured;
    wtq_result_t return_result;
    wtq_result_t expected_commit_flush;
    bool trace_commit_contract;
    unsigned canceled_returns, stream_terminals, callback_sequence;
    unsigned last_return_sequence, last_commit_sequence, last_terminal_sequence;
    void *last_return_cookie;
    wtq_stream_t *last_terminal;
};

static void *allocate(size_t size, void *ctx)
{
    struct rig *r = ctx;
    void *p = malloc(size);
    if (p) { r->allocations++; r->live++; }
    return p;
}

static void deallocate(void *p, size_t size, void *ctx)
{
    (void)size;
    if (p) { ((struct rig *)ctx)->live--; free(p); }
}

static void *reallocate(void *p, size_t old_size, size_t size, void *ctx)
{
    (void)old_size;
    struct rig *r = ctx;
    void *next = realloc(p, size);
    if (next) { r->allocations++; if (!p) r->live++; }
    return next;
}

static struct rig *owner(HQUIC h)
{
    return ((struct wtq_dstream *)(void *)h)->drv->alloc.ctx;
}

static QUIC_STATUS QUIC_API stream_open(HQUIC conn, QUIC_STREAM_OPEN_FLAGS flags,
    QUIC_STREAM_CALLBACK_HANDLER cb, void *ctx, HQUIC *out)
{
    (void)flags; (void)cb;
    struct wtq_driver *d = (void *)conn;
    ((struct rig *)d->alloc.ctx)->provider_calls++;
    *out = (HQUIC)ctx;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API stream_start(HQUIC h, QUIC_STREAM_START_FLAGS flags)
{
    (void)flags;
    owner(h)->provider_calls++;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API stream_send(HQUIC h, const QUIC_BUFFER *bufs,
    uint32_t count, QUIC_SEND_FLAGS flags, void *ctx)
{
    (void)bufs; (void)count; (void)flags;
    struct rig *r = owner(h);
    r->provider_calls++;
    if (r->refuse || r->sent == 128) return QUIC_STATUS_INVALID_STATE;
    if (r->sync_complete) {
        QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SEND_COMPLETE };
        ev.SEND_COMPLETE.ClientContext = ctx;
        (void)wtq_msq_stream_callback(h, (void *)h, &ev);
        return QUIC_STATUS_SUCCESS;
    }
    r->sends[r->sent].ds = (void *)h;
    r->sends[r->sent++].ctx = ctx;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API stream_shutdown(HQUIC h,
    QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    (void)code;
    struct rig *r = owner(h);
    r->provider_calls++;
    r->shutdown_calls++;
    if (r->shutdown_query && wtq_session_local_flush(r->session) !=
        WTQ_ERR_WOULD_BLOCK) r->errors++;
    if (r->shutdown_nested) {
        r->shutdown_nested = false;
        bool refuse = r->refuse;
        r->refuse = true;
        wtq_shutdown_t req = { .abort_send = true, .app_send_cancel = true };
        if (wtq_msq_driver_ops()->shutdown_stream(
            ((struct wtq_dstream *)(void *)h)->drv, (void *)h, &req) !=
            WTQ_ERR_BACKEND) r->errors++;
        r->refuse = refuse;
        r->shutdown_inline = false; /* the one native completion already ran */
    }
    if (r->shutdown_inline && (flags & QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND)) {
        if (r->shutdown_borrow && r->completed < r->sent) {
            size_t i = r->completed++;
            QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SEND_COMPLETE };
            ev.SEND_COMPLETE.ClientContext = r->sends[i].ctx;
            ev.SEND_COMPLETE.Canceled = TRUE;
            (void)wtq_msq_stream_callback(h, (void *)h, &ev);
        }
        QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE };
        ev.SEND_SHUTDOWN_COMPLETE.Graceful = r->shutdown_graceful;
        (void)wtq_msq_stream_callback(h, (void *)h, &ev);
        if (r->shutdown_query && wtq_session_local_flush(r->session) !=
            WTQ_ERR_WOULD_BLOCK) r->errors++;
    }
    return r->refuse || r->shutdown_calls == r->shutdown_refuse_at ?
        QUIC_STATUS_INVALID_STATE : QUIC_STATUS_SUCCESS;
}

static void QUIC_API stream_close(HQUIC h) { owner(h)->provider_calls++; }
static void QUIC_API conn_close(HQUIC h)
{
    struct wtq_driver *d = (void *)h;
    ((struct rig *)d->alloc.ctx)->provider_calls++;
}
static void QUIC_API conn_shutdown(HQUIC h, QUIC_CONNECTION_SHUTDOWN_FLAGS f,
    QUIC_UINT62 code)
{
    (void)f; (void)code;
    conn_close(h);
}

static QUIC_STATUS QUIC_API datagram_send(HQUIC h, const QUIC_BUFFER *bufs,
    uint32_t count, QUIC_SEND_FLAGS flags, void *ctx)
{
    (void)bufs; (void)count; (void)flags;
    struct wtq_driver *d = (void *)h;
    struct rig *r = d->alloc.ctx;
    r->provider_calls++;
    r->dgram_ctx = ctx;
    return QUIC_STATUS_SUCCESS;
}

static void enter(void *ctx)
{
    struct rig *r = ctx;
    pthread_mutex_lock(&r->lane);
    r->entered++;
}
static void leave(void *ctx)
{
    struct rig *r = ctx;
    r->entered--;
    pthread_mutex_unlock(&r->lane);
}

static void *try_observe(void *ctx)
{
    struct rig *r = ctx;
    r->contention_attempts++;
    int rc = pthread_mutex_trylock(&r->lane);
    if (rc == 0) {
        /* Consumer composition may only read WT after successful entry. */
        r->contention_queries++;
        (void)wtq_session_local_flush(r->session);
        pthread_mutex_unlock(&r->lane);
    } else if (rc != EBUSY) r->errors++;
    return NULL;
}

static void established(wtq_session_t *s, wtq_str_t protocol, void *ctx)
{
    (void)protocol;
    struct rig *r = ctx;
    r->callbacks++;
    /* Bootstrap/control/CONNECT remain accepted but uncompleted. */
    if (wtq_session_local_flush(s) !=
        (r->buffered ? WTQ_ERR_UNSUPPORTED : WTQ_ERR_WOULD_BLOCK)) r->errors++;
}

static void returned(wtq_session_t *s, void *cookie, bool canceled, void *ctx)
{
    struct rig *r = ctx;
    r->callbacks++; r->returned++;
    if (r->trace_commit_contract) {
        r->canceled_returns += canceled;
        r->last_return_cookie = cookie;
        r->last_return_sequence = ++r->callback_sequence;
    }
    if (!r->entered) r->errors++;
    if (r->check_return && wtq_session_local_flush(s) != r->return_result)
        r->errors++;
    if (r->nested_reset) {
        r->sync_complete = false; /* one inline event; replacement sends queue */
        wtq_stream_t *st = r->nested_reset;
        r->nested_reset = NULL;
        bool refuse = r->refuse, inline_event = r->shutdown_inline;
        r->refuse = r->shutdown_inline = false;
        if (wtq_stream_reset(st, 43) != WTQ_OK) r->errors++;
        if (wtq_session_local_flush(s) != WTQ_ERR_WOULD_BLOCK) r->errors++;
        if (r->replace_after_reset) {
            static const uint8_t byte = 17;
            wtq_span_t span = { .data = &byte, .len = 1 };
            if (wtq_session_open_uni(s, &r->replacement) != WTQ_OK) r->errors++;
            r->replacement_ds = r->drv->streams;
            r->replacement_es = r->replacement_ds->ectx;
            r->replacement_generation = wtq_estream_generation_v1(r->replacement_es);
            r->replacement_id = wtq_stream_id(r->replacement);
            if (wtq_stream_enable_send_commit(r->replacement) != WTQ_OK) r->errors++;
            if (wtq_stream_send(r->replacement, &span, 1, 0, r) != WTQ_OK) r->errors++;
        }
        r->refuse = refuse; r->shutdown_inline = inline_event;
    }
    if (r->check_contention) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, try_observe, r) != 0) r->errors++;
        else if (pthread_join(thread, NULL) != 0) r->errors++;
    }
}

static void committed(wtq_session_t *s, wtq_stream_t *st, void *ctx)
{
    struct rig *r = ctx;
    r->callbacks++; r->commits++;
    r->last_committed = st;
    if (r->trace_commit_contract)
        r->last_commit_sequence = ++r->callback_sequence;
    if (wtq_session_local_flush(s) != r->expected_commit_flush) r->errors++;
}

static void stream_closed(wtq_session_t *s, wtq_stream_t *st, void *ctx)
{
    (void)s;
    struct rig *r = ctx;
    if (r->trace_commit_contract) {
        r->stream_terminals++;
        r->last_terminal = st;
        r->last_terminal_sequence = ++r->callback_sequence;
    }
    if (!r->replace_after_reset) return;
    if (wtq_stream_id(st) == r->original_id) r->original_closures++;
    if (r->replacement && wtq_stream_id(st) == r->replacement_id)
        r->replacement_closures++;
}

static void closed(wtq_session_t *s, uint32_t code, const uint8_t *reason,
    size_t len, bool clean, void *ctx)
{
    (void)code; (void)reason; (void)len; (void)clean;
    struct rig *r = ctx;
    r->callbacks++;
    r->closed_count++;
    r->closed_flush = wtq_session_local_flush(s);
    if (r->capture_terminal_detail) {
        r->closed_detail.struct_size = sizeof(r->closed_detail);
        if (wtq_session_transport_error(s, &r->closed_detail) != WTQ_OK) r->errors++;
    }
    if (r->closed_flush !=
        (r->terminal_loss ? WTQ_ERR_BACKEND : WTQ_ERR_CLOSED)) r->errors++;
}

static void event(struct wtq_dstream *ds, QUIC_STREAM_EVENT_TYPE type, bool value)
{
    QUIC_STREAM_EVENT ev = { .Type = type };
    if (type == QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE)
        ev.SEND_SHUTDOWN_COMPLETE.Graceful = value;
    (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
}

static void complete(struct rig *r, bool canceled)
{
    size_t i = r->completed++;
    QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SEND_COMPLETE };
    ev.SEND_COMPLETE.ClientContext = r->sends[i].ctx;
    ev.SEND_COMPLETE.Canceled = canceled;
    struct wtq_dstream *ds = r->sends[i].ds;
    (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
}

static void complete_all(struct rig *r)
{
    while (r->completed < r->sent) complete(r, false);
    r->sent = r->completed = 0;
}

static int setup(struct rig *r, bool buffered, bool bounded)
{
    memset(r, 0, sizeof(*r));
    if (pthread_mutex_init(&r->lane, NULL) != 0) return 1;
    r->buffered = buffered;
    r->alloc = (wtq_alloc_t){ .alloc = allocate, .realloc = reallocate,
        .free = deallocate, .ctx = r };
    r->api = (QUIC_API_TABLE){ .StreamOpen = stream_open,
        .StreamStart = stream_start, .StreamSend = stream_send,
        .StreamShutdown = stream_shutdown, .StreamClose = stream_close,
        .ConnectionShutdown = conn_shutdown, .ConnectionClose = conn_close,
        .DatagramSend = datagram_send };
    r->drv = wtq_msq_conn_new(&r->alloc, &r->api, true);
    if (!r->drv) return 1;
    r->drv->conn = (HQUIC)(void *)r->drv;
    r->drv->guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = r };
    wtq_session_events_t ev = WTQ_SESSION_EVENTS_INIT;
    ev.on_established = established; ev.on_send_complete = returned;
    ev.on_stream_send_committed = committed; ev.on_closed = closed;
    ev.on_stream_closed = stream_closed;
    wtq_api_session_cfg_t cfg = { .alloc = &r->alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT, .events = &ev, .user = r,
        .drv = r->drv, .ops = wtq_msq_driver_ops() };
    wtq_msquic_tuning_t t;
    wtq_msquic_tuning_init(&t);
    t.send_buffering = buffered;
    if (!bounded) t.peer_unidi_stream_count++;
    if (wtq_msq_session_create_bounded(r->drv, &cfg, &t, &r->session) != WTQ_OK)
        return 1;
    r->drv->session = r->session;
    if (wtq_session_local_flush(r->session) != WTQ_ERR_STATE) return 1;
    QUIC_CONNECTION_EVENT connected = { .Type = QUIC_CONNECTION_EVENT_CONNECTED };
    (void)wtq_msq_conn_callback(r->drv->conn, r->drv, &connected);
    wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
    cc.authority = "localhost"; cc.path = "/flush";
    if (wtq_api_session_connect(r->session, &cc) != WTQ_OK) return 1;
    uint8_t settings[128] = { 0 }, response[300], section[256];
    size_t n = 0, sn = 0, hn = 0;
    wtq_h3_settings_encode_cfg_t sc = { .enable_connect_protocol = true };
    if (wtq_h3_settings_encode_frame(&sc, settings + 1, sizeof(settings) - 1, &n))
        return 1;
    struct wtq_dstream *peer = wtq_msq_stream_new(r->drv, false, false, 3);
    wtq_conn_t *conn = wtq_api_session_conn(r->session);
    wtq_api_session_enter(r->session);
    if (bounded) {
        (void)wtq_conn_peer_admission_init(conn, &peer->admission, peer, 3,
            false, (unsigned)(peer - r->drv->peers));
        size_t consumed = 0;
        (void)wtq_msq_stream_input(peer, settings, n + 1, false, &consumed);
    } else {
        (void)wtq_conn_on_peer_uni_opened(conn, peer, 3, &peer->ectx);
        (void)wtq_conn_on_stream_bytes(conn, peer->ectx, settings, n + 1, false, 1);
    }
    wtq_msq_conn_leave_and_poll(r->drv);
    if (wtq_connect_encode_response(200, NULL, section, sizeof(section), &sn) ||
        wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, sn, response,
            sizeof(response), &hn)) return 1;
    memcpy(response + hn, section, sn);
    struct wtq_dstream *bidi = r->drv->streams;
    while (bidi && !(bidi->is_local && bidi->is_bidi)) bidi = bidi->next;
    if (!bidi) return 1;
    wtq_api_session_enter(r->session);
    (void)wtq_conn_on_stream_bytes(conn, bidi->ectx, response, hn + sn, false, 2);
    wtq_msq_conn_leave_and_poll(r->drv);
    return wtq_session_status(r->session) != WTQ_SESSION_STATUS_ESTABLISHED;
}

static int teardown(struct rig *r)
{
    r->check_return = false;
    complete_all(r);
    wtq_api_session_admission_detach(r->session);
    wtq_session_release(r->session);
    r->drv->session = NULL;
    wtq_msq_conn_free(r->drv);
    pthread_mutex_destroy(&r->lane);
    return r->errors;
}

static int passive(struct rig *r, wtq_result_t want)
{
    int failures = 0;
    struct wtq_driver before;
    memcpy(&before, r->drv, sizeof(before));
    unsigned a = r->allocations, p = r->provider_calls, c = r->callbacks;
    for (unsigned i = 0; i < 1000; ++i)
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r->session), want);
    WTQ_TEST_CHECK_EQ_INT(r->allocations, a);
    WTQ_TEST_CHECK_EQ_INT(r->provider_calls, p);
    WTQ_TEST_CHECK_EQ_INT(r->callbacks, c);
    WTQ_TEST_CHECK(memcmp(&before, r->drv, sizeof(before)) == 0);
    return failures;
}

static int test_success(void)
{
    int failures = 0;
    struct rig r, other;
    WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
    WTQ_TEST_CHECK_EQ_INT(setup(&other, false, false), 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.session), WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(other.session), WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK); /* bootstrap + CONNECT */
    complete_all(&r);
    failures += passive(&r, WTQ_OK); /* live idle */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(other.session), WTQ_ERR_WOULD_BLOCK);
    complete_all(&other);
    wtq_stream_t *a = NULL, *b = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &a), WTQ_OK);
    struct wtq_dstream *da = r.drv->streams;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK); /* preface */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &b), WTQ_OK);
    struct wtq_dstream *db = r.drv->streams;
    complete(&r, false);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK);
    complete_all(&r);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(other.session), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(a), WTQ_OK);
    wtq_stream_add_ref(a);
    static const uint8_t bytes[] = { 1, 2, 3 };
    wtq_span_t span = { .data = bytes, .len = sizeof(bytes) };
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(a, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(b, NULL, 0, WTQ_SEND_FIN, &r), WTQ_OK);
    r.check_return = true; r.return_result = WTQ_ERR_WOULD_BLOCK;
    complete_all(&r); /* buffer return alone never satisfies FIN */
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
    event(db, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK);
    event(da, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 1); /* query in N23 callback sees cleared FIN */
    failures += passive(&r, WTQ_OK);
    wtq_stream_release(a);
    failures += teardown(&r) + teardown(&other);
    WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    WTQ_TEST_CHECK_EQ_SIZE(other.live, 0);
    return failures;
}

static int test_intent_settlement(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 4; ++row) {
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        complete_all(&r);
        wtq_stream_add_ref(st);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(st), WTQ_OK);
        const uint8_t byte = 1;
        wtq_span_t span = { .data = &byte, .len = 1 };
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, row == 1 ? NULL : &span,
            row == 1 ? 0 : 1, WTQ_SEND_FIN, &r), WTQ_OK);
        if (row == 2) event(ds, QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, false);
        else if (row == 3) WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(st, 42), WTQ_OK);
        else WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
        failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
        r.check_return = true; r.return_result = WTQ_ERR_WOULD_BLOCK;
        if (row == 0) {
            complete(&r, true); /* borrow return is not abort completion */
            failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
        } else {
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
            failures += passive(&r, WTQ_ERR_WOULD_BLOCK); /* still borrowed, even FIN-only */
            r.return_result = WTQ_OK;
            complete(&r, true);
        }
        complete_all(&r);
        failures += passive(&r, WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
        wtq_stream_t *next = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &next), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(next, &span, 1, 0, &r), WTQ_OK);
        r.return_result = WTQ_ERR_WOULD_BLOCK;
        complete(&r, false);
        r.return_result = WTQ_OK;
        complete_all(&r);
        failures += passive(&r, WTQ_OK);
        wtq_stream_release(st);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static int test_transaction_generation(bool retain_old, bool send_entry)
{
    int failures = 0;
    struct rig r;
    WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
    complete_all(&r);
    wtq_stream_t *old = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &old), WTQ_OK);
    struct wtq_dstream *ds = r.drv->streams;
    wtq_estream_t *old_es = ds->ectx;
    uint64_t old_generation = wtq_estream_generation_v1(old_es);
    r.original_id = wtq_stream_id(old);
    complete_all(&r);
    if (retain_old) wtq_stream_add_ref(old);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(old), WTQ_OK);
    static const uint8_t byte = 23;
    wtq_span_t span = { .data = &byte, .len = 1 };
    if (!send_entry)
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(old, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
    r.nested_reset = old;
    r.replace_after_reset = true;
    r.check_return = true; r.return_result = WTQ_ERR_WOULD_BLOCK;
    if (send_entry) {
        r.sync_complete = true;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(old, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
    } else {
        r.shutdown_inline = r.shutdown_borrow = r.shutdown_query = true;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(old, 42), WTQ_OK);
    }
    /* No caller access to the baseline-only old handle after its terminal. */
    r.shutdown_inline = r.shutdown_query = false;
    WTQ_TEST_CHECK(r.replacement != NULL);
    if (retain_old) WTQ_TEST_CHECK(r.replacement != old);
    WTQ_TEST_CHECK_EQ_INT(r.original_closures, 1);
    WTQ_TEST_CHECK_EQ_INT(r.replacement_closures, 0);
    WTQ_TEST_CHECK(r.replacement_ds != ds);
    WTQ_TEST_CHECK(r.replacement_es == old_es); /* causal engine-slot reuse */
    WTQ_TEST_CHECK(r.replacement_generation > old_generation);
    WTQ_TEST_CHECK(r.replacement_ds->ectx == r.replacement_es);
    WTQ_TEST_CHECK(wtq_estream_is_wt_data_v1(r.replacement_es, r.replacement_ds));
    WTQ_TEST_CHECK_EQ_SIZE(wtq_estream_generation_v1(r.replacement_es), r.replacement_generation);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_stream_id(r.replacement), r.replacement_id);
    WTQ_TEST_CHECK(wtq_estream_driver_stream(r.replacement_es) == r.replacement_ds);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(r.replacement, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
    complete_all(&r); /* replacement bytes returned, replacement FIN still owed */
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
    event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, !send_entry); /* old late event */
    WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK); /* only replacement FIN remains */
    event(r.replacement_ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
    failures += passive(&r, WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
    WTQ_TEST_CHECK(r.last_committed == r.replacement);
    WTQ_TEST_CHECK_EQ_INT(r.replacement_closures, 1);
    WTQ_TEST_CHECK_EQ_INT(r.original_closures, 1);
    if (retain_old) wtq_stream_release(old);
    failures += teardown(&r);
    WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    return failures;
}

static int test_loss(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 8; ++row) {
        if (row == 1 || row == 2 || row == 3) continue; /* successor intent rows */
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        complete_all(&r);
        wtq_stream_add_ref(st);
        if (row == 1 || row == 2)
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(st), WTQ_OK);
        static const uint8_t byte = 1;
        wtq_span_t span = { .data = &byte, .len = 1 };
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, row == 6 ? NULL : &span,
            row == 6 ? 0 : 1, WTQ_SEND_FIN, &r), WTQ_OK);
        r.check_return = true; r.return_result = row == 7 ? WTQ_OK : WTQ_ERR_BACKEND;
        if (row == 0) complete(&r, true);
        if (row == 1) WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
        if (row == 2) WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(st, 42), WTQ_OK);
        if (row == 3) event(ds, QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, false);
        if (row == 4 || row == 6) event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
        if (row == 5) event(ds, QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, false);
        if (row == 7) {
            /* Peer RESET only ends receive; it cannot poison our output. */
            event(ds, QUIC_STREAM_EVENT_PEER_SEND_ABORTED, false);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
        }
        if (row != 7) WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_BACKEND);
        complete_all(&r);
        event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true); /* late success cannot clear loss */
        wtq_result_t want = row == 7 ? WTQ_OK : WTQ_ERR_BACKEND;
        failures += passive(&r, want);
        wtq_stream_release(st);
        wtq_stream_t *next = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &next), WTQ_OK);
        complete_all(&r);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), want);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static int test_direct_terminal_loss_cache(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 9; ++row) {
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r); /* critical/control/CONNECT all ACKed first */
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *media = r.drv->streams;
        complete_all(&r);
        wtq_stream_add_ref(st);
        r.capture_terminal_detail = true;
        r.terminal_loss = row != 7 && row != 8;
        bool mismatch = row < 3 || row == 6 || row == 8;
        struct wtq_dstream *critical = r.drv->streams;
        while (critical && !critical->local_critical) critical = critical->next;
        WTQ_TEST_CHECK(critical != NULL);
        if (row == 2 || row == 4) {
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_sends, 0);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_fins, 0);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_settlements, 1);
        } else if (r.terminal_loss) {
            static const uint8_t byte = 31;
            wtq_span_t span = { .data = &byte, .len = 1 };
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, row == 1 ? NULL : &span,
                row == 1 ? 0 : 1, WTQ_SEND_FIN, &r), WTQ_OK);
        }
        uint32_t kind = mismatch ? WTQ_ERR_KIND_LOCAL : WTQ_ERR_KIND_QUIC_APP;
        uint64_t code = mismatch ? WTQ_H3_INTERNAL_ERROR : WTQ_H3_CLOSED_CRITICAL_STREAM;
        uint32_t domain = mismatch ? WTQ_ERRDOM_MSQUIC : WTQ_ERRDOM_NONE;
        int64_t native = mismatch ? (int64_t)QUIC_STATUS_SUCCESS : 0;
        if (row == 6) {
            wtq_msq_conn_stage_local_cause(r.drv, 0x777, 1234);
            code = 0x777; native = 1234;
        }
        /* No local-flush observation between acceptance and terminal ingress. */
        if (mismatch) {
            struct wtq_dstream *target = row == 0 ? media : critical;
            QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_START_COMPLETE };
            ev.START_COMPLETE.Status = QUIC_STATUS_SUCCESS;
            ev.START_COMPLETE.ID = target->id + 4;
            (void)wtq_msq_stream_callback(target->stream, target, &ev);
        } else {
            if (row == 5) r.drv->api_depth++;
            event(critical, QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, false);
            if (row == 5) {
                atomic_store_explicit(&r.drv->env_close_req, true, memory_order_release);
                r.drv->api_depth--;
                QUIC_CONNECTION_EVENT tick = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
                (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &tick);
                kind = WTQ_ERR_KIND_LOCAL; code = WTQ_H3_NO_ERROR;
                domain = WTQ_ERRDOM_MSQUIC;
            }
        }
        wtq_result_t want = r.terminal_loss ? WTQ_ERR_BACKEND : WTQ_ERR_CLOSED;
        WTQ_TEST_CHECK_EQ_INT(r.closed_count, 1);
        WTQ_TEST_CHECK_EQ_INT(r.closed_flush, want);
        WTQ_TEST_CHECK_EQ_INT(r.closed_detail.kind, kind);
        WTQ_TEST_CHECK_EQ_SIZE(r.closed_detail.quic_code, code);
        WTQ_TEST_CHECK_EQ_INT(r.closed_detail.native_domain, domain);
        WTQ_TEST_CHECK(r.closed_detail.native_code == native);
        wtq_session_t *retained = r.session;
        wtq_session_add_ref(retained);
        r.check_return = true; r.return_result = want;
        wtq_stream_release(st);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(retained), want);
        wtq_transport_error_t detail = { .struct_size = sizeof(detail) };
        WTQ_TEST_CHECK_EQ_INT(wtq_session_transport_error(retained, &detail), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(detail.kind, kind);
        WTQ_TEST_CHECK_EQ_SIZE(detail.quic_code, code);
        WTQ_TEST_CHECK_EQ_INT(detail.native_domain, domain);
        WTQ_TEST_CHECK(detail.native_code == native);
        wtq_session_release(retained);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static int test_intent_discriminators(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 17; ++row) {
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(row == 4 ? wtq_session_open_bidi(r.session, &st) :
            wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        complete_all(&r);
        wtq_stream_add_ref(st);
        if (row != 4 && row != 12)
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(st), WTQ_OK);
        const uint8_t byte = 5;
        wtq_span_t span = { .data = &byte, .len = 1 };
        if (row != 10)
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, row == 11 ? NULL : &span,
                row == 11 ? 0 : 1, row == 11 || row == 4 ? 0 : WTQ_SEND_FIN, &r), WTQ_OK);
        r.check_return = true; r.return_result = WTQ_ERR_WOULD_BLOCK;
        wtq_result_t want = WTQ_OK;
        wtq_shutdown_t req = { .abort_send = true, .app_send_cancel = true };
        if (row <= 2 || row == 4 || row == 10 || row >= 13) {
            r.shutdown_inline = r.shutdown_query = true;
            r.shutdown_borrow = row != 10;
            r.shutdown_graceful = row == 1;
            r.terminal_loss = row == 2 || row == 4 || row == 14 || row == 16;
            r.refuse = row == 2 || row == 14 || row == 16;
            if (row == 13 || row == 14) r.nested_reset = st;
            if (row >= 15) r.shutdown_nested = true;
            if (row == 0) r.check_contention = true;
            if (row == 4) {
                req.mode = WTQ_SHUTDOWN_EXACT_HALVES;
                req.abort_recv = true;
                req.send_err = 1; req.recv_err = 2;
                r.shutdown_refuse_at = r.shutdown_calls + 2;
                WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_shutdown(
                    wtq_api_session_conn(r.session), ds->ectx, &req), WTQ_ERR_BACKEND);
            } else WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42),
                row == 2 || row == 14 || row == 16 ? WTQ_ERR_BACKEND : WTQ_OK);
            if (row == 2 || row == 4 || row == 14 || row == 16) want = WTQ_ERR_BACKEND;
            r.refuse = r.shutdown_inline = r.shutdown_query = false;
        } else if (row == 3) {
            r.refuse = true;
            WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->shutdown_stream(r.drv, ds, &req), WTQ_ERR_BACKEND);
            r.refuse = false;
            WTQ_TEST_CHECK_EQ_INT(ds->flush_epoch, 0);
            WTQ_TEST_CHECK(!ds->flush_settling);
            failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
            complete_all(&r);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
            WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
        } else if (row == 5) {
            req.app_send_cancel = false; /* ABORT flag is not authorization */
            WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->shutdown_stream(r.drv, ds, &req), WTQ_OK);
            want = WTQ_ERR_BACKEND;
        } else if (row == 6) {
            wtq_conn_wt_reject(wtq_api_session_conn(r.session), ds->ectx);
            want = WTQ_ERR_BACKEND;
        } else if (row == 7 || row == 8) {
            struct wtq_dstream *control = r.drv->streams;
            while (control && (row == 7 ? !control->local_critical :
                (!control->is_local || !control->is_bidi))) control = control->next;
            WTQ_TEST_CHECK(control != NULL);
            if (control) {
                WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send(r.drv, control, &byte, 1, false), WTQ_OK);
                if (row == 7) {
                    r.terminal_loss = true;
                    event(control, QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, false);
                } else WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->shutdown_stream(r.drv, control, &req), WTQ_OK);
                WTQ_TEST_CHECK_EQ_INT(control->flush_epoch, 0);
            }
            want = WTQ_ERR_BACKEND;
        } else if (row == 9) {
            r.return_result = WTQ_ERR_BACKEND;
            complete(&r, true); /* preexisting unexplained loss */
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
            want = WTQ_ERR_BACKEND;
        } else if (row == 11) {
            failures += passive(&r, WTQ_OK); /* empty non-FIN alone owes no output */
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
            failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
            r.return_result = WTQ_OK;
            complete(&r, true);
        } else if (row == 12) {
            WTQ_TEST_CHECK(ds->ectx == NULL); /* legacy FIN released engine slot */
            wtq_stream_t *next = NULL;
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &next), WTQ_OK);
            struct wtq_dstream *next_ds = r.drv->streams;
            WTQ_TEST_CHECK(next_ds != ds);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(next), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(next, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
            event(ds, QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, false);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
            complete(&r, true);
            failures += passive(&r, WTQ_ERR_WOULD_BLOCK); /* newer stream preface */
            WTQ_TEST_CHECK_EQ_INT(next_ds->flush_epoch, 0);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
            WTQ_TEST_CHECK_EQ_INT(r.commits, 0); /* old generation cannot commit next */
            r.return_result = WTQ_ERR_WOULD_BLOCK;
            complete_all(&r);
            event(next_ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
            r.return_result = WTQ_OK;
        }
        r.return_result = want;
        complete_all(&r);
        if (row == 5 || row == 6 || row == 7 || row == 8)
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
        QUIC_CONNECTION_EVENT tick = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
        (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &tick);
        failures += passive(&r, want);
        if (row != 3) WTQ_TEST_CHECK_EQ_INT(r.commits, row == 12 ? 1 : 0);
        WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_decisions, 0);
        wtq_stream_release(st);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static int test_refusal_and_controls(void)
{
    int failures = 0;
    for (unsigned buffered = 0; buffered < 2; ++buffered) {
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, buffered != 0, buffered == 0), 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.session),
            buffered ? WTQ_LOCAL_FLUSH_UNSUPPORTED : WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
        complete_all(&r);
        struct wtq_dstream *ds = wtq_msq_stream_new(r.drv, true, true, 100);
        ds->stream = (HQUIC)(void *)ds;
        wtq_result_t want = buffered ? WTQ_ERR_UNSUPPORTED : WTQ_OK;
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send_gather(r.drv, ds, NULL, 0, false, NULL), WTQ_OK);
        failures += passive(&r, want); /* empty record owes borrow return, not output */
        complete(&r, true); /* canceling an empty non-FIN send is not output loss */
        complete_all(&r);
        r.refuse = true;
        const uint8_t byte = 1;
        wtq_span_t span = { .data = &byte, .len = 1 };
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send(r.drv, ds, &byte, 1, true), WTQ_ERR_BACKEND);
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send(r.drv, ds, NULL, 0, true), WTQ_ERR_BACKEND);
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send_gather(r.drv, ds, &span, 1, true, NULL), WTQ_ERR_BACKEND);
        wtq_shutdown_t reset = { .abort_send = true };
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->shutdown_stream(r.drv, ds, &reset), WTQ_ERR_BACKEND);
        failures += passive(&r, want);
        r.refuse = false;
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send(r.drv, ds, NULL, 0, true), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), buffered ? want : WTQ_ERR_WOULD_BLOCK);
        event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
        failures += passive(&r, want);
        QUIC_CONNECTION_EVENT terminal = { .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER };
        (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &terminal);
        wtq_local_flush_mode_t mode = wtq_session_local_flush_mode(r.session);
        wtq_session_t *retained = r.session;
        wtq_session_add_ref(retained);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(retained), WTQ_ERR_CLOSED); /* driver freed */
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(retained), mode);
        wtq_session_release(retained);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static int test_intent_terminal_and_isolation(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 3; ++row) {
        struct rig r, other;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        WTQ_TEST_CHECK_EQ_INT(setup(&other, false, true), 0);
        complete_all(&r); complete_all(&other);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        complete_all(&r);
        wtq_stream_add_ref(st);
        /* Idle send reset still owns abort completion, independent of bytes. */
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
        failures += passive(&r, WTQ_ERR_WOULD_BLOCK);
        failures += passive(&other, WTQ_OK);
        if (row == 0) {
            r.terminal_loss = true;
            QUIC_CONNECTION_EVENT terminal = { .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER };
            (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &terminal);
            failures += passive(&r, WTQ_ERR_BACKEND);
        } else if (row == 1) {
            event(ds, QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, false);
            failures += passive(&r, WTQ_ERR_BACKEND);
            WTQ_TEST_CHECK(ds->ectx == NULL);
            WTQ_TEST_CHECK_EQ_SIZE(ds->send_refs, 0);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->api_depth, 0);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->callback_depth, 0);
            WTQ_TEST_CHECK(wtq_api_session_admission_root(r.session));
            wtq_stream_release(st); /* retained app lease intentionally fenced collection */
            st = NULL;
            QUIC_CONNECTION_EVENT tick = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
            (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &tick);
            WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_settlements, 0);
        } else {
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
            failures += passive(&r, WTQ_OK);
        }
        failures += passive(&other, WTQ_OK);
        wtq_stream_release(st);
        failures += teardown(&r) + teardown(&other);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
        WTQ_TEST_CHECK_EQ_SIZE(other.live, 0);
    }
    return failures;
}

static int test_inline_and_domain(void)
{
    int failures = 0;
    struct rig r;
    WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
    complete_all(&r);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
    complete_all(&r);
    static const uint8_t byte = 7;
    wtq_span_t span = { .data = &byte, .len = 1 };
    r.sync_complete = r.check_return = r.check_contention = true;
    r.return_result = WTQ_OK;
    /* Real backend callback reenters during StreamSend. Accounting and the
     * returned record are finalized before the already-held-domain app query. */
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, &span, 1, 0, &r), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.returned, 1);
    WTQ_TEST_CHECK_EQ_INT(r.contention_attempts, 1);
    WTQ_TEST_CHECK_EQ_INT(r.contention_queries, 0);
    WTQ_TEST_CHECK_EQ_INT(r.entered, 0);
    WTQ_TEST_CHECK_EQ_INT(r.drv->pending_sends, 0);
    failures += passive(&r, WTQ_OK);
    r.return_result = WTQ_ERR_WOULD_BLOCK;
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, &r), WTQ_OK);
    /* This second return still owes FIN even when bytes returned inline. */
    failures += teardown(&r);
    WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    return failures;
}

static int test_half_abort_and_datagram(void)
{
    int failures = 0;
    struct rig r;
    WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
    complete_all(&r);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_bidi(r.session, &st), WTQ_OK);
    struct wtq_dstream *ds = r.drv->streams;
    complete_all(&r);
    static const uint8_t byte = 9;
    wtq_span_t span = { .data = &byte, .len = 1 };
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, &span, 1, 0, &r), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_stop_sending(st, 42), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK);
    r.check_return = true; r.return_result = WTQ_OK;
    complete_all(&r);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK); /* already ACKed: no loss */
    failures += passive(&r, WTQ_ERR_WOULD_BLOCK); /* still owns native abort */
    event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
    failures += passive(&r, WTQ_OK);
    r.drv->dgram_max = 1200;
    WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->dgram_send(r.drv, &span, 1), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.drv->dgram_inflight, 1);
    failures += passive(&r, WTQ_OK);
    QUIC_CONNECTION_EVENT ev = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED };
    ev.DATAGRAM_SEND_STATE_CHANGED.ClientContext = r.dgram_ctx;
    ev.DATAGRAM_SEND_STATE_CHANGED.State = QUIC_DATAGRAM_SEND_CANCELED;
    (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &ev);
    WTQ_TEST_CHECK_EQ_INT(r.drv->dgram_inflight, 0);
    failures += passive(&r, WTQ_OK);
    /* Cold protocol FIN remains pending independently of all record returns. */
    WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send(r.drv, ds, &byte, 1, true), WTQ_OK);
    complete_all(&r);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK);
    event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
    failures += passive(&r, WTQ_OK);
    failures += teardown(&r);
    WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    return failures;
}

static int test_resident_reuse_and_blocked(void)
{
    int failures = 0;
    struct rig r;
    WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
    complete_all(&r);
    struct wtq_dstream *first = NULL;
    uint64_t generation = 0;
    static const uint8_t byte = 1;
    wtq_span_t span = { .data = &byte, .len = 1 };
    for (unsigned i = 0; i < 32; ++i) {
        struct wtq_dstream *ds = wtq_msq_stream_new(r.drv, false, true, 1 + 4 * i);
        if (!first) first = ds;
        WTQ_TEST_CHECK(ds == first);
        WTQ_TEST_CHECK(ds->generation > generation);
        generation = ds->generation;
        WTQ_TEST_CHECK_EQ_SIZE(ds->flush_sends, 0);
        WTQ_TEST_CHECK(!ds->flush_fin);
        WTQ_TEST_CHECK_EQ_SIZE(ds->flush_required_sends, 0);
        WTQ_TEST_CHECK_EQ_SIZE(ds->flush_epoch, 0);
        WTQ_TEST_CHECK(!ds->flush_settling && !ds->flush_abort_complete);
        WTQ_TEST_CHECK(ds->flush_decision == NULL);
        ds->stream = (HQUIC)(void *)ds;
        WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send_gather(r.drv, ds, &span, 1, true, &r), WTQ_OK);
        if (i == 0) {
            ds->inflight_bytes = WTQ_MSQ_SEND_BUDGET_MIN;
            size_t accepted = r.sent;
            WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->send_gather(r.drv, ds, &span, 1, false, &r), WTQ_ERR_WOULD_BLOCK);
            WTQ_TEST_CHECK_EQ_SIZE(r.sent, accepted); /* refused budget has zero obligation */
            ds->inflight_bytes = 1;
            WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_WOULD_BLOCK);
            QUIC_STREAM_EVENT failed = { .Type = QUIC_STREAM_EVENT_START_COMPLETE };
            failed.START_COMPLETE.Status = QUIC_STATUS_INVALID_STATE;
            (void)wtq_msq_stream_callback(ds->stream, ds, &failed);
        }
        complete(&r, i == 0);
        complete_all(&r);
        event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
        event(ds, QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, false);
        QUIC_CONNECTION_EVENT tick = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
        (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &tick); /* safe-root retirement */
        WTQ_TEST_CHECK(!first->occupied);
        WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_sends, 0);
        WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_fins, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.session), WTQ_ERR_BACKEND);
    }
    failures += passive(&r, WTQ_ERR_BACKEND);
    failures += teardown(&r);
    WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    return failures;
}

static int test_terminal_loss_without_prior_query(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 2; ++row) {
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        complete_all(&r);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, &r), WTQ_OK);
        /* No observation between acceptance and loss/terminal. */
        if (row == 0) event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, false);
        r.terminal_loss = true;
        QUIC_CONNECTION_EVENT terminal = { .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER };
        (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &terminal);
        wtq_session_t *retained = r.session;
        wtq_session_add_ref(retained);
        r.check_return = true; r.return_result = WTQ_ERR_BACKEND;
        complete(&r, true); /* late cancellation after terminal keeps the cache */
        event(ds, QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, false);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(retained), WTQ_ERR_BACKEND);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(retained), WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
        wtq_session_release(retained);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

static QUIC_STATUS QUIC_API configuration_open(HQUIC reg, const QUIC_BUFFER *alpn,
    uint32_t count, const QUIC_SETTINGS *settings, uint32_t size, void *ctx, HQUIC *out)
{
    (void)alpn; (void)count; (void)ctx;
    struct rig *r = (void *)reg;
    r->provider_calls++;
    if (size != sizeof(*settings)) return QUIC_STATUS_INVALID_PARAMETER;
    r->configured = *settings;
    *out = reg;
    return QUIC_STATUS_SUCCESS;
}
static QUIC_STATUS QUIC_API configuration_credential(HQUIC config,
    const QUIC_CREDENTIAL_CONFIG *cred)
{
    (void)cred;
    ((struct rig *)(void *)config)->provider_calls++;
    return QUIC_STATUS_SUCCESS;
}
static void QUIC_API configuration_close(HQUIC config)
{
    ((struct rig *)(void *)config)->provider_calls++;
}
static QUIC_STATUS QUIC_API connection_open(HQUIC reg,
    QUIC_CONNECTION_CALLBACK_HANDLER cb, void *ctx, HQUIC *out)
{
    (void)cb;
    struct rig *r = (void *)reg;
    r->provider_calls++;
    r->drv = ctx;
    *out = (HQUIC)ctx;
    return QUIC_STATUS_SUCCESS;
}
static QUIC_STATUS QUIC_API connection_start(HQUIC conn, HQUIC config,
    QUIC_ADDRESS_FAMILY family, const char *name, uint16_t port)
{
    (void)conn; (void)family; (void)name; (void)port;
    ((struct rig *)(void *)config)->provider_calls++;
    return QUIC_STATUS_SUCCESS;
}

static int test_effective_client_settings(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 4; ++row) {
        struct rig r = { 0 };
        r.alloc = (wtq_alloc_t){ .alloc = allocate, .realloc = reallocate,
            .free = deallocate, .ctx = &r };
        r.api = (QUIC_API_TABLE){ .ConfigurationOpen = configuration_open,
            .ConfigurationLoadCredential = configuration_credential,
            .ConfigurationClose = configuration_close, .ConnectionOpen = connection_open,
            .ConnectionStart = connection_start, .ConnectionClose = conn_close,
            .ConnectionShutdown = conn_shutdown };
        wtq_msquic_env_cfg_t ec = WTQ_MSQUIC_ENV_CFG_INIT;
        ec.alloc = &r.alloc;
        ec.existing_api = &r.api;
        ec.existing_registration = (HQUIC)(void *)&r;
        if (row != 0) {
            wtq_msquic_tuning_init(&ec.tuning);
            WTQ_TEST_CHECK(!ec.tuning.send_buffering);
            ec.tuning.idle_timeout_ms = 9876; /* actual LibMoQ initialization path */
            ec.tuning.send_buffering = row == 2;
            if (row == 3) ec.tuning.peer_bidi_stream_count++;
        } else {
            ec.tuning.struct_size = 0;
            ec.tuning.send_buffering = true; /* ignored, effective defaults win */
        }
        wtq_msquic_env_t *env = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ec, &env), WTQ_OK);
        wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
        cc.authority = "localhost"; cc.path = "/flush";
        wtq_session_events_t events = WTQ_SESSION_EVENTS_INIT;
        wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
        cfg.connect = &cc; cfg.events = &events;
        cfg.server_name = "127.0.0.1"; cfg.port = 1;
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &cfg, &r.session), WTQ_OK);
        WTQ_TEST_CHECK(r.configured.IsSet.SendBufferingEnabled);
        WTQ_TEST_CHECK_EQ_INT(r.configured.SendBufferingEnabled, row == 2);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.session),
            row == 2 ? WTQ_LOCAL_FLUSH_UNSUPPORTED : WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
        WTQ_TEST_CHECK_EQ_INT(r.drv->bounded_admission, row != 3);
        QUIC_CONNECTION_EVENT done = { .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE };
        (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &done);
        wtq_session_release(r.session);
        wtq_msquic_env_close(env);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
    }
    return failures;
}

/* Reuse the typed provider and real callback path; no socket or scheduling race.
 * Seven bounded cases: payload, framing, refused inline decision, success,
 * accepted intent, distinct healthy stream after loss, and FIN-only borrow. */
static int test_canceled_commit_contract(void)
{
    int total = 0;
    for (unsigned row = 0; row < 7; ++row) {
        int failures = 0;
        struct rig r;
        WTQ_TEST_CHECK_EQ_INT(setup(&r, false, true), 0);
        complete_all(&r);
        r.trace_commit_contract = true;
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &st), WTQ_OK);
        struct wtq_dstream *ds = r.drv->streams;
        wtq_estream_t *es = ds->ectx;
        uint64_t generation = wtq_estream_generation_v1(es);
        WTQ_TEST_CHECK(ds->stream == (HQUIC)(void *)ds);
        WTQ_TEST_CHECK(wtq_estream_driver_stream(es) == ds);
        WTQ_TEST_CHECK_EQ_SIZE(r.sent - r.completed, 1); /* exact WT preface */
        WTQ_TEST_CHECK(r.sends[r.completed].ds == ds);
        struct wtq_msq_send_hdr *preface = r.sends[r.completed].ctx;
        WTQ_TEST_CHECK(!preface->gather && preface->flush_bytes && !preface->flush_fin);
        if (row != 1) complete_all(&r);
        wtq_stream_add_ref(st); /* survives either success or terminal callback */
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(st), WTQ_OK);
        unsigned empty_cookie = 99;
        if (row == 3) {
            /* No reliable output in this borrow: cancellation cannot poison
             * the later uncanceled bytes+FIN on this same stream. */
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, NULL, 0, 0, &empty_cookie), WTQ_OK);
            struct wtq_msq_send_hdr *empty = r.sends[r.completed].ctx;
            WTQ_TEST_CHECK(empty->gather && !empty->flush_bytes && !empty->flush_fin);
            complete(&r, true);
            WTQ_TEST_CHECK_EQ_INT(r.returned, 1);
            WTQ_TEST_CHECK(r.last_return_cookie == &empty_cookie);
            WTQ_TEST_CHECK_EQ_SIZE(ds->send_refs, 0);
            failures += passive(&r, WTQ_OK);
            complete_all(&r);
        }
        const uint8_t byte = 29;
        wtq_span_t span = { .data = &byte, .len = 1 };
        unsigned cookie = row;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, row == 6 ? NULL : &span,
            row == 6 ? 0 : 1, WTQ_SEND_FIN, &cookie), WTQ_OK);
        size_t app_index = row == 1 ? r.completed + 1 : r.completed;
        WTQ_TEST_CHECK_EQ_SIZE(r.sent, app_index + 1);
        WTQ_TEST_CHECK(r.sends[app_index].ds == ds);
        struct wtq_msq_send_hdr *app = r.sends[app_index].ctx;
        WTQ_TEST_CHECK(app->gather && app->flush_fin);
        WTQ_TEST_CHECK(app->flush_bytes == (row != 6));
        WTQ_TEST_CHECK(((struct wtq_msq_gather_rec *)app)->cookie == &cookie);
        WTQ_TEST_CHECK(((struct wtq_msq_gather_rec *)app)->ds == ds);
        WTQ_TEST_CHECK_EQ_SIZE(ds->ectx_generation, generation);
        r.check_return = true;
        r.return_result = row == 2 || row == 3 || row == 4 ?
            WTQ_ERR_WOULD_BLOCK : WTQ_ERR_BACKEND;
        r.expected_commit_flush = row == 3 ? WTQ_OK : WTQ_ERR_BACKEND;

        if (row == 2 || row == 4) {
            r.shutdown_inline = r.shutdown_borrow = r.shutdown_graceful = true;
            if (row == 2) {
                /* Backend refusal leaves engine live: isolate deferred delivery,
                 * not the public API's separate fatal-on-runtime-error path. */
                r.refuse = true;
                wtq_shutdown_t req = { .abort_send = true, .app_send_cancel = true };
                WTQ_TEST_CHECK_EQ_INT(wtq_msq_driver_ops()->shutdown_stream(r.drv, ds, &req), WTQ_ERR_BACKEND);
                WTQ_TEST_CHECK(ds->flush_shutdown_pending);
                WTQ_TEST_CHECK(!ds->flush_decision);
                WTQ_TEST_CHECK_EQ_SIZE(ds->flush_epoch, 0);
                WTQ_TEST_CHECK(ds->ectx == es);
                WTQ_TEST_CHECK_EQ_SIZE(wtq_estream_generation_v1(es), generation);
                WTQ_TEST_CHECK_EQ_INT(r.commits, 0); /* still deferred */
            } else {
                WTQ_TEST_CHECK_EQ_INT(wtq_stream_reset(st, 42), WTQ_OK);
                WTQ_TEST_CHECK_EQ_SIZE(ds->flush_epoch, 1);
            }
            r.refuse = r.shutdown_inline = false;
            QUIC_CONNECTION_EVENT tick = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
            (void)wtq_msq_conn_callback(r.drv->conn, r.drv, &tick);
            WTQ_TEST_CHECK(!ds->flush_shutdown_pending);
        } else {
            if (row == 1) complete(&r, true); /* cold framing record, no app return */
            complete(&r, row != 1 && row != 3);
            WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
            WTQ_TEST_CHECK_EQ_SIZE(ds->send_refs, 0);
            WTQ_TEST_CHECK(ds->ectx == es);
            WTQ_TEST_CHECK_EQ_SIZE(wtq_estream_generation_v1(es), generation);
            event(ds, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
        }
        complete_all(&r);
        WTQ_TEST_CHECK_EQ_INT(r.returned, row == 3 ? 2 : 1);
        WTQ_TEST_CHECK_EQ_INT(r.canceled_returns, row == 1 ? 0 : 1);
        WTQ_TEST_CHECK(r.last_return_cookie == &cookie);
        WTQ_TEST_CHECK_EQ_SIZE(ds->send_refs, 0);
        WTQ_TEST_CHECK_EQ_SIZE(r.drv->pending_sends, 0);
        WTQ_TEST_CHECK_EQ_SIZE(r.drv->flush_decisions, 0);
        WTQ_TEST_CHECK_EQ_INT(r.commits, row == 3 ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT(r.stream_terminals, 1);
        WTQ_TEST_CHECK(r.last_terminal == st);
        WTQ_TEST_CHECK(r.last_return_sequence < r.last_terminal_sequence);
        if (row == 3) {
            WTQ_TEST_CHECK(r.last_committed == st);
            WTQ_TEST_CHECK(r.last_return_sequence < r.last_commit_sequence);
            WTQ_TEST_CHECK(r.last_commit_sequence < r.last_terminal_sequence);
        }
        wtq_result_t want = row == 3 || row == 4 ? WTQ_OK : WTQ_ERR_BACKEND;
        failures += passive(&r, want);

        if (row == 5) {
            /* Loss is connection-sticky, but commitment is stream-specific. */
            wtq_stream_t *healthy = NULL;
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(r.session, &healthy), WTQ_OK);
            struct wtq_dstream *next = r.drv->streams;
            WTQ_TEST_CHECK(next != ds);
            complete_all(&r);
            wtq_stream_add_ref(healthy);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_enable_send_commit(healthy), WTQ_OK);
            unsigned healthy_cookie = 77;
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(healthy, &span, 1, WTQ_SEND_FIN, &healthy_cookie), WTQ_OK);
            WTQ_TEST_CHECK_EQ_SIZE(r.sent - r.completed, 1);
            WTQ_TEST_CHECK(r.sends[r.completed].ds == next);
            complete(&r, false);
            event(next, QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, true);
            WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
            WTQ_TEST_CHECK(r.last_committed == healthy);
            WTQ_TEST_CHECK(r.last_return_cookie == &healthy_cookie);
            WTQ_TEST_CHECK_EQ_INT(r.returned, 2);
            WTQ_TEST_CHECK_EQ_INT(r.canceled_returns, 1);
            WTQ_TEST_CHECK_EQ_INT(r.stream_terminals, 2);
            WTQ_TEST_CHECK(r.last_terminal == healthy);
            WTQ_TEST_CHECK(r.last_return_sequence < r.last_commit_sequence);
            WTQ_TEST_CHECK(r.last_commit_sequence < r.last_terminal_sequence);
            WTQ_TEST_CHECK_EQ_SIZE(next->send_refs, 0);
            failures += passive(&r, WTQ_ERR_BACKEND);
            wtq_stream_release(healthy);
        }
        WTQ_TEST_CHECK_EQ_INT(r.errors, 0);
        printf("canceled commit row%u: commits=%u returns=%u canceled=%u terminals=%u flush=%d failures=%d\n",
            row, r.commits, r.returned, r.canceled_returns, r.stream_terminals,
            wtq_session_local_flush(r.session), failures);
        wtq_stream_release(st);
        failures += teardown(&r);
        WTQ_TEST_CHECK_EQ_SIZE(r.live, 0);
        total += failures;
    }
    return total;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--canceled-commit") == 0)
        return test_canceled_commit_contract() ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--intent") == 0)
        return test_intent_settlement() ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--generation-retained") == 0)
        return test_transaction_generation(true, false) ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--generation-baseline") == 0)
        return test_transaction_generation(false, false) ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--send-generation-retained") == 0)
        return test_transaction_generation(true, true) ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--send-generation-baseline") == 0)
        return test_transaction_generation(false, true) ? 1 : 0;
    if (argc == 2 && strcmp(argv[1], "--terminal-cache") == 0)
        return test_direct_terminal_loss_cache() ? 1 : 0;
    int failures = test_canceled_commit_contract() + test_success() + test_loss() + test_refusal_and_controls() +
        test_intent_settlement() + test_intent_discriminators() +
        test_intent_terminal_and_isolation() +
        test_transaction_generation(true, false) + test_transaction_generation(false, false) +
        test_transaction_generation(true, true) + test_transaction_generation(false, true) +
        test_direct_terminal_loss_cache() +
        test_inline_and_domain() + test_effective_client_settings() +
        test_half_abort_and_datagram() + test_resident_reuse_and_blocked() +
        test_terminal_loss_without_prior_query();
    WTQ_TEST_PASS("msquic_local_flush");
    return failures ? 1 : 0;
}
