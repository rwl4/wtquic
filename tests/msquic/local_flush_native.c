/* Parent-run only: bounded loopback, native events are the progress oracle. */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "msq_internal.h"
#include "test_support.h"
#include "local_flush_oracle.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

struct side;
struct native_stream {
    struct side *side;
    HQUIC handle;
    QUIC_STREAM_CALLBACK_HANDLER callback;
    void *ctx;
    bool fin;
    bool decision, canceled_intent, shutdown_settled;
    unsigned pending_bytes;
    struct nf_stream facts;
};
struct native_send {
    void *ctx;
    struct native_stream *stream;
    bool occupied, bytes, fin;
};
struct application_send {
    struct native_stream *stream;
    bool submitted, returned;
};
struct side {
    pthread_mutex_t lane;
    pthread_cond_t changed;
    wtq_msquic_env_t *env;
    wtq_session_t *session;
    struct wtq_driver *driver;
    QUIC_API_TABLE observed;
    struct native_stream streams[4];
    struct native_send sends[16];
    wtq_stream_t *app_streams[2];
    struct native_stream *app_native[2];
    struct application_send app_sends[2];
    unsigned row, established, returned, canceled, graceful, abortive, commits;
    unsigned stream_count, pending_bytes, pending_fins, provider_calls;
    bool server, active, lost, payload_started, actual_buffering, application_cancel;
    wtq_result_t terminal_result;
    int errors;
};

static const QUIC_API_TABLE *native;
static _Thread_local struct side *current;

static void enter(void *ctx)
{
    struct side *s = ctx;
    pthread_mutex_lock(&s->lane);
    current = s;
}

static void leave(void *ctx)
{
    struct side *s = ctx;
    current = NULL;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lane);
}

static wtq_result_t expected(const struct side *s)
{
    if (s->actual_buffering) return WTQ_ERR_UNSUPPORTED;
    if (s->lost) return WTQ_ERR_BACKEND;
    for (unsigned i = 0; i < s->stream_count; ++i) {
        const struct native_stream *st = &s->streams[i];
        if (st->decision || (st->canceled_intent && !st->shutdown_settled))
            return WTQ_ERR_WOULD_BLOCK;
        if (st->canceled_intent) {
            for (unsigned j = 0; j < 16; ++j)
                if (s->sends[j].occupied && s->sends[j].stream == st)
                    return WTQ_ERR_WOULD_BLOCK;
        }
    }
    return s->pending_bytes || s->pending_fins ? WTQ_ERR_WOULD_BLOCK : WTQ_OK;
}

static void observe(struct side *s)
{
    /* This counter covers only the four instrumented API entries, not the
     * complete provider table. Full passivity also needs source/fake review. */
    unsigned before = s->provider_calls;
    if (wtq_session_local_flush(s->session) != expected(s)) s->errors++;
    if (s->provider_calls != before) s->errors++;
}

static struct native_stream *find_stream(struct side *s, HQUIC h)
{
    for (unsigned i = s->stream_count; i > 0; --i)
        if (s->streams[i - 1].handle == h) return &s->streams[i - 1];
    return NULL;
}

static bool open_application_stream(struct side *s, unsigned index)
{
    unsigned before = s->stream_count;
    wtq_result_t rc = wtq_session_open_uni(s->session, &s->app_streams[index]);
    if (rc != WTQ_OK || !s->app_streams[index]) return false;
    wtq_stream_add_ref(s->app_streams[index]);
    if (s->stream_count != before + 1 || !s->streams[before].handle) return false;
    s->app_native[index] = &s->streams[before];
    s->app_native[index]->facts.identity = s->app_streams[index];
    s->app_sends[index].stream = s->app_native[index];
    return true;
}

static bool send_application(struct side *s, unsigned index,
    const wtq_span_t *span, bool fin)
{
    struct application_send *send = &s->app_sends[index];
    if (!send->stream || send->submitted) return false;
    send->submitted = true;
    wtq_result_t rc = wtq_stream_send(s->app_streams[index], span, span ? 1 : 0,
        fin ? WTQ_SEND_FIN : 0, send);
    if (rc != WTQ_OK) return false;
    send->stream->facts.accepted++;
    send->stream->facts.fin_submitted = fin;
    return true;
}

static bool submit(struct side *s, bool fin)
{
    static const uint8_t bytes[] = { 1, 2, 3, 4 };
    wtq_span_t span = { .data = bytes, .len = sizeof(bytes) };
    s->payload_started = true;
    return send_application(s, 0, &span, fin);
}

static QUIC_STATUS QUIC_API stream_event(HQUIC h, void *ctx, QUIC_STREAM_EVENT *ev)
{
    struct native_stream *st = ctx;
    /* The backend callback owns entry/leave. These event-oracle counters are
     * updated inside that same guard by the forwarding guard below. */
    return st->callback(h, st->ctx, ev);
}

static _Thread_local QUIC_STREAM_EVENT *entering_event;
static _Thread_local struct native_stream *entering_stream;

static QUIC_STATUS QUIC_API stream_event_observed(HQUIC h, void *ctx,
    QUIC_STREAM_EVENT *ev)
{
    entering_event = ev;
    entering_stream = ctx;
    QUIC_STATUS result = stream_event(h, ctx, ev);
    entering_event = NULL;
    entering_stream = NULL;
    return result;
}

static void guarded_enter(void *ctx)
{
    struct side *s = ctx;
    enter(s);
    QUIC_STREAM_EVENT *ev = entering_event;
    struct native_stream *st = entering_stream;
    if (!ev || !s->active || !st) return;
    if (ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE) {
        bool found = false;
        for (unsigned i = 0; i < 16; ++i) {
            struct native_send *send = &s->sends[i];
            if (!send->occupied || send->stream != st ||
                send->ctx != ev->SEND_COMPLETE.ClientContext) continue;
            found = true;
            if (!st->facts.borrows) s->errors++;
            else st->facts.borrows--;
            if (send->bytes) { s->pending_bytes--; st->pending_bytes--; }
            if (ev->SEND_COMPLETE.Canceled && (send->bytes || send->fin) &&
                !st->canceled_intent) s->lost = true;
            send->occupied = false;
            break;
        }
        if (!found) s->errors++;
    } else if (ev->Type == QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE) {
        st->facts.shutdowns++;
        if (st->facts.shutdowns != 1) s->errors++;
        if (ev->SEND_SHUTDOWN_COMPLETE.Graceful) {
            s->graceful++;
            st->facts.graceful++;
        }
        else {
            s->abortive++;
            st->facts.abortive++;
            if ((st->fin || st->pending_bytes) && !st->canceled_intent) s->lost = true;
        }
        st->shutdown_settled = true;
        if (st->fin) { st->fin = false; s->pending_fins--; }
    }
}

static void guarded_leave(void *ctx)
{
    struct side *s = ctx;
    QUIC_STREAM_EVENT *ev = entering_event;
    struct native_stream *st = entering_stream;
    if (s->active && ev && st) {
        observe(s); /* after backend accounting, before releasing the lane */
        if ((s->row == 1 || s->row == 3) && !s->payload_started &&
            ev->Type == QUIC_STREAM_EVENT_SEND_COMPLETE && st == &s->streams[0]) {
            /* Submission happens before returning this preface callback;
             * queued reset and subsequent ACK processing can still race. */
            if (!submit(s, true)) s->errors++;
            observe(s);
            if (!s->errors && s->row == 1) {
                s->application_cancel = true;
                if (wtq_stream_reset(s->app_streams[0], 42) != WTQ_OK) s->errors++;
                s->application_cancel = false;
            } else if (!s->errors) {
                /* Deliberately bypass application intent: real provider loss
                 * must remain distinct from the authorized-reset row. */
                if (QUIC_FAILED(native->StreamShutdown(st->handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, 42))) s->errors++;
            }
            observe(s);
        }
    }
    leave(s);
}

static QUIC_STATUS QUIC_API observed_open(HQUIC conn, QUIC_STREAM_OPEN_FLAGS flags,
    QUIC_STREAM_CALLBACK_HANDLER cb, void *ctx, HQUIC *out)
{
    struct side *s = current;
    s->provider_calls++;
    if (s->stream_count == 4) return QUIC_STATUS_OUT_OF_MEMORY;
    struct native_stream *st = &s->streams[s->stream_count++];
    st->side = s; st->callback = cb; st->ctx = ctx;
    QUIC_STATUS status = native->StreamOpen(conn, flags, stream_event_observed, st, out);
    if (QUIC_SUCCEEDED(status)) st->handle = *out;
    return status;
}

static QUIC_STATUS QUIC_API observed_send(HQUIC h, const QUIC_BUFFER *bufs,
    uint32_t count, QUIC_SEND_FLAGS flags, void *ctx)
{
    struct side *s = current;
    s->provider_calls++;
    struct native_stream *st = find_stream(s, h);
    struct native_send *rec = NULL;
    if (s->active && st) {
        for (unsigned i = 0; i < 16; ++i)
            if (!s->sends[i].occupied) { rec = &s->sends[i]; break; }
        if (!rec) return QUIC_STATUS_OUT_OF_MEMORY;
        bool bytes = false;
        for (uint32_t i = 0; i < count; ++i) bytes |= bufs[i].Length != 0;
        *rec = (struct native_send){ .ctx = ctx, .stream = st, .occupied = true,
            .bytes = bytes, .fin = (flags & QUIC_SEND_FLAG_FIN) != 0 };
        st->facts.borrows++;
        if (bytes) { s->pending_bytes++; st->pending_bytes++; }
        if (rec->fin && !st->fin) { st->fin = true; s->pending_fins++; }
    }
    QUIC_STATUS status = native->StreamSend(h, bufs, count, flags, ctx);
    if (QUIC_FAILED(status) && rec) {
        st->facts.borrows--;
        if (rec->bytes) { s->pending_bytes--; st->pending_bytes--; }
        if (rec->fin && st->fin) { st->fin = false; s->pending_fins--; }
        rec->occupied = false;
    }
    return status;
}

static QUIC_STATUS QUIC_API observed_shutdown(HQUIC h,
    QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    struct side *s = current;
    s->provider_calls++;
    if (flags & QUIC_STREAM_SHUTDOWN_FLAG_INLINE) {
        s->errors++;
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    struct native_stream *st = find_stream(s, h);
    bool cancel = s->active && s->application_cancel && st &&
        (flags & QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND);
    if (cancel) st->decision = st->facts.decision = true;
    QUIC_STATUS status = native->StreamShutdown(h, flags, code);
    if (cancel) {
        if (QUIC_SUCCEEDED(status))
            st->canceled_intent = st->facts.intent_accepted = true;
        st->decision = st->facts.decision = false;
    }
    return status;
}

static QUIC_STATUS QUIC_API observed_get_param(HQUIC handle, uint32_t param,
    uint32_t *size, void *buffer)
{
    current->provider_calls++;
    return native->GetParam(handle, param, size, buffer);
}

static void established(wtq_session_t *session, wtq_str_t protocol, void *ctx)
{
    (void)protocol;
    struct side *s = ctx;
    s->established++;
    if (s->server) {
        s->session = session;
        wtq_session_add_ref(session);
        return;
    }
    pthread_mutex_lock(&s->env->mu);
    for (struct wtq_driver *d = s->env->conns; d; d = d->env_next)
        if (d->session == session) { s->driver = d; break; }
    pthread_mutex_unlock(&s->env->mu);
    if (!s->driver) { s->errors++; return; }
    QUIC_SETTINGS settings = { 0 };
    uint32_t size = sizeof(settings);
    if (QUIC_FAILED(native->GetParam(s->driver->conn, QUIC_PARAM_CONN_SETTINGS,
            &size, &settings))) s->errors++;
    s->actual_buffering = settings.SendBufferingEnabled != FALSE;
    if (s->actual_buffering != (s->row == 2)) s->errors++;
    if (wtq_session_local_flush_mode(session) !=
        (s->row == 2 ? WTQ_LOCAL_FLUSH_UNSUPPORTED : WTQ_LOCAL_FLUSH_ACKNOWLEDGED)) s->errors++;
    s->observed = *s->driver->api;
    s->observed.StreamOpen = observed_open;
    s->observed.StreamSend = observed_send;
    s->observed.StreamShutdown = observed_shutdown;
    s->observed.GetParam = observed_get_param;
    s->driver->api = &s->observed;
}

static void returned(wtq_session_t *session, void *cookie, bool canceled, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    if (!s->active) return;
    struct application_send *send = NULL;
    for (unsigned i = 0; i < 2; ++i)
        if (cookie == &s->app_sends[i]) send = &s->app_sends[i];
    if (!send || !send->submitted || send->returned || !send->stream || current != s) {
        s->errors++;
        return;
    }
    send->returned = true;
    send->stream->facts.returned++;
    send->stream->facts.canceled += canceled;
    s->returned++; s->canceled += canceled;
    observe(s); /* query on the already-held callback domain, never relock */
}

static void committed(wtq_session_t *session, wtq_stream_t *stream, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    struct native_stream *st = NULL;
    for (unsigned i = 0; i < 2; ++i)
        if (stream == s->app_streams[i]) st = s->app_native[i];
    if (!st) s->errors++;
    else st->facts.commits++;
    if (stream != s->app_streams[s->row == 1 ? 1 : 0]) s->errors++;
    s->commits++;
    observe(s);
}

static void quiesced(wtq_session_t *session, void *ctx)
{
    struct side *s = ctx;
    s->terminal_result = wtq_session_local_flush(session);
    if (!s->server && s->row == 3 && s->terminal_result != WTQ_ERR_BACKEND) s->errors++;
    if (s->terminal_result != WTQ_ERR_BACKEND && s->terminal_result != WTQ_ERR_CLOSED) s->errors++;
    s->driver = NULL;
}

static wtq_result_t prepare(void *ctx, const wtq_msquic_accept_info_t *info,
    wtq_msquic_accept_decision_t *out)
{
    (void)info;
    out->accepted = true; out->user = ctx;
    out->guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = ctx };
    return WTQ_OK;
}
static void abandon(void *listener_user, void *ctx)
{
    (void)listener_user;
    ((struct side *)ctx)->errors++;
}

enum native_phase { PH_INITIAL, PH_FIRST, PH_REPLACEMENT };

static enum nf_flush flush_fact(wtq_result_t rc)
{
    if (rc == WTQ_OK) return NF_FLUSH_OK;
    if (rc == WTQ_ERR_WOULD_BLOCK) return NF_FLUSH_PENDING;
    if (rc == WTQ_ERR_BACKEND) return NF_FLUSH_LOSS;
    return NF_FLUSH_INVALID;
}

static void phase_snapshot(struct side *s, enum native_phase phase,
    const char *reason)
{
    fprintf(stderr, "native phase row%u phase=%u reason=%s flush=%d\n",
        s->row, (unsigned)phase, reason, wtq_session_local_flush(s->session));
    for (unsigned i = 0; i < 2; ++i) {
        if (!s->app_native[i]) continue;
        const struct nf_stream *f = &s->app_native[i]->facts;
        fprintf(stderr, "native stream%u accepted=%u returned=%u canceled=%u borrows=%u shutdowns=%u graceful=%u abortive=%u commits=%u fin=%u intent=%u decision=%u\n",
            i, f->accepted, f->returned, f->canceled, f->borrows, f->shutdowns,
            f->graceful, f->abortive, f->commits, (unsigned)f->fin_submitted,
            (unsigned)f->intent_accepted, (unsigned)f->decision);
    }
}

static bool wait_for(struct side *s, enum native_phase phase)
{
    struct timespec until;
    if (clock_gettime(CLOCK_REALTIME, &until) != 0) {
        phase_snapshot(s, phase, "clock_error");
        return false;
    }
    until.tv_sec += 10;
    for (;;) {
        if (s->errors) { phase_snapshot(s, phase, "observation_error"); return false; }
        bool ready = false;
        if (phase == PH_INITIAL) ready = s->established && s->driver &&
            (s->row == 2 || wtq_session_local_flush(s->session) == WTQ_OK);
        else if (s->row == 1 || s->row == 3) {
            enum nf_flush flush = flush_fact(wtq_session_local_flush(s->session));
            enum nf_result result = NF_INVALID;
            if (s->app_native[0]) {
                if (phase == PH_REPLACEMENT && s->app_native[1])
                    result = nf_replacement(&s->app_native[0]->facts,
                        s->app_streams[0], &s->app_native[1]->facts,
                        s->app_streams[1], flush);
                else if (phase == PH_FIRST)
                    result = nf_canceled(&s->app_native[0]->facts,
                        s->app_streams[0], s->row == 1, flush);
            }
            if (result == NF_INVALID || result == NF_COVERAGE_NOT_EXERCISED) {
                phase_snapshot(s, phase, result == NF_INVALID ?
                    "invalid_evidence" : "COVERAGE_NOT_EXERCISED");
                return false;
            }
            ready = result == NF_PASS;
        }
        else if (s->row == 2) ready = s->returned == 1;
        else ready = s->returned == 2 && s->graceful == 2 && s->commits == 1 &&
            wtq_session_local_flush(s->session) == WTQ_OK;
        if (ready) return true;
        /* Event-driven condition, no readiness sleeps or polling interval. */
        int rc = pthread_cond_timedwait(&s->changed, &s->lane, &until);
        if (rc != 0) {
            phase_snapshot(s, phase, rc == ETIMEDOUT ? "deadline" : "wait_error");
            return false;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int failures = 0;
    char cert[1024], key[1024];
    int nc = snprintf(cert, sizeof(cert), "%s/cert.pem", argv[1]);
    int nk = snprintf(key, sizeof(key), "%s/key.pem", argv[1]);
    if (nc < 0 || nk < 0 || (size_t)nc >= sizeof(cert) || (size_t)nk >= sizeof(key)) return 2;
#define ROW_REQUIRE(condition) do { \
    bool ok = (condition); \
    WTQ_TEST_CHECK(ok); \
    if (!ok) { client.errors++; goto row_cleanup; } \
} while (0)
    for (unsigned row = 0; row < 4; ++row) {
        struct side client = { .lane = PTHREAD_MUTEX_INITIALIZER,
            .changed = PTHREAD_COND_INITIALIZER, .row = row };
        struct side server = { .lane = PTHREAD_MUTEX_INITIALIZER,
            .changed = PTHREAD_COND_INITIALIZER, .server = true };
        bool lane_held = false;
        wtq_msquic_env_t *env = NULL;
        wtq_msquic_listener_t *listener = NULL;
        wtq_msquic_env_cfg_t ec = WTQ_MSQUIC_ENV_CFG_INIT;
        wtq_msquic_tuning_init(&ec.tuning);
        ROW_REQUIRE(!ec.tuning.send_buffering);
        if (row == 2) ec.tuning.send_buffering = true;
        ROW_REQUIRE(wtq_msquic_env_open(&ec, &env) == WTQ_OK);
        ROW_REQUIRE(env != NULL);
        native = env->api;
        client.env = server.env = env;
        wtq_session_events_t ev = WTQ_SESSION_EVENTS_INIT;
        ev.on_established = established; ev.on_send_complete = returned;
        ev.on_stream_send_committed = committed;
        wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
        serve.path = "/flush";
        wtq_msquic_listener_cfg_t lc = WTQ_MSQUIC_LISTENER_CFG_INIT;
        lc.bind_address = "127.0.0.1"; lc.cert_file = cert; lc.key_file = key;
        lc.paths = &serve; lc.path_count = 1; lc.events = &ev; lc.user = &server;
        lc.accept_prepare = prepare; lc.accept_abandon = abandon;
        lc.on_transport_quiesced = quiesced;
        ROW_REQUIRE(wtq_msquic_listener_start(env, &lc, &listener) == WTQ_OK);
        ROW_REQUIRE(listener != NULL);
        wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
        cc.authority = "localhost"; cc.path = "/flush";
        wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
        cfg.server_name = "127.0.0.1"; cfg.port = wtq_msquic_listener_port(listener);
        cfg.insecure_skip_verify = true;
        cfg.connect = &cc; cfg.events = &ev; cfg.user = &client;
        cfg.guard = (wtq_guard_t){ .enter = guarded_enter, .leave = guarded_leave, .ctx = &client };
        cfg.on_transport_quiesced = quiesced;
        enter(&client);
        lane_held = true;
        ROW_REQUIRE(wtq_msquic_client_connect(env, &cfg, &client.session) == WTQ_OK);
        ROW_REQUIRE(client.session != NULL && wait_for(&client, PH_INITIAL));
        client.active = true;
        ROW_REQUIRE(open_application_stream(&client, 0));
        if (row != 2)
            ROW_REQUIRE(wtq_stream_enable_send_commit(client.app_streams[0]) == WTQ_OK);
        if (row == 0) {
            ROW_REQUIRE(open_application_stream(&client, 1));
            ROW_REQUIRE(submit(&client, true));
            ROW_REQUIRE(send_application(&client, 1, NULL, true));
            ROW_REQUIRE(wtq_session_local_flush(client.session) == WTQ_ERR_WOULD_BLOCK);
        } else if (row == 2) ROW_REQUIRE(submit(&client, false));
        ROW_REQUIRE(wait_for(&client, PH_FIRST));
        observe(&client);
        ROW_REQUIRE(client.errors == 0);
        if (row == 1 || row == 3) {
            const struct nf_stream *f = &client.app_native[0]->facts;
            printf("native settlement row%u: returned=%u canceled=%u borrows=%u shutdowns=%u graceful=%u abortive=%u commits=%u intent=%u flush=%d\n",
                row, f->returned, f->canceled, f->borrows, f->shutdowns,
                f->graceful, f->abortive, f->commits, (unsigned)f->intent_accepted,
                wtq_session_local_flush(client.session));
        }
        if (row == 1) {
            ROW_REQUIRE(client.commits == 0);
            ROW_REQUIRE(wtq_session_local_flush(client.session) == WTQ_OK);
            ROW_REQUIRE(open_application_stream(&client, 1));
            ROW_REQUIRE(wtq_stream_enable_send_commit(client.app_streams[1]) == WTQ_OK);
            static const uint8_t next_bytes[] = { 5, 6, 7, 8 };
            wtq_span_t next = { .data = next_bytes, .len = sizeof(next_bytes) };
            ROW_REQUIRE(send_application(&client, 1, &next, true));
            ROW_REQUIRE(wtq_session_local_flush(client.session) == WTQ_ERR_WOULD_BLOCK);
            ROW_REQUIRE(wait_for(&client, PH_REPLACEMENT));
            observe(&client);
            ROW_REQUIRE(client.errors == 0);
            const struct nf_stream *f = &client.app_native[1]->facts;
            printf("native replacement row1: returned=%u canceled=%u borrows=%u shutdowns=%u graceful=%u abortive=%u commits=%u flush=%d\n",
                f->returned, f->canceled, f->borrows, f->shutdowns,
                f->graceful, f->abortive, f->commits,
                wtq_session_local_flush(client.session));
        } else if (row == 3)
            ROW_REQUIRE(wtq_session_local_flush(client.session) == WTQ_ERR_BACKEND);
row_cleanup:
        client.active = false;
        if (lane_held && client.session && client.established)
            WTQ_TEST_CHECK_EQ_INT(wtq_session_close(client.session, 0, NULL, 0), WTQ_OK);
        if (lane_held) leave(&client);
        if (listener) wtq_msquic_listener_stop(listener);
        if (env) wtq_msquic_env_close(env);
        WTQ_TEST_CHECK_EQ_INT(client.errors, 0);
        WTQ_TEST_CHECK_EQ_INT(server.errors, 0);
        if (client.session)
            WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(client.session), client.terminal_result);
        printf("native local flush row%u: buffering=%u returned=%u canceled=%u graceful=%u abortive=%u commits=%u errors=%d\n",
            row, (unsigned)client.actual_buffering, client.returned, client.canceled,
            client.graceful, client.abortive, client.commits, client.errors);
        wtq_stream_release(client.app_streams[0]);
        wtq_stream_release(client.app_streams[1]);
        wtq_session_release(client.session); wtq_session_release(server.session);
        pthread_cond_destroy(&client.changed); pthread_mutex_destroy(&client.lane);
        pthread_cond_destroy(&server.changed); pthread_mutex_destroy(&server.lane);
        if (failures) break;
    }
#undef ROW_REQUIRE
    return failures ? 1 : 0;
}
