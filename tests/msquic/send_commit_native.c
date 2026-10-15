/* Real MsQuic; the private table observer forwards every call unchanged. */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "msq_internal.h"
#include "test_support.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

struct side {
    pthread_mutex_t lane;
    pthread_cond_t changed;
    wtq_msquic_env_t *env;
    wtq_session_t *session;
    struct wtq_driver *driver;
    QUIC_API_TABLE observed_api;
    HQUIC target;
    wtq_stream_t *stream;
    unsigned row;
    bool server, in_established;
    unsigned established, commits, closed, session_closed, returned, canceled;
    unsigned native_aborts, abort_inside_established;
    QUIC_STREAM_SHUTDOWN_FLAGS abort_flags;
    QUIC_UINT62 abort_code;
    QUIC_STATUS abort_status;
    wtq_result_t reset_result;
    unsigned order;
    int errors;
};

static const QUIC_API_TABLE *native_api;
static _Thread_local struct side *current_side;

static void enter(void *ctx)
{
    struct side *s = ctx;
    pthread_mutex_lock(&s->lane);
    current_side = s;
}

static void leave(void *ctx)
{
    struct side *s = ctx;
    current_side = NULL;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lane);
}

static QUIC_STATUS QUIC_API observed_shutdown(HQUIC stream,
    QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    struct side *s = current_side;
    QUIC_STATUS result = native_api->StreamShutdown(stream, flags, code);
    if (s != NULL && stream == s->target) {
        s->native_aborts++;
        s->abort_inside_established += s->in_established;
        s->abort_flags = flags;
        s->abort_code = code;
        s->abort_status = result;
    }
    return result;
}

static void committed(wtq_session_t *session, wtq_stream_t *st, void *ctx)
{
    struct side *s = ctx;
    if (s->server || st != s->stream || s->row > 1) s->errors++;
    s->commits++;
    s->order = s->order * 10 + 1;
    if (wtq_stream_reset(st, 42) != WTQ_ERR_CLOSED) s->errors++;
    if (wtq_session_close(session, 0, NULL, 0) != WTQ_OK) s->errors++;
    if (s->closed != 0 || s->session_closed != 0) s->errors++;
}

static void stream_closed(wtq_session_t *session, wtq_stream_t *st, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    if (!s->server && st != s->stream) s->errors++;
    s->closed++;
    s->order = s->order * 10 + 2;
}

static void session_closed(wtq_session_t *session, uint32_t code,
    const uint8_t *reason, size_t len, bool clean, void *ctx)
{
    (void)session; (void)code; (void)reason; (void)len; (void)clean;
    struct side *s = ctx;
    s->session_closed++;
    s->order = s->order * 10 + 3;
}

static void returned(wtq_session_t *session, void *cookie, bool canceled, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    if (cookie != s) s->errors++;
    s->returned++;
    s->canceled += canceled;
}

static void quiesced(wtq_session_t *session, void *ctx)
{
    (void)session;
    ((struct side *)ctx)->driver = NULL;
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
    s->in_established = true;
    pthread_mutex_lock(&s->env->mu);
    for (struct wtq_driver *d = s->env->conns; d != NULL; d = d->env_next)
        if (d->session == session) { s->driver = d; break; }
    pthread_mutex_unlock(&s->env->mu);
    if (s->driver == NULL) { s->errors++; return; }
    s->observed_api = *s->driver->api;
    s->observed_api.StreamShutdown = observed_shutdown;
    s->driver->api = &s->observed_api;
    if (wtq_session_send_commit_mode(session) != WTQ_SEND_COMMIT_LOCAL_UNI_ACK_FIN_RESETTABLE)
        s->errors++;
    if (wtq_session_open_uni(session, &s->stream) != WTQ_OK) { s->errors++; return; }
    wtq_stream_add_ref(s->stream);
    struct wtq_dstream *ds = s->driver->streams;
    s->target = ds->stream;
    if (!ds->is_local || ds->is_bidi || s->target == NULL) s->errors++;
    if (s->row != 5 && wtq_stream_enable_send_commit(s->stream) != WTQ_OK) s->errors++;
    static const uint8_t bytes[] = { 0x12, 0x34, 0x56, 0x78 };
    wtq_span_t span = { bytes, sizeof(bytes) };
    if (wtq_stream_send(s->stream, s->row == 0 ? NULL : &span, s->row == 0 ? 0 : 1,
                        WTQ_SEND_FIN, s) != WTQ_OK) s->errors++;
    if (s->row != 5 && (s->closed != 0 || ds->ectx == NULL)) s->errors++;
    if (s->row == 2 || s->row == 3) {
        /* Same native connection callback: its worker cannot process a peer
         * ACK until this frame returns. This is causal, not a timer race. */
        s->reset_result = s->row == 2 ? wtq_stream_reset(s->stream, 42)
                                      : wtq_stream_abort(s->stream, 42);
        if (s->reset_result != WTQ_OK) s->errors++;
    }
    if (s->row >= 2 && wtq_session_close(session, 0, NULL, 0) != WTQ_OK) s->errors++;
    s->in_established = false;
}

static wtq_result_t prepare(void *ctx, const wtq_msquic_accept_info_t *info,
    wtq_msquic_accept_decision_t *out)
{
    (void)info;
    out->accepted = true;
    out->user = ctx;
    out->guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = ctx };
    return WTQ_OK;
}

static void abandon(void *listener_user, void *ctx)
{
    (void)listener_user;
    ((struct side *)ctx)->errors++;
}

static bool wait_closed(struct side *s)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    while (s->session_closed == 0)
        if (pthread_cond_timedwait(&s->changed, &s->lane, &until) != 0) return false;
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int failures = 0;
    char cert[1024], key[1024];
    (void)snprintf(cert, sizeof(cert), "%s/cert.pem", argv[1]);
    (void)snprintf(key, sizeof(key), "%s/key.pem", argv[1]);
    for (unsigned row = 0; row < 6; ++row) {
        struct side client = { .lane = PTHREAD_MUTEX_INITIALIZER,
            .changed = PTHREAD_COND_INITIALIZER, .row = row };
        struct side server = { .lane = PTHREAD_MUTEX_INITIALIZER,
            .changed = PTHREAD_COND_INITIALIZER, .server = true };
        wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
        wtq_msquic_env_t *env = NULL;
        WTQ_TEST_CHECK(wtq_msquic_env_open(&ecfg, &env) == WTQ_OK);
        if (env == NULL) break;
        native_api = env->api;
        client.env = server.env = env;
        wtq_session_events_t events = WTQ_SESSION_EVENTS_INIT;
        events.on_established = established;
        events.on_stream_send_committed = committed;
        events.on_stream_closed = stream_closed;
        events.on_closed = session_closed;
        events.on_send_complete = returned;
        wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
        serve.path = "/commit";
        wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
        lcfg.bind_address = "127.0.0.1";
        lcfg.cert_file = cert; lcfg.key_file = key;
        lcfg.paths = &serve; lcfg.path_count = 1;
        lcfg.events = &events; lcfg.user = &server;
        lcfg.accept_prepare = prepare; lcfg.accept_abandon = abandon;
        lcfg.on_transport_quiesced = quiesced;
        wtq_msquic_listener_t *listener = NULL;
        WTQ_TEST_CHECK(wtq_msquic_listener_start(env, &lcfg, &listener) == WTQ_OK);
        if (listener == NULL) { wtq_msquic_env_close(env); break; }
        wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
        cc.authority = "localhost"; cc.path = "/commit";
        wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
        cfg.server_name = "127.0.0.1"; cfg.port = wtq_msquic_listener_port(listener);
        cfg.insecure_skip_verify = true;
        cfg.connect = &cc; cfg.events = &events; cfg.user = &client;
        cfg.guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = &client };
        cfg.on_transport_quiesced = quiesced;
        enter(&client);
        WTQ_TEST_CHECK(wtq_msquic_client_connect(env, &cfg, &client.session) == WTQ_OK);
        if (client.session != NULL) WTQ_TEST_CHECK(wait_closed(&client));
        leave(&client);
        wtq_msquic_listener_stop(listener);
        wtq_msquic_env_close(env);
        WTQ_TEST_CHECK_EQ_INT(client.errors, 0);
        WTQ_TEST_CHECK_EQ_INT(server.errors, 0);
        WTQ_TEST_CHECK_EQ_INT(client.established, 1);
        WTQ_TEST_CHECK_EQ_INT(client.commits, row < 2 ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT(client.closed, 1);
        WTQ_TEST_CHECK_EQ_INT(client.session_closed, 1);
        WTQ_TEST_CHECK_EQ_INT(client.returned, 1);
        WTQ_TEST_CHECK_EQ_INT(client.order, row < 2 ? 123 : 23);
        if (row == 2 || row == 3) {
            WTQ_TEST_CHECK_EQ_INT(client.native_aborts, 1);
            WTQ_TEST_CHECK_EQ_INT(client.abort_inside_established, 1);
            WTQ_TEST_CHECK(client.abort_flags & QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND);
            WTQ_TEST_CHECK_EQ_U64(client.abort_code, wtq_app_error_to_h3(42));
            WTQ_TEST_CHECK(QUIC_SUCCEEDED(client.abort_status));
        }
        printf("native commit row%u: commit=%u close=%u returns=%u canceled=%u abort=%u inside=%u order=%u errors=%d\n",
            row, client.commits, client.closed, client.returned, client.canceled,
            client.native_aborts, client.abort_inside_established, client.order, client.errors);
        wtq_stream_release(client.stream);
        wtq_session_release(client.session);
        wtq_session_release(server.session);
        pthread_cond_destroy(&client.changed); pthread_mutex_destroy(&client.lane);
        pthread_cond_destroy(&server.changed); pthread_mutex_destroy(&server.lane);
        if (failures != 0) break;
    }
    return failures ? 1 : 0;
}
