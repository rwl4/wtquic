/* Real pinned MsQuic grant accounting; private struct inspection is test-only. */
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
    wtq_stream_t *held[16];
    unsigned opened, terminal, resident;
    uint64_t grant;
    bool server, established;
    int errors;
};

static void enter(void *ctx) { pthread_mutex_lock(&((struct side *)ctx)->lane); }
static void leave(void *ctx)
{
    struct side *s = ctx;
    /* Called on the native worker, before returning its callback. GetParam
     * is inline here, never a cross-thread wait while owning the guard. */
    if (s->server && s->driver) {
        uint64_t ids[4] = { 0 };
        uint32_t size = sizeof(ids);
        if (QUIC_FAILED(s->driver->api->GetParam(s->driver->conn,
                QUIC_PARAM_CONN_MAX_STREAM_IDS, &size, ids))) s->errors++;
        s->grant = ids[2] >> 2; /* client-initiated uni cumulative grant */
        s->terminal = s->resident = 0;
        for (size_t i = 0; i < 15; ++i) {
            struct wtq_dstream *ds = &s->driver->peers[i];
            if (!ds->occupied) continue;
            s->resident++;
            if (ds->shutdown_complete && ds->credit_held) s->terminal++;
        }
    }
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lane);
}

static void quiesced(wtq_session_t *session, void *ctx)
{
    (void)session;
    ((struct side *)ctx)->driver = NULL;
}

static void established(wtq_session_t *session, wtq_str_t sub, void *ctx)
{
    (void)sub;
    struct side *s = ctx;
    s->established = true;
    if (s->server) { s->session = session; wtq_session_add_ref(session); }
    pthread_mutex_lock(&s->env->mu);
    for (struct wtq_driver *d = s->env->conns; d; d = d->env_next)
        if (d->session == session) { s->driver = d; break; }
    pthread_mutex_unlock(&s->env->mu);
    if (!s->driver || !s->driver->bounded_admission) s->errors++;
}

static void opened(wtq_session_t *session, wtq_stream_t *st, bool bidi, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    if (bidi || s->opened >= 16) { s->errors++; return; }
    wtq_stream_add_ref(st);
    s->held[s->opened++] = st;
}

static wtq_result_t prepare(void *ctx, const wtq_msquic_accept_info_t *info,
    wtq_msquic_accept_decision_t *out)
{
    (void)info;
    out->accepted = true;
    out->guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = ctx };
    out->user = ctx;
    return WTQ_OK;
}

static void abandon(void *listener_user, void *user)
{
    (void)listener_user;
    ((struct side *)user)->errors++;
}

static bool wait_state(struct side *s, unsigned opened_count, unsigned terminals)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    while (!s->established || s->opened < opened_count || s->terminal < terminals)
        if (pthread_cond_timedwait(&s->changed, &s->lane, &until) != 0) return false;
    return true;
}

static QUIC_STATUS QUIC_API raw_callback(HQUIC stream, void *ctx, QUIC_STREAM_EVENT *ev)
{
    const QUIC_API_TABLE *api = ctx;
    if (ev->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE &&
        !ev->SHUTDOWN_COMPLETE.AppCloseInProgress) api->StreamClose(stream);
    return QUIC_STATUS_SUCCESS;
}

static bool sparse_ready(const struct side *s)
{
    for (size_t i = 8; i < 15; ++i)
        if (s->driver->peers[i].occupied && s->driver->peers[i].id == 24 &&
            s->driver->peers[i].admission.es != NULL) return true;
    return false;
}

int main(int argc, char **argv)
{
    int failures = 0;
    if (argc != 2) return 1;
    char cert[1024], key[1024];
    (void)snprintf(cert, sizeof(cert), "%s/cert.pem", argv[1]);
    (void)snprintf(key, sizeof(key), "%s/key.pem", argv[1]);
    struct side client = { .lane = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER };
    struct side server = { .lane = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER, .server = true };
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (!env) return failures;
    client.env = server.env = env;
    wtq_session_events_t events;
    wtq_session_events_init(&events);
    events.on_established = established;
    events.on_stream_opened = opened;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    serve.path = "/admission";
    wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
    lcfg.bind_address = "127.0.0.1";
    lcfg.cert_file = cert; lcfg.key_file = key;
    lcfg.paths = &serve; lcfg.path_count = 1;
    lcfg.events = &events; lcfg.user = &server;
    lcfg.accept_prepare = prepare;
    lcfg.accept_abandon = abandon;
    lcfg.on_transport_quiesced = quiesced;
    wtq_msquic_listener_t *listener = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_listener_start(env, &lcfg, &listener), WTQ_OK);
    if (!listener) { wtq_msquic_env_close(env); return failures; }
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost"; connect.path = "/admission";
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = wtq_msquic_listener_port(listener);
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect; cfg.events = &events; cfg.user = &client;
    cfg.guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = &client };
    cfg.on_transport_quiesced = quiesced;
    pthread_mutex_lock(&client.lane);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &cfg, &client.session), WTQ_OK);
    bool ready = client.session && wait_state(&client, 0, 0);
    WTQ_TEST_CHECK(ready);
    if (ready) {
        static const uint8_t byte = 0xa5;
        wtq_span_t span = { .data = &byte, .len = 1 };
        /* Three local H3 critical streams already use uni credit. The sixth
         * WT stream must wait behind five native-terminal retained leases. */
        for (size_t i = 0; i < 6; ++i) {
            wtq_stream_t *st = NULL;
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(client.session, &st), WTQ_OK);
            if (st) WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL), WTQ_OK);
        }
    }
    pthread_mutex_unlock(&client.lane);
    pthread_mutex_lock(&server.lane);
    ready = ready && wait_state(&server, 5, 5);
    WTQ_TEST_CHECK(ready);
    if (ready) {
        WTQ_TEST_CHECK_EQ_INT(server.opened, 5);
        WTQ_TEST_CHECK_EQ_INT(server.resident, 9); /* eight uni + CONNECT bidi */
        WTQ_TEST_CHECK_EQ_U64(server.grant, 8);
        wtq_stream_release(server.held[0]); server.held[0] = NULL;
        WTQ_TEST_CHECK_EQ_U64(server.grant, 8);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(server.session), WTQ_OK);
        WTQ_TEST_CHECK(wait_state(&server, 6, 5));
        WTQ_TEST_CHECK_EQ_U64(server.grant, 9);
        WTQ_TEST_CHECK_EQ_INT(server.resident, 9);
        printf("native grant: held=8 released-one=%llu resident=%u opened=%u\n",
            (unsigned long long)server.grant, server.resident, server.opened);
    }
    pthread_mutex_unlock(&server.lane);
    if (ready) {
        /* Only the highest new bidi gets STREAM bytes. MsQuic must materialize
         * the five missing ordinals too, each with a delayed credit record. */
        pthread_mutex_lock(&client.lane);
        HQUIC raw[6] = { 0 };
        const QUIC_API_TABLE *api = client.driver->api;
        for (size_t i = 0; i < 6; ++i) {
            WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->StreamOpen(client.driver->conn,
                QUIC_STREAM_OPEN_FLAG_NONE, raw_callback, (void *)api, &raw[i])));
            if (raw[i]) WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->StreamStart(raw[i],
                QUIC_STREAM_START_FLAG_NONE)));
        }
        static uint8_t header_type = 1;
        static QUIC_BUFFER partial = { .Length = 1, .Buffer = &header_type };
        if (raw[5]) WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->StreamSend(raw[5],
            &partial, 1, QUIC_SEND_FLAG_NONE, NULL)));
        pthread_mutex_unlock(&client.lane);
        pthread_mutex_lock(&server.lane);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 10;
        while (server.resident < 15 || !sparse_ready(&server))
            if (pthread_cond_timedwait(&server.changed, &server.lane, &until) != 0) break;
        WTQ_TEST_CHECK_EQ_INT(server.resident, 15);
        unsigned incomplete = 0, requests = 0;
        for (size_t i = 8; i < 15; ++i) {
            const struct wtq_dstream *ds = &server.driver->peers[i];
            WTQ_TEST_CHECK(ds->occupied && ds->admission.reservation == i);
            if (ds->admission.es == NULL) incomplete++;
            else requests++;
        }
        WTQ_TEST_CHECK_EQ_INT(incomplete, 5);
        WTQ_TEST_CHECK_EQ_INT(requests, 2); /* CONNECT + partial highest request */
        printf("native sparse: resident=%u incomplete=%u request-parsers=%u\n",
            server.resident, incomplete, requests);
        pthread_mutex_unlock(&server.lane);
    }
    wtq_msquic_listener_stop(listener);
    wtq_msquic_env_close(env);
    WTQ_TEST_CHECK_EQ_INT(client.errors + server.errors, 0);
    for (size_t i = 0; i < 16; ++i) {
        if (server.held[i]) wtq_stream_release(server.held[i]);
        if (client.held[i]) wtq_stream_release(client.held[i]);
    }
    if (server.session) wtq_session_release(server.session);
    if (client.session) wtq_session_release(client.session);
    pthread_cond_destroy(&server.changed); pthread_mutex_destroy(&server.lane);
    pthread_cond_destroy(&client.changed); pthread_mutex_destroy(&client.lane);
    return failures;
}
