/*
 * White-box tests for the managed-domain contract (guard bracket,
 * transport-quiescence hook, and the client-publication race). Drives the
 * real backend callbacks (wtq_msq_conn_callback / wtq_msq_stream_callback)
 * with a caller-installed guard, below the engine's own argument guards.
 *
 * These are synchronous EXCEPT test_client_publication_race, which spawns a
 * worker and uses condition-variable gates (no sleeps) to prove a callback
 * cannot enter the guard while the "caller" holds it across publication.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "msq_internal.h"
#include "test_support.h"

/* The guard ctx = a "lane" that outlives every driver. */
struct lane {
    pthread_mutex_t mu;   /* the serialization-domain lock */
    int enters, leaves, depth, max_depth;
    int published;        /* client-publication race: set by the "caller" */
    int cb_saw_published; /* what a guarded dispatch observed on entry */
    int cb_entered;
};

static void lane_init(struct lane *L)
{
    memset(L, 0, sizeof(*L));
    pthread_mutex_init(&L->mu, NULL);
}
static void lane_destroy(struct lane *L) { pthread_mutex_destroy(&L->mu); }

static void guard_enter(void *ctx)
{
    struct lane *L = ctx;
    pthread_mutex_lock(&L->mu);
    L->cb_entered = 1;
    L->cb_saw_published = L->published;
    L->enters++;
    L->depth++;
    if (L->depth > L->max_depth)
        L->max_depth = L->depth;
}
static void guard_leave(void *ctx)
{
    struct lane *L = ctx;
    L->depth--;
    L->leaves++;
    pthread_mutex_unlock(&L->mu);
}
static wtq_guard_t lane_guard(struct lane *L)
{
    wtq_guard_t g = { guard_enter, guard_leave, L };
    return g;
}

/* Minimal MsQuic API table: the callbacks only need these to be present. */
static void QUIC_API noop_set_handler(HQUIC h, void *f, void *c)
{ (void)h; (void)f; (void)c; }
static void QUIC_API noop_stream_close(HQUIC h) { (void)h; }
static void QUIC_API noop_conn_close(HQUIC h) { (void)h; }
static void QUIC_API noop_conn_shutdown(HQUIC h, QUIC_CONNECTION_SHUTDOWN_FLAGS fl,
                                        QUIC_UINT62 code)
{ (void)h; (void)fl; (void)code; }
static QUIC_STATUS QUIC_API noop_stream_open(HQUIC c, QUIC_STREAM_OPEN_FLAGS f,
    QUIC_STREAM_CALLBACK_HANDLER h, void *ctx, HQUIC *out)
{ (void)c;(void)f;(void)h;(void)ctx; *out = (HQUIC)0x21; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API noop_stream_start(HQUIC s, QUIC_STREAM_START_FLAGS f)
{ (void)s;(void)f; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API noop_stream_send(HQUIC s, const QUIC_BUFFER *b,
    uint32_t n, QUIC_SEND_FLAGS f, void *c)
{ (void)s;(void)b;(void)n;(void)f;(void)c; return QUIC_STATUS_SUCCESS; }

static void api_init(QUIC_API_TABLE *api)
{
    memset(api, 0, sizeof(*api));
    api->SetCallbackHandler = noop_set_handler;
    api->StreamClose = noop_stream_close;
    api->ConnectionClose = noop_conn_close;
    api->ConnectionShutdown = noop_conn_shutdown;
    api->StreamOpen = noop_stream_open;
    api->StreamStart = noop_stream_start;
    api->StreamSend = noop_stream_send;
}

/* Build a client driver + session with a guard and optional quiescence
 * hook. Holds an extra caller ref so the session survives SHUTDOWN_COMPLETE
 * (which frees drv). */
static struct wtq_driver *rig(QUIC_API_TABLE *api, wtq_session_t **out,
                              wtq_guard_t g, wtq_msquic_transport_quiesced_fn q,
                              void *quser)
{
    api_init(api);
    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), api, true);
    if (drv == NULL)
        return NULL;
    drv->conn = (HQUIC)(void *)drv;
    drv->guard = g;
    drv->on_transport_quiesced = q;
    drv->quiesced_user = quser;

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    wtq_api_session_cfg_t scfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = NULL,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *s = NULL;
    if (wtq_api_session_create(&scfg, &s) != WTQ_OK) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return NULL;
    }
    drv->session = s;
    wtq_session_add_ref(s);
    *out = s;
    return drv;
}

static void feed_conn(struct wtq_driver *drv, QUIC_CONNECTION_EVENT_TYPE type)
{
    QUIC_CONNECTION_EVENT ev;
    memset(&ev, 0, sizeof(ev));
    ev.Type = type;
    if (type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
        ev.SHUTDOWN_COMPLETE.AppCloseInProgress = 1;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &ev);
}

/* --- 1. guard brackets connection AND stream callbacks ------------------ */
static int test_guard_brackets_callbacks(void)
{
    int failures = 0;
    struct lane L;
    lane_init(&L);
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = rig(&api, &sess, lane_guard(&L), NULL, NULL);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL) { lane_destroy(&L); return 1; }

    /* one connection callback -> one enter/leave pair (a benign event that
     * touches no driver ops) */
    feed_conn(drv, QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED);
    WTQ_TEST_CHECK_EQ_INT(L.enters, 1);
    WTQ_TEST_CHECK_EQ_INT(L.leaves, 1);

    /* a stream callback shares the same guard */
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, true, 4);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        ds->stream = (HQUIC)(void *)ds;
        QUIC_STREAM_EVENT sev;
        memset(&sev, 0, sizeof(sev));
        sev.Type = (QUIC_STREAM_EVENT_TYPE)0x7fffffff; /* default: no-op */
        (void)wtq_msq_stream_callback(ds->stream, ds, &sev);
        WTQ_TEST_CHECK_EQ_INT(L.enters, 2);
        WTQ_TEST_CHECK_EQ_INT(L.leaves, 2);
    }

    /* terminal frees drv; the guard leave still runs (copied {leave,ctx}) */
    feed_conn(drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
    WTQ_TEST_CHECK_EQ_INT(L.enters, 3);
    WTQ_TEST_CHECK_EQ_INT(L.leaves, 3);
    /* never nested */
    WTQ_TEST_CHECK_EQ_INT(L.max_depth, 1);

    wtq_session_release(sess);
    lane_destroy(&L);
    return failures;
}

/* --- 2. SHUTDOWN_COMPLETE: leave runs AFTER the driver is freed (ASan) --- */
static int test_leave_after_driver_free(void)
{
    int failures = 0;
    struct lane L;
    lane_init(&L);
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = rig(&api, &sess, lane_guard(&L), NULL, NULL);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL) { lane_destroy(&L); return 1; }

    /* The terminal frees drv inside conn_dispatch; the wrapper's leave uses
     * the lane (guard.ctx), which outlives drv. Under ASan a UAF here would
     * mean the wrapper read drv->guard after the free. */
    feed_conn(drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
    WTQ_TEST_CHECK_EQ_INT(L.enters, 1);
    WTQ_TEST_CHECK_EQ_INT(L.leaves, 1);

    wtq_session_release(sess);
    lane_destroy(&L);
    return failures;
}

/* --- 3. a guarded out-of-callback wtq_session_* operation --------------- */
static int test_guarded_out_of_callback_op(void)
{
    int failures = 0;
    struct lane L;
    lane_init(&L);
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = rig(&api, &sess, lane_guard(&L), NULL, NULL);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL) { lane_destroy(&L); return 1; }

    /* Not inside a callback: hold the guard and run a mutating session op.
     * It must execute (the engine's inner enter/leave is separate from the
     * guard, so no self-deadlock) — drain on a not-yet-established session
     * runs and returns WTQ_ERR_STATE. */
    guard_enter(&L);
    wtq_result_t rc = wtq_session_drain(sess);
    guard_leave(&L);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(L.enters, 1);
    WTQ_TEST_CHECK_EQ_INT(L.leaves, 1);

    /* tear down */
    feed_conn(drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
    wtq_session_release(sess);
    lane_destroy(&L);
    return failures;
}

/* --- 8. quiescence hook: exactly once, before the ref drop, valid handle - */
static int g_q_fired;
static wtq_session_t *g_q_sess;
static int g_q_status_ok;
static void on_quiesced(wtq_session_t *s, void *user)
{
    g_q_fired++;
    g_q_sess = s;
    /* handle still valid here: a query succeeds */
    g_q_status_ok = (wtq_session_status(s) == WTQ_SESSION_STATUS_CONNECTING ||
                     wtq_session_status(s) == WTQ_SESSION_STATUS_FAILED ||
                     wtq_session_status(s) == WTQ_SESSION_STATUS_CLOSED);
    *(int *)user = 42; /* per-connection user delivered */
}

static int test_quiescence_hook(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    int user_marker = 0;
    wtq_guard_t none = { NULL, NULL, NULL };
    struct wtq_driver *drv = rig(&api, &sess, none, on_quiesced, &user_marker);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL) return 1;
    g_q_fired = 0;
    g_q_sess = NULL;
    g_q_status_ok = 0;

    feed_conn(drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);

    WTQ_TEST_CHECK_EQ_INT(g_q_fired, 1);          /* exactly once */
    WTQ_TEST_CHECK(g_q_sess == sess);             /* the right session */
    WTQ_TEST_CHECK(g_q_status_ok);                /* handle valid inside */
    WTQ_TEST_CHECK_EQ_INT(user_marker, 42);       /* user delivered */

    wtq_session_release(sess);
    return failures;
}

/* --- 10. client-publication race: worker cannot enter until published ---- */
/*
 * Exercise the REAL client path: wtq_msquic_client_connect installs the
 * guard before ConnectionOpen, so a callback that begins at ConnectionStart
 * must block on the lane until the caller (holding it across connect)
 * publishes and releases. A fake ConnectionStart delivers that callback on
 * a worker thread; the guard's enter signals "attempted" before blocking.
 * Deterministic (mutex ordering), no sleeps. RED-validate by removing the
 * `drv->guard = cfg.guard` line in msq_client.c: the worker then never
 * blocks and observes published==0.
 */
struct race {
    struct lane lane;            /* guard.ctx */
    struct wtq_driver *drv;      /* captured at ConnectionOpen */
    pthread_t worker;
    pthread_mutex_t gmu;
    pthread_cond_t gcv;
    int attempted;               /* worker's callback reached guard.enter */
    int finished;                /* worker's callback returned */
    int worker_started;          /* pthread_create for the worker succeeded */
};
static struct race *g_race;

static void race_guard_enter(void *ctx)
{
    struct lane *L = ctx;
    pthread_mutex_lock(&g_race->gmu);   /* announce, THEN block on the lane */
    g_race->attempted = 1;
    pthread_cond_signal(&g_race->gcv);
    pthread_mutex_unlock(&g_race->gmu);
    pthread_mutex_lock(&L->mu);
    L->cb_entered = 1;
    L->cb_saw_published = L->published;
    L->enters++;
}

static void *race_worker(void *v)
{
    (void)v;
    QUIC_CONNECTION_EVENT ev;
    memset(&ev, 0, sizeof(ev));
    ev.Type = (QUIC_CONNECTION_EVENT_TYPE)0x7fffffff; /* default: no side effects */
    (void)wtq_msq_conn_callback((HQUIC)(void *)g_race, g_race->drv, &ev);
    /* Signal completion so a RED run (no guard installed => guard.enter
     * never runs, never blocks) fails via assertion rather than hanging. */
    pthread_mutex_lock(&g_race->gmu);
    g_race->finished = 1;
    pthread_cond_signal(&g_race->gcv);
    pthread_mutex_unlock(&g_race->gmu);
    return NULL;
}

static QUIC_STATUS QUIC_API race_config_open(
    HQUIC r, const QUIC_BUFFER *a, uint32_t n, const QUIC_SETTINGS *s,
    uint32_t sz, void *c, HQUIC *out)
{ (void)r;(void)a;(void)n;(void)s;(void)sz;(void)c; *out = (HQUIC)0x11; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API race_config_cred(HQUIC c, const QUIC_CREDENTIAL_CONFIG *cred)
{ (void)c;(void)cred; return QUIC_STATUS_SUCCESS; }
static void QUIC_API race_config_close(HQUIC c) { (void)c; }
static QUIC_STATUS QUIC_API race_conn_open(HQUIC r, QUIC_CONNECTION_CALLBACK_HANDLER h,
                                           void *ctx, HQUIC *out)
{ (void)r;(void)h; g_race->drv = ctx; *out = (HQUIC)0x12; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API race_conn_start(HQUIC conn, HQUIC config,
                                            QUIC_ADDRESS_FAMILY fam,
                                            const char *name, uint16_t port)
{ (void)conn;(void)config;(void)fam;(void)name;(void)port;
  /* async, like a real worker; a create failure must surface as a failed
   * start so client_connect unwinds rather than the test hanging on a
   * worker that never ran. */
  if (pthread_create(&g_race->worker, NULL, race_worker, NULL) != 0)
      return QUIC_STATUS_INTERNAL_ERROR;
  g_race->worker_started = 1;
  return QUIC_STATUS_SUCCESS; }

static int test_client_publication_race(void)
{
    int failures = 0;
    struct race R;
    memset(&R, 0, sizeof(R));
    lane_init(&R.lane);
    pthread_mutex_init(&R.gmu, NULL);
    pthread_cond_init(&R.gcv, NULL);
    g_race = &R;

    QUIC_API_TABLE api;
    api_init(&api);
    api.ConfigurationOpen = race_config_open;
    api.ConfigurationLoadCredential = race_config_cred;
    api.ConfigurationClose = race_config_close;
    api.ConnectionOpen = race_conn_open;
    api.ConnectionStart = race_conn_start;

    struct wtq_msquic_env env;
    memset(&env, 0, sizeof(env));
    env.alloc = *wtq_alloc_default();
    env.api = &api;
    env.registration = (HQUIC)0x10;
    pthread_mutex_init(&env.mu, NULL);
    pthread_cond_init(&env.cv, NULL);

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost";
    connect.path = "/x";
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = 443;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.guard.enter = race_guard_enter;   /* guard.ctx = the lane */
    cfg.guard.leave = guard_leave;
    cfg.guard.ctx = &R.lane;

    /* Hold the guard across connect (as a managed caller would across
     * publishing mc->ws). */
    pthread_mutex_lock(&R.lane.mu);        /* == guard held */

    wtq_session_t *sess = NULL;
    wtq_result_t rc = wtq_msquic_client_connect(&env, &cfg, &sess);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);

    /* Wait until the worker's callback either reached guard.enter (GREEN:
     * blocked on the lane we hold) or finished (RED: ran unguarded — the
     * guard was never installed, so guard.enter never fired). */
    pthread_mutex_lock(&R.gmu);
    while (!R.attempted && !R.finished)
        pthread_cond_wait(&R.gcv, &R.gmu);
    int ran_unguarded = R.finished && !R.attempted;
    pthread_mutex_unlock(&R.gmu);

    /* RED signal: the callback completed without ever entering the guard,
     * i.e. the guard was not installed before ConnectionStart. */
    WTQ_TEST_CHECK(!ran_unguarded);
    /* GREEN: the callback is blocked in guard.enter, pre-publication. */
    WTQ_TEST_CHECK_EQ_INT(R.lane.cb_entered, 0);

    R.lane.published = 1;                  /* publish, THEN release the guard */
    pthread_mutex_unlock(&R.lane.mu);

    /* Join before reading worker-owned lane state. A join failure means the
     * worker's writes are not synchronized to this thread, so the reads below
     * would be a data race — treat it as fatal and bail. */
    if (R.worker_started) {
        int jrc = pthread_join(R.worker, NULL);
        WTQ_TEST_CHECK_EQ_INT(jrc, 0);
        if (jrc != 0) {
            failures++;
            goto done;
        }
    }

    /* The worker entered only after publication+release => saw published. */
    WTQ_TEST_CHECK_EQ_INT(R.lane.cb_entered, 1);
    WTQ_TEST_CHECK_EQ_INT(R.lane.cb_saw_published, 1);

done:
    /* teardown: terminal frees drv + drops backend ref; release caller ref */
    if (R.drv != NULL)
        feed_conn(R.drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
    if (sess != NULL) wtq_session_release(sess);
    pthread_cond_destroy(&env.cv);
    pthread_mutex_destroy(&env.mu);
    pthread_cond_destroy(&R.gcv);
    pthread_mutex_destroy(&R.gmu);
    lane_destroy(&R.lane);
    g_race = NULL;
    return failures;
}

/* --- 11. ABI: the bare *_cfg_init symbols write only the frozen prefix --- */
/*
 * An OLD binary linked wtq_msquic_client_cfg_init / _listener_cfg_init when
 * the structs were smaller (pre-managed-domain). The bare exported symbols
 * MUST never write past that older object. Each test allocates a heap block
 * of EXACTLY the 07570ae layout size and calls the bare symbol through a
 * function pointer (so the header's size-forwarding macro does not intervene);
 * ASan bounds the write to the block. RED-validate by pointing the bare symbol
 * at the full-struct initialiser again — it then writes past the block.
 */
static int test_client_cfg_init_v1_abi(void)
{
    int failures = 0;
    void (*init)(wtq_msquic_client_cfg_t *) = wtq_msquic_client_cfg_init;
    const size_t v1 = sizeof(wtq_msquic_client_cfg_v1_t); /* 07570ae */
    unsigned char *buf = malloc(v1);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf == NULL) return 1;
    memset(buf, 0xEE, v1);
    init((wtq_msquic_client_cfg_t *)buf);   /* ASan: no write beyond v1 */
    uint32_t ss;
    memcpy(&ss, buf, sizeof(ss));
    WTQ_TEST_CHECK_EQ_INT((int)ss, (int)v1); /* records the frozen size */
    free(buf);
    return failures;
}
static int test_listener_cfg_init_v1_abi(void)
{
    int failures = 0;
    void (*init)(wtq_msquic_listener_cfg_t *) = wtq_msquic_listener_cfg_init;
    const size_t v1 =
        sizeof(wtq_msquic_listener_cfg_v1_t); /* 07570ae */
    unsigned char *buf = malloc(v1);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf == NULL) return 1;
    memset(buf, 0xEE, v1);
    init((wtq_msquic_listener_cfg_t *)buf); /* ASan: no write beyond v1 */
    uint32_t ss;
    memcpy(&ss, buf, sizeof(ss));
    WTQ_TEST_CHECK_EQ_INT((int)ss, (int)v1);
    free(buf);
    return failures;
}

/* --- 12. ABI: struct_size handling on the real client-connect path ------- */
/*
 * Drive wtq_msquic_client_connect with heap-backed configs of varied
 * struct_size, over a fake env whose ConnectionStart is a no-op (no worker):
 *   - the config buffer is sized to the caller's struct_size, so ASan flags
 *     any read past it, and
 *   - the fake ConnectionOpen captures the driver, so the test can prove the
 *     optional tail was honoured (or ignored) exactly as struct_size dictates.
 */
static struct wtq_driver *g_abi_drv;
static QUIC_STATUS QUIC_API abi_config_open(HQUIC r, const QUIC_BUFFER *a,
    uint32_t n, const QUIC_SETTINGS *s, uint32_t sz, void *c, HQUIC *out)
{ (void)r;(void)a;(void)n;(void)s;(void)sz;(void)c; *out = (HQUIC)0x11;
  return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API abi_config_cred(HQUIC c,
    const QUIC_CREDENTIAL_CONFIG *cr)
{ (void)c;(void)cr; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API abi_conn_open(HQUIC r,
    QUIC_CONNECTION_CALLBACK_HANDLER h, void *ctx, HQUIC *out)
{ (void)r;(void)h; g_abi_drv = ctx; *out = (HQUIC)0x12;
  return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API abi_conn_start(HQUIC conn, HQUIC config,
    QUIC_ADDRESS_FAMILY fam, const char *name, uint16_t port)
{ (void)conn;(void)config;(void)fam;(void)name;(void)port;
  return QUIC_STATUS_SUCCESS; }   /* async, no event fires */
static QUIC_STATUS QUIC_API abi_listener_open(HQUIC r,
    QUIC_LISTENER_CALLBACK_HANDLER h, void *ctx, HQUIC *out)
{ (void)r;(void)h;(void)ctx; *out = (HQUIC)0x30; return QUIC_STATUS_SUCCESS; }
static QUIC_STATUS QUIC_API abi_listener_start(HQUIC l, const QUIC_BUFFER *a,
    uint32_t n, const QUIC_ADDR *addr)
{ (void)l;(void)a;(void)n;(void)addr; return QUIC_STATUS_SUCCESS; }

/* Dummy admission/quiescence hooks — used only by ADDRESS in the listener ABI
 * tests, never invoked (no real accept occurs). */
static wtq_result_t abi_prepare(void *lu, const wtq_msquic_accept_info_t *info,
                                wtq_msquic_accept_decision_t *out)
{ (void)lu;(void)info; out->accepted = true; return WTQ_OK; }
static void abi_abandon(void *lu, void *u) { (void)lu;(void)u; }
static void abi_quiesced(wtq_session_t *s, void *u) { (void)s;(void)u; }

static void abi_env_init(struct wtq_msquic_env *env, QUIC_API_TABLE *api)
{
    api_init(api);
    api->ConfigurationOpen = abi_config_open;
    api->ConfigurationLoadCredential = abi_config_cred;
    api->ConfigurationClose = noop_conn_close;   /* void(*)(HQUIC) */
    api->ConnectionOpen = abi_conn_open;
    api->ConnectionStart = abi_conn_start;
    api->ListenerOpen = abi_listener_open;
    api->ListenerStart = abi_listener_start;
    api->ListenerClose = noop_conn_close;        /* void(*)(HQUIC) */
    memset(env, 0, sizeof(*env));
    env->alloc = *wtq_alloc_default();
    env->api = api;
    env->registration = (HQUIC)0x10;
    pthread_mutex_init(&env->mu, NULL);
    pthread_cond_init(&env->cv, NULL);
}
static void abi_env_destroy(struct wtq_msquic_env *env)
{
    pthread_cond_destroy(&env->cv);
    pthread_mutex_destroy(&env->mu);
}

/* Fill the required v1 fields of a (possibly undersized) heap client cfg.
 * Only fields at offsets < offsetof(guard) are written, so a buffer sized to
 * the v1 prefix is never overrun. */
static void abi_set_v1(void *buf, uint32_t struct_size,
                       const wtq_connect_config_t *connect,
                       const wtq_session_events_t *events, void *user)
{
    wtq_msquic_client_cfg_t *c = buf;
    c->struct_size = struct_size;
    c->server_name = "127.0.0.1";
    c->port = 443;
    c->insecure_skip_verify = true;
    c->connect = connect;
    c->events = events;
    c->user = user;
}

static void abi_connect_inputs(wtq_connect_config_t *connect,
                               wtq_session_events_t *events)
{
    *connect = (wtq_connect_config_t)WTQ_CONNECT_CONFIG_INIT;
    connect->authority = "localhost";
    connect->path = "/x";
    wtq_session_events_init(events);
}

/* prefix-minus-one: a struct_size that truncates the required v1 prefix is
 * rejected before any transport work (and before any over-read). */
static int test_abi_connect_prefix_minus_one(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);

    const size_t sz = sizeof(wtq_msquic_client_cfg_v1_t) - 1;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        /* Garbage (non-NULL) in the truncated prefix: the reject MUST happen
         * on struct_size alone, before cfg_copy pulls in a partial `events`
         * pointer that a later `events->struct_size` would dereference. */
        memset(buf, 0xEE, sz);
        ((wtq_msquic_client_cfg_t *)buf)->struct_size = (uint32_t)sz;
        wtq_session_t *s = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_client_connect(&env, (void *)buf, &s),
            (int)WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK(s == NULL);
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* exact v1 prefix: a legacy-sized config connects and carries NO guard. The
 * buffer is exactly the prefix, so a read past it would trip ASan. */
static int test_abi_connect_exact_v1(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_connect_config_t connect;
    wtq_session_events_t events;
    abi_connect_inputs(&connect, &events);

    const size_t sz = sizeof(wtq_msquic_client_cfg_v1_t);
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_v1(buf, (uint32_t)sz, &connect, &events, NULL);
        g_abi_drv = NULL;
        wtq_session_t *s = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_client_connect(&env, (void *)buf, &s),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(s != NULL && g_abi_drv != NULL);
        if (g_abi_drv != NULL)          /* legacy: no guard installed */
            WTQ_TEST_CHECK(g_abi_drv->guard.enter == NULL);
        if (g_abi_drv != NULL)
            feed_conn(g_abi_drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
        if (s != NULL) wtq_session_release(s);
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* partial tail: struct_size lands in the MIDDLE of `guard` (enter present,
 * leave truncated). The whole guard must be treated as absent — a truncated
 * pointer must never be installed and later dispatched through. */
static int test_abi_connect_partial_tail(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_connect_config_t connect;
    wtq_session_events_t events;
    abi_connect_inputs(&connect, &events);

    /* Cut struct_size INSIDE guard.leave — computed from the guard's ACTUAL
     * current offset and its own layout, not an assumed pointer size or the
     * frozen v1 size (the guard may be padded past sizeof(v1) on a stronger-
     * aligned ABI): guard.enter is fully present, guard.leave straddled.
     * Without gating, enter and the truncated leave both read non-NULL and a
     * bogus guard would be installed. */
    const size_t leave_off = offsetof(wtq_guard_t, leave);
    const size_t leave_sz = sizeof(((wtq_guard_t *)0)->leave);
    const size_t sz = offsetof(wtq_msquic_client_cfg_t, guard)
                      + leave_off + leave_sz / 2;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0xEE, sz);            /* garbage guard bytes */
        abi_set_v1(buf, (uint32_t)sz, &connect, &events, NULL);
        g_abi_drv = NULL;
        wtq_session_t *s = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_client_connect(&env, (void *)buf, &s),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(s != NULL && g_abi_drv != NULL);
        if (g_abi_drv != NULL)   /* partial guard ignored, not dispatched */
            WTQ_TEST_CHECK(g_abi_drv->guard.enter == NULL &&
                           g_abi_drv->guard.leave == NULL);
        if (g_abi_drv != NULL)
            feed_conn(g_abi_drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
        if (s != NULL) wtq_session_release(s);
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* oversized: a future caller's larger struct_size is accepted and its unknown
 * tail ignored, while the known guard (fully present) IS honoured. */
static int test_abi_connect_oversized(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_connect_config_t connect;
    wtq_session_events_t events;
    abi_connect_inputs(&connect, &events);
    struct lane L;
    lane_init(&L);

    const size_t sz = sizeof(wtq_msquic_client_cfg_t) + 64; /* unknown tail */
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_v1(buf, (uint32_t)sz, &connect, &events, NULL);
        ((wtq_msquic_client_cfg_t *)buf)->guard = lane_guard(&L);
        g_abi_drv = NULL;
        wtq_session_t *s = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_client_connect(&env, (void *)buf, &s),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(s != NULL && g_abi_drv != NULL);
        if (g_abi_drv != NULL)   /* known guard honoured despite big size */
            WTQ_TEST_CHECK(g_abi_drv->guard.enter == guard_enter);
        if (g_abi_drv != NULL)   /* SHUTDOWN_COMPLETE brackets via the guard */
            feed_conn(g_abi_drv, QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
        if (s != NULL) wtq_session_release(s);
        free(buf);
    }
    lane_destroy(&L);
    abi_env_destroy(&env);
    return failures;
}

/* listener: a struct_size that truncates the required v1 prefix is rejected
 * before any transport work — on struct_size alone, before cfg_copy pulls in a
 * partial `events`/cert pointer that later code would dereference. Heap-backed
 * so ASan bounds the (non-)read; garbage-filled so a missing gate would fault. */
static int test_abi_listener_prefix_minus_one(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);

    const size_t sz =
        sizeof(wtq_msquic_listener_cfg_v1_t) - 1;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0xEE, sz);
        ((wtq_msquic_listener_cfg_t *)buf)->struct_size = (uint32_t)sz;
        wtq_msquic_listener_t *l = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(&env, (void *)buf, &l),
            (int)WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK(l == NULL);
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* Fill the required v1 fields of a (possibly undersized) heap listener cfg.
 * Only fields at offsets < offsetof(accept_prepare) are written. */
static void abi_set_listener_v1(void *buf, uint32_t struct_size,
                                const wtq_serve_config_t *serve,
                                const wtq_session_events_t *events, void *user)
{
    wtq_msquic_listener_cfg_t *c = buf;
    c->struct_size = struct_size;
    c->bind_address = "127.0.0.1";
    c->port = 0;
    c->cert_file = "cert.pem";     /* faked LoadCredential: never opened */
    c->key_file = "key.pem";
    c->paths = serve;
    c->path_count = 1;
    c->events = events;
    c->user = user;
}

static void abi_serve(wtq_serve_config_t *serve)
{
    static const char *const protos[] = { "wtq-test" };
    *serve = (wtq_serve_config_t)WTQ_SERVE_CONFIG_INIT;
    serve->path = "/x";
    serve->subprotocols = protos;
    serve->subprotocol_count = 1;
}

/* exact v1 prefix through listener_start: a legacy-sized listener starts and
 * carries NO admission/quiescence. Heap-backed (sizeof frozen v1) so an over-read trips
 * ASan; the retained listener's hook fields are inspected directly. */
static int test_abi_listener_exact_v1(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_serve_config_t serve;
    abi_serve(&serve);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    const size_t sz = sizeof(wtq_msquic_listener_cfg_v1_t);
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_listener_v1(buf, (uint32_t)sz, &serve, &ev, NULL);
        wtq_msquic_listener_t *l = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(&env, (void *)buf, &l),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(l != NULL);
        if (l != NULL) {
            WTQ_TEST_CHECK(l->accept_prepare == NULL &&
                           l->accept_abandon == NULL &&
                           l->on_transport_quiesced == NULL);
            wtq_msquic_listener_stop(l);
        }
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* partial admission pair: struct_size lands mid accept_abandon. The pair must
 * be dropped whole — neither hook installed (else a truncated accept_abandon
 * would later be dispatched through). */
static int test_abi_listener_partial_pair(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_serve_config_t serve;
    abi_serve(&serve);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    const size_t fn =
        sizeof(((wtq_msquic_listener_cfg_t *)0)->accept_abandon);
    const size_t sz =
        offsetof(wtq_msquic_listener_cfg_t, accept_abandon) + fn / 2;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_listener_v1(buf, (uint32_t)sz, &serve, &ev, NULL);
        /* accept_prepare fully present; accept_abandon straddled (garbage). */
        ((wtq_msquic_listener_cfg_t *)buf)->accept_prepare = abi_prepare;
        memset(buf + offsetof(wtq_msquic_listener_cfg_t, accept_abandon),
               0xEE, sz - offsetof(wtq_msquic_listener_cfg_t, accept_abandon));
        wtq_msquic_listener_t *l = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(&env, (void *)buf, &l),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(l != NULL);
        if (l != NULL) {
            WTQ_TEST_CHECK(l->accept_prepare == NULL &&
                           l->accept_abandon == NULL);
            wtq_msquic_listener_stop(l);
        }
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* partial quiescence pointer: admission pair whole, on_transport_quiesced
 * straddled. Admission is honoured; the truncated quiescence hook is dropped. */
static int test_abi_listener_partial_quiesce(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_serve_config_t serve;
    abi_serve(&serve);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    const size_t fn =
        sizeof(((wtq_msquic_listener_cfg_t *)0)->on_transport_quiesced);
    const size_t sz =
        offsetof(wtq_msquic_listener_cfg_t, on_transport_quiesced) + fn / 2;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_listener_v1(buf, (uint32_t)sz, &serve, &ev, NULL);
        ((wtq_msquic_listener_cfg_t *)buf)->accept_prepare = abi_prepare;
        ((wtq_msquic_listener_cfg_t *)buf)->accept_abandon = abi_abandon;
        memset(buf + offsetof(wtq_msquic_listener_cfg_t, on_transport_quiesced),
               0xEE,
               sz - offsetof(wtq_msquic_listener_cfg_t, on_transport_quiesced));
        wtq_msquic_listener_t *l = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(&env, (void *)buf, &l),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(l != NULL);
        if (l != NULL) {
            WTQ_TEST_CHECK(l->accept_prepare == abi_prepare &&
                           l->accept_abandon == abi_abandon &&
                           l->on_transport_quiesced == NULL);
            wtq_msquic_listener_stop(l);
        }
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* oversized future config: known admission + quiescence fields are honoured
 * and the unknown tail ignored. */
static int test_abi_listener_oversized(void)
{
    int failures = 0;
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_serve_config_t serve;
    abi_serve(&serve);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    const size_t sz = sizeof(wtq_msquic_listener_cfg_t) + 64;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        abi_set_listener_v1(buf, (uint32_t)sz, &serve, &ev, NULL);
        ((wtq_msquic_listener_cfg_t *)buf)->accept_prepare = abi_prepare;
        ((wtq_msquic_listener_cfg_t *)buf)->accept_abandon = abi_abandon;
        ((wtq_msquic_listener_cfg_t *)buf)->on_transport_quiesced =
            abi_quiesced;
        wtq_msquic_listener_t *l = NULL;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(&env, (void *)buf, &l),
            (int)WTQ_OK);
        WTQ_TEST_CHECK(l != NULL);
        if (l != NULL) {
            WTQ_TEST_CHECK(l->accept_prepare == abi_prepare &&
                           l->accept_abandon == abi_abandon &&
                           l->on_transport_quiesced == abi_quiesced);
            wtq_msquic_listener_stop(l);
        }
        free(buf);
    }
    abi_env_destroy(&env);
    return failures;
}

/* Start a heap-backed listener cfg of a given struct_size and return the
 * profile the retained listener latched (or -1 if start failed). The buffer is
 * exactly struct_size, so ASan trips any read past it. */
static int abi_listener_profile_start(uint32_t struct_size,
                                      const unsigned char *profile_bytes,
                                      size_t profile_len,
                                      wtq_result_t *rc_out)
{
    struct wtq_msquic_env env;
    QUIC_API_TABLE api;
    abi_env_init(&env, &api);
    wtq_serve_config_t serve;
    abi_serve(&serve);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    int profile = -1;
    *rc_out = WTQ_ERR_NOMEM;
    unsigned char *buf = malloc(struct_size);
    if (buf != NULL) {
        memset(buf, 0, struct_size);
        abi_set_listener_v1(buf, struct_size, &serve, &ev, NULL);
        /* Write the (possibly partial) profile bytes at its field offset. */
        if (profile_len > 0)
            memcpy(buf + offsetof(wtq_msquic_listener_cfg_t,
                                  webtransport_profile),
                   profile_bytes, profile_len);
        wtq_msquic_listener_t *l = NULL;
        *rc_out = wtq_msquic_listener_start(&env, (void *)buf, &l);
        if (*rc_out == WTQ_OK && l != NULL) {
            profile = l->webtransport_profile;
            wtq_msquic_listener_stop(l);
        }
        free(buf);
    }
    abi_env_destroy(&env);
    return profile;
}

/*
 * The listener's WebTransport-profile tail is honoured EXACTLY as struct_size
 * dictates: a wholly-present field is read, a straddled or absent one gates to
 * current (0), an oversized-future struct is clamped, and an out-of-range value
 * is refused. This mirrors the client connect-config profile ABI on the server.
 */
static int test_abi_listener_profile(void)
{
    int failures = 0;
    const size_t full = sizeof(wtq_msquic_listener_cfg_t);
    const size_t poff =
        offsetof(wtq_msquic_listener_cfg_t, webtransport_profile);
    const size_t plen =
        sizeof(((wtq_msquic_listener_cfg_t *)0)->webtransport_profile);
    /* Little-endian encodings of the two valid profile values + an invalid. */
    static const unsigned char COMPAT[] = { 0x01, 0x00, 0x00, 0x00 };
    static const unsigned char CURRENT[] = { 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char BAD[] = { 0x63, 0x00, 0x00, 0x00 }; /* 99 */
    wtq_result_t rc;

    /* exact: the whole field present with the compat value → compat latched. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)full, COMPAT, plen, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);

    /* exact + explicit current value → current. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)full, CURRENT, plen, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);

    /* tail absent (struct_size ends exactly at the profile field): the whole
     * v2 tail is present, the profile is not → defaults to current. This is
     * also the shape of any old caller predating the profile field. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)poff, NULL, 0, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);

    /* old v1 layout (predates even the admission tail) → current. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start(
            (uint32_t)sizeof(wtq_msquic_listener_cfg_v1_t), NULL, 0, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);

    /* prefix-minus-one: struct_size straddles the profile field. A non-zero
     * partial (compat low byte) must NOT be honoured — the field is dropped
     * whole → current. The buffer is exactly struct_size, so a read past it
     * trips ASan. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)(poff + plen - 1), COMPAT,
                                   plen - 1, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);

    /* oversized future config: the compat field at its real offset is read and
     * the unknown trailing bytes ignored (clamped to sizeof). */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)(full + 32), COMPAT, plen, &rc),
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT);

    /* out-of-range value (99) with the whole field present → refused. */
    WTQ_TEST_CHECK_EQ_INT(
        abi_listener_profile_start((uint32_t)full, BAD, plen, &rc), -1);
    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_ERR_INVALID_ARG);

    /* the cfg_init default (through the size-forwarding macro) is current. */
    {
        wtq_msquic_listener_cfg_t cfg;
        wtq_msquic_listener_cfg_init(&cfg);
        WTQ_TEST_CHECK_EQ_INT((int)cfg.webtransport_profile,
                              (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);
        WTQ_TEST_CHECK_EQ_INT((int)cfg.struct_size, (int)full);
    }

    return failures;
}

/* env cfg whose struct_size lands INSIDE the nested tuning: the partial tuning
 * must be treated as absent (full defaults), not left partially active. Uses a
 * borrowed api/registration so env_open touches no real MsQuic. Heap-backed. */
static int test_abi_env_partial_tuning(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    api_init(&api);

    /* struct_size covers only tuning.struct_size (its leading uint32_t). */
    const size_t sz = offsetof(wtq_msquic_env_cfg_t, tuning) + sizeof(uint32_t);
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        memset(buf, 0, sz);
        wtq_msquic_env_cfg_t *c = (wtq_msquic_env_cfg_t *)buf;
        c->struct_size = (uint32_t)sz;
        c->existing_api = &api;
        c->existing_registration = (HQUIC)0x10;
        /* garbage makes the partially-present tuning.struct_size nonzero. */
        memset(buf + offsetof(wtq_msquic_env_cfg_t, tuning), 0xEE,
               sz - offsetof(wtq_msquic_env_cfg_t, tuning));
        wtq_msquic_env_t *env = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)wtq_msquic_env_open(c, &env), (int)WTQ_OK);
        WTQ_TEST_CHECK(env != NULL);
        if (env != NULL) {
            /* absent -> full defaults, NOT the partial garbage. */
            WTQ_TEST_CHECK(env->tuning.struct_size ==
                           (uint32_t)sizeof(wtq_msquic_tuning_t));
            WTQ_TEST_CHECK(env->tuning.idle_timeout_ms == 30000u);
            wtq_msquic_env_close(env);
        }
        free(buf);
    }
    return failures;
}

/* --- client-connect unwind: opened-but-never-published cleanup ---------- */
/*
 * Drive the whole wtq_msquic_client_connect over a fake API whose
 * ConnectionClose delivers a SYNCHRONOUS SHUTDOWN_COMPLETE — exactly the
 * re-entrancy that made the failure paths double-free (guard absent) or
 * deadlock (guard held). A counting allocator proves balance; holding the lane
 * guard across connect proves completion. Covers a session-create OOM, an
 * oversized WT-Protocol offer, and a synchronous ConnectionStart failure.
 */
struct cu_alloc {
    long live;
    long budget; /* <0 unlimited; else deny once it reaches 0 */
};
static void *cu_alloc_fn(size_t n, void *ctx)
{
    struct cu_alloc *c = ctx;
    if (c->budget == 0)
        return NULL;
    if (c->budget > 0)
        c->budget--;
    void *p = malloc(n ? n : 1);
    if (p != NULL)
        c->live++;
    return p;
}
static void *cu_realloc_fn(void *p, size_t os, size_t ns, void *ctx)
{
    struct cu_alloc *c = ctx;
    (void)os;
    if (c->budget == 0)
        return NULL;
    if (c->budget > 0)
        c->budget--;
    void *q = realloc(p, ns ? ns : 1);
    if (q != NULL && p == NULL)
        c->live++;
    return q;
}
static void cu_free_fn(void *p, size_t n, void *ctx)
{
    struct cu_alloc *c = ctx;
    (void)n;
    if (p == NULL)
        return;
    free(p);
    c->live--;
}

static QUIC_CONNECTION_CALLBACK_HANDLER g_cu_cb;
static void *g_cu_cb_ctx;
static HQUIC g_cu_conn;
static int g_cu_start_fail;
static int g_cu_shutdown_done; /* SHUTDOWN_COMPLETE already delivered once */

/*
 * Cross-thread mode: a worker created in ConnectionOpen (BEFORE the abandon
 * store) delivers the close-time SHUTDOWN_COMPLETE when ConnectionClose triggers
 * it through a RELAXED gate. The gate carries no synchronization, so the ONLY
 * happens-before for the callback's abandon load is the abandon atomic itself —
 * a regression to a plain bool is a data race TSan reports. Creating the worker
 * inside ConnectionClose, or using a release/acquire gate, would add ordering
 * that masks it. g_cu_cb/ctx/conn are set before the worker is created (the
 * pthread_create carries them), so only `abandon` rides the atomic.
 */
static int g_cu_threaded;
static int g_cu_delivered; /* worker actually delivered SHUTDOWN_COMPLETE */
static atomic_int g_cu_gate; /* 0 idle, 1 deliver, 2 done */
static pthread_t g_cu_worker;

static void *cu_worker_main(void *arg)
{
    (void)arg;
    while (atomic_load_explicit(&g_cu_gate, memory_order_relaxed) != 1)
        ; /* spin: the trigger provides no synchronization */
    if (g_cu_cb != NULL) {
        QUIC_CONNECTION_EVENT ev;
        memset(&ev, 0, sizeof(ev));
        ev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        ev.SHUTDOWN_COMPLETE.AppCloseInProgress = TRUE;
        g_cu_cb(g_cu_conn, g_cu_cb_ctx, &ev);
        g_cu_delivered = 1; /* read by the test after join (barrier) */
    }
    atomic_store_explicit(&g_cu_gate, 2, memory_order_relaxed);
    return NULL;
}

static QUIC_STATUS QUIC_API cu_cfg_open(HQUIC r, const QUIC_BUFFER *const a,
                                        uint32_t n, const QUIC_SETTINGS *s,
                                        uint32_t ss, void *c, HQUIC *out)
{
    (void)r;(void)a;(void)n;(void)s;(void)ss;(void)c;
    *out = (HQUIC)0x100;
    return QUIC_STATUS_SUCCESS;
}
static QUIC_STATUS QUIC_API cu_cfg_cred(HQUIC c, const QUIC_CREDENTIAL_CONFIG *cc)
{ (void)c;(void)cc; return QUIC_STATUS_SUCCESS; }
static void QUIC_API cu_cfg_close(HQUIC c) { (void)c; }
static QUIC_STATUS QUIC_API cu_conn_open(HQUIC r,
                                         QUIC_CONNECTION_CALLBACK_HANDLER h,
                                         void *ctx, HQUIC *out)
{
    (void)r;
    g_cu_cb = h;
    g_cu_cb_ctx = ctx;
    g_cu_conn = (HQUIC)0x200;
    *out = g_cu_conn;
    if (g_cu_threaded) {
        /* create the worker BEFORE the abandon store (later in connect); the
         * pthread_create carries g_cu_cb/ctx/conn, leaving only `abandon` to
         * the atomic. A create failure is fatal: connect failure is already the
         * expected outcome, so a silently-absent worker would falsely pass. */
        g_cu_delivered = 0;
        atomic_store_explicit(&g_cu_gate, 0, memory_order_relaxed);
        if (pthread_create(&g_cu_worker, NULL, cu_worker_main, NULL) != 0)
            abort();
    }
    return QUIC_STATUS_SUCCESS;
}
static QUIC_STATUS QUIC_API cu_conn_start(HQUIC c, HQUIC cfg,
                                          QUIC_ADDRESS_FAMILY f,
                                          const char *sn, uint16_t p)
{
    (void)c;(void)cfg;(void)f;(void)sn;(void)p;
    return g_cu_start_fail ? QUIC_STATUS_ABORTED : QUIC_STATUS_SUCCESS;
}
/* MsQuic delivers SHUTDOWN_COMPLETE synchronously when an opened connection is
 * closed — but only once. Model that: the re-entrant ConnectionClose inside
 * wtq_msq_conn_free must NOT re-deliver. */
static void QUIC_API cu_conn_close(HQUIC conn)
{
    if (g_cu_cb == NULL || g_cu_shutdown_done)
        return;
    g_cu_shutdown_done = 1;
    if (g_cu_threaded) {
        /* trigger the pre-created worker (relaxed) and join it, modelling the
         * worker-thread delivery real MsQuic does. A join failure is fatal: the
         * driver is freed right after this returns, so an un-reaped worker could
         * still reference it. */
        atomic_store_explicit(&g_cu_gate, 1, memory_order_relaxed);
        if (pthread_join(g_cu_worker, NULL) != 0)
            abort();
        return;
    }
    QUIC_CONNECTION_EVENT ev;
    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
    ev.SHUTDOWN_COMPLETE.AppCloseInProgress = TRUE;
    g_cu_cb(conn, g_cu_cb_ctx, &ev);
}
static void cu_api_init(QUIC_API_TABLE *api)
{
    api_init(api); /* stream/handler noops */
    api->ConfigurationOpen = cu_cfg_open;
    api->ConfigurationLoadCredential = cu_cfg_cred;
    api->ConfigurationClose = cu_cfg_close;
    api->ConnectionOpen = cu_conn_open;
    api->ConnectionStart = cu_conn_start;
    api->ConnectionClose = cu_conn_close;
}

/* One connect attempt. Fills *out_ok when it succeeded (OOM sweep). With
 * hold_guard the guard is held across connect (proves no close-time deadlock);
 * without it the same path proves allocator balance (no double-free). */
static int cu_run(long budget, int oversized, int start_fail, int hold_guard,
                  int *out_ok)
{
    int failures = 0;
    if (out_ok != NULL)
        *out_ok = 0;
    g_cu_cb = NULL;
    g_cu_cb_ctx = NULL;
    g_cu_conn = NULL;
    g_cu_start_fail = start_fail;
    g_cu_shutdown_done = 0;

    struct cu_alloc ac = { .live = 0, .budget = budget };
    wtq_alloc_t alloc = { &ac, cu_alloc_fn, cu_realloc_fn, cu_free_fn };
    QUIC_API_TABLE api;
    cu_api_init(&api);
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    ecfg.alloc = &alloc;
    ecfg.existing_api = &api;
    ecfg.existing_registration = (HQUIC)0x1;
    wtq_msquic_env_t *env = NULL;
    if (wtq_msquic_env_open(&ecfg, &env) != WTQ_OK) {
        /* env_open itself hit the budget: balanced, nothing published */
        WTQ_TEST_CHECK_EQ_INT((int)ac.live, 0);
        return failures;
    }

    struct lane L;
    lane_init(&L);
    char big[600];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    const char *good[] = { "wtq-test" };
    const char *over[] = { big };
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost";
    connect.path = "/x";
    connect.subprotocols = oversized ? over : good;
    connect.subprotocol_count = 1;
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = 443;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.guard = lane_guard(&L);

    wtq_session_t *s = NULL;
    if (hold_guard)
        guard_enter(&L); /* held ACROSS connect + any synchronous cleanup */
    wtq_result_t rc = wtq_msquic_client_connect(env, &cfg, &s);
    if (hold_guard)
        guard_leave(&L);

    if (rc == WTQ_OK) {
        if (out_ok != NULL)
            *out_ok = 1;
        WTQ_TEST_CHECK(s != NULL);
        /* tear the (fake) started connection down cleanly: the terminal event
         * runs the published cleanup, then drop the caller ref. Mark the
         * shutdown delivered so the re-entrant ConnectionClose does not repeat
         * it. */
        g_cu_shutdown_done = 1;
        QUIC_CONNECTION_EVENT sc;
        memset(&sc, 0, sizeof(sc));
        sc.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        if (g_cu_cb != NULL)
            g_cu_cb(g_cu_conn, g_cu_cb_ctx, &sc);
        wtq_session_release(s);
    } else {
        WTQ_TEST_CHECK(s == NULL);
    }

    wtq_msquic_env_close(env);
    WTQ_TEST_CHECK_EQ_INT((int)ac.live, 0); /* no leak, no double-free */
    lane_destroy(&L);
    return failures;
}

/* Oversized WT-Protocol offer: rejected in session_connect, before the start,
 * so the opened connection is discarded via the abandon path. Guard held proves
 * no deadlock; guard absent proves no double-free. */
static int test_client_unwind_oversized(void)
{
    int failures = 0;
    int ok = 0;
    failures += cu_run(-1, /*oversized=*/1, /*start_fail=*/0, /*hold=*/1, &ok);
    WTQ_TEST_CHECK(!ok);
    failures += cu_run(-1, /*oversized=*/1, /*start_fail=*/0, /*hold=*/0, &ok);
    WTQ_TEST_CHECK(!ok);
    return failures;
}

/* Synchronous ConnectionStart failure: the session was published then detached
 * before the abandon cleanup. */
static int test_client_unwind_start_fail(void)
{
    int failures = 0;
    int ok = 0;
    failures += cu_run(-1, /*oversized=*/0, /*start_fail=*/1, /*hold=*/1, &ok);
    WTQ_TEST_CHECK(!ok);
    failures += cu_run(-1, /*oversized=*/0, /*start_fail=*/1, /*hold=*/0, &ok);
    WTQ_TEST_CHECK(!ok);
    return failures;
}

/* Session-create (and every earlier) OOM: sweep the allocation budget; each
 * failure is balanced, and the first success tears down clean. Run guard-held
 * and guard-absent. */
static int test_client_unwind_oom(void)
{
    int failures = 0;
    for (int hold = 0; hold <= 1; hold++) {
        int saw_ok = 0;
        for (long b = 0; b < 80 && !saw_ok; b++) {
            int ok = 0;
            failures += cu_run(b, /*oversized=*/0, /*start_fail=*/0, hold, &ok);
            if (ok)
                saw_ok = 1;
        }
        WTQ_TEST_CHECK(saw_ok); /* the sweep reached a clean success */
    }
    return failures;
}

/* Cross-thread abandon visibility: the terminal callback runs on a worker
 * thread, gated so ONLY the abandon atomic carries the flag. Guard held (no
 * deadlock) and balanced; under TSan, a plain-bool regression is a reported
 * data race on `abandon`. */
static int test_client_unwind_cross_thread(void)
{
    int failures = 0;
    int ok = 0;
    g_cu_delivered = 0;
    g_cu_threaded = 1;
    failures += cu_run(-1, /*oversized=*/1, /*start_fail=*/0, /*hold=*/1, &ok);
    g_cu_threaded = 0;
    WTQ_TEST_CHECK(!ok);
    /* the worker must have actually delivered the callback on its thread —
     * otherwise the atomic property under test was never exercised (safe to
     * read: the join in ConnectionClose is a barrier) */
    WTQ_TEST_CHECK(g_cu_delivered == 1);
    return failures;
}

int main(void)
{
    int failures = 0;
    failures += test_guard_brackets_callbacks();
    failures += test_leave_after_driver_free();
    failures += test_guarded_out_of_callback_op();
    failures += test_quiescence_hook();
    failures += test_client_publication_race();
    failures += test_client_cfg_init_v1_abi();
    failures += test_listener_cfg_init_v1_abi();
    failures += test_abi_connect_prefix_minus_one();
    failures += test_abi_connect_exact_v1();
    failures += test_abi_connect_partial_tail();
    failures += test_abi_connect_oversized();
    failures += test_abi_listener_prefix_minus_one();
    failures += test_abi_listener_exact_v1();
    failures += test_abi_listener_partial_pair();
    failures += test_abi_listener_partial_quiesce();
    failures += test_abi_listener_oversized();
    failures += test_abi_listener_profile();
    failures += test_abi_env_partial_tuning();
    failures += test_client_unwind_oversized();
    failures += test_client_unwind_start_fail();
    failures += test_client_unwind_oom();
    failures += test_client_unwind_cross_thread();
    WTQ_TEST_PASS("msquic_managed");
    return failures;
}
