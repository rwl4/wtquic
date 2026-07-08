/*
 * Managed-lifecycle contract tests (slice 6, §7.2): the public
 * wtq_nw_conn_t handle over the internal transport root.
 *
 *   - post: exactly-once, submission-ordered, deferred from the
 *     domain, accepted-set-runs/rejected-set-never under stop races,
 *     acceptance retains the handle;
 *   - stop_begin: nonblocking, idempotent, legal from any thread
 *     including callbacks and posted jobs, synchronous rejection
 *     latch;
 *   - on_stopped: exactly once, the FINAL app-visible block, may
 *     release the last public reference;
 *   - join: off-domain blocks until completion; on-domain is STATE;
 *   - ownership split: the public handle dies independently of the
 *     internal root; a straggler pin keeps the root (and only the
 *     root) alive until its return, then it frees exactly once;
 *   - release misuse: last release without stop runs the documented
 *     fail-safe implicit stop; over-release is refused;
 *   - OOM at handle/root/post-node creation rolls back exactly.
 *
 * White-box access (driver walks, pins) is deliberate: this binary IS
 * the backend's contract proof, not an example program.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>
#include <wtquic/wtquic_network.h>

#include "nw_internal.h"
#include "test_support.h"

#define WAIT_MS 20000

static char cert_path[512];
static char key_path[512];

static int certs_locate(void)
{
    const char *dir = getenv("WTQ_TEST_CERT_DIR");

    if (dir == NULL)
        return -1;
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    return 0;
}

/* --- observation ------------------------------------------------------------ */

struct obs {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int established;
    int failed;
    int closed;
    int stopped;          /* on_stopped deliveries */
    int stopped_after_all_posts; /* every accepted post had run first */
    int closed_after_stopped; /* an app event AFTER the final block */
    _Atomic int posts_run;
    _Atomic int posts_accepted;
    int last_seq;         /* per-submitter FIFO proof */
    int order_bad;
    int terr_set;              /* on_failed captured the record */
    wtq_transport_error_t terr;
    wtq_nw_conn_t *conn;  /* for callback-context stop tests */
    int stop_in_established; /* run stop_begin inside the callback */
};

static void obs_init(struct obs *o)
{
    memset(o, 0, sizeof(*o));
    pthread_mutex_init(&o->mu, NULL);
    pthread_cond_init(&o->cv, NULL);
}

static void obs_destroy(struct obs *o)
{
    pthread_mutex_destroy(&o->mu);
    pthread_cond_destroy(&o->cv);
}

static bool obs_wait(struct obs *o, const int *flag)
{
    struct timespec dl;

    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&o->mu);
    while (*flag == 0)
        if (pthread_cond_timedwait(&o->cv, &o->mu, &dl) == ETIMEDOUT)
            break;
    bool ok = *flag != 0;
    pthread_mutex_unlock(&o->mu);
    return ok;
}

static void ev_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    struct obs *o = user;
    bool stop = false;

    (void)s;
    (void)sub;
    pthread_mutex_lock(&o->mu);
    o->established++;
    stop = o->stop_in_established != 0;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
    if (stop) {
        /* stop_begin from INSIDE a transport callback: legal,
         * nonblocking, no deadlock */
        (void)wtq_nw_conn_stop_begin(o->conn);
    }
}

static void ev_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    struct obs *o = user;
    wtq_transport_error_t rec;

    (void)why;
    memset(&rec, 0, sizeof(rec));
    rec.struct_size = (uint32_t)sizeof(rec);
    pthread_mutex_lock(&o->mu);
    o->failed++;
    if (s != NULL && !o->terr_set &&
        wtq_session_transport_error(s, &rec) == WTQ_OK) {
        o->terr = rec;
        o->terr_set = 1;
    }
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}

static void ev_closed(wtq_session_t *s, uint32_t code, const uint8_t *r,
                      size_t rlen, bool clean, void *user)
{
    struct obs *o = user;

    (void)s;
    (void)code;
    (void)r;
    (void)rlen;
    (void)clean;
    pthread_mutex_lock(&o->mu);
    o->closed++;
    if (o->stopped != 0)
        o->closed_after_stopped++; /* on_stopped must be FINAL */
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}

static void on_stopped_cb(void *ctx)
{
    struct obs *o = ctx;

    pthread_mutex_lock(&o->mu);
    o->stopped++;
    if (atomic_load(&o->posts_run) == atomic_load(&o->posts_accepted))
        o->stopped_after_all_posts++;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}

static void events_for(wtq_session_events_t *ev, struct obs *o)
{
    (void)o;
    wtq_session_events_init(ev);
    ev->on_established = ev_established;
    ev->on_failed = ev_failed;
    ev->on_closed = ev_closed;
}

/* --- server ------------------------------------------------------------------ */

static wtq_msquic_env_t *g_env;
static wtq_msquic_listener_t *g_listener;
static uint16_t g_port;
static struct obs g_sv;

static wtq_result_t server_up(void)
{
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_result_t rc = wtq_msquic_env_open(&ecfg, &g_env);

    if (rc != WTQ_OK)
        return rc;
    obs_init(&g_sv);
    static const char *protos[1] = { "wtq-nw-test" };
    wtq_session_events_t ev;
    events_for(&ev, &g_sv);
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    serve.path = "/nw";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = &g_sv;
    rc = wtq_msquic_listener_start(g_env, &cfg, &g_listener);
    if (rc != WTQ_OK)
        return rc;
    g_port = wtq_msquic_listener_port(g_listener);
    return WTQ_OK;
}

/* --- client construction ------------------------------------------------------ */

static wtq_result_t client_up_verify(struct obs *o,
                                     const wtq_alloc_t *alloc,
                                     bool insecure, wtq_nw_conn_t **out)
{
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;

    events_for(&ev, o);
    connect.authority = "localhost";
    connect.path = "/nw";
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = insecure;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = o;
    cfg.alloc = alloc;
    cfg.on_stopped = on_stopped_cb;
    cfg.stopped_ctx = o;
    return wtq_nw_conn_create(&cfg, out);
}

static wtq_result_t client_up(struct obs *o, const wtq_alloc_t *alloc,
                              wtq_nw_conn_t **out)
{
    return client_up_verify(o, alloc, true /* self-signed loopback */,
                            out);
}

/* bounded wait for internal quiescence (the root frees only when the
 * last pin returns; join deliberately does not wait for that) */
static bool wait_root_gone(int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        if (atomic_load(&wtq_nw_test_live_drivers) == 0)
            return true;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return atomic_load(&wtq_nw_test_live_drivers) == 0;
}

/* --- 1: cross-thread retain/release ----------------------------------------- */

static void *t1_worker(void *arg)
{
    wtq_nw_conn_t *c = arg;

    for (int i = 0; i < 2000; i++) {
        wtq_nw_conn_retain(c);
        wtq_nw_conn_release(c);
    }
    return NULL;
}

static int t_retain_release(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    pthread_t th[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&th[i], NULL, t1_worker, c);
    for (int i = 0; i < 4; i++)
        pthread_join(th[i], NULL);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    pthread_mutex_unlock(&o.mu);
    wtq_nw_conn_release(c);
    /* over-release after the last drop: refused, never fatal —
     * exercised on a still-live handle in t_stop_shapes below */
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* --- 2+3: order, exactly-once, deferral -------------------------------------- */

struct seq_job {
    struct obs *o;
    int seq;
    _Atomic int *ran;
};

static void seq_fn(void *ctx)
{
    struct seq_job *j = ctx;

    atomic_fetch_add(&j->o->posts_run, 1);
    atomic_fetch_add(j->ran, 1);
    pthread_mutex_lock(&j->o->mu);
    if (j->seq != j->o->last_seq + 1)
        j->o->order_bad++;
    j->o->last_seq = j->seq;
    pthread_mutex_unlock(&j->o->mu);
}

static struct {
    wtq_nw_conn_t *c;
    struct obs *o;
    _Atomic int inner_ran;
    int deferred_ok; /* inner had NOT run when the outer checked */
    int on_domain_ok;
    int session_ok;
    int join_state_ok;
    int inner_post_ok;
} g_t3;

static void t3_inner(void *ctx)
{
    (void)ctx;
    atomic_store(&g_t3.inner_ran, 1);
}

static int g_t3_done;

static void t3_outer(void *ctx)
{
    struct obs *o = ctx;

    atomic_fetch_add(&o->posts_run, 1);
    g_t3.on_domain_ok = wtq_nw_conn_is_on_domain(g_t3.c) ? 1 : 0;
    g_t3.session_ok = wtq_nw_conn_session(g_t3.c) != NULL ? 1 : 0;
    /* on-domain join must refuse, not deadlock */
    g_t3.join_state_ok =
        wtq_nw_conn_join(g_t3.c) == WTQ_ERR_STATE ? 1 : 0;
    g_t3.inner_post_ok =
        wtq_nw_conn_post(g_t3.c, t3_inner, NULL) == WTQ_OK ? 1 : 0;
    /* deferred, never inline: the inner job cannot have run yet */
    g_t3.deferred_ok = atomic_load(&g_t3.inner_ran) == 0 ? 1 : 0;
    pthread_mutex_lock(&o->mu);
    g_t3_done = 1;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}

static int t_post_order_defer(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;

    /* single-submitter total order, exactly once each */
    enum { K = 64 };
    static struct seq_job jobs[K];
    _Atomic int ran = 0;
    for (int i = 0; i < K; i++) {
        jobs[i].o = &o;
        jobs[i].seq = i + 1;
        jobs[i].ran = &ran;
        WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, seq_fn, &jobs[i]),
                              (int)WTQ_OK);
        atomic_fetch_add(&o.posts_accepted, 1);
    }

    /* deferral + on-domain queries from a posted job — completed
     * BEFORE the stop so its own inner post is judged pre-latch */
    memset(&g_t3, 0, sizeof(g_t3));
    g_t3_done = 0;
    g_t3.c = c;
    g_t3.o = &o;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, t3_outer, &o),
                          (int)WTQ_OK);
    atomic_fetch_add(&o.posts_accepted, 1);
    WTQ_TEST_CHECK(obs_wait(&o, &g_t3_done));
    /* the deferred inner job runs in the NEXT turn */
    for (int spin = 0; spin < WAIT_MS / 10; spin++) {
        if (atomic_load(&g_t3.inner_ran) != 0)
            break;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&ran), K); /* exactly once each */
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.order_bad, 0);       /* submission order */
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    WTQ_TEST_CHECK_EQ_INT(o.stopped_after_all_posts, 1);
    pthread_mutex_unlock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(g_t3.on_domain_ok, 1);
    WTQ_TEST_CHECK_EQ_INT(g_t3.session_ok, 1);
    WTQ_TEST_CHECK_EQ_INT(g_t3.join_state_ok, 1);
    WTQ_TEST_CHECK_EQ_INT(g_t3.inner_post_ok, 1);
    WTQ_TEST_CHECK_EQ_INT(g_t3.deferred_ok, 1);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&g_t3.inner_ran), 1);
    /* off-domain: no domain membership, no session access */
    WTQ_TEST_CHECK(!wtq_nw_conn_is_on_domain(c));
    WTQ_TEST_CHECK(wtq_nw_conn_session(c) == NULL);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* --- 4: the post-vs-stop race ------------------------------------------------- */

struct race_ctx {
    wtq_nw_conn_t *c;
    _Atomic int accepted;
    _Atomic int rejected;
    _Atomic int ran;
    _Atomic int go;
};

static void race_fn(void *ctx)
{
    struct race_ctx *r = ctx;

    atomic_fetch_add(&r->ran, 1);
}

static void *race_poster(void *arg)
{
    struct race_ctx *r = arg;

    while (atomic_load(&r->go) == 0)
        ;
    /* hammer until the latch is OBSERVED (bounded): both sides of the
     * race are guaranteed populated whatever the scheduler did */
    for (int i = 0; i < 400000 && atomic_load(&r->rejected) < 4; i++) {
        wtq_result_t rc = wtq_nw_conn_post(r->c, race_fn, r);
        if (rc == WTQ_OK)
            atomic_fetch_add(&r->accepted, 1);
        else if (rc == WTQ_ERR_CLOSED)
            atomic_fetch_add(&r->rejected, 1);
    }
    return NULL;
}

static int t_post_stop_race(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    static struct race_ctx r;
    memset(&r, 0, sizeof(r));
    r.c = c;
    pthread_t th[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&th[i], NULL, race_poster, &r);
    atomic_store(&r.go, 1);
    struct timespec ts = { 0, 2 * 1000 * 1000 };
    nanosleep(&ts, NULL); /* let the posters get going */
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK(!wtq_nw_conn_stop_begin(c)); /* idempotent */
    for (int i = 0; i < 4; i++)
        pthread_join(th[i], NULL);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    /* the accepted set ran exactly once each; the rejected set never */
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&r.ran), atomic_load(&r.accepted));
    WTQ_TEST_CHECK(atomic_load(&r.rejected) > 0);
    /* post-stop rejection is synchronous forever after */
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, race_fn, &r),
                          (int)WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&r.ran), atomic_load(&r.accepted));
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* --- 5+16: stop from callback / posted job; actor shape ---------------------- */

static struct {
    wtq_nw_conn_t *c;
    _Atomic int closed_rc;
} g_actor;

static void actor_close_job(void *ctx)
{
    (void)ctx;
    /* borrowed session, on-domain only */
    wtq_session_t *s = wtq_nw_conn_session(g_actor.c);
    if (s != NULL)
        atomic_store(&g_actor.closed_rc,
                     (int)wtq_session_close(s, 0, NULL, 0));
    /* on-domain stop_begin from a posted job: legal, nonblocking */
    (void)wtq_nw_conn_stop_begin(g_actor.c);
}

static int t_actor_shape(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    memset(&g_actor, 0, sizeof(g_actor));
    g_actor.c = c;
    /* posted close -> on-domain stop_begin -> on_stopped continuation
     * signal -> release. NO join anywhere. */
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, actor_close_job, NULL),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.stopped)); /* the continuation */
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    pthread_mutex_unlock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&g_actor.closed_rc), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* stop_begin from INSIDE a transport callback (on_established) */
static int t_stop_from_callback(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    o.stop_in_established = 1;
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    pthread_mutex_lock(&o.mu);
    o.conn = c;
    pthread_mutex_unlock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    pthread_mutex_unlock(&o.mu);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* --- 9: stop at every phase --------------------------------------------------- */

static int t_stop_shapes(void)
{
    int failures = 0;

    /* (a) immediately after create — before the group can be ready */
    for (int shape = 0; shape < 3; shape++) {
        struct obs o;
        wtq_nw_conn_t *c = NULL;

        obs_init(&o);
        WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
        if (c == NULL)
            return failures + 1;
        if (shape == 1) {
            /* established, then stop */
            WTQ_TEST_CHECK(obs_wait(&o, &o.established));
        } else if (shape == 2) {
            /* session terminal FIRST (posted close), then stop */
            WTQ_TEST_CHECK(obs_wait(&o, &o.established));
            memset(&g_actor, 0, sizeof(g_actor));
            g_actor.c = c;
            WTQ_TEST_CHECK_EQ_INT(
                (int)wtq_nw_conn_post(c, actor_close_job, NULL),
                (int)WTQ_OK);
            /* actor_close_job stops too — idempotence makes the
             * explicit stop below a no-op, which is the point */
            WTQ_TEST_CHECK(obs_wait(&o, &o.closed));
        }
        (void)wtq_nw_conn_stop_begin(c);
        /* over-release protection on a live handle: an extra release
         * beyond the held reference is refused */
        wtq_nw_conn_retain(c);
        wtq_nw_conn_release(c);
        wtq_nw_conn_release(c); /* drops the create reference */
        wtq_nw_conn_release(c); /* OVER-release: refused, harmless */
        WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
        pthread_mutex_lock(&o.mu);
        WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
        WTQ_TEST_CHECK_EQ_INT(o.closed_after_stopped, 0);
        pthread_mutex_unlock(&o.mu);
        obs_destroy(&o);
    }
    return failures;
}

/* --- 10: final release inside on_stopped -------------------------------------- */

static struct {
    wtq_nw_conn_t *c;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int done;
} g_t10;

static void t10_on_stopped(void *ctx)
{
    (void)ctx;
    /* the caller's LAST public reference dies inside on_stopped: the
     * backend holds its own reference through this return */
    wtq_nw_conn_release(g_t10.c);
    pthread_mutex_lock(&g_t10.mu);
    g_t10.done = 1;
    pthread_cond_broadcast(&g_t10.cv);
    pthread_mutex_unlock(&g_t10.mu);
}

static int t_release_in_stopped(void)
{
    int failures = 0;
    struct obs o;
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    memset(&g_t10, 0, sizeof(g_t10));
    pthread_mutex_init(&g_t10.mu, NULL);
    pthread_cond_init(&g_t10.cv, NULL);
    events_for(&ev, &o);
    connect.authority = "localhost";
    connect.path = "/nw";
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = &o;
    cfg.on_stopped = t10_on_stopped;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&cfg, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    g_t10.c = c;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&g_t10.mu);
    while (g_t10.done == 0)
        if (pthread_cond_timedwait(&g_t10.cv, &g_t10.mu, &dl) ==
            ETIMEDOUT)
            break;
    bool done = g_t10.done != 0;
    pthread_mutex_unlock(&g_t10.mu);
    WTQ_TEST_CHECK(done);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    pthread_mutex_destroy(&g_t10.mu);
    pthread_cond_destroy(&g_t10.cv);
    obs_destroy(&o);
    return failures;
}

/* --- 11: implicit fail-safe stop on last release ------------------------------- */

static int t_implicit_stop(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    /* the documented misuse: last release without stop — implicit
     * nonblocking stop; the transport never leaks */
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(obs_wait(&o, &o.stopped));
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    pthread_mutex_unlock(&o.mu);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    return failures;
}

/* --- 12: straggler holder keeps ONLY the internal root ------------------------- */

static int t_straggler_pin(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, NULL, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    struct wtq_driver *drv = wtq_nw_test_conn_driver(c);
    WTQ_TEST_CHECK(drv != NULL);
    dispatch_queue_t q = drv->queue;
    dispatch_retain(q); /* the test's own straggler reference */
    dispatch_sync(q, ^{ wtq_nw_test_pin(drv); });

    /* stop + join + release complete WITHOUT the straggler's return */
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
    pthread_mutex_unlock(&o.mu);
    wtq_nw_conn_release(c); /* the public handle dies safely */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    /* the internal root is STILL alive: the straggler pins it */
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&wtq_nw_test_live_drivers), 1);
    /* the straggler's disposal arrives (on-domain, like a holder's
     * marshaled retirement): the root frees exactly once */
    dispatch_sync(q, ^{ wtq_nw_test_unpin(drv); });
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    dispatch_release(q);
    obs_destroy(&o);
    return failures;
}

/* --- 14: OOM with exact rollback ----------------------------------------------- */

static struct {
    pthread_mutex_t mu;
    long live; /* outstanding allocations */
    int fail_at;
    int fail_n;
} g_fa = { PTHREAD_MUTEX_INITIALIZER, 0, -1, 0 };

static long g_fa_calls; /* every backend alloc attempt (under g_fa.mu) */

static void *fa_alloc(size_t size, void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_fa.mu);
    g_fa_calls++;
    bool fail = false;
    if (g_fa.fail_at > 0) {
        g_fa.fail_at--;
    } else if (g_fa.fail_at == 0 && g_fa.fail_n > 0) {
        g_fa.fail_n--;
        fail = true;
    }
    if (!fail)
        g_fa.live++;
    pthread_mutex_unlock(&g_fa.mu);
    return fail ? NULL : malloc(size);
}

static void *fa_realloc(void *p, size_t o, size_t n, void *ctx)
{
    (void)o;
    (void)ctx;
    return realloc(p, n);
}

static void fa_free(void *p, size_t size, void *ctx)
{
    (void)size;
    (void)ctx;
    if (p == NULL)
        return;
    pthread_mutex_lock(&g_fa.mu);
    g_fa.live--;
    pthread_mutex_unlock(&g_fa.mu);
    free(p);
}

static void fa_arm(int at, int n)
{
    pthread_mutex_lock(&g_fa.mu);
    g_fa.fail_at = at;
    g_fa.fail_n = n;
    pthread_mutex_unlock(&g_fa.mu);
}

static long fa_live(void)
{
    pthread_mutex_lock(&g_fa.mu);
    long v = g_fa.live;
    pthread_mutex_unlock(&g_fa.mu);
    return v;
}

static long fa_calls(void)
{
    pthread_mutex_lock(&g_fa.mu);
    long v = g_fa_calls;
    pthread_mutex_unlock(&g_fa.mu);
    return v;
}

static void noop_fn(void *ctx)
{
    (void)ctx;
}

static int t_oom_rollback(void)
{
    int failures = 0;
    wtq_alloc_t alloc = { NULL, fa_alloc, fa_realloc, fa_free };
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    /* caller-owned SESSION-object allocation fails: the backend-owned
     * handle and root roll back too */
    long base = fa_live();
    fa_arm(0, 1);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &alloc, &c),
                          (int)WTQ_ERR_NOMEM);
    WTQ_TEST_CHECK(c == NULL);
    WTQ_TEST_CHECK_EQ_INT((int)(fa_live() - base), 0);
    fa_arm(-1, 0);
    /* backend HANDLE allocation fails (seam): nothing acquired */
    wtq_nw_test_backend_alloc = &alloc;
    fa_arm(0, 1);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &alloc, &c),
                          (int)WTQ_ERR_NOMEM);
    WTQ_TEST_CHECK(c == NULL);
    WTQ_TEST_CHECK_EQ_INT((int)(fa_live() - base), 0);
    /* backend ROOT allocation fails: the handle rolls back too */
    fa_arm(1, 1);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &alloc, &c),
                          (int)WTQ_ERR_NOMEM);
    WTQ_TEST_CHECK(c == NULL);
    WTQ_TEST_CHECK_EQ_INT((int)(fa_live() - base), 0);
    fa_arm(-1, 0);
    wtq_nw_test_backend_alloc = NULL;

    /* post-node allocation (backend-owned) fails: NOMEM, no retain,
     * and the connection remains fully usable */
    wtq_nw_test_backend_alloc = &alloc;
    fa_arm(-1, 0);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &alloc, &c), (int)WTQ_OK);
    wtq_nw_test_backend_alloc = NULL;
    if (c == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    fa_arm(0, 1);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, noop_fn, NULL),
                          (int)WTQ_ERR_NOMEM);
    fa_arm(-1, 0);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, noop_fn, NULL),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    WTQ_TEST_CHECK_EQ_INT((int)(fa_live() - base), 0); /* balance */
    obs_destroy(&o);
    return failures;
}

/* --- allocator lifetime boundary ------------------------------------------------ */

/*
 * The caller's allocator may die once its PUBLICLY OBSERVABLE objects
 * are gone: after on_stopped ran (releasing any retained session/
 * stream handles there at the latest) and the caller's last public
 * reference dropped. Backend-internal objects that a transport-
 * retirement straggler can keep alive PAST that point (the driver
 * root, stream shells, batches) must therefore never touch the
 * caller's allocator. This test holds a straggler pin across
 * stop/join/final-release, marks the caller allocator INACTIVE, then
 * retires the straggler: any callback into the inactive allocator is
 * recorded and fails the test.
 */
static struct {
    pthread_mutex_t mu;
    long live;
    int active;
    int used_while_inactive;
} g_ba = { PTHREAD_MUTEX_INITIALIZER, 0, 0, 0 };

static void *ba_alloc(size_t size, void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_ba.mu);
    if (!g_ba.active)
        g_ba.used_while_inactive++;
    g_ba.live++;
    pthread_mutex_unlock(&g_ba.mu);
    return malloc(size);
}

static void *ba_realloc(void *p, size_t o, size_t n, void *ctx)
{
    (void)o;
    (void)ctx;
    return realloc(p, n);
}

static void ba_free(void *p, size_t size, void *ctx)
{
    (void)size;
    (void)ctx;
    if (p == NULL)
        return;
    pthread_mutex_lock(&g_ba.mu);
    if (!g_ba.active)
        g_ba.used_while_inactive++;
    g_ba.live--;
    pthread_mutex_unlock(&g_ba.mu);
    free(p);
}

static int t_alloc_boundary(void)
{
    int failures = 0;
    wtq_alloc_t alloc = { NULL, ba_alloc, ba_realloc, ba_free };
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    pthread_mutex_lock(&g_ba.mu);
    g_ba.active = 1;
    g_ba.used_while_inactive = 0;
    pthread_mutex_unlock(&g_ba.mu);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &alloc, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    struct wtq_driver *drv = wtq_nw_test_conn_driver(c);
    dispatch_queue_t q = drv->queue;
    dispatch_retain(q);
    dispatch_sync(q, ^{ wtq_nw_test_pin(drv); }); /* the straggler */

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c); /* the last public reference */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&wtq_nw_test_live_drivers), 1);

    /* every publicly observable object is gone: the caller allocator
     * may now die */
    pthread_mutex_lock(&g_ba.mu);
    g_ba.active = 0;
    pthread_mutex_unlock(&g_ba.mu);

    /* the straggler retires: only BACKEND-OWNED memory may move */
    dispatch_sync(q, ^{ wtq_nw_test_unpin(drv); });
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    dispatch_release(q);
    pthread_mutex_lock(&g_ba.mu);
    WTQ_TEST_CHECK_EQ_INT(g_ba.used_while_inactive, 0);
    pthread_mutex_unlock(&g_ba.mu);
    obs_destroy(&o);
    return failures;
}

/*
 * THE ACTOR RELEASE RACE: on_stopped resumes an actor IMMEDIATELY; the
 * actor may perform the final release and destroy its allocator
 * context while on_stopped is still returning. The handle free that
 * follows the callback's return must therefore never touch cfg.alloc.
 *   1. on_stopped signals the actor thread, then BLOCKS;
 *   2. the actor posts against the stopped connection while a public
 *      reference remains and the allocator is inactive — CLOSED, and
 *      the inactive allocator untouched;
 *   3. the actor performs the final release, then permits on_stopped
 *      to return;
 *   4. the handle free after the callback's return records NO call
 *      into the inactive allocator.
 */
static struct {
    wtq_nw_conn_t *c;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int actor_go;      /* on_stopped -> actor */
    int return_ok;     /* actor -> on_stopped may return */
    int done;
    int post_rc;
} g_ar;

static void ar_noop(void *ctx)
{
    (void)ctx;
}

static void ar_on_stopped(void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_ar.mu);
    g_ar.actor_go = 1;
    pthread_cond_broadcast(&g_ar.cv);
    while (g_ar.return_ok == 0)
        pthread_cond_wait(&g_ar.cv, &g_ar.mu);
    pthread_mutex_unlock(&g_ar.mu);
}

static void *ar_actor(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_ar.mu);
    while (g_ar.actor_go == 0)
        pthread_cond_wait(&g_ar.cv, &g_ar.mu);
    pthread_mutex_unlock(&g_ar.mu);

    /* the allocator context dies NOW, from the actor's perspective —
     * a public reference is still held for the post probe */
    pthread_mutex_lock(&g_ba.mu);
    g_ba.active = 0;
    pthread_mutex_unlock(&g_ba.mu);
    g_ar.post_rc = (int)wtq_nw_conn_post(g_ar.c, ar_noop, NULL);

    /* the final release, while on_stopped is still blocked */
    wtq_nw_conn_release(g_ar.c);

    pthread_mutex_lock(&g_ar.mu);
    g_ar.return_ok = 1;
    g_ar.done = 1;
    pthread_cond_broadcast(&g_ar.cv);
    pthread_mutex_unlock(&g_ar.mu);
    return NULL;
}

static int t_actor_release_race(void)
{
    int failures = 0;
    wtq_alloc_t alloc = { NULL, ba_alloc, ba_realloc, ba_free };
    struct obs o;
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    memset(&g_ar, 0, sizeof(g_ar));
    pthread_mutex_init(&g_ar.mu, NULL);
    pthread_cond_init(&g_ar.cv, NULL);
    pthread_mutex_lock(&g_ba.mu);
    g_ba.active = 1;
    g_ba.used_while_inactive = 0;
    pthread_mutex_unlock(&g_ba.mu);

    events_for(&ev, &o);
    connect.authority = "localhost";
    connect.path = "/nw";
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = &o;
    cfg.alloc = &alloc;
    cfg.on_stopped = ar_on_stopped;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&cfg, &c), (int)WTQ_OK);
    if (c == NULL)
        return failures + 1;
    g_ar.c = c;
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    pthread_t th;
    pthread_create(&th, NULL, ar_actor, NULL);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    pthread_join(th, NULL);
    WTQ_TEST_CHECK_EQ_INT(g_ar.post_rc, (int)WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    pthread_mutex_lock(&g_ba.mu);
    /* NOTHING after inactivity: not the rejected post, not the final
     * release, not the handle free after on_stopped returned */
    WTQ_TEST_CHECK_EQ_INT(g_ba.used_while_inactive, 0);
    pthread_mutex_unlock(&g_ba.mu);
    pthread_mutex_destroy(&g_ar.mu);
    pthread_cond_destroy(&g_ar.cv);
    obs_destroy(&o);
    return failures;
}

/* --- struct_size versioning ------------------------------------------------------ */

/*
 * The config is versioned by struct_size: the v1 prefix (through
 * `user`) is required; alloc / on_stopped / stopped_ctx are optional
 * tails read only when they fit. A PREFIX-SIZED config backed by
 * exactly prefix bytes must work (ASan proves no overread); an
 * undersized prefix is rejected; a larger future struct is accepted
 * with its unknown tail ignored.
 */
static int t_cfg_versioning(void)
{
    int failures = 0;
    struct obs o;
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;

    obs_init(&o);
    events_for(&ev, &o);
    connect.authority = "localhost";
    connect.path = "/nw";

    const size_t prefix = offsetof(wtq_nw_conn_cfg_t, user) +
                          sizeof(((wtq_nw_conn_cfg_t *)0)->user);

    /* prefix-backed: heap-allocate EXACTLY the v1 prefix */
    {
        wtq_nw_conn_cfg_t *cfg = malloc(prefix);
        memset(cfg, 0, prefix);
        cfg->struct_size = (uint32_t)prefix;
        cfg->server_name = "127.0.0.1";
        cfg->port = g_port;
        cfg->insecure_skip_verify = true;
        cfg->connect = &connect;
        cfg->events = &ev;
        cfg->user = &o;
        wtq_nw_conn_t *c = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(cfg, &c),
                              (int)WTQ_OK);
        free(cfg);
        WTQ_TEST_CHECK(c != NULL);
        if (c != NULL) {
            WTQ_TEST_CHECK(obs_wait(&o, &o.established));
            WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
            WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
            /* no on_stopped was configured (absent tail defaults) */
            pthread_mutex_lock(&o.mu);
            WTQ_TEST_CHECK_EQ_INT(o.stopped, 0);
            pthread_mutex_unlock(&o.mu);
            wtq_nw_conn_release(c);
            WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
        }
    }

    /* undersized prefix: rejected outright */
    {
        wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
        cfg.struct_size = (uint32_t)(prefix - 1);
        cfg.server_name = "127.0.0.1";
        cfg.port = g_port;
        cfg.connect = &connect;
        cfg.events = &ev;
        wtq_nw_conn_t *c = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&cfg, &c),
                              (int)WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK(c == NULL);
    }

    /* oversized future struct: accepted, unknown tail ignored */
    {
        struct {
            wtq_nw_conn_cfg_t v1;
            uint64_t future_tail[4];
        } big;
        memset(&big, 0, sizeof(big));
        big.v1 = (wtq_nw_conn_cfg_t)WTQ_NW_CONN_CFG_INIT;
        big.v1.struct_size = (uint32_t)sizeof(big);
        big.v1.server_name = "127.0.0.1";
        big.v1.port = g_port;
        big.v1.insecure_skip_verify = true;
        big.v1.connect = &connect;
        big.v1.events = &ev;
        big.v1.user = &o;
        big.v1.on_stopped = on_stopped_cb;
        big.v1.stopped_ctx = &o;
        wtq_nw_conn_t *c = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&big.v1, &c),
                              (int)WTQ_OK);
        if (c != NULL) {
            WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
            WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
            /* the optional tails were HONORED: on_stopped ran with
             * the configured stopped_ctx (it counted into `o`) */
            pthread_mutex_lock(&o.mu);
            WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);
            pthread_mutex_unlock(&o.mu);
            wtq_nw_conn_release(c);
            WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
        }
    }
    obs_destroy(&o);
    return failures;
}

/* --- main ---------------------------------------------------------------------- */

/* --- earliest callback vs handle publication ----------------------------------- */

/* The output handle is published BEFORE the connection group starts:
 * the earliest block that can possibly run on the domain (the test
 * seam is dispatched ahead of the group start) must find the OWNER'S
 * handle variable set and fully usable — post accepted, stop_begin
 * honoured — even though create has not returned yet. */
struct earliest_probe {
    struct obs *o;
    wtq_nw_conn_t **slot;    /* the owner's own out-variable */
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int ran;
    int published;
    int on_domain;
    int posted_ok;
    int stop_initiated;
    _Atomic int post_job_ran;
};

static void earliest_post_job(void *ctx)
{
    struct earliest_probe *pr = ctx;

    atomic_store(&pr->post_job_ran, 1);
}

static void earliest_hook(void *ctx)
{
    struct earliest_probe *pr = ctx;
    wtq_nw_conn_t *c = *pr->slot;

    pthread_mutex_lock(&pr->mu);
    pr->published = c != NULL;
    if (c != NULL) {
        pr->on_domain = wtq_nw_conn_is_on_domain(c);
        pr->posted_ok =
            wtq_nw_conn_post(c, earliest_post_job, pr) == WTQ_OK;
        pr->stop_initiated = wtq_nw_conn_stop_begin(c);
    }
    pr->ran = 1;
    pthread_cond_broadcast(&pr->cv);
    pthread_mutex_unlock(&pr->mu);
}


/* --- doorbell (preallocated coalescing wake) --------------------------------- */

struct bell {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int fires;
    int in_fire;          /* reentrancy depth (must never exceed 1)    */
    int reentered;
    int fired_after_stop; /* delivery after on_stopped (must stay 0)   */
    int ring_inside;      /* one-shot: the delivery rings once more    */
    struct obs *o;
    wtq_nw_conn_t *conn;
};

static void bell_init(struct bell *b, struct obs *o)
{
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->mu, NULL);
    pthread_cond_init(&b->cv, NULL);
    b->o = o;
}

static void bell_destroy(struct bell *b)
{
    pthread_mutex_destroy(&b->mu);
    pthread_cond_destroy(&b->cv);
}

static void bell_cb(void *ctx)
{
    struct bell *b = ctx;
    wtq_nw_conn_t *ring_target = NULL;

    pthread_mutex_lock(&b->mu);
    b->in_fire++;
    if (b->in_fire > 1)
        b->reentered++;
    b->fires++;
    if (b->ring_inside != 0) {
        b->ring_inside = 0;
        ring_target = b->conn;
    }
    pthread_mutex_unlock(&b->mu);

    if (b->o != NULL) {
        pthread_mutex_lock(&b->o->mu);
        int stopped = b->o->stopped;
        pthread_mutex_unlock(&b->o->mu);
        if (stopped != 0) {
            pthread_mutex_lock(&b->mu);
            b->fired_after_stop++;
            pthread_mutex_unlock(&b->mu);
        }
    }
    /* a ring from INSIDE the delivery: must re-arm exactly one more
     * deferred delivery, never recurse into this one */
    if (ring_target != NULL)
        wtq_nw_conn_doorbell_ring(ring_target);

    pthread_mutex_lock(&b->mu);
    b->in_fire--;
    pthread_cond_broadcast(&b->cv);
    pthread_mutex_unlock(&b->mu);
}

static bool bell_wait_fires(struct bell *b, int min)
{
    struct timespec dl;

    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&b->mu);
    while (b->fires < min)
        if (pthread_cond_timedwait(&b->cv, &b->mu, &dl) == ETIMEDOUT)
            break;
    bool ok = b->fires >= min;
    pthread_mutex_unlock(&b->mu);
    return ok;
}

static int bell_fires(struct bell *b)
{
    pthread_mutex_lock(&b->mu);
    int v = b->fires;
    pthread_mutex_unlock(&b->mu);
    return v;
}

static wtq_result_t client_up_bell(struct obs *o, struct bell *b,
                                   const wtq_alloc_t *alloc,
                                   wtq_nw_conn_t **out)
{
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;

    events_for(&ev, o);
    connect.authority = "localhost";
    connect.path = "/nw";
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = o;
    cfg.alloc = alloc;
    cfg.on_stopped = on_stopped_cb;
    cfg.stopped_ctx = o;
    cfg.on_doorbell = bell_cb;
    cfg.doorbell_ctx = b;
    return wtq_nw_conn_create(&cfg, out);
}

/* Hold the domain in a posted job until released (bounded). */
struct gate {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int in;
    int hold;
};

static void gate_job(void *ctx)
{
    struct gate *g = ctx;
    struct timespec dl;

    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&g->mu);
    g->in = 1;
    pthread_cond_broadcast(&g->cv);
    while (g->hold)
        if (pthread_cond_timedwait(&g->cv, &g->mu, &dl) == ETIMEDOUT)
            break;
    pthread_mutex_unlock(&g->mu);
}

static void gate_wait_in(struct gate *g)
{
    struct timespec dl;

    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&g->mu);
    while (g->in == 0)
        if (pthread_cond_timedwait(&g->cv, &g->mu, &dl) == ETIMEDOUT)
            break;
    pthread_mutex_unlock(&g->mu);
}

static void gate_open(struct gate *g)
{
    pthread_mutex_lock(&g->mu);
    g->hold = 0;
    pthread_cond_broadcast(&g->cv);
    pthread_mutex_unlock(&g->mu);
}

static void barrier_job(void *ctx)
{
    _Atomic int *flag = ctx;

    atomic_store(flag, 1);
}

static bool barrier_wait(_Atomic int *flag)
{
    for (int i = 0; i < WAIT_MS / 10; i++) {
        if (atomic_load(flag) != 0)
            return true;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return atomic_load(flag) != 0;
}

/* 1: rings while the domain is blocked coalesce into ONE delivery, and
 * the doorbell re-arms for the next ring (level-retained). */
/* Trust rejection fails FAST and observably: verification enabled
 * against the self-signed server must deliver exactly one
 * pre-establishment failure with a sealed LOCAL/NW_TLS record --
 * bounded, with NO caller timeout or caller stop creating the
 * terminal. The insecure control against the same server establishes. */
static int t_trust_reject(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up_verify(&o, NULL, false, &c),
                          (int)WTQ_OK);
    /* the verifier itself must converge the dial: bounded arrival */
    WTQ_TEST_CHECK(obs_wait(&o, &o.failed));
    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(o.failed, 1);       /* exactly one failure */
    WTQ_TEST_CHECK_EQ_INT(o.established, 0);  /* never establishes  */
    WTQ_TEST_CHECK(o.terr_set);
    WTQ_TEST_CHECK_EQ_INT((int)o.terr.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_INT((int)o.terr.native_domain,
                          (int)WTQ_ERRDOM_NW_TRUST);
    WTQ_TEST_CHECK(o.terr.native_code != 0);
    printf("TRUST_REJECT,native_code=%lld\n",
           (long long)o.terr.native_code);
    pthread_mutex_unlock(&o.mu);

    /* cleanup stop AFTER the terminal existed (not its cause) */
    (void)wtq_nw_conn_stop_begin(c);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);

    /* insecure control: the same server establishes */
    struct obs oc;
    wtq_nw_conn_t *cc = NULL;
    obs_init(&oc);
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&oc, NULL, &cc), (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&oc, &oc.established));
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(cc));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(cc), (int)WTQ_OK);
    wtq_nw_conn_release(cc);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&oc);

    if (failures == 0)
        printf("PASS: trust_reject\n");
    return failures;
}

static int t_doorbell_coalesce(void)
{
    int failures = 0;
    struct obs o;
    struct bell b;
    struct gate g = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER,
                      0, 1 };
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    bell_init(&b, &o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up_bell(&o, &b, NULL, &c),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));

    /* block the domain, ring repeatedly, release: exactly one fire */
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, gate_job, &g),
                          (int)WTQ_OK);
    gate_wait_in(&g);
    for (int i = 0; i < 5; i++)
        wtq_nw_conn_doorbell_ring(c);
    gate_open(&g);
    WTQ_TEST_CHECK(bell_wait_fires(&b, 1));
    /* barrier AFTER the fire: the queue drained past any pending
     * delivery, so the count is final for the burst */
    _Atomic int flag = 0;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, barrier_job, &flag),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(barrier_wait(&flag));
    WTQ_TEST_CHECK_EQ_INT(bell_fires(&b), 1);

    /* level-retained: a later ring delivers again */
    wtq_nw_conn_doorbell_ring(c);
    WTQ_TEST_CHECK(bell_wait_fires(&b, 2));

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    WTQ_TEST_CHECK_EQ_INT(b.reentered, 0);
    WTQ_TEST_CHECK_EQ_INT(b.fired_after_stop, 0);
    bell_destroy(&b);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: doorbell_coalesce\n");
    return failures;
}

/* 2: a ring from inside the delivery re-arms exactly one more,
 * deferred, never reentrant. */
static int t_doorbell_ring_inside(void)
{
    int failures = 0;
    struct obs o;
    struct bell b;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    bell_init(&b, &o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up_bell(&o, &b, NULL, &c),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    pthread_mutex_lock(&b.mu);
    b.conn = c;
    b.ring_inside = 1;
    pthread_mutex_unlock(&b.mu);
    wtq_nw_conn_doorbell_ring(c);
    WTQ_TEST_CHECK(bell_wait_fires(&b, 2));
    _Atomic int flag = 0;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, barrier_job, &flag),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(barrier_wait(&flag));
    WTQ_TEST_CHECK_EQ_INT(bell_fires(&b), 2);
    WTQ_TEST_CHECK_EQ_INT(b.reentered, 0);

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    bell_destroy(&b);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: doorbell_ring_inside\n");
    return failures;
}

/* 3: ring is allocation-free — with the backend allocator failing ALL
 * requests, the ring still delivers and wtquic attempts ZERO
 * allocations across the ring->delivery window. */
static int t_doorbell_no_alloc(void)
{
    int failures = 0;
    wtq_alloc_t alloc = { NULL, fa_alloc, fa_realloc, fa_free };
    struct obs o;
    struct bell b;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    bell_init(&b, &o);
    fa_arm(-1, 0);
    wtq_nw_test_backend_alloc = &alloc;
    WTQ_TEST_CHECK_EQ_INT((int)client_up_bell(&o, &b, NULL, &c),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));

    /* fail EVERY backend allocation, ring, and require delivery with
     * no allocation attempted */
    fa_arm(0, 1000000);
    long calls_before = fa_calls();
    wtq_nw_conn_doorbell_ring(c);
    WTQ_TEST_CHECK(bell_wait_fires(&b, 1));
    WTQ_TEST_CHECK_EQ_INT((int)(fa_calls() - calls_before), 0);
    /* the discriminator: the allocating post path DOES fail here */
    _Atomic int flag = 0;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, barrier_job, &flag),
                          (int)WTQ_ERR_NOMEM);
    fa_arm(-1, 0);

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    wtq_nw_test_backend_alloc = NULL;
    bell_destroy(&b);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: doorbell_no_alloc\n");
    return failures;
}

/* 4: rings racing stop_begin never deliver after on_stopped. */
static _Atomic int g_bell_hammer_stop;

static void *bell_hammer_main(void *arg)
{
    wtq_nw_conn_t *c = arg;

    while (!atomic_load(&g_bell_hammer_stop))
        wtq_nw_conn_doorbell_ring(c);
    return NULL;
}

static int t_doorbell_stop_race(void)
{
    int failures = 0;
    struct obs o;
    struct bell b;
    wtq_nw_conn_t *c = NULL;
    pthread_t th[2];

    obs_init(&o);
    bell_init(&b, &o);
    WTQ_TEST_CHECK_EQ_INT((int)client_up_bell(&o, &b, NULL, &c),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    atomic_store(&g_bell_hammer_stop, 0);
    WTQ_TEST_CHECK_EQ_INT(pthread_create(&th[0], NULL, bell_hammer_main, c),
                          0);
    WTQ_TEST_CHECK_EQ_INT(pthread_create(&th[1], NULL, bell_hammer_main, c),
                          0);
    struct timespec ts = { 0, 20 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    atomic_store(&g_bell_hammer_stop, 1);
    pthread_join(th[0], NULL);
    pthread_join(th[1], NULL);
    /* absorbed-by-teardown is legal; delivery after on_stopped is not */
    WTQ_TEST_CHECK_EQ_INT(b.fired_after_stop, 0);
    /* 5: rings on the retained post-join handle are harmless no-ops */
    int fires = bell_fires(&b);
    for (int i = 0; i < 3; i++)
        wtq_nw_conn_doorbell_ring(c);
    WTQ_TEST_CHECK_EQ_INT(bell_fires(&b), fires);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    bell_destroy(&b);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: doorbell_stop_race_and_after\n");
    return failures;
}

/* 6: the earliest published handle can ring the already-armed source. */
static wtq_nw_conn_t **g_bell_earliest_slot;

static void bell_earliest_hook(void *ctx)
{
    (void)ctx;
    if (g_bell_earliest_slot != NULL && *g_bell_earliest_slot != NULL)
        wtq_nw_conn_doorbell_ring(*g_bell_earliest_slot);
}

static int t_doorbell_earliest(void)
{
    int failures = 0;
    struct obs o;
    struct bell b;
    wtq_nw_conn_t *c = NULL;

    obs_init(&o);
    bell_init(&b, &o);
    g_bell_earliest_slot = &c;
    wtq_nw_test_on_earliest = bell_earliest_hook;
    wtq_nw_test_on_earliest_ctx = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)client_up_bell(&o, &b, NULL, &c),
                          (int)WTQ_OK);
    wtq_nw_test_on_earliest = NULL;
    wtq_nw_test_on_earliest_ctx = NULL;
    /* the earliest ring targets the configured, activated source (the
     * slot global stays set until the async hook has provably run) */
    WTQ_TEST_CHECK(bell_wait_fires(&b, 1));
    g_bell_earliest_slot = NULL;

    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    bell_destroy(&b);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: doorbell_earliest\n");
    return failures;
}

/* Truncation boundaries around the two new tail fields. */
static _Atomic int g_prefix_bell_fires;
static void *volatile g_prefix_bell_ctx = (void *)(intptr_t)-1;

static void prefix_bell_cb(void *ctx)
{
    g_prefix_bell_ctx = ctx;
    atomic_fetch_add(&g_prefix_bell_fires, 1);
}

static int t_doorbell_cfg_prefix(void)
{
    int failures = 0;
    struct obs o;
    wtq_nw_conn_t *c = NULL;
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;

    /* cut BEFORE on_doorbell: no doorbell; ring is a harmless no-op */
    obs_init(&o);
    events_for(&ev, &o);
    connect.authority = "localhost";
    connect.path = "/nw";
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = &o;
    cfg.on_stopped = on_stopped_cb;
    cfg.stopped_ctx = &o;
    cfg.on_doorbell = prefix_bell_cb;              /* poison past cut */
    cfg.doorbell_ctx = (void *)(intptr_t)0x5A5A;   /* poison past cut */
    cfg.struct_size =
        (uint32_t)offsetof(wtq_nw_conn_cfg_t, on_doorbell);
    atomic_store(&g_prefix_bell_fires, 0);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&cfg, &c), (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    wtq_nw_conn_doorbell_ring(c);
    _Atomic int flag = 0;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, barrier_job, &flag),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(barrier_wait(&flag));
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&g_prefix_bell_fires), 0);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);
    c = NULL;

    /* cut AFTER on_doorbell, BEFORE doorbell_ctx: callback honoured,
     * context defaults to NULL — the poisoned bytes are never read */
    obs_init(&o);
    events_for(&ev, &o);
    cfg = (wtq_nw_conn_cfg_t)WTQ_NW_CONN_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = &o;
    cfg.on_stopped = on_stopped_cb;
    cfg.stopped_ctx = &o;
    cfg.on_doorbell = prefix_bell_cb;
    cfg.doorbell_ctx = (void *)(intptr_t)0x5A5A;   /* poison past cut */
    cfg.struct_size =
        (uint32_t)(offsetof(wtq_nw_conn_cfg_t, on_doorbell) +
                   sizeof(cfg.on_doorbell));
    atomic_store(&g_prefix_bell_fires, 0);
    g_prefix_bell_ctx = (void *)(intptr_t)-1;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_create(&cfg, &c), (int)WTQ_OK);
    WTQ_TEST_CHECK(obs_wait(&o, &o.established));
    wtq_nw_conn_doorbell_ring(c);
    for (int i = 0; i < WAIT_MS / 10 && atomic_load(&g_prefix_bell_fires) == 0;
         i++) {
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    WTQ_TEST_CHECK(atomic_load(&g_prefix_bell_fires) >= 1);
    WTQ_TEST_CHECK(g_prefix_bell_ctx == NULL); /* NULL, not poison */
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c));
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));
    obs_destroy(&o);

    if (failures == 0)
        printf("PASS: doorbell_cfg_prefix\n");
    return failures;
}

static int t_earliest_callback_publication(void)
{
    int failures = 0;
    struct obs o;
    struct earliest_probe pr;
    wtq_nw_conn_t *conn = NULL;

    obs_init(&o);
    memset(&pr, 0, sizeof(pr));
    pthread_mutex_init(&pr.mu, NULL);
    pthread_cond_init(&pr.cv, NULL);
    pr.o = &o;
    pr.slot = &conn;

    wtq_nw_test_on_earliest_ctx = &pr;
    wtq_nw_test_on_earliest = earliest_hook;
    WTQ_TEST_CHECK_EQ_INT(client_up(&o, NULL, &conn), WTQ_OK);
    wtq_nw_test_on_earliest = NULL;
    wtq_nw_test_on_earliest_ctx = NULL;

    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&pr.mu);
    while (pr.ran == 0)
        if (pthread_cond_timedwait(&pr.cv, &pr.mu, &dl) == ETIMEDOUT)
            break;
    WTQ_TEST_CHECK(pr.ran);
    WTQ_TEST_CHECK(pr.published);
    WTQ_TEST_CHECK(pr.on_domain);
    WTQ_TEST_CHECK(pr.posted_ok);
    WTQ_TEST_CHECK(pr.stop_initiated);
    pthread_mutex_unlock(&pr.mu);

    /* the accepted post still runs exactly once, then the stop the
     * earliest callback began completes normally (hang-proof: if the
     * hook could not stop through the handle — the RED condition —
     * stop from here so join stays bounded) */
    if (!pr.stop_initiated)
        (void)wtq_nw_conn_stop_begin(conn);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_conn_join(conn), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&pr.post_job_ran), 1);
    WTQ_TEST_CHECK(obs_wait(&o, &o.stopped));
    wtq_nw_conn_release(conn);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));

    pthread_mutex_destroy(&pr.mu);
    pthread_cond_destroy(&pr.cv);
    obs_destroy(&o);
    if (failures == 0)
        printf("PASS: earliest_callback_publication\n");
    return failures;
}

int main(void)
{
    int failures = 0;

    if (certs_locate() != 0) {
        fprintf(stderr, "WTQ_TEST_CERT_DIR not set\n");
        return 1;
    }
    if (server_up() != WTQ_OK) {
        fprintf(stderr, "server failed to start\n");
        return 1;
    }

    failures += t_retain_release();
    failures += t_post_order_defer();
    failures += t_post_stop_race();
    failures += t_stop_from_callback();
    failures += t_actor_shape();
    failures += t_stop_shapes();
    failures += t_release_in_stopped();
    failures += t_implicit_stop();
    failures += t_straggler_pin();
    failures += t_alloc_boundary();
    failures += t_actor_release_race();
    failures += t_cfg_versioning();
    failures += t_oom_rollback();
    failures += t_earliest_callback_publication();
    failures += t_doorbell_coalesce();
    failures += t_doorbell_ring_inside();
    failures += t_doorbell_no_alloc();
    failures += t_doorbell_stop_race();
    failures += t_doorbell_earliest();
    failures += t_doorbell_cfg_prefix();
    failures += t_trust_reject();

    wtq_msquic_listener_stop(g_listener);
    wtq_msquic_env_close(g_env);
    obs_destroy(&g_sv);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_nw_lifecycle (%d)\n", failures);
        return failures;
    }
    WTQ_TEST_PASS("test_nw_lifecycle");
    return 0;
}
