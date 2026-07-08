/*
 * Accept-registration contract for the MsQuic backend, white-box (this
 * binary compiles the backend sources with WTQ_MSQ_TESTING so it can
 * reach wtq_msq_env_conn_accept, the environment internals, and the
 * accept-path fault seam):
 *
 *   1. close-before-publication — a closing environment refuses the
 *      accept and nothing is published;
 *   2. publication is atomic — a tracked driver always carries the
 *      session and a shutdown-capable handle the moment it is visible;
 *   3. configuration-failure unwind — a failed accept unlinks, frees,
 *      and balances the allocator, and env_close is not stranded;
 *   4. close/accept churn over real loopback connections — env_close
 *      racing live NEW_CONNECTION callbacks lands every accept on
 *      exactly one side of the closing latch (run under TSan in the
 *      sanitizer lanes; the pre-fix unlocked publication is the
 *      recorded RED for this file).
 *
 * One server environment per process, per convention.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

#include "msq_internal.h"
#include "test_support.h"

#define WAIT_SECS 30

/* --- cert fixture ------------------------------------------------------------ */

static char cert_path[512];
static char key_path[512];

static int certs_locate(const char *argv1)
{
    const char *dir = argv1;

    if (dir == NULL)
        dir = getenv("WTQ_TEST_CERT_DIR");
    if (dir == NULL) {
        fprintf(stderr,
                "no cert dir: set WTQ_TEST_CERT_DIR or pass it as the "
                "first argument (see scripts/gen_test_certs.sh)\n");
        return -1;
    }
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    FILE *f = fopen(cert_path, "r");
    if (f == NULL) {
        fprintf(stderr, "missing %s\n", cert_path);
        return -1;
    }
    fclose(f);
    return 0;
}

/* --- counting allocator ------------------------------------------------------- */

typedef struct counting_alloc {
    int allocs;
    int frees;
} counting_alloc_t;

static void *count_alloc(size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    __atomic_fetch_add(&ca->allocs, 1, __ATOMIC_RELAXED);
    return malloc(size);
}

static void count_free(void *ptr, size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    (void)size;
    __atomic_fetch_add(&ca->frees, 1, __ATOMIC_RELAXED);
    free(ptr);
}

/* --- session-event terminals --------------------------------------------------- */

struct peer {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int established;
    int closed;
    int failed;
    int refused;
};

static void peer_init(struct peer *p)
{
    memset(p, 0, sizeof(*p));
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
}

static void peer_destroy(struct peer *p)
{
    pthread_mutex_destroy(&p->mu);
    pthread_cond_destroy(&p->cv);
}

static void peer_bump(struct peer *p, int *field)
{
    pthread_mutex_lock(&p->mu);
    (*field)++;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    (void)s;
    (void)sub;
    peer_bump(user, &((struct peer *)user)->established);
}

static void cb_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t reason_len, bool clean,
                      void *user)
{
    (void)s;
    (void)code;
    (void)reason;
    (void)reason_len;
    (void)clean;
    peer_bump(user, &((struct peer *)user)->closed);
}

static void cb_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    (void)s;
    (void)why;
    peer_bump(user, &((struct peer *)user)->failed);
}

static void cb_refused(wtq_session_t *s, uint16_t status, void *user)
{
    (void)s;
    (void)status;
    peer_bump(user, &((struct peer *)user)->refused);
}

static void events_for(wtq_session_events_t *ev)
{
    wtq_session_events_init(ev);
    ev->on_established = cb_established;
    ev->on_closed = cb_closed;
    ev->on_failed = cb_failed;
    ev->on_refused = cb_refused;
}

static bool peer_wait_terminal(struct peer *p)
{
    struct timespec deadline;
    bool ok = true;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += WAIT_SECS;
    pthread_mutex_lock(&p->mu);
    while (p->closed + p->failed + p->refused == 0 && ok)
        ok = pthread_cond_timedwait(&p->cv, &p->mu, &deadline) == 0;
    ok = p->closed + p->failed + p->refused > 0;
    pthread_mutex_unlock(&p->mu);
    return ok;
}

/* --- loopback fixtures ---------------------------------------------------------- */

static wtq_result_t listener_up(wtq_msquic_env_t *env, struct peer *p,
                                wtq_msquic_listener_t **l_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    events_for(&ev);
    serve.path = "/accept";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = p;
    return wtq_msquic_listener_start(env, &cfg, l_out);
}

static wtq_result_t client_up(wtq_msquic_env_t *env, struct peer *p,
                              uint16_t port, wtq_session_t **s_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;

    events_for(&ev);
    connect.authority = "localhost";
    connect.path = "/accept";
    connect.subprotocols = protos;
    connect.subprotocol_count = 1;
    cfg.server_name = "127.0.0.1";
    cfg.port = port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = p;
    return wtq_msquic_client_connect(env, &cfg, s_out);
}

/* --- 1: close-before-publication ------------------------------------------------ */

/* A closing environment refuses the accept before ANY state is
 * published: the driver stays untracked, unfielded, and the list is
 * untouched. Dummy session/handle pointers are safe — accept stores
 * them without dereferencing, and on refusal must not even store. */
static int t_accept_refused_when_closing(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    int dummy_session, dummy_conn;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (env == NULL)
        return failures + 1;

    struct wtq_driver *drv =
        wtq_msq_conn_new(&env->alloc, env->api, false);
    WTQ_TEST_CHECK(drv != NULL);

    pthread_mutex_lock(&env->mu);
    env->closing = true;
    pthread_mutex_unlock(&env->mu);

    WTQ_TEST_CHECK(!wtq_msq_env_conn_accept(
        env, drv, (wtq_session_t *)&dummy_session, (HQUIC)&dummy_conn));

    pthread_mutex_lock(&env->mu);
    WTQ_TEST_CHECK(env->conns == NULL);
    WTQ_TEST_CHECK_EQ_INT((int)env->conn_count, 0);
    env->closing = false;
    pthread_mutex_unlock(&env->mu);
    WTQ_TEST_CHECK(drv->env == NULL);
    WTQ_TEST_CHECK(drv->conn == NULL);
    WTQ_TEST_CHECK(drv->session == NULL);

    wtq_msq_conn_free(drv);
    wtq_msquic_env_close(env);
    if (failures == 0)
        printf("PASS: accept_refused_when_closing\n");
    return failures;
}

/* --- 2: publication is atomic ----------------------------------------------------- */

/* The moment a driver is reachable from env->conns it carries BOTH the
 * session and the shutdown-capable handle — the close walk can never
 * meet a half-published driver. */
static int t_accept_publishes_atomically(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    int dummy_session, dummy_conn;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (env == NULL)
        return failures + 1;

    struct wtq_driver *drv =
        wtq_msq_conn_new(&env->alloc, env->api, false);
    WTQ_TEST_CHECK(drv != NULL);

    WTQ_TEST_CHECK(wtq_msq_env_conn_accept(
        env, drv, (wtq_session_t *)&dummy_session, (HQUIC)&dummy_conn));

    pthread_mutex_lock(&env->mu);
    for (struct wtq_driver *d = env->conns; d != NULL; d = d->env_next) {
        WTQ_TEST_CHECK(d->conn != NULL);
        WTQ_TEST_CHECK(d->session != NULL);
    }
    WTQ_TEST_CHECK(env->conns == drv);
    WTQ_TEST_CHECK_EQ_INT((int)env->conn_count, 1);
    pthread_mutex_unlock(&env->mu);

    /* unwind by hand (the dummy handle must never reach env_close's
     * ConnectionShutdown walk) */
    wtq_msq_env_conn_unregister(drv);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    wtq_msquic_env_close(env);
    if (failures == 0)
        printf("PASS: accept_publishes_atomically\n");
    return failures;
}

/* --- 3: configuration-failure unwind ------------------------------------------------ */

/* The seam fails the accept-path ConnectionSetConfiguration on a REAL
 * inbound connection: the unwind must unlink the driver (env_close is
 * not stranded waiting on it), free everything (allocator balances),
 * and the client sees a terminal, never an establishment. */
static int t_config_failure_unwind(void)
{
    int failures = 0;
    counting_alloc_t ca = { 0, 0 };
    wtq_alloc_t alloc = { &ca, count_alloc, NULL, count_free };
    struct peer sp, cp;

    peer_init(&sp);
    peer_init(&cp);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    ecfg.alloc = &alloc;
    wtq_msquic_env_t *senv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);

    wtq_msquic_env_cfg_t ccfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ccfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL)
        return failures + 1;

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);

    atomic_store(&wtq_msq_test_fail_set_configuration, 1);

    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);

    /* the rejected accept surfaces client-side as a terminal */
    WTQ_TEST_CHECK(peer_wait_terminal(&cp));
    WTQ_TEST_CHECK_EQ_INT(cp.established, 0);
    WTQ_TEST_CHECK_EQ_INT(sp.established, 0);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&wtq_msq_test_fail_set_configuration),
                          0);

    /* not stranded: the unwound driver left no tracked state behind */
    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    pthread_mutex_lock(&sp.mu);
    /* the server session never surfaced to the app at all */
    WTQ_TEST_CHECK_EQ_INT(sp.closed + sp.failed + sp.refused, 0);
    pthread_mutex_unlock(&sp.mu);

    wtq_msquic_env_close(cenv);
    if (cs != NULL)
        wtq_session_release(cs); /* legal only after env close */
    WTQ_TEST_CHECK_EQ_INT(ca.allocs, ca.frees);

    peer_destroy(&sp);
    peer_destroy(&cp);
    if (failures == 0)
        printf("PASS: config_failure_unwind\n");
    return failures;
}

/* --- 4: close/accept churn ------------------------------------------------------------ */

/* env_close races live NEW_CONNECTION accepts: every accept lands on
 * exactly one side of the closing latch — refused cleanly before
 * publication, or published-and-shut-down after it. Staggered delays
 * sweep the phase; TSan (sanitizer lane) checks the lock discipline;
 * the bounded waits prove nobody is stranded either way. */
#define CHURN_ROUNDS 12
#define CHURN_CLIENTS 3

static int t_close_accept_churn(void)
{
    int failures = 0;

    for (int round = 0; round < CHURN_ROUNDS && failures == 0; round++) {
        struct peer sp, cp[CHURN_CLIENTS];
        wtq_msquic_env_cfg_t secfg = WTQ_MSQUIC_ENV_CFG_INIT;
        wtq_msquic_env_cfg_t cecfg = WTQ_MSQUIC_ENV_CFG_INIT;
        wtq_msquic_env_t *senv = NULL, *cenv = NULL;
        wtq_msquic_listener_t *l = NULL;
        wtq_session_t *cs[CHURN_CLIENTS] = { 0 };

        peer_init(&sp);
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&secfg, &senv), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cecfg, &cenv), WTQ_OK);
        if (senv == NULL || cenv == NULL)
            return failures + 1;
        WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);
        uint16_t port = wtq_msquic_listener_port(l);

        for (int i = 0; i < CHURN_CLIENTS; i++) {
            peer_init(&cp[i]);
            WTQ_TEST_CHECK_EQ_INT(client_up(cenv, &cp[i], port, &cs[i]),
                                  WTQ_OK);
        }

        /* sweep the close across the handshake window */
        usleep((useconds_t)(round * 700));
        wtq_msquic_listener_stop(l);
        wtq_msquic_env_close(senv); /* races in-flight accepts */

        /* every client terminates (refused pre-publication, shut down
         * post-publication, or plain connect failure) — bounded */
        for (int i = 0; i < CHURN_CLIENTS; i++)
            WTQ_TEST_CHECK(peer_wait_terminal(&cp[i]));

        wtq_msquic_env_close(cenv);
        for (int i = 0; i < CHURN_CLIENTS; i++)
            if (cs[i] != NULL)
                wtq_session_release(cs[i]); /* after env close only */
        for (int i = 0; i < CHURN_CLIENTS; i++)
            peer_destroy(&cp[i]);
        peer_destroy(&sp);
    }
    if (failures == 0)
        printf("PASS: close_accept_churn\n");
    return failures;
}

/* --- main --------------------------------------------------------------------------- */

/* --- managed-domain loopback (admission, guard, quiescence) ------------- */

struct mserver {
    pthread_mutex_t lane;     /* guard.ctx: the serialization domain lock */
    int enters, leaves;
    int prepare_calls;
    int had_peer_addr;
    int refuse;               /* prepare returns accepted=false */
    int bad_guard;            /* prepare returns a mismatched guard */
    wtq_result_t prepare_rc;  /* prepare's return code (WTQ_OK normally) */
    int abandon_calls;
    int quiesce_calls;
    int s_established;
    int s_terminal;
};

static void mguard_enter(void *c)
{ struct mserver *S = c; pthread_mutex_lock(&S->lane); S->enters++; }
static void mguard_leave(void *c)
{ struct mserver *S = c; S->leaves++; pthread_mutex_unlock(&S->lane); }

static wtq_result_t m_prepare(void *luser, const wtq_msquic_accept_info_t *info,
                              wtq_msquic_accept_decision_t *out)
{
    struct mserver *S = luser;
    S->prepare_calls++;
    if (info->peer_address != NULL)
        S->had_peer_addr = 1;
    if (S->prepare_rc != WTQ_OK)
        return S->prepare_rc;
    if (S->refuse) {
        out->accepted = false;   /* refuse: nothing constructed */
        return WTQ_OK;
    }
    out->accepted = true;
    out->guard.enter = mguard_enter;
    out->guard.leave = S->bad_guard ? NULL : mguard_leave; /* mismatched */
    out->guard.ctx = S;
    out->user = S;               /* per-child user (one connection per test) */
    return WTQ_OK;
}
static void m_abandon(void *luser, void *user)
{ struct mserver *S = luser; (void)user; S->abandon_calls++; }
static void m_quiesced(wtq_session_t *s, void *user)
{ struct mserver *S = user; (void)s; S->quiesce_calls++; }

/* Session events for a managed server: user is the per-child (mserver). */
static void ms_established(wtq_session_t *s, wtq_str_t sub, void *user)
{ (void)s; (void)sub; ((struct mserver *)user)->s_established++; }
static void ms_terminal(wtq_session_t *s, uint32_t code, const uint8_t *r,
                        size_t rlen, bool clean, void *user)
{ (void)s; (void)code; (void)r; (void)rlen; (void)clean;
  ((struct mserver *)user)->s_terminal++; }

static void mserver_init(struct mserver *S)
{ memset(S, 0, sizeof(*S)); pthread_mutex_init(&S->lane, NULL); }
static void mserver_destroy(struct mserver *S)
{ pthread_mutex_destroy(&S->lane); }

static wtq_result_t managed_listener_up(wtq_msquic_env_t *env,
                                        struct mserver *S,
                                        wtq_msquic_listener_t **l_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    wtq_session_events_init(&ev);
    ev.on_established = ms_established;
    ev.on_closed = ms_terminal;
    serve.path = "/accept";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = S;
    cfg.accept_prepare = m_prepare;
    cfg.accept_abandon = m_abandon;
    cfg.on_transport_quiesced = m_quiesced;
    return wtq_msquic_listener_start(env, &cfg, l_out);
}

/* Admission accepted -> establish under the guard -> stop the listener ->
 * env_close -> quiescence fires exactly once (never abandon), the guard is
 * balanced. Proves admission/construction/quiescence and that the hook +
 * user outlive listener destruction. Runs the guarded barrier under TSan. */
static int t_managed_lifecycle(void)
{
    int failures = 0;
    struct mserver S;
    struct peer cp;
    mserver_init(&S);
    peer_init(&cp);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(managed_listener_up(senv, &S, &l), WTQ_OK);

    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);

    /* wait until the server session established (admission ran, guard used) */
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += WAIT_SECS;
    pthread_mutex_lock(&cp.mu);
    while (cp.established == 0 && cp.closed + cp.failed + cp.refused == 0)
        if (pthread_cond_timedwait(&cp.cv, &cp.mu, &dl) != 0) break;
    pthread_mutex_unlock(&cp.mu);

    /* Destroy the listener BEFORE the connection quiesces: the hook + its
     * user live on the driver, not the listener. env_close is the barrier
     * after which no callback touches S, so all S reads happen here (not
     * racing the worker under the establishment condvar). */
    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);             /* guarded barrier; TSan lane */

    WTQ_TEST_CHECK_EQ_INT(S.prepare_calls, 1);
    WTQ_TEST_CHECK(S.had_peer_addr);
    WTQ_TEST_CHECK(S.enters > 0);                /* guard bracketed callbacks */
    WTQ_TEST_CHECK_EQ_INT(S.enters, S.leaves);   /* balanced */
    WTQ_TEST_CHECK_EQ_INT(S.quiesce_calls, 1);   /* exactly once */
    WTQ_TEST_CHECK_EQ_INT(S.abandon_calls, 0);   /* success => not abandon */
    WTQ_TEST_CHECK(S.s_established > 0);

    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&cp);
    mserver_destroy(&S);
    if (failures == 0) printf("PASS: managed_lifecycle\n");
    return failures;
}

/* Admission refused (accepted=false): no child constructed, so no guard use,
 * no abandon, no quiescence; the client sees a terminal. */
static int t_managed_refuse(void)
{
    int failures = 0;
    struct mserver S;
    struct peer cp;
    mserver_init(&S);
    peer_init(&cp);
    S.refuse = 1;

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(managed_listener_up(senv, &S, &l), WTQ_OK);
    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);

    WTQ_TEST_CHECK(peer_wait_terminal(&cp));
    WTQ_TEST_CHECK_EQ_INT(cp.established, 0);
    WTQ_TEST_CHECK(S.prepare_calls >= 1);
    WTQ_TEST_CHECK_EQ_INT(S.s_established, 0);
    WTQ_TEST_CHECK_EQ_INT(S.enters, 0);          /* no child, no guard */
    WTQ_TEST_CHECK_EQ_INT(S.abandon_calls, 0);   /* refusal != abandon */
    WTQ_TEST_CHECK_EQ_INT(S.quiesce_calls, 0);

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&cp);
    mserver_destroy(&S);
    if (failures == 0) printf("PASS: managed_refuse\n");
    return failures;
}

/* Admitted, then ConnectionSetConfiguration fails: accept_abandon fires
 * exactly once, quiescence never — the exclusivity + abandon-per-failure. */
/* Every documented post-admission failure aborts the connection and fires
 * accept_abandon EXACTLY ONCE, never on_transport_quiesced. stage 0 =
 * ConnectionSetConfiguration; 1 = driver alloc; 2 = session create;
 * 3 = serve; 4 = env-closing accept refusal. */
static int managed_abandon_case(int stage)
{
    int failures = 0;
    struct mserver S;
    struct peer cp;
    mserver_init(&S);
    peer_init(&cp);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(managed_listener_up(senv, &S, &l), WTQ_OK);
    if (stage == 0)
        atomic_store(&wtq_msq_test_fail_set_configuration, 1);
    else
        atomic_store(&wtq_msq_test_fail_admit_stage, stage);

    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait_terminal(&cp));
    WTQ_TEST_CHECK_EQ_INT(cp.established, 0);

    /* barrier: env_close guarantees no further callbacks touch S. */
    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);

    WTQ_TEST_CHECK_EQ_INT(S.prepare_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(S.abandon_calls, 1);   /* exactly once */
    WTQ_TEST_CHECK_EQ_INT(S.quiesce_calls, 0);   /* never ran => not quiesced */
    WTQ_TEST_CHECK_EQ_INT(S.s_established, 0);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&wtq_msq_test_fail_set_configuration),
                          0);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&wtq_msq_test_fail_admit_stage), 0);

    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&cp);
    mserver_destroy(&S);
    if (failures == 0) printf("PASS: managed_abandon[stage %d]\n", stage);
    return failures;
}

static int t_managed_abandon(void)
{
    int failures = 0;
    for (int stage = 0; stage <= 4; stage++)
        failures += managed_abandon_case(stage);
    return failures;
}

/* A server accept_prepare that returns a malformed guard (enter set, leave
 * NULL) is a caller bug: the connection is refused and abandon fires once
 * (unguarded), never quiescence. */
static int t_managed_server_guard_mismatch(void)
{
    int failures = 0;
    struct mserver S;
    struct peer cp;
    mserver_init(&S);
    peer_init(&cp);
    S.bad_guard = 1;

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(managed_listener_up(senv, &S, &l), WTQ_OK);
    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait_terminal(&cp));

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    WTQ_TEST_CHECK_EQ_INT(cp.established, 0);
    WTQ_TEST_CHECK_EQ_INT(S.prepare_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(S.abandon_calls, 1);   /* unguarded, once */
    WTQ_TEST_CHECK_EQ_INT(S.quiesce_calls, 0);
    WTQ_TEST_CHECK_EQ_INT(S.enters, 0);          /* bad guard never used */

    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&cp);
    mserver_destroy(&S);
    if (failures == 0) printf("PASS: managed_server_guard_mismatch\n");
    return failures;
}

/* A client cfg with a mismatched guard (enter set, leave NULL) is rejected. */
static int t_managed_client_guard_mismatch(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (env == NULL) return failures + 1;

    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    wtq_session_events_init(&ev);
    connect.authority = "localhost";
    connect.path = "/accept";
    connect.subprotocols = protos;
    connect.subprotocol_count = 1;
    cfg.server_name = "127.0.0.1";
    cfg.port = 4433;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.guard.enter = mguard_enter;   /* leave left NULL: mismatched */
    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &cfg, &cs),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(cs == NULL);

    wtq_msquic_env_close(env);
    if (failures == 0) printf("PASS: managed_client_guard_mismatch\n");
    return failures;
}

/* An old caller whose config is the frozen 07570ae v1 layout
 * (struct_size = sizeof(wtq_msquic_client_cfg_v1_t)) with garbage in the new
 * fields: the library must read only that v1 prefix and behave legacy. A
 * full-object garbage-tail test on the REAL transport — complements the
 * heap-backed ASan boundary tests in msquic_managed. */
static int t_managed_abi_old_prefix(void)
{
    int failures = 0;
    struct mserver S;   /* unused hooks; just a legacy server */
    struct peer cp;
    mserver_init(&S);
    peer_init(&cp);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    struct peer sp;
    peer_init(&sp);
    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);

    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_msquic_client_cfg_t cfg;
    /* Fill the whole current struct with garbage, set the v1 fields by hand,
     * then report struct_size as the frozen 07570ae v1 size: the library must
     * ignore the garbage guard/quiescence tail entirely. */
    memset(&cfg, 0xEE, sizeof(cfg));
    events_for(&ev);
    connect.authority = "localhost";
    connect.path = "/accept";
    connect.subprotocols = protos;
    connect.subprotocol_count = 1;
    cfg.struct_size = (uint32_t)sizeof(wtq_msquic_client_cfg_v1_t);
    cfg.server_name = "127.0.0.1";
    cfg.port = wtq_msquic_listener_port(l);
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = &cp;
    wtq_session_t *cs = NULL;
    /* garbage guard bytes ignored (else a callback would jump through them) */
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(cenv, &cfg, &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait_terminal(&cp) || cp.established > 0);

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&sp);
    peer_destroy(&cp);
    mserver_destroy(&S);
    if (failures == 0) printf("PASS: managed_abi_old_prefix\n");
    return failures;
}

/* An old caller whose listener cfg is the frozen 07570ae v1 layout
 * (struct_size = sizeof(wtq_msquic_listener_cfg_v1_t)), predating the
 * accept/quiescence tail, with garbage in those tail bytes: the library reads
 * only the v1 prefix, so the server behaves legacy — accepts a client without
 * any admission/guard/quiescence. Full-object garbage-tail test on the REAL
 * transport; the heap-backed ASan boundary tests live in msquic_managed. */
static int t_managed_listener_abi_old_prefix(void)
{
    int failures = 0;
    struct peer sp, cp;
    peer_init(&sp);
    peer_init(&cp);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL, *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &senv), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &cenv), WTQ_OK);
    if (senv == NULL || cenv == NULL) return failures + 1;

    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg;
    memset(&cfg, 0xEE, sizeof(cfg));   /* garbage tail (accept hooks etc.) */
    events_for(&ev);
    serve.path = "/accept";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    cfg.struct_size = (uint32_t)sizeof(wtq_msquic_listener_cfg_v1_t);
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = &sp;
    wtq_msquic_listener_t *l = NULL;
    /* garbage accept_prepare/abandon bytes must be ignored (else the server
     * would jump through them at NEW_CONNECTION). */
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_listener_start(senv, &cfg, &l), WTQ_OK);

    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait_terminal(&cp) || cp.established > 0);

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    wtq_msquic_env_close(cenv);
    if (cs != NULL) wtq_session_release(cs);
    peer_destroy(&sp);
    peer_destroy(&cp);
    if (failures == 0) printf("PASS: managed_listener_abi_old_prefix\n");
    return failures;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (certs_locate(argc > 1 ? argv[1] : NULL) != 0)
        return 2;

    failures += t_accept_refused_when_closing();
    failures += t_accept_publishes_atomically();
    failures += t_config_failure_unwind();
    failures += t_close_accept_churn();
    failures += t_managed_lifecycle();
    failures += t_managed_refuse();
    failures += t_managed_abandon();
    failures += t_managed_server_guard_mismatch();
    failures += t_managed_client_guard_mismatch();
    failures += t_managed_abi_old_prefix();
    failures += t_managed_listener_abi_old_prefix();

    if (failures == 0)
        printf("PASS: msquic_accept\n");
    else
        fprintf(stderr, "FAIL: msquic_accept (%d)\n", failures);
    return failures;
}
