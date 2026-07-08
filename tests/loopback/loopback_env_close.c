/*
 * wtq_msquic_env_close contract over real MsQuic on localhost: the
 * close must actively terminate every child connection (borrowed
 * Registration and idle_timeout 0 included), stop and free still-open
 * listeners, leave borrowed handles usable and unrelated siblings
 * alone, and block until retained session handles are safe to touch.
 *
 * Every scenario here is time-bounded by construction: teardown is
 * ACTIVE (never idle-timeout driven), waits use deadlines, and the
 * ctest registration carries a TIMEOUT — a regression to a passive or
 * absent close fails loudly (assert or test timeout), never silently.
 * One binary = one process, per the one-server-per-process convention.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

#include "test_support.h"

#define WAIT_SECS 30

/* One session's observed terminals, guarded for main-thread waits. */
struct peer {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int established;
    int closed;
    int failed;
    int refused;
    wtq_transport_error_t closed_err; /* record read inside on_closed */
    bool retain;             /* add_ref the session in on_established */
    wtq_session_t *session;  /* retained handle (server side) */
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

/* Wait until *flag != 0 (bounded). Returns false on deadline. */
static bool peer_wait(struct peer *p, const int *flag)
{
    struct timespec deadline;
    bool ok = true;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += WAIT_SECS;
    pthread_mutex_lock(&p->mu);
    while (*flag == 0 && ok)
        ok = pthread_cond_timedwait(&p->cv, &p->mu, &deadline) == 0;
    pthread_mutex_unlock(&p->mu);
    return *flag != 0;
}

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    struct peer *p = user;

    (void)sub;
    pthread_mutex_lock(&p->mu);
    p->established++;
    if (p->retain) {
        wtq_session_add_ref(s);
        p->session = s;
    }
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void cb_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t reason_len, bool clean,
                      void *user)
{
    struct peer *p = user;

    (void)code;
    (void)reason;
    (void)reason_len;
    (void)clean;
    pthread_mutex_lock(&p->mu);
    p->closed++;
    memset(&p->closed_err, 0, sizeof(p->closed_err));
    p->closed_err.struct_size = (uint32_t)sizeof(p->closed_err);
    (void)wtq_session_transport_error(s, &p->closed_err);
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void cb_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    struct peer *p = user;

    (void)s;
    (void)why;
    pthread_mutex_lock(&p->mu);
    p->failed++;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void cb_refused(wtq_session_t *s, uint16_t status, void *user)
{
    struct peer *p = user;

    (void)s;
    (void)status;
    pthread_mutex_lock(&p->mu);
    p->refused++;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void events_for(wtq_session_events_t *ev)
{
    wtq_session_events_init(ev);
    ev->on_established = cb_established;
    ev->on_closed = cb_closed;
    ev->on_failed = cb_failed;
    ev->on_refused = cb_refused;
}

/* a session is terminal once ANY terminal callback ran */
static int peer_terminals(struct peer *p)
{
    pthread_mutex_lock(&p->mu);
    int n = p->closed + p->failed + p->refused;
    pthread_mutex_unlock(&p->mu);
    return n;
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

/* --- fixtures --------------------------------------------------------------- */

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

static wtq_result_t listener_up(wtq_msquic_env_t *env, struct peer *p,
                                wtq_msquic_listener_t **l_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    events_for(&ev);
    serve.path = "/env";
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
    connect.path = "/env";
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

/* --- allocator counters ------------------------------------------------------ */

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

/* --- subtests --------------------------------------------------------------- */

/* Borrowed Registration, active connection: env_close must actively
 * tear the connection down and block for it — and leave the borrowed
 * Registration/API usable afterwards. */
static int t_close_borrowed_active(void)
{
    int failures = 0;
    const QUIC_API_TABLE *api = NULL;
    HQUIC reg = NULL;

    WTQ_TEST_CHECK(QUIC_SUCCEEDED(MsQuicOpen2(&api)));
    QUIC_REGISTRATION_CONFIG rc = { "wtq-borrow",
                                    QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->RegistrationOpen(&rc, &reg)));

    struct peer sp, cp;
    peer_init(&sp);
    peer_init(&cp);

    wtq_msquic_env_cfg_t secfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&secfg, &senv), WTQ_OK);

    wtq_msquic_env_cfg_t cecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    cecfg.existing_api = api;
    cecfg.existing_registration = reg;
    wtq_msquic_env_t *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cecfg, &cenv), WTQ_OK);

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);
    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait(&cp, &cp.established));
    WTQ_TEST_CHECK(peer_wait(&sp, &sp.established));

    /* the close under test */
    wtq_msquic_env_close(cenv);

    /* by return: the connection is fully torn down; the retained
     * handle is dead-but-valid and this thread may touch it */
    WTQ_TEST_CHECK_EQ_INT(peer_terminals(&cp), 1);
    WTQ_TEST_CHECK(wtq_session_status(cs) !=
                   WTQ_SESSION_STATUS_ESTABLISHED);
    /* environment close is a CAUSAL local error, not routine cleanup:
     * classified {LOCAL, MsQuic domain} in the record the terminal
     * callback observed */
    WTQ_TEST_CHECK_EQ_INT((int)cp.closed_err.kind,
                          (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_HEX(cp.closed_err.quic_code, 0x100);
    WTQ_TEST_CHECK_EQ_INT((int)cp.closed_err.native_domain,
                          (int)WTQ_ERRDOM_MSQUIC);
    wtq_session_release(cs);
    cs = NULL;

    /* the borrowed handles are untouched and still usable */
    QUIC_SETTINGS qs;
    memset(&qs, 0, sizeof(qs));
    QUIC_BUFFER alpn = { 2, (uint8_t *)"h3" };
    HQUIC config = NULL;
    WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->ConfigurationOpen(
        reg, &alpn, 1, &qs, sizeof(qs), NULL, &config)));
    if (config != NULL)
        api->ConfigurationClose(config);

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    api->RegistrationClose(reg);
    MsQuicClose(api);
    peer_destroy(&sp);
    peer_destroy(&cp);
    if (failures == 0)
        printf("PASS: close_borrowed_active\n");
    return failures;
}

/* Two environments sharing one borrowed Registration: closing one must
 * not shut down the other's connection. */
static int t_close_shared_borrowed_isolation(void)
{
    int failures = 0;
    const QUIC_API_TABLE *api = NULL;
    HQUIC reg = NULL;

    WTQ_TEST_CHECK(QUIC_SUCCEEDED(MsQuicOpen2(&api)));
    QUIC_REGISTRATION_CONFIG rc = { "wtq-shared",
                                    QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->RegistrationOpen(&rc, &reg)));

    struct peer sp, pa, pb;
    peer_init(&sp);
    peer_init(&pa);
    peer_init(&pb);

    wtq_msquic_env_cfg_t secfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&secfg, &senv), WTQ_OK);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    ecfg.existing_api = api;
    ecfg.existing_registration = reg;
    wtq_msquic_env_t *env_a = NULL;
    wtq_msquic_env_t *env_b = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env_a), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env_b), WTQ_OK);

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);
    uint16_t port = wtq_msquic_listener_port(l);

    wtq_session_t *sa = NULL;
    wtq_session_t *sb = NULL;
    WTQ_TEST_CHECK_EQ_INT(client_up(env_a, &pa, port, &sa), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(client_up(env_b, &pb, port, &sb), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait(&pa, &pa.established));
    WTQ_TEST_CHECK(peer_wait(&pb, &pb.established));

    wtq_msquic_env_close(env_a);

    /* A is done; B — an unrelated child of the SAME borrowed
     * Registration — is untouched */
    WTQ_TEST_CHECK_EQ_INT(peer_terminals(&pa), 1);
    WTQ_TEST_CHECK(wtq_session_status(sa) !=
                   WTQ_SESSION_STATUS_ESTABLISHED);
    wtq_session_release(sa);
    WTQ_TEST_CHECK_EQ_INT(peer_terminals(&pb), 0);

    wtq_msquic_env_close(env_b);
    WTQ_TEST_CHECK_EQ_INT(peer_terminals(&pb), 1);
    wtq_session_release(sb);

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    api->RegistrationClose(reg);
    MsQuicClose(api);
    peer_destroy(&sp);
    peer_destroy(&pa);
    peer_destroy(&pb);
    if (failures == 0)
        printf("PASS: close_shared_borrowed_isolation\n");
    return failures;
}

/* idle_timeout_ms = 0 (never idles out): env_close must actively
 * terminate the connection — a passive close would wait forever (the
 * ctest TIMEOUT is the backstop that makes such a regression loud).
 * The server side retains its session in on_established and inspects
 * it after ITS env_close returns. */
static int t_close_idle_zero(void)
{
    int failures = 0;
    struct peer sp, cp;

    peer_init(&sp);
    peer_init(&cp);
    sp.retain = true;

    wtq_msquic_env_cfg_t secfg = WTQ_MSQUIC_ENV_CFG_INIT;
    secfg.tuning.idle_timeout_ms = 0;
    wtq_msquic_env_t *senv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&secfg, &senv), WTQ_OK);

    wtq_msquic_env_cfg_t cecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    cecfg.tuning.idle_timeout_ms = 0;
    wtq_msquic_env_t *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cecfg, &cenv), WTQ_OK);

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);
    wtq_session_t *cs = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        client_up(cenv, &cp, wtq_msquic_listener_port(l), &cs), WTQ_OK);
    WTQ_TEST_CHECK(peer_wait(&cp, &cp.established));
    WTQ_TEST_CHECK(peer_wait(&sp, &sp.established));

    wtq_msquic_env_close(cenv); /* must return without an idle timeout */
    WTQ_TEST_CHECK_EQ_INT(peer_terminals(&cp), 1);
    wtq_session_release(cs);

    /* the server side notices the peer's shutdown (bounded wait), then
     * its env closes and the retained server session is inspectable */
    WTQ_TEST_CHECK(peer_wait_terminal(&sp));
    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    WTQ_TEST_CHECK(sp.session != NULL);
    if (sp.session != NULL) {
        WTQ_TEST_CHECK(wtq_session_status(sp.session) !=
                       WTQ_SESSION_STATUS_ESTABLISHED);
        wtq_session_release(sp.session);
    }
    peer_destroy(&sp);
    peer_destroy(&cp);
    if (failures == 0)
        printf("PASS: close_idle_zero\n");
    return failures;
}

/* A listener still open at env_close is stopped and freed by the close
 * (its handle is invalid afterwards, per the documented ownership); a
 * passive close would wait forever on the owned Registration's live
 * listener child. */
static int t_close_live_listener(void)
{
    int failures = 0;
    struct peer sp;

    peer_init(&sp);
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(env, &sp, &l), WTQ_OK);
    WTQ_TEST_CHECK(wtq_msquic_listener_port(l) != 0);

    /* no listener_stop: env_close owns it from here */
    wtq_msquic_env_close(env);

    peer_destroy(&sp);
    if (failures == 0)
        printf("PASS: close_live_listener\n");
    return failures;
}

/* Several simultaneous connections under one environment: env_close
 * returns only after ALL of them are torn down. */
static int t_close_multi(void)
{
    enum { N = 3 };
    int failures = 0;
    struct peer sp;
    struct peer cps[N];

    peer_init(&sp);
    wtq_msquic_env_cfg_t secfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&secfg, &senv), WTQ_OK);

    wtq_msquic_env_cfg_t cecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *cenv = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cecfg, &cenv), WTQ_OK);

    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sp, &l), WTQ_OK);
    uint16_t port = wtq_msquic_listener_port(l);

    wtq_session_t *cs[N] = { NULL, NULL, NULL };
    for (int i = 0; i < N; i++) {
        peer_init(&cps[i]);
        WTQ_TEST_CHECK_EQ_INT(client_up(cenv, &cps[i], port, &cs[i]),
                              WTQ_OK);
    }
    for (int i = 0; i < N; i++)
        WTQ_TEST_CHECK(peer_wait(&cps[i], &cps[i].established));

    wtq_msquic_env_close(cenv);

    for (int i = 0; i < N; i++) {
        WTQ_TEST_CHECK_EQ_INT(peer_terminals(&cps[i]), 1);
        WTQ_TEST_CHECK(wtq_session_status(cs[i]) !=
                       WTQ_SESSION_STATUS_ESTABLISHED);
        wtq_session_release(cs[i]);
        peer_destroy(&cps[i]);
    }

    wtq_msquic_listener_stop(l);
    wtq_msquic_env_close(senv);
    peer_destroy(&sp);
    if (failures == 0)
        printf("PASS: close_multi\n");
    return failures;
}

/* Failure paths keep the child accounting balanced: a failed listener
 * start and a refused client leave nothing tracked, and env_close
 * frees everything the env allocated. env_close(NULL) is a no-op. */
static int t_close_failure_paths(void)
{
    int failures = 0;
    counting_alloc_t ca = { 0, 0 };
    wtq_alloc_t alloc = { &ca, count_alloc, NULL, count_free };
    struct peer p;

    peer_init(&p);
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    ecfg.alloc = &alloc;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);

    /* listener start failure: nonexistent certificate */
    wtq_session_events_t ev;
    events_for(&ev);
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    static const char *const protos[] = { "wtq-test" };
    serve.path = "/env";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
    lcfg.bind_address = "127.0.0.1";
    lcfg.cert_file = "/nonexistent/cert.pem";
    lcfg.key_file = "/nonexistent/key.pem";
    lcfg.paths = &serve;
    lcfg.path_count = 1;
    lcfg.events = &ev;
    lcfg.user = &p;
    wtq_msquic_listener_t *l = NULL;
    WTQ_TEST_CHECK(wtq_msquic_listener_start(env, &lcfg, &l) != WTQ_OK);
    WTQ_TEST_CHECK(l == NULL);

    /* client connect failure: invalid config (port 0) */
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost";
    connect.path = "/env";
    wtq_msquic_client_cfg_t ccfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    ccfg.server_name = "127.0.0.1";
    ccfg.port = 0;
    ccfg.connect = &connect;
    ccfg.events = &ev;
    ccfg.user = &p;
    wtq_session_t *s = NULL;
    WTQ_TEST_CHECK(wtq_msquic_client_connect(env, &ccfg, &s) != WTQ_OK);
    WTQ_TEST_CHECK(s == NULL);

    /* nothing tracked: close returns and the accounting balances */
    wtq_msquic_env_close(env);
    WTQ_TEST_CHECK_EQ_INT(ca.allocs, ca.frees);

    wtq_msquic_env_close(NULL); /* harmless */
    peer_destroy(&p);
    if (failures == 0)
        printf("PASS: close_failure_paths\n");
    return failures;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (certs_locate(argc > 1 ? argv[1] : NULL) != 0)
        return 2;

    failures += t_close_borrowed_active();
    failures += t_close_shared_borrowed_isolation();
    failures += t_close_idle_zero();
    failures += t_close_live_listener();
    failures += t_close_multi();
    failures += t_close_failure_paths();

    if (failures == 0)
        printf("PASS: loopback_env_close\n");
    else
        fprintf(stderr, "FAIL: loopback_env_close (%d)\n", failures);
    return failures;
}
