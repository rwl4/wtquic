/*
 * Dedicated caller-thread establishment battery for the managed Network
 * backend, with its OWN fresh MsQuic environment + listener (not appended
 * to the shared lifecycle suite). Interleaves main-thread and spawned-
 * thread creation per iteration and requires establishment (via the
 * on_established callback observed under a condition-variable gate, the
 * normal WAIT_MS=20000 ceiling). Every lifecycle result is asserted:
 * pthread_create/join, wtq_nw_conn_create, stop_begin, join, and
 * wait_root_gone. No retries, no ignored cleanup. Explicit pass/fail
 * counts per creation thread.
 */
#include <wtquic/wtquic.h>
#include <wtquic/wtquic_network.h>
#include <wtquic/wtquic_msquic.h>

#include "test_support.h"
#include "nw_internal.h"   /* wtq_nw_test_live_drivers (network-testing seam) */

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WAIT_MS 20000

/* The main thread services the main dispatch queue (see main()); off-main
 * creates schedule their group start there. This flag ends that service. */
static _Atomic int g_battery_done;

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

/* --- observation gate ---------------------------------------------------- */
struct obs {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int established, failed, closed, stopped;
    int after_stopped; /* ANY application event after on_stopped (must stay 0) */
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
static void bump(struct obs *o, int *field)
{
    pthread_mutex_lock(&o->mu);
    (*field)++;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}
/* Every APPLICATION event (established/failed/closed) goes through here so a
 * single accounting rule holds: on_stopped is FINAL -- no application event
 * of ANY kind may follow it. */
static void obs_app_event(struct obs *o, int *field)
{
    pthread_mutex_lock(&o->mu);
    (*field)++;
    if (o->stopped != 0)
        o->after_stopped++;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->mu);
}
static void ev_established(wtq_session_t *s, wtq_str_t sub, void *user)
{ (void)s; (void)sub; obs_app_event(user, &((struct obs *)user)->established); }
static void ev_failed(wtq_session_t *s, wtq_connect_failure_t why, void *user)
{ (void)s; (void)why; obs_app_event(user, &((struct obs *)user)->failed); }
static void ev_closed(wtq_session_t *s, uint32_t code, const uint8_t *r,
                      size_t rlen, bool clean, void *user)
{ (void)s; (void)code; (void)r; (void)rlen; (void)clean;
  obs_app_event(user, &((struct obs *)user)->closed); }
static void on_stopped_cb(void *ctx)
{ bump(ctx, &((struct obs *)ctx)->stopped); }
static void events_for(wtq_session_events_t *ev, struct obs *o)
{
    (void)o;
    wtq_session_events_init(ev);
    ev->on_established = ev_established;
    ev->on_failed = ev_failed;
    ev->on_closed = ev_closed;
}

/* --- server (fresh, owned by this binary) -------------------------------- */
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

static wtq_result_t client_up(struct obs *o, wtq_nw_conn_t **out)
{
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    events_for(&ev, o);
    connect.authority = "localhost";
    connect.path = "/nw";
    cfg.server_name = "127.0.0.1";
    cfg.port = g_port;
    cfg.insecure_skip_verify = true;   /* self-signed loopback */
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = o;
    cfg.on_stopped = on_stopped_cb;
    cfg.stopped_ctx = o;
    return wtq_nw_conn_create(&cfg, out);
}

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

/* --- one establishment attempt, all results asserted --------------------- */
struct create_arg { struct obs *o; wtq_nw_conn_t **out; wtq_result_t rc; };
static void *create_worker(void *a)
{
    struct create_arg *ca = a;
    ca->rc = client_up(ca->o, ca->out);
    return NULL;
}

/* returns 1 if established, 0 if not; *failures bumped on any lifecycle
 * assertion breach (never silently ignored). */
static int attempt(bool spawned, int *fail_out)
{
    int failures = 0;   /* LOCAL: WTQ_TEST_CHECK* increments this */
    struct obs o;
    wtq_nw_conn_t *c = NULL;
    wtq_result_t rc;
    int established = 0;
    obs_init(&o);
    pthread_mutex_lock(&g_sv.mu);
    int sv_before = g_sv.established;
    pthread_mutex_unlock(&g_sv.mu);

    if (spawned) {
        struct create_arg ca = { &o, &c, WTQ_ERR_BACKEND };
        pthread_t th;
        int pc = pthread_create(&th, NULL, create_worker, &ca);
        WTQ_TEST_CHECK_EQ_INT(pc, 0);
        if (pc != 0) { *fail_out += failures; obs_destroy(&o); return 0; }
        int pj = pthread_join(th, NULL);
        if (pj != 0) {
            /* An impossible join failure leaves ca.rc/c owned by a thread
             * that never terminated -- reading them is undefined. Fatal. */
            fprintf(stderr, "FATAL: pthread_join failed (%d)\n", pj);
            abort();
        }
        rc = ca.rc;
    } else {
        /* main-thread control: the create must run ON the process main
         * thread (which starts the group directly). We are on the driver
         * thread, so route it through the main dispatch queue, which main()
         * is servicing. */
        __block wtq_result_t mrc = WTQ_ERR_BACKEND;
        struct obs *op = &o; wtq_nw_conn_t **cp = &c;
        dispatch_sync(dispatch_get_main_queue(), ^{ mrc = client_up(op, cp); });
        rc = mrc;
    }

    WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);
    if (rc != WTQ_OK || c == NULL) { *fail_out += failures; obs_destroy(&o); return 0; }

    established = obs_wait(&o, &o.established) ? 1 : 0;
    /* server-side: did the SERVER's WT session establish for THIS conn?
     * (delta of the shared server obs). On a client stall the 20s wait
     * above already elapsed, so a server establish (<1s) has landed. */
    pthread_mutex_lock(&g_sv.mu);
    int sv_delta = g_sv.established - sv_before;
    pthread_mutex_unlock(&g_sv.mu);
    fprintf(stderr, "  ATTEMPT spawned=%d client_est=%d server_est_delta=%d\n",
            spawned, established, sv_delta);

    bool sb = wtq_nw_conn_stop_begin(c);
    WTQ_TEST_CHECK(sb);
    wtq_result_t jr = wtq_nw_conn_join(c);
    WTQ_TEST_CHECK_EQ_INT((int)jr, (int)WTQ_OK);
    wtq_nw_conn_release(c);
    bool gone = wait_root_gone(WAIT_MS);
    WTQ_TEST_CHECK(gone);
    *fail_out += failures;

    obs_destroy(&o);
    return established;
}

/* --- deterministic lifecycle: stop/post BEFORE the main-thread start ------
 * Uses the test-only start gate to hold an off-main-created group in the
 * STARTING state while we inject an accepted post() and a stop_begin(), then
 * releases it and verifies the ordered, exactly-once start+stop. Runs on the
 * DRIVER thread (off-main); main() services the main dispatch queue, so the
 * gated trampoline reaches the gate. */
static dispatch_semaphore_t g_gate;      /* released to let start proceed */
static dispatch_semaphore_t g_gate_reached; /* signaled when start is gated */
static _Atomic int g_post_ran;
static void gate_fn(void *ctx)
{
    (void)ctx;
    dispatch_semaphore_signal(g_gate_reached);       /* start is now blocked */
    dispatch_semaphore_wait(g_gate, DISPATCH_TIME_FOREVER);
}
static void post_job(void *ctx) { (void)ctx; atomic_fetch_add(&g_post_ran, 1); }

static int t_stop_before_start(int *fail_out)
{
    int failures = 0;
    struct obs o; obs_init(&o);
    wtq_nw_conn_t *c = NULL;

    g_gate = dispatch_semaphore_create(0);
    g_gate_reached = dispatch_semaphore_create(0);
    atomic_store(&g_post_ran, 0);
    wtq_nw_test_main_start_gate = gate_fn;

    /* create off-main (this driver thread) -> start trampoline QUEUED */
    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &c), (int)WTQ_OK);
    if (c == NULL) { *fail_out += failures + 1; obs_destroy(&o);
                     wtq_nw_test_main_start_gate = NULL; return 0; }

    /* block until the trampoline reaches the gate (STARTING) -- deterministic
     * (a semaphore, not a timed poll) */
    dispatch_semaphore_wait(g_gate_reached, DISPATCH_TIME_FOREVER);

    /* accepted post BEFORE stop; stop_begin BEFORE start latches CLOSED;
     * a later post rejects. */
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, post_job, NULL), (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_stop_begin(c) == true);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_post(c, post_job, NULL),
                          (int)WTQ_ERR_CLOSED);

    /* release the gate: start runs on main, then the stop worker is enqueued
     * AFTER it (and after the accepted post already on the domain). */
    dispatch_semaphore_signal(g_gate);
    wtq_nw_test_main_start_gate = NULL;

    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_join(c), (int)WTQ_OK);
    wtq_nw_conn_release(c);
    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS));

    pthread_mutex_lock(&o.mu);
    WTQ_TEST_CHECK_EQ_INT(atomic_load(&g_post_ran), 1); /* accepted post ran once */
    WTQ_TEST_CHECK_EQ_INT(o.stopped, 1);                /* on_stopped exactly once */
    WTQ_TEST_CHECK_EQ_INT(o.after_stopped, 0);        /* NO app event after on_stopped */
    pthread_mutex_unlock(&o.mu);

    dispatch_release(g_gate);
    dispatch_release(g_gate_reached);
    obs_destroy(&o);
    *fail_out += failures;
    return failures == 0;
}

/* Release the ONLY public ref while the off-main start is still gated in
 * STARTING: the construction reference must keep the handle alive until the
 * (gated) start runs; then implicit stop tears it down with no leak. Using
 * the gate makes the "release strictly before start" ordering deterministic
 * (a serviced main queue could otherwise finish the start first).
 * RED-validated by temporarily removing the construction reference in
 * nw_conn_build: without it, this release frees the handle out from under the
 * pending trampoline (ASan use-after-free). */
static int t_immediate_release(int *fail_out)
{
    int failures = 0;
    struct obs o; obs_init(&o);
    wtq_nw_conn_t *c = NULL;

    g_gate = dispatch_semaphore_create(0);
    g_gate_reached = dispatch_semaphore_create(0);
    wtq_nw_test_main_start_gate = gate_fn;

    WTQ_TEST_CHECK_EQ_INT((int)client_up(&o, &c), (int)WTQ_OK);
    if (c == NULL) { *fail_out += failures + 1; obs_destroy(&o);
                     wtq_nw_test_main_start_gate = NULL; return 0; }

    /* start is gated in STARTING -- drop the only public ref BEFORE start */
    dispatch_semaphore_wait(g_gate_reached, DISPATCH_TIME_FOREVER);
    wtq_nw_conn_release(c);            /* construction ref must still hold it */

    dispatch_semaphore_signal(g_gate); /* let the gated start proceed */
    wtq_nw_test_main_start_gate = NULL;

    WTQ_TEST_CHECK(wait_root_gone(WAIT_MS)); /* implicit stop + free, no leak */
    dispatch_release(g_gate);
    dispatch_release(g_gate_reached);
    obs_destroy(&o);
    *fail_out += failures;
    return failures == 0;
}

/* The interleaved battery runs on a DRIVER thread; main() services the main
 * dispatch queue so off-main creates' start trampolines (and the main-thread
 * control's dispatch_sync) execute. */
struct battery { int n; int failures; int main_ok; int spawn_ok; };
static void *battery_main(void *arg)
{
    struct battery *b = arg;
    for (int i = 0; i < b->n; i++) {     /* INTERLEAVED per iteration */
        b->main_ok += attempt(false, &b->failures);
        b->spawn_ok += attempt(true, &b->failures);
    }
    /* deterministic lifecycle coverage on the off-main start path */
    (void)t_stop_before_start(&b->failures);
    (void)t_immediate_release(&b->failures);
    atomic_store(&g_battery_done, 1);
    /* wake the main run loop so it notices g_battery_done promptly */
    CFRunLoopWakeUp(CFRunLoopGetMain());
    return NULL;
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

    int n = 20;
    const char *env = getenv("WTQ_NW_CREATE_ITERS");
    if (env != NULL && atoi(env) > 0)
        n = atoi(env);

    struct battery b = { n, 0, 0, 0 };
    pthread_t dth;
    if (pthread_create(&dth, NULL, battery_main, &b) != 0) {
        fprintf(stderr, "driver thread spawn failed\n");
        return 1;
    }
    /* SERVICE the main dispatch queue until the battery finishes. */
    while (!atomic_load(&g_battery_done))
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
    int dj = pthread_join(dth, NULL);
    if (dj != 0) {
        /* the driver owns b.*; an impossible join failure makes reading them
         * undefined -- fatal, as the per-attempt join already is */
        fprintf(stderr, "FATAL: driver pthread_join failed (%d)\n", dj);
        abort();
    }

    failures += b.failures;
    int main_ok = b.main_ok, spawn_ok = b.spawn_ok;
    fprintf(stderr, "[create-thread] main %d/%d, spawned %d/%d established\n",
            main_ok, n, spawn_ok, n);
    WTQ_TEST_CHECK_EQ_INT(main_ok, n);   /* control: perfect on main */
    WTQ_TEST_CHECK_EQ_INT(spawn_ok, n);  /* required: caller-independent */

    wtq_msquic_listener_stop(g_listener);
    wtq_msquic_env_close(g_env);
    obs_destroy(&g_sv);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_nw_create_thread (%d)\n", failures);
        return failures;
    }
    WTQ_TEST_PASS("test_nw_create_thread");
    return 0;
}
