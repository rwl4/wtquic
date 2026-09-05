/*
 * Network.framework client <-> MsQuic wtquic server loopback.
 *
 * Real cross-backend transport: the NW attach core (backends/network,
 * built through its test-only internal constructor) dials the public
 * managed MsQuic listener over localhost with self-signed certs. Covers
 * the slice-5 battery:
 *
 *   1. TLS/ALPN + WebTransport establishment.
 *   2. CONNECT response vs async native id ordering: the id arrives at
 *      the NW stream's `ready`, which is not externally schedulable, so
 *      the response/id race falls in BOTH orders across the 20-run gate;
 *      the deterministic pinning of each order lives in
 *      tests/unit/test_engine_async_id.c (fake async-id driver). Here
 *      every run asserts the establishment invariants hold whichever
 *      side won.
 *   3. Exact selected subprotocol, including escaped content.
 *   4. Local + peer uni/bidi streams, bytes, FIN, reset, detach.
 *   5. Datagrams both directions, exact payloads.
 *   6. Whole-stream abort wire behavior (stamped cancel: RESET + STOP,
 *      one code, observed by the MsQuic peer).
 *   7. Send completions exactly once across success, abort, peer STOP
 *      followed by local cancel, session close, and connection loss.
 *   8. Record ABA prevention and bounded WOULD_BLOCK (ring reuse under
 *      churn; writable edge resumes).
 *   9. Native error-domain population (posix refusal on a dead port).
 *  10. Clean refusal and setup failure without leaks (ASan lane).
 *  11. The hidden NW client-bidi 0 is parked in the backend: it never
 *      reaches the engine, so its engine-pool impact is ZERO slots; the
 *      session's identity (CONNECT stream id, datagram routing) is
 *      unaffected.
 *  12. WTQ_NW_LOOPBACK_RUNS consecutive full passes (ctest registers
 *      the 20-run gate) with no timeout or attribution mismatch.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

#include "nw_internal.h"

#include "test_support.h"

/*
 * Bounded-wait budget for every condition wait in this binary. The
 * normal lane keeps 20 s; sanitizer lanes pass WTQ_NW_WAIT_MS with a
 * budget matched to instrumentation overhead (an ASan/TSan-loaded
 * establishment occasionally needs more than 20 s). TEST-ONLY: no
 * production timeout semantics change and the engine still adds no
 * timer (§2.6 — the owning layer's connect timeout governs).
 */
static int g_wait_ms = 20000;
#define WAIT_MS g_wait_ms

/* Short, explicit watchdog for the wait-wake probe: a broken mutant is
 * rescued in a bounded time instead of consuming WAIT_MS four times. It is
 * never the oracle -- the recorded wait return status is. */
#define WP_BACKSTOP_MS 1000

/*
 * Environmental establishment retries are OPT-IN (WTQ_NW_ESTABLISH_
 * RETRIES, default 0): normal correctness gates take ONE attempt so an
 * intermittent backend regression can never hide behind a retry.
 * Sanitizer STRESS lanes enable a bounded count; every retry is
 * printed and counted, and the normal gates assert the count is 0.
 * A retry is infrastructure information, never equivalent to a
 * first-attempt pass.
 */
static int g_est_retries;    /* extra attempts allowed (default 0) */
static int g_est_retry_count;

/* In-memory server event ring: no I/O during the run (stderr prints
 * perturb timing enough to mask the race under investigation); dumped
 * only from a failure branch. */
static pthread_mutex_t g_ring_mu = PTHREAD_MUTEX_INITIALIZER;
static struct {
    char tag[12];
    size_t len;
    int fin;
} g_ring[256];
static int g_ring_n;

static void ring_put(const char *tag, size_t len, int fin)
{
    pthread_mutex_lock(&g_ring_mu);
    if (g_ring_n < 256) {
        strncpy(g_ring[g_ring_n].tag, tag, sizeof(g_ring[0].tag) - 1);
        g_ring[g_ring_n].tag[sizeof(g_ring[0].tag) - 1] = 0;
        g_ring[g_ring_n].len = len;
        g_ring[g_ring_n].fin = fin;
        g_ring_n++;
    }
    pthread_mutex_unlock(&g_ring_mu);
}

static void ring_dump(void)
{
    pthread_mutex_lock(&g_ring_mu);
    for (int i = 0; i < g_ring_n; i++)
        fprintf(stderr, "[ring] %s len=%zu fin=%d\n", g_ring[i].tag,
                g_ring[i].len, g_ring[i].fin);
    g_ring_n = 0;
    pthread_mutex_unlock(&g_ring_mu);
}

static void ring_reset(void)
{
    pthread_mutex_lock(&g_ring_mu);
    g_ring_n = 0;
    pthread_mutex_unlock(&g_ring_mu);
}

static bool test_dbg(void)
{
    static int on = -1;

    if (on < 0)
        on = getenv("WTQ_SV_DEBUG") != NULL ? 1 : 0;
    return on == 1;
}

/*
 * Domain routing: EVERY public-API call on the NW-backed session must
 * run on the connection's serialization domain (driver operations are
 * queue-confined; the public entry point for applications is slice 6's
 * wtq_nw_conn_post). These dispatch_sync wrappers are the test-only
 * internal analogue. Client callbacks already run on the domain and
 * never call back into the API here.
 */
static wtq_result_t dom_open_uni(struct wtq_driver *drv, wtq_session_t *s,
                                 wtq_stream_t **out)
{
    __block wtq_result_t rc;
    __block wtq_stream_t *st = NULL;
    dispatch_sync(drv->queue, ^{ rc = wtq_session_open_uni(s, &st); });
    *out = st;
    return rc;
}

static wtq_result_t dom_open_bidi(struct wtq_driver *drv, wtq_session_t *s,
                                  wtq_stream_t **out)
{
    __block wtq_result_t rc;
    __block wtq_stream_t *st = NULL;
    dispatch_sync(drv->queue, ^{ rc = wtq_session_open_bidi(s, &st); });
    *out = st;
    return rc;
}

static wtq_result_t dom_send(struct wtq_driver *drv, wtq_stream_t *st,
                             const wtq_span_t *spans, size_t n,
                             uint32_t flags, void *ctx)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue,
                  ^{ rc = wtq_stream_send(st, spans, n, flags, ctx); });
    return rc;
}

static wtq_result_t dom_abort(struct wtq_driver *drv, wtq_stream_t *st,
                              uint32_t code)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue, ^{ rc = wtq_stream_abort(st, code); });
    return rc;
}

static wtq_result_t dom_reset(struct wtq_driver *drv, wtq_stream_t *st,
                              uint32_t code)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue, ^{ rc = wtq_stream_reset(st, code); });
    return rc;
}

static wtq_result_t dom_stop(struct wtq_driver *drv, wtq_stream_t *st,
                             uint32_t code)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue,
                  ^{ rc = wtq_stream_stop_sending(st, code); });
    return rc;
}

static wtq_result_t dom_dgram(struct wtq_driver *drv, wtq_session_t *s,
                              const wtq_span_t *spans, size_t n)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue,
                  ^{ rc = wtq_session_send_datagram(s, spans, n); });
    return rc;
}

static size_t dom_dgram_max(struct wtq_driver *drv, wtq_session_t *s)
{
    __block size_t n;
    dispatch_sync(drv->queue, ^{ n = wtq_session_datagram_max_size(s); });
    return n;
}

static void dom_stream_release(struct wtq_driver *drv, wtq_stream_t *st)
{
    dispatch_sync(drv->queue, ^{ wtq_stream_release(st); });
}

static wtq_result_t dom_pause(struct wtq_driver *drv, wtq_stream_t *st)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue, ^{ rc = wtq_stream_pause_receive(st); });
    return rc;
}

static wtq_result_t dom_resume(struct wtq_driver *drv, wtq_stream_t *st)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue, ^{ rc = wtq_stream_resume_receive(st); });
    return rc;
}

/*
 * Find the backend stream a test paused: exactly one local app bidi ever
 * has recv_enabled == false (the one just paused), so !recv_enabled is a
 * unique, race-free selector on the domain. `ectx` is set at open, before
 * ready, so this works even before the stream is ready.
 */
static struct wtq_dstream *dom_find_paused_bidi(struct wtq_driver *drv)
{
    __block struct wtq_dstream *found = NULL;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->is_local && ds->is_bidi && !ds->hidden &&
              ds->ectx != NULL && !ds->recv_enabled && !ds->terminal &&
              !ds->failed_seen && !ds->cancel_issued &&
              !ds->cancel_deferred && !ds->recv_ended)
              found = ds; /* the LIVE paused stream — not a dead/cancelling
                             one, and not one whose receive side already
                             ENDED while paused (its recv_enabled can never
                             legally reset, so it would shadow the next
                             case's freshly paused stream) */
    });
    return found;
}

/*
 * Inject a receive completion on the domain exactly as Apple's
 * nw_connection_receive callback would (via the WTQ_NW_TESTING seam). The
 * dispatch_data_t is created with a copy destructor, so the seam's retain
 * (when it defers) is the only reference that outlives this call.
 */
static void dom_inject_recv_ex(struct wtq_driver *drv, struct wtq_dstream *ds,
                               const void *bytes, size_t len, bool fin,
                               bool errored)
{
    dispatch_sync(drv->queue, ^{
      dispatch_data_t d = NULL;
      if (bytes != NULL && len > 0)
          d = dispatch_data_create(bytes, len, drv->queue,
                                   DISPATCH_DATA_DESTRUCTOR_DEFAULT);
      wtq_nw_test_deliver_recv(ds, d, fin, errored, false);
      if (d != NULL)
          dispatch_release(d);
    });
}

static void dom_inject_recv(struct wtq_driver *drv, struct wtq_dstream *ds,
                            const void *bytes, size_t len, bool fin)
{
    dom_inject_recv_ex(drv, ds, bytes, len, fin, false);
}

/*
 * Destructor-counting injection: the injected dispatch_data_t carries a
 * custom destructor (no copy — the buffer is used as-is) that CAPTURES this
 * call's own counter, so the block runs EXACTLY when the last reference is
 * released and bumps that counter once — proving the retained transport
 * object is released exactly once whichever path (resume, reset, cancel,
 * teardown) drops it. No shared global: each object owns its token.
 */
static void dom_inject_recv_counted_ex(struct wtq_driver *drv,
                                       struct wtq_dstream *ds,
                                       const void *bytes, size_t len,
                                       bool fin, bool errored, int *counter)
{
    dispatch_sync(drv->queue, ^{
      int *token = counter; /* captured per-object by the destructor */
      dispatch_data_t d = dispatch_data_create(bytes, len, drv->queue,
                                               ^{ (*token)++; });
      wtq_nw_test_deliver_recv(ds, d, fin, errored, false);
      dispatch_release(d); /* the seam's retain (on defer) is the last ref */
    });
}

static void dom_inject_recv_counted(struct wtq_driver *drv,
                                    struct wtq_dstream *ds, const void *bytes,
                                    size_t len, bool fin, int *counter)
{
    dom_inject_recv_counted_ex(drv, ds, bytes, len, fin, false, counter);
}

/* Snapshot a stream's deferred-receive state on the domain. */
static bool dom_ds_deferred(struct wtq_driver *drv, struct wtq_dstream *ds)
{
    __block bool v = false;
    dispatch_sync(drv->queue, ^{ v = ds->recv_deferred; });
    return v;
}

/*
 * Snapshot BOTH the deferred flag and the per-stream arm count in ONE domain
 * turn. After a teardown op the ds is valid for only a bounded window (two-
 * phase reaping frees it a few turns later), so a separate late arm read can
 * touch reaped memory. Reading both here, adjacent to the teardown (the same
 * window dom_ds_deferred() already relies on), keeps the arm attribution
 * reap-safe: capture arms0 while the stream is live, do the teardown, then take
 * this single snapshot.
 */
static void dom_ds_snapshot(struct wtq_driver *drv, struct wtq_dstream *ds,
                            bool *deferred, unsigned *arms)
{
    __block bool d = false;
    __block unsigned a = 0;
    dispatch_sync(drv->queue, ^{ d = ds->recv_deferred; a = ds->recv_arm_count; });
    *deferred = d;
    *arms = a;
}


/* Drain one domain turn: lets blocks the previous operation enqueued (e.g.
 * a released dispatch_data's destructor, which runs on the domain) execute
 * before their effects are asserted. Touches no stream state. */
static void dom_drain(struct wtq_driver *drv)
{
    dispatch_sync(drv->queue, ^{});
}

/*
 * Resume + SAME-TURN capture. When the resume's replay can tear the stream
 * down REENTRANTLY (the data callback aborts it or closes the session), the
 * post-resume state must be read in the same domain turn as the resume — the
 * two-phase reap gives no later validity window for the raw ds.
 */
static wtq_result_t dom_resume_snap(struct wtq_driver *drv, wtq_stream_t *st,
                                    struct wtq_dstream *ds, bool *deferred,
                                    unsigned *arms)
{
    __block wtq_result_t rc;
    __block bool d = false;
    __block unsigned a = 0;
    dispatch_sync(drv->queue, ^{
      rc = wtq_stream_resume_receive(st);
      d = ds->recv_deferred;
      a = ds->recv_arm_count;
    });
    *deferred = d;
    *arms = a;
    return rc;
}

/* Per-stream nw_connection_receive arm count, read on the domain. Attributed
 * to THIS stream so another live stream arming between two samples cannot
 * perturb a single-stream assertion (a process-global counter could). Read it
 * only while the stream is LIVE; after a teardown-capable operation use the
 * same-turn combined helpers (dom_resume_snap / the fail-probe seam). */
static unsigned dom_ds_arms(struct wtq_driver *drv, struct wtq_dstream *ds)
{
    __block unsigned v = 0;
    dispatch_sync(drv->queue, ^{ v = ds->recv_arm_count; });
    return v;
}

/*
 * Capture the backend stream behind a freshly opened app bidi: pause it
 * (making it the unique !recv_enabled local bidi), snapshot the pointer,
 * then resume so it is a normal running stream again.
 */
static struct wtq_dstream *dom_capture_bidi(struct wtq_driver *drv,
                                            wtq_stream_t *st)
{
    (void)dom_pause(drv, st);
    struct wtq_dstream *ds = dom_find_paused_bidi(drv);
    (void)dom_resume(drv, st);
    return ds;
}

static wtq_result_t dom_close(struct wtq_driver *drv, wtq_session_t *s,
                              uint32_t code)
{
    __block wtq_result_t rc;
    dispatch_sync(drv->queue,
                  ^{ rc = wtq_session_close(s, code, NULL, 0); });
    return rc;
}

/* Bounded wait for datagram availability: the NW datagram flow's own
 * `ready` may lag session establishment; max_size flips nonzero when
 * the flow is usable. A condition wait, not a sleep-as-verdict. */
static bool wait_dgram_ready(struct wtq_driver *drv, wtq_session_t *s)
{
    for (int i = 0; i < WAIT_MS / 10; i++) {
        if (dom_dgram_max(drv, s) > 0)
            return true;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return false;
}

/* --- per-side observation ---------------------------------------------- */

#define MAX_CTX 64

struct side {
    pthread_mutex_t mu;
    pthread_cond_t cv;

    int established;
    char subproto[128];
    size_t subproto_len;
    /* the negotiated profile sampled INSIDE on_established, which is what
     * proves the value is published BEFORE the callback rather than merely
     * by the time the test gets around to asking. */
    int cb_prof_rc;
    int cb_prof;
    int refused;
    uint16_t refused_status;
    int failed;
    int failed_why;
    int closed;
    bool closed_clean;
    uint32_t closed_code;
    wtq_transport_error_t closed_err;

    int streams_opened;
    wtq_stream_t *last_opened;
    bool echo_streams;          /* echo bytes+FIN back on bidi streams  */
    uint8_t rx[4096];
    size_t rx_len;
    int rx_fins;
    int resets;
    uint64_t last_reset_code;
    size_t rx_at_reset;         /* rx_len sampled inside on_stream_reset  */
    bool resume_on_reset;       /* attempt a reentrant resume there       */
    wtq_result_t reset_resume_rc;
    /*
     * Replay-reentrancy probe: when the data callback delivers on
     * `reentry_target`, perform ONE action from INSIDE the delivery
     * (mirroring an app that reacts to replayed bytes) and record its rc.
     * One-shot; the action runs OUTSIDE sd->mu (it may fire callbacks that
     * re-lock it), exactly like the echo path.
     */
    wtq_stream_t *reentry_target;   /* comparison key; not dereferenced */
    wtq_session_t *reentry_session; /* for REENTRY_CLOSE_SESSION */
#define REENTRY_NONE 0
#define REENTRY_ABORT 1          /* wtq_stream_abort(st, 0x42) */
#define REENTRY_CLOSE_SESSION 2  /* wtq_session_close(session, 9, ...) */
#define REENTRY_RESUME 3         /* wtq_stream_resume_receive(st) */
    int reentry_action;
    wtq_result_t reentry_rc;
    int reentry_fired;
    int stops;
    uint64_t last_stop_code;
    int streams_closed;

    int dgrams;
    uint8_t last_dgram[256];
    size_t last_dgram_len;

    int writable_events;

    /*
     * OWNED echo records with an explicit state machine. The send
     * contract borrows span DATA until the exactly-once completion, so
     * every echo fragment is copied into a record first. States:
     *   FREE      available
     *   CALLING   wtq_stream_send is in flight on this thread; the
     *             completion-owed presumption is established BEFORE the
     *             call, and a completion arriving before the call
     *             returns is handled via completed_early
     *   ACCEPTED  completion owed
     *   QUEUED    WOULD_BLOCK: parked, retried per-stream in order
     * Records hold a stream reference (wtq_stream_add_ref) from
     * FREE-departure until FREE-return, released exactly once. Terminal
     * streams purge their QUEUED records (test-visible count).
     */
#define ECHO_RECS 32
#define ECHO_FREE 0
#define ECHO_CALLING 1
#define ECHO_ACCEPTED 2
#define ECHO_QUEUED 3
    struct echo_rec {
        uint8_t buf[80];
        size_t len;
        bool fin;
        wtq_stream_t *st; /* referenced while state != FREE */
        int state;
        bool completed_early; /* completion landed during CALLING */
    } echo[ECHO_RECS];
    struct echo_rec *echo_fifo[ECHO_RECS]; /* QUEUED, global order;
                                              retries filter per stream
                                              (no cross-stream HOL) */
    int echo_fifo_n;
    int echo_accepted;
    int echo_completed;
    int echo_purged;  /* QUEUED records dropped at stream terminal */
    int echo_dropped; /* pool exhausted / DATA-echo hard error: test-visible */
    int echo_fin_races; /* FIN-only echo whose send hard-errored because the
                           peer already reset/closed the stream — a benign,
                           timing-dependent teardown race (loses no data, leaks
                           nothing). Tracked, NOT asserted zero: counting it as
                           a hard drop makes the loopback gate flaky. */
    int echo_bad_transition; /* invariant violations */

    /* exactly-once completion audit: counts per registered ctx */
    void *ctx_key[MAX_CTX];
    int ctx_completions[MAX_CTX];
    int ctx_canceled[MAX_CTX];
    int nctx;
    int completions_total;
    /* One specific accepted send, tracked by cookie
     * identity, so a row can prove it received exactly one CANCELED
     * completion and never a successful one. */
    const void *nr_cookie;
    int nr_completions;
    int nr_canceled;
    int nr_success;
    /* a second independently tracked cookie */
    const void *k2_cookie;
    int k2_completions;
    int k2_canceled;
    /* a third slot for the second replacement batch */
    const void *k3_cookie;
    int k3_completions;
    int k3_canceled;
    /* the phase-order harness's own target send */
    const void *ph_slot_cookie;
    int ph_slot_completions;
    int ph_slot_canceled;

    /* --- deferral-barrier proof (server + client roles) --- */
    bool payload_barrier;         /* server: answer a "go" request with the
                                     full patterned payload + FIN */
    wtq_stream_t *barrier_stream; /* server: the responding bidi (referenced
                                     until the payload send completes) */
    bool verify_barrier;          /* client: barrier receiver role */
    wtq_stream_t *barrier_target_st; /* client: the TARGET stream handle —
                                     per-stream attribution key, so a second
                                     (progress) stream never pollutes the
                                     target's byte accounting */
    size_t barrier_total;         /* client: bytes delivered on the target */
    size_t barrier_mismatch;      /* client: bytes off the pattern */
    int barrier_fins;             /* client: FINs on the target */
    int other_total;              /* client: bytes on NON-target bidis (the
                                     progress stream's echo) */
    int other_fins;               /* client: FINs on non-target bidis */
    int defer_events;             /* client: backend deferral events for the
                                     target (test-seam hook; THE barrier) */
    int barrier_send_errors;      /* server: any payload send failure */
};

static void side_init(struct side *sd)
{
    memset(sd, 0, sizeof(*sd));
    pthread_mutex_init(&sd->mu, NULL);
    pthread_cond_init(&sd->cv, NULL);
}

static void side_destroy(struct side *sd)
{
    pthread_mutex_destroy(&sd->mu);
    pthread_cond_destroy(&sd->cv);
}

static void side_signal(struct side *sd)
{
    pthread_cond_broadcast(&sd->cv);
}

/* wait until *flag != 0 (mu held by caller pattern: helper takes it) */
static bool side_wait(struct side *sd, const int *flag)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&sd->mu);
    while (*flag == 0) {
        if (pthread_cond_timedwait(&sd->cv, &sd->mu, &ts) != 0)
            break;
    }
    bool ok = *flag != 0;
    pthread_mutex_unlock(&sd->mu);
    return ok;
}

/*
 * Wait for ANY session outcome -- established, REFUSED, failed or closed
 * -- on the callback condition variable, against ONE wall-clock deadline.
 * No polling and no sleeping: every one of those callbacks broadcasts, so
 * this wakes on the event itself.
 *
 * A refusal is a real terminal outcome. Omitting it would let an ordinary
 * HTTP refusal wake the wait, fail the predicate, block until the full
 * deadline, and then be misreported as "no outcome".
 *
 * Returns with `sd->mu` released.
 */
/*
 * TEST-ONLY probe for the wait helper. It records the causal facts the
 * ordinary path has no reason to keep:
 *
 *   entered   - set immediately BEFORE pthread_cond_timedwait, so a
 *               signaler can prove the waiter is at the wait point;
 *   wait_rc   - the return status of the wait that released us. 0 means a
 *               real condition-variable wake; ETIMEDOUT means the backstop
 *               expired. This is the oracle: never elapsed time.
 *
 * Lock ordering is explicit and never nested in both directions. The
 * waiter takes sd->mu, then briefly takes probe->mu to publish `entered`,
 * then RELEASES probe->mu before waiting. The signaler holds only
 * probe->mu while waiting for `entered`, releases it, and only then takes
 * sd->mu -- which it cannot acquire until pthread_cond_timedwait has
 * atomically released it, so the broadcast can never be missed.
 */
struct wp_probe {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool entered;
    int wait_rc;
    bool waited;
};

static void wp_probe_init(struct wp_probe *p)
{
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
    p->entered = false;
    p->wait_rc = -1;
    p->waited = false;
}

static void wp_probe_destroy(struct wp_probe *p)
{
    pthread_mutex_destroy(&p->mu);
    pthread_cond_destroy(&p->cv);
}

static bool side_wait_outcome_ex(struct side *sd, int backstop_ms,
                                 struct wp_probe *probe)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += backstop_ms / 1000;
    ts.tv_nsec += (long)(backstop_ms % 1000) * 1000 * 1000L;
    if (ts.tv_nsec >= 1000 * 1000 * 1000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000 * 1000 * 1000L;
    }
    pthread_mutex_lock(&sd->mu);
    while (sd->established == 0 && sd->refused == 0 && sd->failed == 0 &&
           sd->closed == 0) {
        if (probe != NULL && !probe->entered) {
            /* published while sd->mu is still HELD: the signaler cannot
             * take sd->mu, and so cannot broadcast, until the wait below
             * has released it */
            pthread_mutex_lock(&probe->mu);
            probe->entered = true;
            pthread_cond_broadcast(&probe->cv);
            pthread_mutex_unlock(&probe->mu);
        }
        const int rc = pthread_cond_timedwait(&sd->cv, &sd->mu, &ts);
        if (probe != NULL) {
            probe->waited = true;
            probe->wait_rc = rc;
        }
        if (rc != 0)
            break;
    }
    const bool got = sd->established != 0 || sd->refused != 0 ||
                     sd->failed != 0 || sd->closed != 0;
    pthread_mutex_unlock(&sd->mu);
    return got;
}

/*
 * Wait for ANY session outcome -- established, REFUSED, failed or closed
 * -- on the callback condition variable, against ONE wall-clock deadline.
 * No polling and no sleeping: every one of those callbacks broadcasts, so
 * this wakes on the event itself.
 *
 * A refusal is a real terminal outcome. Omitting it would let an ordinary
 * HTTP refusal wake the wait, fail the predicate, block until the full
 * deadline, and then be misreported as "no outcome".
 *
 * Returns with `sd->mu` released.
 */
static bool side_wait_outcome(struct side *sd)
{
    return side_wait_outcome_ex(sd, WAIT_MS, NULL);
}

static bool side_wait_ge(struct side *sd, const int *ctr, int want)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&sd->mu);
    while (*ctr < want) {
        if (pthread_cond_timedwait(&sd->cv, &sd->mu, &ts) != 0)
            break;
    }
    bool ok = *ctr >= want;
    pthread_mutex_unlock(&sd->mu);
    return ok;
}

static int ctx_slot(struct side *sd, void *key)
{
    for (int i = 0; i < sd->nctx; i++)
        if (sd->ctx_key[i] == key)
            return i;
    if (sd->nctx < MAX_CTX) {
        sd->ctx_key[sd->nctx] = key;
        return sd->nctx++;
    }
    return -1;
}

/* --- deferral-barrier fixtures ------------------------------------------- *
 *
 * The MsQuic server answers a "go" request on the target bidi with the full
 * patterned payload + FIN. The client keeps the target PAUSED with one
 * receive outstanding; THE barrier is the target's own backend DEFERRAL
 * EVENT (a test-seam hook fired the moment its completion is held) — a
 * direct, same-stream observation, deliberately NOT an ACK on one stream
 * used to order application callbacks on another (QUIC gives no such
 * cross-stream ordering). Progress while held is proven independently: a
 * second stream completes a full echo round-trip while the target stays
 * deferred with zero app delivery. Resume then yields the whole payload and
 * FIN, byte-exact and in order.
 *
 * SCOPE — this is an APP-LEVEL delivery-isolation proof, NOT a transport
 * flow-control bound. Network.framework auto-tunes its receive window and
 * buffers/ACKs data past the public initial-window setters (measured: a
 * ~500 KiB response completes under a 64 KiB advertised connection window),
 * so no exhaustion/blocking of the peer is claimed or asserted (see
 * COMPATIBILITY.md). */
#define BARRIER_TOTAL (256u * 1024u)
static uint8_t g_barrier_payload[BARRIER_TOTAL];
static int g_payload_ctx;

static uint8_t barrier_pat(size_t i)
{
    return (uint8_t)(i * 131u + 17u);
}

/* completions recorded for a registered send ctx (0 if unseen). */
static int side_ctx_completions_locked(struct side *sd, void *key)
{
    for (int i = 0; i < sd->nctx; i++)
        if (sd->ctx_key[i] == key)
            return sd->ctx_completions[i];
    return 0;
}

static int side_ctx_completions(struct side *sd, void *key)
{
    pthread_mutex_lock(&sd->mu);
    int n = side_ctx_completions_locked(sd, key);
    pthread_mutex_unlock(&sd->mu);
    return n;
}

/* Wait (condition, not sleep) until a ctx has >= want completions. */
static bool side_wait_ctx(struct side *sd, void *key, int want)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += WAIT_MS / 1000;
    pthread_mutex_lock(&sd->mu);
    while (side_ctx_completions_locked(sd, key) < want)
        if (pthread_cond_timedwait(&sd->cv, &sd->mu, &ts) != 0)
            break;
    bool ok = side_ctx_completions_locked(sd, key) >= want;
    pthread_mutex_unlock(&sd->mu);
    return ok;
}

/*
 * THE barrier: the backend deferral event for the TARGET stream, delivered
 * through the test-seam hook (wtq_nw_test_defer_hook) on the serialization
 * domain the moment a receive completion is held. Filtered to the target ds
 * and signalled on the client cv — a condition, not a poll or a sleep, and
 * a direct same-stream observation (no cross-stream ordering assumed).
 */
static struct side *g_defer_side;
static struct wtq_dstream *g_defer_ds;

static void barrier_defer_hook(struct wtq_dstream *ds)
{
    struct side *sd = g_defer_side;

    if (sd == NULL || (g_defer_ds != NULL && ds != g_defer_ds))
        return;
    pthread_mutex_lock(&sd->mu);
    sd->defer_events++;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

/* --- callbacks ----------------------------------------------------------- */

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    struct side *sd = user;

    /* query while the callback's session handle is known valid */
    wtq_webtransport_profile_t cbp = (wtq_webtransport_profile_t)0x7f;
    const wtq_result_t cbrc = wtq_session_webtransport_profile(s, &cbp);

    pthread_mutex_lock(&sd->mu);
    sd->cb_prof_rc = (int)cbrc;
    sd->cb_prof = (int)cbp;
    sd->established++;
    sd->subproto_len =
        sub.len < sizeof(sd->subproto) ? sub.len : sizeof(sd->subproto) - 1;
    memcpy(sd->subproto, sub.data, sd->subproto_len);
    sd->subproto[sd->subproto_len] = 0;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_refused(wtq_session_t *s, uint16_t status, void *user)
{
    struct side *sd = user;

    pthread_mutex_lock(&sd->mu);
    sd->refused++;
    sd->refused_status = status;
    memset(&sd->closed_err, 0, sizeof(sd->closed_err));
    sd->closed_err.struct_size = (uint32_t)sizeof(sd->closed_err);
    (void)wtq_session_transport_error(s, &sd->closed_err);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    struct side *sd = user;

    pthread_mutex_lock(&sd->mu);
    sd->failed++;
    sd->failed_why = (int)why;
    memset(&sd->closed_err, 0, sizeof(sd->closed_err));
    sd->closed_err.struct_size = (uint32_t)sizeof(sd->closed_err);
    (void)wtq_session_transport_error(s, &sd->closed_err);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_closed(wtq_session_t *s, uint32_t code, const uint8_t *reason,
                      size_t rlen, bool clean, void *user)
{
    struct side *sd = user;

    (void)reason;
    (void)rlen;
    pthread_mutex_lock(&sd->mu);
    sd->closed++;
    sd->closed_code = code;
    sd->closed_clean = clean;
    memset(&sd->closed_err, 0, sizeof(sd->closed_err));
    sd->closed_err.struct_size = (uint32_t)sizeof(sd->closed_err);
    (void)wtq_session_transport_error(s, &sd->closed_err);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_stream_opened(wtq_session_t *s, wtq_stream_t *st, bool bidi,
                             void *user)
{
    struct side *sd = user;

    (void)s;
    (void)bidi;
    pthread_mutex_lock(&sd->mu);
    sd->streams_opened++;
    sd->last_opened = st;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_stream_data(wtq_session_t *s, wtq_stream_t *st,
                           const uint8_t *data, size_t len, bool fin,
                           void *user)
{
    struct side *sd = user;
    bool echo = false;

    (void)s;
    ring_put(sd->echo_streams ? "sv-data" : "cl-data", len, (int)fin);
    if (test_dbg())
        fprintf(stderr, "[%s] data len=%zu fin=%d\n",
                sd->echo_streams ? "sv" : "cl", len, (int)fin);

    /* --- client: deferral-barrier receiver --- */
    if (sd->verify_barrier) {
        pthread_mutex_lock(&sd->mu);
        if (st == sd->barrier_target_st) {
            /* the TARGET stream's payload — verify each byte against the
             * pattern at its stream offset (delivered only after resume) */
            size_t off = sd->barrier_total;
            for (size_t i = 0; i < len; i++)
                if (data[i] != barrier_pat(off + i)) {
                    sd->barrier_mismatch++;
                    break;
                }
            sd->barrier_total += len;
            if (fin)
                sd->barrier_fins++;
        } else if (wtq_stream_is_bidi(st)) {
            /* a NON-target bidi (the progress stream's echo): counted
             * separately so it can never pollute the target accounting */
            sd->other_total += (int)len;
            if (fin)
                sd->other_fins++;
        }
        side_signal(sd);
        pthread_mutex_unlock(&sd->mu);
        return;
    }

    /* --- server: payload-barrier responder ("go" only; everything else
     * falls through to the echo path so a progress stream round-trips) --- */
    if (sd->payload_barrier && wtq_stream_is_bidi(st) && fin && len == 2 &&
        memcmp(data, "go", 2) == 0) {
        pthread_mutex_lock(&sd->mu);
        sd->barrier_stream = st;
        pthread_mutex_unlock(&sd->mu);
        wtq_stream_add_ref(st); /* held until the payload send completes */
        wtq_span_t all = { g_barrier_payload, BARRIER_TOTAL };
        wtq_result_t rc = wtq_stream_send(st, &all, 1, WTQ_SEND_FIN,
                                          &g_payload_ctx);
        if (rc != WTQ_OK) {
            pthread_mutex_lock(&sd->mu);
            sd->barrier_send_errors++;
            sd->barrier_stream = NULL;
            side_signal(sd);
            pthread_mutex_unlock(&sd->mu);
            wtq_stream_release(st); /* the ref we just took, on failure */
        }
        return;
    }

    pthread_mutex_lock(&sd->mu);
    if (sd->rx_len + len <= sizeof(sd->rx)) {
        memcpy(sd->rx + sd->rx_len, data, len);
        sd->rx_len += len;
    }
    if (fin)
        sd->rx_fins++;
    echo = sd->echo_streams && wtq_stream_is_bidi(st);
    /* replay-reentrancy probe: snapshot the one-shot action under the
     * lock, ACT outside it (the action fires callbacks that re-lock). */
    int reentry = REENTRY_NONE;
    wtq_session_t *reentry_s = NULL;
    if (sd->reentry_action != REENTRY_NONE && st == sd->reentry_target &&
        sd->reentry_fired == 0) {
        sd->reentry_fired = 1;
        reentry = sd->reentry_action;
        reentry_s = sd->reentry_session;
    }
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (reentry != REENTRY_NONE) {
        wtq_result_t rrc = WTQ_OK;
        switch (reentry) {
        case REENTRY_ABORT:
            rrc = wtq_stream_abort(st, 0x42);
            break;
        case REENTRY_CLOSE_SESSION:
            rrc = wtq_session_close(reentry_s, 9, NULL, 0);
            break;
        case REENTRY_RESUME:
            rrc = wtq_stream_resume_receive(st);
            break;
        default:
            break;
        }
        pthread_mutex_lock(&sd->mu);
        sd->reentry_rc = rrc;
        side_signal(sd);
        pthread_mutex_unlock(&sd->mu);
    }

    if (echo && (len > 0 || fin) && len <= 64) {
        /* select + transition under the lock; CALL OUTSIDE it */
        struct echo_rec *rec = NULL;
        pthread_mutex_lock(&sd->mu);
        for (int i = 0; i < ECHO_RECS; i++)
            if (sd->echo[i].state == ECHO_FREE) {
                rec = &sd->echo[i];
                rec->state = ECHO_CALLING;
                rec->completed_early = false;
                rec->len = len;
                rec->fin = fin;
                rec->st = st;
                if (len > 0)
                    memcpy(rec->buf, data, len);
                break;
            }
        if (rec == NULL)
            sd->echo_dropped++;
        pthread_mutex_unlock(&sd->mu);
        if (rec != NULL) {
            wtq_stream_add_ref(st); /* held until FREE-return */
            wtq_result_t rc;
            if (rec->len > 0) {
                wtq_span_t span = { rec->buf, rec->len };
                rc = wtq_stream_send(st, &span, 1,
                                     rec->fin ? WTQ_SEND_FIN : 0, rec);
            } else {
                rc = wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, rec);
            }
            ring_put("sv-echo-rc", (size_t)(-rc), 0);
            /* reconcile under the lock (the completion may already
             * have run: completed_early) */
            bool release_ref = false;
            pthread_mutex_lock(&sd->mu);
            if (rc == WTQ_OK) {
                sd->echo_accepted++;
                if (rec->completed_early) {
                    rec->state = ECHO_FREE; /* completed before return */
                    release_ref = true;
                } else {
                    rec->state = ECHO_ACCEPTED;
                }
            } else if (rc == WTQ_ERR_WOULD_BLOCK) {
                if (rec->completed_early)
                    sd->echo_bad_transition++; /* impossible: no accept */
                if (sd->echo_fifo_n < ECHO_RECS) {
                    rec->state = ECHO_QUEUED;
                    sd->echo_fifo[sd->echo_fifo_n++] = rec;
                } else {
                    rec->state = ECHO_FREE;
                    release_ref = true;
                    sd->echo_dropped++;
                }
            } else {
                /* not accepted: no completion owed. A FIN-ONLY echo (no
                 * payload) that hard-errors is a benign peer-teardown race —
                 * the peer reset/stopped the stream before we could echo its
                 * FIN; no data is lost and nothing leaks (freed + ref released
                 * here). It is timing-dependent, so folding it into
                 * echo_dropped makes the gate flaky. A DATA echo (len>0) that
                 * fails is still counted as a real drop. */
                if (rec->completed_early)
                    sd->echo_bad_transition++;
                rec->state = ECHO_FREE;
                release_ref = true;
                /* ONLY the measured teardown return (WTQ_ERR_BACKEND: MsQuic's
                 * StreamSend rejected the FIN because the peer already
                 * reset/stopped the stream) on a FIN-only echo is the benign
                 * race. Any other code (NOMEM, INVALID_ARG, STATE, ...) — or a
                 * DATA echo — is a real drop the accounting must catch. */
                if (rec->len == 0 && rc == WTQ_ERR_BACKEND)
                    sd->echo_fin_races++;
                else
                    sd->echo_dropped++;
            }
            pthread_mutex_unlock(&sd->mu);
            if (release_ref)
                wtq_stream_release(st);
        }
    }
}

static void cb_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *user)
{
    struct side *sd = user;
    bool try_resume;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->resets++;
    sd->last_reset_code = code;
    sd->rx_at_reset = sd->rx_len; /* bytes delivered as of the reset */
    try_resume = sd->resume_on_reset;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (try_resume) {
        /* Reentrancy probe: a resume attempted from INSIDE on_stream_reset
         * (the API has not yet cleared recv_open) must be rejected and must
         * replay nothing — the backend dropped the deferred receive before
         * emitting this callback. Runs on the domain already. */
        sd->reset_resume_rc = wtq_stream_resume_receive(st);
    }
}

static void cb_stream_stop(wtq_session_t *s, wtq_stream_t *st, uint32_t code,
                           void *user)
{
    struct side *sd = user;

    (void)s;
    (void)st;
    pthread_mutex_lock(&sd->mu);
    sd->stops++;
    sd->last_stop_code = code;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_stream_closed(wtq_session_t *s, wtq_stream_t *st, void *user)
{
    struct side *sd = user;
    wtq_stream_t *release[ECHO_RECS];
    int nrel = 0;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->streams_closed++;
    /* purge this stream's QUEUED echoes: no retry can succeed and the
     * FIFO must never hold dangling entries (test-visible outcome) */
    for (int i = 0; i < sd->echo_fifo_n;) {
        if (sd->echo_fifo[i]->st == st) {
            struct echo_rec *rec = sd->echo_fifo[i];
            memmove(&sd->echo_fifo[i], &sd->echo_fifo[i + 1],
                    (size_t)(sd->echo_fifo_n - i - 1) *
                        sizeof(sd->echo_fifo[0]));
            sd->echo_fifo_n--;
            rec->state = ECHO_FREE;
            release[nrel++] = rec->st;
            sd->echo_purged++;
        } else {
            i++;
        }
    }
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
    for (int i = 0; i < nrel; i++)
        wtq_stream_release(release[i]);
}

static void cb_send_complete(wtq_session_t *s, void *send_ctx, bool canceled,
                             void *user)
{
    struct side *sd = user;

    (void)s;
    struct echo_rec *rec = NULL;
    wtq_stream_t *release_st = NULL;

    pthread_mutex_lock(&sd->mu);
    sd->completions_total++;
    if (sd->nr_cookie != NULL && send_ctx == sd->nr_cookie) {
        sd->nr_completions++;
        if (canceled)
            sd->nr_canceled++;
        else
            sd->nr_success++;
    }
    if (sd->k2_cookie != NULL && send_ctx == sd->k2_cookie) {
        sd->k2_completions++;
        if (canceled)
            sd->k2_canceled++;
    }
    if (sd->k3_cookie != NULL && send_ctx == sd->k3_cookie) {
        sd->k3_completions++;
        if (canceled)
            sd->k3_canceled++;
    }
    if (sd->ph_slot_cookie != NULL && send_ctx == sd->ph_slot_cookie) {
        sd->ph_slot_completions++;
        if (canceled)
            sd->ph_slot_canceled++;
    }
    for (int i = 0; i < ECHO_RECS; i++)
        if (send_ctx == (void *)&sd->echo[i]) { /* identity, not range */
            rec = &sd->echo[i];
            break;
        }
    if (rec != NULL) {
        sd->echo_completed++;
        if (rec->state == ECHO_ACCEPTED) {
            rec->state = ECHO_FREE;
            release_st = rec->st;
        } else if (rec->state == ECHO_CALLING) {
            /* completion beat the send call's return: the caller's
             * reconcile frees the record and releases the reference */
            rec->completed_early = true;
        } else {
            sd->echo_bad_transition++; /* completion for FREE/QUEUED */
        }
    } else if (send_ctx != NULL) {
        int i = ctx_slot(sd, send_ctx);
        if (i >= 0) {
            sd->ctx_completions[i]++;
            if (canceled)
                sd->ctx_canceled[i]++;
        }
    }
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
    if (release_st != NULL)
        wtq_stream_release(release_st);

    /* payload-barrier: the response send completed (or was canceled) —
     * release the ref the responder took, exactly once. Same server network
     * thread as the responder, so barrier_stream is stable here. */
    if (send_ctx == &g_payload_ctx && sd->payload_barrier &&
        sd->barrier_stream != NULL) {
        wtq_stream_release(sd->barrier_stream);
        sd->barrier_stream = NULL;
        if (canceled) {
            pthread_mutex_lock(&sd->mu);
            sd->barrier_send_errors++;
            side_signal(sd);
            pthread_mutex_unlock(&sd->mu);
        }
    }
}

static void cb_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->dgrams++;
    sd->last_dgram_len = len < sizeof(sd->last_dgram) ? len : 0;
    if (sd->last_dgram_len > 0)
        memcpy(sd->last_dgram, data, sd->last_dgram_len);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_writable(wtq_session_t *s, wtq_stream_t *st, void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->writable_events++;
    side_signal(sd);
    for (;;) {
        /* pick THIS stream's oldest QUEUED record (others keep their
         * positions: per-stream order, no cross-stream blocking) */
        struct echo_rec *rec = NULL;
        int idx = -1;
        for (int i = 0; i < sd->echo_fifo_n; i++)
            if (sd->echo_fifo[i]->st == st) {
                rec = sd->echo_fifo[i];
                idx = i;
                break;
            }
        if (rec == NULL)
            break;
        memmove(&sd->echo_fifo[idx], &sd->echo_fifo[idx + 1],
                (size_t)(sd->echo_fifo_n - idx - 1) *
                    sizeof(sd->echo_fifo[0]));
        sd->echo_fifo_n--;
        rec->state = ECHO_CALLING;
        rec->completed_early = false;
        pthread_mutex_unlock(&sd->mu); /* never send under the lock */
        wtq_result_t rc;
        if (rec->len > 0) {
            wtq_span_t span = { rec->buf, rec->len };
            rc = wtq_stream_send(st, &span, 1,
                                 rec->fin ? WTQ_SEND_FIN : 0, rec);
        } else {
            rc = wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, rec);
        }
        bool release_ref = false;
        bool stop = false;
        pthread_mutex_lock(&sd->mu);
        if (rc == WTQ_OK) {
            sd->echo_accepted++;
            if (rec->completed_early) {
                rec->state = ECHO_FREE;
                release_ref = true;
            } else {
                rec->state = ECHO_ACCEPTED;
            }
        } else if (rc == WTQ_ERR_WOULD_BLOCK) {
            /* still blocked: back to the FRONT (per-stream order) */
            memmove(&sd->echo_fifo[1], &sd->echo_fifo[0],
                    (size_t)sd->echo_fifo_n * sizeof(sd->echo_fifo[0]));
            sd->echo_fifo[0] = rec;
            sd->echo_fifo_n++;
            rec->state = ECHO_QUEUED;
            stop = true;
        } else {
            rec->state = ECHO_FREE; /* hard error: no completion owed */
            release_ref = true;
            /* Same benign-race gate as the initial-send path: only a FIN-only
             * echo failing with the measured teardown return is excused; every
             * other code (and any DATA echo) is a real drop. */
            if (rec->len == 0 && rc == WTQ_ERR_BACKEND)
                sd->echo_fin_races++;
            else
                sd->echo_dropped++;
        }
        pthread_mutex_unlock(&sd->mu);
        if (release_ref)
            wtq_stream_release(st);
        pthread_mutex_lock(&sd->mu);
        if (stop)
            break;
    }
    pthread_mutex_unlock(&sd->mu);
}

static void events_for(wtq_session_events_t *ev)
{
    wtq_session_events_init(ev);
    ev->on_established = cb_established;
    ev->on_refused = cb_refused;
    ev->on_failed = cb_failed;
    ev->on_closed = cb_closed;
    ev->on_stream_opened = cb_stream_opened;
    ev->on_stream_data = cb_stream_data;
    ev->on_stream_reset = cb_stream_reset;
    ev->on_stream_stop = cb_stream_stop;
    ev->on_stream_closed = cb_stream_closed;
    ev->on_send_complete = cb_send_complete;
    ev->on_datagram = cb_datagram;
    ev->on_stream_writable = cb_writable;
}

/* --- fixtures -------------------------------------------------------------- */

static char cert_path[512];
static char key_path[512];

/* The subprotocol needs SF-string escaping on the wire: quote + slash. */
static const char *const ESCAPED_PROTO = "wt-\"esc\\proto";

static int certs_locate(const char *argv1)
{
    const char *dir = argv1;

    if (dir == NULL)
        dir = getenv("WTQ_TEST_CERT_DIR");
    if (dir == NULL) {
        fprintf(stderr, "no cert dir: set WTQ_TEST_CERT_DIR or argv[1]\n");
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

static wtq_result_t listener_up(wtq_msquic_env_t *env, struct side *sd,
                                wtq_msquic_listener_t **l_out)
{
    static const char *protos_storage[2];
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    protos_storage[0] = ESCAPED_PROTO;
    protos_storage[1] = "wtq-nw-test";
    events_for(&ev);
    serve.path = "/nw";
    serve.subprotocols = protos_storage;
    serve.subprotocol_count = 2;

    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = sd;
    return wtq_msquic_listener_start(env, &cfg, l_out);
}

/* Per-scenario connect overrides. Both default to "unset", so every
 * scenario that does not touch them builds exactly the config it built
 * before: profile 0 is H3_CURRENT and a NULL origin is omitted. */
static uint32_t g_nw_profile;
static const char *g_nw_origin;
static const char NW_TEST_ORIGIN[] = "https://localhost:443";

/* Same listener as listener_up, but advertising a caller-chosen profile
 * capability SET rather than the default singular current profile. */
static wtq_result_t listener_up_profiles(wtq_msquic_env_t *env,
                                         struct side *sd,
                                         wtq_webtransport_profile_set_t set,
                                         wtq_msquic_listener_t **l_out)
{
    static const char *protos_storage[2];
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    protos_storage[0] = ESCAPED_PROTO;
    protos_storage[1] = "wtq-nw-test";
    events_for(&ev);
    serve.path = "/nw";
    serve.subprotocols = protos_storage;
    serve.subprotocol_count = 2;
    if ((set & WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT) !=
        0)
        serve.origin_policy = WTQ_ORIGIN_POLICY_ALLOW_ANY_NON_OPAQUE;

    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = sd;
    cfg.webtransport_profiles = set;
    return wtq_msquic_listener_start(env, &cfg, l_out);
}

static wtq_result_t nw_client_up_alloc(struct side *sd, uint16_t port,
                                       const char *path,
                                       const char *const *protos,
                                       size_t nprotos,
                                       const wtq_alloc_t *alloc,
                                       const char *origin,
                                       struct wtq_driver **drv_out,
                                       wtq_session_t **s_out)
{
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_nw_test_cfg_t cfg;

    events_for(&ev);
    connect.authority = "localhost";
    connect.path = path;
    connect.subprotocols = protos;
    connect.subprotocol_count = nprotos;
    connect.webtransport_profile = g_nw_profile;
    connect.origin = origin;

    memset(&cfg, 0, sizeof(cfg));
    cfg.alloc = alloc != NULL ? alloc : wtq_alloc_default();
    cfg.events = &ev;
    cfg.user = sd;
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.insecure_no_verify = true; /* self-signed loopback */
    cfg.connect = &connect;
    return wtq_nw_conn_create_internal(&cfg, drv_out, s_out);
}

static wtq_result_t nw_client_up(struct side *sd, uint16_t port,
                                 const char *path,
                                 const char *const *protos, size_t nprotos,
                                 struct wtq_driver **drv_out,
                                 wtq_session_t **s_out)
{
    return nw_client_up_alloc(sd, port, path, protos, nprotos, NULL,
                              g_nw_origin,
                              drv_out, s_out);
}

static wtq_result_t nw_client_up_origin(struct side *sd, uint16_t port,
                                        const char *path,
                                        const char *const *protos,
                                        size_t nprotos, const char *origin,
                                        struct wtq_driver **drv_out,
                                        wtq_session_t **s_out)
{
    return nw_client_up_alloc(sd, port, path, protos, nprotos, NULL, origin,
                              drv_out, s_out);
}

/* An establishment failure whose record carries {LOCAL, NW-native}
 * detail is ENVIRONMENTAL (measured under sanitizer load: {LOCAL,
 * NW_POSIX}, roughly 1 per 200 rapid loopback handshakes) — not a
 * backend or engine outcome. Anything else (including the metadata
 * invariant's {LOCAL, BACKEND}) is never retried. */
static bool side_err_is_environmental(const struct side *sd)
{
    return sd->closed_err.kind == WTQ_ERR_KIND_LOCAL &&
           (sd->closed_err.native_domain == WTQ_ERRDOM_NW_POSIX ||
            sd->closed_err.native_domain == WTQ_ERRDOM_NW_DNS ||
            sd->closed_err.native_domain == WTQ_ERRDOM_NW_TLS);
}

/*
 * Connect AND establish. Environmental retries are OPT-IN (see
 * g_est_retries): with the default 0, this is strictly ONE attempt.
 * When a stress lane enables retries, only a failure whose record
 * proves {LOCAL, NW-native} is retried — anything else (or exhausting
 * the bound) fails the test here — and every retry is counted and
 * printed.
 */
/*
 * Outcome of one setup attempt, snapshotted by the helper BEFORE it resets
 * its latches, so a caller taking the FALSE branch can still see exactly
 * what happened and whether the helper's own cleanup ran and succeeded.
 */
static bool nw_client_up_ready(struct side *cl, uint16_t port,
                               const char *path,
                               const char *const *protos, size_t nprotos,
                               const wtq_alloc_t *alloc,
                               struct wtq_driver **drv_out,
                               wtq_session_t **cs_out);

struct nw_setup_outcome {
    bool observed;        /* an outcome was delivered inside the budget */
    int established;
    int failed;
    int failed_why;
    int refused;
    int closed;
    bool cleanup_ran;     /* helper-owned rundown executed */
    bool rundown_ok;      /* and the bounded rundown SUCCEEDED */
    /*
     * FAIL-SAFE RETENTION. wtq_nw_conn_rundown_internal() returns false
     * when it could not quiesce: by contract it frees nothing, because
     * callbacks may still be live. In that case the helper must NOT
     * release the session and the caller must NOT destroy its `side` --
     * doing either would expose caller-owned callback state to a late
     * callback. `retained` says the objects were deliberately kept alive
     * (leaked) instead, mirroring the production contract.
     */
    bool retained;
};

static bool nw_client_up_ready_ex(struct side *cl, uint16_t port,
                                  const char *path,
                                  const char *const *protos, size_t nprotos,
                                  const wtq_alloc_t *alloc,
                                  const char *origin,
                                  struct wtq_driver **drv_out,
                                  wtq_session_t **cs_out,
                                  struct nw_setup_outcome *out)
{
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    for (int attempt = 0; attempt < 1 + g_est_retries; attempt++) {
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;

        if (nw_client_up_alloc(cl, port, path, protos, nprotos, alloc, origin,
                               &drv, &cs) != WTQ_OK ||
            cs == NULL)
            return false;
        /* Wait for ANY session outcome on the condition variable. This
         * blocks on the callback broadcast against one deadline -- it does
         * not poll and does not sleep. */
        const bool done = side_wait_outcome(cl);
        pthread_mutex_lock(&cl->mu);
        const bool est = cl->established > 0;
        pthread_mutex_unlock(&cl->mu);
        if (est) {
            *drv_out = drv;
            *cs_out = cs;
            if (out != NULL) {
                pthread_mutex_lock(&cl->mu);
                out->observed = true;
                out->established = cl->established;
                out->failed = cl->failed;
                out->failed_why = cl->failed_why;
                out->refused = cl->refused;
                out->closed = cl->closed;
                pthread_mutex_unlock(&cl->mu);
            }
            return true;
        }
        pthread_mutex_lock(&cl->mu);
        /* SNAPSHOT the outcome before the latches below are cleared */
        if (out != NULL) {
            out->observed = done;
            out->established = cl->established;
            out->failed = cl->failed;
            out->failed_why = cl->failed_why;
            out->refused = cl->refused;
            out->closed = cl->closed;
        }
        bool env = done && side_err_is_environmental(cl);
        /* a retry exists only when it will actually RUN */
        bool more = env && attempt + 1 < 1 + g_est_retries;
        fprintf(stderr,
                "[env] establishment attempt %d failed: outcome=%s "
                "kind=%d dom=%u code=%lld%s\n",
                attempt + 1, done ? "failure" : "none-in-budget",
                (int)cl->closed_err.kind, cl->closed_err.native_domain,
                (long long)cl->closed_err.native_code,
                more ? " — environmental, retrying" : "");
        /* reset the outcome latches for the next attempt */
        cl->established = 0;
        cl->failed = 0;
        cl->closed = 0;
        memset(&cl->closed_err, 0, sizeof(cl->closed_err));
        pthread_mutex_unlock(&cl->mu);
        {
            const bool rok = wtq_nw_conn_rundown_internal(drv, WAIT_MS);
            if (out != NULL) {
                out->cleanup_ran = true;
                out->rundown_ok = rok;   /* CHECKED, not discarded */
                out->retained = !rok;
            }
            if (rok) {
                wtq_session_release(cs);
            }
            /* else: the domain has NOT quiesced. Release nothing and let
             * the caller see `retained` so it keeps its callback state
             * alive. No timeout is widened and no late callback is
             * reclassified; the objects are deliberately leaked, exactly
             * as the rundown contract itself does. */
        }
        /* the caller's handles must be unusable after helper cleanup */
        if (drv_out != NULL)
            *drv_out = NULL;
        if (cs_out != NULL)
            *cs_out = NULL;
        if (!more)
            return false; /* not environmental, retries disabled, or
                             the bound is spent: the test sees it */
        g_est_retry_count++; /* counted at the START of a real retry */
    }
    return false;
}

/* The ordinary form: the SAME single implementation, no outcome wanted. */
static bool nw_client_up_ready(struct side *cl, uint16_t port,
                               const char *path,
                               const char *const *protos, size_t nprotos,
                               const wtq_alloc_t *alloc,
                               struct wtq_driver **drv_out,
                               wtq_session_t **cs_out)
{
    return nw_client_up_ready_ex(cl, port, path, protos, nprotos, alloc,
                                 g_nw_origin, drv_out, cs_out, NULL);
}

static bool nw_client_up_ready_origin(struct side *cl, uint16_t port,
                                      const char *path,
                                      const char *const *protos,
                                      size_t nprotos,
                                      const wtq_alloc_t *alloc,
                                      const char *origin,
                                      struct wtq_driver **drv_out,
                                      wtq_session_t **cs_out)
{
    return nw_client_up_ready_ex(cl, port, path, protos, nprotos, alloc,
                                 origin, drv_out, cs_out, NULL);
}

/* --- subtests --------------------------------------------------------------- */

/*
 * Establishment + traffic: escaped subprotocol; streams and bytes in
 * all four shapes; FIN; peer reset attribution; datagrams both ways;
 * the hidden NW bidi-0; clean session close.
 */
static int t_establish_traffic(wtq_msquic_env_t *env, uint16_t port)
{
    int failures = 0;
    struct side cl, sv_seen;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wt-\"esc\\proto" };

    (void)env;
    (void)sv_seen;
    side_init(&cl);
    cl.echo_streams = false;
    ring_reset();

    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs));
    if (cs == NULL) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* 3: the EXACT escaped subprotocol was selected */
    pthread_mutex_lock(&cl.mu);
    bool proto_ok = cl.subproto_len == strlen(ESCAPED_PROTO) &&
                    memcmp(cl.subproto, ESCAPED_PROTO, cl.subproto_len) == 0;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(proto_ok);

    /* 11: the hidden NW client-bidi 0 is backend-parked, never surfaced
     * to the engine — zero engine-pool slots consumed. Inspect the
     * backend on its own domain. */
    __block int hidden_count = 0;
    __block uint64_t hidden_id = UINT64_MAX;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->hidden) {
              hidden_count++;
              hidden_id = ds->id;
          }
    });
    if (hidden_count > 0) {
        /* when NW opens its hidden stream, it is client-bidi 0 and it
         * must not have corrupted session identity: the session
         * established and traffic below flows on other ids */
        WTQ_TEST_CHECK_EQ_U64(hidden_id, 0);
    }

    /* 4: client uni -> server, bytes + FIN */
    wtq_stream_t *uni = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &uni), (int)WTQ_OK);
    static const uint8_t msg_a[] = "nw-uni-hello";
    wtq_span_t sp = { msg_a, sizeof(msg_a) - 1 };
    WTQ_TEST_CHECK_EQ_INT(
        (int)dom_send(drv, uni, &sp, 1, WTQ_SEND_FIN, NULL),
        (int)WTQ_OK);

    /* 4: client bidi -> server echoes bytes + FIN back. NO retry: any
     * missing byte or FIN fails this run outright (the send-loss
     * investigation lives in test_nw_send_matrix; nothing here may
     * convert a transport-integrity failure into green). */
    static const uint8_t msg_b[] = "nw-bidi-echo";
    {
        wtq_stream_t *bidi = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &bidi),
                              (int)WTQ_OK);
        wtq_span_t sb = { msg_b, sizeof(msg_b) - 1 };
        pthread_mutex_lock(&cl.mu);
        cl.rx_len = 0;
        int fins_before = cl.rx_fins;
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT(
            (int)dom_send(drv, bidi, &sb, 1, WTQ_SEND_FIN, NULL),
            (int)WTQ_OK);
        bool got = side_wait_ge(&cl, &cl.rx_fins, fins_before + 1);
        WTQ_TEST_CHECK(got);
        if (!got) {
            ring_dump();
            dispatch_sync(drv->queue, ^{
              for (struct wtq_dstream *d = drv->streams; d != NULL;
                   d = d->next)
                  fprintf(stderr,
                          "[diag] ds id=%llu local=%d bidi=%d ready=%d "
                          "term=%d recvp=%d fin=%d pend=%d infl=%d "
                          "issued=%zu unret=%d live=%d\n",
                          (unsigned long long)d->id, (int)d->is_local,
                          (int)d->is_bidi, (int)d->ready_seen,
                          (int)d->terminal, (int)d->recv_pending,
                          (int)d->fin_delivered,
                          d->pending_sends != NULL,
                          (int)d->send_inflight, d->bytes_issued,
                          d->recs_unretired, d->batches_live);
            });
        }
    }
    pthread_mutex_lock(&cl.mu);
    bool echo_ok = cl.rx_len == sizeof(msg_b) - 1 &&
                   memcmp(cl.rx, msg_b, cl.rx_len) == 0;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(echo_ok);

    /* 5: datagrams both directions, exact payloads (server echoes) */
    static const uint8_t dg[] = "nw-dgram-ping";
    wtq_span_t dspan = { dg, sizeof(dg) - 1 };
    /* the datagram flow needs the session established; usable size > 0 */
    WTQ_TEST_CHECK(wait_dgram_ready(drv, cs));
    WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &dspan, 1),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.dgrams));
    pthread_mutex_lock(&cl.mu);
    bool dg_ok = cl.last_dgram_len == sizeof(dg) - 1 &&
                 memcmp(cl.last_dgram, dg, cl.last_dgram_len) == 0;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(dg_ok);

    /* 4: server-initiated peer streams reach the client (the server
     * echo harness opens one uni + one bidi on request via a control
     * datagram; see server_ops in main). Reset attribution: the server
     * RESETs a stream toward us with 0x77. */
    static const uint8_t cmd_open[] = "cmd:open-uni";
    wtq_span_t cspan = { cmd_open, sizeof(cmd_open) - 1 };
    WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &cspan, 1),
                          (int)WTQ_OK);
    /* the peer stream surfaces at NW-ready with bytes, THEN the server
     * resets it on command (an instantly-reset stream may legitimately
     * never surface from NW — it dies before ready) */
    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.streams_opened, 1));
    static const uint8_t cmd_reset[] = "cmd:reset-last";
    wtq_span_t rspan = { cmd_reset, sizeof(cmd_reset) - 1 };
    WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &rspan, 1),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.resets));
    pthread_mutex_lock(&cl.mu);
    uint64_t rcode = cl.last_reset_code;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK_EQ_U64(rcode, 0x77);

    /* peer-reset lifecycle on a SERVER-INITIATED bidi — pinning the
     * measured DEFERRAL: a peer RESET of a bidi's receive half does
     * NOT surface from NW while our send half is open (no reset
     * event, no receive error, no state change — measured on local
     * AND inbound bidis, with delivered bytes and an armed receive;
     * only UNI resets surface immediately, via stream failure). Once
     * our FIN completes the send half, NW reaches its terminal and
     * the reset surfaces with the REAL wire code — exactly one reset
     * event, exactly one closed event, dead-but-valid handle. */
    {
        pthread_mutex_lock(&cl.mu);
        int opened0 = cl.streams_opened;
        int resets0 = cl.resets;
        int closed0 = cl.streams_closed;
        cl.last_opened = NULL;
        pthread_mutex_unlock(&cl.mu);
        static const uint8_t cmd_ob[] = "cmd:open-bidi";
        wtq_span_t obs = { cmd_ob, sizeof(cmd_ob) - 1 };
        WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &obs, 1),
                              (int)WTQ_OK);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.streams_opened,
                                    opened0 + 1));
        pthread_mutex_lock(&cl.mu);
        wtq_stream_t *pb = cl.last_opened;
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK(pb != NULL);
        if (pb != NULL) {
            /* refcounting is domain-confined like every public call */
            wtq_stream_t *cap_pb = pb;
            dispatch_sync(drv->queue, ^{ wtq_stream_add_ref(cap_pb); });
        }
        static const uint8_t cmd_now[] = "cmd:reset-now";
        wtq_span_t nsp = { cmd_now, sizeof(cmd_now) - 1 };
        WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &nsp, 1),
                              (int)WTQ_OK);
        if (pb != NULL) {
            /* our send half is untouched by the peer's reset: FIN it —
             * the QUIC stream is then complete in both directions and
             * NW's terminal delivers the DEFERRED reset (bounded hint
             * wait; the abort's rc below is the per-stream ground
             * truth, immune to other streams' closed events) */
            WTQ_TEST_CHECK_EQ_INT(
                (int)dom_send(drv, pb, NULL, 0, WTQ_SEND_FIN, NULL),
                (int)WTQ_OK);
            (void)side_wait_ge(&cl, &cl.streams_closed, closed0 + 1);
            wtq_result_t arc = dom_abort(drv, pb, 1);
            pthread_mutex_lock(&cl.mu);
            int rdelta = cl.resets - resets0;
            uint64_t rlast = cl.last_reset_code;
            pthread_mutex_unlock(&cl.mu);
            fprintf(stderr,
                    "peer-reset bidi: %s, deferred resets=%d code=%llu\n",
                    arc == WTQ_ERR_CLOSED ? "terminaled" : "abort-closed",
                    rdelta, (unsigned long long)rlast);
            /* the SDK-guaranteed invariants, any interleaving: the
             * deferred reset arrives AT MOST once, its code is the
             * real 0x71 or the s4.4-legal absent 0 (measured: exact on
             * quiet runs, absent under load), and nothing is forged */
            WTQ_TEST_CHECK(rdelta == 0 || rdelta == 1);
            if (rdelta == 1)
                WTQ_TEST_CHECK(rlast == 0x71 || rlast == 0);
            /* dead exactly once: whichever path closed it, the handle
             * is dead-but-valid now */
            WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, pb, 1),
                                  (int)WTQ_ERR_CLOSED);
            dom_stream_release(drv, pb);
        }
    }

    /* clean close: sealed NONE record, clean on both ends */
    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 9),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK(cl.closed_clean);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.kind, (int)WTQ_ERR_KIND_NONE);
    pthread_mutex_unlock(&cl.mu);

    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    return failures;
}

/*
 * 6: whole-stream abort wire behavior. wtq_stream_abort on the NW side
 * is a stamped cancel; the MsQuic server must observe BOTH halves with
 * the one code: RESET_STREAM (on_stream_reset) and STOP_SENDING
 * (on_stream_stop) on a bidi; RESET alone on a uni.
 */
struct server_bridge; /* forward: server state lives in main's harness */

static int t_abort_wire(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wtq-nw-test" };

    side_init(&cl);
    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs));
    if (cs == NULL) {
        side_destroy(&cl);
        return failures + 1;
    }

    pthread_mutex_lock(&sv->mu);
    int base_resets = sv->resets;
    int base_stops = sv->stops;
    int base_opened = sv->streams_opened;
    pthread_mutex_unlock(&sv->mu);

    /* bidi abort: server sees RESET + STOP, one code */
    wtq_stream_t *bidi = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &bidi),
                          (int)WTQ_OK);
    static const uint8_t seed[] = "abort-me";
    wtq_span_t sp = { seed, sizeof(seed) - 1 };
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, bidi, &sp, 1, 0, NULL),
                          (int)WTQ_OK);
    /* the server must have the stream before the abort tears it down
     * (a stream reset before its first bytes never associates and
     * surfaces no app events at all) */
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->streams_opened, base_opened + 1));
    WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, bidi, 0x2A), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->resets, base_resets + 1));
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->stops, base_stops + 1));
    pthread_mutex_lock(&sv->mu);
    WTQ_TEST_CHECK_EQ_U64(sv->last_reset_code, 0x2A);
    WTQ_TEST_CHECK_EQ_U64(sv->last_stop_code, 0x2A);
    pthread_mutex_unlock(&sv->mu);

    /* uni abort: the sole (send) half, exact code -> server RESET */
    wtq_stream_t *uni = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &uni), (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, uni, &sp, 1, 0, NULL),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->streams_opened, base_opened + 2));
    WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, uni, 0x2B), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->resets, base_resets + 2));
    pthread_mutex_lock(&sv->mu);
    WTQ_TEST_CHECK_EQ_U64(sv->last_reset_code, 0x2B);
    pthread_mutex_unlock(&sv->mu);

    /* exact-half requests on a fully-open bidi are UNSUPPORTED on NW:
     * zero effect */
    wtq_stream_t *bidi2 = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &bidi2),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)dom_reset(drv, bidi2, 1),
                          (int)WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT((int)dom_stop(drv, bidi2, 1),
                          (int)WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, bidi2, &sp, 1, 0, NULL),
                          (int)WTQ_OK); /* still fully usable */
    WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, bidi2, 0), (int)WTQ_OK);

    /* deterministic in-callback-eligibility: a stream whose records
     * have FULLY retired before its cancel reaches `cancelled` with
     * nothing pending — the cancelled frame itself detects reap
     * eligibility. Destruction must still happen in a later queue
     * turn (the reap accounting at the end of main proves it). */
    {
        wtq_stream_t *settled = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &settled),
                              (int)WTQ_OK);
        static const uint8_t tiny[] = "settle";
        wtq_span_t tsp = { tiny, sizeof(tiny) - 1 };
        WTQ_TEST_CHECK_EQ_INT(
            (int)dom_send(drv, settled, &tsp, 1, 0, NULL), (int)WTQ_OK);
        bool settled_ok = false;
        for (int spin = 0; spin < WAIT_MS / 10 && !settled_ok; spin++) {
            __block int unret = 0;
            dispatch_sync(drv->queue, ^{
              for (struct wtq_dstream *d = drv->streams; d != NULL;
                   d = d->next)
                  unret += d->recs_unretired + d->batches_live;
            });
            settled_ok = unret == 0;
            if (!settled_ok) {
                struct timespec ts = { 0, 10 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
        }
        WTQ_TEST_CHECK(settled_ok);
        pthread_mutex_lock(&cl.mu);
        int closed_before = cl.streams_closed;
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, settled, 0),
                              (int)WTQ_OK);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.streams_closed,
                                    closed_before + 1));
    }

    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0),
                          (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    return failures;
}

/*
 * 7 + 8: exactly-once completions and the bounded send window. Every
 * registered send ctx must complete exactly once across success, flood
 * (WOULD_BLOCK + writable resume), whole-stream abort with pending
 * sends, peer STOP followed by local abort, session close, and hard
 * connection loss (rundown with sends in flight).
 */
static int t_send_completions(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wtq-nw-test" };
    static uint8_t payload[32 * 1024]; /* large: fills the byte cap */
    static int ctx_tokens[MAX_CTX];

    side_init(&cl);
    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs));
    if (cs == NULL) {
        side_destroy(&cl);
        return failures + 1;
    }
    memset(payload, 0xA5, sizeof(payload));
    int tok = 0;

    /* success: one tracked send, completes exactly once, not canceled */
    wtq_stream_t *ok_uni = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &ok_uni),
                          (int)WTQ_OK);
    {
        wtq_span_t sp = { payload, 64 };
        WTQ_TEST_CHECK_EQ_INT(
            (int)dom_send(drv, ok_uni, &sp, 1, WTQ_SEND_FIN,
                           &ctx_tokens[tok]),
            (int)WTQ_OK);
        int slot;
        pthread_mutex_lock(&cl.mu);
        slot = ctx_slot(&cl, &ctx_tokens[tok]);
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.ctx_completions[slot], 1));
        pthread_mutex_lock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT(cl.ctx_completions[slot], 1);
        WTQ_TEST_CHECK_EQ_INT(cl.ctx_canceled[slot], 0);
        pthread_mutex_unlock(&cl.mu);
        tok++;
    }

    /* flood until WOULD_BLOCK (8): the bounded ring/byte cap bites;
     * every ACCEPTED send completes exactly once; the writable edge
     * arrives; record slots are reused (churn = ABA exposure) */
    wtq_stream_t *flood = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &flood),
                          (int)WTQ_OK);
    {
        int accepted = 0;
        bool blocked = false;
        int first_tok = tok;
        for (int i = 0; i < MAX_CTX - 8 && !blocked; i++) {
            wtq_span_t sp = { payload, sizeof(payload) };
            wtq_result_t rc =
                dom_send(drv, flood, &sp, 1, 0, &ctx_tokens[tok]);
            if (rc == WTQ_OK) {
                pthread_mutex_lock(&cl.mu);
                (void)ctx_slot(&cl, &ctx_tokens[tok]);
                pthread_mutex_unlock(&cl.mu);
                accepted++;
                tok++;
            } else {
                WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_ERR_WOULD_BLOCK);
                blocked = true;
            }
        }
        WTQ_TEST_CHECK(blocked);      /* the bound is real */
        WTQ_TEST_CHECK(accepted > 0); /* and not degenerate */
        /* writable edge after capacity frees */
        WTQ_TEST_CHECK(side_wait(&cl, &cl.writable_events));
        /* every accepted send completes exactly once */
        for (int i = first_tok; i < tok; i++) {
            int slot;
            pthread_mutex_lock(&cl.mu);
            slot = ctx_slot(&cl, &ctx_tokens[i]);
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.ctx_completions[slot], 1));
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.ctx_completions[slot], 1);
            pthread_mutex_unlock(&cl.mu);
        }
        /* reuse after BOTH phases: a slot frees only once its record
         * is APP_COMPLETED and TRANSPORT_RETIRED (§3.3), so the next
         * send may legitimately WOULD_BLOCK until retirement lands —
         * the writable edge announces it; retry on that edge. */
        wtq_span_t sp2 = { payload, 128 };
        wtq_result_t rrc = WTQ_ERR_WOULD_BLOCK;
        for (int spin = 0; spin < WAIT_MS / 10 &&
                           rrc == WTQ_ERR_WOULD_BLOCK; spin++) {
            rrc = dom_send(drv, flood, &sp2, 1, 0, &ctx_tokens[tok]);
            if (rrc == WTQ_ERR_WOULD_BLOCK) {
                struct timespec rt = { 0, 10 * 1000 * 1000 };
                nanosleep(&rt, NULL);
            }
        }
        WTQ_TEST_CHECK_EQ_INT((int)rrc, (int)WTQ_OK);
        int slot;
        pthread_mutex_lock(&cl.mu);
        slot = ctx_slot(&cl, &ctx_tokens[tok]);
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.ctx_completions[slot], 1));
        tok++;
        (void)dom_abort(drv, flood, 0);
    }

    /* peer STOP then local cancel (7): the server STOPs our bidi; the
     * STOP is INVISIBLE on NW (standing limitation) — pending sends
     * stall until the local abort forces retirement; each completes
     * exactly once, canceled */
    wtq_stream_t *stopped = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &stopped),
                          (int)WTQ_OK);
    {
        pthread_mutex_lock(&sv->mu);
        int base_opened = sv->streams_opened;
        pthread_mutex_unlock(&sv->mu);
        WTQ_TEST_CHECK(wait_dgram_ready(drv, cs));
        static const uint8_t cmd[] = "cmd:stop-next";
        wtq_span_t csp = { cmd, sizeof(cmd) - 1 };
        WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &csp, 1),
                              (int)WTQ_OK);
        wtq_span_t seed = { payload, 32 };
        WTQ_TEST_CHECK_EQ_INT(
            (int)dom_send(drv, stopped, &seed, 1, 0, NULL), (int)WTQ_OK);
        WTQ_TEST_CHECK(side_wait_ge(sv, &sv->streams_opened,
                                    base_opened + 1));
        /* server issued STOP (see harness); give the wire a moment,
         * then stack pending sends and abort them */
        int first_tok = tok;
        for (int i = 0; i < 4; i++) {
            wtq_span_t sp = { payload, 4096 };
            if (dom_send(drv, stopped, &sp, 1, 0, &ctx_tokens[tok]) ==
                WTQ_OK) {
                pthread_mutex_lock(&cl.mu);
                (void)ctx_slot(&cl, &ctx_tokens[tok]);
                pthread_mutex_unlock(&cl.mu);
                tok++;
            }
        }
        WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, stopped, 0x33),
                              (int)WTQ_OK);
        for (int i = first_tok; i < tok; i++) {
            int slot;
            pthread_mutex_lock(&cl.mu);
            slot = ctx_slot(&cl, &ctx_tokens[i]);
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.ctx_completions[slot], 1));
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.ctx_completions[slot], 1);
            pthread_mutex_unlock(&cl.mu);
        }
    }

    /* session close with a pending send (7) */
    wtq_stream_t *closer = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &closer),
                          (int)WTQ_OK);
    {
        wtq_span_t sp = { payload, sizeof(payload) };
        int first_tok = tok;
        for (int i = 0; i < 3; i++)
            if (dom_send(drv, closer, &sp, 1, 0, &ctx_tokens[tok]) ==
                WTQ_OK) {
                pthread_mutex_lock(&cl.mu);
                (void)ctx_slot(&cl, &ctx_tokens[tok]);
                pthread_mutex_unlock(&cl.mu);
                tok++;
            }
        WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0),
                              (int)WTQ_OK);
        /* connection loss for the rest: rundown with sends in flight */
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        drv = NULL;
        for (int i = first_tok; i < tok; i++) {
            int slot;
            pthread_mutex_lock(&cl.mu);
            slot = ctx_slot(&cl, &ctx_tokens[i]);
            int n = cl.ctx_completions[slot];
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(n, 1); /* exactly once, via close or
                                          * forced retirement */
        }
    }

    /* the global audit: nothing ever completed twice */
    pthread_mutex_lock(&cl.mu);
    for (int i = 0; i < cl.nctx; i++)
        WTQ_TEST_CHECK(cl.ctx_completions[i] <= 1);
    pthread_mutex_unlock(&cl.mu);

    wtq_session_release(cs);
    side_destroy(&cl);
    return failures;
}

/* 10a: clean refusal (unknown path -> 404-class), sealed NONE record. */
static int t_refusal(uint16_t port)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wtq-nw-test" };

    side_init(&cl);
    WTQ_TEST_CHECK_EQ_INT(
        (int)nw_client_up(&cl, port, "/wrong", offer, 1, &drv, &cs),
        (int)WTQ_OK);
    if (cs == NULL) {
        side_destroy(&cl);
        return failures + 1;
    }
    WTQ_TEST_CHECK(side_wait(&cl, &cl.refused));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK(cl.refused_status >= 400);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.kind, (int)WTQ_ERR_KIND_NONE);
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    return failures;
}
/*
 * 9 + 10b: NW-native error-domain population + leak-free failure
 * teardown, via CONNECTION LOSS on an established session: a private
 * env/listener pair is torn down under the client (env_close sends the
 * transport close), and the client's terminal record must carry NW's
 * native domain/code — nothing fabricated.
 *
 * A PRE-READY setup failure cannot be used here: measured on this SDK,
 * a multiplex group that never becomes ready emits no state transition
 * with an error (and extract_connection returns NULL before start, so
 * no canary connection can exist). The owning layer's connect timeout
 * governs that case (§2.6); slice 6's managed lifecycle owns it.
 */

/*
 * A REAL Network.framework client speaking the D02/RFC9297 profile to a
 * REAL managed MsQuic listener over localhost. This is the only place the
 * profile is exercised end to end across two independent transports, so it
 * pins what neither the in-memory pair nor the MsQuic loopback can: that
 * the profile survives an actual QUIC handshake, an actual SETTINGS
 * exchange, and an actual extended CONNECT with its draft-02 markers.
 *
 * The negative row is the Origin duty. draft-02 3.3 makes Origin an
 * unconditional MUST, so a D02 client with no Origin must fail in
 * preflight -- before any socket work -- and must leave the process able
 * to run the positive row again.
 */
/* Runs ON the driver queue. Split out so the check macros write this
 * function's own failure counter rather than capturing the caller's. */
static int nw_d02_on_queue(wtq_session_t *cs)
{
    int failures = 0;

              /* the negotiated profile is D02 over a real wire */
              wtq_webtransport_profile_t p =
                  (wtq_webtransport_profile_t)0x7f;
              WTQ_TEST_CHECK_EQ_INT(
                  (int)wtq_session_webtransport_profile(cs, &p),
                  (int)WTQ_OK);
              WTQ_TEST_CHECK_EQ_INT(
                  (int)p,
                  (int)
                      WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT);

              /* The D02 outbound error cap holds over the real transport,
               * not only in the in-memory pair, and it is a PRE-transport
               * validation: 256 is refused as an invalid argument even on
               * a backend that could not perform the operation at all.
               * A one-sided reset/stop on a fully-open bidi is separately
               * UNSUPPORTED on Network.framework -- a pre-existing
               * transport limit that D02 neither introduces nor changes --
               * so the in-cap value surfaces THAT, and abort (which NW
               * does implement) carries the accepted 255. */
              wtq_stream_t *st = NULL;
              if (wtq_session_open_bidi(cs, &st) == WTQ_OK && st != NULL) {
                  WTQ_TEST_CHECK_EQ_INT((int)wtq_stream_reset(st, 256u),
                                        (int)WTQ_ERR_INVALID_ARG);
                  WTQ_TEST_CHECK_EQ_INT((int)wtq_stream_stop_sending(st, 256u),
                                        (int)WTQ_ERR_INVALID_ARG);
                  WTQ_TEST_CHECK_EQ_INT((int)wtq_stream_abort(st, 256u),
                                        (int)WTQ_ERR_INVALID_ARG);
                  WTQ_TEST_CHECK_EQ_INT((int)wtq_stream_reset(st, 255u),
                                        (int)WTQ_ERR_UNSUPPORTED);
                  /* the over-cap attempts left the stream fully usable */
                  WTQ_TEST_CHECK_EQ_INT((int)wtq_stream_abort(st, 255u),
                                        (int)WTQ_OK);
              } else {
                  failures++;
              }
    /* the session close belongs to the caller's step (6), so that the
     * terminal cardinality assertions own exactly one close. */
    return failures;
}

/*
 * A REAL Network.framework client speaking the D02/RFC9297 profile to a
 * REAL managed MsQuic listener over localhost. This is the only place the
 * profile is exercised end to end across two independent transports, so it
 * pins what neither the in-memory pair nor the MsQuic loopback can: that
 * the profile survives an actual QUIC handshake, an actual SETTINGS
 * exchange, and an actual extended CONNECT with its draft-02 markers, and
 * that real application bytes then cross that session.
 *
 * There are no retries and no timing sleeps: every wait is causal, on the
 * existing condition variables.
 */
/*
 * The wait helper's WAKE is proven causally, with no elapsed-time oracle.
 *
 * The sequence is:
 *   1. a waiter thread enters side_wait_outcome_ex;
 *   2. it publishes `entered` while still holding sd->mu, immediately
 *      before pthread_cond_timedwait -- so the signaler cannot proceed
 *      past the handshake and then acquire sd->mu until the wait has
 *      atomically released it;
 *   3. the signaler sets exactly ONE outcome latch under sd->mu and
 *      broadcasts;
 *   4. the waiter records the RETURN STATUS of the wait that released it.
 *
 * The oracle is that status: 0 means a genuine condition-variable wake,
 * ETIMEDOUT means the backstop expired. A latch that is merely set is NOT
 * sufficient, because after a backstop expiry the final predicate is true
 * either way -- which is exactly how a missing broadcast previously passed.
 *
 * The backstop here is short and explicit so that a broken mutant is
 * rescued quickly instead of consuming the normal WAIT_MS four times over.
 * It is a watchdog, never the oracle.
 */
struct wp_arg {
    struct side *sd;
    struct wp_probe *probe;
    int which;
    bool got;
};

/* the waiter */
static void *wp_waiter(void *p)
{
    struct wp_arg *a = p;

    a->got = side_wait_outcome_ex(a->sd, WP_BACKSTOP_MS, a->probe);
    return NULL;
}

static int t_wait_predicate(void)
{
    int failures = 0;
    static const char *const NAMES[] = { "established", "refused",
                                         "failed", "closed" };

    for (int which = 0; which < 4; which++) {
        struct side sd;
        struct wp_probe probe;
        struct wp_arg a;
        pthread_t th;

        side_init(&sd);
        wp_probe_init(&probe);
        a.sd = &sd;
        a.probe = &probe;
        a.which = which;
        a.got = false;

        if (pthread_create(&th, NULL, wp_waiter, &a) != 0) {
            fprintf(stderr, "FAIL: could not start waiter for '%s'\n",
                    NAMES[which]);
            failures++;
            wp_probe_destroy(&probe);
            side_destroy(&sd);
            continue; /* never join an uninitialised thread */
        }

        /* HANDSHAKE: block until the waiter is provably at the wait point.
         * Bounded so a broken build cannot hang the suite. */
        struct timespec hts;
        clock_gettime(CLOCK_REALTIME, &hts);
        hts.tv_sec += (WP_BACKSTOP_MS / 1000) + 2;
        pthread_mutex_lock(&probe.mu);
        while (!probe.entered) {
            if (pthread_cond_timedwait(&probe.cv, &probe.mu, &hts) != 0)
                break;
        }
        const bool entered = probe.entered;
        pthread_mutex_unlock(&probe.mu);
        if (!entered) {
            fprintf(stderr, "FAIL: waiter never reached the wait point "
                            "for '%s'\n", NAMES[which]);
            failures++;
        }

        /* set exactly ONE latch and broadcast */
        pthread_mutex_lock(&sd.mu);
        switch (which) {
        case 0: sd.established++; break;
        case 1: sd.refused++;     break;
        case 2: sd.failed++;      break;
        default: sd.closed++;     break;
        }
        side_signal(&sd);
        pthread_mutex_unlock(&sd.mu);

        pthread_join(th, NULL);

        /* THE ORACLE: the wait returned because it was SIGNALED. */
        pthread_mutex_lock(&probe.mu);
        const bool waited = probe.waited;
        const int wrc = probe.wait_rc;
        pthread_mutex_unlock(&probe.mu);
        if (!waited || wrc != 0) {
            fprintf(stderr,
                    "FAIL: outcome '%s' did not wake the wait by signal "
                    "(waited=%d wait_rc=%d%s)\n",
                    NAMES[which], (int)waited, wrc,
                    wrc == ETIMEDOUT ? " ETIMEDOUT/backstop" : "");
            failures++;
        }
        /* and the outcome itself is reported */
        if (!a.got) {
            fprintf(stderr, "FAIL: wait predicate missed outcome '%s'\n",
                    NAMES[which]);
            failures++;
        }
        pthread_mutex_lock(&sd.mu);
        const int seen = which == 0   ? sd.established
                         : which == 1 ? sd.refused
                         : which == 2 ? sd.failed
                                      : sd.closed;
        pthread_mutex_unlock(&sd.mu);
        WTQ_TEST_CHECK_EQ_INT(seen, 1);
        wp_probe_destroy(&probe);
        side_destroy(&sd);
    }
    return failures;
}

/*
 * Counting allocator for the close-flush lifetime oracle: it tracks the
 * live allocation balance so a test can prove that, after rundown and the
 * application's final release, everything the session and engine allocated
 * has actually been freed -- i.e. the session was really DESTROYED, not
 * merely dereferenced. This is what catches a corrupted callback bracket:
 * a session whose cb_depth never returns to 0 can never be destroyed by
 * session_unref, so its allocations stay live here.
 */
static struct {
    pthread_mutex_t mu;
    int live;
    size_t live_bytes;
    int errors;
} g_cnt = { PTHREAD_MUTEX_INITIALIZER, 0, 0, 0 };

static void cnt_reset(void)
{
    pthread_mutex_lock(&g_cnt.mu);
    g_cnt.live = 0;
    g_cnt.live_bytes = 0;
    g_cnt.errors = 0;
    pthread_mutex_unlock(&g_cnt.mu);
}

static void *cnt_alloc(size_t size, void *ctx)
{
    (void)ctx;
    void *p = malloc(size);
    if (p != NULL) {
        pthread_mutex_lock(&g_cnt.mu);
        g_cnt.live++;
        g_cnt.live_bytes += size;
        pthread_mutex_unlock(&g_cnt.mu);
    }
    return p;
}

/*
 * The allocator contract is SIZED: free/realloc receive the ORIGINAL
 * allocation size. This oracle must therefore account exactly, and must
 * never let a mis-accounted byte total wrap into a huge value that looks
 * like a leak (or, worse, back to zero and looks clean).
 *
 * TEST SEMANTICS, chosen deliberately and not inferred from libc:
 *   - realloc(NULL, n) behaves as alloc(n);
 *   - a FAILED realloc leaves the old block live and still charged, and is
 *     not accounted;
 *   - realloc(p, 0) is handled WITHOUT calling libc realloc at all, because
 *     libc may free the block and return NULL, which is indistinguishable
 *     from a failure. The public allocator contract defines no zero-size
 *     rule, so this oracle keeps the ORIGINAL block live and re-charges it
 *     to zero bytes. That transition is asserted directly by
 *     test_cnt_allocator_semantics().
 */
static void *cnt_realloc(void *ptr, size_t old_size, size_t new_size,
                         void *ctx)
{
    (void)ctx;
    if (ptr == NULL)
        return cnt_alloc(new_size, ctx);
    if (new_size == 0) {
        /* deterministic: never ask libc, keep the block, re-charge to 0 */
        pthread_mutex_lock(&g_cnt.mu);
        if (old_size > g_cnt.live_bytes) {
            g_cnt.errors++;
            g_cnt.live_bytes = 0;
        } else {
            g_cnt.live_bytes -= old_size;
        }
        pthread_mutex_unlock(&g_cnt.mu);
        return ptr;
    }
    void *p = realloc(ptr, new_size);
    if (p == NULL)
        return NULL; /* old block still live and still charged */
    pthread_mutex_lock(&g_cnt.mu);
    if (old_size > g_cnt.live_bytes) {
        g_cnt.errors++; /* accounting underflow: report, never wrap */
        g_cnt.live_bytes = 0;
    } else {
        g_cnt.live_bytes -= old_size;
    }
    g_cnt.live_bytes += new_size;
    pthread_mutex_unlock(&g_cnt.mu);
    return p;
}

static void cnt_free(void *ptr, size_t size, void *ctx)
{
    (void)ctx;
    if (ptr == NULL)
        return;
    pthread_mutex_lock(&g_cnt.mu);
    g_cnt.live--;
    if (g_cnt.live < 0)
        g_cnt.errors++;
    if (size > g_cnt.live_bytes) {
        g_cnt.errors++;
        g_cnt.live_bytes = 0;
    } else {
        g_cnt.live_bytes -= size;
    }
    pthread_mutex_unlock(&g_cnt.mu);
    free(ptr);
}

/*
 * STATIC allocator descriptor. It must outlive every path that can install
 * it: a stack-local descriptor installed into the process-global
 * wtq_nw_test_backend_alloc would dangle the moment a setup failure
 * returned early, and a later test would dereference dead stack.
 */
static const wtq_alloc_t g_cnt_vtable = { NULL, cnt_alloc, cnt_realloc,
                                          cnt_free };

/*
 * Scoped install/restore for EVERY process-global test seam this file's
 * close-flush rows touch. Installing through this and restoring on a single
 * exit path is what makes an early return safe.
 */
struct seam_scope {
    const wtq_alloc_t *prev_backend_alloc;
    int prev_hold_pump;
    int prev_cancel_with_owed;
    int prev_conn_closes;
    int prev_completion_first;
    int prev_retire_first;
    uint32_t prev_nw_profile;
    const char *prev_nw_origin;
};

/* Saves the PRIOR value of every mutable global these rows touch -- never
 * an assumed zero/NULL -- and restores exactly that. */
static void seam_install(struct seam_scope *s, bool count_allocs)
{
    s->prev_backend_alloc = wtq_nw_test_backend_alloc;
    s->prev_hold_pump = wtq_nw_test_hold_pump;
    s->prev_cancel_with_owed = wtq_nw_test_cancel_with_owed;
    s->prev_conn_closes = wtq_nw_test_conn_closes;
    s->prev_completion_first = wtq_nw_test_phase_completion_first;
    s->prev_retire_first = wtq_nw_test_phase_retire_first;
    s->prev_nw_profile = g_nw_profile;
    s->prev_nw_origin = g_nw_origin;
    if (count_allocs) {
        cnt_reset();
        wtq_nw_test_backend_alloc = &g_cnt_vtable;
    }
}

static void seam_restore(struct seam_scope *s)
{
    wtq_nw_test_backend_alloc = s->prev_backend_alloc;
    wtq_nw_test_hold_pump = s->prev_hold_pump;
    wtq_nw_test_cancel_with_owed = s->prev_cancel_with_owed;
    wtq_nw_test_conn_closes = s->prev_conn_closes;
    wtq_nw_test_phase_completion_first = s->prev_completion_first;
    wtq_nw_test_phase_retire_first = s->prev_retire_first;
    g_nw_profile = s->prev_nw_profile;
    g_nw_origin = s->prev_nw_origin;
}

/* Assert the counting oracle is fully balanced: BOTH the object count and
 * the byte total, plus zero accounting errors. */
static int cnt_assert_balanced(const char *what)
{
    pthread_mutex_lock(&g_cnt.mu);
    const int live = g_cnt.live;
    const size_t bytes = g_cnt.live_bytes;
    const int errs = g_cnt.errors;
    pthread_mutex_unlock(&g_cnt.mu);
    if (live != 0 || bytes != 0 || errs != 0) {
        fprintf(stderr,
                "FAIL: %s: allocation not balanced: live=%d bytes=%zu "
                "errors=%d\n", what, live, bytes, errs);
        return 1;
    }
    return 0;
}

/* Fired from the REAL batch_on_complete(); releases the waiter. */
static void wp_sem_signal(void *ctx)
{
    dispatch_semaphore_signal((dispatch_semaphore_t)ctx);
}

/*
 * The counting oracle's own semantics, asserted directly
 * rather than described in prose. Each transition is checked against the
 * documented test semantics above.
 */
static int t_cnt_allocator_semantics(void)
{
    int failures = 0;
    int live; size_t bytes; int errs;

    cnt_reset();
    /* alloc charges once */
    void *a = cnt_alloc(100, NULL);
    WTQ_TEST_CHECK(a != NULL);
    pthread_mutex_lock(&g_cnt.mu);
    live = g_cnt.live; bytes = g_cnt.live_bytes;
    pthread_mutex_unlock(&g_cnt.mu);
    WTQ_TEST_CHECK_EQ_INT(live, 1);
    WTQ_TEST_CHECK_EQ_SIZE(bytes, 100u);

    /* realloc(NULL, n) == alloc(n) */
    void *b = cnt_realloc(NULL, 0, 50, NULL);
    WTQ_TEST_CHECK(b != NULL);
    pthread_mutex_lock(&g_cnt.mu);
    live = g_cnt.live; bytes = g_cnt.live_bytes;
    pthread_mutex_unlock(&g_cnt.mu);
    WTQ_TEST_CHECK_EQ_INT(live, 2);
    WTQ_TEST_CHECK_EQ_SIZE(bytes, 150u);

    /* grow: old size released, new size charged, count unchanged */
    a = cnt_realloc(a, 100, 200, NULL);
    WTQ_TEST_CHECK(a != NULL);
    pthread_mutex_lock(&g_cnt.mu);
    live = g_cnt.live; bytes = g_cnt.live_bytes;
    pthread_mutex_unlock(&g_cnt.mu);
    WTQ_TEST_CHECK_EQ_INT(live, 2);
    WTQ_TEST_CHECK_EQ_SIZE(bytes, 250u);

    /* realloc(p, 0): the block STAYS LIVE, re-charged to zero bytes, and
     * libc realloc is never consulted -- so a NULL return can never be
     * confused with a failure. */
    void *b0 = cnt_realloc(b, 50, 0, NULL);
    WTQ_TEST_CHECK(b0 == b); /* same block, deterministically */
    pthread_mutex_lock(&g_cnt.mu);
    live = g_cnt.live; bytes = g_cnt.live_bytes; errs = g_cnt.errors;
    pthread_mutex_unlock(&g_cnt.mu);
    WTQ_TEST_CHECK_EQ_INT(live, 2);       /* still live */
    WTQ_TEST_CHECK_EQ_SIZE(bytes, 200u);  /* only `a` is charged now */
    WTQ_TEST_CHECK_EQ_INT(errs, 0);

    /* underflow is REPORTED, never wrapped */
    cnt_free(a, 999999, NULL);
    pthread_mutex_lock(&g_cnt.mu);
    bytes = g_cnt.live_bytes; errs = g_cnt.errors;
    pthread_mutex_unlock(&g_cnt.mu);
    WTQ_TEST_CHECK_EQ_SIZE(bytes, 0u);
    WTQ_TEST_CHECK_EQ_INT(errs, 1);

    cnt_free(b0, 0, NULL);
    cnt_reset();
    return failures;
}

/*
 * Deterministic oracle for orderly-terminal truncation.
 *
 * The defect: wtq_session_close enqueues the close wire unit (H3 DATA
 * header, then CLOSE_WEBTRANSPORT_SESSION capsule + FIN) and publishes the
 * local clean terminal synchronously. Any Network callback that then runs
 * nw_leave_and_poll sees session state CLOSED and, before the fix, called
 * op_conn_close immediately -- cancelling the CONNECT stream while those
 * accepted bytes were still owed. The peer had already received the DATA
 * frame header, so it saw a TRUNCATED frame and raised H3_FRAME_ERROR.
 *
 * The oracle is ORDERING AND STATE, never elapsed time:
 *   wtq_nw_test_cancel_with_owed counts every transport cancel issued
 *   while accepted engine bytes were still queued or in flight. An
 *   orderly terminal must never contribute to it.
 *
 * The hold gate pins the failing boundary deterministically: accepted
 * bytes stay QUEUED (owed, unissued) while the post-terminal poll runs.
 */
static int t_close_flush_ordering(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv, cl;
    wtq_msquic_listener_t *l = NULL;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    sv.echo_streams = true;
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    const uint16_t port = wtq_msquic_listener_port(l);

    side_init(&cl);
    cl.echo_streams = false;
    wtq_nw_test_cancel_with_owed = 0;
    /* every session/engine allocation for this row goes through the
     * counting allocator, installed through the SCOPED seam so that even
     * an environmental setup failure restores it before its storage dies */
    struct seam_scope scope;
    seam_install(&scope, true);
    if (!nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0,
                                   &g_cnt_vtable, NW_TEST_ORIGIN, &drv,
                                   &cs) ||
        cs == NULL || drv == NULL) {
        seam_restore(&scope);            /* single-exit discipline */
        side_destroy(&cl);
        wtq_msquic_listener_stop(l);
        side_destroy(&sv);
        return failures + 1;
    }

    /* HOLD accepted sends in the queue, then close. The close wire unit
     * is accepted by the driver and stays owed. */
    __block int owed_at_close = 0;
    __block int started_at_close = 0;
    __block int cancels_owed = 0;
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_hold_pump = 1;
      (void)wtq_session_close(cs, 0, NULL, 0);
      /* accepted close bytes are owed to the transport right now */
      for (struct wtq_dstream *ds = drv->streams; ds != NULL;
           ds = ds->next)
          if (ds->conn != NULL && !ds->terminal && !ds->cancel_issued &&
              (ds->pending_sends != NULL || ds->send_inflight))
              owed_at_close++;
      /* drive an otherwise legitimate post-terminal poll: exactly what a
       * stray Network callback does after the local terminal fired */
      nw_poll_after_balanced_test_callback(drv);
      started_at_close = (int)drv->shutdown_started;
      cancels_owed = wtq_nw_test_cancel_with_owed;
      wtq_nw_test_hold_pump = 0;
    });

    /* the local clean terminal is synchronous and exactly once */
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    WTQ_TEST_CHECK(cl.closed_clean);
    pthread_mutex_unlock(&cl.mu);

    /* the boundary really was the failing one: bytes WERE owed */
    WTQ_TEST_CHECK(owed_at_close > 0);
    /* THE ORACLE: the post-terminal poll must not have cancelled the
     * transport while those bytes were owed */
    WTQ_TEST_CHECK_EQ_INT(started_at_close, 0);
    WTQ_TEST_CHECK_EQ_INT(cancels_owed, 0);

    /* NO STRAND: the deferred shutdown must also complete when the last
     * owed stream goes TERMINAL rather than draining -- a cancelled
     * stream may never produce another send completion, so the
     * completion-side re-poll alone would leave the connection waiting.
     * The bounded rundown below is the joiner, and it must succeed.
     *
     * Release the gate: the held bytes are issued through the ordinary
     * pump and the deferred shutdown is re-polled from the completion
     * path. The counter is NOT re-asserted after the rundown below:
     * an OWNER-REQUESTED rundown is explicitly allowed to cancel
     * outstanding sends and synthesize their completions, so it may
     * legitimately cancel with bytes owed. The load-bearing assertion is
     * the one above, at the orderly-terminal boundary. */
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *ds = drv->streams; ds != NULL;
           ds = ds->next)
          ds_pump_sends_for_test(ds);
    });
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));

    /*
     * CAUSAL LIFETIME ORACLE: after rundown and the application's final
     * release, the session must actually have been DESTROYED, so every
     * allocation made through the counting allocator must be freed. A
     * corrupted callback bracket (an unmatched session leave) drives
     * cb_depth negative, session_unref can then never destroy the
     * session, and its allocations stay live -- which fails here.
     */
    wtq_session_release(cs);
    cs = NULL;
    seam_restore(&scope);
    failures += cnt_assert_balanced("close-flush lifetime");

    side_destroy(&cl);
    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

/*
 * The fix is NOT D02-specific, so the strict clean-close oracle is also
 * run for the CURRENT profile over the same real transports: a real
 * Network.framework client to a real managed MsQuic listener, one
 * attempt, no retries. The peer must observe exactly one clean terminal
 * with the exact code and no H3/QUIC error.
 */
/*
 * An engine-fatal condition while ordinary sends are
 * known owed must still shut the connection down IMMEDIATELY, with the
 * first-causal H3 code preserved. The orderly flush gate must NOT apply to
 * it -- a protocol error must never wait behind ordinary traffic.
 *
 * Driven causally, not asserted from branch order: a real malformed H3
 * frame is fed into the CONNECT stream's engine context through the
 * production receive SPI, inside a correctly balanced session bracket.
 */
static int t_fatal_shutdown_with_owed_sends(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv, cl;
    wtq_msquic_listener_t *l = NULL;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    side_init(&cl);
    cl.echo_streams = false;
    if (!nw_client_up_ready_origin(&cl, wtq_msquic_listener_port(l), "/nw",
                                   NULL, 0, NULL, NW_TEST_ORIGIN, &drv,
                                   &cs) ||
        cs == NULL || drv == NULL) {
        side_destroy(&cl);
        wtq_msquic_listener_stop(l);
        side_destroy(&sv);
        return failures + 1;
    }

    __block int owed = 0;
    __block int started = 0;
    __block uint64_t code = 0;
    __block int closed_flag = 0;
    __block wtq_stream_t *data_st = NULL;
    __block struct wtq_dstream *sess = NULL;

    /* (a) open an ordinary data stream and send once, so the stream
     *     reaches ready_processed on a real transport. Also capture the
     *     CONNECT stream now, before any other stream exists. */
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->ectx != NULL && ds->is_local && ds->is_bidi)
              sess = ds; /* oldest local bidi == the CONNECT stream */
      if (wtq_session_open_bidi(cs, &data_st) == WTQ_OK &&
          data_st != NULL) {
          static const uint8_t pay[] = "ordinary-traffic";
          wtq_span_t sp = { pay, sizeof(pay) - 1 };
          (void)wtq_stream_send(data_st, &sp, 1, 0, NULL);
      }
    });
    /* causal: the peer seeing the stream proves it is ready and flowing */
    WTQ_TEST_CHECK(side_wait_ge(&sv, &sv.streams_opened, 1));

    dispatch_sync(drv->queue, ^{
      /* (b) HOLD the pump and enqueue more ordinary traffic: it is now
       *     owed on a stream that IS ready_processed, so the orderly
       *     flush gate would genuinely apply -- which is what makes the
       *     fatal-branch mutant below load-bearing. */
      wtq_nw_test_hold_pump = 1;
      if (data_st != NULL) {
          static const uint8_t more[] = "more-ordinary-traffic";
          wtq_span_t sp2 = { more, sizeof(more) - 1 };
          (void)wtq_stream_send(data_st, &sp2, 1, 0, NULL);
      }
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->conn != NULL && !ds->terminal && !ds->cancel_issued &&
              ds->ready_processed &&
              (ds->pending_sends != NULL || ds->send_inflight))
              owed++;

      /* (c) drive a REAL engine-fatal input on the CONNECT stream through
       *     the production receive SPI, inside a balanced bracket: a DATA
       *     frame header announcing 16 bytes, one byte of body, then FIN
       *     -- a truncated frame, the engine's fatal H3_FRAME_ERROR. */
      if (sess != NULL && drv->session != NULL) {
          static const uint8_t bad[] = { 0x00, 0x10, 0xAA };
          wtq_api_session_enter(drv->session);
          wtq_conn_t *ec = wtq_api_session_conn(drv->session);
          (void)wtq_conn_on_stream_bytes(ec, sess->ectx, bad, sizeof(bad),
                                         true, 3000);
          closed_flag = (int)wtq_conn_is_closed(ec);
          code = wtq_conn_close_code(ec);
          /* (d) production's shape exactly: ONE bracket --
           *     enter -> feed engine -> leave-and-poll. The immediate
           *     shutdown is delivered by conn_fatal() calling
           *     ops.conn_close() during the feed above; this poll does NOT
           *     cause it, and is here only because production always runs
           *     it after a receive delivery. */
          nw_leave_and_poll_with_enter_held(drv);
      }
      /* (e) shutdown must have started IMMEDIATELY, despite owed bytes */
      started = (int)drv->shutdown_started;
      wtq_nw_test_hold_pump = 0;
    });

    WTQ_TEST_CHECK(owed > 0);          /* the boundary really was owed */
    WTQ_TEST_CHECK_EQ_INT(closed_flag, 1);
    /* the EXACT first-causal code is preserved, not merely "nonzero" */
    WTQ_TEST_CHECK_EQ_U64(code, UINT64_C(0x0106)); /* H3_FRAME_ERROR */
    WTQ_TEST_CHECK_EQ_INT(started, 1); /* the flush gate did NOT apply */
    fprintf(stderr, "[fatal] owed=%d code=0x%llx started=%d\n", owed,
            (unsigned long long)code, started);

    /* exactly one terminal, and rundown stays bounded */
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

/*
 * Explicit stop at the held-close boundary.
 *
 * The close wire unit is left demonstrably queued and owed, and
 * wtq_nw_conn_stop_begin() is invoked at exactly that point -- once ON the
 * driver domain and once off it -- proving that an owner-requested stop
 * OVERRIDES graceful flushing, returns without blocking, and still
 * converges: the bounded join completes, completions/disposals stay
 * exactly-once, and the allocation balance returns to baseline.
 *
 * The oracle is ordering and state. The bounded join is a watchdog against
 * a broken build, never the semantic oracle.
 */
static int t_stop_begin_with_held_close(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv, cl;
    wtq_msquic_listener_t *l = NULL;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    side_init(&cl);
    cl.echo_streams = false;
    struct seam_scope scope;
    seam_install(&scope, true);
    if (!nw_client_up_ready_origin(&cl, wtq_msquic_listener_port(l), "/nw",
                                   NULL, 0, &g_cnt_vtable, NW_TEST_ORIGIN,
                                   &drv, &cs) ||
        cs == NULL || drv == NULL) {
        seam_restore(&scope);
        side_destroy(&cl);
        wtq_msquic_listener_stop(l);
        side_destroy(&sv);
        return failures + 1;
    }

    __block int owed = 0;
    __block int on_domain_stop = 0;
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_hold_pump = 1;
      (void)wtq_session_close(cs, 0, NULL, 0);
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->conn != NULL && !ds->terminal && !ds->cancel_issued &&
              (ds->pending_sends != NULL || ds->send_inflight))
              owed++;
      /* ON-DOMAIN invocation at the held boundary */
      on_domain_stop = (int)wtq_nw_conn_stop_begin(drv->pub);
    });
    /* the close wire unit really was owed when stop was requested */
    WTQ_TEST_CHECK(owed > 0);
    WTQ_TEST_CHECK_EQ_INT(on_domain_stop, 1);
    /* the local clean terminal was still delivered synchronously */
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    WTQ_TEST_CHECK(cl.closed_clean);
    pthread_mutex_unlock(&cl.mu);
    /* OFF-DOMAIN, and idempotent: a second stop reports "already" */
    WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_conn_stop_begin(drv->pub), 0);

    /* explicit stop overrides graceful flushing: it converges even though
     * the close send is still owed and the hold is never released */
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_nw_test_hold_pump = 0;

    wtq_session_release(cs);
    cs = NULL;
    seam_restore(&scope);
    failures += cnt_assert_balanced("stop_begin lifetime");
    side_destroy(&cl);
    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

/*
 * Causal rows for the convergence properties of deferred shutdown. Each row
 * is deterministic and
 * asserts ordering/state, never elapsed time.
 */
static int t_deferred_shutdown_convergence(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv;
    wtq_msquic_listener_t *l = NULL;

    side_init(&sv);
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    const uint16_t port = wtq_msquic_listener_port(l);

    /* ROW 1: terminal with NO drainable send -> ONE immediate shutdown,
     * no deferred flag left behind. */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        side_init(&cl);
        if (nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0, NULL,
                                      NW_TEST_ORIGIN, &drv, &cs) &&
            cs != NULL && drv != NULL) {
            __block int started = 0, deferred = 0, owed = 0;
            dispatch_sync(drv->queue, ^{
              (void)wtq_session_close(cs, 0, NULL, 0);
            });
            /* let the close atom drain on its own (no hold) */
            WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
            dispatch_sync(drv->queue, ^{
              /* a SECOND poll with nothing owed must close immediately */
              nw_poll_after_balanced_test_callback(drv);
              started = (int)drv->shutdown_started;
              deferred = (int)drv->shutdown_when_flushed;
              for (struct wtq_dstream *ds = drv->streams; ds != NULL;
                   ds = ds->next)
                  if (ds->conn != NULL && !ds->terminal &&
                      !ds->cancel_issued && ds->ready_processed &&
                      (ds->pending_sends != NULL || ds->send_inflight))
                      owed++;
            });
            WTQ_TEST_CHECK_EQ_INT(owed, 0);
            WTQ_TEST_CHECK_EQ_INT(started, 1);   /* immediate */
            WTQ_TEST_CHECK_EQ_INT(deferred, 0);  /* no flag stranded */
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            wtq_session_release(cs);
        } else {
            failures++;
        }
        side_destroy(&cl);
        pthread_mutex_lock(&sv.mu);
        sv.closed = 0;
        pthread_mutex_unlock(&sv.mu);
    }

    /* ROW 2: REJECTED before establishment (unknown path, no CLOSE
     * capsule) -> converges, no deferred flag, no hang. */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        side_init(&cl);
        (void)nw_client_up_origin(&cl, port, "/wrong", NULL, 0,
                                  NW_TEST_ORIGIN, &drv, &cs);
        if (cs != NULL && drv != NULL) {
            wtq_nw_test_conn_closes = 0;
            WTQ_TEST_CHECK(side_wait(&cl, &cl.refused));
            /* DOMAIN BARRIER ONLY -- no injected poll */
            __block int deferred = 0, started = 0, owed = 0, closes_pre = 0;
            dispatch_sync(drv->queue, ^{
              deferred = (int)drv->shutdown_when_flushed;
              started = (int)drv->shutdown_started;
              owed = (int)wtq_nw_test_sends_owed(drv);
              closes_pre = wtq_nw_test_conn_closes;
            });
            pthread_mutex_lock(&cl.mu);
            /* exact refusal cardinality and status, and no other outcome */
            WTQ_TEST_CHECK_EQ_INT(cl.refused, 1);
            WTQ_TEST_CHECK_EQ_U64((uint64_t)cl.refused_status, 404u);
            WTQ_TEST_CHECK_EQ_INT(cl.established, 0);
            WTQ_TEST_CHECK_EQ_INT(cl.failed, 0);
            WTQ_TEST_CHECK_EQ_INT(cl.closed, 0);
            pthread_mutex_unlock(&cl.mu);
            /* no close capsule to flush: nothing owed, nothing deferred,
             * shutdown started immediately */
            WTQ_TEST_CHECK_EQ_INT(owed, 0);
            WTQ_TEST_CHECK_EQ_INT(deferred, 0);
            /* production converged BEFORE owner rundown: exactly one close
             * body already, and rundown must not add another */
            WTQ_TEST_CHECK_EQ_INT(started, 1);
            WTQ_TEST_CHECK_EQ_INT(closes_pre, 1);
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_conn_closes, 1);
            wtq_session_release(cs);
        } else {
            failures++;
        }
        side_destroy(&cl);
    }

    /* The not-ready exception, with exact stream
     * identity and an exact disposition proof.
     *
     * Both streams are captured by IDENTITY (the fresh application dstream
     * and the CONNECT dstream), not "any ready drainable stream". The
     * not-ready send carries a unique cookie, and the row proves it
     * receives EXACTLY ONE CANCELED completion during teardown and never a
     * successful one.
     */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        static const uint8_t NRPAY[] = "not-ready-queue";
        static int nr_cookie_obj; /* unique cookie identity */

        side_init(&cl);
        if (nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0, NULL,
                                      NW_TEST_ORIGIN, &drv, &cs) &&
            cs != NULL && drv != NULL) {
            struct seam_scope sc3;
            seam_install(&sc3, false);
            pthread_mutex_lock(&cl.mu);
            cl.nr_cookie = &nr_cookie_obj;
            pthread_mutex_unlock(&cl.mu);

            __block struct wtq_dstream *connect_ds = NULL;
            __block struct wtq_dstream *fresh_ds = NULL;
            __block wtq_stream_t *fresh_st = NULL;
            __block int fresh_drainable = 0, owed_before_close = 0;
            __block int connect_drainable = 0, deferred = 0, started = 0;
            __block int send_rc = -1;

            dispatch_sync(drv->queue, ^{
              wtq_nw_test_hold_pump = 1;
              /* EXACT CONNECT stream identity, captured before any other
               * stream exists */
              for (struct wtq_dstream *ds = drv->streams; ds != NULL;
                   ds = ds->next)
                  if (ds->ectx != NULL && ds->is_local && ds->is_bidi)
                      connect_ds = ds;
              /* a FRESH application stream, opened and written in the same
               * domain turn, so it cannot be ready_processed */
              if (wtq_session_open_bidi(cs, &fresh_st) == WTQ_OK &&
                  fresh_st != NULL) {
                  wtq_span_t sp = { NRPAY, sizeof(NRPAY) - 1 };
                  send_rc = (int)wtq_stream_send(fresh_st, &sp, 1, 0,
                                                 &nr_cookie_obj);
                  for (struct wtq_dstream *ds = drv->streams; ds != NULL;
                       ds = ds->next)
                      if (ds != connect_ds && ds->pending_sends != NULL &&
                          !ds->ready_processed)
                          fresh_ds = ds; /* EXACT fresh stream identity */
              }
              /* (i) production says the FRESH stream is not drainable */
              if (fresh_ds != NULL)
                  fresh_drainable =
                      (int)wtq_nw_test_stream_drainable(fresh_ds);
              owed_before_close = (int)wtq_nw_test_sends_owed(drv);

              /* (ii) the CONNECT stream carrying the close atom IS */
              (void)wtq_session_close(cs, 0, NULL, 0);
              if (connect_ds != NULL)
                  connect_drainable =
                      (int)wtq_nw_test_stream_drainable(connect_ds);
              nw_poll_after_balanced_test_callback(drv);
              deferred = (int)drv->shutdown_when_flushed;
              started = (int)drv->shutdown_started;
              wtq_nw_test_hold_pump = 0;
            });

            WTQ_TEST_CHECK(connect_ds != NULL);
            WTQ_TEST_CHECK(fresh_ds != NULL);
            WTQ_TEST_CHECK(connect_ds != fresh_ds);
            WTQ_TEST_CHECK_EQ_INT(send_rc, (int)WTQ_OK);
            /* (i) the fresh not-ready queue is NOT drainable, and with only
             * it outstanding production sees nothing owed */
            WTQ_TEST_CHECK_EQ_INT(fresh_drainable, 0);
            WTQ_TEST_CHECK_EQ_INT(owed_before_close, 0);
            /* (ii) the ready CONNECT stream IS drainable, and the
             * connection defers rather than cancelling over it */
            WTQ_TEST_CHECK_EQ_INT(connect_drainable, 1);
            WTQ_TEST_CHECK_EQ_INT(deferred, 1);
            WTQ_TEST_CHECK_EQ_INT(started, 0);

            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            /* the not-ready accepted send is INTENTIONALLY cancelled:
             * exactly one completion, canceled, never successful */
            pthread_mutex_lock(&cl.mu);
            const int nrc = cl.nr_completions, nrx = cl.nr_canceled;
            const int nrs = cl.nr_success;
            cl.nr_cookie = NULL;
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(nrc, 1);
            WTQ_TEST_CHECK_EQ_INT(nrx, 1);
            WTQ_TEST_CHECK_EQ_INT(nrs, 0);
            /* every public stream handle is released explicitly */
            if (fresh_st != NULL)
                wtq_stream_release(fresh_st);
            seam_restore(&sc3);
            wtq_session_release(cs);
        } else {
            failures++;
        }
        side_destroy(&cl);
    }

    /* Two real transport submissions on the exact
     * CONNECT stream, each watched BY BATCH IDENTITY, with the graceful
     * close proven BEFORE any owner rundown.
     *
     * The watch is keyed to the exact batch and lives on the driver, so an
     * unrelated completion cannot satisfy it, and it is disarmed
     * unconditionally on the domain on every path -- including the
     * watchdog path -- before its semaphore is released.
     */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        side_init(&cl);
        if (nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0, NULL,
                                      NW_TEST_ORIGIN, &drv, &cs) &&
            cs != NULL && drv != NULL) {
            struct seam_scope sc4;
            seam_install(&sc4, false);
            wtq_nw_test_conn_closes = 0;

            dispatch_semaphore_t done = dispatch_semaphore_create(0);
            __block struct wtq_dstream *sess4 = NULL;
            __block void *b1 = NULL, *b2 = NULL;
            __block int pre_pending = 0, pre_inflight = 0, pre_batches = 0;
            __block int n_connect = 0;
            __block int drain_rc = -1, close_rc = -1;
            __block int b1_inflight = 0, b1_batches = 0, close_pending = 0;

            /* (1) the CONNECT stream is UNIQUE and completely idle */
            dispatch_sync(drv->queue, ^{
              for (struct wtq_dstream *ds = drv->streams; ds != NULL;
                   ds = ds->next)
                  if (ds->ectx != NULL && ds->is_local && ds->is_bidi) {
                      sess4 = ds;
                      n_connect++;
                  }
              if (sess4 != NULL) {
                  pre_pending = sess4->pending_sends != NULL;
                  pre_inflight = (int)sess4->send_inflight;
                  pre_batches = sess4->batches_live;
              }
            });
            WTQ_TEST_CHECK_EQ_INT(n_connect, 1);
            WTQ_TEST_CHECK(sess4 != NULL);
            WTQ_TEST_CHECK_EQ_INT(pre_pending, 0);
            WTQ_TEST_CHECK_EQ_INT(pre_inflight, 0);
            WTQ_TEST_CHECK_EQ_INT(pre_batches, 0);

            /* (2-3) DRAIN alone becomes batch 1; the hold then keeps the
             *       CLOSE atom pending as a DISTINCT batch behind it */
            dispatch_sync(drv->queue, ^{
              drain_rc = (int)wtq_session_drain(cs);
              b1 = wtq_nw_test_stream_live_batch(sess4);
              b1_inflight = (int)sess4->send_inflight;
              b1_batches = sess4->batches_live;
              /* (4) watch BATCH 1 BY IDENTITY before anything can complete */
              wtq_nw_test_watch_arm(drv, b1, wp_sem_signal, (void *)done);
              wtq_nw_test_hold_pump = 1;
              close_rc = (int)wtq_session_close(cs, 0, NULL, 0);
              close_pending = sess4->pending_sends != NULL;
              nw_poll_after_balanced_test_callback(drv);
            });
            WTQ_TEST_CHECK_EQ_INT(drain_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(close_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK(b1 != NULL);
            /*
             * The DRAIN/CLOSE discriminator is TEMPORAL IDENTITY plus
             * queue state, NOT record count: both are engine sends with no
             * application record, so nrecs cannot tell them apart.
             * Batch 1 exists and is in flight with the live count at 1
             * BEFORE the close is enqueued; the close then appears as a
             * pending record behind it, and batch 2 is a distinct identity.
             */
            WTQ_TEST_CHECK_EQ_INT(b1_inflight, 1);   /* in flight */
            WTQ_TEST_CHECK_EQ_INT(b1_batches, 1);    /* exactly one live */
            WTQ_TEST_CHECK_EQ_INT(close_pending, 1); /* queued behind it */

            /* wait for BATCH 1's real completion; disarm unconditionally */
            struct timespec dl;
            clock_gettime(CLOCK_REALTIME, &dl);
            dl.tv_sec += WAIT_MS / 1000;
            const bool got1 =
                dispatch_semaphore_wait(done,
                                        dispatch_walltime(&dl, 0)) == 0;
            __block int hits1 = 0, canceled1 = 0;
            dispatch_sync(drv->queue, ^{
              hits1 = wtq_nw_test_watch_disarm(drv); /* ALWAYS */
              canceled1 = (int)wtq_nw_test_watch_was_canceled(drv);
            });
            WTQ_TEST_CHECK(got1);
            WTQ_TEST_CHECK_EQ_INT(hits1, 1);      /* the TARGET completed */
            WTQ_TEST_CHECK_EQ_INT(canceled1, 0);  /* non-canceled */

            /* post-batch-1 boundary, before ANY owner rundown */
            __block int owed_now = 0, deferred_now = 0;
            __block int started_now = 0, closes_now = 0, still_pending = 0;
            dispatch_sync(drv->queue, ^{
              owed_now = (int)wtq_nw_test_sends_owed(drv);
              deferred_now = (int)drv->shutdown_when_flushed;
              started_now = (int)drv->shutdown_started;
              closes_now = wtq_nw_test_conn_closes;
              still_pending = sess4->pending_sends != NULL;
            });
            WTQ_TEST_CHECK_EQ_INT(still_pending, 1);
            WTQ_TEST_CHECK_EQ_INT(owed_now, 1);
            WTQ_TEST_CHECK_EQ_INT(deferred_now, 1);
            WTQ_TEST_CHECK_EQ_INT(started_now, 0);
            WTQ_TEST_CHECK_EQ_INT(closes_now, 0);

            /* (5) release: CLOSE issues as batch 2; watch IT by identity */
            dispatch_sync(drv->queue, ^{
              wtq_nw_test_hold_pump = 0;
              ds_pump_sends_for_test(sess4);
              b2 = wtq_nw_test_stream_live_batch(sess4);
              if (b2 != NULL)
                  wtq_nw_test_watch_arm(drv, b2, wp_sem_signal,
                                        (void *)done);
            });
            WTQ_TEST_CHECK(b2 != NULL);
            WTQ_TEST_CHECK(b2 != b1); /* a genuinely DISTINCT submission */
            clock_gettime(CLOCK_REALTIME, &dl);
            dl.tv_sec += WAIT_MS / 1000;
            const bool got2 =
                dispatch_semaphore_wait(done,
                                        dispatch_walltime(&dl, 0)) == 0;
            __block int hits2 = 0, canceled2 = 0;
            __block int started_end = 0, deferred_end = 0, closes_end = 0;
            dispatch_sync(drv->queue, ^{
              hits2 = wtq_nw_test_watch_disarm(drv); /* ALWAYS */
              canceled2 = (int)wtq_nw_test_watch_was_canceled(drv);
              started_end = (int)drv->shutdown_started;
              deferred_end = (int)drv->shutdown_when_flushed;
              closes_end = wtq_nw_test_conn_closes;
            });
            WTQ_TEST_CHECK(got2);
            WTQ_TEST_CHECK_EQ_INT(hits2, 1);
            WTQ_TEST_CHECK_EQ_INT(canceled2, 0); /* completed naturally */
            /* THE graceful close, proven BEFORE owner rundown */
            WTQ_TEST_CHECK_EQ_INT(started_end, 1);
            WTQ_TEST_CHECK_EQ_INT(deferred_end, 0);
            WTQ_TEST_CHECK_EQ_INT(closes_end, 1);

            /* (6) owner rundown must not add another close body */
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_conn_closes, 1);
            dispatch_release(done);
            seam_restore(&sc4);
            wtq_session_release(cs);
        } else {
            failures++;
        }
        side_destroy(&cl);
    }

    /* ROW 5: a stream goes TERMINAL while graceful shutdown is deferred
     * -> the connection still converges (no strand). */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        side_init(&cl);
        if (nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0, NULL,
                                      NW_TEST_ORIGIN, &drv, &cs) &&
            cs != NULL && drv != NULL) {
            __block int deferred = 0;
            dispatch_sync(drv->queue, ^{
              wtq_nw_test_hold_pump = 1;
              (void)wtq_session_close(cs, 0, NULL, 0);
              nw_poll_after_balanced_test_callback(drv);
              deferred = (int)drv->shutdown_when_flushed;
            });
            WTQ_TEST_CHECK_EQ_INT(deferred, 1); /* really deferred */
            /* never release the hold: the owner-requested rundown must
             * still converge, driving the owed stream terminal */
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            wtq_nw_test_hold_pump = 0;
            wtq_session_release(cs);
        } else {
            failures++;
        }
        side_destroy(&cl);
    }

    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

/*
 * A real establishment failure, with the seams installed,
 * must be observed as a failure, must clean up exactly once, and must leave
 * no process-global state or allocation behind.
 *
 * The failure is deterministic and supported: the listener offers ONLY the
 * D02 profile while the client requests CURRENT, so peer SETTINGS carry no
 * mutually supported profile and the session fails NO_WT_SUPPORT. No port
 * races, no fault seam, and an exact expected outcome.
 *
 * Non-default SENTINELS are seeded into every scoped global before entry so
 * restoration is proved against real prior values, not assumed zeros.
 */
static int t_setup_failure_restores_seams(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv;
    wtq_msquic_listener_t *l = NULL;

    /* SAVE the real outer state first, so the sentinels below are restored
     * to what actually existed on entry -- never to a presumed default. */
    struct seam_scope outer;
    seam_install(&outer, false);

    side_init(&sv);
    /* D02-ONLY listener: a CURRENT client cannot establish against it */
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(
            env, &sv, WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT,
            &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        seam_restore(&outer);
        return failures + 1;
    }
    const uint16_t port = wtq_msquic_listener_port(l);

    /* seed non-default sentinels INSIDE the outer scope */
    static const wtq_alloc_t sentinel_vtable = { NULL, cnt_alloc,
                                                 cnt_realloc, cnt_free };
    wtq_nw_test_backend_alloc = &sentinel_vtable;
    wtq_nw_test_hold_pump = 7;
    wtq_nw_test_cancel_with_owed = 11;
    wtq_nw_test_conn_closes = 13;
    wtq_nw_test_phase_completion_first = 17;
    wtq_nw_test_phase_retire_first = 19;
    g_nw_profile = 23u;
    g_nw_origin = "sentinel-origin";

    /* ---- the REAL false-return branch of the shared setup helper ---- */
    {
        struct side bad;
        struct wtq_driver *bdrv = (struct wtq_driver *)1; /* poisoned */
        wtq_session_t *bcs = (wtq_session_t *)1;          /* poisoned */
        struct nw_setup_outcome oc;
        struct seam_scope scope;

        side_init(&bad);
        seam_install(&scope, true);   /* installs the counting allocator */
        wtq_nw_test_hold_pump = 0;
        g_nw_profile = (uint32_t)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT;
        g_nw_origin = NULL;

        /* THE SAME helper the successful rows use, on its FALSE branch */
        const bool up = nw_client_up_ready_ex(&bad, port, "/nw", NULL, 0,
                                              &g_cnt_vtable, g_nw_origin,
                                              &bdrv, &bcs, &oc);
        WTQ_TEST_CHECK(!up);                      /* false return */
        /* it returned false only AFTER observing the exact failure */
        WTQ_TEST_CHECK(oc.observed);
        WTQ_TEST_CHECK_EQ_INT(oc.failed, 1);
        WTQ_TEST_CHECK_EQ_INT(oc.failed_why,
                              (int)WTQ_CONNECT_FAILURE_NO_WT_SUPPORT);
        WTQ_TEST_CHECK_EQ_INT(oc.established, 0);
        /* helper-owned cleanup ran exactly once and its bounded result
         * was CHECKED, not discarded */
        WTQ_TEST_CHECK(oc.cleanup_ran);
        WTQ_TEST_CHECK(oc.rundown_ok);
        /* the returned handles are unusable after helper cleanup */
        WTQ_TEST_CHECK(bdrv == NULL);
        WTQ_TEST_CHECK(bcs == NULL);
        /* balance asserted BEFORE any later reset can erase evidence */
        failures += cnt_assert_balanced("setup-failure lifetime");
        seam_restore(&scope);
        side_destroy(&bad);
    }

    /* ---- the UNFINISHED-RUNDOWN path, exercised deterministically ---- */
    {
        struct side bad2;
        struct wtq_driver *b2drv = (struct wtq_driver *)1;
        wtq_session_t *b2cs = (wtq_session_t *)1;
        struct nw_setup_outcome oc2;
        struct seam_scope sc2;

        side_init(&bad2);
        seam_install(&sc2, false);
        g_nw_profile = (uint32_t)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT;
        g_nw_origin = NULL;
        /* force the leak-safe false return exactly once */
        wtq_nw_test_force_rundown_false = 1;
        const bool up2 = nw_client_up_ready_ex(&bad2, port, "/nw", NULL, 0,
                                               NULL, g_nw_origin, &b2drv,
                                               &b2cs, &oc2);
        WTQ_TEST_CHECK(!up2);
        WTQ_TEST_CHECK(oc2.cleanup_ran);
        /*
         * THE SAFETY PROPERTY: rundown did not complete, so the helper
         * must report retention and must NOT have released the session.
         * The caller therefore keeps `bad2` alive -- it is deliberately
         * NOT destroyed below -- so no late callback can reach freed
         * caller-owned state. The seam is consumed one-shot, so the
         * ordinary rows are unaffected.
         */
        WTQ_TEST_CHECK(!oc2.rundown_ok);
        WTQ_TEST_CHECK(oc2.retained);
        WTQ_TEST_CHECK_EQ_INT((int)wtq_nw_test_force_rundown_false, 0);
        seam_restore(&sc2);
        /* deliberately NOT side_destroy(&bad2): retained by contract */
    }

    /* every scoped seam is restored to the SENTINELS by that branch */
    WTQ_TEST_CHECK(wtq_nw_test_backend_alloc == &sentinel_vtable);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_hold_pump, 7);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_cancel_with_owed, 11);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_conn_closes, 13);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_phase_completion_first, 17);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_phase_retire_first, 19);
    WTQ_TEST_CHECK_EQ_U64((uint64_t)g_nw_profile, 23u);
    WTQ_TEST_CHECK(g_nw_origin != NULL &&
                   strcmp(g_nw_origin, "sentinel-origin") == 0);

    /* ---- the SUCCESS path uses the same framework ---- */
    wtq_nw_test_backend_alloc = NULL;
    wtq_nw_test_hold_pump = 0;
    g_nw_profile = 0;
    g_nw_origin = NULL;
    {
        struct side sv2, ok;
        wtq_msquic_listener_t *l2 = NULL;
        struct wtq_driver *odrv = NULL;
        wtq_session_t *ocs = NULL;
        struct nw_setup_outcome oc2;
        struct seam_scope sc2;

        side_init(&sv2);
        if (listener_up_profiles(env, &sv2, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                 &l2) == WTQ_OK && l2 != NULL) {
            side_init(&ok);
            ok.echo_streams = false;
            seam_install(&sc2, true);
            if (nw_client_up_ready_ex(&ok, wtq_msquic_listener_port(l2),
                                      "/nw", NULL, 0, &g_cnt_vtable,
                                      NW_TEST_ORIGIN, &odrv, &ocs, &oc2) &&
                ocs != NULL && odrv != NULL) {
                WTQ_TEST_CHECK(oc2.observed);
                WTQ_TEST_CHECK_EQ_INT(oc2.established, 1);
                WTQ_TEST_CHECK_EQ_INT(oc2.failed, 0);
                WTQ_TEST_CHECK(!oc2.cleanup_ran); /* success: no cleanup */
                WTQ_TEST_CHECK_EQ_INT((int)dom_close(odrv, ocs, 0),
                                      (int)WTQ_OK);
                WTQ_TEST_CHECK(side_wait(&ok, &ok.closed));
                WTQ_TEST_CHECK(
                    wtq_nw_conn_rundown_internal(odrv, WAIT_MS));
                wtq_session_release(ocs);
            } else {
                failures++;
            }
            seam_restore(&sc2);
            failures += cnt_assert_balanced("setup-success lifetime");
            side_destroy(&ok);
            wtq_msquic_listener_stop(l2);
        } else {
            failures++;
        }
        side_destroy(&sv2);
    }

    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    /* restore the ORIGINAL pre-sentinel outer state exactly */
    seam_restore(&outer);
    return failures;
}

static int t_watch_keying_and_lifetime(wtq_msquic_env_t *env, uint16_t port,
                                       struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static int foreign_key;
    static int cookie_a, cookie_b, cookie_b2;

    (void)env;
    side_init(&cl);
    struct seam_scope sc;
    seam_install(&sc, true);       /* counting allocator, pre-construction */
    if (!nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0,
                                   &g_cnt_vtable, NW_TEST_ORIGIN, &drv,
                                   &cs) ||
        cs == NULL || drv == NULL) {
        seam_restore(&sc);
        side_destroy(&cl);
        return failures + 1;
    }

    pthread_mutex_lock(&cl.mu);
    cl.nr_cookie = &cookie_a;
    cl.k2_cookie = &cookie_b;
    cl.k3_cookie = &cookie_b2;   /* the SECOND replacement batch */
    pthread_mutex_unlock(&cl.mu);
    pthread_mutex_lock(&sv->mu);
    const int opened0 = sv->streams_opened;
    pthread_mutex_unlock(&sv->mu);

    /* a ready application stream */
    __block wtq_stream_t *ast = NULL;
    dispatch_sync(drv->queue, ^{
      if (wtq_session_open_bidi(cs, &ast) == WTQ_OK && ast != NULL) {
          static const uint8_t p0[] = "make-ready";
          wtq_span_t s0 = { p0, sizeof(p0) - 1 };
          (void)wtq_stream_send(ast, &s0, 1, 0, NULL);
      }
    });
    WTQ_TEST_CHECK(ast != NULL);
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->streams_opened, opened0 + 1));

    /* ---- (2a) unrelated completion AFTER arming, with a baseline ---- */
    dispatch_semaphore_t foreign_sem = dispatch_semaphore_create(0);
    __block int epoch0 = 0, send_a_rc = -1;
    dispatch_sync(drv->queue, ^{
      epoch0 = wtq_nw_test_driver_completions(drv);   /* BASELINE */
      /* a REAL context, so an unkeyed mutant genuinely signals it */
      wtq_nw_test_watch_arm(drv, &foreign_key, wp_sem_signal,
                            (void *)foreign_sem);
      static const uint8_t pa[] = "unrelated-after-arm";
      wtq_span_t sa = { pa, sizeof(pa) - 1 };
      send_a_rc = (int)wtq_stream_send(ast, &sa, 1, 0, &cookie_a);
    });
    /* CAUSAL: wait on the exact application completion, not a sleep */
    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.nr_completions, 1));
    __block int epoch1 = 0, armed1 = 0, hits1 = 0;
    dispatch_sync(drv->queue, ^{                       /* domain barrier */
      epoch1 = wtq_nw_test_driver_completions(drv);
      armed1 = (int)wtq_nw_test_watch_armed(drv);
      hits1 = wtq_nw_test_watch_hits(drv);
    });
    pthread_mutex_lock(&cl.mu);
    const int cookie_a_done = cl.nr_completions;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(send_a_rc, (int)WTQ_OK);  /* accepted */
    WTQ_TEST_CHECK_EQ_INT(cookie_a_done, 1);   /* that exact send finished */
    WTQ_TEST_CHECK(epoch1 > epoch0);           /* AFTER the baseline */
    WTQ_TEST_CHECK_EQ_INT(armed1, 1);          /* watch still armed */
    WTQ_TEST_CHECK_EQ_INT(hits1, 0);           /* and never satisfied */
    /* and its context was never signalled */
    WTQ_TEST_CHECK(dispatch_semaphore_wait(foreign_sem, DISPATCH_TIME_NOW)
                   != 0);

    /* ---- (2b) + (3): an EXACT held target, then replacement ordering ---- */
    dispatch_semaphore_t ctxsem = dispatch_semaphore_create(0);
    __block void *b1 = NULL, *b2 = NULL;
    __block struct wtq_dstream *ads = NULL;
    __block int b1_batches = 0, send_b1_rc = -1, send_b2_rc = -1;
    dispatch_sync(drv->queue, ^{
      (void)wtq_nw_test_watch_disarm(drv);   /* retire the foreign watch */
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->ectx != NULL && ds->is_local && ds->is_bidi &&
              ads == NULL)
              ads = ds;                       /* newest-first: app stream */
      if (ads != NULL && ads->ready_processed && !ads->send_inflight) {
          /* send A becomes b1, DETACHED: it cannot complete on its own */
          wtq_nw_test_detach_next(ads);
          static const uint8_t pb[] = "held-target";
          wtq_span_t sb = { pb, sizeof(pb) - 1 };
          send_b1_rc = (int)wtq_stream_send(ast, &sb, 1, 0, &cookie_b);
          b1 = wtq_nw_test_stream_live_batch(ads);
          b1_batches = ads->batches_live;
          /* the SECOND replacement batch queues BEHIND b1 and carries its
           * OWN distinct cookie, so its completion is observed
           * independently of b1's; arm detach for the next pump so the
           * replacement is also non-submitted */
          static const uint8_t pc[] = "replacement";
          wtq_span_t scv = { pc, sizeof(pc) - 1 };
          send_b2_rc = (int)wtq_stream_send(ast, &scv, 1, 0, &cookie_b2);
          wtq_nw_test_detach_next(ads);
          /* arm the watch on the EXACT held target */
          wtq_nw_test_watch_arm(drv, b1, wp_sem_signal, (void *)ctxsem);
      }
    });
    /* every prerequisite is CHECKED before any raw batch seam is used */
    WTQ_TEST_CHECK_EQ_INT(send_b1_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(send_b2_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK(b1 != NULL);
    WTQ_TEST_CHECK_EQ_INT(b1_batches, 1);
    if (b1 == NULL || send_b1_rc != (int)WTQ_OK ||
        send_b2_rc != (int)WTQ_OK) {
        /* a failed prerequisite must NEVER fall through to a raw phase
         * seam: tear down through the supported path and return */
        dispatch_sync(drv->queue, ^{ (void)wtq_nw_test_watch_disarm(drv); });
        dispatch_release(ctxsem);
        dispatch_release(foreign_sem);
        if (ast != NULL)
            wtq_stream_release(ast);
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        wtq_session_release(cs);
        seam_restore(&sc);
        side_destroy(&cl);
        return failures + 1;
    }

    /* the target CANNOT complete on its own, so the real wait must take its
     * watchdog path; use a short explicit backstop as that trigger only */
    struct timespec wdl;
    clock_gettime(CLOCK_REALTIME, &wdl);
    wdl.tv_nsec += 200 * 1000 * 1000L;
    if (wdl.tv_nsec >= 1000000000L) { wdl.tv_sec++; wdl.tv_nsec -= 1000000000L; }
    const bool signalled =
        dispatch_semaphore_wait(ctxsem, dispatch_walltime(&wdl, 0)) == 0;
    WTQ_TEST_CHECK(!signalled);   /* structurally impossible to complete */

    /* the SAME unconditional on-domain disarm the real wait uses */
    __block int hits_at_disarm = 0, epoch2 = 0;
    dispatch_sync(drv->queue, ^{
      hits_at_disarm = wtq_nw_test_watch_disarm(drv);
      epoch2 = wtq_nw_test_driver_completions(drv);
    });
    WTQ_TEST_CHECK_EQ_INT(hits_at_disarm, 0);
    /* only NOW is the context released -- after the disarm returned */
    dispatch_release(ctxsem);

    /* (3) drive b1's completion: it must install b2 */
    __block int live_is_b2 = 0, b1_phases = 0, batches_mid = 0;
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_batch_phase_one(b1, true, true);   /* completion first */
      b1_phases = wtq_nw_test_batch_phases_done(b1);
      b2 = wtq_nw_test_stream_live_batch(ads);
      live_is_b2 = (int)(b2 != NULL && b2 != b1);
      batches_mid = ads->batches_live;
    });
    WTQ_TEST_CHECK_EQ_INT(b1_phases, 1);
    WTQ_TEST_CHECK_EQ_INT(live_is_b2, 1);   /* b2 installed, distinct */
    WTQ_TEST_CHECK_EQ_INT(batches_mid, 2);  /* both batches live */

    /* b1 RETIRES: the live pointer must still be b2 */
    __block int live_still_b2 = 0, epoch3 = 0, hits_after = 0;
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_batch_phase_two(b1, true, true);   /* retire b1 */
      live_still_b2 = (int)(wtq_nw_test_stream_live_batch(ads) == b2);
      epoch3 = wtq_nw_test_driver_completions(drv);
      hits_after = wtq_nw_test_watch_hits(drv);
    });
    WTQ_TEST_CHECK_EQ_INT(live_still_b2, 1); /* retirement did NOT erase */
    /* (2b) the epoch advanced past the disarm while target hits stayed 0,
     * and nothing touched the released context */
    WTQ_TEST_CHECK(epoch3 > epoch2);
    WTQ_TEST_CHECK_EQ_INT(hits_after, 0);

    /* b2's final phase clears the slot */
    __block void *live_end = (void *)1;
    __block int batches_end = 0;
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_batch_phase_one(b2, true, true);
      wtq_nw_test_batch_phase_two(b2, true, true);
      live_end = wtq_nw_test_stream_live_batch(ads);
      batches_end = ads->batches_live;
    });
    WTQ_TEST_CHECK(live_end == NULL);
    WTQ_TEST_CHECK_EQ_INT(batches_end, 0);

    /* ALL THREE application cookies observed exactly once, each with its
     * expected disposition; B1 and B2 are driven canceled by the harness */
    pthread_mutex_lock(&cl.mu);
    const int a_done = cl.nr_completions, a_cx = cl.nr_canceled;
    const int b_done = cl.k2_completions, b_cx = cl.k2_canceled;
    const int b2_done = cl.k3_completions, b2_cx = cl.k3_canceled;
    cl.nr_cookie = NULL;
    cl.k2_cookie = NULL;
    cl.k3_cookie = NULL;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(a_done, 1);
    WTQ_TEST_CHECK_EQ_INT(a_cx, 0);    /* a real, successful send */
    WTQ_TEST_CHECK_EQ_INT(b_done, 1);
    WTQ_TEST_CHECK_EQ_INT(b_cx, 1);    /* driven canceled */
    WTQ_TEST_CHECK_EQ_INT(b2_done, 1); /* the SECOND replacement batch */
    WTQ_TEST_CHECK_EQ_INT(b2_cx, 1);
    /* STREAM-OWNED final state: no record left in use or owed, read from
     * the dstream rather than a freed batch */
    __block int rec_in_use = -1, rec_app_pending = -1, rec_unretired = -1;
    dispatch_sync(drv->queue, ^{
      rec_in_use = wtq_nw_test_stream_recs_in_use(ads);
      rec_app_pending = wtq_nw_test_stream_recs_app_pending(ads);
      rec_unretired = wtq_nw_test_stream_recs_unretired(ads);
    });
    WTQ_TEST_CHECK_EQ_INT(rec_in_use, 0);
    WTQ_TEST_CHECK_EQ_INT(rec_app_pending, 0);
    WTQ_TEST_CHECK_EQ_INT(rec_unretired, 0);

    dispatch_release(foreign_sem);
    if (ast != NULL)
        wtq_stream_release(ast);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    cs = NULL;
    seam_restore(&sc);
    failures += cnt_assert_balanced("watch/replacement lifetime");
    side_destroy(&cl);
    return failures;
}

static int t_phase_order_both(wtq_msquic_env_t *env, uint16_t port,
                              struct side *sv, bool complete_first)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    struct seam_scope sc;

    (void)env;
    side_init(&cl);
    /* the counting allocator is installed BEFORE construction, so the
     * final balance measures the objects it names */
    seam_install(&sc, true);
    if (!nw_client_up_ready_origin(&cl, port, "/nw", NULL, 0,
                                   &g_cnt_vtable, NW_TEST_ORIGIN, &drv,
                                   &cs) ||
        cs == NULL || drv == NULL) {
        seam_restore(&sc);
        side_destroy(&cl);
        return failures + 1;
    }
    wtq_nw_test_conn_closes = 0;

    __block void *hb = NULL;
    __block struct wtq_dstream *sess = NULL;
    __block int armed = 0, batches_before = 0, nrecs = 0;
    __block int target_rc = -1, close_rc = -1;

    /*
     * The detached batch must carry a real send RECORD, so it is an
     * APPLICATION send with a cookie -- the CLOSE capsule is an engine
     * send with no app cookie and therefore no record, which is why it
     * cannot be the harness batch.
     *
     * Sequence: get an app stream ready with a first real send, then mark
     * its NEXT batch detached (one-shot, consumed in the same domain turn)
     * and issue a second cookie'd send. That batch is
     * PRODUCTION-CONSTRUCTED and fully accounted but deliberately NOT
     * transport-submitted, so no real completion can race the phases
     * driven below. It is NOT an issued batch.
     */
    pthread_mutex_lock(&sv->mu);
    const int opened0 = sv->streams_opened;
    pthread_mutex_unlock(&sv->mu);
    __block wtq_stream_t *app_st = NULL;
    __block struct wtq_dstream *app_ds = NULL;
    static int ph_cookie;
    dispatch_semaphore_t ready = dispatch_semaphore_create(0);
    __block void *first_b = NULL;
    dispatch_sync(drv->queue, ^{
      if (wtq_session_open_bidi(cs, &app_st) == WTQ_OK && app_st != NULL) {
          static const uint8_t p1[] = "phase-first";
          wtq_span_t s1 = { p1, sizeof(p1) - 1 };
          (void)wtq_stream_send(app_st, &s1, 1, 0, NULL);
      }
    });
    /* CAUSAL, in two steps and with no sleeping or polling:
     *   (a) the PEER observing the stream proves it became ready and the
     *       first batch actually went out;
     *   (b) that first batch is then watched BY IDENTITY and its real
     *       completion awaited, so the pump is free to issue a SECOND
     *       batch -- ds_pump_sends() will not issue while one is in
     *       flight, which is why (a) alone is not enough. */
    WTQ_TEST_CHECK(side_wait_ge(sv, &sv->streams_opened, opened0 + 1));
    /*
     * ONE explicit selection, made once and reused for the precondition,
     * the target send, the phase callbacks and the final assertions. The
     * stream list is NEWEST-FIRST, so the newest local bidi is the
     * application stream just opened and the OLDEST is the CONNECT stream;
     * both are captured and required to differ, rather than relying on
     * traversal order at each use site.
     */
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->ectx != NULL && ds->is_local && ds->is_bidi) {
              if (app_ds == NULL)
                  app_ds = ds;   /* newest == the application stream */
              sess = ds;         /* oldest == the CONNECT stream */
          }
      if (app_ds != NULL && app_ds != sess) {
          first_b = wtq_nw_test_stream_live_batch(app_ds);
          if (first_b != NULL)
              wtq_nw_test_watch_arm(drv, first_b, wp_sem_signal,
                                    (void *)ready);
      }
    });
    WTQ_TEST_CHECK(app_ds != NULL);
    WTQ_TEST_CHECK(sess != NULL);
    WTQ_TEST_CHECK(app_ds != sess);
    if (app_ds == NULL || sess == NULL || app_ds == sess) {
        dispatch_sync(drv->queue, ^{ (void)wtq_nw_test_watch_disarm(drv); });
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        if (app_st != NULL)
            wtq_stream_release(app_st);
        wtq_session_release(cs);
        dispatch_release(ready);
        seam_restore(&sc);
        failures += cnt_assert_balanced("phase-order selection abort");
        side_destroy(&cl);
        return failures + 1;
    }
    /* The first batch's completion is a PRECONDITION for the target send,
     * so its outcome is required and recorded -- never discarded. On the
     * watchdog path the test disarms on-domain and fails rather than
     * driving a batch whose prerequisite never happened. */
    /* first_b is non-NULL only if that batch is STILL in flight; if it has
     * already completed the precondition is met without any wait. */
    bool first_ok = (first_b == NULL);
    if (first_b != NULL) {
        struct timespec rdl;
        clock_gettime(CLOCK_REALTIME, &rdl);
        rdl.tv_sec += WAIT_MS / 1000;
        first_ok =
            dispatch_semaphore_wait(ready, dispatch_walltime(&rdl, 0)) == 0;
    }
    __block int first_hits = 0, first_canceled = 0, first_idle = 0;
    dispatch_sync(drv->queue, ^{
      first_hits = wtq_nw_test_watch_hits(drv);
      first_canceled = (int)wtq_nw_test_watch_was_canceled(drv);
      (void)wtq_nw_test_watch_disarm(drv);   /* ALWAYS, on the domain */
      for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
          if (ds->ectx != NULL && ds->is_local && ds->is_bidi) {
              first_idle = (int)(ds->ready_processed && !ds->send_inflight);
              break;
          }
    });
    WTQ_TEST_CHECK(first_ok);      /* if a wait was needed, it SUCCEEDED */
    if (first_b != NULL) {
        WTQ_TEST_CHECK_EQ_INT(first_hits, 1);     /* the exact target */
        WTQ_TEST_CHECK_EQ_INT(first_canceled, 0); /* non-canceled */
    }
    /*
     * THE precondition is ready-and-idle. Under load the stream can still
     * have a batch in flight here (the pump may have issued another), so
     * this is WAITED FOR causally on the keyed watch rather than asserted
     * once -- asserting a single snapshot made this row load-dependent.
     */
    for (int guard = 0; guard < 4 && first_idle != 1; guard++) {
        __block void *pend_b = NULL;
        dispatch_sync(drv->queue, ^{
          for (struct wtq_dstream *ds = drv->streams; ds != NULL;
               ds = ds->next)
              if (ds->ectx != NULL && ds->is_local && ds->is_bidi) {
                  if (ds->send_inflight)
                      pend_b = wtq_nw_test_stream_live_batch(ds);
                  break;
              }
          if (pend_b != NULL)
              wtq_nw_test_watch_arm(drv, pend_b, wp_sem_signal,
                                    (void *)ready);
        });
        if (pend_b == NULL)
            break;                       /* nothing in flight to wait on */
        struct timespec gdl;
        clock_gettime(CLOCK_REALTIME, &gdl);
        gdl.tv_sec += WAIT_MS / 1000;
        (void)dispatch_semaphore_wait(ready, dispatch_walltime(&gdl, 0));
        dispatch_sync(drv->queue, ^{
          (void)wtq_nw_test_watch_disarm(drv);   /* ALWAYS, on the domain */
          for (struct wtq_dstream *ds = drv->streams; ds != NULL;
               ds = ds->next)
              if (ds->ectx != NULL && ds->is_local && ds->is_bidi) {
                  first_idle =
                      (int)(ds->ready_processed && !ds->send_inflight);
                  break;
              }
        });
    }
    WTQ_TEST_CHECK_EQ_INT(first_idle, 1);
    if (!first_ok || first_idle != 1) {
        /* precondition absent: take one safe cleanup path, drive nothing */
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        if (app_st != NULL)
            wtq_stream_release(app_st);
        wtq_session_release(cs);
        dispatch_release(ready);
        seam_restore(&sc);
        failures += cnt_assert_balanced("phase-order precondition abort");
        side_destroy(&cl);
        return failures + 1;
    }
    /* register the target send's OWN completion slot before delivery */
    pthread_mutex_lock(&cl.mu);
    cl.ph_slot_cookie = &ph_cookie;
    cl.ph_slot_completions = 0;
    cl.ph_slot_canceled = 0;
    pthread_mutex_unlock(&cl.mu);

    dispatch_sync(drv->queue, ^{
      if (app_ds->ready_processed) {
          wtq_nw_test_detach_next(app_ds);  /* ONE-SHOT, this turn only */
          static const uint8_t p2[] = "phase-second";
          wtq_span_t s2 = { p2, sizeof(p2) - 1 };
          target_rc = (int)wtq_stream_send(app_st, &s2, 1, 0, &ph_cookie);
          hb = wtq_nw_test_stream_live_batch(app_ds);
          if (hb != NULL)
              nrecs = wtq_nw_test_batch_nrecs(hb);
          batches_before = app_ds->batches_live;
      }
      /* the close atom arms the graceful deferral */
      close_rc = (int)wtq_session_close(cs, 0, NULL, 0);
      nw_poll_after_balanced_test_callback(drv);
      armed = (int)drv->shutdown_when_flushed;
    });
    WTQ_TEST_CHECK_EQ_INT(target_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(close_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(armed, 1);
    WTQ_TEST_CHECK(hb != NULL);
    WTQ_TEST_CHECK_EQ_INT(batches_before, 1);
    WTQ_TEST_CHECK(nrecs >= 1);
    if (hb == NULL || target_rc != (int)WTQ_OK || nrecs < 1) {
        /* a failed prerequisite must NEVER reach a raw phase seam */
        dispatch_sync(drv->queue, ^{ (void)wtq_nw_test_watch_disarm(drv); });
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        if (app_st != NULL)
            wtq_stream_release(app_st);
        wtq_session_release(cs);
        dispatch_release(ready);
        pthread_mutex_lock(&cl.mu);
        cl.ph_slot_cookie = NULL;
        pthread_mutex_unlock(&cl.mu);
        seam_restore(&sc);
        failures += cnt_assert_balanced("phase-order prerequisite abort");
        side_destroy(&cl);
        return failures + 1;
    }

    __block int mid_phases = 0, mid_batches = 0, mid_closes = 0;
    __block int mid_app = 0, mid_transport = 0, mid_live = 0;
    __block int end_batches = 0, end_closes = 0;
    __block void *end_live = (void *)1;
    dispatch_sync(drv->queue, ^{
      /* PHASE 1 in the chosen order */
      wtq_nw_test_batch_phase_one(hb, complete_first, true);
      mid_phases = wtq_nw_test_batch_phases_done(hb);
      mid_batches = app_ds->batches_live;
      mid_closes = wtq_nw_test_conn_closes;
      mid_app = (int)wtq_nw_test_batch_rec_app_done(hb, 0);
      mid_transport = (int)wtq_nw_test_batch_rec_transport_done(hb, 0);
      mid_live = (int)(wtq_nw_test_stream_live_batch(app_ds) == hb);
      /* PHASE 2 completes the pair */
      wtq_nw_test_batch_phase_two(hb, complete_first, true);
      end_batches = app_ds->batches_live;
      end_closes = wtq_nw_test_conn_closes;
      end_live = wtq_nw_test_stream_live_batch(app_ds);
    });

    /* PHASE 1: exactly one phase done, batch still live and still owned */
    WTQ_TEST_CHECK_EQ_INT(mid_phases, 1);
    WTQ_TEST_CHECK_EQ_INT(mid_batches, 1);
    WTQ_TEST_CHECK_EQ_INT(mid_live, 1);
    if (complete_first) {
        /* app completion delivered, transport not yet retired */
        WTQ_TEST_CHECK_EQ_INT(mid_app, 1);
        WTQ_TEST_CHECK_EQ_INT(mid_transport, 0);
    } else {
        /* transport retired, app completion NOT yet delivered */
        WTQ_TEST_CHECK_EQ_INT(mid_app, 0);
        WTQ_TEST_CHECK_EQ_INT(mid_transport, 1);
    }
    /* PHASE 2: batch released exactly once, no live pointer left behind */
    WTQ_TEST_CHECK_EQ_INT(end_batches, 0);
    WTQ_TEST_CHECK(end_live == NULL);
    /*
     * NOT asserted here: "exactly one deferred transport close at the
     * expected phase". A DETACHED batch is never transport-completed, so
     * it keeps this connection permanently owed and the graceful close
     * cannot fire in this construction. That property is proven exactly,
     * and before owner rundown, on the REAL path in row 4. This harness
     * proves the two-phase OWNERSHIP semantics for both callback orders,
     * which is what the real path cannot drive.
     */
    WTQ_TEST_CHECK_EQ_INT(end_closes, mid_closes);
    if (complete_first) {
        WTQ_TEST_CHECK(wtq_nw_test_phase_completion_first >= 1);
    } else {
        WTQ_TEST_CHECK(wtq_nw_test_phase_retire_first >= 1);
    }
    fprintf(stderr,
            "[phase-harness] complete_first=%d mid_phases=%d mid_app=%d "
            "mid_transport=%d mid_closes=%d end_closes=%d\n",
            (int)complete_first, mid_phases, mid_app, mid_transport,
            mid_closes, end_closes);

    /*
     * FINAL OWNERSHIP, read from the STREAM-owned record pool -- never
     * from the freed batch: no record left in use, none app-pending, none
     * unretired. Plus the target send's own callback, exactly once with
     * the expected disposition and no duplicate.
     */
    __block int ph_in_use = -1, ph_app_pending = -1, ph_unretired = -1;
    dispatch_sync(drv->queue, ^{
      ph_in_use = wtq_nw_test_stream_recs_in_use(app_ds);
      ph_app_pending = wtq_nw_test_stream_recs_app_pending(app_ds);
      ph_unretired = wtq_nw_test_stream_recs_unretired(app_ds);
    });
    WTQ_TEST_CHECK_EQ_INT(ph_in_use, 0);
    WTQ_TEST_CHECK_EQ_INT(ph_app_pending, 0);
    WTQ_TEST_CHECK_EQ_INT(ph_unretired, 0);
    pthread_mutex_lock(&cl.mu);
    const int ph_done = cl.ph_slot_completions;
    const int ph_cx = cl.ph_slot_canceled;
    cl.ph_slot_cookie = NULL;
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(ph_done, 1);   /* exactly one, no duplicate */
    WTQ_TEST_CHECK_EQ_INT(ph_cx, 1);     /* driven canceled by the harness */

    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    dispatch_release(ready);
    if (app_st != NULL)
        wtq_stream_release(app_st);
    wtq_session_release(cs);
    cs = NULL;
    seam_restore(&sc);
    /* the counting allocator was installed before construction, so this
     * measures the connection's own objects. A DETACHED batch has no real
     * transport holder, so no source-balance claim is made here; the
     * real-path source checks remain separate. */
    failures += cnt_assert_balanced("phase-order harness");
    side_destroy(&cl);
    return failures;
}

static int t_current_clean_close(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv, cl;
    wtq_msquic_listener_t *l = NULL;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    const int retries0 = g_est_retry_count;

    side_init(&sv);
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv,
                                  WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    side_init(&cl);
    cl.echo_streams = false;
    g_nw_profile = (uint32_t)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT;
    g_nw_origin = NULL;
    const bool up = nw_client_up_ready(&cl, wtq_msquic_listener_port(l),
                                       "/nw", NULL, 0, NULL, &drv, &cs);
    WTQ_TEST_CHECK(up);
    if (up && cs != NULL && drv != NULL) {
        WTQ_TEST_CHECK(side_wait_ge(&sv, &sv.established, 1));
        WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
        pthread_mutex_lock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT(cl.established, 1);
        WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
        WTQ_TEST_CHECK(cl.closed_clean);
        WTQ_TEST_CHECK_EQ_U64((uint64_t)cl.closed_code, 0u);
        WTQ_TEST_CHECK_EQ_INT(cl.failed, 0);
        WTQ_TEST_CHECK_EQ_INT(cl.refused, 0);
        pthread_mutex_unlock(&cl.mu);
        /* STRICT on the server: one CLEAN terminal, exact code, and no
         * H3/QUIC error -- the truncated-frame disposition this task
         * exists to eliminate would fail here. */
        pthread_mutex_lock(&sv.mu);
        WTQ_TEST_CHECK_EQ_INT(sv.established, 1);
        WTQ_TEST_CHECK_EQ_INT(sv.closed, 1);
        WTQ_TEST_CHECK(sv.closed_clean);
        WTQ_TEST_CHECK_EQ_U64((uint64_t)sv.closed_code, 0u);
        WTQ_TEST_CHECK_EQ_INT((int)sv.closed_err.kind,
                              (int)WTQ_ERR_KIND_NONE);
        WTQ_TEST_CHECK_EQ_INT(sv.failed, 0);
        WTQ_TEST_CHECK_EQ_INT(sv.refused, 0);
        pthread_mutex_unlock(&sv.mu);
        WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    }
    if (cs != NULL)
        wtq_session_release(cs);
    g_nw_profile = 0;
    g_nw_origin = NULL;
    /* one attempt, no retries consumed */
    WTQ_TEST_CHECK_EQ_INT(g_est_retry_count, retries0);
    side_destroy(&cl);
    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

static int t_nw_d02_profile(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side sv;
    wtq_msquic_listener_t *l = NULL;
    const int D02 =
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT;
    static const char SUB[] = "wtq-nw-test";

    /* The canonical D02 row is exactly ONE attempt: snapshot the retry
     * counter and the allowance, and assert below that neither the
     * environmental retry policy was enabled nor a retry was consumed. */
    const int retries0 = g_est_retry_count;
    const int retry_allow0 = g_est_retries;

    side_init(&sv);
    /* the SERVER echoes, so one client write proves a full round trip */
    sv.echo_streams = true;
    WTQ_TEST_CHECK_EQ_INT(
        (int)listener_up_profiles(env, &sv, WTQ_WEBTRANSPORT_PROFILES_ALL,
                                  &l),
        (int)WTQ_OK);
    if (l == NULL) {
        side_destroy(&sv);
        return failures + 1;
    }
    const uint16_t port = wtq_msquic_listener_port(l);

    /* ---- negative: D02 without an Origin fails BEFORE any effect ----- */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;

        side_init(&cl);
        g_nw_profile = (uint32_t)D02;
        g_nw_origin = NULL;
        const wtq_result_t rc =
            nw_client_up_alloc(&cl, port, "/nw", NULL, 0, NULL, NULL, &drv,
                               &cs);
        WTQ_TEST_CHECK(rc != WTQ_OK);
        WTQ_TEST_CHECK(cs == NULL);
        pthread_mutex_lock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT(cl.established, 0);
        WTQ_TEST_CHECK_EQ_INT(cl.failed, 0);
        pthread_mutex_unlock(&cl.mu);
        side_destroy(&cl);
        /* the globals are reset on EVERY exit path from this row */
        g_nw_profile = 0;
        g_nw_origin = NULL;
    }

    /* ---- positive: full D02 session across two real transports ------- */
    {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;
        static const char *const offer[] = { SUB };

        side_init(&cl);
        cl.echo_streams = false;
        g_nw_profile = (uint32_t)D02;
        g_nw_origin = "https://localhost:443";
        const bool up =
            nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs);
        WTQ_TEST_CHECK(up);
        if (up && cs != NULL && drv != NULL) {
            /* (1) exactly one establishment on BOTH sides, each with the
             *     profile sampled INSIDE its own on_established */
            WTQ_TEST_CHECK(side_wait_ge(&sv, &sv.established, 1));
            pthread_mutex_lock(&cl.mu);
            const int c_est = cl.established, c_fail = cl.failed;
            const int c_ref = cl.refused;
            const int c_rc = cl.cb_prof_rc, c_pr = cl.cb_prof;
            const size_t c_sl = cl.subproto_len;
            char c_sub[128];
            memcpy(c_sub, cl.subproto, sizeof(c_sub));
            pthread_mutex_unlock(&cl.mu);
            pthread_mutex_lock(&sv.mu);
            const int s_est = sv.established, s_fail = sv.failed;
            const int s_rc = sv.cb_prof_rc, s_pr = sv.cb_prof;
            const size_t s_sl = sv.subproto_len;
            char s_sub[128];
            memcpy(s_sub, sv.subproto, sizeof(s_sub));
            pthread_mutex_unlock(&sv.mu);

            WTQ_TEST_CHECK_EQ_INT(c_est, 1);
            WTQ_TEST_CHECK_EQ_INT(s_est, 1);
            WTQ_TEST_CHECK_EQ_INT(c_fail, 0);
            WTQ_TEST_CHECK_EQ_INT(s_fail, 0);
            WTQ_TEST_CHECK_EQ_INT(c_ref, 0);
            /* (2) callback-time profile query: D02 on BOTH sides */
            WTQ_TEST_CHECK_EQ_INT(c_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(s_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(c_pr, D02);
            WTQ_TEST_CHECK_EQ_INT(s_pr, D02);
            /* (3) exact negotiated subprotocol bytes on both sides */
            WTQ_TEST_CHECK_EQ_SIZE(c_sl, sizeof(SUB) - 1);
            WTQ_TEST_CHECK_EQ_SIZE(s_sl, sizeof(SUB) - 1);
            WTQ_TEST_CHECK(memcmp(c_sub, SUB, sizeof(SUB) - 1) == 0);
            WTQ_TEST_CHECK(memcmp(s_sub, SUB, sizeof(SUB) - 1) == 0);

            /* (4) a REAL application exchange: exact bytes out, the
             *     server's echo + FIN back, exact bytes in. On its own
             *     stream, so the cap probe's abort below cannot be
             *     mistaken for this stream's completion. */
            {
                static const uint8_t PAY[] = "d02-real-transport-payload";
                wtq_stream_t *ds = NULL;
                pthread_mutex_lock(&cl.mu);
                const int fins0 = cl.rx_fins;
                cl.rx_len = 0;
                pthread_mutex_unlock(&cl.mu);
                WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &ds),
                                      (int)WTQ_OK);
                if (ds != NULL) {
                    wtq_span_t sp = { PAY, sizeof(PAY) - 1 };
                    WTQ_TEST_CHECK_EQ_INT(
                        (int)dom_send(drv, ds, &sp, 1, WTQ_SEND_FIN, NULL),
                        (int)WTQ_OK);
                    /* causal wait for the echoed FIN, no sleep */
                    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.rx_fins,
                                                fins0 + 1));
                    pthread_mutex_lock(&cl.mu);
                    const size_t got = cl.rx_len;
                    uint8_t echo[64];
                    memcpy(echo, cl.rx,
                           got < sizeof(echo) ? got : sizeof(echo));
                    pthread_mutex_unlock(&cl.mu);
                    /* EXACT bytes crossed both transports and came back */
                    WTQ_TEST_CHECK_EQ_SIZE(got, sizeof(PAY) - 1);
                    if (got == sizeof(PAY) - 1)
                        WTQ_TEST_CHECK(memcmp(echo, PAY,
                                              sizeof(PAY) - 1) == 0);
                } else {
                    failures++;
                }
            }

            /* (5) the public post-establishment query still reports D02,
             *     and the D02 outbound cap holds over the real transport.
             *     The cap is a PRE-transport validation: 256 is refused as
             *     an invalid argument even on a backend that could not
             *     perform the operation at all. A one-sided reset/stop on
             *     a fully-open bidi is separately UNSUPPORTED on
             *     Network.framework -- a pre-existing transport limit D02
             *     neither introduces nor changes -- so the in-cap value
             *     surfaces THAT, and abort (which NW implements) carries
             *     the accepted 255. Separate stream from (4). */
            __block int f2 = 0;
            dispatch_sync(drv->queue, ^{ f2 = nw_d02_on_queue(cs); });
            failures += f2;

            /* (6) close normally; both sides observe exactly one terminal
             *     and no failure, then the client runs down cleanly. */
            WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0),
                                  (int)WTQ_OK);
            WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
            WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
            /* EXACTLY one clean terminal per peer, with the exact code,
             * and no failure or refusal anywhere on either side. */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.established, 1);
            WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
            WTQ_TEST_CHECK(cl.closed_clean);
            WTQ_TEST_CHECK_EQ_U64((uint64_t)cl.closed_code, 0u);
            WTQ_TEST_CHECK_EQ_INT(cl.failed, 0);
            WTQ_TEST_CHECK_EQ_INT(cl.refused, 0);
            pthread_mutex_unlock(&cl.mu);
            pthread_mutex_lock(&sv.mu);
            WTQ_TEST_CHECK_EQ_INT(sv.established, 1);
            WTQ_TEST_CHECK_EQ_INT(sv.closed, 1);
            WTQ_TEST_CHECK(sv.closed_clean);
            WTQ_TEST_CHECK_EQ_U64((uint64_t)sv.closed_code, 0u);
            WTQ_TEST_CHECK_EQ_INT(sv.failed, 0);
            WTQ_TEST_CHECK_EQ_INT(sv.refused, 0);
            pthread_mutex_unlock(&sv.mu);
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
        }
        if (cs != NULL)
            wtq_session_release(cs);
        side_destroy(&cl);
        g_nw_profile = 0;
        g_nw_origin = NULL;
    }

    /* ONE attempt: the retry allowance was never raised for this row and
     * no retry was consumed by it. */
    WTQ_TEST_CHECK_EQ_INT(g_est_retries, retry_allow0);
    WTQ_TEST_CHECK_EQ_INT(g_est_retries, 0);
    WTQ_TEST_CHECK_EQ_INT(g_est_retry_count, retries0);
    /* globals are already reset on every path above; assert it so a later
     * CURRENT scenario can never inherit this row's configuration. */
    WTQ_TEST_CHECK_EQ_INT((int)g_nw_profile, 0);
    WTQ_TEST_CHECK(g_nw_origin == NULL);
    wtq_msquic_listener_stop(l);
    side_destroy(&sv);
    return failures;
}

static int t_conn_loss_error(void)
{
    int failures = 0;
    struct side cl, sv2;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wtq-nw-test" };

    side_init(&cl);
    side_init(&sv2);

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env2 = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_msquic_env_open(&ecfg, &env2),
                          (int)WTQ_OK);
    if (env2 == NULL) {
        side_destroy(&cl);
        side_destroy(&sv2);
        return failures + 1;
    }
    wtq_msquic_listener_t *l2 = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)listener_up(env2, &sv2, &l2), (int)WTQ_OK);
    if (l2 == NULL) {
        wtq_msquic_env_close(env2);
        side_destroy(&cl);
        side_destroy(&sv2);
        return failures + 1;
    }

    WTQ_TEST_CHECK(nw_client_up_ready(&cl, wtq_msquic_listener_port(l2),
                                      "/nw", offer, 1, NULL, &drv, &cs));
    if (cs == NULL) {
        wtq_msquic_listener_stop(l2);
        wtq_msquic_env_close(env2);
        side_destroy(&cl);
        side_destroy(&sv2);
        return failures + 1;
    }

    /* the connection dies under the established client */
    wtq_msquic_listener_stop(l2);
    wtq_msquic_env_close(env2);

    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK(!cl.closed_clean);
    /*
     * FIRST CAUSAL error, two legitimate shapes depending on which
     * signal lands first (both observed; sanitizer timing flips it):
     *  - the NW transport error (receive failure) -> LOCAL kind with a
     *    REAL NW domain and code, quic_code 0 (NW exposes no peer close
     *    code — standing limitation, never fabricated). The dominant
     *    shape at native speed: the 20-run gate exercises this mapping
     *    repeatedly.
     *  - the engine's own protocol teardown -> QUIC_APP with the H3
     *    code the engine latched (engine-owned first-causal precedence
     *    doing its job).
     */
    WTQ_TEST_CHECK(cl.closed_err.kind == WTQ_ERR_KIND_LOCAL ||
                   cl.closed_err.kind == WTQ_ERR_KIND_QUIC_APP ||
                   cl.closed_err.kind == WTQ_ERR_KIND_NONE);
    if (cl.closed_err.kind == WTQ_ERR_KIND_LOCAL) {
        /* the NW transport error won: real domain, real code, and no
         * fabricated wire code */
        WTQ_TEST_CHECK(cl.closed_err.quic_code == 0);
        WTQ_TEST_CHECK(cl.closed_err.native_domain == WTQ_ERRDOM_NW_POSIX ||
                       cl.closed_err.native_domain == WTQ_ERRDOM_NW_DNS ||
                       cl.closed_err.native_domain == WTQ_ERRDOM_NW_TLS);
        WTQ_TEST_CHECK(cl.closed_err.native_code != 0);
    } else {
        /* an engine-observed teardown won (protocol error, or the
         * peer's orderly stream teardown sealing NONE): no NW detail
         * is fabricated onto it */
        WTQ_TEST_CHECK(cl.closed_err.native_domain == WTQ_ERRDOM_NONE);
    }
    pthread_mutex_unlock(&cl.mu);

    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    side_destroy(&sv2);
    return failures;
}

/*
 * Production concat-failure rollback (forced via the backend seam):
 * accepted gathers whose batch never issues must each complete exactly
 * once (canceled), leave zero unretired records and zero live batches,
 * and the connection must run down bounded. The failure path fails the
 * CONNECTION by contract, so this runs on a dedicated session.
 */
static int t_concat_failure(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wtq-nw-test" };
    static uint8_t payload[512];
    static int toks[4];

    (void)sv;
    side_init(&cl);
    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs));
    if (cs == NULL) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* Let the pump's first TWO concats succeed (the WT preamble plus
     * the first gather — that gather's record JOINS the batch), then
     * fail the third: the rollback now has a real target. All sends
     * queue pre-ready and coalesce in one pump. */
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &st), (int)WTQ_OK);
    dispatch_sync(drv->queue, ^{
      wtq_nw_test_concat_skip = 2;
      wtq_nw_test_force_concat_failures = 1;
    });
    int accepted = 0;
    for (int i = 0; i < 4; i++) {
        wtq_span_t sp = { payload, sizeof(payload) };
        if (dom_send(drv, st, &sp, 1, 0, &toks[i]) == WTQ_OK) {
            pthread_mutex_lock(&cl.mu);
            (void)ctx_slot(&cl, &toks[i]);
            pthread_mutex_unlock(&cl.mu);
            accepted++;
        }
    }
    WTQ_TEST_CHECK(accepted > 0);

    /* the contract: the connection FAILS, every accepted send completes
     * exactly once (canceled) */
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    int canceled_total = 0;
    for (int i = 0; i < accepted; i++) {
        int slot;
        pthread_mutex_lock(&cl.mu);
        slot = ctx_slot(&cl, &toks[i]);
        pthread_mutex_unlock(&cl.mu);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.ctx_completions[slot], 1));
        pthread_mutex_lock(&cl.mu);
        WTQ_TEST_CHECK_EQ_INT(cl.ctx_completions[slot], 1);
        canceled_total += cl.ctx_canceled[slot];
        pthread_mutex_unlock(&cl.mu);
    }
    /* exactly-once is the §3.3 contract; CANCELED-ness is timing for
     * the records the skip seam let through: at most those 2 can ride
     * an early batch that genuinely reaches the wire and completes
     * successfully before the forced failure kills the connection.
     * Everything the failure caught can only complete canceled. */
    WTQ_TEST_CHECK(canceled_total >= accepted - 2);
    WTQ_TEST_CHECK(canceled_total >= 1);

    /* zero unretired records, zero live batches, bounded rundown */
    __block int unret = 0, live = 0;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next) {
          unret += d->recs_unretired;
          live += d->batches_live;
      }
      wtq_nw_test_force_concat_failures = 0;
      wtq_nw_test_concat_skip = 0;
    });
    WTQ_TEST_CHECK_EQ_INT(unret, 0);
    WTQ_TEST_CHECK_EQ_INT(live, 0);
    __block int in_use = 0, tdone_bad = 0;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
          for (int i = 0; i < WTQ_NW_SEND_RECORDS; i++) {
              if (d->recs[i].in_use)
                  in_use++;
              if (d->recs[i].in_use && !d->recs[i].transport_done)
                  tdone_bad++;
          }
    });
    WTQ_TEST_CHECK_EQ_INT(in_use, 0);   /* every slot released */
    WTQ_TEST_CHECK_EQ_INT(tdone_bad, 0);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    return failures;
}

/* Bounded on-domain wait for the native id report (ids are ASYNC:
 * known only at NW-ready, so a known id implies ready_seen). */
static bool wait_native_id(struct wtq_driver *drv, wtq_stream_t *st,
                           uint64_t *out)
{
    for (int i = 0; i < WAIT_MS / 10; i++) {
        __block uint64_t id;
        dispatch_sync(drv->queue, ^{ id = wtq_stream_id(st); });
        if (id != WTQ_STREAM_ID_UNKNOWN) {
            *out = id;
            return true;
        }
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return false;
}

/* Bounded on-domain wait for a predicate over the backend's streams. */
static bool wait_streams(struct wtq_driver *drv,
                         bool (^pred)(struct wtq_dstream *head))
{
    for (int i = 0; i < WAIT_MS / 10; i++) {
        __block bool ok = false;
        dispatch_sync(drv->queue, ^{ ok = pred(drv->streams); });
        if (ok)
            return true;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return false;
}

/*
 * Terminal-order permutations: each case engineers a different LAST
 * gate for reap eligibility and then proves teardown stayed two-phase
 * (the end-of-main counters assert no detach/release ever ran inside a
 * callback frame, whatever order the gates closed in).
 *
 *  (a) send-retirement-last: a uni stream with a batch in flight at
 *      abort — send and abort issue in ONE domain block, so no
 *      completion can interleave; the holder disposal (TRANSPORT_
 *      RETIRED) necessarily follows the flushed completion, making
 *      RETIRE (or, if NW delivers `cancelled` after the retirement,
 *      STATE) the closing gate.
 *  (b) receive-completion vs state vs detach: a bidi with an armed
 *      receive at abort — the receive flush, the cancelled transition,
 *      and the engine's detach (the terminal input resolves the abort
 *      drain, releasing the estream) race; whichever loses closes the
 *      gate.
 *  (c) datagram-completion-last: datagram sends still in flight when
 *      the connection closes (sends + close in ONE domain block) —
 *      the dgram flow's completion/receive flush closes its reap gate
 *      after `cancelled`.
 *  (d) group-terminal-before-child-terminal: the group is cancelled
 *      directly (test SPI) over live idle streams; the children tear
 *      down FROM the group-terminal path.
 *  (Child-terminal-before-group is every other subtest's shape: the
 *   settled-abort and clean-close cases reap all streams long before
 *   rundown cancels the group.)
 */
static int t_teardown_orders(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    /* silence the server echo: streams here are torn down mid-flight by
     * design (aborts, group cancel), and NW surfaces a group-cancelled
     * stream to the peer as a clean FIN — a FIN-echo into the dying
     * session would be refused and miscounted as an ownership drop */
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }

    /* (a) retirement-last on a local uni. The engine's critical h3
     * streams are local unis too and the CONNECT stream is a local
     * bidi WITH an ectx: the only reliable discriminator is the
     * native id the engine reported for OUR handle. */
    wtq_stream_t *uni = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &uni), (int)WTQ_OK);
    __block uint64_t tid = WTQ_STREAM_ID_UNKNOWN;
    WTQ_TEST_CHECK(wait_native_id(drv, uni, &tid));
    __block struct wtq_dstream *target = NULL;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
          if (d->id == tid)
              target = d;
    });
    WTQ_TEST_CHECK(target != NULL);
    int gate_a_before = wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RETIRE] +
                        wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_STATE] +
                        wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_DETACH];
    static const uint8_t pay_a[] = "order-retire-last";
    __block wtq_result_t rc_send, rc_abort;
    dispatch_sync(drv->queue, ^{
      wtq_span_t sp = { pay_a, sizeof(pay_a) - 1 };
      rc_send = wtq_stream_send(uni, &sp, 1, 0, (void *)pay_a);
      rc_abort = wtq_stream_abort(uni, 0x51);
    });
    WTQ_TEST_CHECK_EQ_INT((int)rc_send, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)rc_abort, (int)WTQ_OK);
    WTQ_TEST_CHECK(wait_streams(drv, ^bool(struct wtq_dstream *head) {
      for (struct wtq_dstream *d = head; d != NULL; d = d->next)
          if (d == target)
              return false; /* still linked: not reaped yet */
      return true;
    }));
    WTQ_TEST_CHECK(wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RETIRE] +
                       wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_STATE] +
                       wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_DETACH] >
                   gate_a_before);

    /* (b) receive-flush vs cancelled on a local bidi (armed receive) */
    wtq_stream_t *bidi = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &bidi), (int)WTQ_OK);
    tid = WTQ_STREAM_ID_UNKNOWN;
    WTQ_TEST_CHECK(wait_native_id(drv, bidi, &tid));
    target = NULL;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
          if (d->id == tid)
              target = d;
    });
    WTQ_TEST_CHECK(target != NULL);
    int gate_b_before = wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RECV] +
                        wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_STATE] +
                        wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_DETACH];
    WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, bidi, 0x52), (int)WTQ_OK);
    bool b_reaped = wait_streams(drv, ^bool(struct wtq_dstream *head) {
      for (struct wtq_dstream *d = head; d != NULL; d = d->next)
          if (d == target)
              return false;
      return true;
    });
    WTQ_TEST_CHECK(b_reaped);
    if (!b_reaped)
        dispatch_sync(drv->queue, ^{
          for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
              if (d == target)
                  fprintf(stderr,
                          "[diag] stuck bidi id=%llu term=%d recvp=%d "
                          "unret=%d apppend=%d live=%d cancel=%d\n",
                          (unsigned long long)d->id, (int)d->terminal,
                          (int)d->recv_pending, d->recs_unretired,
                          d->recs_app_pending, d->batches_live,
                          (int)d->cancel_issued);
        });
    WTQ_TEST_CHECK(wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RECV] +
                       wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_STATE] +
                       wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_DETACH] >
                   gate_b_before);

    /* (c) datagram-completion-last: sends still in flight at close */
    WTQ_TEST_CHECK(wait_dgram_ready(drv, cs));
    int dgram_before = wtq_nw_test_dgram_reaps_run;
    __block int dg_sent = 0;
    dispatch_sync(drv->queue, ^{
      static const uint8_t d[] = "order-dgram-last";
      wtq_span_t sp = { d, sizeof(d) - 1 };
      for (int i = 0; i < 4; i++)
          if (wtq_session_send_datagram(cs, &sp, 1) == WTQ_OK)
              dg_sent++;
      (void)wtq_session_close(cs, 7, NULL, 0);
    });
    WTQ_TEST_CHECK(dg_sent > 0); /* in flight when the close landed */
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    WTQ_TEST_CHECK(wtq_nw_test_dgram_reaps_run > dgram_before);
    wtq_session_release(cs);
    side_destroy(&cl);

    /* (d) group terminal BEFORE child terminal: cancel the group over
     * live idle streams; children tear down from the group-terminal
     * path (armed receives flush, states converge to cancelled) */
    side_init(&cl);
    cl.echo_streams = false;
    drv = NULL;
    cs = NULL;
    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }
    wtq_stream_t *b1 = NULL, *b2 = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b1), (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b2), (int)WTQ_OK);
    uint64_t id1 = WTQ_STREAM_ID_UNKNOWN, id2 = WTQ_STREAM_ID_UNKNOWN;
    WTQ_TEST_CHECK(wait_native_id(drv, b1, &id1));
    WTQ_TEST_CHECK(wait_native_id(drv, b2, &id2));
    int reaps_before = wtq_nw_test_reaps_run;
    wtq_nw_test_cancel_group(drv);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    /* both live streams (at least) were reaped through the two-phase
     * path even though the GROUP died first */
    WTQ_TEST_CHECK(wtq_nw_test_reaps_run >= reaps_before + 2);
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

/*
 * Long-lived churn (env-gated: WTQ_NW_CHURN=N): N whole-stream aborts
 * on ONE connection, releasing every handle. Proves bounded
 * per-LIVE-stream memory across all four pools: backend shells (the
 * two-phase reap + engine detach recycle them), engine estream slots
 * (wtq_conn_on_stream_terminal resolves each abort's receive drain —
 * without it the drain tombstones exhaust the pool and opens fail),
 * API stream slots (released each iteration), and NW handles.
 * Under WTQ_NW_TEARDOWN=2 (quarantine diagnostic) the bounded-shell
 * assertion is skipped and the linear growth is REPORTED instead.
 */
static int t_churn(uint16_t port, struct side *sv, int n)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }

    __block int baseline = 0;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
          baseline++;
    });

    int peak = 0;
    bool broke = false;
    for (int i = 0; i < n && !broke; i++) {
        wtq_stream_t *st = NULL;
        wtq_result_t rc = WTQ_ERR_STREAM_LIMIT;
        /* churn opens faster than slots/credit recycle: STREAM_LIMIT is
         * backpressure, retried on a bounded condition wait. The
         * recycling itself is the assertion — without the engine's
         * whole-stream-terminal input the abort drains pin their slots
         * forever and this retry times out (the RED). */
        for (int spin = 0; spin < WAIT_MS / 5; spin++) {
            rc = dom_open_bidi(drv, cs, &st);
            if (rc != WTQ_ERR_STREAM_LIMIT)
                break;
            struct timespec ts = { 0, 5 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        WTQ_TEST_CHECK_EQ_INT((int)rc, (int)WTQ_OK);
        if (rc != WTQ_OK) {
            broke = true; /* recycling stopped: the churn RED */
            break;
        }
        WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, st, 0x60),
                              (int)WTQ_OK);
        dom_stream_release(drv, st);
        if ((i & 15) == 15) {
            __block int live = 0;
            dispatch_sync(drv->queue, ^{
              for (struct wtq_dstream *d = drv->streams; d != NULL;
                   d = d->next)
                  live++;
            });
            if (live > peak)
                peak = live;
            if (wtq_nw_test_teardown_variant == 0) {
                /* bounded per-LIVE: wait for the churn tail to recycle
                 * before opening more (condition wait, not a verdict) */
                for (int spin = 0;
                     spin < WAIT_MS / 10 && live > baseline + 24;
                     spin++) {
                    struct timespec ts = { 0, 10 * 1000 * 1000 };
                    nanosleep(&ts, NULL);
                    __block int now = 0;
                    dispatch_sync(drv->queue, ^{
                      for (struct wtq_dstream *d = drv->streams;
                           d != NULL; d = d->next)
                          now++;
                    });
                    live = now;
                }
                WTQ_TEST_CHECK(live <= baseline + 24);
                if (live > baseline + 24)
                    broke = true;
            }
        }
    }
    fprintf(stderr,
            "churn: %d aborted streams, live-shell peak %d "
            "(baseline %d, variant %d)\n",
            n, peak, baseline, wtq_nw_test_teardown_variant);
    if (wtq_nw_test_teardown_variant == 2)
        fprintf(stderr, "churn quarantine growth: peak %d for %d "
                        "historical streams\n", peak, n);

    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 9), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

/* Bounded poll for a cumulative backend counter (written on the
 * domain queue): each read is a dispatch_sync so the value is
 * SYNCHRONIZED, not a cross-thread race. */
static bool wait_counter_ge(struct wtq_driver *drv, const int *ctr,
                            int want, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        __block int v;
        dispatch_sync(drv->queue, ^{ v = *ctr; });
        if (v >= want)
            return true;
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return false;
}

/*
 * Hostile-peer reject churn (env-gated with WTQ_NW_CHURN). The client
 * fills its own estream pool with LIVE local opens, then every server
 * stream that surfaces is a GENUINE engine STREAM_LIMIT rejection with
 * no engine linkage — each rejected shell must recycle at its
 * transport terminal, NOT at connection close.
 *
 * OS/SDK OBSERVATION (not a correctness or security bound): on the
 * current Network.framework, stream grants to the peer were measured
 * NOT to replenish (~8 unis, ~5 bidis per connection lifetime,
 * cancelled streams included), which caps how many genuine overflows
 * one connection can produce here. Ownership does NOT rely on that:
 * the recycling asserted per reject holds for arbitrarily many rejects
 * (the engine-level unit tests and the abort-churn lane establish the
 * per-stream recycling independently), so a future SDK that
 * replenishes grants indefinitely stays bounded.
 */
static int t_reject_churn(uint16_t port, struct side *sv, int m)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const uint8_t cmd_open[] = "cmd:open-uni";
    static const uint8_t cmd_openb[] = "cmd:open-bidi";

    (void)m; /* the wire cap, not the caller, bounds the churn */
    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }

    /* fill the SHARED estream pool with live local opens: every peer
     * stream that surfaces from now on overflows it */
    wtq_stream_t *held[12] = { NULL };
    for (int i = 0; i < 12; i++)
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &held[i]),
                              (int)WTQ_OK);

    __block int baseline = 0;
    dispatch_sync(drv->queue, ^{
      for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
          baseline++;
    });

    /* churn: both directions until the peer's grants run dry; every
     * surfaced stream is rejected by the engine without storage. Each
     * attempt is paced by a datagram ECHO round trip — inbound traffic
     * the client's NW idle timer needs (grant-dry stalls with no
     * inbound bytes measured to idle the connection out, err 60). */
    __block int rejects0;
    dispatch_sync(drv->queue, ^{ rejects0 = wtq_nw_test_peer_rejects; });
    int rejects_seen = 0;
    for (int dir = 0; dir < 2; dir++) {
        const uint8_t *cmd = dir == 0 ? cmd_open : cmd_openb;
        size_t cmdlen = dir == 0 ? sizeof(cmd_open) - 1
                                 : sizeof(cmd_openb) - 1;
        for (int i = 0; i < 8; i++) {
            static const uint8_t ping[] = "rj-ping";
            pthread_mutex_lock(&cl.mu);
            int dg0 = cl.dgrams;
            pthread_mutex_unlock(&cl.mu);
            wtq_span_t pp = { ping, sizeof(ping) - 1 };
            WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &pp, 1),
                                  (int)WTQ_OK);
            WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.dgrams, dg0 + 1));
            __block int opens0;
            dispatch_sync(drv->queue,
                          ^{ opens0 = wtq_nw_test_peer_opens; });
            wtq_span_t sp = { cmd, cmdlen };
            WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &sp, 1),
                                  (int)WTQ_OK);
            if (!wait_counter_ge(drv, &wtq_nw_test_peer_opens,
                                 opens0 + 1, 3000))
                break; /* this direction's lifetime grant is spent */
        }
    }
    __block int rejects_end;
    dispatch_sync(drv->queue,
                  ^{ rejects_end = wtq_nw_test_peer_rejects; });
    rejects_seen = rejects_end - rejects0;
    /* at least the uni arm must genuinely overflow the pool */
    WTQ_TEST_CHECK(rejects_seen >= 2);

    /* bounded: every rejected shell recycles at its transport
     * terminal; only the live fill streams remain */
    __block int live_end = 0;
    for (int spin = 0; spin < WAIT_MS / 10; spin++) {
        __block int now = 0;
        dispatch_sync(drv->queue, ^{
          for (struct wtq_dstream *d = drv->streams; d != NULL;
               d = d->next)
              now++;
        });
        live_end = now;
        if (live_end <= baseline + 1)
            break;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    fprintf(stderr,
            "reject churn: %d genuine overflow rejects, shells end %d "
            "(baseline %d)\n",
            rejects_seen, live_end, baseline);
    if (wtq_nw_test_teardown_variant == 0)
        WTQ_TEST_CHECK(live_end <= baseline + 1);
    /* variant 2 (quarantine diagnostic) RETAINS the rejected shells by
     * design: the growth lane reports, never bounds */

    for (int i = 0; i < 12; i++)
        if (held[i] != NULL)
            dom_stream_release(drv, held[i]);
    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 9), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

/*
 * Foreign-thread ARC-holder disposal (§3.3): Apple may drop its copy
 * of a send-completion block on ANY thread, invoked or not; the
 * holder's dealloc must marshal TRANSPORT_RETIRED onto the connection
 * queue exactly once. Exercised via the backend hook that releases an
 * uninvoked block copy from a global concurrent queue.
 */
static dispatch_queue_t g_fr_queue;
static const void *g_fr_key = &g_fr_key;
static struct {
    pthread_mutex_t mu;
    int count;
    int on_queue;
} g_fr;

static void foreign_retire(void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_fr.mu);
    g_fr.count++;
    if (dispatch_get_specific(g_fr_key) == g_fr_key)
        g_fr.on_queue++;
    pthread_mutex_unlock(&g_fr.mu);
}

static int t_holder_foreign(void)
{
    int failures = 0;

    pthread_mutex_init(&g_fr.mu, NULL);
    g_fr.count = 0;
    g_fr.on_queue = 0;
    g_fr_queue = dispatch_queue_create("wtq.nw.frtest", NULL);
    dispatch_queue_set_specific(g_fr_queue, g_fr_key, (void *)g_fr_key,
                                NULL);
    wtq_nw_test_holder_foreign_dispose(g_fr_queue, foreign_retire, NULL);
    bool got = false;
    for (int i = 0; i < WAIT_MS / 10 && !got; i++) {
        pthread_mutex_lock(&g_fr.mu);
        got = g_fr.count >= 1;
        pthread_mutex_unlock(&g_fr.mu);
        if (!got) {
            struct timespec ts = { 0, 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    WTQ_TEST_CHECK(got);
    /* settle: exactly once, and ON the marshaled queue */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    dispatch_sync(g_fr_queue, ^{ /* drain */ });
    pthread_mutex_lock(&g_fr.mu);
    WTQ_TEST_CHECK_EQ_INT(g_fr.count, 1);
    WTQ_TEST_CHECK_EQ_INT(g_fr.on_queue, 1);
    pthread_mutex_unlock(&g_fr.mu);
    dispatch_release(g_fr_queue);
    return failures;
}

/* Counted-failure allocator: passthrough until `fail_at` reaches zero,
 * then exactly `fail_n` allocation failures. Thread-safe (transport
 * worker threads allocate). */
static struct {
    pthread_mutex_t mu;
    int fail_at; /* fail when a countdown of accepted allocs expires */
    int fail_n;
} g_falloc = { PTHREAD_MUTEX_INITIALIZER, -1, 0 };

static void *falloc_alloc(size_t size, void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_falloc.mu);
    bool fail = false;
    if (g_falloc.fail_at > 0) {
        g_falloc.fail_at--;
    } else if (g_falloc.fail_at == 0 && g_falloc.fail_n > 0) {
        g_falloc.fail_n--;
        fail = true;
    }
    pthread_mutex_unlock(&g_falloc.mu);
    if (fail)
        return NULL;
    return malloc(size);
}

static void *falloc_realloc(void *ptr, size_t old_size, size_t new_size,
                            void *ctx)
{
    (void)old_size;
    (void)ctx;
    return realloc(ptr, new_size);
}

static void falloc_free(void *ptr, size_t size, void *ctx)
{
    (void)size;
    (void)ctx;
    free(ptr);
}

/*
 * Allocator failures before and after ready. BEFORE ready: the shell
 * allocation at open fails — the open reports NOMEM, nothing leaks,
 * and the session stays fully usable. AFTER ready: the send-chain
 * entry (and separately the preallocated batch) fails — the send
 * reports NOMEM with a clean rollback (no completion owed, no record
 * consumed), and a retry succeeds.
 */
static int t_alloc_failures(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    wtq_alloc_t alloc = { NULL, falloc_alloc, falloc_realloc,
                          falloc_free };
    /* the failing allocator must reach the BACKEND paths (shells,
     * send-chain nodes, batches): those live on the backend-owned
     * allocator now, overridden via the seam for this test */
    wtq_nw_test_backend_alloc = &alloc;
    WTQ_TEST_CHECK(nw_client_up_ready(&cl, port, "/nw", NULL, 0, &alloc,
                                      &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }

    /* BEFORE ready: shell allocation fails at open */
    pthread_mutex_lock(&g_falloc.mu);
    g_falloc.fail_at = 0;
    g_falloc.fail_n = 1;
    pthread_mutex_unlock(&g_falloc.mu);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &st),
                          (int)WTQ_ERR_NOMEM);
    WTQ_TEST_CHECK(st == NULL);
    /* the session survives: the SAME open now succeeds */
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &st), (int)WTQ_OK);
    uint64_t sid = WTQ_STREAM_ID_UNKNOWN;
    WTQ_TEST_CHECK(wait_native_id(drv, st, &sid));

    /* AFTER ready: the send-chain entry allocation fails — NOMEM with
     * clean rollback; the identical retry is accepted */
    static const uint8_t pay[] = "alloc-after-ready";
    wtq_span_t sp = { pay, sizeof(pay) - 1 };
    pthread_mutex_lock(&g_falloc.mu);
    g_falloc.fail_at = 0;
    g_falloc.fail_n = 1;
    pthread_mutex_unlock(&g_falloc.mu);
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, st, &sp, 1, 0, NULL),
                          (int)WTQ_ERR_NOMEM);
    /* and the PREALLOCATED-batch arm (second allocation in enqueue) */
    pthread_mutex_lock(&g_falloc.mu);
    g_falloc.fail_at = 1;
    g_falloc.fail_n = 1;
    pthread_mutex_unlock(&g_falloc.mu);
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, st, &sp, 1, 0, NULL),
                          (int)WTQ_ERR_NOMEM);
    WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, st, &sp, 1, WTQ_SEND_FIN,
                                        NULL),
                          (int)WTQ_OK);
    dom_stream_release(drv, st);

    pthread_mutex_lock(&g_falloc.mu);
    g_falloc.fail_at = -1;
    g_falloc.fail_n = 0;
    pthread_mutex_unlock(&g_falloc.mu);
    wtq_nw_test_backend_alloc = NULL; /* new conns back on default;
                                         THIS conn keeps its copy */
    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 9), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK(cl.closed_clean);
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

/*
 * Missing QUIC metadata at ready is a BACKEND INVARIANT FAILURE: a
 * silent stream cancel would strand engine state, so the connection
 * fails deterministically with {LOCAL, BACKEND} detail — for EVERY
 * stream class. The seam targets a class, never a ready ordering:
 *   A. an h3 critical uni during startup (no establishment happens,
 *      nothing stays silently pending);
 *   B. the CONNECT bidi (no 2xx/establishment ever, exactly one
 *      failure outcome, no stale response can establish later);
 *   C. an ordinary app WT stream after establishment.
 */
static int meta_case_startup(uint16_t port, struct side *sv, int deny_bit)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    /* armed before the backend exists: consumed at the target class's
     * ready, wherever it falls in startup. The EXPECTED outcome is a
     * {LOCAL, BACKEND} failure; an environmental NW-native connect
     * failure (which precedes the target stream's ready and leaves the
     * seam un-consumed) retries the whole case, loudly and bounded. */
    bool backend_failure = false;
    for (int attempt = 0; attempt < 1 + g_est_retries && !backend_failure;
         attempt++) {
        drv = NULL;
        cs = NULL;
        /* STICKY: persistent metadata absence — denied at the ready
         * callback AND at the one-turn recheck, so the deterministic
         * connection-fatal invariant is what this case asserts. A
         * one-shot denial now RECOVERS (t_meta_recovers). */
        wtq_nw_test_meta_deny_sticky = deny_bit;
        WTQ_TEST_CHECK_EQ_INT(
            (int)nw_client_up(&cl, port, "/nw", NULL, 0, &drv, &cs),
            (int)WTQ_OK);
        if (cs == NULL) {
            wtq_nw_test_meta_deny_sticky = 0;
            pthread_mutex_lock(&sv->mu);
            sv->echo_streams = true;
            pthread_mutex_unlock(&sv->mu);
            side_destroy(&cl);
            return failures + 1;
        }
        WTQ_TEST_CHECK(side_wait(&cl, &cl.failed));
        pthread_mutex_lock(&cl.mu);
        bool env = cl.failed > 0 && side_err_is_environmental(&cl);
        /* a retry exists only when it will actually RUN */
        bool more = env && attempt + 1 < 1 + g_est_retries;
        if (more) {
            fprintf(stderr,
                    "[env] meta case (bit %d) attempt %d: NW-native "
                    "connect failure dom=%u — retrying\n",
                    deny_bit, attempt + 1, cl.closed_err.native_domain);
            g_est_retry_count++; /* counted at the START of a real retry */
            cl.established = 0;
            cl.failed = 0;
            cl.closed = 0;
            memset(&cl.closed_err, 0, sizeof(cl.closed_err));
        } else {
            /* {LOCAL, BACKEND} — or retries disabled: this is the
             * outcome the assertions judge */
            backend_failure = true;
        }
        pthread_mutex_unlock(&cl.mu);
        if (!backend_failure) {
            /* reset the seam ON the domain while the driver exists:
             * callbacks may still inspect it */
            dispatch_sync(drv->queue, ^{ wtq_nw_test_meta_deny_sticky = 0; });
            (void)wtq_nw_conn_rundown_internal(drv, WAIT_MS);
            wtq_session_release(cs);
        }
    }
    WTQ_TEST_CHECK(backend_failure);
    if (!backend_failure) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }
    /* settle: no second outcome, no stale establishment */
    struct timespec ts = { 0, 200 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(cl.failed, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.established, 0);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 0);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.kind,
                          (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.native_domain,
                          (int)WTQ_ERRDOM_BACKEND);
    pthread_mutex_unlock(&cl.mu);

    /* sticky seam: never consumed — cleared BY THE TEST on the domain */
    dispatch_sync(drv->queue, ^{ wtq_nw_test_meta_deny_sticky = 0; });

    /* bounded rundown: every accepted send settled exactly once, no
     * critical stream silently pending */
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

static int t_meta_missing(uint16_t port, struct side *sv)
{
    int failures = 0;

    /* A: h3 critical uni at startup */
    failures += meta_case_startup(port, sv, WTQ_NW_META_DENY_CRITICAL);
    /* B: the CONNECT bidi (the test opens no app bidi in the window,
     * so the class targets the CONNECT stream deterministically) */
    failures += meta_case_startup(port, sv, WTQ_NW_META_DENY_LOCAL_BIDI);

    /* C: an app WT stream after establishment */
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = false;
    pthread_mutex_unlock(&sv->mu);

    WTQ_TEST_CHECK(
        nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs));
    if (cs == NULL) {
        pthread_mutex_lock(&sv->mu);
        sv->echo_streams = true;
        pthread_mutex_unlock(&sv->mu);
        side_destroy(&cl);
        return failures + 1;
    }

    dispatch_sync(drv->queue,
                  ^{ wtq_nw_test_meta_deny_sticky = WTQ_NW_META_DENY_APP; });
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_uni(drv, cs, &st), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK(!cl.closed_clean);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.kind,
                          (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.native_domain,
                          (int)WTQ_ERRDOM_BACKEND);
    pthread_mutex_unlock(&cl.mu);
    if (st != NULL)
        dom_stream_release(drv, st);
    dispatch_sync(drv->queue, ^{ wtq_nw_test_meta_deny_sticky = 0; });
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true;
    pthread_mutex_unlock(&sv->mu);
    return failures;
}

/*
 * FRAME-ONLY metadata absence RECOVERS. MEASURED (366 events over 780
 * loopback-gate iterations): NW can deliver a stream's `ready` with the
 * QUIC metadata absent inside that callback frame; the backend now
 * rechecks one domain turn later instead of failing the connection. The
 * one-shot deny seam models exactly that frame-only miss (the recheck
 * sees the real metadata), and every dependent behavior must come out
 * whole: bootstrap, CONNECT, app streams (usable, REAL id reported),
 * pre-ready aborts (exact stamped code), and inbound classification
 * (exactly once). Persistent absence stays connection-fatal —
 * t_meta_missing, via the sticky seam.
 */
static int t_meta_recovers(uint16_t port, struct side *sv)
{
    int failures = 0;

    /* (1)+(2): critical bootstrap and the CONNECT stream each recover
     * from a frame-only miss at connect time — the session ESTABLISHES. */
    static const int startup_bits[2] = { WTQ_NW_META_DENY_CRITICAL,
                                         WTQ_NW_META_DENY_LOCAL_BIDI };
    for (int i = 0; i < 2; i++) {
        struct side cl;
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;

        side_init(&cl);
        cl.echo_streams = false;
        wtq_nw_test_meta_deny = startup_bits[i];
        bool up = nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL,
                                     &drv, &cs);
        WTQ_TEST_CHECK(up); /* established despite the in-frame miss */
        if (up) {
            /* the one-shot seam was consumed by its target */
            __block int left;
            dispatch_sync(drv->queue, ^{ left = wtq_nw_test_meta_deny; });
            WTQ_TEST_CHECK_EQ_INT(left, 0);
            WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
            WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
            wtq_session_release(cs);
        } else {
            wtq_nw_test_meta_deny = 0;
        }
        side_destroy(&cl);
        if (!up)
            return failures + 1;
    }

    /* (3)-(5) share one established connection */
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;

    side_init(&cl);
    cl.echo_streams = false;
    pthread_mutex_lock(&sv->mu);
    sv->echo_streams = true; /* the usability round-trip needs the echo */
    pthread_mutex_unlock(&sv->mu);
    if (!nw_client_up_ready(&cl, port, "/nw", NULL, 0, NULL, &drv, &cs)) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* (3) an app bidi whose ready missed metadata in-frame SURVIVES, is
     * USABLE (full echo round-trip), and reports its REAL id late. */
    {
        wtq_stream_t *b = NULL;
        dispatch_sync(drv->queue,
                      ^{ wtq_nw_test_meta_deny = WTQ_NW_META_DENY_LOCAL_BIDI; });
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        pthread_mutex_lock(&cl.mu);
        cl.rx_len = 0;
        pthread_mutex_unlock(&cl.mu);
        static const uint8_t hi[2] = { 'h', 'i' };
        wtq_span_t sp = { hi, sizeof(hi) };
        WTQ_TEST_CHECK_EQ_INT((int)dom_send(drv, b, &sp, 1, 0, NULL),
                              (int)WTQ_OK);
        /* wait for the echo (bytes back on the same stream) */
        {
            pthread_mutex_lock(&cl.mu);
            struct timespec dl;
            clock_gettime(CLOCK_REALTIME, &dl);
            dl.tv_sec += WAIT_MS / 1000;
            while (cl.rx_len < sizeof(hi)) {
                if (pthread_cond_timedwait(&cl.cv, &cl.mu, &dl) != 0)
                    break;
            }
            WTQ_TEST_CHECK(cl.rx_len == sizeof(hi) &&
                           memcmp(cl.rx, hi, sizeof(hi)) == 0);
            pthread_mutex_unlock(&cl.mu);
        }
        /* the REAL id was reported (late, at the recheck) — not UNKNOWN */
        __block uint64_t got_id;
        dispatch_sync(drv->queue, ^{ got_id = wtq_stream_id(b); });
        WTQ_TEST_CHECK(got_id != WTQ_STREAM_ID_UNKNOWN);
        __block int left;
        dispatch_sync(drv->queue, ^{ left = wtq_nw_test_meta_deny; });
        WTQ_TEST_CHECK_EQ_INT(left, 0); /* consumed by the target */
        dom_stream_release(drv, b);
    }

    /* (4) an abort BEFORE the (metadata-less) ready keeps its EXACT
     * stamped code — the deferred cancel is applied at the recheck, where
     * the stamp slot exists. The stream itself never surfaces at the peer
     * (a pre-association reset, by design), so the proof is the backend's
     * stamped-cancel record: the stamp landed on live metadata with the
     * requested code, not code 0 and not skipped. */
    {
        wtq_stream_t *b = NULL;
        __block wtq_stream_t *nb = NULL;
        __block int stamps0 = 0;
        __block wtq_result_t orc = WTQ_ERR_STATE, arc = WTQ_ERR_STATE;
        __block bool pre_deferred = false, pre_processed = true;
        /* open AND abort in ONE domain block: NW's ready state callback is
         * itself a queued block, so it cannot interleave — the abort
         * DETERMINISTICALLY precedes ready processing, and the captured
         * precondition proves the DEFERRED stamped-cancel path was taken
         * (not an immediate post-ready stamp). */
        dispatch_sync(drv->queue, ^{
          stamps0 = wtq_nw_test_stamp_count;
          wtq_nw_test_meta_deny = WTQ_NW_META_DENY_LOCAL_BIDI;
          orc = wtq_session_open_bidi(cs, &nb);
          if (orc == WTQ_OK && nb != NULL) {
              arc = wtq_stream_abort(nb, 0x7654);
              /* the just-opened stream: ready cannot have fired inside
               * this block, so it is the unique local bidi without
               * ready_seen */
              for (struct wtq_dstream *d = drv->streams; d != NULL;
                   d = d->next)
                  if (d->is_local && d->is_bidi && !d->hidden &&
                      !d->ready_seen) {
                      pre_deferred = d->cancel_deferred;
                      pre_processed = d->ready_processed;
                      break;
                  }
          }
        });
        b = nb;
        WTQ_TEST_CHECK_EQ_INT((int)orc, (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)arc, (int)WTQ_OK);
        WTQ_TEST_CHECK(pre_deferred);   /* the DEFERRED cancel path */
        WTQ_TEST_CHECK(!pre_processed); /* ...before ready processing */
        /* the recheck (and so the deferred stamped cancel) runs after NW
         * delivers the ready — transport-async: bounded condition poll on
         * the domain value, in the file's settle style */
        {
            bool stamped = false;
            for (int i = 0; i < WAIT_MS / 20 && !stamped; i++) {
                __block int now = 0;
                dispatch_sync(drv->queue,
                              ^{ now = wtq_nw_test_stamp_count; });
                if (now > stamps0) {
                    stamped = true;
                    break;
                }
                struct timespec ts = { 0, 20 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            WTQ_TEST_CHECK(stamped);
        }
        __block int stamps1 = 0;
        __block uint64_t code = 0;
        dispatch_sync(drv->queue, ^{
          stamps1 = wtq_nw_test_stamp_count;
          code = wtq_nw_test_last_stamp_code;
          wtq_nw_test_meta_deny = 0;
        });
        WTQ_TEST_CHECK_EQ_INT(stamps1, stamps0 + 1); /* exactly one stamp */
        /* the exact code — as the WIRE carries it: the engine maps the app
         * code into the WebTransport H3 error space before the backend
         * stamps it, so the round-trippable mapping is the assertion */
        WTQ_TEST_CHECK_EQ_U64(code, wtq_app_error_to_h3(0x7654));
        dom_stream_release(drv, b);
    }

    /* (5) an INBOUND stream whose ready missed metadata in-frame is
     * classified exactly once and delivers its bytes exactly once. */
    {
        pthread_mutex_lock(&cl.mu);
        int opened0 = cl.streams_opened;
        cl.rx_len = 0;
        pthread_mutex_unlock(&cl.mu);
        dispatch_sync(drv->queue,
                      ^{ wtq_nw_test_meta_deny = WTQ_NW_META_DENY_INBOUND; });
        static const uint8_t cmd_open[] = "cmd:open-uni";
        wtq_span_t cspan = { cmd_open, sizeof(cmd_open) - 1 };
        WTQ_TEST_CHECK_EQ_INT((int)dom_dgram(drv, cs, &cspan, 1),
                              (int)WTQ_OK);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.streams_opened, opened0 + 1));
        /* wait for the stream's bytes ("sv"), then verify exactly-once */
        {
            pthread_mutex_lock(&cl.mu);
            struct timespec dl;
            clock_gettime(CLOCK_REALTIME, &dl);
            dl.tv_sec += WAIT_MS / 1000;
            while (cl.rx_len < 2) {
                if (pthread_cond_timedwait(&cl.cv, &cl.mu, &dl) != 0)
                    break;
            }
            WTQ_TEST_CHECK(cl.rx_len == 2 && memcmp(cl.rx, "sv", 2) == 0);
            WTQ_TEST_CHECK_EQ_INT(cl.streams_opened, opened0 + 1);
            pthread_mutex_unlock(&cl.mu);
        }
        __block int left;
        dispatch_sync(drv->queue, ^{ left = wtq_nw_test_meta_deny; });
        WTQ_TEST_CHECK_EQ_INT(left, 0);
    }

    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_session_release(cs);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: meta_recovers\n");
    return failures;
}

/* --- server harness --------------------------------------------------------- */

/*
 * The server side reacts to client control datagrams:
 *   "cmd:open+reset"  open one uni toward the client and RESET it with
 *                     0x77 (reset attribution), echo other datagrams;
 *   "cmd:stop-next"   STOP_SENDING (0x55) the next bidi that opens.
 * Everything else: echo datagrams; echo bidi bytes+FIN (cb_stream_data).
 */
static struct side g_sv;
static pthread_mutex_t g_sv_ops_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_sv_stop_next;
static wtq_stream_t *g_sv_reset_st; /* retained: reset on cmd:reset-now */
static wtq_stream_t *g_sv_last_uni; /* retained: reset on command */

static void sv_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    if (test_dbg())
        fprintf(stderr, "[sv] dgram len=%zu\n", len);
    cb_datagram(s, data, len, user);
    if (len == 12 && memcmp(data, "cmd:open-uni", 12) == 0) {
        wtq_stream_t *st = NULL;
        if (wtq_session_open_uni(s, &st) == WTQ_OK) {
            static const uint8_t hello[] = "sv";
            wtq_span_t sp = { hello, 2 };
            (void)wtq_stream_send(st, &sp, 1, 0, NULL);
            pthread_mutex_lock(&g_sv_ops_mu);
            wtq_stream_add_ref(st);
            if (g_sv_last_uni != NULL)
                wtq_stream_release(g_sv_last_uni);
            g_sv_last_uni = st;
            pthread_mutex_unlock(&g_sv_ops_mu);
        }
        return;
    }
    if (len == 13 && memcmp(data, "cmd:open-bidi", 13) == 0) {
        wtq_stream_t *st = NULL;
        wtq_result_t obrc = wtq_session_open_bidi(s, &st);
        if (test_dbg())
            fprintf(stderr, "[sv] open-bidi rc=%d\n", (int)obrc);
        if (obrc == WTQ_OK) {
            static const uint8_t hello[] = "sb";
            wtq_span_t sp = { hello, 2 };
            (void)wtq_stream_send(st, &sp, 1, 0, NULL);
            /* parked: cmd:reset-now resets this send half later */
            pthread_mutex_lock(&g_sv_ops_mu);
            if (g_sv_reset_st != NULL)
                wtq_stream_release(g_sv_reset_st);
            g_sv_reset_st = st;
            pthread_mutex_unlock(&g_sv_ops_mu);
        }
        return;
    }
    if (len == 14 && memcmp(data, "cmd:reset-last", 14) == 0) {
        pthread_mutex_lock(&g_sv_ops_mu);
        wtq_stream_t *st = g_sv_last_uni;
        g_sv_last_uni = NULL;
        pthread_mutex_unlock(&g_sv_ops_mu);
        if (st != NULL) {
            (void)wtq_stream_reset(st, 0x77);
            wtq_stream_release(st);
        }
        return;
    }
    if (len == 13 && memcmp(data, "cmd:stop-next", 13) == 0) {
        pthread_mutex_lock(&g_sv_ops_mu);
        g_sv_stop_next = true;
        pthread_mutex_unlock(&g_sv_ops_mu);
        return;
    }
    if (len == 13 && memcmp(data, "cmd:reset-now", 13) == 0) {
        pthread_mutex_lock(&g_sv_ops_mu);
        wtq_stream_t *st = g_sv_reset_st;
        g_sv_reset_st = NULL;
        pthread_mutex_unlock(&g_sv_ops_mu);
        if (st != NULL) {
            wtq_result_t rrc = wtq_stream_reset(st, 0x71);
            if (test_dbg())
                fprintf(stderr, "[sv] reset-now rc=%d\n", (int)rrc);
            wtq_stream_release(st);
        }
        return;
    }
    if (len > 0 && len <= 64) {
        wtq_span_t span = { data, len };
        (void)wtq_session_send_datagram(s, &span, 1);
    }
}

static void sv_stream_opened(wtq_session_t *s, wtq_stream_t *st, bool bidi,
                             void *user)
{
    bool stop = false;

    ring_put("sv-open", 0, (int)bidi);
    if (test_dbg())
        fprintf(stderr, "[sv] stream opened bidi=%d\n", (int)bidi);
    cb_stream_opened(s, st, bidi, user);
    if (bidi) {
        pthread_mutex_lock(&g_sv_ops_mu);
        stop = g_sv_stop_next;
        g_sv_stop_next = false;
        pthread_mutex_unlock(&g_sv_ops_mu);
    }
    if (stop)
        (void)wtq_stream_stop_sending(st, 0x55);
}

/*
 * RECEIVE PAUSE DEFERRAL — deterministic, via the WTQ_NW_TESTING receive
 * injection seam. op_recv_enable(false) only stops FUTURE arms, so the one
 * already-outstanding nw_connection_receive can still complete after pause
 * returned; without deferral its bytes or FIN would reach the engine while
 * paused. The seam replays that completion ON THE DOMAIN — no network
 * timing — so the backend-local deferral is proven exactly.
 *
 * Every scenario opens a FRESH client app bidi and pauses it BEFORE its
 * ready (open + pause are dispatch_sync'd ahead of the ready callback), so
 * no real receive is ever armed to race the injection.
 */
static int t_recv_pause(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wt" };

    (void)sv;
    side_init(&cl);
    cl.echo_streams = false;
    ring_reset();
    wtq_nw_test_recv_defer_overflow = 0;

    if (!nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs)) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* (1) data deferral + resume delivers exactly once, byte-exact */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        /* this backend's advertised pause mode is DELIVERY-ONLY (no hard
         * flow-control bound — see COMPATIBILITY.md); assert the query
         * agrees with the backend under test */
        __block wtq_receive_pause_mode_t pmode;
        dispatch_sync(drv->queue,
                      ^{ pmode = wtq_stream_receive_pause_mode(b); });
        WTQ_TEST_CHECK_EQ_INT((int)pmode,
                              (int)WTQ_RECEIVE_PAUSE_DELIVERY_ONLY);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t hello[5] = { 'h', 'e', 'l', 'l', 'o' };
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv(drv, ds, hello, sizeof(hello), false);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds)); /* held */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0);     /* engine/app saw none */
            pthread_mutex_unlock(&cl.mu);
            /* no receive was armed while paused (paused before ready, so
             * ready armed nothing either) */
            unsigned arms0 = dom_ds_arms(drv, ds);
            WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
            WTQ_TEST_CHECK(!dom_ds_deferred(drv, ds));
            /* resume arms EXACTLY one receive */
            WTQ_TEST_CHECK_EQ_INT((int)(dom_ds_arms(drv, ds) - arms0), 1);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(hello) &&
                           memcmp(cl.rx, hello, sizeof(hello)) == 0);
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* (2) pure zero-byte FIN stays deferred while paused */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            pthread_mutex_lock(&cl.mu);
            int fins0 = cl.rx_fins;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv(drv, ds, NULL, 0, true); /* pure FIN */
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.rx_fins, fins0); /* FIN held */
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
            WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.rx_fins, fins0 + 1));
        }
        dom_stream_release(drv, b);
    }

    /* (3) data + FIN together: one deferral, one ordered delivery */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t bye[3] = { 'b', 'y', 'e' };
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            int fins0 = cl.rx_fins;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv(drv, ds, bye, sizeof(bye), true);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0);
            WTQ_TEST_CHECK_EQ_INT(cl.rx_fins, fins0);
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
            WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.rx_fins, fins0 + 1));
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(bye) &&
                           memcmp(cl.rx, bye, sizeof(bye)) == 0);
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* (3b) content delivered alongside a receive ERROR is deferred while
     * paused, then delivered once on resume WITHOUT re-arming (the error
     * ended the receive side) */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t oops[4] = { 'o', 'o', 'p', 's' };
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            /* content + error, while paused */
            dom_inject_recv_ex(drv, ds, oops, sizeof(oops), false, true);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds)); /* held, not delivered */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0);
            pthread_mutex_unlock(&cl.mu);
            unsigned arms0 = dom_ds_arms(drv, ds);
            WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
            /* delivered once, byte-exact, and NO re-arm (error ended it) */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(oops) &&
                           memcmp(cl.rx, oops, sizeof(oops)) == 0);
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT((int)(dom_ds_arms(drv, ds) - arms0), 0);
            WTQ_TEST_CHECK(!dom_ds_deferred(drv, ds));
        }
        dom_stream_release(drv, b);
    }

    /* (4) two-stream isolation: while A is paused with data HELD, an
     * unpaused B delivers a DISTINCT payload — B progresses while A does
     * not, and resuming A then yields exactly A's bytes */
    {
        wtq_stream_t *a = NULL, *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        struct wtq_dstream *dsb = dom_capture_bidi(drv, b); /* B, running */
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &a), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, a), (int)WTQ_OK);
        struct wtq_dstream *dsa = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(dsa != NULL && dsb != NULL);
        if (dsa != NULL && dsb != NULL) {
            static const uint8_t a_bytes[4] = { 'A', 'A', 'A', 'A' };
            static const uint8_t b_bytes[3] = { 'B', 'B', 'B' };
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            /* A paused -> held; B running -> delivered immediately */
            dom_inject_recv(drv, dsa, a_bytes, sizeof(a_bytes), false);
            dom_inject_recv(drv, dsb, b_bytes, sizeof(b_bytes), false);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, dsa));   /* A held */
            WTQ_TEST_CHECK(!dom_ds_deferred(drv, dsb));  /* B not held */
            pthread_mutex_lock(&cl.mu);
            /* exactly B's payload has been delivered; none of A's */
            WTQ_TEST_CHECK(cl.rx_len == sizeof(b_bytes) &&
                           memcmp(cl.rx, b_bytes, sizeof(b_bytes)) == 0);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            /* now resume A -> exactly A's held bytes arrive */
            WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, a), (int)WTQ_OK);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(a_bytes) &&
                           memcmp(cl.rx, a_bytes, sizeof(a_bytes)) == 0);
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, a);
        dom_stream_release(drv, b);
    }

    /* (5) repeated pause/resume toggles never re-arm: with one receive
     * already outstanding, the recv_pending guard means every resume
     * across the toggles issues ZERO new arms */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_capture_bidi(drv, b); /* running */
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            /* the capture's resume armed exactly one receive */
            __block bool armed = false;
            dispatch_sync(drv->queue, ^{ armed = ds->recv_pending; });
            WTQ_TEST_CHECK(armed);
            unsigned arms0 = dom_ds_arms(drv, ds);
            for (int i = 0; i < 4; i++) {
                WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
                WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
            }
            /* the outstanding receive was never replaced: no re-arm */
            WTQ_TEST_CHECK_EQ_INT((int)(dom_ds_arms(drv, ds) - arms0), 0);
        }
        dom_stream_release(drv, b);
    }

    /* (6) teardown while deferred: leave a completion held (with a
     * counting destructor), then run the connection down. The retained
     * transport object must be released EXACTLY ONCE on the terminal/reap
     * path — proven by the destructor count, not just recv_deferred and
     * the sanitizer. */
    int td_dtor = 0;
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t held[6] = { 'h', 'e', 'l', 'd', '!', '!' };
            dom_inject_recv_counted(drv, ds, held, sizeof(held), false,
                                    &td_dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            WTQ_TEST_CHECK_EQ_INT(td_dtor, 0); /* still held */
        }
        dom_stream_release(drv, b);
        /* fall through to rundown WITHOUT resuming */
    }

    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    /* the held object was released exactly once during teardown */
    WTQ_TEST_CHECK_EQ_INT(td_dtor, 1);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: recv_pause\n");
    return failures;
}

/*
 * RESET / CANCEL WHILE DEFERRED — its own connection because both cases
 * terminate a real stream (transport churn). Proves the held buffer is
 * dropped before the engine is notified, a resume attempted reentrantly
 * from on_stream_reset is rejected, and nothing stale is replayed or
 * re-armed on the way down.
 */
static int t_recv_reset_deferred(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wt" };

    (void)sv;
    side_init(&cl);
    cl.echo_streams = false;
    ring_reset();

    if (!nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs)) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* (1) STREAM-LOCAL ABORT while deferred: op_shutdown_stream drops the
     * held completion SYNCHRONOUSLY — its counting destructor fires exactly
     * once — then a resume is rejected and nothing is replayed or re-armed.
     * Runs first, on a healthy connection. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t gone[4] = { 'g', 'o', 'n', 'e' };
            int dtor = 0;
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv_counted(drv, ds, gone, sizeof(gone), false, &dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            WTQ_TEST_CHECK_EQ_INT(dtor, 0); /* held */
            unsigned arms0 = dom_ds_arms(drv, ds);       /* stream still live */
            /* abort + capture in ONE domain turn: after the abort the ds
             * may be reaped on any later turn, so the post-abort state is
             * read atomically with the operation itself */
            __block wtq_result_t arc;
            __block bool defd = true;
            __block unsigned arms1 = arms0;
            dispatch_sync(drv->queue, ^{
              arc = wtq_stream_abort(b, 7);
              defd = ds->recv_deferred;
              arms1 = ds->recv_arm_count;
            });
            WTQ_TEST_CHECK_EQ_INT((int)arc, (int)WTQ_OK);
            WTQ_TEST_CHECK(!defd);                       /* dropped now */
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0); /* abort armed nothing */
            dom_drain(drv); /* run the queued buffer destructor */
            WTQ_TEST_CHECK_EQ_INT(dtor, 1);              /* released once */
            WTQ_TEST_CHECK(dom_resume(drv, b) != WTQ_OK); /* rejected: can't arm
                                                             (public path via the
                                                             handle — no ds read) */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0); /* nothing replayed */
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* (2) PEER RESET while deferred, with a reentrant resume in the reset
     * callback: the held buffer (counting destructor) is dropped BEFORE the
     * callback and released exactly once, the resume is rejected, and
     * nothing is replayed or re-armed. Also proves the backend guard
     * rejects a direct op_recv_enable on the failed stream without mutating
     * recv_enabled. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t stale[5] = { 's', 't', 'a', 'l', 'e' };
            int dtor = 0;
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            cl.resume_on_reset = true;
            cl.reset_resume_rc = WTQ_OK;
            int resets0 = cl.resets;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv_counted(drv, ds, stale, sizeof(stale), false,
                                    &dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            WTQ_TEST_CHECK_EQ_INT(dtor, 0);
            unsigned arms0 = dom_ds_arms(drv, ds);
            /* failure + capture + guard probe in ONE domain turn: after
             * the failure the ds may be reaped on any later turn, so the
             * post-failure state and the direct op_recv_enable guard are
             * taken atomically with the failure itself (this exact probe,
             * as separate dispatches, was a measured use-after-free). */
            wtq_nw_test_fail_probe_t fp;
            wtq_nw_test_stream_fail_probe(drv, ds, &fp);
            WTQ_TEST_CHECK_EQ_INT(cl.resets, resets0 + 1);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_at_reset, 0); /* nothing before */
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0);      /* nothing replayed */
            WTQ_TEST_CHECK(cl.reset_resume_rc != WTQ_OK); /* resume rejected */
            cl.resume_on_reset = false;
            pthread_mutex_unlock(&cl.mu);
            WTQ_TEST_CHECK(!fp.deferred_after);        /* dropped */
            dom_drain(drv); /* run the queued buffer destructor */
            WTQ_TEST_CHECK_EQ_INT(dtor, 1);            /* released once */
            WTQ_TEST_CHECK_EQ_INT((int)(fp.arms_after - arms0), 0); /* no
                                                                re-arm */
            /* the backend guard, exercised directly (same turn): rejects
             * and does not mutate recv_enabled */
            WTQ_TEST_CHECK_EQ_INT((int)fp.enable_rc, (int)WTQ_ERR_CLOSED);
            WTQ_TEST_CHECK(fp.re_after == fp.re_before); /* state unchanged */
            /* a further resume through the public path is still rejected
             * (handle-based: no ds read) */
            WTQ_TEST_CHECK(dom_resume(drv, b) != WTQ_OK);
        }
        dom_stream_release(drv, b);
    }

    /* (3) content + error deferred, then FAILURE arrives FIRST: terminal
     * handling drops the held completion and NOTHING is delivered (the
     * failure-first ordering of the content-plus-error case) */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t part[3] = { 'p', 'a', 'r' };
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            /* content + error, held while paused */
            dom_inject_recv_ex(drv, ds, part, sizeof(part), false, true);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            unsigned arms0 = dom_ds_arms(drv, ds);   /* stream still live */
            /* failure first — capture in the SAME domain turn (reap-safe) */
            wtq_nw_test_fail_probe_t fp3;
            wtq_nw_test_stream_fail_probe(drv, ds, &fp3);
            WTQ_TEST_CHECK(!fp3.deferred_after); /* dropped, not resumed */
            WTQ_TEST_CHECK_EQ_INT((int)(fp3.arms_after - arms0), 0);
            WTQ_TEST_CHECK_EQ_INT((int)fp3.enable_rc, (int)WTQ_ERR_CLOSED);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0); /* never delivered */
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: recv_reset_deferred\n");
    return failures;
}

/*
 * REPLAY REENTRANCY + RECEIVE-SIDE-ENDED — the resume/replay path with an
 * application that reacts from INSIDE the replayed delivery (abort / session
 * close / another resume), plus the error-only-while-paused window. Every
 * case proves exactly-once delivery and disposal (counting destructor) and
 * ZERO receive arms after the terminal transition, with per-stream arm
 * attribution snapshotted in one domain turn (reap-safe).
 */
static int t_recv_replay_reentrant(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wt" };

    (void)sv;
    side_init(&cl);
    cl.echo_streams = false;
    ring_reset();

    if (!nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs)) {
        side_destroy(&cl);
        return failures + 1;
    }

    /* (1) ERROR-ONLY completion while paused, resume BEFORE any failed-state
     * callback: the completion ended the receive side permanently; nothing
     * was held, so the resume is REJECTED and arms nothing — the window
     * between an error-only completion and the (later) failed state can
     * never re-arm a finished stream. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            pthread_mutex_unlock(&cl.mu);
            unsigned arms0 = dom_ds_arms(drv, ds);
            dom_inject_recv_ex(drv, ds, NULL, 0, false, true); /* error only */
            WTQ_TEST_CHECK(!dom_ds_deferred(drv, ds)); /* nothing to hold */
            WTQ_TEST_CHECK(dom_resume(drv, b) != WTQ_OK); /* rejected */
            /* PAUSE in the same window is rejected too — the incoming
             * direction is finished for BOTH directions — and mutates
             * nothing (recv_enabled stays as it was) */
            WTQ_TEST_CHECK(dom_pause(drv, b) != WTQ_OK);
            __block bool re_now = true;
            dispatch_sync(drv->queue, ^{ re_now = ds->recv_enabled; });
            WTQ_TEST_CHECK(!re_now); /* unmutated: still the original pause */
            bool defd = false;
            unsigned arms1 = arms0;
            dom_ds_snapshot(drv, ds, &defd, &arms1);
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0); /* no re-arm */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_SIZE(cl.rx_len, 0); /* nothing delivered */
            pthread_mutex_unlock(&cl.mu);
            /* tear the ended stream down so it cannot linger as a paused,
             * receive-ended shell for the rest of the connection */
            WTQ_TEST_CHECK_EQ_INT((int)dom_abort(drv, b, 0), (int)WTQ_OK);
        }
        dom_stream_release(drv, b);
    }

    /* (2) CONTENT+ERROR held, replay with a REENTRANT RESUME from inside the
     * data callback: the bytes are delivered exactly once, the inner resume
     * is rejected (the side ended; nothing is held any more), and neither
     * resume arms a receive. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t part[3] = { 'p', 'a', 'r' };
            int dtor = 0;
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            cl.reentry_target = b;
            cl.reentry_action = REENTRY_RESUME;
            cl.reentry_rc = WTQ_OK;
            cl.reentry_fired = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv_counted_ex(drv, ds, part, sizeof(part), false,
                                       true, &dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            WTQ_TEST_CHECK_EQ_INT(dtor, 0); /* held */
            unsigned arms0 = dom_ds_arms(drv, ds);
            bool defd = true;
            unsigned arms1 = arms0;
            WTQ_TEST_CHECK_EQ_INT(
                (int)dom_resume_snap(drv, b, ds, &defd, &arms1), (int)WTQ_OK);
            WTQ_TEST_CHECK(!defd); /* replayed and released */
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0); /* error ended it */
            dom_drain(drv); /* run the queued buffer destructor */
            WTQ_TEST_CHECK_EQ_INT(dtor, 1); /* disposed exactly once */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.reentry_fired, 1);
            WTQ_TEST_CHECK(cl.reentry_rc != WTQ_OK); /* inner resume rejected */
            WTQ_TEST_CHECK(cl.rx_len == sizeof(part) &&
                           memcmp(cl.rx, part, sizeof(part)) == 0);
            cl.reentry_action = REENTRY_NONE;
            cl.reentry_target = NULL;
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* (3) DEFERRED PURE FIN, replay with a reentrant resume from inside the
     * FIN delivery: exactly one FIN, inner resume rejected, no arm. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            pthread_mutex_lock(&cl.mu);
            int fins0 = cl.rx_fins;
            cl.reentry_target = b;
            cl.reentry_action = REENTRY_RESUME;
            cl.reentry_rc = WTQ_OK;
            cl.reentry_fired = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv(drv, ds, NULL, 0, true); /* pure FIN, held */
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            unsigned arms0 = dom_ds_arms(drv, ds);
            bool defd = true;
            unsigned arms1 = arms0;
            WTQ_TEST_CHECK_EQ_INT(
                (int)dom_resume_snap(drv, b, ds, &defd, &arms1), (int)WTQ_OK);
            WTQ_TEST_CHECK(!defd);
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0); /* FIN ended it */
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.rx_fins, fins0 + 1); /* exactly once */
            WTQ_TEST_CHECK_EQ_INT(cl.reentry_fired, 1);
            WTQ_TEST_CHECK(cl.reentry_rc != WTQ_OK); /* inner rejected */
            cl.reentry_action = REENTRY_NONE;
            cl.reentry_target = NULL;
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* (4) replayed data callback REENTRANTLY ABORTS the stream: delivery and
     * disposal exactly once, the abort is accepted, and the resume that
     * drove the replay must NOT arm a receive afterwards — the teardown
     * happened inside its own replay. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t boom[4] = { 'b', 'o', 'o', 'm' };
            int dtor = 0;
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            cl.reentry_target = b;
            cl.reentry_action = REENTRY_ABORT;
            cl.reentry_rc = WTQ_ERR_STATE;
            cl.reentry_fired = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv_counted(drv, ds, boom, sizeof(boom), false,
                                    &dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            WTQ_TEST_CHECK_EQ_INT(dtor, 0);
            unsigned arms0 = dom_ds_arms(drv, ds);
            bool defd = true;
            unsigned arms1 = arms0;
            WTQ_TEST_CHECK_EQ_INT(
                (int)dom_resume_snap(drv, b, ds, &defd, &arms1), (int)WTQ_OK);
            WTQ_TEST_CHECK(!defd);
            /* THE reentrant-teardown re-arm hazard: the replay had no FIN
             * and no error, so without the cancel-aware arm gate the outer
             * resume would arm a receive on the stream the callback just
             * aborted. */
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0);
            dom_drain(drv); /* run the queued buffer destructor */
            WTQ_TEST_CHECK_EQ_INT(dtor, 1);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.reentry_fired, 1);
            WTQ_TEST_CHECK_EQ_INT((int)cl.reentry_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(boom) &&
                           memcmp(cl.rx, boom, sizeof(boom)) == 0);
            cl.reentry_action = REENTRY_NONE;
            cl.reentry_target = NULL;
            pthread_mutex_unlock(&cl.mu);
            /* the aborted stream stays closed to resume */
            WTQ_TEST_CHECK(dom_resume(drv, b) != WTQ_OK);
        }
        dom_stream_release(drv, b);
    }

    /* (5) replayed data callback CLOSES THE SESSION (runs LAST — it ends
     * the connection): delivery/disposal exactly once, close accepted, and
     * the teardown the close performed must not let the outer resume arm. */
    {
        wtq_stream_t *b = NULL;
        WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
        struct wtq_dstream *ds = dom_find_paused_bidi(drv);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            static const uint8_t last[4] = { 'l', 'a', 's', 't' };
            int dtor = 0;
            pthread_mutex_lock(&cl.mu);
            cl.rx_len = 0;
            cl.reentry_target = b;
            cl.reentry_session = cs;
            cl.reentry_action = REENTRY_CLOSE_SESSION;
            cl.reentry_rc = WTQ_ERR_STATE;
            cl.reentry_fired = 0;
            pthread_mutex_unlock(&cl.mu);
            dom_inject_recv_counted(drv, ds, last, sizeof(last), false,
                                    &dtor);
            WTQ_TEST_CHECK(dom_ds_deferred(drv, ds));
            unsigned arms0 = dom_ds_arms(drv, ds);
            bool defd = true;
            unsigned arms1 = arms0;
            WTQ_TEST_CHECK_EQ_INT(
                (int)dom_resume_snap(drv, b, ds, &defd, &arms1), (int)WTQ_OK);
            WTQ_TEST_CHECK(!defd);
            WTQ_TEST_CHECK_EQ_INT((int)(arms1 - arms0), 0); /* no arm after
                                                               the close's
                                                               teardown */
            dom_drain(drv); /* run the queued buffer destructor */
            WTQ_TEST_CHECK_EQ_INT(dtor, 1);
            pthread_mutex_lock(&cl.mu);
            WTQ_TEST_CHECK_EQ_INT(cl.reentry_fired, 1);
            WTQ_TEST_CHECK_EQ_INT((int)cl.reentry_rc, (int)WTQ_OK);
            WTQ_TEST_CHECK(cl.rx_len == sizeof(last) &&
                           memcmp(cl.rx, last, sizeof(last)) == 0);
            WTQ_TEST_CHECK_EQ_INT(cl.closed, 1); /* the close landed */
            cl.reentry_action = REENTRY_NONE;
            cl.reentry_target = NULL;
            cl.reentry_session = NULL;
            pthread_mutex_unlock(&cl.mu);
        }
        dom_stream_release(drv, b);
    }

    /* the session was closed by case (5); run the transport down */
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: recv_replay_reentrant\n");
    return failures;
}

/*
 * SINGLE-SLOT INVARIANT — a second completion deferred while one is held is
 * impossible by design (one receive is ever armed). If it ever happened the
 * backend must NOT silently drop the peer's bytes: it stages a local
 * backend error and fails the CONNECTION, like the missing-metadata
 * invariant. Its own connection because the outcome is terminal.
 */
static int t_recv_defer_invariant(uint16_t port, struct side *sv)
{
    int failures = 0;
    struct side cl;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    static const char *const offer[] = { "wt" };

    (void)sv;
    side_init(&cl);
    cl.echo_streams = false;
    ring_reset();
    wtq_nw_test_recv_defer_overflow = 0;

    if (!nw_client_up_ready(&cl, port, "/nw", offer, 1, NULL, &drv, &cs)) {
        side_destroy(&cl);
        return failures + 1;
    }

    wtq_stream_t *b = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);
    struct wtq_dstream *ds = dom_find_paused_bidi(drv);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        static const uint8_t one[3] = { 'o', 'n', 'e' };
        static const uint8_t two[3] = { 't', 'w', 'o' };
        dom_inject_recv(drv, ds, one, sizeof(one), false); /* held */
        dom_inject_recv(drv, ds, two, sizeof(two), false); /* invariant */
        WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_recv_defer_overflow, 1);
        /* the second deferral staged a backend error and failed the
         * connection — never a silent data drop */
        __block bool staged = false, backend = false, shut = false;
        dispatch_sync(drv->queue, ^{
          staged = drv->err_staged;
          backend = drv->err_domain == WTQ_ERRDOM_BACKEND;
          shut = drv->shutdown_started;
        });
        WTQ_TEST_CHECK(staged);
        WTQ_TEST_CHECK(backend);
        WTQ_TEST_CHECK(shut);
        WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.closed, 1)); /* terminal */
    }
    dom_stream_release(drv, b);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: recv_defer_invariant\n");
    return failures;
}

/*
 * DEFERRAL BARRIER — real-transport proof that a paused stream's completion
 * is HELD in the backend deferral and delivers NOTHING to the app while the
 * connection keeps progressing. Its own MsQuic listener/server so the
 * payload-send accounting is isolated. THE barrier is the target stream's
 * OWN deferral event (test-seam hook, fired on the domain the instant its
 * completion is held) — a direct same-stream observation; deliberately NO
 * transport ACK is used to order application callbacks across independent
 * QUIC streams (QUIC provides no such ordering). Progress while held is
 * proven independently AFTER the barrier: a second stream completes a full
 * echo round-trip while the target remains deferred with zero app delivery.
 * Resume then yields the whole payload and FIN, byte-exact and in order.
 * Barriers are callbacks/conditions only — no sleeps, no polling.
 *
 * SCOPE: application-delivery isolation only. NW auto-tunes and buffers past
 * the public initial-window setters, so no peer flow-control bound is
 * claimed or asserted (see COMPATIBILITY.md).
 */
static int t_recv_defer_barrier(wtq_msquic_env_t *env)
{
    int failures = 0;
    struct side cl, sv_b;
    struct wtq_driver *drv = NULL;
    wtq_session_t *cs = NULL;
    wtq_msquic_listener_t *lb = NULL;
    static const char *const offer[] = { "wtq-nw-test" };

    side_init(&cl);
    side_init(&sv_b);
    sv_b.payload_barrier = true;
    sv_b.echo_streams = true; /* the progress stream round-trips via echo */
    cl.verify_barrier = true;
    ring_reset();

    WTQ_TEST_CHECK_EQ_INT((int)listener_up(env, &sv_b, &lb), (int)WTQ_OK);
    if (lb == NULL) {
        side_destroy(&cl);
        side_destroy(&sv_b);
        return failures + 1;
    }

    bool up = nw_client_up_ready(&cl, wtq_msquic_listener_port(lb), "/nw",
                                 offer, 1, NULL, &drv, &cs);
    WTQ_TEST_CHECK(up);
    if (!up) {
        wtq_msquic_listener_stop(lb);
        side_destroy(&cl);
        side_destroy(&sv_b);
        return failures + 1;
    }

    /* the target bidi: arm its receive, then pause with ONE outstanding */
    wtq_stream_t *b = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b), (int)WTQ_OK);
    struct wtq_dstream *dsb = dom_capture_bidi(drv, b); /* arms a receive */
    WTQ_TEST_CHECK(dsb != NULL);
    __block bool armed = false;
    if (dsb != NULL)
        dispatch_sync(drv->queue, ^{ armed = dsb->recv_pending; });
    WTQ_TEST_CHECK(armed);
    /* per-stream attribution + the deferral hook, installed BEFORE the
     * request so the event cannot be missed */
    pthread_mutex_lock(&cl.mu);
    cl.barrier_target_st = b;
    pthread_mutex_unlock(&cl.mu);
    g_defer_side = &cl;
    g_defer_ds = dsb;
    wtq_nw_test_defer_hook = barrier_defer_hook;
    WTQ_TEST_CHECK_EQ_INT((int)dom_pause(drv, b), (int)WTQ_OK);

    /* the request — the server answers with the whole payload + FIN */
    static const uint8_t go[2] = { 'g', 'o' };
    wtq_span_t rq = { go, sizeof(go) };
    WTQ_TEST_CHECK_EQ_INT(
        (int)dom_send(drv, b, &rq, 1, WTQ_SEND_FIN, NULL), (int)WTQ_OK);

    /* THE barrier: the target's OWN completion was held in the backend
     * deferral (the real deferred path ran) and the app has seen nothing. */
    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.defer_events, 1));
    WTQ_TEST_CHECK(dom_ds_deferred(drv, dsb));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_SIZE(cl.barrier_total, 0); /* nothing to the app */
    pthread_mutex_unlock(&cl.mu);

    /* independent progress proof: a full echo round-trip on ANOTHER stream
     * completes while the target stays held and silent */
    wtq_stream_t *b2 = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)dom_open_bidi(drv, cs, &b2), (int)WTQ_OK);
    static const uint8_t ping[4] = { 'p', 'i', 'n', 'g' };
    wtq_span_t p2 = { ping, sizeof(ping) };
    WTQ_TEST_CHECK_EQ_INT(
        (int)dom_send(drv, b2, &p2, 1, WTQ_SEND_FIN, NULL), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.other_fins, 1));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_INT(cl.other_total, (int)sizeof(ping)); /* echoed */
    WTQ_TEST_CHECK_EQ_SIZE(cl.barrier_total, 0); /* target still silent */
    pthread_mutex_unlock(&cl.mu);
    WTQ_TEST_CHECK(dom_ds_deferred(drv, dsb)); /* ...and still held */

    /* only now resume; the whole payload + FIN follows, byte-exact */
    WTQ_TEST_CHECK_EQ_INT((int)dom_resume(drv, b), (int)WTQ_OK);
    WTQ_TEST_CHECK(side_wait_ge(&cl, &cl.barrier_fins, 1));
    pthread_mutex_lock(&cl.mu);
    WTQ_TEST_CHECK_EQ_SIZE(cl.barrier_total, (size_t)BARRIER_TOTAL);
    WTQ_TEST_CHECK_EQ_SIZE(cl.barrier_mismatch, 0);
    WTQ_TEST_CHECK_EQ_INT(cl.barrier_fins, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.defer_events, 1); /* held exactly once */
    pthread_mutex_unlock(&cl.mu);

    /* the payload send completed exactly once, with no send failure */
    WTQ_TEST_CHECK(side_wait_ctx(&sv_b, &g_payload_ctx, 1));
    WTQ_TEST_CHECK_EQ_INT(side_ctx_completions(&sv_b, &g_payload_ctx), 1);
    pthread_mutex_lock(&sv_b.mu);
    WTQ_TEST_CHECK_EQ_INT(sv_b.barrier_send_errors, 0);
    pthread_mutex_unlock(&sv_b.mu);

    wtq_nw_test_defer_hook = NULL; /* uninstall before teardown */
    g_defer_side = NULL;
    g_defer_ds = NULL;
    dom_stream_release(drv, b2);
    dom_stream_release(drv, b);
    WTQ_TEST_CHECK_EQ_INT((int)dom_close(drv, cs, 0), (int)WTQ_OK);
    WTQ_TEST_CHECK(wtq_nw_conn_rundown_internal(drv, WAIT_MS));
    wtq_msquic_listener_stop(lb);
    side_destroy(&cl);
    side_destroy(&sv_b);
    if (failures == 0)
        printf("PASS: recv_defer_barrier\n");
    return failures;
}

/* --- main ---------------------------------------------------------------- */

int main(int argc, char **argv)
{
    int failures = 0;

    if (certs_locate(argc > 1 ? argv[1] : NULL) != 0)
        return 1;
    for (size_t i = 0; i < sizeof(g_barrier_payload); i++)
        g_barrier_payload[i] = barrier_pat(i); /* deterministic verify */
    if (getenv("WTQ_NW_WAIT_MS") != NULL) {
        g_wait_ms = atoi(getenv("WTQ_NW_WAIT_MS"));
        if (g_wait_ms < 1000)
            g_wait_ms = 20000;
    }
    if (getenv("WTQ_NW_ESTABLISH_RETRIES") != NULL) {
        g_est_retries = atoi(getenv("WTQ_NW_ESTABLISH_RETRIES"));
        if (g_est_retries < 0 || g_est_retries > 4)
            g_est_retries = 0;
    }
    if (getenv("WTQ_NW_PARK_REAPS") != NULL)
        wtq_nw_test_park_reaps = 1; /* diagnostic leak-everything mode */
    if (getenv("WTQ_NW_TEARDOWN") != NULL)
        wtq_nw_test_teardown_variant = atoi(getenv("WTQ_NW_TEARDOWN"));

    int runs = 1;
    const char *runs_env = getenv("WTQ_NW_LOOPBACK_RUNS");
    if (runs_env != NULL)
        runs = atoi(runs_env);
    if (runs < 1)
        runs = 1;
    if (getenv("WTQ_NW_SKIP_MAIN") != NULL)
        runs = 0; /* churn/growth-only process (diagnostic variants) */

    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT((int)wtq_msquic_env_open(&ecfg, &env),
                          (int)WTQ_OK);
    if (env == NULL)
        return failures + 1;

    side_init(&g_sv);
    g_sv.echo_streams = true;

    /* the server's event table: the shared callbacks plus the harness
     * command layer */
    wtq_msquic_listener_t *listener = NULL;
    {
        static const char *protos_storage[2];
        wtq_session_events_t ev;
        wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
        wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

        protos_storage[0] = ESCAPED_PROTO;
        protos_storage[1] = "wtq-nw-test";
        events_for(&ev);
        ev.on_datagram = sv_datagram;
        ev.on_stream_opened = sv_stream_opened;
        serve.path = "/nw";
        serve.subprotocols = protos_storage;
        serve.subprotocol_count = 2;
        cfg.bind_address = "127.0.0.1";
        cfg.port = 0;
        cfg.cert_file = cert_path;
        cfg.key_file = key_path;
        cfg.paths = &serve;
        cfg.path_count = 1;
        cfg.events = &ev;
        cfg.user = &g_sv;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_msquic_listener_start(env, &cfg, &listener),
            (int)WTQ_OK);
    }
    if (listener == NULL) {
        wtq_msquic_env_close(env);
        return failures + 1;
    }
    uint16_t port = wtq_msquic_listener_port(listener);

    for (int run = 0; run < runs; run++) {
        int before = failures;

        failures += t_establish_traffic(env, port);
        failures += t_recv_pause(port, &g_sv);
        failures += t_recv_reset_deferred(port, &g_sv);
        failures += t_recv_replay_reentrant(port, &g_sv);
        failures += t_recv_defer_invariant(port, &g_sv);
        failures += t_recv_defer_barrier(env);
        failures += t_abort_wire(port, &g_sv);
        failures += t_send_completions(port, &g_sv);
        failures += t_refusal(port);
        failures += t_concat_failure(port, &g_sv);
        failures += t_teardown_orders(port, &g_sv);
        failures += t_holder_foreign();
        failures += t_alloc_failures(port, &g_sv);
        failures += t_meta_missing(port, &g_sv);
        failures += t_meta_recovers(port, &g_sv);
        failures += t_conn_loss_error();
        failures += t_wait_predicate();
        failures += t_cnt_allocator_semantics();
        failures += t_close_flush_ordering(env);
        failures += t_setup_failure_restores_seams(env);
        failures += t_current_clean_close(env);
        failures += t_fatal_shutdown_with_owed_sends(env);
        failures += t_stop_begin_with_held_close(env);
        failures += t_deferred_shutdown_convergence(env);
        {
            struct side psv;
            wtq_msquic_listener_t *pl = NULL;
            side_init(&psv);
            if (listener_up_profiles(env, &psv,
                                     WTQ_WEBTRANSPORT_PROFILES_ALL,
                                     &pl) == WTQ_OK && pl != NULL) {
                const uint16_t pport = wtq_msquic_listener_port(pl);
                failures += t_watch_keying_and_lifetime(env, pport, &psv);
                failures += t_phase_order_both(env, pport, &psv, true);
                failures += t_phase_order_both(env, pport, &psv, false);
                wtq_msquic_listener_stop(pl);
            } else {
                failures++;
            }
            side_destroy(&psv);
        }
        failures += t_nw_d02_profile(env);
        if (failures != before) {
            fprintf(stderr, "run %d/%d FAILED\n", run + 1, runs);
            break;
        }
        if (runs > 1)
            fprintf(stderr, "run %d/%d ok\n", run + 1, runs);
    }

    if (getenv("WTQ_NW_CHURN") != NULL && failures == 0) {
        int churn_n = atoi(getenv("WTQ_NW_CHURN"));
        failures += t_churn(port, &g_sv, churn_n);
        failures += t_reject_churn(port, &g_sv,
                                   churn_n < 100 ? churn_n : 100);
    }

    (void)listener_up; /* alternate-listener helper reserved */
    wtq_msquic_listener_stop(listener);
    wtq_msquic_env_close(env);

    /* ownership accounting: nothing pending, nothing leaked, every
     * accepted echo record completed exactly once */
    pthread_mutex_lock(&g_sv.mu);
    WTQ_TEST_CHECK_EQ_INT(g_sv.echo_fifo_n, 0);
    WTQ_TEST_CHECK_EQ_INT(g_sv.echo_accepted, g_sv.echo_completed);
    WTQ_TEST_CHECK_EQ_INT(g_sv.echo_dropped, 0);
    WTQ_TEST_CHECK_EQ_INT(g_sv.echo_bad_transition, 0);
    int busy = 0;
    for (int i = 0; i < ECHO_RECS; i++)
        if (g_sv.echo[i].state != ECHO_FREE)
            busy++;
    WTQ_TEST_CHECK_EQ_INT(busy, 0); /* all refs released */
    if (g_sv.echo_purged != 0)
        fprintf(stderr, "note: %d queued echoes purged at stream "
                        "terminal (test-visible, not a failure)\n",
                g_sv.echo_purged);
    if (g_sv.echo_fin_races != 0)
        fprintf(stderr, "note: %d FIN-only echoes lost to a peer-teardown "
                        "race (test-visible, not a failure)\n",
                g_sv.echo_fin_races);
    pthread_mutex_unlock(&g_sv.mu);

    /* environmental-retry accounting: infrastructure information,
     * reported separately; ZERO by definition on normal gates */
    fprintf(stderr, "establishment retries: %d (allowed %d)\n",
            g_est_retry_count, g_est_retries);
    if (g_est_retries == 0)
        WTQ_TEST_CHECK_EQ_INT(g_est_retry_count, 0);

    /* deferred-reaping proof: every stream destruction ran through the
     * reaper, in a later queue turn, NEVER inside an NW callback frame */
    fprintf(stderr,
            "reap counters: run=%d in_cb=%d detach_in_cb=%d "
            "release_in_cb=%d order_bad=%d\n",
            wtq_nw_test_reaps_run, wtq_nw_test_reaps_in_callback,
            wtq_nw_test_detach_in_cb, wtq_nw_test_release_in_cb,
            wtq_nw_test_order_bad);
    fprintf(stderr,
            "reap gates: state=%d recv=%d complete=%d retire=%d "
            "rundown=%d detach=%d\n",
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_STATE],
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RECV],
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_COMPLETE],
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RETIRE],
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_RUNDOWN],
            wtq_nw_test_reap_src[WTQ_NW_REAP_SRC_DETACH]);
    fprintf(stderr,
            "dgram reaps: run=%d detach_in_cb=%d release_in_cb=%d "
            "gates state=%d recv=%d complete=%d rundown=%d\n",
            wtq_nw_test_dgram_reaps_run, wtq_nw_test_dgram_detach_in_cb,
            wtq_nw_test_dgram_release_in_cb,
            wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC_STATE],
            wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC_RECV],
            wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC_COMPLETE],
            wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC_RUNDOWN]);
    /* the dgram flow is torn down two-phase as well: it reaped on
     * every clean connection, never detached or released in-callback */
    WTQ_TEST_CHECK(wtq_nw_test_dgram_reaps_run > 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_dgram_detach_in_cb, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_dgram_release_in_cb, 0);
    if (wtq_nw_test_teardown_variant != 2) /* quarantine never phase-2s */
        WTQ_TEST_CHECK(wtq_nw_test_reaps_run > 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_reaps_in_callback, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_detach_in_cb, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_release_in_cb, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_nw_test_order_bad, 0);
    if (wtq_nw_test_teardown_variant == 2)
        fprintf(stderr, "quarantine peak: %d\n",
                wtq_nw_test_quarantined_peak);
    side_destroy(&g_sv);

    WTQ_TEST_PASS("test_nw_loopback");
    return failures;
}
