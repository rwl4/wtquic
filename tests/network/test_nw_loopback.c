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

    (void)s;
    pthread_mutex_lock(&sd->mu);
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

static wtq_result_t nw_client_up_alloc(struct side *sd, uint16_t port,
                                       const char *path,
                                       const char *const *protos,
                                       size_t nprotos,
                                       const wtq_alloc_t *alloc,
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
static bool nw_client_up_ready(struct side *cl, uint16_t port,
                               const char *path,
                               const char *const *protos, size_t nprotos,
                               const wtq_alloc_t *alloc,
                               struct wtq_driver **drv_out,
                               wtq_session_t **cs_out)
{
    for (int attempt = 0; attempt < 1 + g_est_retries; attempt++) {
        struct wtq_driver *drv = NULL;
        wtq_session_t *cs = NULL;

        if (nw_client_up_alloc(cl, port, path, protos, nprotos, alloc,
                               &drv, &cs) != WTQ_OK ||
            cs == NULL)
            return false;
        /* wait for ANY session outcome */
        bool est = false, done = false;
        for (int i = 0; i < WAIT_MS / 10 && !done; i++) {
            pthread_mutex_lock(&cl->mu);
            est = cl->established > 0;
            done = est || cl->failed > 0 || cl->closed > 0;
            pthread_mutex_unlock(&cl->mu);
            if (!done) {
                struct timespec ts = { 0, 10 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
        }
        if (est) {
            *drv_out = drv;
            *cs_out = cs;
            return true;
        }
        pthread_mutex_lock(&cl->mu);
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
        (void)wtq_nw_conn_rundown_internal(drv, WAIT_MS);
        wtq_session_release(cs);
        if (!more)
            return false; /* not environmental, retries disabled, or
                             the bound is spent: the test sees it */
        g_est_retry_count++; /* counted at the START of a real retry */
    }
    return false;
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
