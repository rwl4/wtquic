/*
 * Network.framework client backend — attach core (slice 5).
 *
 * Grounded in the committed capability probe (backends/
 * network_experimental) and §§2-7 of the stream-identity design:
 *
 *  - IDs are ASYNC: local opens report WTQ_STREAM_ID_UNKNOWN; the native
 *    id is read from the stream's QUIC metadata at `ready` and reported
 *    through the dstream's CURRENT ectx (never a cached estream).
 *  - Inbound streams stay invisible to the engine until ready; direction
 *    and initiator come from the id bits (nw_quic_get_stream_type is
 *    unreliable — probe-proven). NW's own hidden client-initiated
 *    streams (client-bidi 0 on a multiplex group) are parked in the
 *    backend and never surfaced: they occupy NO engine pool slot.
 *  - Per-stream options: NW aliases the copied transport options, so
 *    "set every stream flag + extract" is one indivisible on-domain
 *    operation (§7.3 rule 5), always via the GROUP's options — a fresh
 *    nw_quic_create_options() re-specifies the protocol and kills the
 *    stream (probe: posix/50).
 *  - Shutdown: no WTQ_DCAP_SHUT_* bits. The baseline is exact: the sole
 *    half of a uni stream, or both bidi halves with ONE code, via
 *    stamped cancel (stamp the application error, then cancel — the
 *    peer observes RESET_STREAM and STOP_SENDING with that code).
 *  - Sends: two-phase records (§3.3). The app reference is discharged
 *    exactly once through wtq_conn_on_send_complete (real completion,
 *    or the deduplicated synthetic fallback at rundown); the transport
 *    reference is owned by an ARC holder captured by Apple's completion
 *    block and released from its dealloc (nw_send_holder.m). Cancel
 *    forces pending completion retirement (measured: exactly once,
 *    posix/89, disposed at the same stage).
 *  - Received STOP_SENDING has no public signal (standing limitation):
 *    it is never inferred, and the bounded ring + forced retirement is
 *    what keeps the send path live.
 *  - Errors: POSIX/DNS/TLS nw_error_t detail is mapped into the
 *    transport-error record BEFORE the terminal engine input. No peer
 *    application-close codes or QUIC transport codes are fabricated;
 *    first-causal and sealed-record semantics stay engine-owned.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nw_internal.h"

#include <Security/Security.h>

/*
 * The PUBLIC handle (managed lifecycle). Reference-counted
 * by the application; its memory lives until the public refs hit zero
 * AND the lifecycle finished (whichever transition happens second
 * frees it, under `mu`). It never owns the transport: the driver is
 * the internal root, pinned by live shells/dgram/lifecycle (see
 * nw_internal.h) so a straggler holder disposal can never land on
 * freed memory whatever the application did with this handle.
 */
/*
 * Startup state machine (guarded by mu). Network.framework drops inbound
 * streams pending at group READY unless nw_connection_group_start() runs
 * on the MAIN thread (proven, platform defect). So an off-main creator
 * schedules the start on the main dispatch queue; the start therefore may
 * be deferred past create()'s return, and a stop can arrive before the
 * group has started. QUEUED -> STARTING -> STARTED tracks the trampoline;
 * stop_enqueued makes the ordered stop-worker enqueue exactly-once whether
 * it is driven by stop_begin (already STARTED) or by the trampoline
 * (stop latched while QUEUED/STARTING).
 */
enum { NW_START_QUEUED = 0, NW_START_STARTING, NW_START_STARTED };

struct wtq_nw_conn {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int refs;             /* public references                        */
    bool closed;          /* the acceptance latch (posts reject)      */
    bool stop_started;    /* stop_begin latched (idempotence)         */
    int start_state;      /* NW_START_* (main-thread start ordering)  */
    bool stop_enqueued;   /* nw_stop_worker enqueued exactly once     */
    bool stopped_done;    /* on_stopped delivered (join gate)         */
    bool lifecycle_over;  /* internal callback reference returned     */
    bool internal_gone;   /* driver root freed (test quiesce gate)    */
    struct wtq_driver *drv; /* valid until lifecycle_over             */
    void (*on_stopped)(void *ctx);
    void *stopped_ctx;
    /* the doorbell: a preallocated coalescing wake source targeting
     * the domain queue. doorbell_src is guarded by mu (ring reads it
     * under mu; the finish worker NULLs it under mu before cancel);
     * the fn/ctx pair is immutable after create. */
    dispatch_source_t doorbell_src;
    void (*on_doorbell)(void *ctx);
    void *doorbell_ctx;
    wtq_alloc_t alloc;    /* frees this handle                        */
};

static void nw_conn_handle_free(struct wtq_nw_conn *c)
{
    wtq_alloc_t alloc = c->alloc;

    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->cv);
    alloc.free(c, sizeof(*c), alloc.ctx);
}

static void drv_free_if_done(struct wtq_driver *drv);
static void nw_maybe_schedule_finish(struct wtq_driver *drv);

#include "proto/h3_err.h"

static bool nw_dbg(void)
{
    static int on = -1;
    if (on < 0)
        on = getenv("WTQ_NW_DEBUG") != NULL ? 1 : 0;
    return on == 1;
}
#define NWDBG(...) do { if (nw_dbg()) fprintf(stderr, "[nw] " __VA_ARGS__); } while (0)

static uint64_t nw_now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* --- engine bracket ---------------------------------------------------- */

static void conn_poll_shutdown(struct wtq_driver *drv);

static void nw_leave_and_poll(struct wtq_driver *drv)
{
    if (drv->session == NULL)
        return;
    if (wtq_api_session_leave(drv->session)) {
        /* deferred destroy fired: session and engine conn are gone */
        drv->session = NULL;
        return;
    }
    conn_poll_shutdown(drv);
}

/* --- error mapping ------------------------------------------------------ */

/*
 * Stage the FIRST nw_error_t observed for the transport-error record.
 * kind LOCAL always: NW exposes no peer application-close code and no
 * QUIC transport wire code — fabricating either is forbidden. The
 * native domain/code carry the full fidelity NW does provide.
 */
static void stage_nw_error(struct wtq_driver *drv, nw_error_t e)
{
    if (drv->err_staged || e == NULL)
        return;
    drv->err_staged = true;
    drv->err_kind = WTQ_ERR_KIND_LOCAL;
    switch (nw_error_get_error_domain(e)) {
    case nw_error_domain_posix:
        drv->err_domain = WTQ_ERRDOM_NW_POSIX;
        break;
    case nw_error_domain_dns:
        drv->err_domain = WTQ_ERRDOM_NW_DNS;
        break;
    case nw_error_domain_tls:
        drv->err_domain = WTQ_ERRDOM_NW_TLS;
        break;
    default:
        drv->err_domain = WTQ_ERRDOM_BACKEND;
        break;
    }
    drv->err_code = (int64_t)nw_error_get_error_code(e);
}

/* Deliver staged detail immediately before the terminal engine input. */
static void put_error_detail(struct wtq_driver *drv)
{
    if (!drv->err_staged || drv->session == NULL)
        return;
    wtq_transport_error_t rec = {
        .struct_size = (uint32_t)sizeof(rec),
        .kind = drv->err_kind,
        .quic_code = 0,
        .native_domain = drv->err_domain,
        .native_code = drv->err_code,
    };
    wtq_conn_set_transport_error(wtq_api_session_conn(drv->session), &rec);
}

/* --- send records (§3.3) ------------------------------------------------ */

static void ds_maybe_free(struct wtq_dstream *ds, enum wtq_nw_reap_src src);
static void ds_pump_sends(struct wtq_dstream *ds);
static void dgram_maybe_reap(struct wtq_driver *drv,
                             enum wtq_nw_reap_src src);
static void ds_drop_pending_sends(struct wtq_dstream *ds);
static wtq_result_t op_conn_close(wtq_driver_t *drv, uint64_t h3_err);

/* APP_COMPLETED: deliver the engine completion exactly once. */
static void rec_app_complete(struct wtq_nw_send_rec *rec, bool canceled)
{
    struct wtq_dstream *ds = rec->ds;
    struct wtq_driver *drv = ds->drv;

    if (rec->app_done)
        return; /* deduplicated: synthetic already delivered */
    rec->app_done = true;
    ds->recs_app_pending--;
    ds->inflight_bytes -= rec->bytes;
    /* the completion released window capacity: deliver the blocked->
     * writable edge (once per transition) after the completion */
    bool edge = ds->send_blocked && !ds->terminal && !ds->cancel_issued;
    if (edge)
        ds->send_blocked = false;
    if (drv->session != NULL) {
        wtq_api_session_enter(drv->session);
        wtq_conn_t *ec = wtq_api_session_conn(drv->session);
        wtq_conn_on_send_complete(ec, rec->cookie, canceled);
        if (edge && ds->ectx != NULL)
            wtq_conn_on_stream_writable(ec, ds->ectx);
        nw_leave_and_poll(drv);
    }
}

/* Synthetic fallback at rundown: dedupe via the app-ref state. */
static void ds_synthesize_completions(struct wtq_dstream *ds)
{
    for (int i = 0; i < WTQ_NW_SEND_RECORDS; i++) {
        struct wtq_nw_send_rec *rec = &ds->recs[i];

        if (rec->in_use && !rec->app_done)
            rec_app_complete(rec, true);
        if (rec->in_use && rec->app_done && rec->transport_done)
            rec->in_use = false;
    }
}

/* --- stream lifetime ----------------------------------------------------- */

/*
 * A dstream is freeable only when the transport is terminal, no receive
 * block is outstanding, and every send record is TRANSPORT_RETIRED —
 * an undisposed completion block still references its record (§3.3);
 * until it retires, the stream (and through it the connection root)
 * simply stays alive. Correctness never depends on when.
 */
static bool ds_reap_eligible(const struct wtq_dstream *ds)
{
    return ds->terminal && !ds->recv_pending &&
           ds->recs_unretired == 0 && ds->recs_app_pending == 0 &&
           ds->batches_live == 0;
}

/* PHASE 2: release the connection and free the shell — only after
 * phase 1 detached the handler, in yet another queue turn, never
 * inside an NW callback frame. The ONLY destruction path. */
static void ds_reap_phase2(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;

    WTQ_NW_TEST(wtq_nw_test_reaps_run++);
    WTQ_NW_TEST(if (drv->callback_depth != 0)
                    wtq_nw_test_reaps_in_callback++);
    WTQ_NW_TEST(if (!ds->handler_detached) wtq_nw_test_order_bad++);
#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_park_reaps)
        return; /* diagnostic: hold every object forever */
#endif
    if (ds->conn != NULL) {
        WTQ_NW_TEST(if (drv->callback_depth != 0)
                        wtq_nw_test_release_in_cb++);
        nw_release(ds->conn);
        ds->conn = NULL;
    }
    if (ds->engine_known && !ds->engine_detached && !drv->closed_fed) {
        /* the ENGINE may still name this ds (es->ds, or a critical-
         * stream pointer): the transport handle is gone but the STRUCT
         * stays — every op on a handleless shell returns CLOSED — until
         * op_detach or the connection terminal re-arms the reap. This
         * is the msquic policy: the handle releases at the stream
         * terminal; the struct lives until the linkage is severed. */
        ds->reap_scheduled = false;
        return;
    }
    struct wtq_dstream **pp = &drv->streams;
    while (*pp != NULL && *pp != ds)
        pp = &(*pp)->next;
    if (*pp == ds)
        *pp = ds->next;
    drv->alloc.free(ds, sizeof(*ds), drv->alloc.ctx);
    drv->pins--;
    drv_free_if_done(drv);
}

/* PHASE 1: a queue turn after eligibility — detach the state handler
 * (the documented removal mechanism), then schedule phase 2 in yet
 * another turn. (The diagnostic quarantine variant instead parks the
 * handle + shell until group rundown — the linear-growth arm.) */
static void ds_reap_phase1(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;

    if (ds->conn != NULL) {
        WTQ_NW_TEST(if (drv->callback_depth != 0)
                        wtq_nw_test_detach_in_cb++);
        nw_connection_set_state_changed_handler(ds->conn, NULL);
    }
    ds->handler_detached = true;
#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_teardown_variant == 2) {
        /* quarantine: hold the handle + shell until group rundown */
        ds->quarantined = true;
        int n = 0;
        for (struct wtq_dstream *d = drv->streams; d != NULL; d = d->next)
            if (d->quarantined)
                n++;
        if (n > wtq_nw_test_quarantined_peak)
            wtq_nw_test_quarantined_peak = n;
        return;
    }
#endif
    struct wtq_dstream *cap = ds;
    dispatch_async(drv->queue, ^{
      if (ds_reap_eligible(cap) && cap->handler_detached)
          ds_reap_phase2(cap);
      else
          cap->reap_scheduled = false; /* reschedulable */
    });
}

/*
 * Eligibility may be DETECTED inside any callback; destruction is
 * DEFERRED across TWO queue turns (detach, then release). The latch
 * guarantees exactly one in-flight reap however many paths (receive,
 * state, completion, retirement) notice eligibility; each phase
 * re-checks and clears the latch when a new transition made the
 * stream live again.
 */
static void ds_maybe_free(struct wtq_dstream *ds, enum wtq_nw_reap_src src)
{
    if (ds->reap_scheduled || ds->quarantined || !ds_reap_eligible(ds))
        return;
    ds->reap_scheduled = true;
    WTQ_NW_TEST(wtq_nw_test_reap_src[src]++);
    (void)src;
    struct wtq_dstream *cap = ds;
    dispatch_async(ds->drv->queue, ^{
      if (ds_reap_eligible(cap))
          ds_reap_phase1(cap);
      else
          cap->reap_scheduled = false;
    });
}

static struct wtq_dstream *ds_new(struct wtq_driver *drv, bool is_local,
                                  bool is_bidi)
{
    struct wtq_dstream *ds =
        drv->alloc.alloc(sizeof(*ds), drv->alloc.ctx);

    if (ds == NULL)
        return NULL;
    memset(ds, 0, sizeof(*ds));
    ds->drv = drv;
    ds->id = WTQ_STREAM_ID_UNKNOWN;
    ds->is_local = is_local;
    ds->is_bidi = is_bidi;
    ds->recv_enabled = true;
    ds->next = drv->streams;
    drv->streams = ds;
    drv->pins++; /* a live shell pins the internal root */
    return ds;
}

/* --- per-stream QUIC metadata ------------------------------------------- */

static nw_protocol_metadata_t stream_quic_metadata(nw_connection_t c)
{
    nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(c, def);

    nw_release(def);
    return md; /* caller releases */
}

static uint64_t stream_native_id(nw_connection_t c, bool *ok)
{
    nw_protocol_metadata_t md = stream_quic_metadata(c);

    *ok = false;
    if (md == NULL)
        return WTQ_STREAM_ID_UNKNOWN;
    uint64_t id = nw_quic_get_stream_id(md);
    nw_release(md);
    *ok = true;
    return id;
}

/* The peer's RESET code (the app-error getters are receive-side). */
static bool stream_peer_reset_code(nw_connection_t c, uint64_t *code)
{
    nw_protocol_metadata_t md = stream_quic_metadata(c);

    if (md == NULL)
        return false;
    bool has = nw_quic_get_stream_application_error(md) != UINT64_MAX;
    if (has)
        *code = nw_quic_get_stream_application_error(md);
    nw_release(md);
    return has;
}

/* --- the per-stream send chain -------------------------------------------- */

/*
 * The send chain (see wtq_nw_pending_send in nw_internal.h): QUIC
 * stream sends use the default STREAM context exclusively —
 * is_complete=true there IS the write-side FIN, attachable to content.
 * (The MESSAGE contexts are for datagram-style protocols; a mixed
 * context lineage on a stream loses buffered content — measured.)
 * At most one nw_connection_send is in flight per stream; the next is
 * issued from the previous one's completion.
 */
/* Batch completion: fan out to every carried record, exactly once
 * each; the batch frees when BOTH phases (completion + retire) ran. */
static void batch_on_complete(void *ctx, bool canceled)
{
    struct wtq_nw_send_batch *b = ctx;
    struct wtq_dstream *ds = b->ds;
    struct wtq_driver *drv = ds->drv;

    drv->callback_depth++; /* NW's completion frame */
    NWDBG("batch complete id=%llu nrecs=%d canceled=%d\n",
          (unsigned long long)ds->id, b->nrecs, (int)canceled);
    ds->send_inflight = false;
    for (int i = 0; i < b->nrecs; i++) {
        rec_app_complete(b->recs[i], canceled);
        if (b->recs[i]->transport_done && b->recs[i]->app_done)
            b->recs[i]->in_use = false;
    }
    bool last = ++b->phases_done == 2;
    if (last) {
        drv->alloc.free(b, sizeof(*b), drv->alloc.ctx);
        ds->batches_live--;
    }
    ds_pump_sends(ds);
    ds_maybe_free(ds, WTQ_NW_REAP_SRC_COMPLETE); /* schedules only */
    drv->callback_depth--;
}

static void batch_on_retire(void *ctx)
{
    struct wtq_nw_send_batch *b = ctx;
    struct wtq_dstream *ds = b->ds;
    struct wtq_driver *drv = ds->drv;
    bool freed_slot = false;

    for (int i = 0; i < b->nrecs; i++) {
        struct wtq_nw_send_rec *rec = b->recs[i];
        rec->transport_done = true;
        ds->recs_unretired--;
        if (rec->app_done) {
            rec->in_use = false;
            freed_slot = true;
        }
    }
    bool last = ++b->phases_done == 2;
    if (last) {
        drv->alloc.free(b, sizeof(*b), drv->alloc.ctx);
        ds->batches_live--;
    }
    /* slot reuse requires BOTH phases (§3.3): when RETIREMENT is what
     * finally frees capacity, the blocked->writable edge fires here —
     * an armed sender would otherwise never wake */
    if (freed_slot && ds->send_blocked && !ds->terminal &&
        !ds->cancel_issued && ds->ectx != NULL && drv->session != NULL) {
        ds->send_blocked = false;
        wtq_api_session_enter(drv->session);
        wtq_conn_on_stream_writable(wtq_api_session_conn(drv->session),
                                    ds->ectx);
        nw_leave_and_poll(drv);
    }
    ds_maybe_free(ds, WTQ_NW_REAP_SRC_RETIRE);
}

#ifdef WTQ_NW_TESTING
/* TEST SEAM: after skipping `skip` concat attempts, the next `force`
 * attempts in ds_pump_sends fail as if allocation failed (0 = off).
 * The skip lets a test land records IN the batch before the failure,
 * exercising the rollback. Backend-internal. */
int wtq_nw_test_force_concat_failures;
void (*wtq_nw_test_on_earliest)(void *ctx);
void *wtq_nw_test_on_earliest_ctx;
void (*wtq_nw_test_main_start_gate)(void *ctx);
void *wtq_nw_test_main_start_gate_ctx;
int wtq_nw_test_concat_skip;
int wtq_nw_test_reaps_run;
int wtq_nw_test_reaps_in_callback;
/* DIAGNOSTIC: 1 = never destroy streams (leak everything) — isolates
 * whether crashes depend on our destruction at all. */
int wtq_nw_test_park_reaps;
int wtq_nw_test_teardown_variant;
int wtq_nw_test_detach_in_cb;
int wtq_nw_test_release_in_cb;
int wtq_nw_test_order_bad;
int wtq_nw_test_quarantined_peak;
int wtq_nw_test_reap_src[WTQ_NW_REAP_SRC__N];
int wtq_nw_test_dgram_reaps_run;
int wtq_nw_test_dgram_detach_in_cb;
int wtq_nw_test_dgram_release_in_cb;
int wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC__N];
int wtq_nw_test_peer_opens;
int wtq_nw_test_peer_rejects;
int wtq_nw_test_adopts;
int wtq_nw_test_meta_deny;
#endif /* WTQ_NW_TESTING */

/*
 * Coalesce EVERYTHING queued into one nw_connection_send. Single sends
 * at stream-ready are the probe-proven reliable pattern; back-to-back
 * sends on a fresh stream intermittently lose one (measured, even
 * chained through completions).
 *
 * MEASURED STANDING LIMITATION (SDK defect, load-dependent, ~1% of
 * loopback batteries under contention): even a SINGLE coalesced send
 * on a fresh stream can be partially lost — the peer receives the
 * head (stream opens, preamble consumed) while the tail never arrives,
 * the send completion fires normally, and no QUIC retransmission ever
 * recovers it (verified: still absent 10s later, while a parallel
 * stream's identical traffic flowed). Nothing below the nw_connection
 * API can observe or repair this; serializing first flights across
 * streams was tried and does not prevent it. Applications retrying on
 * their own timeout are the only recourse (the cross-backend loopback
 * documents and bounds it).
 */
static void ds_pump_sends(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;

    if (ds->send_inflight || !ds->ready_seen || ds->terminal ||
        ds->cancel_issued || ds->conn == NULL)
        return;
    if (ds->pending_sends == NULL)
        return;

    /* the batch memory was PREALLOCATED at enqueue: no allocation can
     * fail between an accepted send and its completion */
    struct wtq_nw_send_batch *b = ds->pending_sends->batch;
    ds->pending_sends->batch = NULL;
    memset(b, 0, sizeof(*b));
    b->ds = ds;

    dispatch_data_t all = dispatch_data_empty;
    dispatch_retain(all);
    bool fin = false;
    bool concat_failed = false;
    struct wtq_nw_pending_send *p = ds->pending_sends;
    while (p != NULL && b->nrecs < WTQ_NW_SEND_RECORDS) {
        struct wtq_nw_pending_send *next = p->next;
        if (p->d != NULL && !concat_failed) {
            dispatch_data_t merged;
#ifdef WTQ_NW_TESTING
            if (wtq_nw_test_concat_skip > 0) {
                wtq_nw_test_concat_skip--;
                merged = dispatch_data_create_concat(all, p->d);
            } else if (wtq_nw_test_force_concat_failures > 0) {
                wtq_nw_test_force_concat_failures--;
                merged = NULL; /* seam: behave exactly like OOM */
            } else {
                merged = dispatch_data_create_concat(all, p->d);
            }
#else
            merged = dispatch_data_create_concat(all, p->d);
#endif
            if (merged == NULL) {
                /* post-accept allocation failure: the accepted-send
                 * contract still owes completions — fail the whole
                 * connection; the terminal sweep delivers every
                 * accepted send exactly one CANCELED completion */
                concat_failed = true;
            } else {
                dispatch_release(all);
                all = merged;
            }
        }
        if (p->d != NULL)
            dispatch_release(p->d);
        if (p->fin)
            fin = true;
        if (p->rec != NULL && !concat_failed) {
            p->rec->transport_done = false; /* holder exists from issue */
            ds->recs_unretired++;
            b->recs[b->nrecs++] = p->rec;
        }
        if (p->batch != NULL)
            drv->alloc.free(p->batch, sizeof(*p->batch), drv->alloc.ctx);
        drv->alloc.free(p, sizeof(*p), drv->alloc.ctx);
        p = next;
    }
    ds->pending_sends = p;
    if (p == NULL)
        ds->pending_sends_tail = NULL;

    if (concat_failed) {
        /* ROLL BACK the never-issued batch: no holder will ever exist
         * for it, so every record added above must return to "no
         * transport reference" — transport_done true, recs_unretired
         * restored — or it could never retire and rundown would hang.
         * The records stay app-pending: the terminal sweep delivers
         * their exactly-once CANCELED completions. */
        for (int i = 0; i < b->nrecs; i++) {
            b->recs[i]->transport_done = true;
            ds->recs_unretired--;
        }
        dispatch_release(all);
        drv->alloc.free(b, sizeof(*b), drv->alloc.ctx);
        ds_drop_pending_sends(ds);
        if (!drv->err_staged) { /* first cause wins */
            drv->err_staged = true;
            drv->err_kind = WTQ_ERR_KIND_LOCAL;
            drv->err_domain = WTQ_ERRDOM_BACKEND;
            drv->err_code = 0;
        }
        (void)op_conn_close(drv, 0);
        return;
    }

    ds->bytes_issued += dispatch_data_get_size(all);
    NWDBG("batch issue id=%llu dsz=%zu nrecs=%d fin=%d\n",
          (unsigned long long)ds->id, dispatch_data_get_size(all),
          b->nrecs, (int)fin);
    ds->send_inflight = true;
    ds->batches_live++; /* pins the stream until BOTH phases ran */
    wtqi_nw_send_with_holder(ds->conn, drv->queue, all, fin,
                            batch_on_complete, batch_on_retire, b);
    dispatch_release(all);
}

static wtq_result_t ds_enqueue_send(struct wtq_dstream *ds,
                                    dispatch_data_t d, bool fin,
                                    struct wtq_nw_send_rec *rec)
{
    struct wtq_driver *drv = ds->drv;
    struct wtq_nw_pending_send *p =
        drv->alloc.alloc(sizeof(*p), drv->alloc.ctx);

    if (p == NULL)
        return WTQ_ERR_NOMEM;
    /* preallocate the batch NOW: after acceptance no allocation may
     * stand between an accepted send and its guaranteed completion */
    p->batch = drv->alloc.alloc(sizeof(*p->batch), drv->alloc.ctx);
    if (p->batch == NULL) {
        drv->alloc.free(p, sizeof(*p), drv->alloc.ctx);
        return WTQ_ERR_NOMEM;
    }
    if (d != NULL)
        dispatch_retain(d);
    p->d = d;
    p->fin = fin;
    p->rec = rec;
    p->next = NULL;
    if (ds->pending_sends_tail != NULL)
        ds->pending_sends_tail->next = p;
    else
        ds->pending_sends = p;
    ds->pending_sends_tail = p;
    return WTQ_OK;
}

/* Drop the queue (stream going down): a dropped gather's app
 * completion comes from the synthetic sweep; its transport reference
 * never existed (no holder was created). */
static void ds_drop_pending_sends(struct wtq_dstream *ds)
{
    struct wtq_nw_pending_send *p = ds->pending_sends;

    ds->pending_sends = NULL;
    ds->pending_sends_tail = NULL;
    while (p != NULL) {
        struct wtq_nw_pending_send *next = p->next;
        if (p->d != NULL)
            dispatch_release(p->d);
        if (p->batch != NULL)
            ds->drv->alloc.free(p->batch, sizeof(*p->batch),
                                ds->drv->alloc.ctx);
        p->next = NULL;
        ds->drv->alloc.free(p, sizeof(*p), ds->drv->alloc.ctx);
        p = next;
    }
}

/* --- receive loop -------------------------------------------------------- */

static void ds_arm_receive(struct wtq_dstream *ds);
static void ds_stamped_cancel(struct wtq_dstream *ds, uint64_t code);

static void ds_deliver_bytes(struct wtq_dstream *ds, dispatch_data_t content,
                             bool fin)
{
    struct wtq_driver *drv = ds->drv;

    if (drv->session == NULL || ds->ectx == NULL) {
        if (fin)
            ds->fin_delivered = true;
        return;
    }
    wtq_api_session_enter(drv->session);
    wtq_conn_t *ec = wtq_api_session_conn(drv->session);
    if (content != NULL && dispatch_data_get_size(content) > 0) {
        size_t total = dispatch_data_get_size(content);
        size_t seen = 0;
        dispatch_data_apply(
            content, ^bool(dispatch_data_t region, size_t off,
                           const void *buf, size_t len) {
              (void)region;
              (void)off;
              bool last = off + len == total;
              if (ds->ectx != NULL)
                  (void)wtq_conn_on_stream_bytes(ec, ds->ectx, buf, len,
                                                 fin && last, nw_now_us());
              return true;
            });
        (void)seen;
        if (fin)
            ds->fin_delivered = true;
    } else if (fin && !ds->fin_delivered) {
        ds->fin_delivered = true;
        if (ds->ectx != NULL)
            (void)wtq_conn_on_stream_bytes(ec, ds->ectx, NULL, 0, true,
                                           nw_now_us());
    }
    nw_leave_and_poll(drv);
}

static void ds_arm_receive(struct wtq_dstream *ds)
{
    if (ds->recv_pending || ds->terminal || ds->conn == NULL ||
        !ds->recv_enabled || ds->fin_delivered)
        return;
    ds->recv_pending = true;
    struct wtq_dstream *cap = ds;
    nw_connection_receive(
        ds->conn, 1, 65535,
        ^(dispatch_data_t content, nw_content_context_t ctx,
          bool is_complete, nw_error_t error) {
          cap->drv->callback_depth++;
          cap->recv_pending = false;
          /* stream-local receive errors (peer reset etc.) are NOT
           * connection-causal: never consume the first-causal latch
           * here — connection-scoped detail comes from the datagram
           * flow and the group terminal */
          if (cap->cancel_issued) {
              /* locally-cancelled: this is the cancel FLUSH, not peer
               * data. NW can flush with a synthetic FINAL context and
               * no error (measured: read as a clean CONNECT-stream
               * FIN, closing the session CLEAN and sealing an empty
               * record before the causal error could be delivered) —
               * nothing from a dead stream reaches the engine. */
              ds_maybe_free(cap, WTQ_NW_REAP_SRC_RECV);
              cap->drv->callback_depth--;
              return;
          }
          bool fin = is_complete && ctx != NULL &&
                     nw_content_context_get_is_final(ctx) &&
                     error == NULL;
          if (content != NULL || fin)
              ds_deliver_bytes(cap, content, fin);
          /* errors surface through the state handler (failed), which
           * owns reset attribution — never double-report here */
          if (error == NULL && !fin)
              ds_arm_receive(cap);
          ds_maybe_free(cap, WTQ_NW_REAP_SRC_RECV); /* schedules only */
          cap->drv->callback_depth--;
        });
}

/* --- stream state handler ------------------------------------------------ */

static void ds_handle_ready(struct wtq_dstream *ds);
static void ds_handle_failure(struct wtq_dstream *ds, nw_error_t e);

static void ds_attach_state_handler(struct wtq_dstream *ds)
{
    struct wtq_dstream *cap = ds;

    nw_connection_set_state_changed_handler(
        ds->conn, ^(nw_connection_state_t st, nw_error_t e) {
          cap->drv->callback_depth++;
          if (st == nw_connection_state_ready) {
              if (!cap->ready_seen) {
                  cap->ready_seen = true;
                  ds_handle_ready(cap);
              }
          } else if (st == nw_connection_state_failed) {
              if (!cap->failed_seen) {
                  cap->failed_seen = true;
                  ds_handle_failure(cap, e);
                  /* converge on `cancelled`: Apple requires the cancel
                   * even after failure, and it is the ONLY state after
                   * which no further callback can fire */
                  if (!cap->cancel_issued) {
                      cap->cancel_issued = true;
                      nw_connection_cancel(cap->conn);
                  }
              }
          } else if (st == nw_connection_state_cancelled) {
              if (!cap->failed_seen) {
                  cap->failed_seen = true;
                  ds_handle_failure(cap, e);
              }
              cap->terminal = true;
              /* whole-stream transport terminal: nothing further can
               * ever be delivered — resolve any engine receive drain
               * (a cancelled stream can never deliver the peer's
               * answering FIN/RESET) so a drain tombstone cannot pin
               * the slot and this shell for the connection's life;
               * op_detach re-arms the reap from inside the bracket */
              if (cap->ectx != NULL && cap->drv->session != NULL) {
                  wtq_api_session_enter(cap->drv->session);
                  (void)wtq_conn_on_stream_terminal(
                      wtq_api_session_conn(cap->drv->session), cap->ectx);
                  nw_leave_and_poll(cap->drv);
              }
              ds_maybe_free(cap, WTQ_NW_REAP_SRC_STATE); /* schedules only */
          }
          cap->drv->callback_depth--;
        });
}

/*
 * ready: metadata (and the native id) exist now. Local streams report
 * the id through the CURRENT ectx (critical ectx-NULL streams do not
 * report). Inbound streams become visible to the engine here — never
 * earlier — classified by id bits alone.
 */
static void ds_handle_ready(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;
    bool ok = false;
    uint64_t id = stream_native_id(ds->conn, &ok);

#ifdef WTQ_NW_TESTING
    {
        /* class-targeted metadata denial (one-shot per class bit) */
        int cls = 0;
        if (ds->is_local && !ds->is_bidi && ds->ectx == NULL)
            cls = WTQ_NW_META_DENY_CRITICAL;
        else if (ds->is_local && ds->is_bidi)
            cls = WTQ_NW_META_DENY_LOCAL_BIDI;
        else if (ds->is_local && ds->ectx != NULL)
            cls = WTQ_NW_META_DENY_APP;
        if (cls != 0 && (wtq_nw_test_meta_deny & cls) != 0) {
            wtq_nw_test_meta_deny &= ~cls;
            ok = false; /* SEAM: metadata missing at ready */
        }
    }
#endif

    if (!ok) {
        /* Missing QUIC metadata (and so the id) at ready is a BACKEND
         * INVARIANT FAILURE: a silent stream cancel would strand engine
         * state (a CONNECT or critical stream would never produce a
         * session outcome). Fail the CONNECTION — one deterministic
         * outcome for every dependent piece of state. */
        if (!drv->err_staged) {
            drv->err_staged = true;
            drv->err_kind = WTQ_ERR_KIND_LOCAL;
            drv->err_domain = WTQ_ERRDOM_BACKEND;
            drv->err_code = 0;
        }
        (void)op_conn_close(drv, 0);
        return;
    }
    ds->id = id;
    NWDBG("ready %s %s id=%llu ectx=%p\n", ds->is_local ? "local" : "peer",
          ds->is_bidi ? "bidi" : "uni", (unsigned long long)id,
          (void *)ds->ectx);

    if (ds->cancel_deferred && !ds->cancel_issued) {
        ds->cancel_deferred = false;
        ds_drop_pending_sends(ds); /* going down: drop queued */
        ds_stamped_cancel(ds, ds->cancel_code);
        return; /* no id report, no engine surfacing */
    }

    if (ds->is_local) {
        /* start the send chain OUTSIDE the state-handler frame (a send
         * issued from inside the ready callback intermittently never
         * reaches the wire — measured NW re-entrancy hazard) */
        struct wtq_dstream *cap = ds;
        dispatch_async(drv->queue, ^{ ds_pump_sends(cap); });
        if (ds->ectx != NULL && drv->session != NULL) {
            wtq_api_session_enter(drv->session);
            wtq_conn_on_stream_native_id(
                wtq_api_session_conn(drv->session), ds->ectx, id);
            nw_leave_and_poll(drv);
        }
        if (ds->is_bidi)
            ds_arm_receive(ds);
        return;
    }

    /* Inbound: initiator/direction from the id bits (a client sees
     * peer == server-initiated as bit0 set; bit1 set == uni). A
     * client-initiated id here is NW's own hidden stream (the
     * multiplex group's client-bidi 0): park it — it never touches
     * the engine or its stream pool. */
    if ((id & 1u) == 0) {
        NWDBG("hidden inbound id=%llu parked\n", (unsigned long long)id);
        ds->hidden = true;
        return;
    }
    ds->is_bidi = (id & 2u) == 0;
    if (drv->session == NULL)
        return;
    wtq_api_session_enter(drv->session);
    wtq_conn_t *ec = wtq_api_session_conn(drv->session);
    wtq_estream_t *ectx = NULL;
    wtq_result_t rc =
        ds->is_bidi ? wtq_conn_on_peer_bidi_opened(ec, ds, id, &ectx)
                    : wtq_conn_on_peer_uni_opened(ec, ds, id, &ectx);
    NWDBG("peer_opened id=%llu bidi=%d rc=%d ectx=%p\n",
          (unsigned long long)id, (int)ds->is_bidi, (int)rc, (void *)ectx);
    WTQ_NW_TEST(wtq_nw_test_peer_opens++);
    WTQ_NW_TEST(if (rc != WTQ_OK || ectx == NULL)
                    wtq_nw_test_peer_rejects++);
    if (rc == WTQ_OK && ectx != NULL) {
        /* the engine PROVED retention by returning the estream: only
         * now may the shell's life be tied to the engine linkage. An
         * accepted stream later reclassified to a drain tombstone
         * keeps this SAME estream, so the linkage stays accurate. */
        ds->engine_known = true;
        ds->ectx = ectx;
    } else if (!ds->cancel_issued && !ds->terminal && ds->conn != NULL) {
        /* rejected WITHOUT storage: STREAM_LIMIT already carried the
         * engine's own stamped cancel through op_shutdown_stream; any
         * other failure (CLOSED, future codes) must not leave a live
         * transport stream nobody owns */
        ds_stamped_cancel(ds, WTQ_WT_BUFFERED_STREAM_REJECTED);
    }
    nw_leave_and_poll(drv);
    if (ds->ectx != NULL)
        ds_arm_receive(ds);
}

/*
 * Terminal (failed/cancelled). A peer RESET of their send half surfaces
 * as failure with the receive-side application error stamped in the
 * metadata; deliver it as a stream reset. A received STOP_SENDING has
 * NO public signal and is never inferred (standing limitation). Streams
 * that fail before ready never open an engine stream at all.
 */
static void ds_handle_failure(struct wtq_dstream *ds, nw_error_t e)
{
    struct wtq_driver *drv = ds->drv;

    /* stream-local terminations (peer RESET_STREAM shows up here) are
     * NOT connection-causal: the first-causal transport-error latch is
     * never consumed by them */
    (void)e;
    if (ds->ectx != NULL && drv->session != NULL && !ds->reset_delivered &&
        !ds->fin_delivered && !ds->cancel_issued) {
        uint64_t code = 0;
        bool has_code =
            ds->conn != NULL && stream_peer_reset_code(ds->conn, &code);
        ds->reset_delivered = true;
        wtq_api_session_enter(drv->session);
        (void)wtq_conn_on_stream_reset(wtq_api_session_conn(drv->session),
                                       ds->ectx, has_code ? code : 0,
                                       nw_now_us());
        nw_leave_and_poll(drv);
    }
    /* queued sends never reached NW — drop them (the gathers' app
     * completions come from the synthetic sweep below) */
    ds_drop_pending_sends(ds);
    /* the cancel path flushed pending completions (measured); anything
     * still app-pending after a terminal gets the deduped synthetic */
    ds_synthesize_completions(ds);
}

/* --- set-flags + extract (one indivisible on-domain operation) ---------- */

/*
 * NW aliases the copied transport options (probe-proven): every flag is
 * set immediately before each extract, as one serialized operation, and
 * ALWAYS from the group's live options — never nw_quic_create_options().
 */
static nw_connection_t group_extract(struct wtq_driver *drv, bool uni,
                                     bool dgram)
{
    nw_parameters_t params = nw_connection_group_copy_parameters(drv->group);

    if (params == NULL)
        return NULL;
    nw_protocol_stack_t stack =
        nw_parameters_copy_default_protocol_stack(params);
    nw_release(params);
    if (stack == NULL)
        return NULL;
    nw_protocol_options_t opts =
        nw_protocol_stack_copy_transport_protocol(stack);
    nw_release(stack);
    if (opts == NULL)
        return NULL;
    /* ALL flags explicitly, every time (the handle is aliased) */
    nw_quic_set_stream_is_unidirectional(opts, uni);
    nw_quic_set_stream_is_datagram(opts, dgram);
    nw_connection_t c =
        nw_connection_group_extract_connection(drv->group, NULL, opts);
    nw_release(opts);
    return c;
}

/* --- driver ops ----------------------------------------------------------- */

static wtq_result_t op_open(struct wtq_driver *drv, wtq_estream_t *ectx,
                            struct wtq_dstream **out, uint64_t *id_out,
                            bool bidi)
{
    if (drv->shutdown_started || drv->group_terminal)
        return WTQ_ERR_CLOSED;
    struct wtq_dstream *ds = ds_new(drv, true, bidi);
    if (ds == NULL)
        return WTQ_ERR_NOMEM;
    ds->ectx = ectx;
    ds->conn = group_extract(drv, !bidi, false);
    if (ds->conn == NULL) {
        drv->streams = ds->next;
        drv->alloc.free(ds, sizeof(*ds), drv->alloc.ctx);
        drv->pins--; /* never came alive; the root check cannot fire
                        here (the lifecycle pin is still held) */
        return WTQ_ERR_BACKEND;
    }
    ds_attach_state_handler(ds);
    nw_connection_set_queue(ds->conn, drv->queue);
    nw_connection_start(ds->conn);
    ds->engine_known = true; /* the engine stores the ds it opened */
    *out = ds;
    *id_out = WTQ_STREAM_ID_UNKNOWN; /* reported at ready via ectx */
    return WTQ_OK;
}

static wtq_result_t op_open_uni(wtq_driver_t *drv, wtq_estream_t *ectx,
                                wtq_dstream_t **out, uint64_t *id_out)
{
    return op_open(drv, ectx, out, id_out, false);
}

static wtq_result_t op_open_bidi(wtq_driver_t *drv, wtq_estream_t *ectx,
                                 wtq_dstream_t **out, uint64_t *id_out)
{
    return op_open(drv, ectx, out, id_out, true);
}

/* Borrow-during-call send: the bytes are COPIED into dispatch data;
 * FIN rides the entry through the per-stream send chain. */
static wtq_result_t op_send(wtq_driver_t *drv, wtq_dstream_t *ds,
                            const uint8_t *data, size_t len, bool fin)
{
    (void)drv;
    if (ds->terminal || ds->cancel_issued || ds->conn == NULL)
        return WTQ_ERR_CLOSED;
    dispatch_data_t d = NULL;
    if (len > 0) {
        d = dispatch_data_create(data, len, ds->drv->queue,
                                 DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        if (d == NULL)
            return WTQ_ERR_NOMEM;
    }
    wtq_result_t qrc = ds_enqueue_send(ds, d, fin, NULL);
    if (d != NULL)
        dispatch_release(d);
    if (qrc == WTQ_OK)
        ds_pump_sends(ds);
    return qrc;
}

/*
 * Gather send: the spans are NOT copied — each becomes a no-copy
 * dispatch_data region concatenated into one object; the application's
 * bytes stay borrowed until the exactly-once completion discharges the
 * app reference (§3.1).
 */
static wtq_result_t op_send_gather(wtq_driver_t *drv, wtq_dstream_t *ds,
                                   const wtq_span_t *spans, size_t count,
                                   bool fin, void *cookie)
{
    if (ds->terminal || ds->cancel_issued || ds->conn == NULL)
        return WTQ_ERR_CLOSED;

    size_t bytes = 0;
    for (size_t i = 0; i < count; i++)
        bytes += spans[i].len;

    /* bounded window: fixed record ring + byte cap (§3.3) */
    struct wtq_nw_send_rec *rec = NULL;
    for (int i = 0; i < WTQ_NW_SEND_RECORDS; i++)
        if (!ds->recs[i].in_use) {
            rec = &ds->recs[i];
            break;
        }
    if (rec == NULL || ds->inflight_bytes + bytes > WTQ_NW_SEND_BYTES_MAX) {
        ds->send_blocked = true; /* arm the writable edge */
        return WTQ_ERR_WOULD_BLOCK;
    }

    dispatch_data_t all = dispatch_data_empty;
    dispatch_retain(all);
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len == 0)
            continue;
        dispatch_data_t part = dispatch_data_create(
            spans[i].data, spans[i].len, drv->queue, ^{
              /* no-copy: ownership hangs on the completion */
            });
        if (part == NULL) {
            dispatch_release(all);
            return WTQ_ERR_NOMEM;
        }
        dispatch_data_t next = dispatch_data_create_concat(all, part);
        dispatch_release(all);
        dispatch_release(part);
        if (next == NULL)
            return WTQ_ERR_NOMEM;
        all = next;
    }

    rec->in_use = true;
    rec->app_done = false;
    rec->transport_done = true; /* no holder yet: set false at issue */
    rec->cookie = cookie;
    rec->bytes = bytes;
    rec->ds = ds;
    ds->inflight_bytes += bytes;
    ds->recs_app_pending++;

    wtq_result_t qrc = ds_enqueue_send(ds, all, fin, rec);
    if (qrc != WTQ_OK) {
        /* not accepted: no completion will ever fire */
        rec->in_use = false;
        ds->inflight_bytes -= bytes;
        ds->recs_app_pending--;
    }
    dispatch_release(all);
    if (qrc == WTQ_OK)
        ds_pump_sends(ds);
    return qrc;
}

/*
 * Baseline shutdown via STAMPED CANCEL: stamp the application error in
 * the stream's metadata, then cancel. The peer observes RESET_STREAM
 * and (on a bidi) STOP_SENDING carrying that code — both halves, one
 * code, exactly the engine-accepted baseline (no WTQ_DCAP_SHUT_* bits
 * are advertised, so no exact-half request ever reaches this backend).
 * Cancel also forces pending send-completion retirement (measured).
 */
static void ds_stamped_cancel(struct wtq_dstream *ds, uint64_t code)
{
    nw_protocol_metadata_t md = stream_quic_metadata(ds->conn);

    if (md != NULL) {
        nw_quic_set_stream_application_error(md, code);
        nw_release(md);
    }
    ds->cancel_issued = true;
    nw_connection_cancel(ds->conn);
}

static wtq_result_t op_shutdown_stream(wtq_driver_t *drv, wtq_dstream_t *ds,
                                       const wtq_shutdown_t *req)
{
    (void)drv;
    if (ds->terminal || ds->conn == NULL)
        return WTQ_ERR_CLOSED;
    if (ds->cancel_issued || ds->cancel_deferred)
        return WTQ_OK; /* idempotent */

    uint64_t code = req->abort_send ? req->send_err : req->recv_err;
    NWDBG("shutdown id=%llu ready=%d code=%llu\n",
          (unsigned long long)ds->id, (int)ds->ready_seen,
          (unsigned long long)code);
    if (!ds->ready_seen) {
        /* pre-ready: the metadata (and the stamp slot) does not exist
         * yet — a cancel now would go out unstamped (code 0). Defer the
         * stamped cancel to the ready transition; the engine's view is
         * unchanged (the stream is going down either way). */
        ds->cancel_deferred = true;
        ds->cancel_code = code;
        return WTQ_OK;
    }
    ds_stamped_cancel(ds, code);
    return WTQ_OK;
}

/*
 * Application-level connection close. STANDING LIMITATION: NW exposes
 * no way to send an H3 application CONNECTION_CLOSE code — the code is
 * not fabricated; the connection is torn down and the peer observes a
 * transport-level close.
 */
static wtq_result_t op_conn_close(wtq_driver_t *drv, uint64_t h3_err)
{
    (void)h3_err;
    if (drv->shutdown_started)
        return WTQ_OK;
    drv->shutdown_started = true;
    for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
        if (ds->conn != NULL && !ds->terminal && !ds->cancel_issued) {
            ds->cancel_issued = true;
            nw_connection_cancel(ds->conn);
        }
    if (drv->dgram != NULL && !drv->dgram_terminal &&
        !drv->dgram_cancel_issued) {
        drv->dgram_cancel_issued = true;
        nw_connection_cancel(drv->dgram);
    }
    nw_connection_group_cancel(drv->group);
    return WTQ_OK;
}

static wtq_result_t op_dgram_send(wtq_driver_t *drv, const wtq_span_t *spans,
                                  size_t count)
{
    if (drv->dgram == NULL || drv->dgram_terminal ||
        drv->dgram_cancel_issued || !drv->dgram_ready)
        return WTQ_ERR_CLOSED;
    if (drv->dgram_inflight >= 32)
        return WTQ_ERR_WOULD_BLOCK;

    /* borrow-during-call: COPY the spans into one datagram */
    size_t total = 0;
    for (size_t i = 0; i < count; i++)
        total += spans[i].len;
    uint8_t stack_buf[2048];
    uint8_t *buf = stack_buf;
    if (total > sizeof(stack_buf)) {
        buf = drv->alloc.alloc(total, drv->alloc.ctx);
        if (buf == NULL)
            return WTQ_ERR_NOMEM;
    }
    size_t off = 0;
    for (size_t i = 0; i < count; i++) {
        memcpy(buf + off, spans[i].data, spans[i].len);
        off += spans[i].len;
    }
    dispatch_data_t d = NULL;
    if (total > 0) {
        d = dispatch_data_create(buf, total, drv->queue,
                                 DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        if (buf != stack_buf)
            drv->alloc.free(buf, total, drv->alloc.ctx);
        if (d == NULL)
            return WTQ_ERR_NOMEM;
    } else if (buf != stack_buf) {
        drv->alloc.free(buf, total, drv->alloc.ctx);
    }
    drv->dgram_inflight++;
    NWDBG("dgram send %zu bytes\n", total);
    struct wtq_driver *cap = drv;
    nw_connection_send(drv->dgram, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
                       true, ^(nw_error_t error) {
                         cap->callback_depth++;
                         NWDBG("dgram send complete err=%d\n",
                               error ? nw_error_get_error_code(error) : 0);
                         cap->dgram_inflight--;
                         dgram_maybe_reap(cap, WTQ_NW_REAP_SRC_COMPLETE);
                         cap->callback_depth--;
                       });
    if (d != NULL)
        dispatch_release(d);
    return WTQ_OK;
}

static size_t op_dgram_max_size(wtq_driver_t *drv)
{
    if (drv->dgram == NULL || !drv->dgram_ready || drv->dgram_terminal ||
        drv->dgram_cancel_issued)
        return 0;
    nw_protocol_metadata_t md = stream_quic_metadata(drv->dgram);
    if (md == NULL)
        return 0;
    size_t n = nw_quic_get_stream_usable_datagram_frame_size(md);
    nw_release(md);
    NWDBG("dgram max_size=%zu\n", n);
    return n;
}

static wtq_result_t op_recv_enable(wtq_driver_t *drv, wtq_dstream_t *ds,
                                   bool enabled)
{
    (void)drv;
    ds->recv_enabled = enabled;
    if (enabled)
        ds_arm_receive(ds); /* re-arm; disabling stops FUTURE arms only */
    return WTQ_OK;
}

/* Identity-checked detach: no Apple call (§7.3 rule 2). */
static void op_detach(wtq_driver_t *drv, wtq_dstream_t *ds,
                      wtq_estream_t *es)
{
    (void)drv;
    if (ds->ectx == es) {
        ds->ectx = NULL;
        /* the engine promises never to name this ds again: the struct
         * becomes freeable once the transport side is also done */
        ds->engine_detached = true;
        ds_maybe_free(ds, WTQ_NW_REAP_SRC_DETACH);
    }
}

static const wtq_driver_ops_t nw_driver_ops = {
    /* no WTQ_DCAP_SHUT_* bits: NW cannot abort one bidi half alone and
     * cannot split codes; the mandatory baseline is exact and enough.
     * Datagram and receive-pause support are advertised structurally
     * (the ops below are non-NULL). */
    .caps = 0,
    .open_uni = op_open_uni,
    .open_bidi = op_open_bidi,
    .send = op_send,
    .send_gather = op_send_gather,
    .shutdown_stream = op_shutdown_stream,
    .conn_close = op_conn_close,
    .dgram_send = op_dgram_send,
    .dgram_max_size = op_dgram_max_size,
    .recv_enable = op_recv_enable,
    .detach = op_detach,
};

/* --- connection lifetime policy ------------------------------------------ */

static void conn_poll_shutdown(struct wtq_driver *drv)
{
    if (drv->shutdown_started || drv->session == NULL)
        return;
    wtq_conn_t *ec = wtq_api_session_conn(drv->session);
    if (ec == NULL)
        return;
    if (wtq_conn_is_closed(ec)) {
        (void)op_conn_close(drv, wtq_conn_close_code(ec));
        return;
    }
    switch (wtq_conn_session_state(ec)) {
    case WTQ_SESSION_CLOSED:
    case WTQ_SESSION_REJECTED:
    case WTQ_SESSION_FAILED:
        /* post-terminal retirement: the record was sealed at the
         * session terminal; this cleanup stages nothing */
        (void)op_conn_close(drv, 0);
        break;
    default:
        break;
    }
}

/* --- datagram flow --------------------------------------------------------- */

/*
 * The dgram flow tears down with the SAME detach-then-release
 * discipline as the streams: eligibility may be DETECTED inside any
 * callback; the handler detach and the release each get their own
 * later queue turn. Unlike a stream shell, the driver itself is not
 * freed here — it outlives every child callback and block disposal
 * (rundown frees it only after every child released and a final
 * barrier drained the queue).
 */
static bool dgram_reap_eligible(const struct wtq_driver *drv)
{
    return drv->dgram != NULL && drv->dgram_terminal &&
           !drv->dgram_recv_pending && drv->dgram_inflight == 0;
}

static void dgram_reap_phase2(struct wtq_driver *drv)
{
    WTQ_NW_TEST(wtq_nw_test_dgram_reaps_run++);
    WTQ_NW_TEST(if (drv->callback_depth != 0)
                    wtq_nw_test_dgram_release_in_cb++);
#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_park_reaps)
        return; /* diagnostic: hold everything forever */
#endif
    if (drv->dgram != NULL) {
        nw_release(drv->dgram);
        drv->dgram = NULL;
        drv->pins--;
        drv_free_if_done(drv);
    }
}

static void dgram_reap_phase1(struct wtq_driver *drv)
{
    if (drv->dgram != NULL) {
        WTQ_NW_TEST(if (drv->callback_depth != 0)
                        wtq_nw_test_dgram_detach_in_cb++);
        nw_connection_set_state_changed_handler(drv->dgram, NULL);
    }
    drv->dgram_handler_detached = true;
    struct wtq_driver *cap = drv;
    dispatch_async(drv->queue, ^{
      if (dgram_reap_eligible(cap) && cap->dgram_handler_detached)
          dgram_reap_phase2(cap);
      else
          cap->dgram_reap_scheduled = false;
    });
}

static void dgram_maybe_reap(struct wtq_driver *drv,
                             enum wtq_nw_reap_src src)
{
    if (drv->dgram_reap_scheduled || !dgram_reap_eligible(drv))
        return;
    drv->dgram_reap_scheduled = true;
    WTQ_NW_TEST(wtq_nw_test_dgram_reap_src[src]++);
    (void)src;
    struct wtq_driver *cap = drv;
    dispatch_async(drv->queue, ^{
      if (dgram_reap_eligible(cap))
          dgram_reap_phase1(cap);
      else
          cap->dgram_reap_scheduled = false;
    });
}

static void dgram_arm_receive(struct wtq_driver *drv)
{
    if (drv->dgram_recv_pending || drv->dgram_terminal ||
        drv->dgram == NULL)
        return;
    drv->dgram_recv_pending = true;
    struct wtq_driver *cap = drv;
    nw_connection_receive(
        drv->dgram, 1, 65535,
        ^(dispatch_data_t content, nw_content_context_t ctx,
          bool is_complete, nw_error_t error) {
          (void)ctx;
          (void)is_complete;
          cap->callback_depth++;
          cap->dgram_recv_pending = false;
          NWDBG("dgram recv content=%zu err=%d\n",
                content ? dispatch_data_get_size(content) : 0,
                error ? nw_error_get_error_code(error) : 0);
          if (error != NULL && !cap->shutdown_started)
              stage_nw_error(cap, error);
          if (content != NULL && cap->session != NULL) {
              /* one receive == one datagram: flatten and deliver */
              dispatch_data_t flat = content;
              const void *buf = NULL;
              size_t len = 0;
              dispatch_data_t map =
                  dispatch_data_create_map(flat, &buf, &len);
              if (map != NULL) {
                  wtq_api_session_enter(cap->session);
                  (void)wtq_conn_on_datagram(
                      wtq_api_session_conn(cap->session), buf, len,
                      nw_now_us());
                  nw_leave_and_poll(cap);
                  dispatch_release(map);
              }
          }
          if (error == NULL)
              dgram_arm_receive(cap);
          dgram_maybe_reap(cap, WTQ_NW_REAP_SRC_RECV);
          cap->callback_depth--;
        });
}

/* --- inbound streams --------------------------------------------------------- */

static void adopt_inbound(struct wtq_driver *drv, nw_connection_t in)
{
    NWDBG("adopt inbound\n");
    WTQ_NW_TEST(wtq_nw_test_adopts++);
    nw_retain(in);
    struct wtq_dstream *ds = ds_new(drv, false, false);
    if (ds == NULL) {
        nw_connection_cancel(in);
        nw_release(in);
        return;
    }
    ds->conn = in;
    ds_attach_state_handler(ds);
    nw_connection_set_queue(in, drv->queue);
    nw_connection_start(in);
    if (drv->shutdown_started || drv->rundown) {
        /* teardown in progress (NW refuses clearing the new-connection
         * handler after start): adopt-and-kill */
        ds->cancel_issued = true;
        nw_connection_cancel(in);
    }
    /* invisible to the engine until ready (§2.5) */
}

/* --- group lifecycle -------------------------------------------------------- */

static void group_handle_terminal(struct wtq_driver *drv, nw_error_t e)
{
    if (drv->group_terminal)
        return;
    drv->group_terminal = true;
    stage_nw_error(drv, e);

    /* every stream is going down with the connection: force retirement
     * (cancel flushes pending completions — measured), then the
     * deduplicated synthetic fallback for anything left */
    for (struct wtq_dstream *ds = drv->streams; ds != NULL;) {
        struct wtq_dstream *next = ds->next;
        if (ds->conn != NULL && !ds->terminal && !ds->cancel_issued) {
            ds->cancel_issued = true;
            nw_connection_cancel(ds->conn);
        }
        ds_synthesize_completions(ds);
        ds = next;
    }
    /* the dgram flow goes down with the connection too — converge it
     * regardless of WHY the group ended (a direct group cancel never
     * ran the op_conn_close sweep) */
    if (drv->dgram != NULL && !drv->dgram_terminal &&
        !drv->dgram_cancel_issued) {
        drv->dgram_cancel_issued = true;
        nw_connection_cancel(drv->dgram);
    }

    if (drv->session != NULL && !drv->closed_fed) {
        drv->closed_fed = true;
        wtq_api_session_enter(drv->session);
        put_error_detail(drv);
        /* remote attribution and peer close codes are unobservable on
         * NW (standing limitation): never fabricated */
        wtq_conn_on_conn_closed(wtq_api_session_conn(drv->session), 0,
                                false, nw_now_us());
        wtq_session_t *s = drv->session;
        drv->session = NULL; /* drop the backend's reference */
        wtq_session_release(s);
        (void)wtq_api_session_leave(s);
    }
    /* the engine can never call a driver op again (conn->closed):
     * shells that were pinned only by engine linkage are freeable */
    for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
        ds_maybe_free(ds, WTQ_NW_REAP_SRC_RUNDOWN);
    /* RUNDOWN COMPLETION is transport-terminal + every accepted send
     * APP_COMPLETED (the sweeps above) — on_stopped can deliver once
     * the application also ASKED for the stop */
    drv->terminal_done = true;
    nw_maybe_schedule_finish(drv);
}

#ifdef WTQ_NW_TESTING
/* TEST SPI: force the group-terminal-before-child-terminal order —
 * cancel the group directly WITHOUT cancelling children first; the
 * group-terminal path then tears the children down. */
void wtq_nw_test_cancel_group(struct wtq_driver *drv)
{
    dispatch_async(drv->queue, ^{
      if (!drv->shutdown_started) {
          drv->shutdown_started = true;
          nw_connection_group_cancel(drv->group);
      }
    });
}
#endif /* WTQ_NW_TESTING */

/* --- managed lifecycle (§7.2) ---------------------------------------------- */

#ifdef WTQ_NW_TESTING
_Atomic int wtq_nw_test_live_drivers;
const wtq_alloc_t *wtq_nw_test_backend_alloc;

struct wtq_driver *wtq_nw_test_conn_driver(wtq_nw_conn_t *c)
{
    return c != NULL ? c->drv : NULL;
}

/* Models a STRAGGLER HOLDER for the ownership-split tests: an extra
 * internal-root pin taken/returned on the domain, exactly like an
 * undisposed completion block's shell pin. Unpin re-checks the root. */
void wtq_nw_test_pin(struct wtq_driver *drv)
{
    drv->pins++;
}

void wtq_nw_test_unpin(struct wtq_driver *drv)
{
    drv->pins--;
    drv_free_if_done(drv);
}
#endif

/* The internal root dies when its last pin returns: every shell and
 * the dgram flow released, and the lifecycle pin (dropped after
 * on_stopped) returned. §7.3 rule 3 ordering held by construction:
 * children released before the group. Never touches the PUBLIC handle
 * — pins == 0 implies the lifecycle finished, and the handle may
 * legally be long gone. Releasing the queue from one of its own
 * blocks is legal (it dies after the block completes). */
static void drv_free_if_done(struct wtq_driver *drv)
{
    if (drv->pins != 0)
        return;
    nw_release(drv->group);
    dispatch_release(drv->queue);
    wtq_alloc_t alloc = drv->alloc;
    alloc.free(drv, sizeof(*drv), alloc.ctx);
    WTQ_NW_TEST(atomic_fetch_sub(&wtq_nw_test_live_drivers, 1));
}

/*
 * The FINAL lifecycle block — its own queue turn, after the group
 * terminal (rundown complete: transport terminal + every accepted
 * send APP_COMPLETED via the terminal sweeps). Delivers on_stopped
 * exactly once (the last application-visible block; it may release
 * the caller's final public reference — the lifecycle itself is the
 * internal reference held through its return), then returns the
 * lifecycle pin.
 */
/* The doorbell delivery, on the domain. Cancellation happens ON this
 * serial queue (finish worker / rollback) before on_stopped, so this
 * never runs during or after the final block, and never on a freed
 * handle (the handle outlives the lifecycle). */
static void nw_doorbell_fire(void *arg)
{
    struct wtq_nw_conn *c = arg;

    c->on_doorbell(c->doorbell_ctx);
}

/* Cancel + release the doorbell source (idempotent). The finish worker
 * calls this on the domain BEFORE on_stopped — on a serial queue that
 * guarantees no event handler runs during or after the final block.
 * Build rollback paths call it before anything started. */
static void nw_doorbell_teardown(struct wtq_nw_conn *c)
{
    pthread_mutex_lock(&c->mu);
    dispatch_source_t bell = c->doorbell_src;
    c->doorbell_src = NULL;
    pthread_mutex_unlock(&c->mu);
    if (bell != NULL) {
        dispatch_source_cancel(bell);
        dispatch_release(bell);
    }
}

static void nw_finish_worker(void *arg)
{
    struct wtq_driver *drv = arg;
    struct wtq_nw_conn *c = drv->pub;

#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_teardown_variant == 2) {
        /* variant-C diagnostic: quarantined shells release ONLY now
         * (group terminal, every child cancelled, later queue turn) */
        struct wtq_dstream *ds = drv->streams;
        while (ds != NULL) {
            struct wtq_dstream *next = ds->next;
            if (ds->quarantined) {
                if (ds->conn != NULL)
                    nw_release(ds->conn);
                struct wtq_dstream **pp = &drv->streams;
                while (*pp != NULL && *pp != ds)
                    pp = &(*pp)->next;
                if (*pp == ds)
                    *pp = ds->next;
                drv->alloc.free(ds, sizeof(*ds), drv->alloc.ctx);
                drv->pins--;
            }
            ds = next;
        }
    }
#endif
    /* the doorbell dies FIRST, on the domain: after this point no
     * event handler can run, so on_stopped stays the final block */
    nw_doorbell_teardown(c);
    if (c->on_stopped != NULL)
        c->on_stopped(c->stopped_ctx);
    /* only the domain writes c->drv; on-domain readers (the session
     * accessor) are race-free by thread identity */
    c->drv = NULL;
    bool free_handle;
    pthread_mutex_lock(&c->mu);
    c->stopped_done = true;
    c->lifecycle_over = true;
    free_handle = c->refs == 0;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
    if (free_handle)
        nw_conn_handle_free(c);
    drv->pub = NULL;
    drv->lifecycle_pin_dropped = true;
    drv->pins--;
    drv_free_if_done(drv);
}

static void nw_maybe_schedule_finish(struct wtq_driver *drv)
{
    if (drv->finish_scheduled || !drv->terminal_done ||
        !drv->stop_started)
        return;
    drv->finish_scheduled = true;
    dispatch_async_f(drv->queue, drv, nw_finish_worker);
}

/* Enqueued by stop_begin AFTER every already-accepted post (the
 * acceptance mutex orders the dispatches): accepted posts have all run
 * by the time rundown starts. */
static void nw_stop_worker(void *arg)
{
    struct wtq_driver *drv = arg;

    /* NW refuses clearing the new-connection handler after start:
     * rundown mode makes late adoptions adopt-and-kill instead */
    drv->rundown = true;
    drv->stop_started = true;
    (void)op_conn_close(drv, 0);
    nw_maybe_schedule_finish(drv); /* terminal may already be in */
}

/* --- public API ------------------------------------------------------------- */

void wtq_nw_conn_cfg_init(wtq_nw_conn_cfg_t *cfg)
{
    if (cfg == NULL)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->struct_size = (uint32_t)sizeof(*cfg);
}

void wtq_nw_conn_retain(wtq_nw_conn_t *c)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->mu);
    c->refs++;
    pthread_mutex_unlock(&c->mu);
}

void wtq_nw_conn_release(wtq_nw_conn_t *c)
{
    bool free_handle = false;
    bool implicit_stop = false;

    if (c == NULL)
        return;
    pthread_mutex_lock(&c->mu);
    if (c->refs <= 0) {
        /* over-release: refused, never fatal */
        pthread_mutex_unlock(&c->mu);
        return;
    }
    c->refs--;
    if (c->refs == 0) {
        if (!c->stop_started)
            implicit_stop = true; /* FAIL-SAFE: a dropped handle never
                                     leaks a live transport (header) */
        else if (c->lifecycle_over)
            free_handle = true;
        /* else: the lifecycle finisher frees it */
    }
    pthread_mutex_unlock(&c->mu);
    if (implicit_stop)
        (void)wtq_nw_conn_stop_begin(c);
    if (free_handle)
        nw_conn_handle_free(c);
}

struct nw_post_node {
    struct wtq_nw_conn *c;
    void (*fn)(void *ctx);
    void *ctx;
};

static void nw_post_tramp(void *arg)
{
    struct nw_post_node *n = arg;
    struct wtq_nw_conn *c = n->c;
    void (*fn)(void *) = n->fn;
    void *ctx = n->ctx;
    wtq_alloc_t alloc = c->alloc;

    alloc.free(n, sizeof(*n), alloc.ctx);
    fn(ctx);
    wtq_nw_conn_release(c); /* the acceptance retain */
}

wtq_result_t wtq_nw_conn_post(wtq_nw_conn_t *c, void (*fn)(void *ctx),
                              void *ctx)
{
    if (c == NULL || fn == NULL)
        return WTQ_ERR_INVALID_ARG;
    struct nw_post_node *n = c->alloc.alloc(sizeof(*n), c->alloc.ctx);
    if (n == NULL)
        return WTQ_ERR_NOMEM; /* nothing queued, nothing retained */
    n->c = c;
    n->fn = fn;
    n->ctx = ctx;
    pthread_mutex_lock(&c->mu);
    if (c->closed) {
        pthread_mutex_unlock(&c->mu);
        c->alloc.free(n, sizeof(*n), c->alloc.ctx);
        return WTQ_ERR_CLOSED; /* rejected synchronously: never runs */
    }
    /* ACCEPTED under the latch mutex: the retain and the enqueue are
     * atomic against stop_begin, so every accepted post is dispatched
     * BEFORE the stop worker — it runs exactly once, before rundown
     * starts, in cross-thread submission order. From ON the domain
     * this enqueues behind the current block, never inline. */
    c->refs++;
    dispatch_async_f(c->drv->queue, n, nw_post_tramp);
    pthread_mutex_unlock(&c->mu);
    return WTQ_OK;
}

void wtq_nw_conn_doorbell_ring(wtq_nw_conn_t *c)
{
    if (c == NULL)
        return;
    /* Under mu: synchronized against stop_begin's closed latch and the
     * finish worker's teardown (which NULLs the source under mu before
     * cancelling). NON-ALLOCATING and infallible: merge_data only folds
     * a bit into the armed source; coalescing and one-more-after-a-ring-
     * during-delivery are dispatch-source semantics. Once stop wins the
     * latch this is a documented no-op — no delivery is promised. */
    pthread_mutex_lock(&c->mu);
    if (!c->closed && c->doorbell_src != NULL)
        dispatch_source_merge_data(c->doorbell_src, 1);
    pthread_mutex_unlock(&c->mu);
}

bool wtq_nw_conn_is_on_domain(const wtq_nw_conn_t *c)
{
    if (c == NULL)
        return false;
    return dispatch_get_specific((const void *)c) == (void *)c;
}

wtq_session_t *wtq_nw_conn_session(wtq_nw_conn_t *c)
{
    if (c == NULL || !wtq_nw_conn_is_on_domain(c))
        return NULL; /* never a cross-thread entry point */
    /* on-domain, c->drv is written only by this thread (create before
     * publication; the finisher clears it) */
    if (c->drv == NULL)
        return NULL; /* dead-but-valid */
    return c->drv->session; /* NULL once the connection terminated */
}

bool wtq_nw_conn_stop_begin(wtq_nw_conn_t *c)
{
    struct wtq_driver *drv;

    if (c == NULL)
        return false;
    pthread_mutex_lock(&c->mu);
    if (c->stop_started) {
        pthread_mutex_unlock(&c->mu);
        return false; /* idempotent */
    }
    c->stop_started = true;
    c->closed = true; /* the latch: posts reject from here on */
    drv = c->drv;
    /*
     * If the group has already started, enqueue the ordered stop worker now
     * (exactly once). If the start is still QUEUED/STARTING (an off-main
     * creator's main-thread start has not run yet), only LATCH the intent
     * here: the start trampoline enqueues the stop worker after start
     * returns, so we never cancel an unstarted group and previously
     * accepted posts stay ahead of the stop worker. stop_enqueued makes the
     * enqueue exactly-once across both paths.
     */
    bool enqueue_now = false;
    if (c->start_state == NW_START_STARTED && !c->stop_enqueued) {
        c->stop_enqueued = true;
        enqueue_now = true;
    }
    pthread_mutex_unlock(&c->mu);
    if (enqueue_now)
        dispatch_async_f(drv->queue, drv, nw_stop_worker);
    return true;
}

wtq_result_t wtq_nw_conn_join(wtq_nw_conn_t *c)
{
    if (c == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (wtq_nw_conn_is_on_domain(c))
        return WTQ_ERR_STATE; /* would deadlock by definition */
    pthread_mutex_lock(&c->mu);
    while (!c->stopped_done)
        pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
    return WTQ_OK;
}

/*
 * MAIN-THREAD START TRAMPOLINE. Runs on the main dispatch queue for an
 * off-main creator (see the startup state machine on wtq_nw_conn). It
 * starts the group EXACTLY ONCE on the main thread -- the only context in
 * which Network.framework reliably delivers inbound streams pending at
 * READY -- and, if a stop was latched while the start was queued, enqueues
 * the ordered stop worker on the domain AFTER start returns (so previously
 * accepted posts stay ahead of it). Holds the construction reference until
 * it is done, then releases it. c->mu is never held across
 * nw_connection_group_start (which drives callbacks on the domain).
 */
static void nw_main_start_tramp(void *arg)
{
    struct wtq_nw_conn *c = arg;
    struct wtq_driver *drv;

    pthread_mutex_lock(&c->mu);
    drv = c->drv;
    c->start_state = NW_START_STARTING;
    pthread_mutex_unlock(&c->mu);

#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_main_start_gate != NULL)
        wtq_nw_test_main_start_gate(wtq_nw_test_main_start_gate_ctx);
#endif
    nw_connection_group_start(drv->group); /* on the MAIN thread, once */

    bool enqueue_stop = false;
    pthread_mutex_lock(&c->mu);
    c->start_state = NW_START_STARTED;
    if (c->stop_started && !c->stop_enqueued) {
        c->stop_enqueued = true; /* stop latched while queued: enqueue now */
        enqueue_stop = true;
    }
    pthread_mutex_unlock(&c->mu);
    if (enqueue_stop)
        dispatch_async_f(drv->queue, drv, nw_stop_worker);

    wtq_nw_conn_release(c); /* the construction reference */
}

/* --- construction ------------------------------------------------------------ */

static wtq_result_t nw_conn_build(const wtq_alloc_t *alloc,
                                  const wtq_session_events_t *events,
                                  void *user, const char *host,
                                  uint16_t port, bool insecure,
                                  const wtq_connect_config_t *connect,
                                  void (*on_stopped)(void *ctx),
                                  void *stopped_ctx,
                                  void (*on_doorbell)(void *ctx),
                                  void *doorbell_ctx,
                                  wtq_session_t **session_ref_out,
                                  struct wtq_nw_conn **conn_out)
{
    *conn_out = NULL;

    /*
     * THE ALLOCATOR BOUNDARY: the CALLER's allocator (cfg.alloc) owns
     * ONLY the API session/stream objects behind the events. The
     * backend's own references to those are gone before on_stopped
     * begins; handles the application retained are the application's
     * explicit responsibility (the cleanup deadline: by the end of
     * on_stopped). Everything else — this managed handle, post nodes,
     * the driver root, stream shells, batches, send-chain nodes —
     * lives on the BACKEND-OWNED allocator: neither the handle free
     * after on_stopped returns (an actor may already have released
     * and torn down its context by then), nor a rejected post, nor a
     * transport-retirement straggler can ever touch cfg.alloc.
     */
    const wtq_alloc_t *balloc = wtq_alloc_default();
#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_backend_alloc != NULL)
        balloc = wtq_nw_test_backend_alloc;
#endif

    struct wtq_nw_conn *c = balloc->alloc(sizeof(*c), balloc->ctx);
    if (c == NULL)
        return WTQ_ERR_NOMEM;
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->refs = 1;
    c->alloc = *balloc; /* frees this handle + post nodes */
    c->on_stopped = on_stopped;
    c->stopped_ctx = stopped_ctx;

    struct wtq_driver *drv = balloc->alloc(sizeof(*drv), balloc->ctx);
    if (drv == NULL) {
        nw_conn_handle_free(c);
        return WTQ_ERR_NOMEM;
    }
    memset(drv, 0, sizeof(*drv));
    drv->alloc = *balloc;

    /* the serialization domain: one serial queue per connection, with
     * work-item autorelease so ObjC holder disposal is prompt and
     * attributable at block granularity */
    dispatch_queue_attr_t qattr =
        dispatch_queue_attr_make_with_autorelease_frequency(
            DISPATCH_QUEUE_SERIAL, DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM);
    drv->queue = dispatch_queue_create("wtq.nw.conn", qattr);
    /* domain membership: the queue is tagged with the PUBLIC handle */
    dispatch_queue_set_specific(drv->queue, c, c, NULL);

    /* The doorbell: created and ACTIVATED before anything can start
     * transport callbacks, so the earliest published handle can ring
     * an already-armed source. Context is the public handle. */
    if (on_doorbell != NULL) {
        c->on_doorbell = on_doorbell;
        c->doorbell_ctx = doorbell_ctx;
        c->doorbell_src = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, drv->queue);
        if (c->doorbell_src == NULL) {
            dispatch_release(drv->queue);
            balloc->free(drv, sizeof(*drv), balloc->ctx);
            nw_conn_handle_free(c);
            return WTQ_ERR_BACKEND;
        }
        dispatch_set_context(c->doorbell_src, c);
        dispatch_source_set_event_handler_f(c->doorbell_src,
                                            nw_doorbell_fire);
        dispatch_activate(c->doorbell_src);
    }

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    nw_endpoint_t ep = nw_endpoint_create_host(host, portstr);
    nw_parameters_t params =
        nw_parameters_create_quic(^(nw_protocol_options_t quic) {
          /* advertise QUIC datagram support in OUR transport params —
           * without it the peer never sends DATAGRAM frames (probe) */
          nw_quic_set_max_datagram_frame_size(quic, 65535);
          sec_protocol_options_t sec =
              nw_quic_copy_sec_protocol_options(quic);
          sec_protocol_options_add_tls_application_protocol(sec, "h3");
          if (insecure) {
              /* loopback/development ONLY (header); explicit trust
               * verification (below) is the default when this flag is
               * off */
              sec_protocol_options_set_verify_block(
                  sec,
                  ^(sec_protocol_metadata_t m, sec_trust_t t,
                    sec_protocol_verify_complete_t done) {
                    (void)m;
                    (void)t;
                    done(true);
                  },
                  drv->queue);
          } else {
              /*
               * EXPLICIT TRUST VERIFICATION, fail-fast. NW's own trust
               * rejection is INVISIBLE on this SDK (the group emits no
               * waiting/failed transition), so a wrong certificate
               * would hang the dial forever. Evaluate the SUPPLIED
               * SecTrustRef ourselves -- it carries NW's configured
               * hostname policy; no replacement trust object is built
               * -- and on rejection the VERIFIER creates the causal
               * record and initiates terminal convergence:
               *   stage {LOCAL, NW_TRUST, code} first, latch
               *   shutdown_started so later generic errors cannot
               *   replace the first cause, answer done(false) exactly
               *   once, and cancel the group on the NEXT queue turn
               *   (never re-entering NW from inside its verification
               *   callback). The ordinary group-terminal path then
               *   publishes the staged record and delivers exactly one
               *   pre-establishment failure.
               */
              struct wtq_driver *vcap = drv;
              sec_protocol_options_set_verify_block(
                  sec,
                  ^(sec_protocol_metadata_t m, sec_trust_t t,
                    sec_protocol_verify_complete_t done) {
                    (void)m;
                    bool ok = false;
                    /* a missing trust reference or an evaluation error
                     * is a TLS FAILURE, never success */
                    int64_t code = (int64_t)errSecNotTrusted;
                    SecTrustRef trust =
                        t != NULL ? sec_trust_copy_ref(t) : NULL;
                    if (trust != NULL) {
                        CFErrorRef err = NULL;
                        ok = SecTrustEvaluateWithError(trust, &err);
                        if (!ok && err != NULL)
                            code = (int64_t)CFErrorGetCode(err);
                        if (err != NULL)
                            CFRelease(err);
                        CFRelease(trust);
                    }
                    bool converge = false;
                    if (!ok && !vcap->shutdown_started) {
                        if (!vcap->err_staged) {
                            vcap->err_staged = true;
                            vcap->err_kind = WTQ_ERR_KIND_LOCAL;
                            /* provenance domain: the EXPLICIT evaluator
                             * rejected the trust — consumers classify
                             * certificate failure by this domain, not
                             * by an OSStatus allowlist */
                            vcap->err_domain = WTQ_ERRDOM_NW_TRUST;
                            vcap->err_code = code;
                        }
                        vcap->shutdown_started = true;
                        converge = true;
                    }
                    /* answer FIRST, then enqueue the convergence: the
                     * cancel lands behind any work NW schedules from
                     * done(false), never ahead of it */
                    done(ok);
                    if (converge)
                        dispatch_async(vcap->queue, ^{
                          if (vcap->group != NULL)
                              nw_connection_group_cancel(vcap->group);
                        });
                  },
                  drv->queue);
          }
          nw_release(sec);
        });
    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_release(ep);
    drv->group = nw_connection_group_create(desc, params);
    nw_release(desc);
    nw_release(params);
    if (drv->group == NULL) {
        nw_doorbell_teardown(c);
        dispatch_release(drv->queue);
        balloc->free(drv, sizeof(*drv), balloc->ctx);
        nw_conn_handle_free(c);
        return WTQ_ERR_BACKEND;
    }

    wtq_api_session_cfg_t scfg = {
        .alloc = alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = events,
        .user = user,
        .drv = drv,
        .ops = &nw_driver_ops,
    };
    wtq_session_t *session = NULL;
    wtq_result_t rc = wtq_api_session_create(&scfg, &session);
    if (rc == WTQ_OK)
        rc = wtq_api_session_connect(session, connect);
    if (rc != WTQ_OK) {
        if (session != NULL)
            wtq_session_release(session);
        nw_doorbell_teardown(c);
        nw_release(drv->group);
        dispatch_release(drv->queue);
        balloc->free(drv, sizeof(*drv), balloc->ctx);
        nw_conn_handle_free(c);
        return rc;
    }
    drv->session = session; /* the backend's reference */
    if (session_ref_out != NULL) {
        wtq_session_add_ref(session); /* the caller's reference */
        *session_ref_out = session;
    }

    /* the ownership split: the handle borrows the driver; the driver
     * pins itself with the lifecycle pin until on_stopped returned */
    c->drv = drv;
    drv->pub = c;
    drv->pins = 1;

    struct wtq_driver *cap = drv;
    nw_connection_group_set_queue(drv->group, drv->queue);
    nw_connection_group_set_receive_handler(
        drv->group, 65535, true,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool done) {
          (void)ctx;
          (void)done;
          NWDBG("group recv content=%zu\n",
                content ? dispatch_data_get_size(content) : 0);
        });
    nw_connection_group_set_new_connection_handler(
        drv->group, ^(nw_connection_t in) {
          cap->callback_depth++;
          adopt_inbound(cap, in);
          cap->callback_depth--;
        });
    nw_connection_group_set_state_changed_handler(
        drv->group, ^(nw_connection_group_state_t st, nw_error_t e) {
          cap->callback_depth++;
          NWDBG("group state=%d err=%d/%d\n", (int)st,
                e ? (int)nw_error_get_error_domain(e) : -1,
                e ? nw_error_get_error_code(e) : 0);
          if (st == nw_connection_group_state_ready) {
              if (!cap->started && cap->session != NULL) {
                  cap->started = true;
                  /* the QUIC datagram flow — extracted from the LIVE
                   * group only (extract_connection returns NULL before
                   * the group starts), all flags explicit */
                  cap->dgram = group_extract(cap, false, true);
                  if (cap->dgram != NULL) {
                      cap->pins++; /* the dgram flow pins the root */
                      nw_connection_set_state_changed_handler(
                          cap->dgram,
                          ^(nw_connection_state_t dst, nw_error_t de) {
                            cap->callback_depth++;
                            if (dst == nw_connection_state_ready) {
                                cap->dgram_ready = true;
                                dgram_arm_receive(cap);
                            } else if (dst == nw_connection_state_failed) {
                                if (de != NULL && !cap->shutdown_started)
                                    stage_nw_error(cap, de);
                                /* converge on `cancelled` — the ONLY
                                 * final state (same rule as streams) */
                                if (!cap->dgram_cancel_issued) {
                                    cap->dgram_cancel_issued = true;
                                    nw_connection_cancel(cap->dgram);
                                }
                            } else if (dst ==
                                       nw_connection_state_cancelled) {
                                cap->dgram_terminal = true;
                                dgram_maybe_reap(cap,
                                                 WTQ_NW_REAP_SRC_STATE);
                            }
                            cap->callback_depth--;
                          });
                      nw_connection_set_queue(cap->dgram, cap->queue);
                      nw_connection_start(cap->dgram);
                  }
                  wtq_api_session_enter(cap->session);
                  (void)wtq_api_session_start(cap->session, nw_now_us());
                  nw_leave_and_poll(cap);
              }
          } else if (st == nw_connection_group_state_waiting) {
              /* `waiting` with an error is NW's retry loop: a client
               * backend fails FAST — stage the causal error and
               * cancel; the terminal state follows. (Trust rejection
               * never surfaces here — measured; the explicit verifier
               * handles it.) */
              if (e != NULL && !cap->shutdown_started) {
                  stage_nw_error(cap, e);
                  cap->shutdown_started = true;
                  nw_connection_group_cancel(cap->group);
              }
          } else if (st == nw_connection_group_state_failed ||
                     st == nw_connection_group_state_cancelled) {
              group_handle_terminal(cap, e);
              if (st == nw_connection_group_state_failed &&
                  !cap->shutdown_started)
                  (void)op_conn_close(cap, 0); /* converge to cancelled */
          }
          cap->callback_depth--;
        });

    /*
     * STANDING LIMITATION (measured on this SDK): a multiplex group
     * that never becomes ready emits NO state transition with an error
     * — not on the group handler, and extract_connection returns NULL
     * before the group starts, so no per-connection canary can exist
     * either. Pre-ready setup failures with no local observation
     * (dead port, DNS) are therefore INVISIBLE to this backend; per
     * the design (§2.6), the owning layer's connect timeout governs
     * and the engine adds no timer. LOCALLY OBSERVED trust rejection
     * is the exception: the explicit verifier above evaluates trust
     * itself, so a wrong certificate fails fast with a sealed
     * NW_TRUST record instead of hanging. Errors NW does deliver (on
     * live extracted connections and on group failure) are mapped
     * into the transport-error record.
     */
    /*
     * PUBLISH BEFORE START: the group's callbacks run on the domain
     * the moment it starts — possibly before this function returns —
     * and an owner acting from a callback (stop_begin, post, domain
     * access through its own handle variable) must find the handle
     * already published. Callbacks may precede create's RETURN, but
     * never precede output-handle publication. The CONSTRUCTION
     * REFERENCE pins the handle across the start: an earliest callback
     * that stops and releases cannot free it out from under this
     * frame (dropping it below behaves like any release — fail-safe
     * implicit stop or deferred free apply as usual).
     */
    *conn_out = c;
    wtq_nw_conn_retain(c); /* construction reference, held across the start */
#ifdef WTQ_NW_TESTING
    if (wtq_nw_test_on_earliest != NULL) {
        /* deterministic earliest domain block: scheduled BEFORE the
         * group starts, so it runs ahead of every transport callback */
        void (*hook)(void *) = wtq_nw_test_on_earliest;
        void *hctx = wtq_nw_test_on_earliest_ctx;
        dispatch_async(drv->queue, ^{ hook(hctx); });
    }
#endif
    WTQ_NW_TEST(atomic_fetch_add(&wtq_nw_test_live_drivers, 1));

    /*
     * START ON THE MAIN THREAD. Network.framework intermittently drops
     * inbound streams that are pending at the group's READY unless
     * nw_connection_group_start() runs on the main thread (proven with a
     * pure-Network reproducer; the create thread and a serviced non-main
     * run loop do NOT fix it). If we are already on the main thread, start
     * directly; otherwise enqueue exactly one asynchronous start on the
     * main dispatch queue (never dispatch_sync(main): the caller may block
     * or not service the main queue while waiting). *conn_out is already
     * published, and the construction reference is held across either path.
     */
    if (pthread_main_np() != 0) {
        pthread_mutex_lock(&c->mu);
        c->start_state = NW_START_STARTING;
        pthread_mutex_unlock(&c->mu);
        nw_connection_group_start(drv->group);
        bool enqueue_stop = false;
        pthread_mutex_lock(&c->mu);
        c->start_state = NW_START_STARTED;
        if (c->stop_started && !c->stop_enqueued) {
            c->stop_enqueued = true;
            enqueue_stop = true;
        }
        pthread_mutex_unlock(&c->mu);
        if (enqueue_stop)
            dispatch_async_f(drv->queue, drv, nw_stop_worker);
        wtq_nw_conn_release(c); /* the construction reference */
    } else {
        /* start_state stays NW_START_QUEUED; the trampoline releases the
         * construction reference when it has started (and enqueued any
         * latched stop). */
        dispatch_async_f(dispatch_get_main_queue(), c, nw_main_start_tramp);
    }
    return WTQ_OK;
}

wtq_result_t wtq_nw_conn_create(const wtq_nw_conn_cfg_t *cfg,
                                wtq_nw_conn_t **conn_out)
{
    if (conn_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *conn_out = NULL;
    /* struct_size REALLY versions the config: the v1 prefix (through
     * `user`) is required; optional tails are read only when their
     * COMPLETE field fits, defaulting otherwise; a larger future
     * struct is accepted with its unknown tail ignored. */
#define NW_CFG_HAS(field)                                          \
    ((size_t)cfg->struct_size >=                                   \
     offsetof(wtq_nw_conn_cfg_t, field) + sizeof(cfg->field))
    const size_t min_size =
        offsetof(wtq_nw_conn_cfg_t, user) +
        sizeof(((const wtq_nw_conn_cfg_t *)0)->user);
    if (cfg == NULL || (size_t)cfg->struct_size < min_size ||
        cfg->server_name == NULL || cfg->port == 0 ||
        cfg->connect == NULL || cfg->events == NULL)
        return WTQ_ERR_INVALID_ARG;
    const wtq_alloc_t *alloc =
        NW_CFG_HAS(alloc) && cfg->alloc != NULL ? cfg->alloc
                                                : wtq_alloc_default();
    void (*on_stopped)(void *) =
        NW_CFG_HAS(on_stopped) ? cfg->on_stopped : NULL;
    void *stopped_ctx = NW_CFG_HAS(stopped_ctx) ? cfg->stopped_ctx : NULL;
    /* each tail field gates on ITS OWN complete fit: a struct cut
     * between on_doorbell and doorbell_ctx yields the callback with a
     * NULL context, never a read past the caller's struct */
    void (*on_doorbell)(void *) =
        NW_CFG_HAS(on_doorbell) ? cfg->on_doorbell : NULL;
    void *doorbell_ctx = NW_CFG_HAS(doorbell_ctx) ? cfg->doorbell_ctx : NULL;
#undef NW_CFG_HAS
    return nw_conn_build(alloc, cfg->events, cfg->user, cfg->server_name,
                         cfg->port, cfg->insecure_skip_verify,
                         cfg->connect, on_stopped, stopped_ctx,
                         on_doorbell, doorbell_ctx,
                         NULL, conn_out);
}

#ifdef WTQ_NW_TESTING
/* --- internal constructor + blocking rundown (tests) ------------------------ */

wtq_result_t wtq_nw_conn_create_internal(const wtq_nw_test_cfg_t *cfg,
                                         struct wtq_driver **drv_out,
                                         wtq_session_t **session_out)
{
    if (cfg == NULL || cfg->alloc == NULL || cfg->events == NULL ||
        cfg->host == NULL || cfg->port == 0 || cfg->connect == NULL ||
        drv_out == NULL || session_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *drv_out = NULL;
    *session_out = NULL;

    struct wtq_nw_conn *c = NULL;
    wtq_session_t *session = NULL;
    wtq_result_t rc = nw_conn_build(cfg->alloc, cfg->events, cfg->user,
                                    cfg->host, cfg->port,
                                    cfg->insecure_no_verify, cfg->connect,
                                    NULL, NULL, NULL, NULL, &session, &c);
    if (rc != WTQ_OK)
        return rc;
    *drv_out = c->drv;
    *session_out = session;
    return WTQ_OK;
}

/*
 * Test-only blocking rundown: the ONE lifecycle implementation
 * composed — stop_begin + bounded join + bounded internal quiescence
 * (join deliberately does not wait for TRANSPORT_RETIRED stragglers;
 * the tests' leak accounting does), then the create reference drops.
 * Returns false on timeout, leaking rather than freeing under a live
 * callback — the same fail-safe as the old implementation.
 */
bool wtq_nw_conn_rundown_internal(struct wtq_driver *drv, int timeout_ms)
{
    if (drv == NULL)
        return true;
    wtq_nw_conn_t *c = drv->pub;
    if (c == NULL)
        return false;
    (void)wtq_nw_conn_stop_begin(c);

    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += timeout_ms / 1000;
    dl.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) {
        dl.tv_sec++;
        dl.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&c->mu);
    while (!c->stopped_done)
        if (pthread_cond_timedwait(&c->cv, &c->mu, &dl) == ETIMEDOUT)
            break;
    bool done = c->stopped_done;
    pthread_mutex_unlock(&c->mu);
    if (!done)
        return false; /* leak-safe: nothing freed under callbacks */

    if (wtq_nw_test_park_reaps) {
        /* diagnostic leak-everything mode: rundown succeeds by
         * deliberately leaking the whole internal root */
        wtq_nw_conn_release(c);
        return true;
    }

    /* bounded internal quiescence: every shell/holder retired and the
     * root freed (single live connection per rundown by test design) */
    bool gone = false;
    for (int spin = 0; spin < timeout_ms / 25 && !gone; spin++) {
        gone = atomic_load(&wtq_nw_test_live_drivers) == 0;
        if (!gone) {
            struct timespec ts = { 0, 25 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    wtq_nw_conn_release(c);
    return gone;
}
#endif /* WTQ_NW_TESTING */
