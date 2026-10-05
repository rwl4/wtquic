/*
 * MsQuic stream: the per-stream event handler. Receive accepts an exact
 * prefix, stopping even when the app pauses from inside a callback. When
 * already paused, a data-bearing RECEIVE accepts zero bytes so MsQuic holds it
 * for in-order redelivery on resume, and a graceful FIN with nothing to
 * redeliver is deferred and replayed on resume; nothing reaches the engine
 * until resume. Otherwise MsQuic's own flow-control windows are the only
 * inbound throttle.
 *
 * Qualified peer streams delay native StreamClose/stream-ID credit until
 * transport shutdown, engine detach, send completion and API lease release.
 * Their preallocated records retire only at a safe admission/dispatch root.
 * Legacy/local native handles close at SHUTDOWN_COMPLETE; their metadata
 * likewise survives outstanding engine, API and send borrows.
 */

#include <string.h>

#include "msq_internal.h"

#include "proto/h3_err.h"

struct wtq_dstream *wtq_msq_stream_new(struct wtq_driver *drv,
                                       bool is_local, bool is_bidi,
                                       uint64_t id)
{
    struct wtq_dstream *ds = NULL;
    if (drv->bounded_admission && !is_local) {
        size_t first = is_bidi ? 8u : 0u;
        size_t end = is_bidi ? 15u : 8u;
        for (size_t i = first; i < end; ++i) {
            if (!drv->peers[i].occupied) { ds = &drv->peers[i]; break; }
        }
    } else {
        ds = drv->alloc.alloc(sizeof(*ds), drv->alloc.ctx);
    }

    if (ds == NULL)
        return NULL;
    memset(ds, 0, sizeof(*ds));
    ds->occupied = true;
    ds->pooled = drv->bounded_admission && !is_local;
    ds->generation = ++drv->peer_generation;
    ds->drv = drv;
    ds->id = id;
    ds->is_local = is_local;
    ds->is_bidi = is_bidi;
    ds->next = drv->streams;
    drv->streams = ds;
    return ds;
}

static void admission_remove(struct wtq_driver *drv, struct wtq_dstream *ds)
{
    struct wtq_dstream *prev = NULL;
    for (struct wtq_dstream *p = drv->admission_head; p; p = p->admission_next) {
        if (p == ds) {
            if (prev) prev->admission_next = p->admission_next;
            else drv->admission_head = p->admission_next;
            if (drv->admission_tail == p) drv->admission_tail = prev;
            p->admission_next = NULL;
            return;
        }
        prev = p;
    }
}

static void stream_collect(struct wtq_driver *drv,
                            const struct wtq_dstream *borrowed)
{
    struct wtq_dstream **link = &drv->streams;
    while (*link != NULL) {
        struct wtq_dstream *ds = *link;
        if (ds != borrowed && ds->shutdown_complete && ds->ectx == NULL &&
            ds->admission.es == NULL && ds->admission.state != 1 &&
            !ds->credit_held && ds->send_refs == 0) {
            *link = ds->next;
            if (ds->pooled) admission_remove(drv, ds);
            if (ds->pooled && drv->session)
                wtq_conn_peer_admission_forget(wtq_api_session_conn(drv->session),
                    &ds->admission);
            HQUIC handle = ds->stream;
            ds->stream = NULL;
            if (handle) {
                drv->api_depth++;
                drv->api->StreamClose(handle);
                drv->api_depth--;
            }
            if (ds->pooled) ds->occupied = false;
            else drv->alloc.free(ds, sizeof(*ds), drv->alloc.ctx);
        } else {
            link = &ds->next;
        }
    }
}

void wtq_msq_stream_collect(struct wtq_driver *drv,
                            const struct wtq_dstream *borrowed)
{
    if (drv->callback_depth || drv->api_depth ||
        atomic_load_explicit(&drv->sweeping, memory_order_acquire) ||
        (drv->bounded_admission &&
         !wtq_api_session_admission_root(drv->session))) return;
    stream_collect(drv, borrowed);
}

wtq_result_t wtq_msq_stream_input(struct wtq_dstream *ds,
    const uint8_t *data, size_t len, bool fin, size_t *consumed)
{
    wtq_conn_t *conn = wtq_api_session_conn(ds->drv->session);
    wtq_result_t rc;
    if (ds->pooled) {
        bool was_waiting = ds->admission.state == 1;
        rc = wtq_conn_peer_admission_bytes(conn, &ds->admission,
            data, len, fin, wtq_msq_now_us(), consumed);
        ds->ectx = ds->admission.es;
        if (!was_waiting && ds->admission.state == 1) {
            /* Ready-prefix order is independent of direction and recycled
             * pool indices. There is at most one node per peer record. */
            ds->admission_next = NULL;
            if (ds->drv->admission_tail)
                ds->drv->admission_tail->admission_next = ds;
            else ds->drv->admission_head = ds;
            ds->drv->admission_tail = ds;
        }
    } else {
        rc = wtq_conn_on_stream_bytes_accounted(conn, ds->ectx,
            data, len, fin, wtq_msq_now_us(), consumed);
    }
    return rc;
}

/* Feed one FIN to the engine at most once per stream: data-carrying
 * receives flag it, and PEER_SEND_SHUTDOWN follows as a separate
 * event — whichever arrives first delivers it. */
static void stream_feed_fin(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;

    if (ds->fin_delivered || (!ds->pooled && ds->ectx == NULL) || drv->session == NULL)
        return;
    wtq_api_session_enter(drv->session);
    size_t consumed = 0;
    wtq_result_t rc = wtq_msq_stream_input(ds, NULL, 0, true, &consumed);
    ds->fin_delivered = rc == WTQ_OK;
    ds->fin_pending = rc == WTQ_ERR_WOULD_BLOCK;
    wtq_msq_conn_leave_and_poll(drv);
}

static void admission_lease(wtq_driver_t *drv, wtq_dstream_t *ds, bool held)
{
    (void)drv;
    ds->credit_held = held; /* releasing only marks; never collects or publishes */
}

static wtq_result_t admission_service(wtq_driver_t *drv)
{
    if (drv->shutdown_started || atomic_load_explicit(&drv->sweeping,
            memory_order_acquire)) return WTQ_ERR_CLOSED;
    stream_collect(drv, drv->admission_borrowed);
    struct { struct wtq_dstream *ds; uint64_t generation; } snapshot[15];
    size_t count = 0;
    for (struct wtq_dstream *ds = drv->admission_head;
         ds && count < 15; ds = ds->admission_next) {
        snapshot[count].ds = ds;
        snapshot[count++].generation = ds->generation;
    }
    wtq_result_t result = WTQ_OK;
    for (size_t i = 0; i < count && !drv->shutdown_started; ++i) {
        struct wtq_dstream *ds = snapshot[i].ds;
        if (!ds->occupied || ds->generation != snapshot[i].generation) continue;
        wtq_result_t rc;
        if (ds->admission.state == 1) {
            rc = wtq_api_session_admit(drv->session, &ds->admission);
            ds->ectx = ds->admission.es;
            if (rc == WTQ_ERR_WOULD_BLOCK) continue;
            if (rc != WTQ_OK) return rc;
            ds->admission_resume_pending = true;
        }
        if (!ds->admission_resume_pending || !ds->ectx) {
            /* A terminal or successful explicit receive operation took over. */
            ds->admission_resume_pending = false;
            admission_remove(drv, ds);
            continue;
        }
        /* Native half-terminals can precede publication. Replay their original
         * order before any deferred FIN; RESET discarded the receive suffix. */
        for (unsigned n = 0; n < 2 && ds->ectx && !drv->shutdown_started; ++n) {
            wtq_conn_t *conn = wtq_api_session_conn(drv->session);
            if (ds->admission_stop_pending &&
                (ds->admission_stop_first || !ds->admission_reset_pending)) {
                ds->admission_stop_pending = false;
                (void)wtq_conn_on_stop_sending(conn, ds->ectx,
                    ds->admission_stop_error, wtq_msq_now_us());
            } else if (ds->admission_reset_pending) {
                ds->admission_reset_pending = false;
                ds->admission_resume_pending = false;
                (void)wtq_conn_on_stream_reset(conn, ds->ectx,
                    ds->admission_reset_error, wtq_msq_now_us());
            }
        }
        if (ds->admission_resume_pending && !ds->recv_disabled &&
            ds->ectx && !drv->shutdown_started) {
            rc = wtq_msq_driver_ops()->recv_enable(drv, ds, true);
            if (rc != WTQ_OK) {
                if (result == WTQ_OK) result = rc;
                continue; /* retain one retry obligation, never reopen */
            }
        }
        ds->admission_resume_pending = false;
        admission_remove(drv, ds);
    }
    return result;
}

wtq_result_t wtq_msq_session_create_bounded(struct wtq_driver *drv,
    const wtq_api_session_cfg_t *cfg, const wtq_msquic_tuning_t *tuning,
    wtq_session_t **out)
{
    QUIC_SETTINGS settings;
    wtq_msq_settings_init(&settings, tuning);
    if (settings.PeerUnidiStreamCount != 8 || settings.PeerBidiStreamCount != 7)
        return wtq_api_session_create_accounted(cfg, out);
    const wtq_api_admission_ops_t ops = {
        .peer_uni = 8, .peer_bidi = 7,
        .service = admission_service, .lease = admission_lease,
    };
    wtq_result_t rc = wtq_api_session_create_admission(cfg, &ops, out);
    if (rc == WTQ_OK) drv->bounded_admission = true;
    return rc;
}

void wtq_msq_stream_writable_check(struct wtq_driver *drv,
                                   struct wtq_dstream *ds)
{
    /* edge-triggered: armed by a WOULD_BLOCK gather, delivered once.
     * A stream already shut down, refused by the engine, or with no
     * session linkage has no one to retry — stay armed for nobody. */
    if (!ds->send_blocked || drv->session == NULL || ds->ectx == NULL ||
        ds->stream == NULL)
        return;
    ds->send_blocked = false;
    wtq_api_session_enter(drv->session);
    wtq_conn_on_stream_writable(wtq_api_session_conn(drv->session),
                                ds->ectx);
    wtq_msq_conn_leave_and_poll(drv);
}

/* The event switch, run inside the connection's guard bracket by
 * wtq_msq_stream_callback. The stream struct outlives its terminal event,
 * so no self-free here — the wrapper
 * still reads leave/ctx into locals for symmetry with the conn path. */
static QUIC_STATUS stream_dispatch(HQUIC stream, struct wtq_dstream *ds,
                                   QUIC_STREAM_EVENT *ev)
{
    struct wtq_driver *drv = ds->drv;

    (void)stream;
    switch (ev->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        /* The id the backend computed at open MUST be the id MsQuic
         * assigned — a divergence would corrupt every id-derived piece
         * of session state, so it kills the connection. */
        if (QUIC_FAILED(ev->START_COMPLETE.Status))
            break; /* start failed: the connection is going down */
        if (ev->START_COMPLETE.ID != ds->id) {
            /* the main MsQuic backend-invariant failure: stage its
             * full-fidelity causal detail (native value = the MsQuic
             * status; the diverging ids belong in diagnostics, not in
             * the native error field) before the terminal input */
            wtq_msq_conn_stage_local_cause(
                drv, WTQ_H3_INTERNAL_ERROR,
                (int64_t)ev->START_COMPLETE.Status);
            drv->event_err = WTQ_H3_INTERNAL_ERROR;
            drv->event_err_set = true;
            if (drv->session != NULL) {
                wtq_api_session_enter(drv->session);
                wtq_msq_conn_put_error_detail(drv);
                wtq_conn_on_conn_closed(
                    wtq_api_session_conn(drv->session),
                    WTQ_H3_INTERNAL_ERROR, false, wtq_msq_now_us());
                wtq_msq_conn_leave_and_poll(drv);
            }
            if (!drv->shutdown_started) {
                drv->shutdown_started = true;
                drv->api->ConnectionShutdown(
                    drv->conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTQ_H3_INTERNAL_ERROR);
            }
        }
        break;

    case QUIC_STREAM_EVENT_RECEIVE: {
        bool fin = (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;

        /*
         * Logical pause arrest. StreamReceiveSetEnabled(FALSE) is
         * asynchronous, so this RECEIVE may have been queued behind the
         * app's pause. While logically paused NOTHING reaches the engine:
         *  - a data-bearing receive is rejected by accepting zero bytes,
         *    so MsQuic holds the unconsumed bytes (and any FIN riding
         *    them) and stops indicating RECEIVE until resume, at which
         *    point they redeliver exactly once, in order;
         *  - a pure zero-byte FIN carries no data to hold and MsQuic will
         *    not re-indicate it, so the backend remembers it and replays
         *    it to the engine on resume.
         * Accounted input also arrests the current event between callbacks,
         * including opened followed by coalesced payload.
         */
        if (ds->recv_disabled) {
            if (ev->RECEIVE.TotalBufferLength > 0) {
                ds->recv_held_data = true;
                ev->RECEIVE.TotalBufferLength = 0;
            } else if (fin) {
                ds->fin_pending = true;
            }
            break;
        }

        /* Feed the accepted prefix only; MsQuic owns the pending suffix. */
        if ((!ds->pooled && ds->ectx == NULL) || drv->session == NULL)
            break; /* engine refused the stream: discard the bytes */

        wtq_estream_t *key = ds->ectx;

        wtq_api_session_enter(drv->session);
        if (ev->RECEIVE.BufferCount == 0) {
            if (fin && !ds->fin_delivered) {
                size_t consumed = 0;
                wtq_result_t rc = wtq_msq_stream_input(ds, NULL, 0, true, &consumed);
                ds->fin_delivered = rc == WTQ_OK;
                ds->fin_pending = rc == WTQ_ERR_WOULD_BLOCK;
            }
        } else {
            uint64_t accepted = 0;
            uint64_t total = ev->RECEIVE.TotalBufferLength;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; i++) {
                if ((!ds->pooled && ds->ectx != key) || drv->shutdown_started)
                    break; /* retired: discard the remaining transport input */
                if (ds->recv_disabled) {
                    ev->RECEIVE.TotalBufferLength = accepted;
                    ds->recv_held_data = accepted < total;
                    ds->fin_pending = fin && !ds->recv_held_data;
                    break;
                }
                const QUIC_BUFFER *b = &ev->RECEIVE.Buffers[i];
                bool last = i + 1 == ev->RECEIVE.BufferCount;
                bool this_fin = fin && last;

                size_t consumed = 0;
                wtq_result_t rc = wtq_msq_stream_input(ds, b->Buffer,
                                             b->Length, this_fin, &consumed);
                accepted += consumed;
                if (rc == WTQ_ERR_WOULD_BLOCK) {
                    ev->RECEIVE.TotalBufferLength = accepted;
                    /* A fully consumed preamble may still owe a bare FIN. */
                    ds->recv_held_data = accepted < total;
                    ds->fin_pending = fin && !ds->recv_held_data;
                    break;
                }
                if (this_fin && rc == WTQ_OK)
                    ds->fin_delivered = true;
                if (rc != WTQ_OK)
                    break; /* engine closed: remaining bytes are moot */
            }
        }
        wtq_msq_conn_leave_and_poll(drv);
        break;
    }

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        /* graceful end of the peer's send direction; the FIN usually
         * already arrived on a RECEIVE. While paused nothing is delivered:
         * if data is held for redelivery the FIN rides it on resume, so
         * only a shutdown with nothing held needs the backend to remember
         * the FIN and replay it on resume. */
        if (ds->recv_disabled || (ds->pooled && ds->admission.state == 1)) {
            if (!ds->recv_held_data)
                ds->fin_pending = true;
            break;
        }
        stream_feed_fin(ds);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        /* the peer aborted its send: the receive direction is terminal,
         * any held-back bytes are discarded, and no resume is owed — clear
         * the logical pause and any deferred FIN so nothing lingers */
        ds->recv_disabled = false;
        ds->recv_held_data = false;
        ds->fin_pending = false;
        /* A bidi send half may keep ectx alive after receive RESET. */
        ds->admission_resume_pending = false;
        if (ds->pooled && ds->admission.es == NULL) {
            if (ds->admission.state == 1) {
                ds->admission_reset_pending = true;
                ds->admission_reset_error = ev->PEER_SEND_ABORTED.ErrorCode;
            } else ds->admission.state = 3;
        }
        if (ds->ectx != NULL && drv->session != NULL) {
            wtq_api_session_enter(drv->session);
            (void)wtq_conn_on_stream_reset(
                wtq_api_session_conn(drv->session), ds->ectx,
                ev->PEER_SEND_ABORTED.ErrorCode, wtq_msq_now_us());
            wtq_msq_conn_leave_and_poll(drv);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        if (ds->pooled && ds->ectx == NULL && !ds->admission_stop_pending) {
            ds->admission_stop_pending = true;
            ds->admission_stop_first = !ds->admission_reset_pending;
            ds->admission_stop_error = ev->PEER_RECEIVE_ABORTED.ErrorCode;
        }
        if (ds->ectx != NULL && drv->session != NULL) {
            wtq_api_session_enter(drv->session);
            (void)wtq_conn_on_stop_sending(
                wtq_api_session_conn(drv->session), ds->ectx,
                ev->PEER_RECEIVE_ABORTED.ErrorCode, wtq_msq_now_us());
            wtq_msq_conn_leave_and_poll(drv);
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        /* the record's borrow ends here (data ACKed, or canceled by a
         * reset/close — exactly one completion either way) */
        struct wtq_msq_send_hdr *h = ev->SEND_COMPLETE.ClientContext;

        if (h == NULL)
            break;
        if (h->gather) {
            struct wtq_msq_gather_rec *rec = (struct wtq_msq_gather_rec *)h;
            void *cookie = rec->cookie;
            struct wtq_dstream *rds = rec->ds;

            rds->send_refs--;
            rds->inflight_bytes -= rec->bytes;
            wtq_msq_gather_put(drv, rec);
            drv->pending_sends--;
            /* forward exactly once — even when the engine is already
             * closed, the application must get its buffers back. Every
             * SEND_COMPLETE precedes the connection's SHUTDOWN_COMPLETE,
             * so the session linkage still stands here. */
            if (drv->session != NULL) {
                wtq_api_session_enter(drv->session);
                wtq_conn_on_send_complete(
                    wtq_api_session_conn(drv->session), cookie,
                    ev->SEND_COMPLETE.Canceled);
                wtq_msq_conn_leave_and_poll(drv);
            }
            /* the completion released this stream's budget: a send it
             * refused meanwhile can go now — the buffers-back callback
             * above stays first, so the app retries with its data
             * already returned */
            wtq_msq_stream_writable_check(drv, rds);
        } else {
            struct wtq_msq_send_rec *rec = (struct wtq_msq_send_rec *)h;

            ds->send_refs--;
            drv->alloc.free(rec, rec->alloc_size, drv->alloc.ctx);
            drv->pending_sends--;
        }
        if (drv->pending_sends == 0 && drv->shutdown_when_flushed &&
            !drv->shutdown_started) {
            drv->shutdown_started = true;
            /* post-terminal CLEANUP: stage no error record for it */
            drv->close_cleanup = true;
            drv->api->ConnectionShutdown(
                drv->conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                WTQ_H3_NO_ERROR);
        }
        break;
    }

    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE: {
        /* the transport's per-stream buffering advice raises (or
         * lowers, floored elsewhere) the in-flight send budget */
        uint64_t ideal = ev->IDEAL_SEND_BUFFER_SIZE.ByteCount;
        bool grew = ideal > ds->ideal_send;

        ds->ideal_send = ideal;
        /* a raised ceiling can admit a refused send with no completion
         * coming to say so — the peer may be fully caught up, its
         * final ACK parked behind its delayed-ACK timer */
        if (grew)
            wtq_msq_stream_writable_check(drv, ds);
        break;
    }

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        /* Publish the dead handle before Close can synchronously call back.
         * The record is only eligible after Close and this frame return. */
        HQUIC handle = ds->stream;
        if (!ds->pooled || ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
            ds->stream = NULL;
        if (!ds->pooled && !ev->SHUTDOWN_COMPLETE.AppCloseInProgress && handle != NULL)
            drv->api->StreamClose(handle);
        ds->shutdown_complete = true;
        break;
    }

    default:
        /* SEND_SHUTDOWN_COMPLETE, IDEAL_SEND_BUFFER_SIZE, PEER_ACCEPTED
         * carry nothing the backend acts on yet */
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API wtq_msq_stream_callback(HQUIC stream, void *ctx,
                                             QUIC_STREAM_EVENT *ev)
{
    struct wtq_dstream *ds = ctx;
    struct wtq_driver *drv = ds->drv;
    if (atomic_load_explicit(&drv->sweeping, memory_order_acquire))
        return QUIC_STATUS_SUCCESS;
    /* Same guard as the connection (guard.ctx is the shared lane). MsQuic
     * never nests callbacks for one connection, so this acquires the lane
     * once per dispatch. */
    void (*g_leave)(void *) = drv->guard.leave;
    void *g_ctx = drv->guard.ctx;
    if (drv->guard.enter != NULL)
        drv->guard.enter(g_ctx);
    bool admission_root = drv->callback_depth == 0 && drv->api_depth == 0 &&
        wtq_api_session_admission_root(drv->session);
    wtq_msq_stream_collect(drv, ds);
    drv->callback_depth++;
    QUIC_STATUS st = stream_dispatch(stream, ds, ev);
    drv->callback_depth--;
    if (admission_root && !drv->shutdown_started && drv->session != NULL) {
        drv->admission_borrowed = ds;
        (void)wtq_session_service_stream_admission(drv->session);
        drv->admission_borrowed = NULL;
    }
    if (g_leave != NULL)
        g_leave(g_ctx);
    return st;
}
