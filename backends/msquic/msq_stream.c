/*
 * MsQuic stream: the per-stream event handler. Receive is consume-all
 * while running — every byte MsQuic indicates is fed straight into the
 * engine and the event returns success — except when the app has logically
 * paused the stream (wtq_stream_pause_receive). While paused, a data-
 * bearing RECEIVE is arrested by accepting zero bytes so MsQuic holds it
 * for in-order redelivery on resume, and a graceful FIN with nothing to
 * redeliver is deferred and replayed on resume; nothing reaches the engine
 * until resume. Otherwise MsQuic's own flow-control windows are the only
 * inbound throttle.
 *
 * A backend stream's transport life ends at its SHUTDOWN_COMPLETE
 * (StreamClose there); the struct survives until the connection sweep
 * because engine stream slots may still hold the pointer (driver ops on
 * a transport-dead stream return WTQ_ERR_CLOSED).
 */

#include <string.h>

#include "msq_internal.h"

#include "proto/h3_err.h"

struct wtq_dstream *wtq_msq_stream_new(struct wtq_driver *drv,
                                       bool is_local, bool is_bidi,
                                       uint64_t id)
{
    struct wtq_dstream *ds =
        drv->alloc.alloc(sizeof(*ds), drv->alloc.ctx);

    if (ds == NULL)
        return NULL;
    memset(ds, 0, sizeof(*ds));
    ds->drv = drv;
    ds->id = id;
    ds->is_local = is_local;
    ds->is_bidi = is_bidi;
    ds->next = drv->streams;
    drv->streams = ds;
    return ds;
}

/* Feed one FIN to the engine at most once per stream: data-carrying
 * receives flag it, and PEER_SEND_SHUTDOWN follows as a separate
 * event — whichever arrives first delivers it. */
static void stream_feed_fin(struct wtq_dstream *ds)
{
    struct wtq_driver *drv = ds->drv;

    if (ds->fin_delivered || ds->ectx == NULL || drv->session == NULL)
        return;
    ds->fin_delivered = true;
    wtq_api_session_enter(drv->session);
    (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(drv->session),
                                   ds->ectx, NULL, 0, true,
                                   wtq_msq_now_us());
    wtq_msq_conn_leave_and_poll(drv);
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
 * wtq_msq_stream_callback. The stream struct outlives its terminal event
 * (freed only in the connection sweep), so no self-free here — the wrapper
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
         * The bytes of a receive ALREADY being processed are untouched —
         * this only arrests the queued-later events the public pause must
         * stop.
         */
        if (ds->recv_disabled) {
            if (ev->RECEIVE.BufferCount > 0) {
                ds->recv_held_data = true;
                ev->RECEIVE.TotalBufferLength = 0;
            } else if (fin) {
                ds->fin_pending = true;
            }
            break;
        }

        /* consume-all: feed every buffer, return success */
        if (ds->ectx == NULL || drv->session == NULL)
            break; /* engine refused the stream: discard the bytes */

        wtq_conn_t *ec = wtq_api_session_conn(drv->session);

        wtq_api_session_enter(drv->session);
        if (ev->RECEIVE.BufferCount == 0) {
            if (fin && !ds->fin_delivered) {
                ds->fin_delivered = true;
                (void)wtq_conn_on_stream_bytes(ec, ds->ectx, NULL, 0,
                                               true, wtq_msq_now_us());
            }
        } else {
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; i++) {
                const QUIC_BUFFER *b = &ev->RECEIVE.Buffers[i];
                bool last = i + 1 == ev->RECEIVE.BufferCount;
                bool this_fin = fin && last;

                if (this_fin)
                    ds->fin_delivered = true;
                if (wtq_conn_on_stream_bytes(ec, ds->ectx, b->Buffer,
                                             b->Length, this_fin,
                                             wtq_msq_now_us()) != WTQ_OK)
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
        if (ds->recv_disabled) {
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
        if (ds->ectx != NULL && drv->session != NULL) {
            wtq_api_session_enter(drv->session);
            (void)wtq_conn_on_stream_reset(
                wtq_api_session_conn(drv->session), ds->ectx,
                ev->PEER_SEND_ABORTED.ErrorCode, wtq_msq_now_us());
            wtq_msq_conn_leave_and_poll(drv);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
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

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        /* the stream's last event: release the transport handle; the
         * struct lives until the connection sweep */
        if (!ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
            drv->api->StreamClose(ds->stream);
        ds->stream = NULL;
        break;

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
    /* Same guard as the connection (guard.ctx is the shared lane). MsQuic
     * never nests callbacks for one connection, so this acquires the lane
     * once per dispatch. */
    void (*g_leave)(void *) = drv->guard.leave;
    void *g_ctx = drv->guard.ctx;
    if (drv->guard.enter != NULL)
        drv->guard.enter(g_ctx);
    QUIC_STATUS st = stream_dispatch(stream, ds, ev);
    if (g_leave != NULL)
        g_leave(g_ctx);
    return st;
}
