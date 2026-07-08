/*
 * MsQuic connection: the driver-op implementations and the connection
 * event handler. See msq_internal.h for the teardown-order and
 * session-linkage rules this file is built around.
 */

#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <string.h>
#include <time.h>

#include "msq_internal.h"

#include "proto/h3_err.h"

uint64_t wtq_msq_now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

struct wtq_driver *wtq_msq_conn_new(const wtq_alloc_t *alloc,
                                    const QUIC_API_TABLE *api,
                                    bool is_client)
{
    struct wtq_driver *drv = alloc->alloc(sizeof(*drv), alloc->ctx);

    if (drv == NULL)
        return NULL;
    memset(drv, 0, sizeof(*drv));
    /* C11: a dynamically allocated atomic must be atomic_init'ed before
     * any atomic operation — the zeroed representation is not portable.
     * The driver is allocated here once and never copied. */
    atomic_init(&drv->env_close_req, false);
    drv->alloc = *alloc;
    drv->api = api;
    drv->is_client = is_client;
    return drv;
}

void wtq_msq_conn_free(struct wtq_driver *drv)
{
    wtq_alloc_t alloc = drv->alloc;

    while (drv->streams != NULL) {
        struct wtq_dstream *ds = drv->streams;
        drv->streams = ds->next;
        if (ds->stream != NULL)
            drv->api->StreamClose(ds->stream);
        alloc.free(ds, sizeof(*ds), alloc.ctx);
    }
    /* every send record is back by now (each SEND_COMPLETE precedes the
     * connection's SHUTDOWN_COMPLETE); only the pool storage remains */
    while (drv->gather_chunks != NULL) {
        struct wtq_msq_gather_chunk *c = drv->gather_chunks;
        drv->gather_chunks = c->next;
        alloc.free(c, sizeof(*c), alloc.ctx);
    }
    if (drv->conn != NULL)
        drv->api->ConnectionClose(drv->conn);
    alloc.free(drv, sizeof(*drv), alloc.ctx);
}

/* Shut the QUIC connection down (at most once). Safe from any event
 * handler: ConnectionShutdown only queues. */
void wtq_msq_conn_stage_local_cause(struct wtq_driver *drv, uint64_t code,
                                    int64_t status)
{
    if (drv->close_kind != WTQ_ERR_KIND_NONE || drv->close_cleanup)
        return;
    drv->close_kind = WTQ_ERR_KIND_LOCAL;
    drv->close_err = code;
    drv->close_status = status;
}

/*
 * Consume a pending environment-close request ON THE WORKER, before any
 * shutdown-event classification: the env thread only sets the atomic
 * latch; the causal tuple is written here, on the serialization domain.
 * env_close always shuts down with 0x100 (H3_NO_ERROR).
 */
static void conn_consume_env_close(struct wtq_driver *drv)
{
    if (atomic_exchange_explicit(&drv->env_close_req, false,
                                 memory_order_acq_rel))
        wtq_msq_conn_stage_local_cause(drv, UINT64_C(0x100), 0);
}

/*
 * cleanup=false: a CAUSAL local shutdown (engine fatal, backend
 * invariant failure) — stage {LOCAL, err} for the error record (a
 * write-once engine latch from an earlier cause still wins).
 * cleanup=true: post-session-terminal connection retirement — stage
 * NOTHING; the record was sealed at the session terminal and routine
 * cleanup must never look like a transport error.
 */
static void conn_shutdown(struct wtq_driver *drv, uint64_t err,
                          bool cleanup)
{
    if (drv->shutdown_started || drv->conn == NULL)
        return;
    drv->shutdown_started = true;
    if (cleanup)
        drv->close_cleanup = true;
    else
        wtq_msq_conn_stage_local_cause(drv, err, 0);
    drv->api->ConnectionShutdown(drv->conn,
                                 QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, err);
}

/*
 * The connection-lifetime policy, applied after every engine-input
 * batch: once the WebTransport session is terminal the connection has
 * no further purpose — shut it down as soon as the in-flight sends
 * (the close capsule and FIN, under SendBufferingEnabled=FALSE their
 * completion means peer ACK) have flushed.
 */
static void conn_poll_shutdown(struct wtq_driver *drv)
{
    if (drv->shutdown_started || drv->session == NULL)
        return;

    wtq_conn_t *ec = wtq_api_session_conn(drv->session);
    if (ec == NULL)
        return;
    if (wtq_conn_is_closed(ec)) {
        /* engine-level fatal: its conn_close op already shut us down;
         * this covers transport-close-first orderings */
        conn_shutdown(drv, wtq_conn_close_code(ec), false);
        return;
    }
    switch (wtq_conn_session_state(ec)) {
    case WTQ_SESSION_CLOSED:
    case WTQ_SESSION_REJECTED:
    case WTQ_SESSION_FAILED:
        if (drv->pending_sends == 0)
            conn_shutdown(drv, WTQ_H3_NO_ERROR, true);
        else
            drv->shutdown_when_flushed = true;
        break;
    default:
        break;
    }
}

void wtq_msq_conn_leave_and_poll(struct wtq_driver *drv)
{
    if (drv->session == NULL)
        return;
    if (wtq_api_session_leave(drv->session)) {
        /* deferred destroy fired: the session and its engine conn are
         * gone; only the final teardown bracket can trigger this */
        drv->session = NULL;
        return;
    }
    conn_poll_shutdown(drv);
}

/* --- driver ops ---------------------------------------------------------- */

/*
 * Compute the id MsQuic will assign: type + (per-type count << 2), in
 * StreamStart order. The backend is the only opener of local streams
 * and per-connection calls are serialized, so the order is fixed; the
 * START_COMPLETE handler verifies every id anyway.
 */
/* Undo a wtq_msq_stream_new whose stream never came to life: the
 * struct is still the list head and no event can reference it. */
static void open_unwind(struct wtq_driver *drv, struct wtq_dstream *ds)
{
    drv->streams = ds->next;
    drv->alloc.free(ds, sizeof(*ds), drv->alloc.ctx);
}

static wtq_result_t op_open(struct wtq_driver *drv, wtq_estream_t *ectx,
                            struct wtq_dstream **out, uint64_t *id_out,
                            bool bidi)
{
    if (drv->shutdown_started || drv->conn == NULL)
        return WTQ_ERR_CLOSED;

    uint64_t type = (drv->is_client ? 0u : 1u) | (bidi ? 0u : 2u);
    uint64_t count = bidi ? drv->local_bidi_count : drv->local_uni_count;
    struct wtq_dstream *ds =
        wtq_msq_stream_new(drv, true, bidi, type + (count << 2));

    if (ds == NULL)
        return WTQ_ERR_NOMEM;
    ds->ectx = ectx;

    if (QUIC_FAILED(drv->api->StreamOpen(
            drv->conn,
            bidi ? QUIC_STREAM_OPEN_FLAG_NONE
                 : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
            wtq_msq_stream_callback, ds, &ds->stream))) {
        open_unwind(drv, ds); /* no handle: no event can fire */
        return WTQ_ERR_BACKEND;
    }
    /* StreamStart queues and returns PENDING; a synchronous failure
     * means the start op was never queued, so no events will fire. */
    if (QUIC_FAILED(drv->api->StreamStart(ds->stream,
                                          QUIC_STREAM_START_FLAG_NONE))) {
        drv->api->StreamClose(ds->stream);
        open_unwind(drv, ds);
        return WTQ_ERR_BACKEND;
    }
    if (bidi)
        drv->local_bidi_count++;
    else
        drv->local_uni_count++;
    *out = ds;
    *id_out = ds->id;
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

/*
 * Borrow-during-call send: copy the bytes into a record that lives
 * until the stream's SEND_COMPLETE (MsQuic borrows the QUIC_BUFFER and
 * the data until then; with SendBufferingEnabled=FALSE the completion
 * is the peer's ACK).
 */
static wtq_result_t op_send(wtq_driver_t *drv, wtq_dstream_t *ds,
                            const uint8_t *data, size_t len, bool fin)
{
    if (drv->shutdown_started || ds->stream == NULL)
        return WTQ_ERR_CLOSED;
    if (len == 0 && !fin)
        return WTQ_OK;
    if (len == 0) {
        /* pure FIN: graceful send-shutdown, nothing to borrow */
        if (QUIC_FAILED(drv->api->StreamShutdown(
                ds->stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0)))
            return WTQ_ERR_BACKEND;
        return WTQ_OK;
    }

    size_t rec_size = sizeof(struct wtq_msq_send_rec) + len;
    struct wtq_msq_send_rec *rec =
        drv->alloc.alloc(rec_size, drv->alloc.ctx);
    if (rec == NULL)
        return WTQ_ERR_NOMEM;
    rec->h.gather = false;
    rec->alloc_size = rec_size;
    rec->buf.Length = (uint32_t)len;
    rec->buf.Buffer = (uint8_t *)(rec + 1);
    memcpy(rec->buf.Buffer, data, len);

    if (QUIC_FAILED(drv->api->StreamSend(
            ds->stream, &rec->buf, 1,
            fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, rec))) {
        drv->alloc.free(rec, rec_size, drv->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }
    drv->pending_sends++;
    return WTQ_OK;
}

/* Get a gather record: pooled for the common span counts, a one-off
 * allocation (buffer array in the tail) above the pooled capacity. */
static struct wtq_msq_gather_rec *gather_rec_get(struct wtq_driver *drv,
                                                 size_t count)
{
    if (count > WTQ_MSQ_GATHER_SPANS) {
        if (count > (SIZE_MAX - sizeof(struct wtq_msq_gather_rec)) /
                        sizeof(QUIC_BUFFER))
            return NULL; /* allocation size would overflow */
        size_t size = sizeof(struct wtq_msq_gather_rec) +
                      count * sizeof(QUIC_BUFFER);
        struct wtq_msq_gather_rec *rec =
            drv->alloc.alloc(size, drv->alloc.ctx);

        if (rec == NULL)
            return NULL;
        rec->h.gather = true;
        rec->alloc_size = size;
        rec->bufs = (QUIC_BUFFER *)(rec + 1);
        return rec;
    }
    if (drv->gather_free == NULL) {
        struct wtq_msq_gather_chunk *c =
            drv->alloc.alloc(sizeof(*c), drv->alloc.ctx);

        if (c == NULL)
            return NULL;
        c->next = drv->gather_chunks;
        drv->gather_chunks = c;
        for (size_t i = 0; i < WTQ_MSQ_GATHER_CHUNK; i++) {
            struct wtq_msq_gather_rec *rec = &c->recs[i];

            rec->h.gather = true;
            rec->alloc_size = 0;
            rec->bufs = rec->inline_bufs;
            rec->next = drv->gather_free;
            drv->gather_free = rec;
        }
    }
    struct wtq_msq_gather_rec *rec = drv->gather_free;
    drv->gather_free = rec->next;
    return rec;
}

void wtq_msq_gather_put(struct wtq_driver *drv,
                        struct wtq_msq_gather_rec *rec)
{
    if (rec->alloc_size != 0) {
        drv->alloc.free(rec, rec->alloc_size, drv->alloc.ctx);
    } else {
        rec->next = drv->gather_free;
        drv->gather_free = rec;
    }
}

/*
 * The WebTransport data-path send: the span data is the caller's,
 * borrowed until the completion for the cookie; nothing is copied. The
 * per-stream in-flight budget is enforced BEFORE StreamSend because
 * MsQuic itself queues without bound. All-or-nothing: any non-OK return
 * means nothing was accepted and no completion will fire.
 *
 * The budget throttles queued DEPTH, it is not a maximum write size:
 * an idle stream admits one legal send of any size. A refused send has
 * no completion, so nothing would ever wake a retry — capping the size
 * of an idle send would deadlock the caller, not backpressure it.
 */
static wtq_result_t op_send_gather(wtq_driver_t *drv, wtq_dstream_t *ds,
                                   const wtq_span_t *spans, size_t count,
                                   bool fin, void *cookie)
{
    if (drv->shutdown_started || ds->stream == NULL)
        return WTQ_ERR_CLOSED;
    /* the transport takes a 32-bit buffer count; refuse before anything
     * walks the array or narrows the count */
    if (count > UINT32_MAX)
        return WTQ_ERR_TOO_LARGE;

    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > UINT32_MAX)
            return WTQ_ERR_TOO_LARGE; /* one QUIC_BUFFER per span */
        total += spans[i].len;
    }
    uint64_t ceiling = ds->ideal_send > WTQ_MSQ_SEND_BUDGET_MIN
                           ? ds->ideal_send
                           : WTQ_MSQ_SEND_BUDGET_MIN;
    /* subtraction form: an accepted oversized send can leave
     * inflight_bytes above the ceiling, so the naive addition could
     * wrap; zero-byte sends (a bare FIN) always pass */
    if (total != 0 && ds->inflight_bytes != 0 &&
        (ds->inflight_bytes >= ceiling ||
         total > ceiling - ds->inflight_bytes)) {
        /* arm the writable edge: budget release or ceiling growth
         * will deliver on_stream_writable exactly once */
        ds->send_blocked = true;
        return WTQ_ERR_WOULD_BLOCK;
    }

    struct wtq_msq_gather_rec *rec = gather_rec_get(drv, count);
    if (rec == NULL)
        return WTQ_ERR_NOMEM;
    rec->cookie = cookie;
    rec->ds = ds;
    rec->bytes = total;
    for (size_t i = 0; i < count; i++) {
        rec->bufs[i].Length = (uint32_t)spans[i].len;
        /* QUIC_BUFFER is not const-qualified, but MsQuic only reads
         * send buffers */
        rec->bufs[i].Buffer = (uint8_t *)spans[i].data;
    }

    if (QUIC_FAILED(drv->api->StreamSend(
            ds->stream, rec->bufs, (uint32_t)count,
            fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, rec))) {
        wtq_msq_gather_put(drv, rec);
        return WTQ_ERR_BACKEND; /* not accepted: no completion */
    }
    ds->inflight_bytes += total;
    drv->pending_sends++;
    /* an accepted send disarms the writable edge: the app already
     * found its own way through (typically a retry from inside
     * on_send_complete, which runs before this stream's writable
     * check) — a stale edge after it would be a lie */
    ds->send_blocked = false;
    return WTQ_OK;
}

/*
 * Structured shutdown. MsQuic's StreamShutdown flags are exactly this
 * request's shape: a same-code whole/both maps to ONE call with both
 * flags, an exact single half to one flag, and split codes (cap-gated
 * upstream) to two sequential calls — a failure of the second is a
 * partial application surfaced to the engine for connection teardown.
 */
static wtq_result_t op_shutdown_stream(wtq_driver_t *drv, wtq_dstream_t *ds,
                                       const wtq_shutdown_t *req)
{
    if (drv->shutdown_started || ds->stream == NULL)
        return WTQ_ERR_CLOSED;

    if (req->abort_send && req->abort_recv &&
        req->send_err != req->recv_err) {
        if (QUIC_FAILED(drv->api->StreamShutdown(
                ds->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
                req->send_err)))
            return WTQ_ERR_BACKEND;
        if (QUIC_FAILED(drv->api->StreamShutdown(
                ds->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                req->recv_err)))
            return WTQ_ERR_BACKEND; /* partial: engine tears down */
        return WTQ_OK;
    }

    QUIC_STREAM_SHUTDOWN_FLAGS flags = 0;
    if (req->abort_send)
        flags |= QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND;
    if (req->abort_recv)
        flags |= QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE;
    uint64_t code = req->abort_send ? req->send_err : req->recv_err;
    if (QUIC_FAILED(drv->api->StreamShutdown(ds->stream, flags, code)))
        return WTQ_ERR_BACKEND;
    return WTQ_OK;
}

/*
 * Datagram send. Borrow-during-call at the SPI (the engine's
 * association prefix is transient), so the bytes are copied into a
 * record MsQuic borrows until it reports a FINAL send state. In-flight
 * records are capped — MsQuic's own datagram queue is unbounded.
 */
static wtq_result_t op_dgram_send(wtq_driver_t *drv,
                                  const wtq_span_t *spans, size_t count)
{
    if (drv->shutdown_started || drv->conn == NULL)
        return WTQ_ERR_CLOSED;
    if (drv->dgram_inflight >= WTQ_MSQ_DGRAM_INFLIGHT_MAX)
        return WTQ_ERR_WOULD_BLOCK;

    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > SIZE_MAX - total)
            return WTQ_ERR_TOO_LARGE; /* the sum must not wrap */
        total += spans[i].len;
    }
    if (total > UINT32_MAX)
        return WTQ_ERR_TOO_LARGE; /* the engine bounds this earlier */

    size_t rec_size = sizeof(struct wtq_msq_dgram_rec) + total;
    struct wtq_msq_dgram_rec *rec =
        drv->alloc.alloc(rec_size, drv->alloc.ctx);
    if (rec == NULL)
        return WTQ_ERR_NOMEM;
    rec->alloc_size = rec_size;
    rec->buf.Length = (uint32_t)total;
    rec->buf.Buffer = (uint8_t *)(rec + 1);
    size_t off = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > 0)
            memcpy(rec->buf.Buffer + off, spans[i].data, spans[i].len);
        off += spans[i].len;
    }

    if (QUIC_FAILED(drv->api->DatagramSend(drv->conn, &rec->buf, 1,
                                           QUIC_SEND_FLAG_NONE, rec))) {
        drv->alloc.free(rec, rec_size, drv->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }
    drv->dgram_inflight++;
    return WTQ_OK;
}

/* The transport's datagram payload limit; 0 while the peer does not
 * accept datagrams (the engine turns that into DGRAM_DISABLED and
 * subtracts the association prefix from a nonzero limit itself). */
static size_t op_dgram_max_size(wtq_driver_t *drv)
{
    if (drv->shutdown_started || drv->conn == NULL)
        return 0;
    return (size_t)drv->dgram_max;
}

/*
 * Pause/resume delivery of received stream data. Disabling stops
 * future RECEIVE indications; MsQuic buffers what keeps arriving up to
 * the stream's receive window and its flow control pushes back on the
 * peer — the engine's consume-all handling of already-indicated bytes
 * is untouched.
 */
static wtq_result_t op_recv_enable(wtq_driver_t *drv, wtq_dstream_t *ds,
                                   bool enabled)
{
    if (drv->shutdown_started || ds->stream == NULL)
        return WTQ_ERR_CLOSED;
    if (QUIC_FAILED(drv->api->StreamReceiveSetEnabled(
            ds->stream, enabled ? TRUE : FALSE)))
        return WTQ_ERR_BACKEND;
    return WTQ_OK;
}

static wtq_result_t op_conn_close(wtq_driver_t *drv, uint64_t h3_err)
{
    if (drv->conn == NULL)
        return WTQ_ERR_CLOSED;
    conn_shutdown(drv, h3_err, false);
    return WTQ_OK;
}

/*
 * The engine released this stream's estream slot: drop the linkage so
 * no later MsQuic event (RECEIVE, PEER_SEND_SHUTDOWN/ABORTED,
 * PEER_RECEIVE_ABORTED, writable) reaches the slot's next occupant —
 * every delivery site is already gated on ds->ectx. Identity-checked
 * per the SPI contract.
 */
static void op_detach(wtq_driver_t *drv, wtq_dstream_t *ds,
                      wtq_estream_t *es)
{
    (void)drv;
    if (ds->ectx == es)
        ds->ectx = NULL;
}

const wtq_driver_ops_t *wtq_msq_driver_ops(void)
{
    static const wtq_driver_ops_t ops = {
        .open_uni = op_open_uni,
        .send = op_send,
        .caps = WTQ_DCAP_SHUT_BIDI_SEND | WTQ_DCAP_SHUT_BIDI_RECV |
                WTQ_DCAP_SHUT_SPLIT_CODES,
        .shutdown_stream = op_shutdown_stream,
        .conn_close = op_conn_close,
        .open_bidi = op_open_bidi,
        .dgram_send = op_dgram_send,
        .dgram_max_size = op_dgram_max_size,
        .send_gather = op_send_gather,
        .recv_enable = op_recv_enable,
        .detach = op_detach,
    };
    return &ops;
}

/* --- connection events ---------------------------------------------------- */

/*
 * Full-fidelity detail BEFORE the terminal input it explains (§6),
 * from EVERY delivery path (initiated events and SHUTDOWN_COMPLETE).
 * A local shutdown that reaches completion without a BY_TRANSPORT /
 * BY_PEER event and was not post-terminal cleanup is a causal LOCAL
 * error (environment close, backend invariant failure). Write-once in
 * the engine: the first causal flavor wins, repeats are ignored, and a
 * record sealed at the session terminal is never replaced.
 */
void wtq_msq_conn_put_error_detail(struct wtq_driver *drv)
{
    if (drv->close_kind == WTQ_ERR_KIND_NONE && !drv->close_cleanup) {
        /* un-attributed local shutdown reaching completion (e.g. an
         * external ConnectionShutdown the backend never saw staged) */
        drv->close_kind = WTQ_ERR_KIND_LOCAL;
        drv->close_err = drv->event_err;
    }
    if (drv->close_kind == WTQ_ERR_KIND_NONE)
        return;
    /* the CAUSAL tuple, verbatim — never the latest event's code */
    wtq_transport_error_t rec = {
        .struct_size = (uint32_t)sizeof(rec),
        .kind = drv->close_kind,
        .quic_code = drv->close_err,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = drv->close_status,
    };
    wtq_conn_set_transport_error(wtq_api_session_conn(drv->session), &rec);
}

/* Tell the engine the transport is gone. Idempotent (the engine's
 * closed flag guards), and once it ran the engine never calls another
 * driver op — the property the teardown order rests on. */
static void conn_feed_closed(struct wtq_driver *drv, uint64_t err,
                             bool remote)
{
    if (drv->session == NULL)
        return;
    wtq_api_session_enter(drv->session);
    wtq_msq_conn_put_error_detail(drv);
    wtq_conn_on_conn_closed(wtq_api_session_conn(drv->session), err,
                            remote, wtq_msq_now_us());
    wtq_msq_conn_leave_and_poll(drv);
}

QUIC_STATUS QUIC_API wtq_msq_conn_callback(HQUIC conn, void *ctx,
                                           QUIC_CONNECTION_EVENT *ev)
{
    struct wtq_driver *drv = ctx;

    (void)conn;
    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        if (drv->session != NULL) {
            wtq_api_session_enter(drv->session);
            wtq_result_t rc =
                wtq_api_session_start(drv->session, wtq_msq_now_us());
            wtq_msq_conn_leave_and_poll(drv);
            if (rc != WTQ_OK)
                conn_shutdown(drv, WTQ_H3_INTERNAL_ERROR, false);
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        conn_consume_env_close(drv);
        /* latest-event code for the legacy terminal input only — the
         * staged causal tuple is immutable once assigned */
        drv->event_err =
            ev->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
        drv->event_err_set = true;
        drv->close_remote = false;
        if (drv->close_kind == WTQ_ERR_KIND_NONE && !drv->close_cleanup) {
            drv->close_kind = WTQ_ERR_KIND_QUIC_TRANSPORT;
            drv->close_err = drv->event_err;
            drv->close_status =
                (int64_t)ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        }
        conn_feed_closed(drv, drv->event_err, false);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        conn_consume_env_close(drv);
        drv->event_err = ev->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        drv->event_err_set = true;
        drv->close_remote = true;
        if (drv->close_kind == WTQ_ERR_KIND_NONE && !drv->close_cleanup) {
            drv->close_kind = WTQ_ERR_KIND_QUIC_APP;
            drv->close_err = drv->event_err;
        }
        conn_feed_closed(drv, drv->event_err, true);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        /* the last event this connection will ever deliver */
        conn_consume_env_close(drv);
        if (drv->session != NULL) {
            /* Legacy terminal code: the latest transport-event code
             * when one exists (it drives the engine's close_code even
             * though it can never replace the first-causal record),
             * else the staged local causal code. */
            uint64_t term_code =
                drv->event_err_set
                    ? drv->event_err
                    : (drv->close_kind != WTQ_ERR_KIND_NONE
                           ? drv->close_err
                           : 0);
            wtq_api_session_enter(drv->session);
            wtq_msq_conn_put_error_detail(drv);
            wtq_conn_on_conn_closed(wtq_api_session_conn(drv->session),
                                    term_code, drv->close_remote,
                                    wtq_msq_now_us());
            /* drop the backend's reference INSIDE the bracket so a
             * resulting destroy runs here, on the worker, with nothing
             * else in flight */
            wtq_session_release(drv->session);
            (void)wtq_api_session_leave(drv->session);
            drv->session = NULL;
        }
        /* unregister AFTER the session-ref drop (a blocked env_close
         * may only return once retained handles are safe to touch) and
         * BEFORE any drv mutation below — while listed, env_close may
         * read drv under the env lock */
        wtq_msq_env_conn_unregister(drv);
        if (ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
            drv->conn = NULL; /* an app-side Close owns the handle */
        wtq_msq_conn_free(drv);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        drv->dgram_max =
            ev->DATAGRAM_STATE_CHANGED.SendEnabled
                ? ev->DATAGRAM_STATE_CHANGED.MaxSendLength
                : 0;
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        /* release the record at the FIRST final state — every accepted
         * datagram reaches exactly one (canceled at shutdown included);
         * the non-final SENT state passes through untouched */
        struct wtq_msq_dgram_rec *rec =
            ev->DATAGRAM_SEND_STATE_CHANGED.ClientContext;

        if (rec != NULL &&
            QUIC_DATAGRAM_SEND_STATE_IS_FINAL(
                ev->DATAGRAM_SEND_STATE_CHANGED.State)) {
            drv->alloc.free(rec, rec->alloc_size, drv->alloc.ctx);
            drv->dgram_inflight--;
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        /* Receive-side datagrams are live (the engine advertises H3
         * datagram support — WebTransport requires it): the engine
         * delivers session datagrams, counts drops for unknown ones,
         * and treats a malformed association prefix as fatal. Sending
         * stays unavailable until the datagram ops are wired. */
        if (drv->session != NULL) {
            const QUIC_BUFFER *b = ev->DATAGRAM_RECEIVED.Buffer;

            wtq_api_session_enter(drv->session);
            (void)wtq_conn_on_datagram(wtq_api_session_conn(drv->session),
                                       b->Buffer, b->Length,
                                       wtq_msq_now_us());
            wtq_msq_conn_leave_and_poll(drv);
        }
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        bool bidi = (ev->PEER_STREAM_STARTED.Flags &
                     QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) == 0;
        if (drv->session == NULL)
            return QUIC_STATUS_CONNECTION_REFUSED;

        /* a peer stream is already started, so its id is readable */
        uint64_t id = 0;
        uint32_t id_size = sizeof(id);
        if (QUIC_FAILED(drv->api->GetParam(ev->PEER_STREAM_STARTED.Stream,
                                           QUIC_PARAM_STREAM_ID, &id_size,
                                           &id)))
            return QUIC_STATUS_INTERNAL_ERROR; /* MsQuic closes it */

        struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, bidi, id);
        if (ds == NULL)
            return QUIC_STATUS_OUT_OF_MEMORY; /* MsQuic closes the stream */
        ds->stream = ev->PEER_STREAM_STARTED.Stream;

        /* Register the handler IMMEDIATELY, as MsQuic requires on
         * PEER_STREAM_STARTED, and before the engine runs: on pool
         * exhaustion the engine rejects the stream from inside the
         * open call (StreamShutdown), which must never happen on a
         * stream with no callback handler set. */
        drv->api->SetCallbackHandler(ev->PEER_STREAM_STARTED.Stream,
                                     (void *)wtq_msq_stream_callback, ds);

        wtq_conn_t *ec = wtq_api_session_conn(drv->session);
        wtq_estream_t *es = NULL;
        wtq_api_session_enter(drv->session);
        wtq_result_t rc =
            bidi ? wtq_conn_on_peer_bidi_opened(ec, ds, id, &es)
                 : wtq_conn_on_peer_uni_opened(ec, ds, id, &es);
        wtq_msq_conn_leave_and_poll(drv);
        /* Engine refusal (pool exhausted / closed): es stays NULL. The
         * engine has ALREADY rejected the stream on the wire
         * (STOP_SENDING, plus RESET_STREAM when bidirectional), so any
         * bytes still in flight are discarded only until that rejection
         * reaches the peer — never a permanent silent sink. The ctx is
         * published only after the engine returns, so no event can
         * reach a half-built estream. */
        (void)rc;
        ds->ectx = es;
        break;
    }

    default:
        /* STREAMS_AVAILABLE, address changes, datagram state, resumption
         * and the rest carry nothing the backend acts on yet */
        break;
    }
    return QUIC_STATUS_SUCCESS;
}
