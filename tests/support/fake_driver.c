#include "fake_driver.h"

#include <stdint.h>
#include <string.h>

void fake_driver_init(struct wtq_driver *drv, bool is_client)
{
    memset(drv, 0, sizeof(*drv));
    drv->is_client = is_client;
    drv->next_uni_id = is_client ? 2 : 3;
    drv->next_bidi_id = is_client ? 0 : 1;
    drv->dgram_max = 1200;
}

static struct wtq_dstream *alloc_slot(struct wtq_driver *drv)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (!drv->streams[i].in_use) {
            memset(&drv->streams[i], 0, sizeof(drv->streams[i]));
            drv->streams[i].in_use = true;
            return &drv->streams[i];
        }
    return NULL;
}

/* True when this attempt is the one the test wants to fail. */
static bool open_should_fail(struct wtq_driver *drv)
{
    drv->open_calls++;
    return drv->fail_open ||
           (drv->fail_open_at != 0 &&
            drv->open_calls == drv->fail_open_at);
}

static bool send_should_fail(struct wtq_driver *drv)
{
    drv->send_calls++;
    return drv->fail_send ||
           (drv->fail_send_at != 0 &&
            drv->send_calls == drv->fail_send_at);
}

static wtq_result_t fake_open_uni(wtq_driver_t *drv, wtq_estream_t *ectx,
                                  wtq_dstream_t **out, uint64_t *id_out)
{
    if (open_should_fail(drv))
        return WTQ_ERR_STREAM_LIMIT;

    struct wtq_dstream *s = alloc_slot(drv);
    if (s == NULL)
        return WTQ_ERR_STREAM_LIMIT;
    s->is_local = true;
    s->id = drv->next_uni_id;
    s->ectx = ectx;
    drv->next_uni_id += 4;
    drv->open_count++;
    *out = s;
    *id_out = drv->async_ids ? WTQ_STREAM_ID_UNKNOWN : s->id;
    return WTQ_OK;
}

static wtq_result_t fake_send(wtq_driver_t *drv, wtq_dstream_t *ds,
                              const uint8_t *data, size_t len, bool fin)
{
    if (send_should_fail(drv))
        return WTQ_ERR_WOULD_BLOCK;
    if (ds->len + len > FAKE_STREAM_CAP)
        return WTQ_ERR_TOO_LARGE;
    if (len > 0)
        memcpy(ds->bytes + ds->len, data, len);
    ds->len += len;
    if (fin)
        ds->fin = true;
    drv->send_count++;
    return WTQ_OK;
}

static void cancel_pending_for(struct wtq_driver *drv,
                               struct wtq_dstream *ds);

/*
 * The structured shutdown op. Records the COMPLETE request (mode, halves,
 * codes, call count) for call-site assertions, keeps the legacy per-half
 * fields (reset/stopped + codes) updated so the deterministic pumps keep
 * propagating reset/stop exactly once, and injects faults:
 *   fail_shutdown_before      fail before ANY effect;
 *   fail_shutdown_after_first apply the send half, then fail (models a
 *                             split-code sequence dying half-way).
 */
static wtq_result_t fake_shutdown_stream(wtq_driver_t *drv,
                                         wtq_dstream_t *ds,
                                         const wtq_shutdown_t *req)
{
    if (drv->fail_shutdown_before)
        return WTQ_ERR_BACKEND;
    ds->shutdown_count++;
    ds->last_shutdown = *req;
    if (req->abort_send) {
        ds->reset = true;
        ds->reset_err = req->send_err;
        ds->reset_count++;
        cancel_pending_for(drv, ds);
    }
    if (drv->fail_shutdown_after_first && req->abort_send &&
        req->abort_recv)
        return WTQ_ERR_BACKEND; /* partial application */
    if (req->abort_recv) {
        ds->stopped = true;
        ds->stop_err = req->recv_err;
        ds->stop_count++;
    }
    return WTQ_OK;
}

static wtq_result_t fake_conn_close(wtq_driver_t *drv, uint64_t h3_err)
{
    if (!drv->closed) {
        drv->closed = true;
        drv->close_err = h3_err;
    }
    drv->close_count++;
    cancel_pending_for(drv, NULL);
    return WTQ_OK;
}

static wtq_result_t fake_open_bidi(wtq_driver_t *drv, wtq_estream_t *ectx,
                                   wtq_dstream_t **out, uint64_t *id_out)
{
    if (open_should_fail(drv))
        return WTQ_ERR_STREAM_LIMIT;

    struct wtq_dstream *s = alloc_slot(drv);
    if (s == NULL)
        return WTQ_ERR_STREAM_LIMIT;
    s->is_local = true;
    s->is_bidi = true;
    s->id = drv->next_bidi_id;
    s->ectx = ectx;
    drv->next_bidi_id += 4;
    drv->open_count++;
    *out = s;
    *id_out = drv->async_ids ? WTQ_STREAM_ID_UNKNOWN : s->id;
    return WTQ_OK;
}

static void cancel_pending_for(struct wtq_driver *drv,
                               struct wtq_dstream *ds)
{
    for (size_t i = drv->pending_head; i < drv->pending_tail; i++)
        if (drv->pending[i % FAKE_MAX_PENDING].in_use &&
            (ds == NULL ||
             drv->pending[i % FAKE_MAX_PENDING].ds == ds))
            drv->pending[i % FAKE_MAX_PENDING].canceled = true;
}

static wtq_result_t fake_send_gather(wtq_driver_t *drv, wtq_dstream_t *ds,
                                     const wtq_span_t *spans, size_t count,
                                     bool fin, void *cookie)
{
    if (drv->fail_send)
        return WTQ_ERR_WOULD_BLOCK;
    if (drv->pending_tail - drv->pending_head >= FAKE_MAX_PENDING)
        return WTQ_ERR_WOULD_BLOCK;

    size_t total = 0;
    for (size_t i = 0; i < count; i++)
        total += spans[i].len;
    if (ds->len + total > FAKE_STREAM_CAP)
        return WTQ_ERR_TOO_LARGE;

    /* The copy is the sim's WIRE (delivery log), not a backend buffer:
     * a real backend borrows the span data until completion. */
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > 0)
            memcpy(ds->bytes + ds->len, spans[i].data, spans[i].len);
        ds->len += spans[i].len;
    }
    if (fin)
        ds->fin = true;
    drv->gather_count++;

    struct fake_pending_send *p =
        &drv->pending[drv->pending_tail % FAKE_MAX_PENDING];
    p->in_use = true;
    p->ds = ds;
    p->cookie = cookie;
    p->canceled = false;
    drv->pending_tail++;
    return WTQ_OK;
}

size_t fake_driver_complete_sends(struct wtq_driver *drv, wtq_conn_t *conn)
{
    size_t n = 0;

    while (drv->pending_head < drv->pending_tail) {
        struct fake_pending_send *p =
            &drv->pending[drv->pending_head % FAKE_MAX_PENDING];
        drv->pending_head++;
        if (!p->in_use)
            continue;
        p->in_use = false;
        wtq_conn_on_send_complete(conn, p->cookie, p->canceled);
        n++;
    }
    return n;
}

static wtq_result_t fake_dgram_send(wtq_driver_t *drv,
                                    const wtq_span_t *spans, size_t count)
{
    if (drv->fail_dgram)
        return WTQ_ERR_WOULD_BLOCK;
    if (drv->dgram_count >= FAKE_MAX_DGRAMS)
        return WTQ_ERR_WOULD_BLOCK;

    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > SIZE_MAX - total)
            return WTQ_ERR_TOO_LARGE;
        total += spans[i].len;
    }
    if (total > drv->dgram_max || total > FAKE_DGRAM_CAP)
        return WTQ_ERR_TOO_LARGE;

    uint8_t *dst = drv->dgrams[drv->dgram_count].bytes;
    size_t off = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > 0)
            memcpy(dst + off, spans[i].data, spans[i].len);
        off += spans[i].len;
    }
    drv->dgrams[drv->dgram_count].len = off;
    drv->dgram_count++;
    return WTQ_OK;
}

static size_t fake_dgram_max_size(wtq_driver_t *drv)
{
    return drv->dgram_max;
}

static wtq_result_t fake_recv_enable(wtq_driver_t *drv, wtq_dstream_t *ds,
                                     bool enabled)
{
    (void)drv;
    ds->recv_disabled = !enabled;
    ds->recv_enable_count++;
    return WTQ_OK;
}

static void fake_detach(wtq_driver_t *drv, wtq_dstream_t *ds,
                        wtq_estream_t *es)
{
    (void)drv;
    /* identity-checked: a stale stream cannot sever a reused slot's
     * new attachment */
    if (ds->ectx == es)
        ds->ectx = NULL;
    ds->detach_count++;
}

const wtq_driver_ops_t *fake_driver_ops(void)
{
    static const wtq_driver_ops_t ops = {
        .open_uni = fake_open_uni,
        .send = fake_send,
        .recv_enable = fake_recv_enable,
        .caps = WTQ_DCAP_SHUT_BIDI_SEND | WTQ_DCAP_SHUT_BIDI_RECV |
                WTQ_DCAP_SHUT_SPLIT_CODES,
        .shutdown_stream = fake_shutdown_stream,
        .conn_close = fake_conn_close,
        .open_bidi = fake_open_bidi,
        .send_gather = fake_send_gather,
        .dgram_send = fake_dgram_send,
        .dgram_max_size = fake_dgram_max_size,
        .detach = fake_detach,
    };
    return &ops;
}

void fake_driver_cancel_pending(struct wtq_driver *drv)
{
    cancel_pending_for(drv, NULL);
}

struct wtq_dstream *fake_driver_add_peer_stream(struct wtq_driver *drv,
                                                uint64_t id)
{
    struct wtq_dstream *s = alloc_slot(drv);

    if (s == NULL)
        return NULL;
    s->is_local = false;
    s->id = id;
    return s;
}

bool fake_driver_deliver_bytes(wtq_conn_t *conn, struct wtq_dstream *ds,
                               const uint8_t *data, size_t len, bool fin,
                               uint64_t now_us)
{
    if (ds->ectx == NULL)
        return false;
    (void)wtq_conn_on_stream_bytes(conn, ds->ectx, data, len, fin,
                                   now_us);
    return true;
}

bool fake_driver_deliver_reset(wtq_conn_t *conn, struct wtq_dstream *ds,
                               uint64_t quic_err, uint64_t now_us)
{
    if (ds->ectx == NULL)
        return false;
    (void)wtq_conn_on_stream_reset(conn, ds->ectx, quic_err, now_us);
    return true;
}

bool fake_driver_deliver_stop(wtq_conn_t *conn, struct wtq_dstream *ds,
                              uint64_t quic_err, uint64_t now_us)
{
    if (ds->ectx == NULL)
        return false;
    (void)wtq_conn_on_stop_sending(conn, ds->ectx, quic_err, now_us);
    return true;
}

bool fake_driver_deliver_native_id(wtq_conn_t *conn, struct wtq_dstream *ds,
                                   uint64_t now_us)
{
    return fake_driver_deliver_native_id_as(conn, ds, ds->id, now_us);
}

bool fake_driver_deliver_native_id_as(wtq_conn_t *conn,
                                      struct wtq_dstream *ds, uint64_t id,
                                      uint64_t now_us)
{
    (void)now_us;
    if (ds->ectx == NULL)
        return false;
    wtq_conn_on_stream_native_id(conn, ds->ectx, id);
    return true;
}

struct wtq_dstream *fake_driver_local(struct wtq_driver *drv, size_t index)
{
    size_t seen = 0;

    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++) {
        if (drv->streams[i].in_use && drv->streams[i].is_local) {
            if (seen == index)
                return &drv->streams[i];
            seen++;
        }
    }
    return NULL;
}
