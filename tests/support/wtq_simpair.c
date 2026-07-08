#include "wtq_simpair.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* splitmix64 mixing (libmoq's stateless fault-decision recipe). */
static uint64_t mix64(uint64_t x)
{
    x += UINT64_C(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94D049BB133111EB);
    return x ^ (x >> 31);
}

static void trace(wtq_simpair_t *sp, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (sp->trace_overflow)
        return;
    va_start(ap, fmt);
    n = vsnprintf(sp->trace + sp->trace_len,
                  WTQ_SIMPAIR_TRACE_CAP - sp->trace_len, fmt, ap);
    va_end(ap);
    if (n < 0 ||
        (size_t)n >= WTQ_SIMPAIR_TRACE_CAP - sp->trace_len) {
        sp->trace_overflow = true;
        return;
    }
    sp->trace_len += (size_t)n;
}

static void on_peer_settings(wtq_conn_t *conn, bool wt_supported,
                             void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->settings_events++;
    side->wt_supported = wt_supported;
    trace(side->sp, "e side=%c settings wt=%d\n", side->label,
          wt_supported ? 1 : 0);
}

static void on_conn_error(wtq_conn_t *conn, uint64_t h3_err, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->error_events++;
    side->last_error = h3_err;
    trace(side->sp, "e side=%c error=0x%llx\n", side->label,
          (unsigned long long)h3_err);
}

static void on_established(wtq_conn_t *conn, const char *sel,
                           size_t len, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->established_events++;
    side->selected_len = len < sizeof(side->selected) ? len : 0;
    if (side->selected_len > 0)
        memcpy(side->selected, sel, side->selected_len);
    trace(side->sp, "e side=%c established sel=%.*s\n", side->label,
          (int)side->selected_len, side->selected_len ? sel : "");
}

static void on_rejected(wtq_conn_t *conn, uint16_t status, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->rejected_events++;
    side->rejected_status = status;
    trace(side->sp, "e side=%c rejected status=%u\n", side->label,
          (unsigned)status);
}

static void on_failed(wtq_conn_t *conn, wtq_session_fail_reason_t r,
                      void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->failed_events++;
    side->failed_reason = (int)r;
    trace(side->sp, "e side=%c failed reason=%d\n", side->label, (int)r);
}

static void on_closed(wtq_conn_t *conn, uint32_t code,
                      const uint8_t *reason, size_t reason_len,
                      bool clean, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->closed_events++;
    side->closed_code = code;
    side->closed_reason_len =
        reason_len < sizeof(side->closed_reason) ? reason_len : 0;
    if (side->closed_reason_len > 0)
        memcpy(side->closed_reason, reason, side->closed_reason_len);
    side->closed_clean = clean;
    trace(side->sp, "e side=%c closed code=%u rlen=%zu clean=%d\n",
          side->label, (unsigned)code, reason_len, clean ? 1 : 0);
}

static void on_draining(wtq_conn_t *conn, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->draining_events++;
    trace(side->sp, "e side=%c draining\n", side->label);
}

static void on_wt_opened(wtq_conn_t *conn, wtq_estream_t *es, bool bidi,
                         uint64_t id, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->wt_opened_events++;
    side->wt_last_es = es;
    side->wt_last_bidi = bidi;
    trace(side->sp, "e side=%c wtopen bidi=%d id=%llu\n", side->label,
          bidi ? 1 : 0, (unsigned long long)id);
}

static void on_wt_data(wtq_conn_t *conn, wtq_estream_t *es,
                       const uint8_t *data, size_t len, bool fin,
                       void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    (void)es;
    side->wt_data_events++;
    if (len > 0 && side->wt_data_len + len <= sizeof(side->wt_data)) {
        memcpy(side->wt_data + side->wt_data_len, data, len);
        side->wt_data_len += len;
    }
    if (fin)
        side->wt_fin_events++;
    trace(side->sp, "e side=%c wtdata len=%zu fin=%d\n", side->label,
          len, fin ? 1 : 0);
}

static void on_wt_reset(wtq_conn_t *conn, wtq_estream_t *es,
                        uint32_t app_code, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    (void)es;
    side->wt_reset_events++;
    trace(side->sp, "e side=%c wtreset code=%u\n", side->label,
          (unsigned)app_code);
}

static void on_wt_stop(wtq_conn_t *conn, wtq_estream_t *es,
                       uint32_t app_code, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    (void)es;
    side->wt_stop_events++;
    trace(side->sp, "e side=%c wtstop code=%u\n", side->label,
          (unsigned)app_code);
}

static void on_wt_dgram(wtq_conn_t *conn, const uint8_t *data,
                        size_t len, void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    side->dgram_events++;
    if (len > 0 &&
        side->dgram_data_len + len <= sizeof(side->dgram_data)) {
        memcpy(side->dgram_data + side->dgram_data_len, data, len);
        side->dgram_data_len += len;
    }
    trace(side->sp, "e side=%c dgram len=%zu\n", side->label, len);
}

static void on_send_done(wtq_conn_t *conn, void *cookie, bool canceled,
                         void *ctx)
{
    wtq_simpair_side_t *side = ctx;

    (void)conn;
    (void)cookie; /* a pointer: never traced (determinism) */
    side->send_completions++;
    if (canceled)
        side->send_cancels++;
    trace(side->sp, "e side=%c sendcomplete canceled=%d\n", side->label,
          canceled ? 1 : 0);
}

static int side_up(wtq_simpair_t *sp, wtq_simpair_side_t *side,
                   char label, wtq_perspective_t persp)
{
    side->sp = sp;
    side->label = label;
    fake_driver_init(&side->drv, persp == WTQ_PERSPECTIVE_CLIENT);

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = persp,
        .enable_connect_protocol = true,
        .callbacks = { .on_peer_settings = on_peer_settings,
                       .on_conn_error = on_conn_error,
                       .on_session_established = on_established,
                       .on_session_rejected = on_rejected,
                       .on_session_failed = on_failed,
                       .on_session_closed = on_closed,
                       .on_session_draining = on_draining,
                       .on_wt_stream_opened = on_wt_opened,
                       .on_wt_stream_data = on_wt_data,
                       .on_wt_stream_reset = on_wt_reset,
                       .on_wt_stream_stop = on_wt_stop,
                       .on_wt_send_complete = on_send_done,
                       .on_wt_datagram = on_wt_dgram,
                       .ctx = side },
    };
    if (wtq_conn_create(&cfg, &side->drv, fake_driver_ops(),
                        &side->conn) != WTQ_OK)
        return -1;
    if (wtq_conn_start(side->conn, sp->now_us) != WTQ_OK)
        return -1;
    return 0;
}

int wtq_simpair_create(wtq_simpair_t *sp, uint64_t seed)
{
    memset(sp, 0, sizeof(*sp));
    sp->seed = seed;
    sp->now_us = 1000;
    trace(sp, "create seed=0x%llx\n", (unsigned long long)seed);

    if (side_up(sp, &sp->c, 'c', WTQ_PERSPECTIVE_CLIENT) != 0)
        return -1;
    if (side_up(sp, &sp->s, 's', WTQ_PERSPECTIVE_SERVER) != 0)
        return -1;
    return 0;
}

void wtq_simpair_destroy(wtq_simpair_t *sp)
{
    wtq_conn_destroy(sp->c.conn);
    wtq_conn_destroy(sp->s.conn);
}

/* Deliver one sender stream's pending bytes into the receiver engine
 * with seeded chunking. Returns delivered units. */
static size_t deliver_stream(wtq_simpair_t *sp, wtq_simpair_side_t *from,
                             wtq_simpair_side_t *to, size_t slot)
{
    struct wtq_dstream *src = &from->drv.streams[slot];
    size_t delivered = 0;

    if (!src->in_use || !src->is_local)
        return 0;

    /* First contact: surface the stream to the receiving engine, ONCE
     * (a real backend reports a peer stream a single time). The twin
     * pointer is the latch — the engine ctx is not, because a refused
     * stream legitimately has none. */
    if (src->linked == NULL && src->len > 0) {
        struct wtq_dstream *peer_ds =
            fake_driver_add_peer_stream(&to->drv, src->id);
        wtq_estream_t *es = NULL;
        if (peer_ds == NULL)
            return 0;
        peer_ds->is_bidi = src->is_bidi;
        peer_ds->linked = src;
        src->linked = peer_ds;
        wtq_result_t rc =
            src->is_bidi
                ? wtq_conn_on_peer_bidi_opened(to->conn, peer_ds, src->id,
                                               &es)
                : wtq_conn_on_peer_uni_opened(to->conn, peer_ds, src->id,
                                              &es);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x %c>%c open id=%llu rc=%d\n", from->label,
                  to->label, (unsigned long long)src->id, rc);
        }
        to->es_for_slot[slot] = es;
        peer_ds->ectx = es; /* as a backend records it */
        trace(sp, "d %c>%c open id=%llu\n", from->label, to->label,
              (unsigned long long)src->id);
        delivered++;
    }

    if (src->linked == NULL)
        return delivered;

    /* Bytes, in seeded chunks; per-stream order always preserved.
     * The receiving dstream's engine ctx is re-read before EVERY
     * delivery, exactly like a real backend: an early chunk can
     * detach the stream (poison, terminal), and the rest of the
     * queued bytes must then reach nobody. */
    while (src->delivered < src->len) {
        wtq_estream_t *es = src->linked->ectx;
        if (es == NULL)
            return delivered;
        size_t remaining = src->len - src->delivered;
        uint64_t h = mix64(sp->seed ^ (sp->step * 31 + slot * 7 +
                                       src->delivered));
        size_t chunk = 1 + (size_t)(h % 7);
        if (chunk > remaining)
            chunk = remaining;
        bool deliver_fin = src->fin &&
                           (src->delivered + chunk == src->len);
        wtq_result_t rc = wtq_conn_on_stream_bytes(
            to->conn, es, src->bytes + src->delivered, chunk, deliver_fin,
            sp->now_us);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x %c>%c id=%llu bytes rc=%d\n", from->label,
                  to->label, (unsigned long long)src->id, rc);
        }
        if (deliver_fin)
            src->fin_delivered = true;
        trace(sp, "d %c>%c id=%llu bytes=%zu off=%zu fin=%d\n",
              from->label, to->label, (unsigned long long)src->id, chunk,
              src->delivered, deliver_fin ? 1 : 0);
        src->delivered += chunk;
        delivered += chunk;
    }

    /* A bare FIN with no pending bytes (re-read ectx: a detached
     * stream's FIN reaches nobody). */
    if (src->fin && !src->fin_delivered && src->delivered == src->len &&
        src->linked->ectx != NULL) {
        wtq_result_t rc = wtq_conn_on_stream_bytes(
            to->conn, src->linked->ectx, NULL, 0, true, sp->now_us);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x %c>%c id=%llu fin rc=%d\n", from->label,
                  to->label, (unsigned long long)src->id, rc);
        }
        src->fin_delivered = true;
        trace(sp, "d %c>%c id=%llu fin\n", from->label, to->label,
              (unsigned long long)src->id);
        delivered++;
    }

    return delivered;
}

/* Reverse direction of a bidi stream: bytes the receiving engine sent
 * on its peer-side dstream flow back to the opener's estream. */
static size_t deliver_reverse(wtq_simpair_t *sp, wtq_simpair_side_t *from,
                              wtq_simpair_side_t *to, size_t slot)
{
    struct wtq_dstream *src = &from->drv.streams[slot];
    size_t delivered = 0;

    if (!src->in_use || src->is_local || !src->is_bidi ||
        src->linked == NULL)
        return 0;

    /* ectx re-read per chunk: detachment mid-pass stops delivery */
    while (src->delivered < src->len) {
        wtq_estream_t *es = src->linked->ectx;
        if (es == NULL)
            return delivered;
        size_t remaining = src->len - src->delivered;
        uint64_t h = mix64(sp->seed ^ (sp->step * 131 + slot * 17 +
                                       src->delivered));
        size_t chunk = 1 + (size_t)(h % 7);
        if (chunk > remaining)
            chunk = remaining;
        bool deliver_fin = src->fin &&
                           (src->delivered + chunk == src->len);
        wtq_result_t rc = wtq_conn_on_stream_bytes(
            to->conn, es, src->bytes + src->delivered, chunk, deliver_fin,
            sp->now_us);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x %c>%c id=%llu rbytes rc=%d\n", from->label,
                  to->label, (unsigned long long)src->id, rc);
        }
        if (deliver_fin)
            src->fin_delivered = true;
        trace(sp, "d %c>%c id=%llu rbytes=%zu off=%zu fin=%d\n",
              from->label, to->label, (unsigned long long)src->id, chunk,
              src->delivered, deliver_fin ? 1 : 0);
        src->delivered += chunk;
        delivered += chunk;
    }
    return delivered;
}

/* Propagate a stream closure the sender recorded (reset of the
 * direction it writes, STOP_SENDING of the direction it reads) to the
 * peer engine, exactly once each. Delivery is keyed on the twin
 * dstream's engine ctx: a detached stream's closures reach nobody. */
static size_t deliver_closures(wtq_simpair_t *sp, wtq_simpair_side_t *from,
                               wtq_simpair_side_t *to, size_t slot)
{
    struct wtq_dstream *src = &from->drv.streams[slot];
    size_t delivered = 0;

    if (!src->in_use || src->linked == NULL)
        return 0;

    if (src->reset && !src->reset_delivered) {
        src->reset_delivered = true;
        if (src->linked->ectx != NULL) {
            wtq_result_t rc = wtq_conn_on_stream_reset(
                to->conn, src->linked->ectx, src->reset_err, sp->now_us);
            if (rc != WTQ_OK) {
                sp->engine_errors++;
                trace(sp, "x %c>%c id=%llu reset rc=%d\n", from->label,
                      to->label, (unsigned long long)src->id, rc);
            }
        }
        trace(sp, "d %c>%c id=%llu reset\n", from->label, to->label,
              (unsigned long long)src->id);
        delivered++;
    }
    if (src->stopped && !src->stop_delivered) {
        src->stop_delivered = true;
        if (src->linked->ectx != NULL) {
            wtq_result_t rc = wtq_conn_on_stop_sending(
                to->conn, src->linked->ectx, src->stop_err, sp->now_us);
            if (rc != WTQ_OK) {
                sp->engine_errors++;
                trace(sp, "x %c>%c id=%llu stop rc=%d\n", from->label,
                      to->label, (unsigned long long)src->id, rc);
            }
        }
        trace(sp, "d %c>%c id=%llu stop\n", from->label, to->label,
              (unsigned long long)src->id);
        delivered++;
    }
    return delivered;
}

size_t wtq_simpair_step(wtq_simpair_t *sp)
{
    size_t delivered = 0;

    sp->step++;
    sp->now_us += 100;
    trace(sp, "s step=%zu now=%llu\n", sp->step,
          (unsigned long long)sp->now_us);

    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_stream(sp, &sp->c, &sp->s, slot);
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_stream(sp, &sp->s, &sp->c, slot);
    /* reverse (response) direction: bytes written by each side onto
     * its RECEIVED bidi streams flow back to the opener */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_reverse(sp, &sp->s, &sp->c, slot);
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_reverse(sp, &sp->c, &sp->s, slot);
    /* stream closures after in-flight bytes (the rail's one ordering) */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_closures(sp, &sp->c, &sp->s, slot);
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++)
        delivered += deliver_closures(sp, &sp->s, &sp->c, slot);

    /* Datagrams: deliver each side's undelivered log to the peer.
     * Non-OK returns are recorded like every other engine input —
     * protocol failures must never vanish from the rail. */
    while (sp->c.drv.dgram_delivered < sp->c.drv.dgram_count) {
        size_t i = sp->c.drv.dgram_delivered++;
        trace(sp, "d c>s dgram len=%zu\n", sp->c.drv.dgrams[i].len);
        wtq_result_t rc = wtq_conn_on_datagram(
            sp->s.conn, sp->c.drv.dgrams[i].bytes,
            sp->c.drv.dgrams[i].len, sp->now_us);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x c>s dgram rc=%d\n", rc);
        }
        delivered++;
    }
    while (sp->s.drv.dgram_delivered < sp->s.drv.dgram_count) {
        size_t i = sp->s.drv.dgram_delivered++;
        trace(sp, "d s>c dgram len=%zu\n", sp->s.drv.dgrams[i].len);
        wtq_result_t rc = wtq_conn_on_datagram(
            sp->c.conn, sp->s.drv.dgrams[i].bytes,
            sp->s.drv.dgrams[i].len, sp->now_us);
        if (rc != WTQ_OK) {
            sp->engine_errors++;
            trace(sp, "x s>c dgram rc=%d\n", rc);
        }
        delivered++;
    }

    /* Send completions fire on each sender once its bytes went out —
     * the sim's stand-in for MsQuic's SEND_COMPLETE-on-ACK. */
    delivered += fake_driver_complete_sends(&sp->c.drv, sp->c.conn);
    delivered += fake_driver_complete_sends(&sp->s.drv, sp->s.conn);

    if (delivered == 0)
        trace(sp, "q step=%zu\n", sp->step);
    return delivered;
}

size_t wtq_simpair_run_until_quiescent(wtq_simpair_t *sp,
                                       size_t max_steps)
{
    size_t steps = 0;

    while (steps < max_steps) {
        steps++;
        if (wtq_simpair_step(sp) == 0)
            break;
    }
    return steps;
}

uint64_t wtq_simpair_trace_hash(const wtq_simpair_t *sp)
{
    uint64_t h = UINT64_C(0xCBF29CE484222325);

    for (size_t i = 0; i < sp->trace_len; i++) {
        h ^= (uint8_t)sp->trace[i];
        h *= UINT64_C(0x100000001B3);
    }
    return h;
}

wtq_result_t wtq_simpair_client_connect(wtq_simpair_t *sp,
                                        const wtq_client_connect_cfg_t *c)
{
    trace(sp, "a side=c connect path=%s\n", c->path);
    return wtq_conn_client_connect(sp->c.conn, c);
}

wtq_result_t wtq_simpair_server_paths(wtq_simpair_t *sp,
                                      const wtq_server_path_cfg_t *paths,
                                      size_t count)
{
    trace(sp, "a side=s paths=%zu\n", count);
    return wtq_conn_server_set_paths(sp->s.conn, paths, count);
}

wtq_result_t wtq_simpair_session_close(wtq_simpair_t *sp, char side,
                                       uint32_t code, const char *reason)
{
    wtq_simpair_side_t *s = side == 'c' ? &sp->c : &sp->s;

    trace(sp, "a side=%c close code=%u\n", side, (unsigned)code);
    return wtq_conn_session_close(s->conn, code,
                                  (const uint8_t *)reason,
                                  reason != NULL ? strlen(reason) : 0);
}

wtq_result_t wtq_simpair_session_drain(wtq_simpair_t *sp, char side)
{
    wtq_simpair_side_t *s = side == 'c' ? &sp->c : &sp->s;

    trace(sp, "a side=%c drain\n", side);
    return wtq_conn_session_drain(s->conn);
}

wtq_result_t wtq_simpair_wt_open(wtq_simpair_t *sp, char side, bool bidi,
                                 wtq_estream_t **es_out)
{
    wtq_simpair_side_t *s = side == 'c' ? &sp->c : &sp->s;

    trace(sp, "a side=%c wtopen bidi=%d\n", side, bidi ? 1 : 0);
    return bidi ? wtq_conn_wt_open_bidi(s->conn, es_out)
                : wtq_conn_wt_open_uni(s->conn, es_out);
}

wtq_result_t wtq_simpair_wt_send(wtq_simpair_t *sp, char side,
                                 wtq_estream_t *es, const void *data,
                                 size_t len, bool fin)
{
    wtq_simpair_side_t *s = side == 'c' ? &sp->c : &sp->s;
    wtq_span_t span = { data, len };

    trace(sp, "a side=%c wtsend len=%zu fin=%d\n", side, len,
          fin ? 1 : 0);
    return wtq_conn_wt_send(s->conn, es, &span, 1, fin, es);
}

wtq_result_t wtq_simpair_dgram_send(wtq_simpair_t *sp, char side,
                                    const void *data, size_t len)
{
    wtq_simpair_side_t *s = side == 'c' ? &sp->c : &sp->s;
    wtq_span_t span = { data, len };

    trace(sp, "a side=%c dgsend len=%zu\n", side, len);
    return wtq_conn_dgram_send(s->conn, &span, 1);
}
