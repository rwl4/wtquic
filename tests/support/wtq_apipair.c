#include "wtq_apipair.h"

#include "api_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* splitmix64 chunking recipe (shared with the engine simpair). */
static uint64_t mix64(uint64_t x)
{
    x += UINT64_C(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94D049BB133111EB);
    return x ^ (x >> 31);
}

static void append(char *buf, size_t cap, size_t *len, bool *overflow,
                   const char *s, size_t n)
{
    if (*overflow)
        return;
    if (*len + n >= cap) {
        *overflow = true;
        return;
    }
    memcpy(buf + *len, s, n);
    *len += n;
}

/* A semantic line: recorded in BOTH the full trace and the semantic
 * trace (drives both hashes). */
static void sem(wtq_apipair_t *p, const char *fmt, ...)
{
    char line[256];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t nn = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
    append(p->trace, WTQ_APIPAIR_TRACE_CAP, &p->trace_len, &p->overflow,
           line, nn);
    append(p->sem, WTQ_APIPAIR_TRACE_CAP, &p->sem_len, &p->overflow,
           line, nn);
}

/* A delivery/timing line: full trace only (seed-dependent). */
static void dlv(wtq_apipair_t *p, const char *fmt, ...)
{
    char line[256];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t nn = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
    append(p->trace, WTQ_APIPAIR_TRACE_CAP, &p->trace_len, &p->overflow,
           line, nn);
}

void wtq_apipair_mark(wtq_apipair_t *p, const char *fmt, ...)
{
    char line[256];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t nn = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
    append(p->trace, WTQ_APIPAIR_TRACE_CAP, &p->trace_len, &p->overflow,
           line, nn);
    append(p->sem, WTQ_APIPAIR_TRACE_CAP, &p->sem_len, &p->overflow,
           line, nn);
}

/* --- callbacks ----------------------------------------------------------- */

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->established++;
    sd->sub_len = sub.len < sizeof(sd->sub) ? sub.len : 0;
    if (sd->sub_len > 0)
        memcpy(sd->sub, sub.data, sd->sub_len);
    sem(sd->pair, "E %c established sub=%.*s\n", sd->label,
        (int)sd->sub_len, sd->sub_len ? sd->sub : "");
}

static void cb_refused(wtq_session_t *s, uint16_t status, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->refused++;
    sd->refused_status = status;
    sem(sd->pair, "E %c refused status=%u\n", sd->label,
        (unsigned)status);
}

static void cb_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->failed++;
    sd->failed_reason = (int)why;
    sem(sd->pair, "E %c failed why=%d\n", sd->label, (int)why);
}

static void cb_draining(wtq_session_t *s, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->draining++;
    sem(sd->pair, "E %c draining\n", sd->label);
}

static void cb_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t rlen, bool clean,
                      void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->closed++;
    sd->closed_code = code;
    sd->closed_reason_len = rlen < sizeof(sd->closed_reason) ? rlen : 0;
    if (sd->closed_reason_len > 0)
        memcpy(sd->closed_reason, reason, sd->closed_reason_len);
    sd->closed_clean = clean;
    sem(sd->pair, "E %c closed code=%u rlen=%zu clean=%d\n", sd->label,
        (unsigned)code, rlen, clean ? 1 : 0);
}

static void retain(wtq_apipair_side_t *sd, wtq_stream_t *st)
{
    if (sd->retained_count < FAKE_MAX_STREAMS) {
        wtq_stream_add_ref(st);
        sd->retained[sd->retained_count++] = st;
    }
}

static void cb_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                             bool bidi, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->stream_opened++;
    sd->last_stream = st;
    sd->last_stream_bidi = bidi;
    sem(sd->pair, "E %c stream-open bidi=%d id=%llu\n", sd->label,
        bidi ? 1 : 0, (unsigned long long)wtq_stream_id(st));
    if (sd->retain_streams)
        retain(sd, st);
}

static void cb_stream_data(wtq_session_t *s, wtq_stream_t *st,
                           const uint8_t *data, size_t len, bool fin,
                           void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->data_events++;
    if (len > 0 && sd->data_len + len <= sizeof(sd->data)) {
        memcpy(sd->data + sd->data_len, data, len);
        sd->data_len += len;
    }
    if (fin)
        sd->fin_events++;
    sem(sd->pair, "E %c data len=%zu fin=%d\n", sd->label, len,
        fin ? 1 : 0);
    if (sd->echo_bidi && fin && wtq_stream_is_bidi(st)) {
        wtq_span_t span = { (const uint8_t *)"pong", 4 };
        (void)wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL);
    }
    if (sd->stop_in_data)
        (void)wtq_stream_stop_sending(st, sd->behavior_code);
    if (sd->close_in_data)
        (void)wtq_session_close(sd->s, sd->behavior_code, NULL, 0);
}

static void cb_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    (void)st;
    sd->stream_reset++;
    sd->last_reset_code = code;
    sem(sd->pair, "E %c stream-reset code=%u\n", sd->label,
        (unsigned)code);
}

static void cb_stream_stop(wtq_session_t *s, wtq_stream_t *st,
                           uint32_t code, void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    (void)st;
    sd->stream_stop++;
    sd->last_stop_code = code;
    sem(sd->pair, "E %c stream-stop code=%u\n", sd->label,
        (unsigned)code);
}

static void cb_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->stream_closed++;
    sem(sd->pair, "E %c stream-closed id=%llu\n", sd->label,
        (unsigned long long)wtq_stream_id(st));
}

static void cb_send_complete(wtq_session_t *s, void *ctx, bool canceled,
                             void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    (void)ctx;
    sd->send_completions++;
    if (canceled)
        sd->send_cancels++;
    sem(sd->pair, "E %c send-complete canceled=%d\n", sd->label,
        canceled ? 1 : 0);
}

static void cb_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    wtq_apipair_side_t *sd = user;

    (void)s;
    sd->dgram_events++;
    sd->dgram_len = len < sizeof(sd->dgram) ? len : 0;
    if (sd->dgram_len > 0)
        memcpy(sd->dgram, data, sd->dgram_len);
    sem(sd->pair, "E %c dgram len=%zu\n", sd->label, len);
}

/* --- lifecycle ----------------------------------------------------------- */

static void *count_alloc(size_t size, void *ctx)
{
    ((wtq_apipair_t *)ctx)->allocs++;
    return malloc(size);
}

static void count_free(void *ptr, size_t size, void *ctx)
{
    (void)size;
    ((wtq_apipair_t *)ctx)->frees++;
    free(ptr);
}

static int side_up(wtq_apipair_t *p, wtq_apipair_side_t *sd, char label,
                   bool client, const wtq_alloc_t *alloc)
{
    wtq_session_events_t ev;

    memset(sd, 0, sizeof(*sd));
    sd->pair = p;
    sd->label = label;
    fake_driver_init(&sd->drv, client);
    wtq_session_events_init(&ev);
    ev.on_established = cb_established;
    ev.on_refused = cb_refused;
    ev.on_failed = cb_failed;
    ev.on_draining = cb_draining;
    ev.on_closed = cb_closed;
    ev.on_stream_opened = cb_stream_opened;
    ev.on_stream_data = cb_stream_data;
    ev.on_stream_reset = cb_stream_reset;
    ev.on_stream_stop = cb_stream_stop;
    ev.on_stream_closed = cb_stream_closed;
    ev.on_send_complete = cb_send_complete;
    ev.on_datagram = cb_datagram;

    wtq_api_session_cfg_t cfg = {
        .alloc = alloc,
        .perspective = client ? WTQ_PERSPECTIVE_CLIENT
                              : WTQ_PERSPECTIVE_SERVER,
        .events = &ev,
        .user = sd,
        .drv = &sd->drv,
        .ops = fake_driver_ops(),
    };
    if (wtq_api_session_create(&cfg, &sd->s) != WTQ_OK || sd->s == NULL) {
        sd->s = NULL; /* create leaves it NULL, but be explicit */
        return -1;
    }
    if (wtq_api_session_start(sd->s, 1000) != WTQ_OK) {
        wtq_session_release(sd->s);
        sd->s = NULL;
        return -1;
    }
    return 0;
}

static int apipair_create_impl(wtq_apipair_t *p, uint64_t seed,
                               const wtq_alloc_t *ext)
{
    memset(p, 0, sizeof(*p));
    p->seed = seed;
    p->now_us = 1000;
    p->alloc = (wtq_alloc_t){ p, count_alloc, NULL, count_free };
    /* the sessions allocate through ext when given (OOM sweeps), else
     * the pair's built-in counting allocator */
    const wtq_alloc_t *use = ext != NULL ? ext : &p->alloc;
    dlv(p, "A create seed=0x%llx\n", (unsigned long long)seed);
    if (side_up(p, &p->c, 'c', true, use) != 0)
        return -1;
    if (side_up(p, &p->s, 's', false, use) != 0) {
        /* partial construction: tear the client back down, no leak */
        wtq_session_release(p->c.s);
        p->c.s = NULL;
        return -1;
    }
    return 0;
}

int wtq_apipair_create_alloc(wtq_apipair_t *p, uint64_t seed,
                             const wtq_alloc_t *alloc)
{
    return apipair_create_impl(p, seed, alloc);
}

int wtq_apipair_create(wtq_apipair_t *p, uint64_t seed)
{
    return apipair_create_impl(p, seed, NULL);
}

void wtq_apipair_destroy(wtq_apipair_t *p)
{
    for (size_t i = 0; i < p->c.retained_count; i++)
        wtq_stream_release(p->c.retained[i]);
    for (size_t i = 0; i < p->s.retained_count; i++)
        wtq_stream_release(p->s.retained[i]);
    if (p->c.s != NULL)
        wtq_session_release(p->c.s);
    if (p->s.s != NULL)
        wtq_session_release(p->s.s);
}

/* --- the pump ------------------------------------------------------------ */

static void count_error(wtq_apipair_t *p, char from, char to,
                        const char *what, wtq_result_t rc)
{
    if (rc != WTQ_OK) {
        p->engine_errors++;
        sem(p, "X %c>%c %s rc=%d\n", from, to, what, (int)rc);
    }
}

/* Record the H3 connection close code once, semantically, so two
 * protocol-fatal scenarios that close with different codes hash
 * differently. Fires only on a real H3 CONNECTION close (conn_fatal /
 * transport close), not on a clean WT session close. */
static void note_fatal(wtq_apipair_t *p, wtq_apipair_side_t *sd)
{
    wtq_conn_t *conn;

    if (sd->s == NULL || sd->fatal_traced)
        return;
    conn = wtq_api_session_conn(sd->s);
    if (conn != NULL && wtq_conn_is_closed(conn)) {
        sd->fatal_traced = true;
        sem(p, "E %c conn-fatal code=0x%llx\n", sd->label,
            (unsigned long long)wtq_conn_close_code(conn));
    }
}

/* Leave the backend bracket; if leave() reports the deferred destroy
 * fired, the session and its wtq_conn are gone — drop the side's
 * pointer so nothing touches freed memory. Returns true on destroy. */
static bool pair_leave(wtq_apipair_side_t *sd)
{
    if (sd->s == NULL)
        return true;
    if (wtq_api_session_leave(sd->s)) {
        sd->s = NULL;
        return true;
    }
    return false;
}

static size_t deliver_dir(wtq_apipair_t *p, wtq_apipair_side_t *from,
                          wtq_apipair_side_t *to)
{
    size_t delivered = 0;
    wtq_conn_t *conn = wtq_api_session_conn(to->s);

    if (conn == NULL)
        return 0;
    wtq_api_session_enter(to->s);

    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++) {
        struct wtq_dstream *src = &from->drv.streams[slot];
        if (!src->in_use || !src->is_local)
            continue;
        /* surface a peer stream ONCE (a refused stream has no engine
         * ctx, so the twin pointer — not the ctx — is the latch) */
        if (src->linked == NULL && src->len > 0) {
            struct wtq_dstream *pds =
                fake_driver_add_peer_stream(&to->drv, src->id);
            if (pds == NULL)
                continue;
            pds->is_bidi = src->is_bidi;
            pds->linked = src;
            src->linked = pds;
            wtq_estream_t *es = NULL;
            wtq_result_t rc =
                src->is_bidi
                    ? wtq_conn_on_peer_bidi_opened(conn, pds, src->id, &es)
                    : wtq_conn_on_peer_uni_opened(conn, pds, src->id, &es);
            count_error(p, from->label, to->label, "open", rc);
            to->es_for_slot[slot] = es;
            pds->ectx = es; /* as a backend records it */
            dlv(p, "D %c>%c open id=%llu\n", from->label, to->label,
                (unsigned long long)src->id);
            delivered++;
        }
        if (src->linked == NULL)
            continue;
        /* keyed on the receiving dstream's engine ctx, re-read before
         * EVERY delivery like a real backend: detachment mid-pass
         * (poison, terminal) stops delivery — the rest reach nobody */
        while (src->delivered < src->len) {
            wtq_estream_t *es = src->linked->ectx;
            if (es == NULL)
                break;
            size_t rem = src->len - src->delivered;
            size_t chunk = 1 + (size_t)(mix64(p->seed ^
                                              (p->step * 31 + slot * 7 +
                                               src->delivered)) %
                                        7);
            if (chunk > rem)
                chunk = rem;
            bool fin = src->fin && (src->delivered + chunk == src->len);
            wtq_result_t rc = wtq_conn_on_stream_bytes(
                conn, es, src->bytes + src->delivered, chunk, fin,
                p->now_us);
            count_error(p, from->label, to->label, "bytes", rc);
            if (fin)
                src->fin_delivered = true;
            dlv(p, "D %c>%c id=%llu bytes=%zu fin=%d\n", from->label,
                to->label, (unsigned long long)src->id, chunk, fin ? 1 : 0);
            src->delivered += chunk;
            delivered++;
        }
        if (src->fin && !src->fin_delivered &&
            src->delivered == src->len && src->linked->ectx != NULL) {
            wtq_result_t rc = wtq_conn_on_stream_bytes(
                conn, src->linked->ectx, NULL, 0, true, p->now_us);
            count_error(p, from->label, to->label, "fin", rc);
            src->fin_delivered = true;
            dlv(p, "D %c>%c id=%llu fin\n", from->label, to->label,
                (unsigned long long)src->id);
            delivered++;
        }
    }
    /* reverse direction of peer-opened bidi streams */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++) {
        struct wtq_dstream *src = &from->drv.streams[slot];
        if (!src->in_use || src->is_local || !src->is_bidi ||
            src->linked == NULL)
            continue;
        /* ectx re-read per chunk: detachment mid-pass stops delivery */
        while (src->delivered < src->len) {
            wtq_estream_t *es = src->linked->ectx;
            if (es == NULL)
                break;
            size_t rem = src->len - src->delivered;
            size_t chunk = 1 + (size_t)(mix64(p->seed ^
                                              (p->step * 131 + slot * 17 +
                                               src->delivered)) %
                                        7);
            if (chunk > rem)
                chunk = rem;
            bool fin = src->fin && (src->delivered + chunk == src->len);
            wtq_result_t rc = wtq_conn_on_stream_bytes(
                conn, es, src->bytes + src->delivered,
                chunk, fin, p->now_us);
            count_error(p, from->label, to->label, "rbytes", rc);
            if (fin)
                src->fin_delivered = true;
            dlv(p, "D %c>%c id=%llu rbytes=%zu fin=%d\n", from->label,
                to->label, (unsigned long long)src->id, chunk,
                fin ? 1 : 0);
            src->delivered += chunk;
            delivered++;
        }
    }
    /* stream closures (reset / STOP_SENDING), exactly once each, after
     * any in-flight bytes; a detached twin delivers nothing */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++) {
        struct wtq_dstream *src = &from->drv.streams[slot];
        if (!src->in_use || src->linked == NULL)
            continue;
        if (src->reset && !src->reset_delivered) {
            src->reset_delivered = true;
            if (src->linked->ectx != NULL) {
                wtq_result_t rc = wtq_conn_on_stream_reset(
                    conn, src->linked->ectx, src->reset_err, p->now_us);
                count_error(p, from->label, to->label, "reset", rc);
            }
            dlv(p, "D %c>%c id=%llu reset\n", from->label, to->label,
                (unsigned long long)src->id);
            delivered++;
        }
        if (src->stopped && !src->stop_delivered) {
            src->stop_delivered = true;
            if (src->linked->ectx != NULL) {
                wtq_result_t rc = wtq_conn_on_stop_sending(
                    conn, src->linked->ectx, src->stop_err, p->now_us);
                count_error(p, from->label, to->label, "stop", rc);
            }
            dlv(p, "D %c>%c id=%llu stop\n", from->label, to->label,
                (unsigned long long)src->id);
            delivered++;
        }
    }
    /* datagrams */
    while (from->drv.dgram_delivered < from->drv.dgram_count) {
        size_t i = from->drv.dgram_delivered++;
        wtq_result_t rc =
            wtq_conn_on_datagram(conn, from->drv.dgrams[i].bytes,
                                 from->drv.dgrams[i].len, p->now_us);
        count_error(p, from->label, to->label, "dgram", rc);
        dlv(p, "D %c>%c dgram len=%zu\n", from->label, to->label,
            from->drv.dgrams[i].len);
        delivered++;
    }

    note_fatal(p, to);
    (void)pair_leave(to);
    return delivered;
}

size_t wtq_apipair_pump(wtq_apipair_t *p)
{
    size_t total = 0;
    size_t moved;

    do {
        p->step++;
        p->now_us += 100;
        moved = deliver_dir(p, &p->c, &p->s) + deliver_dir(p, &p->s, &p->c);
        moved += fake_driver_complete_sends(&p->c.drv,
                                            wtq_api_session_conn(p->c.s));
        moved += fake_driver_complete_sends(&p->s.drv,
                                            wtq_api_session_conn(p->s.s));
        total += moved;
    } while (moved > 0 && p->step < 128);
    return total;
}

uint64_t wtq_apipair_trace_hash(const wtq_apipair_t *p)
{
    uint64_t h = UINT64_C(0xCBF29CE484222325);

    for (size_t i = 0; i < p->trace_len; i++) {
        h ^= (uint8_t)p->trace[i];
        h *= UINT64_C(0x100000001B3);
    }
    return h;
}

uint64_t wtq_apipair_semantic_hash(const wtq_apipair_t *p)
{
    uint64_t h = UINT64_C(0xCBF29CE484222325);

    for (size_t i = 0; i < p->sem_len; i++) {
        h ^= (uint8_t)p->sem[i];
        h *= UINT64_C(0x100000001B3);
    }
    return h;
}

/* --- injection seam ------------------------------------------------------ */

void wtq_apipair_inject_stream(wtq_apipair_t *p, char side, uint64_t id,
                               bool is_bidi, const uint8_t *bytes,
                               size_t len, bool fin, size_t chunk)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&sd->drv, id);
    wtq_estream_t *es = NULL;

    if (conn == NULL || ds == NULL || (bytes == NULL && len > 0))
        return; /* NULL payload is only valid for a zero-length inject */
    wtq_api_session_enter(sd->s);
    wtq_result_t rc =
        is_bidi ? wtq_conn_on_peer_bidi_opened(conn, ds, id, &es)
                : wtq_conn_on_peer_uni_opened(conn, ds, id, &es);
    count_error(p, side, side, "inject-open", rc);
    ds->ectx = es; /* mirror the engine ctx so scenarios can recover it */
    if (es != NULL) {
        size_t off = 0;
        size_t step = chunk > 0 ? chunk : (len > 0 ? len : 1);
        while (off < len && !wtq_conn_is_closed(conn)) {
            size_t take = len - off < step ? len - off : step;
            bool this_fin = fin && (off + take == len);
            rc = wtq_conn_on_stream_bytes(conn, es, bytes + off, take,
                                          this_fin, p->now_us);
            count_error(p, side, side, "inject-bytes", rc);
            off += take;
        }
        /* zero-length stream: exactly one bare FIN, never NULL+0 */
        if (len == 0 && fin) {
            rc = wtq_conn_on_stream_bytes(conn, es, NULL, 0, true,
                                          p->now_us);
            count_error(p, side, side, "inject-bytes", rc);
        }
    }
    note_fatal(p, sd);
    (void)pair_leave(sd);
}

wtq_result_t wtq_apipair_inject_datagram(wtq_apipair_t *p, char side,
                                         const uint8_t *bytes, size_t len)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    wtq_result_t rc;

    if (conn == NULL)
        return WTQ_ERR_STATE;
    wtq_api_session_enter(sd->s);
    rc = wtq_conn_on_datagram(conn, bytes, len, p->now_us);
    count_error(p, side, side, "inject-dgram", rc);
    note_fatal(p, sd);
    (void)pair_leave(sd);
    return rc;
}

wtq_result_t wtq_apipair_deliver(wtq_apipair_t *p, char side,
                                 wtq_estream_t *es, const uint8_t *data,
                                 size_t len, bool fin)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    wtq_result_t rc;

    if (conn == NULL)
        return WTQ_ERR_CLOSED;
    wtq_api_session_enter(sd->s);
    rc = wtq_conn_on_stream_bytes(conn, es, data, len, fin, p->now_us);
    count_error(p, side, side, "deliver", rc);
    note_fatal(p, sd);
    (void)pair_leave(sd);
    return rc;
}

/* Deliver [data,len] to a live estream in seeded 1..8-byte chunks. */
static void deliver_seeded(wtq_apipair_t *p, char side, wtq_conn_t *conn,
                           wtq_estream_t *es, const uint8_t *data,
                           size_t len, bool fin, uint64_t nonce)
{
    size_t off = 0;

    while (off < len && !wtq_conn_is_closed(conn)) {
        size_t rem = len - off;
        size_t chunk =
            1 + (size_t)(mix64(p->seed ^ (nonce * 0x9E37 + off)) % 8);
        if (chunk > rem)
            chunk = rem;
        bool this_fin = fin && (off + chunk == len);
        wtq_result_t rc = wtq_conn_on_stream_bytes(conn, es, data + off,
                                                   chunk, this_fin,
                                                   p->now_us);
        count_error(p, side, side, "seeded-bytes", rc);
        off += chunk;
    }
    if (len == 0 && fin) {
        wtq_result_t rc =
            wtq_conn_on_stream_bytes(conn, es, NULL, 0, true, p->now_us);
        count_error(p, side, side, "seeded-bytes", rc);
    }
}

void wtq_apipair_inject_stream_seeded(wtq_apipair_t *p, char side,
                                      uint64_t id, bool is_bidi,
                                      const uint8_t *bytes, size_t len,
                                      bool fin, uint64_t nonce)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&sd->drv, id);
    wtq_estream_t *es = NULL;

    if (conn == NULL || ds == NULL || (bytes == NULL && len > 0))
        return;
    wtq_api_session_enter(sd->s);
    wtq_result_t rc =
        is_bidi ? wtq_conn_on_peer_bidi_opened(conn, ds, id, &es)
                : wtq_conn_on_peer_uni_opened(conn, ds, id, &es);
    count_error(p, side, side, "inject-open", rc);
    ds->ectx = es;
    if (es != NULL)
        deliver_seeded(p, side, conn, es, bytes, len, fin, nonce);
    note_fatal(p, sd);
    (void)pair_leave(sd);
}

wtq_result_t wtq_apipair_deliver_seeded(wtq_apipair_t *p, char side,
                                        wtq_estream_t *es,
                                        const uint8_t *data, size_t len,
                                        bool fin, uint64_t nonce)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);

    if (conn == NULL)
        return WTQ_ERR_CLOSED;
    if (data == NULL && len > 0)
        return WTQ_ERR_INVALID_ARG;
    wtq_api_session_enter(sd->s);
    deliver_seeded(p, side, conn, es, data, len, fin, nonce);
    note_fatal(p, sd);
    (void)pair_leave(sd);
    return WTQ_OK;
}

wtq_result_t wtq_apipair_reset(wtq_apipair_t *p, char side,
                               wtq_estream_t *es, uint64_t quic_err)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    wtq_result_t rc;

    if (conn == NULL)
        return WTQ_ERR_CLOSED;
    wtq_api_session_enter(sd->s);
    rc = wtq_conn_on_stream_reset(conn, es, quic_err, p->now_us);
    count_error(p, side, side, "reset", rc);
    note_fatal(p, sd);
    (void)pair_leave(sd);
    return rc;
}

wtq_result_t wtq_apipair_stop(wtq_apipair_t *p, char side,
                              wtq_estream_t *es, uint64_t quic_err)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);
    wtq_result_t rc;

    if (conn == NULL)
        return WTQ_ERR_CLOSED;
    wtq_api_session_enter(sd->s);
    rc = wtq_conn_on_stop_sending(conn, es, quic_err, p->now_us);
    count_error(p, side, side, "stop", rc);
    note_fatal(p, sd);
    (void)pair_leave(sd);
    return rc;
}

void wtq_apipair_conn_closed(wtq_apipair_t *p, char side, uint64_t err)
{
    wtq_apipair_side_t *sd = side == 'c' ? &p->c : &p->s;
    wtq_conn_t *conn = wtq_api_session_conn(sd->s);

    if (conn == NULL)
        return;
    wtq_api_session_enter(sd->s);
    wtq_conn_on_conn_closed(conn, err, true, p->now_us);
    /* a lost transport connection cancels its in-flight sends */
    fake_driver_cancel_pending(&sd->drv);
    note_fatal(p, sd);
    (void)pair_leave(sd);
}

wtq_conn_t *wtq_apipair_conn(wtq_apipair_t *p, char side)
{
    return wtq_api_session_conn(side == 'c' ? p->c.s : p->s.s);
}
