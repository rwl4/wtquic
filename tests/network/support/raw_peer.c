/*
 * Raw MsQuic observer peer for Network.framework tests and diagnostics.
 * See raw_peer.h for the design rules. Public MsQuic APIs only.
 */

#include "raw_peer.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <msquic.h>

#define MAX_STREAMS 64
#define MARKER_MAX 48
#define MAX_DGRAMS 32

struct stream_rec {
    bool used;
    uint64_t id;
    HQUIC h;      /* valid until raw_peer_stop; never closed in a callback */
    bool terminal; /* MsQuic reported SHUTDOWN_COMPLETE */

    /* Length-delimited marker, reassembled across RECEIVE fragments. */
    char marker[MARKER_MAX + 1];
    size_t marker_len;
    bool marker_done;

    bool saw_fin;
    bool saw_reset;
    uint64_t reset_code;
    bool saw_stop;
    uint64_t stop_code;
};

struct raw_peer {
    const QUIC_API_TABLE *api;
    HQUIC reg;
    HQUIC cfg;
    HQUIC listener;
    HQUIC conn;
    bool conn_terminal;

    pthread_mutex_t mu;
    pthread_cond_t cv;

    struct stream_rec streams[MAX_STREAMS];
    bool overflow;
    bool dup_marker;

    char dgram_rx[MAX_DGRAMS][MARKER_MAX + 1];
    int dgram_rx_count;
    int dgram_sends_outstanding;

    raw_peer_close_kind_t close_kind;
    uint64_t close_code;

    void (*log)(const char *);
};

static void plog(raw_peer_t *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void plog(raw_peer_t *p, const char *fmt, ...)
{
    if (!p->log)
        return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    p->log(buf);
}

/* --- bounded waits --------------------------------------------------------- */

static void deadline_in(struct timespec *ts, int ms)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long ns = (long)tv.tv_usec * 1000 + (long)(ms % 1000) * 1000000L;
    ts->tv_sec = tv.tv_sec + ms / 1000 + ns / 1000000000L;
    ts->tv_nsec = ns % 1000000000L;
}

/* Caller holds `mu`. */
static bool wait_until(raw_peer_t *p, bool (*pred)(raw_peer_t *, void *),
                       void *arg, int timeout_ms)
{
    struct timespec ts;
    deadline_in(&ts, timeout_ms);
    while (!pred(p, arg)) {
        int rc = pthread_cond_timedwait(&p->cv, &p->mu, &ts);
        if (rc == ETIMEDOUT)
            return pred(p, arg);
    }
    return true;
}

/* --- stream table (caller holds `mu`) -------------------------------------- */

static struct stream_rec *rec_find(raw_peer_t *p, uint64_t id)
{
    for (int i = 0; i < MAX_STREAMS; i++)
        if (p->streams[i].used && p->streams[i].id == id)
            return &p->streams[i];
    return NULL;
}

static struct stream_rec *rec_intern(raw_peer_t *p, uint64_t id, HQUIC h)
{
    struct stream_rec *r = rec_find(p, id);
    if (r)
        return r;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!p->streams[i].used) {
            r = &p->streams[i];
            memset(r, 0, sizeof(*r));
            r->used = true;
            r->id = id;
            r->h = h;
            r->reset_code = RAW_PEER_NO_CODE;
            r->stop_code = RAW_PEER_NO_CODE;
            return r;
        }
    }
    p->overflow = true; /* explicit, visible; never a silent drop */
    return NULL;
}

static const char *dir_of(uint64_t id)
{
    switch (id & 0x3u) {
    case 0: return "client-bidi";
    case 1: return "server-bidi";
    case 2: return "client-uni";
    default: return "server-uni";
    }
}

static uint64_t stream_id_of(raw_peer_t *p, HQUIC s)
{
    uint64_t id = RAW_PEER_NO_CODE;
    uint32_t len = sizeof(id);
    if (QUIC_FAILED(p->api->GetParam(s, QUIC_PARAM_STREAM_ID, &len, &id)))
        return RAW_PEER_NO_CODE;
    return id;
}

/*
 * Reassemble a length-delimited marker. Caller holds `mu`.
 * Returns true when the marker just became complete.
 */
static bool marker_absorb(raw_peer_t *p, struct stream_rec *r,
                          const QUIC_STREAM_EVENT *e)
{
    if (r->marker_done)
        return false;
    for (uint32_t i = 0; i < e->RECEIVE.BufferCount; i++) {
        const QUIC_BUFFER *b = &e->RECEIVE.Buffers[i];
        for (uint32_t j = 0; j < b->Length; j++) {
            char ch = (char)b->Buffer[j];
            if (ch == RAW_PEER_MARKER_TERM) {
                r->marker[r->marker_len] = '\0';
                r->marker_done = true;
                /* Duplicate markers destroy attribution: hard error. */
                for (int k = 0; k < MAX_STREAMS; k++) {
                    struct stream_rec *o = &p->streams[k];
                    if (o != r && o->used && o->marker_done &&
                        strcmp(o->marker, r->marker) == 0)
                        p->dup_marker = true;
                }
                return true;
            }
            if (r->marker_len < MARKER_MAX)
                r->marker[r->marker_len++] = ch;
        }
    }
    return false;
}

/* --- stream callback ------------------------------------------------------- */

static QUIC_STATUS QUIC_API stream_cb(HQUIC s, void *ctx, QUIC_STREAM_EVENT *e)
{
    raw_peer_t *p = ctx;
    uint64_t id = stream_id_of(p, s);

    switch (e->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        char done_marker[MARKER_MAX + 1] = { 0 };
        bool completed = false, over = false;
        pthread_mutex_lock(&p->mu);
        struct stream_rec *r = rec_intern(p, id, s);
        if (r == NULL) {
            over = true;
        } else if (marker_absorb(p, r, e)) {
            completed = true;
            memcpy(done_marker, r->marker, r->marker_len + 1);
        }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);

        if (over)
            plog(p, "RAWPEER FATAL stream table overflow at id=%llu",
                 (unsigned long long)id);
        else if (completed)
            plog(p, "RAWPEER stream %llu (%s) marker=\"%s\"",
                 (unsigned long long)id, dir_of(id), done_marker);
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(e->SEND_COMPLETE.ClientContext); /* exactly once */
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        pthread_mutex_lock(&p->mu);
        { struct stream_rec *r = rec_intern(p, id, s); if (r) r->saw_fin = true; }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER stream %llu (%s) FIN", (unsigned long long)id, dir_of(id));
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: /* RESET_STREAM */
        pthread_mutex_lock(&p->mu);
        {
            struct stream_rec *r = rec_intern(p, id, s);
            if (r) { r->saw_reset = true; r->reset_code = e->PEER_SEND_ABORTED.ErrorCode; }
        }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER stream %llu (%s) RESET_STREAM code=%llu",
             (unsigned long long)id, dir_of(id),
             (unsigned long long)e->PEER_SEND_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED: /* STOP_SENDING */
        pthread_mutex_lock(&p->mu);
        {
            struct stream_rec *r = rec_intern(p, id, s);
            if (r) { r->saw_stop = true; r->stop_code = e->PEER_RECEIVE_ABORTED.ErrorCode; }
        }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER stream %llu (%s) STOP_SENDING code=%llu",
             (unsigned long long)id, dir_of(id),
             (unsigned long long)e->PEER_RECEIVE_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        /*
         * Mark terminal ONLY. The handle is deliberately NOT closed here: an
         * action thread may be between rec_find() and its MsQuic call, and
         * closing underneath it would be a use-after-free. Every handle is
         * closed once in raw_peer_stop(), after MsQuic has quiesced.
         */
        pthread_mutex_lock(&p->mu);
        { struct stream_rec *r = rec_intern(p, id, s); if (r) r->terminal = true; }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER stream %llu terminal", (unsigned long long)id);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

/* --- connection callback --------------------------------------------------- */

static QUIC_STATUS QUIC_API conn_cb(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *e)
{
    (void)c;
    raw_peer_t *p = ctx;

    switch (e->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        plog(p, "RAWPEER connected");
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        HQUIC s = e->PEER_STREAM_STARTED.Stream;
        p->api->SetCallbackHandler(s, (void *)stream_cb, p);
        uint64_t id = stream_id_of(p, s);
        pthread_mutex_lock(&p->mu);
        bool over = (rec_intern(p, id, s) == NULL);
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        if (over)
            plog(p, "RAWPEER FATAL stream table overflow at id=%llu",
                 (unsigned long long)id);
        plog(p, "RAWPEER peer stream started id=%llu (%s) flags=0x%x",
             (unsigned long long)id, dir_of(id),
             (unsigned)e->PEER_STREAM_STARTED.Flags);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const QUIC_BUFFER *b = e->DATAGRAM_RECEIVED.Buffer;
        size_t n = b->Length < MARKER_MAX ? b->Length : MARKER_MAX;
        pthread_mutex_lock(&p->mu);
        if (p->dgram_rx_count < MAX_DGRAMS) {
            memcpy(p->dgram_rx[p->dgram_rx_count], b->Buffer, n);
            p->dgram_rx[p->dgram_rx_count][n] = '\0';
            p->dgram_rx_count++;
        } else {
            p->overflow = true;
        }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER DATAGRAM received %u bytes", (unsigned)b->Length);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        QUIC_DATAGRAM_SEND_STATE st = e->DATAGRAM_SEND_STATE_CHANGED.State;
        bool terminal = (st == QUIC_DATAGRAM_SEND_LOST_DISCARDED ||
                         st == QUIC_DATAGRAM_SEND_ACKNOWLEDGED ||
                         st == QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS ||
                         st == QUIC_DATAGRAM_SEND_CANCELED);
        if (terminal) {
            free(e->DATAGRAM_SEND_STATE_CHANGED.ClientContext); /* exactly once */
            pthread_mutex_lock(&p->mu);
            if (p->dgram_sends_outstanding > 0)
                p->dgram_sends_outstanding--;
            pthread_cond_broadcast(&p->cv);
            pthread_mutex_unlock(&p->mu);
            plog(p, "RAWPEER datagram send terminal state=%d", (int)st);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        pthread_mutex_lock(&p->mu);
        p->close_kind = RAW_PEER_CLOSE_BY_APP;
        p->close_code = e->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER CONNECTION_CLOSE (application) code=%llu",
             (unsigned long long)e->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        pthread_mutex_lock(&p->mu);
        if (p->close_kind == RAW_PEER_CLOSE_NONE) {
            p->close_kind = RAW_PEER_CLOSE_BY_TRANSPORT;
            p->close_code = e->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
        }
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER CONNECTION_CLOSE (transport) code=%llu status=0x%x",
             (unsigned long long)e->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode,
             (unsigned)e->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        /* Like streams: mark terminal, close the handle in raw_peer_stop. */
        pthread_mutex_lock(&p->mu);
        p->conn_terminal = true;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        plog(p, "RAWPEER connection terminal");
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API listener_cb(HQUIC l, void *ctx,
                                        QUIC_LISTENER_EVENT *e)
{
    (void)l;
    raw_peer_t *p = ctx;
    if (e->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        return QUIC_STATUS_SUCCESS;

    HQUIC c = e->NEW_CONNECTION.Connection;
    p->api->SetCallbackHandler(c, (void *)conn_cb, p);
    pthread_mutex_lock(&p->mu);
    p->conn = c;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return p->api->ConnectionSetConfiguration(c, p->cfg);
}

/* --- lifecycle ------------------------------------------------------------- */

raw_peer_t *raw_peer_start(const char *cert_file, const char *key_file,
                           uint16_t *port_out, void (*log)(const char *))
{
    raw_peer_t *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    p->log = log;
    p->close_code = RAW_PEER_NO_CODE;
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);

    if (QUIC_FAILED(MsQuicOpen2(&p->api)))
        goto fail;

    QUIC_REGISTRATION_CONFIG rc = { .AppName = "wtq-raw-peer",
                                    .ExecutionProfile =
                                        QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(p->api->RegistrationOpen(&rc, &p->reg)))
        goto fail;

    QUIC_SETTINGS st;
    memset(&st, 0, sizeof(st));
    st.PeerBidiStreamCount = 32;   st.IsSet.PeerBidiStreamCount = 1;
    st.PeerUnidiStreamCount = 32;  st.IsSet.PeerUnidiStreamCount = 1;
    st.DatagramReceiveEnabled = 1; st.IsSet.DatagramReceiveEnabled = 1;
    st.IdleTimeoutMs = 30000;      st.IsSet.IdleTimeoutMs = 1;

    QUIC_BUFFER alpn = { 2, (uint8_t *)"h3" };
    if (QUIC_FAILED(p->api->ConfigurationOpen(p->reg, &alpn, 1, &st, sizeof(st),
                                              NULL, &p->cfg)))
        goto fail;

    QUIC_CERTIFICATE_FILE cf = { .PrivateKeyFile = key_file,
                                 .CertificateFile = cert_file };
    QUIC_CREDENTIAL_CONFIG cc;
    memset(&cc, 0, sizeof(cc));
    cc.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cc.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cc.CertificateFile = &cf;
    if (QUIC_FAILED(p->api->ConfigurationLoadCredential(p->cfg, &cc)))
        goto fail;

    if (QUIC_FAILED(p->api->ListenerOpen(p->reg, listener_cb, p, &p->listener)))
        goto fail;

    QUIC_ADDR addr;
    memset(&addr, 0, sizeof(addr));
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&addr, 0);
    if (QUIC_FAILED(p->api->ListenerStart(p->listener, &alpn, 1, &addr)))
        goto fail;

    QUIC_ADDR bound;
    uint32_t blen = sizeof(bound);
    if (QUIC_FAILED(p->api->GetParam(
            p->listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &blen, &bound)))
        goto fail;
    *port_out = QuicAddrGetPort(&bound);
    return p;

fail:
    (void)raw_peer_stop(p);
    return NULL;
}

static bool pred_conn_terminal(raw_peer_t *p, void *a);

bool raw_peer_stop(raw_peer_t *p)
{
    if (!p)
        return true;
    bool clean = true;
    if (p->api) {
        if (p->listener) {
            p->api->ListenerStop(p->listener);
            p->api->ListenerClose(p->listener);
        }
        /*
         * Ordering actually used, stated precisely:
         *   1. ConnectionShutdown (silent) -- asks MsQuic to tear the
         *      connection down without a CONNECTION_CLOSE frame.
         *   2. WAIT for the connection's SHUTDOWN_COMPLETE callback. Only
         *      after it has fired is MsQuic done delivering stream and
         *      connection events for this connection.
         *   3. Close every stream handle exactly once. No callback ever
         *      closes one, so there is no lookup-then-use race: a handle
         *      found under `mu` cannot be freed while it is being used.
         *   4. ConnectionClose, then ConfigurationClose (the configuration is
         *      a child of the registration and MUST be closed before it),
         *      then RegistrationClose, which blocks until MsQuic quiesces.
         *
         * Step 2 is a bounded wait: if it expires we report teardown failure
         * rather than closing handles that MsQuic may still touch.
         */
        pthread_mutex_lock(&p->mu);
        HQUIC c = p->conn;
        pthread_mutex_unlock(&p->mu);

        if (c) {
            p->api->ConnectionShutdown(c, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            pthread_mutex_lock(&p->mu);
            bool done = wait_until(p, pred_conn_terminal, NULL, 5000);
            pthread_mutex_unlock(&p->mu);
            if (!done) {
                plog(p, "RAWPEER teardown: connection never reached "
                        "SHUTDOWN_COMPLETE; handles not closed");
                clean = false;
            }
        }

        if (clean) {
            pthread_mutex_lock(&p->mu);
            for (int i = 0; i < MAX_STREAMS; i++) {
                if (p->streams[i].used && p->streams[i].h) {
                    HQUIC h = p->streams[i].h;
                    p->streams[i].h = NULL;
                    pthread_mutex_unlock(&p->mu);
                    p->api->StreamClose(h);
                    pthread_mutex_lock(&p->mu);
                }
            }
            pthread_mutex_unlock(&p->mu);
            if (c)
                p->api->ConnectionClose(c);
        }

        if (p->cfg)
            p->api->ConfigurationClose(p->cfg);
        if (p->reg)
            p->api->RegistrationClose(p->reg);
        MsQuicClose(p->api);
    }
    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
    free(p);
    return clean;
}

/* --- predicates ------------------------------------------------------------ */

struct marker_arg { const char *marker; uint64_t id; };
static bool pred_marker(raw_peer_t *p, void *a)
{
    struct marker_arg *m = a;
    for (int i = 0; i < MAX_STREAMS; i++) {
        struct stream_rec *r = &p->streams[i];
        if (r->used && r->marker_done && strcmp(r->marker, m->marker) == 0) {
            m->id = r->id;
            return true;
        }
    }
    return false;
}

struct id_arg { uint64_t id; uint64_t code; };
static bool pred_reset(raw_peer_t *p, void *a)
{
    struct id_arg *x = a;
    struct stream_rec *r = rec_find(p, x->id);
    if (r && r->saw_reset) { x->code = r->reset_code; return true; }
    return false;
}
static bool pred_stop(raw_peer_t *p, void *a)
{
    struct id_arg *x = a;
    struct stream_rec *r = rec_find(p, x->id);
    if (r && r->saw_stop) { x->code = r->stop_code; return true; }
    return false;
}
static bool pred_terminal(raw_peer_t *p, void *a)
{
    struct id_arg *x = a;
    struct stream_rec *r = rec_find(p, x->id);
    return r && r->terminal;
}
static bool pred_conn(raw_peer_t *p, void *a) { (void)a; return p->conn != NULL; }
static bool pred_conn_terminal(raw_peer_t *p, void *a)
{
    (void)a;
    return p->conn == NULL || p->conn_terminal;
}

static bool pred_dgram_sent(raw_peer_t *p, void *a)
{
    (void)a;
    return p->dgram_sends_outstanding == 0;
}
static bool pred_dgram_rx(raw_peer_t *p, void *a)
{
    const char *want = a;
    for (int i = 0; i < p->dgram_rx_count; i++)
        if (strcmp(p->dgram_rx[i], want) == 0)
            return true;
    return false;
}
static bool pred_close(raw_peer_t *p, void *a)
{
    (void)a;
    return p->close_kind != RAW_PEER_CLOSE_NONE;
}

/* --- observation API ------------------------------------------------------- */

bool raw_peer_wait_marker(raw_peer_t *p, const char *marker, uint64_t *id_out,
                          int timeout_ms)
{
    struct marker_arg m = { marker, RAW_PEER_NO_CODE };
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_marker, &m, timeout_ms);
    pthread_mutex_unlock(&p->mu);
    if (ok && id_out)
        *id_out = m.id;
    return ok;
}

bool raw_peer_wait_reset(raw_peer_t *p, uint64_t id, uint64_t *code_out,
                         int timeout_ms)
{
    struct id_arg x = { id, RAW_PEER_NO_CODE };
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_reset, &x, timeout_ms);
    pthread_mutex_unlock(&p->mu);
    if (ok && code_out) *code_out = x.code;
    return ok;
}

bool raw_peer_wait_stop(raw_peer_t *p, uint64_t id, uint64_t *code_out,
                        int timeout_ms)
{
    struct id_arg x = { id, RAW_PEER_NO_CODE };
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_stop, &x, timeout_ms);
    pthread_mutex_unlock(&p->mu);
    if (ok && code_out) *code_out = x.code;
    return ok;
}

bool raw_peer_wait_stream_terminal(raw_peer_t *p, uint64_t id,
                                   raw_peer_stream_events_t *out,
                                   int timeout_ms)
{
    struct id_arg x = { id, 0 };
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_terminal, &x, timeout_ms);
    if (out) {
        struct stream_rec *r = rec_find(p, id);
        memset(out, 0, sizeof(*out));
        if (r) {
            out->terminal = r->terminal;
            out->saw_fin = r->saw_fin;
            out->saw_reset = r->saw_reset;
            out->reset_code = r->reset_code;
            out->saw_stop = r->saw_stop;
            out->stop_code = r->stop_code;
        }
    }
    pthread_mutex_unlock(&p->mu);
    return ok;
}

bool raw_peer_wait_close(raw_peer_t *p, raw_peer_close_kind_t *kind_out,
                         uint64_t *code_out, int timeout_ms)
{
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_close, NULL, timeout_ms);
    if (kind_out) *kind_out = p->close_kind;
    if (code_out) *code_out = p->close_code;
    pthread_mutex_unlock(&p->mu);
    return ok;
}

bool raw_peer_failed(const raw_peer_t *p, const char **why)
{
    raw_peer_t *q = (raw_peer_t *)p;
    pthread_mutex_lock(&q->mu);
    bool o = q->overflow, d = q->dup_marker;
    pthread_mutex_unlock(&q->mu);
    if (why)
        *why = o ? "stream table overflow" : (d ? "duplicate marker" : "");
    return o || d;
}

/* --- actions --------------------------------------------------------------- */

/*
 * Handle lookup. The returned HQUIC stays valid because no callback ever
 * closes a stream handle -- raw_peer_stop() does, once, after quiesce. A
 * terminal stream is refused rather than acted on.
 */
static HQUIC actionable(raw_peer_t *p, uint64_t id)
{
    pthread_mutex_lock(&p->mu);
    struct stream_rec *r = rec_find(p, id);
    HQUIC h = (r && !r->terminal) ? r->h : NULL;
    pthread_mutex_unlock(&p->mu);
    return h;
}

bool raw_peer_reset_stream(raw_peer_t *p, uint64_t id, uint64_t code)
{
    HQUIC h = actionable(p, id);
    if (!h) return false;
    plog(p, "RAWPEER sending RESET_STREAM(%llu) on stream %llu",
         (unsigned long long)code, (unsigned long long)id);
    return !QUIC_FAILED(p->api->StreamShutdown(
        h, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, code));
}

bool raw_peer_stop_sending(raw_peer_t *p, uint64_t id, uint64_t code)
{
    HQUIC h = actionable(p, id);
    if (!h) return false;
    plog(p, "RAWPEER sending STOP_SENDING(%llu) on stream %llu",
         (unsigned long long)code, (unsigned long long)id);
    return !QUIC_FAILED(p->api->StreamShutdown(
        h, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE, code));
}

bool raw_peer_send_on_stream(raw_peer_t *p, uint64_t id, const void *buf,
                             size_t len, bool fin)
{
    HQUIC h = actionable(p, id);
    if (!h) return false;
    QUIC_BUFFER *qb = malloc(sizeof(*qb) + len);
    if (!qb) return false;
    qb->Buffer = (uint8_t *)(qb + 1);
    qb->Length = (uint32_t)len;
    memcpy(qb->Buffer, buf, len);
    QUIC_STATUS s = p->api->StreamSend(
        h, qb, 1, fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, qb);
    if (QUIC_FAILED(s)) { free(qb); return false; }
    return true; /* freed in SEND_COMPLETE */
}

/* The connection handle is likewise only closed in raw_peer_stop(). */
static HQUIC actionable_conn(raw_peer_t *p, int timeout_ms)
{
    pthread_mutex_lock(&p->mu);
    bool have = wait_until(p, pred_conn, NULL, timeout_ms);
    HQUIC c = (have && !p->conn_terminal) ? p->conn : NULL;
    pthread_mutex_unlock(&p->mu);
    return c;
}

bool raw_peer_open_stream(raw_peer_t *p, bool unidirectional, uint64_t *id_out,
                          int timeout_ms)
{
    HQUIC c = actionable_conn(p, timeout_ms);
    if (!c) return false;

    HQUIC s = NULL;
    if (QUIC_FAILED(p->api->StreamOpen(
            c, unidirectional ? QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL
                              : QUIC_STREAM_OPEN_FLAG_NONE,
            stream_cb, p, &s)))
        return false;
    if (QUIC_FAILED(p->api->StreamStart(s, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        p->api->StreamClose(s);
        return false;
    }

    uint64_t id = stream_id_of(p, s);
    pthread_mutex_lock(&p->mu);
    bool over = (rec_intern(p, id, s) == NULL);
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    if (over) {
        plog(p, "RAWPEER FATAL stream table overflow opening id=%llu",
             (unsigned long long)id);
        return false;
    }
    plog(p, "RAWPEER opened %s stream id=%llu",
         unidirectional ? "server-uni" : "server-bidi", (unsigned long long)id);
    if (id_out) *id_out = id;
    return true;
}

bool raw_peer_send_datagram(raw_peer_t *p, const void *buf, size_t len,
                            int timeout_ms)
{
    HQUIC c = actionable_conn(p, timeout_ms);
    if (!c) return false;

    QUIC_BUFFER *qb = malloc(sizeof(*qb) + len);
    if (!qb) return false;
    qb->Buffer = (uint8_t *)(qb + 1);
    qb->Length = (uint32_t)len;
    memcpy(qb->Buffer, buf, len);

    pthread_mutex_lock(&p->mu);
    p->dgram_sends_outstanding++;
    pthread_mutex_unlock(&p->mu);

    QUIC_STATUS s = p->api->DatagramSend(c, qb, 1, QUIC_SEND_FLAG_NONE, qb);
    if (QUIC_FAILED(s)) {
        pthread_mutex_lock(&p->mu);
        p->dgram_sends_outstanding--;
        pthread_mutex_unlock(&p->mu);
        free(qb);
        return false;
    }

    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_dgram_sent, NULL, timeout_ms);
    pthread_mutex_unlock(&p->mu);
    return ok;
}

bool raw_peer_wait_datagram(raw_peer_t *p, const char *payload, int timeout_ms)
{
    pthread_mutex_lock(&p->mu);
    bool ok = wait_until(p, pred_dgram_rx, (void *)payload, timeout_ms);
    pthread_mutex_unlock(&p->mu);
    return ok;
}
