/*
 * White-box driver-op edge cases: exercises the backend ops directly,
 * below the engine's own argument guards, so the ops' defensive checks
 * are provably load-bearing on their own.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "msq_internal.h"

#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

#include "test_support.h"

/* A span list whose length sum wraps size_t must be refused before any
 * allocation is sized from it or any byte is copied. */
static int test_dgram_len_sum_overflow(void)
{
    int failures = 0;
    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), NULL, true);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    /* non-NULL sentinel so the closed-guard passes; the op must reject
     * the spans before ever touching the transport */
    drv->conn = (HQUIC)(void *)drv;

    static const uint8_t byte = 0;
    wtq_span_t spans[2] = {
        { &byte, SIZE_MAX - 1 },
        { &byte, 2 }, /* wraps the naive sum to 1 */
    };
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->dgram_send(drv, spans, 2),
        WTQ_ERR_TOO_LARGE);
    WTQ_TEST_CHECK_EQ_INT(drv->dgram_inflight, 0);

    drv->conn = NULL; /* nothing to close */
    wtq_msq_conn_free(drv);
    return failures;
}

/* Receive enable/disable on a transport-dead stream (its HQUIC already
 * closed at stream shutdown) reports closed without touching MsQuic. */
static int test_recv_enable_dead_stream(void)
{
    int failures = 0;
    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), NULL, true);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    drv->conn = (HQUIC)(void *)drv;

    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, true, 0);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        /* ds->stream is NULL: the transport handle is gone */
        WTQ_TEST_CHECK_EQ_INT(
            wtq_msq_driver_ops()->recv_enable(drv, ds, false),
            WTQ_ERR_CLOSED);
        WTQ_TEST_CHECK_EQ_INT(
            wtq_msq_driver_ops()->recv_enable(drv, ds, true),
            WTQ_ERR_CLOSED);
    }

    drv->conn = NULL; /* nothing to close */
    wtq_msq_conn_free(drv);
    return failures;
}

/* The gather send budget is a queue-depth throttle, not a size cap:
 * an idle stream admits one legal send of any size (a refused send has
 * no completion to wake a retry — refusing it would deadlock), while a
 * stream with bytes already in flight blocks anything over the budget.
 * A fake StreamSend stands in for the transport. */
static int fake_stream_sends;
static void *fake_stream_send_ctx;

static QUIC_STATUS QUIC_API fake_stream_send(HQUIC stream,
                                             const QUIC_BUFFER *bufs,
                                             uint32_t count,
                                             QUIC_SEND_FLAGS flags,
                                             void *client_ctx)
{
    (void)stream;
    (void)bufs;
    (void)count;
    (void)flags;
    fake_stream_sends++;
    fake_stream_send_ctx = client_ctx;
    return QUIC_STATUS_SUCCESS;
}

static int test_gather_budget_is_depth_not_size(void)
{
    int failures = 0;
    QUIC_API_TABLE api;

    memset(&api, 0, sizeof(api));
    api.StreamSend = fake_stream_send;
    fake_stream_sends = 0;
    fake_stream_send_ctx = NULL;

    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), &api, true);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    drv->conn = (HQUIC)(void *)drv;

    struct wtq_dstream *ds = wtq_msq_stream_new(drv, true, false, 2);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds == NULL) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return failures;
    }
    ds->stream = (HQUIC)(void *)ds; /* live-stream sentinel */

    /* the fake never dereferences the data; only the length matters */
    static const uint8_t byte = 0;
    wtq_span_t big = { &byte, 3u * WTQ_MSQ_SEND_BUDGET_MIN };
    int cookie;

    /* bytes already in flight: over-budget blocks before the
     * transport is touched */
    ds->inflight_bytes = 1;
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &big, 1, false,
                                          &cookie),
        WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 0);
    WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 0);

    /* the floor itself, pinned from both sides: a queued send whose
     * sum with in-flight bytes stays under 1 MiB is admitted (the old
     * 64 KiB floor would have refused it and serialized the stream at
     * one full-ACK cycle per send)... */
    wtq_span_t mid = { &byte, 600u * 1024u };
    ds->inflight_bytes = 40u * 1024u;
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &mid, 1, false,
                                          &cookie),
        WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 1);
    WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 1);
    WTQ_TEST_CHECK(ds->inflight_bytes == 640u * 1024u);
    /* ...while a sum past 1 MiB parks behind the in-flight bytes */
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &mid, 1, false,
                                          &cookie),
        WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 1);
    {
        struct wtq_msq_gather_rec *mrec = fake_stream_send_ctx;

        WTQ_TEST_CHECK(mrec != NULL && mrec->cookie == &cookie);
        if (mrec != NULL) {
            ds->inflight_bytes -= mrec->bytes;
            drv->pending_sends--;
            wtq_msq_gather_put(drv, mrec);
        }
        ds->inflight_bytes = 0;
        fake_stream_sends = 0;
        fake_stream_send_ctx = NULL;
    }

    /* an oversized accepted send can leave inflight_bytes above the
     * ceiling: the budget math must not wrap and re-admit — a huge
     * in-flight count plus a small span must still block, before the
     * transport is touched */
    ds->inflight_bytes = UINT64_MAX - 1;
    wtq_span_t small = { &byte, 16 };
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &small, 1, false,
                                          &cookie),
        WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 0);
    WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 0);

    /* idle: the same oversized send is admitted whole */
    ds->inflight_bytes = 0;
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &big, 1, false,
                                          &cookie),
        WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 1);
    WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 1);
    WTQ_TEST_CHECK(ds->inflight_bytes == big.len);

    /* while it is in flight, the depth throttle holds */
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &big, 1, false,
                                          &cookie),
        WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(fake_stream_sends, 1);

    /* completion bookkeeping, as the stream event handler does it */
    struct wtq_msq_gather_rec *rec = fake_stream_send_ctx;
    WTQ_TEST_CHECK(rec != NULL && rec->cookie == &cookie);
    if (rec != NULL) {
        ds->inflight_bytes -= rec->bytes;
        drv->pending_sends--;
        wtq_msq_gather_put(drv, rec);
    }

    ds->stream = NULL; /* nothing to close */
    drv->conn = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

/* The writable edge's backend bookkeeping: a WOULD_BLOCK gather arms
 * the stream's flag, a successful gather does not, and the delivery
 * helper without session/engine linkage is a safe no-op that keeps the
 * flag armed for when linkage exists (the real emission path is pinned
 * end-to-end by the loopback suite). */
static int test_writable_arming(void)
{
    int failures = 0;
    QUIC_API_TABLE api;

    memset(&api, 0, sizeof(api));
    api.StreamSend = fake_stream_send;
    fake_stream_sends = 0;
    fake_stream_send_ctx = NULL;

    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), &api, true);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    drv->conn = (HQUIC)(void *)drv;

    struct wtq_dstream *ds = wtq_msq_stream_new(drv, true, false, 2);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds == NULL) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return failures;
    }
    ds->stream = (HQUIC)(void *)ds;

    static const uint8_t byte = 0;
    wtq_span_t span = { &byte, 600u * 1024u };
    int cookie;

    /* an accepted send never arms */
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &span, 1, false,
                                          &cookie),
        WTQ_OK);
    WTQ_TEST_CHECK(!ds->send_blocked);

    /* a refused send arms the edge */
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &span, 1, false,
                                          &cookie),
        WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK(ds->send_blocked);

    /* no session linkage: nothing to notify, the arm survives */
    wtq_msq_stream_writable_check(drv, ds);
    WTQ_TEST_CHECK(ds->send_blocked);

    /* ideal-size growth without linkage: bookkeeping only, arm kept */
    QUIC_STREAM_EVENT ev;
    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE;
    ev.IDEAL_SEND_BUFFER_SIZE.ByteCount = 8u * 1024u * 1024u;
    (void)wtq_msq_stream_callback((HQUIC)(void *)ds, ds, &ev);
    WTQ_TEST_CHECK(ds->ideal_send == 8u * 1024u * 1024u);
    WTQ_TEST_CHECK(ds->send_blocked);

    /* completion bookkeeping for the accepted send */
    struct wtq_msq_gather_rec *rec = fake_stream_send_ctx;
    WTQ_TEST_CHECK(rec != NULL);
    if (rec != NULL) {
        ds->inflight_bytes -= rec->bytes;
        drv->pending_sends--;
        wtq_msq_gather_put(drv, rec);
    }

    /* a retry that succeeds through any other path (typically from
     * inside on_send_complete, which runs before the writable check)
     * disarms the edge — the armed flag is the check's first guard,
     * so no stale writable can follow the successful send */
    WTQ_TEST_CHECK(ds->send_blocked);
    fake_stream_send_ctx = NULL;
    WTQ_TEST_CHECK_EQ_INT(
        wtq_msq_driver_ops()->send_gather(drv, ds, &span, 1, false,
                                          &cookie),
        WTQ_OK);
    WTQ_TEST_CHECK(!ds->send_blocked);
    wtq_msq_stream_writable_check(drv, ds); /* armed? no — no emission */
    WTQ_TEST_CHECK(!ds->send_blocked);

    rec = fake_stream_send_ctx;
    WTQ_TEST_CHECK(rec != NULL);
    if (rec != NULL) {
        ds->inflight_bytes -= rec->bytes;
        drv->pending_sends--;
        wtq_msq_gather_put(drv, rec);
    }
    ds->stream = NULL;
    drv->conn = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}


/* The MsQuic stream credits must not promise more concurrent peer
 * streams than the engine's fixed 16-slot pool can hold. 8 uni + 7 bidi
 * = 15, leaving one slot for the client's local CONNECT stream while
 * the HTTP/3 critical streams (control + 2 QPACK) fit inside the uni
 * budget. Macro, initializer, and QUIC_SETTINGS translation must agree. */
static void test_tuning_stream_credits(int *fp)
{
    int failures = 0;
    static const wtq_msquic_tuning_t MACRO = WTQ_MSQUIC_TUNING_INIT;
    wtq_msquic_tuning_t t;
    QUIC_SETTINGS qs;

    WTQ_TEST_CHECK_EQ_INT(MACRO.peer_unidi_stream_count, 8);
    WTQ_TEST_CHECK_EQ_INT(MACRO.peer_bidi_stream_count, 7);

    wtq_msquic_tuning_init(&t);
    WTQ_TEST_CHECK_EQ_INT(t.peer_unidi_stream_count, 8);
    WTQ_TEST_CHECK_EQ_INT(t.peer_bidi_stream_count, 7);

    wtq_msq_settings_init(&qs, &t);
    WTQ_TEST_CHECK_EQ_INT((int)qs.PeerUnidiStreamCount, 8);
    WTQ_TEST_CHECK_EQ_INT((int)qs.PeerBidiStreamCount, 7);
    WTQ_TEST_CHECK(qs.IsSet.PeerUnidiStreamCount);
    WTQ_TEST_CHECK(qs.IsSet.PeerBidiStreamCount);

    /* a tuning left at struct_size 0 must still translate to 8/7 */
    wtq_msquic_tuning_t zero;
    memset(&zero, 0, sizeof(zero));
    wtq_msq_settings_init(&qs, &zero);
    WTQ_TEST_CHECK_EQ_INT((int)qs.PeerUnidiStreamCount, 8);
    WTQ_TEST_CHECK_EQ_INT((int)qs.PeerBidiStreamCount, 7);

    *fp += failures;
}


/* --- PEER_STREAM_STARTED: handler registration precedes rejection ------- */

/* Records the order of the MsQuic API calls the connection callback
 * makes, so "SetCallbackHandler first" is provable, not assumed. */
#define ORD_MAX 8
static struct {
    int n;
    struct {
        int is_handler;                  /* else a StreamShutdown */
        HQUIC stream;
        void *ctx;                       /* handler ctx / unused */
        void *handler;
        QUIC_STREAM_SHUTDOWN_FLAGS flags;
        QUIC_UINT62 code;
    } call[ORD_MAX];
} g_ord;

static void QUIC_API rec_set_handler(HQUIC h, void *handler, void *ctx)
{
    if (g_ord.n < ORD_MAX) {
        g_ord.call[g_ord.n].is_handler = 1;
        g_ord.call[g_ord.n].stream = h;
        g_ord.call[g_ord.n].handler = handler;
        g_ord.call[g_ord.n].ctx = ctx;
        g_ord.n++;
    }
}

static QUIC_STATUS QUIC_API rec_stream_shutdown(
    HQUIC h, QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    if (g_ord.n < ORD_MAX) {
        g_ord.call[g_ord.n].is_handler = 0;
        g_ord.call[g_ord.n].stream = h;
        g_ord.call[g_ord.n].flags = flags;
        g_ord.call[g_ord.n].code = code;
        g_ord.n++;
    }
    return QUIC_STATUS_SUCCESS;
}

static uint64_t g_peer_id;
static QUIC_STATUS QUIC_API rec_get_param(HQUIC h, uint32_t param,
                                          uint32_t *len, void *buf)
{
    (void)h;
    if (param != QUIC_PARAM_STREAM_ID || buf == NULL ||
        len == NULL || *len < sizeof(uint64_t))
        return QUIC_STATUS_INVALID_PARAMETER;
    memcpy(buf, &g_peer_id, sizeof(g_peer_id));
    return QUIC_STATUS_SUCCESS;
}

static void QUIC_API rec_stream_close(HQUIC h)
{
    (void)h; /* the sentinels are not real handles */
}

static void ord_api(QUIC_API_TABLE *api)
{
    memset(api, 0, sizeof(*api));
    api->SetCallbackHandler = rec_set_handler;
    api->StreamShutdown = rec_stream_shutdown;
    api->StreamClose = rec_stream_close;
    api->GetParam = rec_get_param;
}

/* Drive the REAL connection callback with a peer stream. */
static void feed_peer_stream_started(struct wtq_driver *drv, HQUIC stream,
                                     bool bidi, uint64_t id)
{
    QUIC_CONNECTION_EVENT ev;

    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
    ev.PEER_STREAM_STARTED.Stream = stream;
    ev.PEER_STREAM_STARTED.Flags =
        bidi ? 0 : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    g_peer_id = id;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &ev);
}

/* MsQuic requires the stream's callback handler to be registered
 * immediately on PEER_STREAM_STARTED. On engine-pool overflow the
 * engine rejects the stream from inside the open call (StreamShutdown),
 * so the handler MUST already be set. */
static int test_peer_stream_started_handler_before_shutdown(void)
{
    int failures = 0;

    for (int bidi = 0; bidi < 2; bidi++) {
        QUIC_API_TABLE api;
        ord_api(&api);

        struct wtq_driver *drv =
            wtq_msq_conn_new(wtq_alloc_default(), &api, true);
        WTQ_TEST_CHECK(drv != NULL);
        if (drv == NULL)
            return failures;
        drv->conn = (HQUIC)(void *)drv;

        wtq_session_events_t ev;
        wtq_session_events_init(&ev);
        wtq_api_session_cfg_t scfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .events = &ev,
            .user = NULL,
            .drv = drv,
            .ops = wtq_msq_driver_ops(),
        };
        wtq_session_t *sess = NULL;
        WTQ_TEST_CHECK(wtq_api_session_create(&scfg, &sess) == WTQ_OK);
        if (sess == NULL) {
            drv->conn = NULL;
            wtq_msq_conn_free(drv);
            return failures + 1;
        }
        drv->session = sess;
        wtq_conn_t *ec = wtq_api_session_conn(sess);

        /* fill the engine's fixed peer pool */
        size_t filled = 0;
        for (uint64_t i = 0; i < 64; i++) {
            struct wtq_dstream *ds =
                wtq_msq_stream_new(drv, false, false, 100 + i);
            wtq_estream_t *es = NULL;
            if (ds == NULL)
                break;
            ds->stream = (HQUIC)(void *)ds;
            if (wtq_conn_on_peer_uni_opened(ec, ds, 100 + i, &es) !=
                WTQ_OK)
                break;
            ds->ectx = es;
            filled++;
        }
        WTQ_TEST_CHECK_EQ_SIZE(filled, 16);

        /* now the overflowing peer stream, through the real callback */
        g_ord.n = 0;
        HQUIC peer = (HQUIC)(void *)&g_ord; /* stream sentinel */
        feed_peer_stream_started(drv, peer, bidi != 0, 40);

        /* the handler came first, on the right stream */
        WTQ_TEST_CHECK(g_ord.n >= 2);
        if (g_ord.n < 2) {
            wtq_session_release(sess);
            drv->conn = NULL;
            drv->session = NULL;
            wtq_msq_conn_free(drv);
            return failures + 1;
        }
        WTQ_TEST_CHECK(g_ord.call[0].is_handler);
        WTQ_TEST_CHECK(g_ord.call[0].stream == peer);
        WTQ_TEST_CHECK(g_ord.call[0].handler ==
                       wtq_msq_stream_cb_ptr(wtq_msq_stream_callback));

        /* the handler context is the backend stream for THIS stream */
        struct wtq_dstream *ds = g_ord.call[0].ctx;
        WTQ_TEST_CHECK(ds != NULL);
        WTQ_TEST_CHECK(ds != NULL && ds->stream == peer);
        WTQ_TEST_CHECK(ds != NULL && ds->id == 40);
        /* refused: no engine ctx published */
        WTQ_TEST_CHECK(ds != NULL && ds->ectx == NULL);

        /* every StreamShutdown came AFTER it, with the exact code.
         * Rejection is ONE whole-stream transaction: a single call whose
         * flags cover exactly the still-open halves (recv for a uni,
         * recv+send for a bidi) — never a sequential pair. */
        int shutdowns = 0;
        bool saw_abort_recv = false;
        bool saw_abort_send = false;
        for (int i = 1; i < g_ord.n; i++) {
            WTQ_TEST_CHECK(!g_ord.call[i].is_handler);
            if (g_ord.call[i].is_handler)
                continue;
            shutdowns++;
            WTQ_TEST_CHECK(g_ord.call[i].stream == peer);
            WTQ_TEST_CHECK_EQ_HEX(g_ord.call[i].code,
                                  WTQ_WT_BUFFERED_STREAM_REJECTED);
            if (g_ord.call[i].flags &
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE)
                saw_abort_recv = true;
            if (g_ord.call[i].flags &
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND)
                saw_abort_send = true;
        }
        WTQ_TEST_CHECK(saw_abort_recv);
        WTQ_TEST_CHECK_EQ_INT(shutdowns, 1);
        WTQ_TEST_CHECK(saw_abort_send == (bidi != 0));

        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

/* An ACCEPTED peer stream still registers the handler and then
 * publishes its engine context; no shutdown is issued. */
static int test_peer_stream_started_accepted(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    ord_api(&api);

    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), &api, true);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    drv->conn = (HQUIC)(void *)drv;

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    wtq_api_session_cfg_t scfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = NULL,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *sess = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&scfg, &sess) == WTQ_OK);
    if (sess == NULL) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return failures + 1;
    }
    drv->session = sess;

    g_ord.n = 0;
    HQUIC peer = (HQUIC)(void *)&g_ord;
    feed_peer_stream_started(drv, peer, false, 3);

    WTQ_TEST_CHECK_EQ_INT(g_ord.n, 1); /* handler only */
    if (g_ord.n >= 1) {
        WTQ_TEST_CHECK(g_ord.call[0].is_handler);
        struct wtq_dstream *ds = g_ord.call[0].ctx;
        WTQ_TEST_CHECK(ds != NULL);
        WTQ_TEST_CHECK(ds != NULL && ds->ectx != NULL); /* published */
    }

    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

/* --- transport-error record population (design §6) --------------------- */

static int g_conn_shutdowns;
static void QUIC_API rec_conn_shutdown(HQUIC h,
                                       QUIC_CONNECTION_SHUTDOWN_FLAGS f,
                                       QUIC_UINT62 code)
{
    (void)h;
    (void)f;
    (void)code;
    g_conn_shutdowns++;
}

/* Terminal capture: the record as observed INSIDE the first session
 * terminal callback. */
static wtq_transport_error_t g_term_err;
static int g_term_fired;
static int g_term_refused;

static void cap_record(wtq_session_t *s)
{
    g_term_fired++;
    memset(&g_term_err, 0, sizeof(g_term_err));
    g_term_err.struct_size = (uint32_t)sizeof(g_term_err);
    (void)wtq_session_transport_error(s, &g_term_err);
}

static void cap_on_failed(wtq_session_t *s, wtq_connect_failure_t why,
                          void *user)
{
    (void)why;
    (void)user;
    cap_record(s);
}

static void cap_on_refused(wtq_session_t *s, uint16_t status, void *user)
{
    (void)status;
    (void)user;
    g_term_refused++;
    cap_record(s);
}

static void cap_on_closed(wtq_session_t *s, uint32_t code,
                          const uint8_t *reason, size_t rlen, bool clean,
                          void *user)
{
    (void)code;
    (void)reason;
    (void)rlen;
    (void)clean;
    (void)user;
    cap_record(s);
}

/* Local-stream flow stubs: streams open/start/send successfully so the
 * engine's CONNECT flow can run over the fake table; sends are recorded
 * and completed by feeding SEND_COMPLETE back. */
struct sent_rec {
    HQUIC stream;
    void *cctx;
};
static struct sent_rec g_sent[32];
static int g_sent_n;

static QUIC_STATUS QUIC_API rec_stream_open(HQUIC conn,
                                            QUIC_STREAM_OPEN_FLAGS flags,
                                            QUIC_STREAM_CALLBACK_HANDLER cb,
                                            void *ctx, HQUIC *out)
{
    (void)conn;
    (void)flags;
    (void)cb;
    *out = (HQUIC)ctx; /* the ds doubles as its own handle sentinel */
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API rec_stream_start(HQUIC h,
                                             QUIC_STREAM_START_FLAGS f)
{
    (void)h;
    (void)f;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API rec_stream_send(HQUIC h,
                                            const QUIC_BUFFER *bufs,
                                            uint32_t n, QUIC_SEND_FLAGS f,
                                            void *cctx)
{
    (void)bufs;
    (void)n;
    (void)f;
    if (g_sent_n < (int)(sizeof(g_sent) / sizeof(g_sent[0]))) {
        g_sent[g_sent_n].stream = h;
        g_sent[g_sent_n].cctx = cctx;
        g_sent_n++;
    }
    return QUIC_STATUS_SUCCESS;
}

static void complete_all_sends(void)
{
    for (int i = 0; i < g_sent_n; i++) {
        QUIC_STREAM_EVENT sev;
        memset(&sev, 0, sizeof(sev));
        sev.Type = QUIC_STREAM_EVENT_SEND_COMPLETE;
        sev.SEND_COMPLETE.ClientContext = g_sent[i].cctx;
        (void)wtq_msq_stream_callback(g_sent[i].stream,
                                      (void *)g_sent[i].stream, &sev);
    }
    g_sent_n = 0;
}

/* SHUTDOWN_INITIATED_BY_TRANSPORT populates {QUIC_TRANSPORT, wire code,
 * MSQUIC domain, native status}; BY_PEER populates {QUIC_APP, code,
 * MSQUIC, 0}. Each record is set BEFORE the terminal input and the
 * SHUTDOWN_COMPLETE repeat cannot overwrite it (engine write-once). */
static int test_transport_error_population(void)
{
    int failures = 0;

    for (int by_peer = 0; by_peer < 2; by_peer++) {
        QUIC_API_TABLE api;
        ord_api(&api);
        api.ConnectionShutdown = rec_conn_shutdown;

        struct wtq_driver *drv =
            wtq_msq_conn_new(wtq_alloc_default(), &api, true);
        WTQ_TEST_CHECK(drv != NULL);
        if (drv == NULL)
            return failures + 1;
        drv->conn = (HQUIC)(void *)drv;

        wtq_session_events_t ev;
        wtq_session_events_init(&ev);
        wtq_api_session_cfg_t scfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .events = &ev,
            .user = NULL,
            .drv = drv,
            .ops = wtq_msq_driver_ops(),
        };
        wtq_session_t *sess = NULL;
        WTQ_TEST_CHECK(wtq_api_session_create(&scfg, &sess) == WTQ_OK);
        if (sess == NULL) {
            drv->conn = NULL;
            wtq_msq_conn_free(drv);
            return failures + 1;
        }
        drv->session = sess;

        QUIC_CONNECTION_EVENT cev;
        memset(&cev, 0, sizeof(cev));
        if (by_peer) {
            cev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
            cev.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = 0x77;
        } else {
            cev.Type =
                QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
            cev.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = 0x42;
            cev.SHUTDOWN_INITIATED_BY_TRANSPORT.Status =
                (QUIC_STATUS)0x80410005; /* representative native status */
        }
        (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);

        wtq_transport_error_t e;
        memset(&e, 0, sizeof(e));
        e.struct_size = (uint32_t)sizeof(e);
        WTQ_TEST_CHECK(wtq_session_transport_error(sess, &e) == WTQ_OK);
        if (by_peer) {
            WTQ_TEST_CHECK_EQ_INT((int)e.kind,
                                  (int)WTQ_ERR_KIND_QUIC_APP);
            WTQ_TEST_CHECK_EQ_HEX(e.quic_code, 0x77);
            WTQ_TEST_CHECK(e.native_code == 0);
        } else {
            WTQ_TEST_CHECK_EQ_INT((int)e.kind,
                                  (int)WTQ_ERR_KIND_QUIC_TRANSPORT);
            WTQ_TEST_CHECK_EQ_HEX(e.quic_code, 0x42);
            WTQ_TEST_CHECK(e.native_code == (int64_t)0x80410005);
        }
        WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_MSQUIC);

        /* a later local shutdown flavor cannot overwrite the record */
        wtq_transport_error_t before = e;
        QUIC_CONNECTION_EVENT done;
        memset(&done, 0, sizeof(done));
        done.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
        done.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = 0x99;
        done.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = (QUIC_STATUS)1;
        (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &done);
        memset(&e, 0, sizeof(e));
        e.struct_size = (uint32_t)sizeof(e);
        WTQ_TEST_CHECK(wtq_session_transport_error(sess, &e) == WTQ_OK);
        WTQ_TEST_CHECK(e.kind == before.kind &&
                       e.quic_code == before.quic_code &&
                       e.native_code == before.native_code);

        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

/* Build the standard error-record rig: fake API table with a shutdown
 * recorder, real driver, real session (an extra caller ref so the
 * record can be queried after SHUTDOWN_COMPLETE drops the backend's). */
static struct wtq_driver *err_rig_up(QUIC_API_TABLE *api,
                                     wtq_session_t **out_sess)
{
    ord_api(api);
    api->ConnectionShutdown = rec_conn_shutdown;
    api->StreamOpen = rec_stream_open;
    api->StreamStart = rec_stream_start;
    api->StreamSend = rec_stream_send;

    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), api, true);
    if (drv == NULL)
        return NULL;
    drv->conn = (HQUIC)(void *)drv;
    g_term_fired = 0;
    g_term_refused = 0;
    g_sent_n = 0;

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    ev.on_failed = cap_on_failed;
    ev.on_refused = cap_on_refused;
    ev.on_closed = cap_on_closed;
    wtq_api_session_cfg_t scfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = NULL,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *sess = NULL;
    if (wtq_api_session_create(&scfg, &sess) != WTQ_OK) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return NULL;
    }
    drv->session = sess;
    wtq_session_add_ref(sess); /* caller ref: survives SHUTDOWN_COMPLETE */
    *out_sess = sess;
    return drv;
}

/* Feed the terminal event. NOTE: the handler drops the backend's
 * session reference and FREES drv — the caller must not touch drv
 * afterwards. AppCloseInProgress=1 keeps the fake sentinel handle away
 * from api->ConnectionClose. */
static void feed_shutdown_complete(struct wtq_driver *drv)
{
    QUIC_CONNECTION_EVENT cev;

    memset(&cev, 0, sizeof(cev));
    cev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
    cev.SHUTDOWN_COMPLETE.AppCloseInProgress = 1;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);
}

static int query_record(wtq_session_t *sess, wtq_transport_error_t *e)
{
    memset(e, 0, sizeof(*e));
    e->struct_size = (uint32_t)sizeof(*e);
    return wtq_session_transport_error(sess, e) == WTQ_OK;
}

/* A CAUSAL local shutdown (engine conn_close op) that completes without
 * any BY_TRANSPORT/BY_PEER event still delivers its staged MsQuic
 * detail: {LOCAL, code, MSQUIC domain} from SHUTDOWN_COMPLETE. */
static int test_local_shutdown_no_initiated_event(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    g_conn_shutdowns = 0;
    WTQ_TEST_CHECK(wtq_msq_driver_ops()->conn_close(drv, 0x33) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_conn_shutdowns, 1);
    feed_shutdown_complete(drv);

    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, 0x33);
    WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_MSQUIC);
    /* no transport event: the legacy terminal code is the causal one */
    WTQ_TEST_CHECK_EQ_HEX(
        wtq_conn_close_code(wtq_api_session_conn(sess)), 0x33);

    wtq_session_release(sess); /* drv was freed by SHUTDOWN_COMPLETE */
    return failures;
}

/* Environment close: ConnectionShutdown was issued OUTSIDE conn_shutdown
 * (nothing staged, not cleanup). SHUTDOWN_COMPLETE classifies it as a
 * causal LOCAL error with MsQuic domain. */
static int test_env_close_classification(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    /* no initiated event, no conn_shutdown: straight to completion */
    feed_shutdown_complete(drv);

    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_MSQUIC);

    wtq_session_release(sess); /* drv was freed by SHUTDOWN_COMPLETE */
    return failures;
}

/* An ENGINE fatal is the first cause: it latches {QUIC_APP, h3 code}
 * before asking the backend to shut down, so the backend's staged LOCAL
 * detail delivered at SHUTDOWN_COMPLETE is ignored. */
static int test_engine_fatal_precedence(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    wtq_conn_t *ec = wtq_api_session_conn(sess);

    /* peer control stream, SETTINGS delivered TWICE: engine fatal
     * (FRAME_UNEXPECTED), which calls the conn_close op -> real
     * conn_shutdown stages LOCAL — too late to matter */
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, false, 3);
    WTQ_TEST_CHECK(ds != NULL);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(ec, ds, 3, &es) == WTQ_OK);
    ds->ectx = es;
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    buf[0] = 0x00; /* control stream type */
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    g_conn_shutdowns = 0;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(ec, es, buf, 1 + flen, false,
                                            1000) == WTQ_OK);
    (void)wtq_conn_on_stream_bytes(ec, es, buf + 1, flen, false, 1100);
    WTQ_TEST_CHECK_EQ_INT(g_conn_shutdowns, 1); /* engine shut us down */
    feed_shutdown_complete(drv);

    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_QUIC_APP);
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, WTQ_H3_FRAME_UNEXPECTED);
    WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_NONE);

    wtq_session_release(sess); /* drv was freed by SHUTDOWN_COMPLETE */
    return failures;
}

/* Once a cause is staged, later BY_TRANSPORT / BY_PEER events must not
 * rewrite the causal tuple — {LOCAL, 0x33} survives both. */
static int test_first_causal_survives_later_events(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    WTQ_TEST_CHECK(wtq_msq_driver_ops()->conn_close(drv, 0x33) == WTQ_OK);

    /* conflicting later events */
    QUIC_CONNECTION_EVENT cev;
    memset(&cev, 0, sizeof(cev));
    cev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
    cev.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = 0x99;
    cev.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = (QUIC_STATUS)7;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);
    memset(&cev, 0, sizeof(cev));
    cev.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
    cev.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = 0x77;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);
    feed_shutdown_complete(drv);

    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, 0x33);   /* NOT 0x99 / 0x77 */
    WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_MSQUIC);
    WTQ_TEST_CHECK(e.native_code == 0);
    /* the intentional split: the later transport event drives the
     * LEGACY close code while the first-causal record stays 0x33 */
    WTQ_TEST_CHECK_EQ_HEX(
        wtq_conn_close_code(wtq_api_session_conn(sess)), 0x99);

    wtq_session_release(sess); /* drv was freed by SHUTDOWN_COMPLETE */
    return failures;
}

/* Environment close stages its EXACT code (0x100) before shutdown. */
static int test_env_close_exact_code(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    /* exactly what env_close does: only the atomic latch crosses
     * threads; the worker stages the cause at classification time */
    atomic_store_explicit(&drv->env_close_req, true,
                          memory_order_release);
    wtq_conn_t *ec = wtq_api_session_conn(sess);
    feed_shutdown_complete(drv);

    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, 0x100);
    WTQ_TEST_CHECK((int)e.native_domain == (int)WTQ_ERRDOM_MSQUIC);
    /* the legacy terminal input carried the causal code too */
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(ec), 0x100);

    wtq_session_release(sess);
    return failures;
}

/* Stream-ID divergence (the main MsQuic backend-invariant failure)
 * delivers {LOCAL, H3_INTERNAL_ERROR, MSQUIC, msquic-assigned id},
 * visible INSIDE the terminal callback. */
static int test_stream_id_mismatch_detail(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, true, false, 2);
    WTQ_TEST_CHECK(ds != NULL);
    ds->stream = (HQUIC)(void *)ds;

    g_conn_shutdowns = 0;
    QUIC_STREAM_EVENT sev;
    memset(&sev, 0, sizeof(sev));
    sev.Type = QUIC_STREAM_EVENT_START_COMPLETE;
    sev.START_COMPLETE.Status = QUIC_STATUS_SUCCESS;
    sev.START_COMPLETE.ID = 6; /* diverges from the computed id 2 */
    (void)wtq_msq_stream_callback((HQUIC)(void *)ds, ds, &sev);

    /* terminal fired with the detail already visible inside it; the
     * native value is the MsQuic STATUS (success here — the failure is
     * the divergence), never the stream id */
    WTQ_TEST_CHECK_EQ_INT(g_term_fired, 1);
    WTQ_TEST_CHECK_EQ_INT((int)g_term_err.kind, (int)WTQ_ERR_KIND_LOCAL);
    WTQ_TEST_CHECK_EQ_HEX(g_term_err.quic_code, WTQ_H3_INTERNAL_ERROR);
    WTQ_TEST_CHECK((int)g_term_err.native_domain ==
                   (int)WTQ_ERRDOM_MSQUIC);
    WTQ_TEST_CHECK(g_term_err.native_code ==
                   (int64_t)QUIC_STATUS_SUCCESS);
    WTQ_TEST_CHECK_EQ_INT(g_conn_shutdowns, 1);

    feed_shutdown_complete(drv);
    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, WTQ_H3_INTERNAL_ERROR);
    WTQ_TEST_CHECK(e.native_code == (int64_t)QUIC_STATUS_SUCCESS);

    wtq_session_release(sess);
    return failures;
}

/* A REJECTED session seals NONE; the post-terminal cleanup shutdown and
 * its completion must leave the sealed record untouched. Runs the real
 * client CONNECT flow over the fake table. */
static int test_cleanup_preserves_sealed_none(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = err_rig_up(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    wtq_conn_t *ec = wtq_api_session_conn(sess);

    /* CONNECTED: the engine starts (control streams open + send) */
    QUIC_CONNECTION_EVENT cev;
    memset(&cev, 0, sizeof(cev));
    cev.Type = QUIC_CONNECTION_EVENT_CONNECTED;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);

    static const char *const offer[] = { "moqt-18" };
    wtq_connect_config_t ccfg;
    wtq_connect_config_init(&ccfg);
    ccfg.authority = "example.com";
    ccfg.path = "/app";
    ccfg.subprotocols = offer;
    ccfg.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(sess, &ccfg) == WTQ_OK);

    /* peer SETTINGS -> the engine sends CONNECT */
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    struct wtq_dstream *pds = wtq_msq_stream_new(drv, false, false, 3);
    WTQ_TEST_CHECK(pds != NULL);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(ec, pds, 3, &pes) ==
                   WTQ_OK);
    pds->ectx = pes;
    wtq_api_session_enter(sess);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(ec, pes, buf, 1 + flen,
                                            false, 1000) == WTQ_OK);
    wtq_msq_conn_leave_and_poll(drv);

    /* every queued send completes: the flush gate opens */
    complete_all_sends();
    WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 0);

    /* 403: REJECTED -> sealed NONE, then the lifetime policy retires
     * the connection as post-terminal CLEANUP */
    uint8_t section[256];
    uint8_t resp[300];
    size_t slen = 0;
    WTQ_TEST_CHECK(wtq_connect_encode_response(403, NULL, section,
                                               sizeof(section),
                                               &slen) == 0);
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen,
                                              resp, sizeof(resp),
                                              &hl) == 0);
    memcpy(resp + hl, section, slen);
    struct wtq_dstream *bidi = NULL;
    for (struct wtq_dstream *it = drv->streams; it != NULL; it = it->next)
        if (it->is_local && it->is_bidi)
            bidi = it;
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    g_conn_shutdowns = 0;
    wtq_api_session_enter(sess);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(ec, bidi->ectx, resp,
                                            hl + slen, false, 2000) ==
                   WTQ_OK);
    wtq_msq_conn_leave_and_poll(drv);

    WTQ_TEST_CHECK_EQ_INT(g_term_refused, 1);
    /* sealed NONE was visible inside on_refused */
    WTQ_TEST_CHECK_EQ_INT((int)g_term_err.kind, (int)WTQ_ERR_KIND_NONE);
    /* the retirement was classified CLEANUP and staged no cause */
    WTQ_TEST_CHECK_EQ_INT(g_conn_shutdowns, 1);
    WTQ_TEST_CHECK(drv->close_cleanup);
    WTQ_TEST_CHECK_EQ_INT((int)drv->close_kind, (int)WTQ_ERR_KIND_NONE);

    feed_shutdown_complete(drv);
    wtq_transport_error_t e;
    WTQ_TEST_CHECK(query_record(sess, &e));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_NONE);
    WTQ_TEST_CHECK(e.quic_code == 0);
    WTQ_TEST_CHECK(e.native_domain == WTQ_ERRDOM_NONE);

    wtq_session_release(sess);
    return failures;
}

/* --- receive pause/resume: synchronous arrest of queued receives ------ *
 *
 * StreamReceiveSetEnabled(FALSE) is asynchronous — a RECEIVE queued behind
 * it still fires — so the backend keeps logical recv_disabled state and
 * rejects such a receive by accepting zero bytes (TotalBufferLength -> 0),
 * leaving the data with MsQuic for redelivery on resume. These white-box
 * cases exercise the mechanic and the pause/resume failure handling the
 * real loopback cannot inject; the end-to-end "engine observed none, all
 * delivered byte-exact after resume" is the loopback's job. */

static int g_rse_calls;              /* successful SetEnabled submissions */
static BOOLEAN g_rse_last;           /* last submitted value */
static int g_rse_fail;               /* fail the next N SetEnabled calls */

static QUIC_STATUS QUIC_API rec_recv_set_enabled(HQUIC h, BOOLEAN enabled)
{
    (void)h;
    if (g_rse_fail > 0) {
        g_rse_fail--;
        return QUIC_STATUS_ABORTED;
    }
    g_rse_calls++;
    g_rse_last = enabled;
    return QUIC_STATUS_SUCCESS;
}

static void recv_api(QUIC_API_TABLE *api)
{
    memset(api, 0, sizeof(*api));
    api->StreamReceiveSetEnabled = rec_recv_set_enabled;
    api->StreamClose = rec_stream_close;
}

/* Deliver a RECEIVE event with `count` single-byte-filled buffers; returns
 * the TotalBufferLength the callback left (the bytes it accepted). */
static uint64_t recv_deliver(struct wtq_dstream *ds, uint32_t count,
                             uint32_t each, bool fin)
{
    static uint8_t data[64];
    QUIC_BUFFER qb[4];
    QUIC_STREAM_EVENT ev;
    uint64_t total = 0;

    memset(data, 0x5a, sizeof(data));
    if (each > sizeof(data))
        each = sizeof(data);
    if (count > 4)
        count = 4;
    for (uint32_t i = 0; i < count; i++) {
        qb[i].Buffer = data;
        qb[i].Length = each;
        total += each;
    }
    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_STREAM_EVENT_RECEIVE;
    ev.RECEIVE.TotalBufferLength = total;
    ev.RECEIVE.Buffers = count > 0 ? qb : NULL;
    ev.RECEIVE.BufferCount = count;
    ev.RECEIVE.Flags = fin ? QUIC_RECEIVE_FLAG_FIN : 0;
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &ev);
    return ev.RECEIVE.TotalBufferLength;
}

/* A live-stream rig with no session: the arrest short-circuits before the
 * engine feed, and a non-arrested data receive with no engine is simply
 * discarded (TotalBufferLength left unchanged), so the accepted length is
 * the observable: 0 == arrested, `total` == not arrested. */
static struct wtq_driver *recv_rig(QUIC_API_TABLE *api,
                                   struct wtq_dstream **ds_out)
{
    struct wtq_driver *drv =
        wtq_msq_conn_new(wtq_alloc_default(), api, true);
    if (drv == NULL)
        return NULL;
    drv->conn = (HQUIC)(void *)drv;
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, true, 4);
    if (ds == NULL) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return NULL;
    }
    ds->stream = (HQUIC)(void *)ds; /* live-stream sentinel */
    *ds_out = ds;
    return drv;
}

static void recv_rig_free(struct wtq_driver *drv)
{
    drv->conn = NULL;
    wtq_msq_conn_free(drv);
}

static const wtq_driver_ops_t *OPS(void) { return wtq_msq_driver_ops(); }

/* Pause succeeds; a data-bearing RECEIVE queued behind it is arrested
 * (accepts zero bytes) — single- and multi-buffer, and data+FIN — while an
 * unpaused stream accepts in full; resume clears the state. */
static int test_recv_pause_arrest(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    struct wtq_dstream *ds = NULL;

    recv_api(&api);
    g_rse_calls = 0;
    g_rse_fail = 0;
    struct wtq_driver *drv = recv_rig(&api, &ds);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;

    /* not paused: a data receive is accepted in full (no arrest) */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 8);

    /* pause: SetEnabled(FALSE), logical state published on success */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    WTQ_TEST_CHECK(ds->recv_disabled);
    WTQ_TEST_CHECK_EQ_INT(g_rse_calls, 1);
    WTQ_TEST_CHECK(g_rse_last == FALSE);

    /* a data receive queued behind the pause is arrested */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 0);
    /* multi-buffer: the whole event is arrested */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 3, 8, false), 0);
    /* data+FIN: arrested (data and FIN held for redelivery) */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, true), 0);
    WTQ_TEST_CHECK(!ds->fin_delivered);

    /* resume: SetEnabled(TRUE), state cleared on success */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true), WTQ_OK);
    WTQ_TEST_CHECK(!ds->recv_disabled);
    WTQ_TEST_CHECK_EQ_INT(g_rse_calls, 2);
    WTQ_TEST_CHECK(g_rse_last == TRUE);

    /* delivery is usable again */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 8);

    recv_rig_free(drv);
    return failures;
}

/* A failed pause returns the backend error and leaves the stream unpaused:
 * data delivery stays usable. */
static int test_recv_pause_failure(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    struct wtq_dstream *ds = NULL;

    recv_api(&api);
    g_rse_calls = 0;
    g_rse_fail = 1; /* fail the pause submission */
    struct wtq_driver *drv = recv_rig(&api, &ds);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;

    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false),
                          WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(!ds->recv_disabled);   /* state unchanged */
    WTQ_TEST_CHECK_EQ_INT(g_rse_calls, 0);
    /* delivery usable: a data receive is not arrested */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 8);
    /* and a retried pause now takes effect */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    WTQ_TEST_CHECK(ds->recv_disabled);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 0);

    recv_rig_free(drv);
    return failures;
}

/* A failed resume returns the backend error and leaves the stream paused
 * (retryable); a subsequent successful resume clears it. */
static int test_recv_resume_failure(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    struct wtq_dstream *ds = NULL;

    recv_api(&api);
    g_rse_calls = 0;
    g_rse_fail = 0;
    struct wtq_driver *drv = recv_rig(&api, &ds);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;

    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    WTQ_TEST_CHECK(ds->recv_disabled);

    g_rse_fail = 1; /* fail the resume submission */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true),
                          WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(ds->recv_disabled);    /* still paused (retryable) */
    /* receives are still arrested while the retry is owed */
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 0);

    /* the retry succeeds and clears the pause */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true), WTQ_OK);
    WTQ_TEST_CHECK(!ds->recv_disabled);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver(ds, 1, 8, false), 8);

    recv_rig_free(drv);
    return failures;
}

/* A peer reset / stream teardown while paused clears the logical pause,
 * attempts no resume, and does not make the connection fatal; a later
 * resume on the dead stream is CLOSED, not fatal. */
static int test_recv_reset_while_paused(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    struct wtq_dstream *ds = NULL;

    recv_api(&api);
    g_rse_calls = 0;
    g_rse_fail = 0;
    struct wtq_driver *drv = recv_rig(&api, &ds);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;

    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    WTQ_TEST_CHECK(ds->recv_disabled);

    /* peer reset: the receive direction is terminal, pause cleared, and
     * the connection is not torn down */
    QUIC_STREAM_EVENT ev;
    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
    ev.PEER_SEND_ABORTED.ErrorCode = 7;
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &ev);
    WTQ_TEST_CHECK(!ds->recv_disabled);
    WTQ_TEST_CHECK(!drv->shutdown_started);

    /* stream teardown: the transport handle is released */
    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
    ev.SHUTDOWN_COMPLETE.AppCloseInProgress = FALSE;
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &ev);
    WTQ_TEST_CHECK(ds->stream == NULL);

    /* resume on the dead stream: CLOSED, no resume attempted, not fatal */
    g_rse_calls = 0;
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true),
                          WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK_EQ_INT(g_rse_calls, 0);
    WTQ_TEST_CHECK(!drv->shutdown_started);

    recv_rig_free(drv);
    return failures;
}

/* --- receive pause/resume over an ESTABLISHED session ----------------- *
 *
 * The rigs above prove the arrest mechanic and the pause/resume failure
 * handling in isolation. These drive the arrest through a real established
 * WebTransport session so the APP-VISIBLE outcome is observable: while
 * paused the engine and the on_stream_data callback see NOTHING, and after
 * resume the held bytes (modeled by MsQuic re-indicating them) arrive
 * exactly once, byte-exact and in order, FIN included. */

/* on_stream_data / on_stream_opened / on_established capture. */
static struct rx_cap {
    int established;
    int opened;
    int data_calls;
    int fin_calls;
    size_t bytes;
    size_t buf_len;
    uint8_t buf[64];
    bool pause_open;
    int pause_at_call;
    wtq_result_t pause_result;
    size_t max_payload;
    wtq_stream_t *stream;
    bool retain_stream;
    bool patterned;
    size_t bad_bytes;
    void (*opened_hook)(wtq_session_t *);
    unsigned terminal_order;
    uint32_t reset_code, stop_code;
    unsigned closed_calls;
} g_pr;

static void pr_on_established(wtq_session_t *s, wtq_str_t sub, void *u)
{
    (void)s;
    (void)sub;
    (void)u;
    g_pr.established++;
}

static struct {
    struct wtq_driver *drv;
    int endpoint_depth;
    int unsafe_publications;
    int probes;
    bool active;
} admission_borrow;

static void pr_on_stream_closed(wtq_session_t *s, wtq_stream_t *st, void *u)
{
    (void)u;
    g_pr.closed_calls++;
    if (!admission_borrow.active) return;
    admission_borrow.probes++;
    int before = g_pr.opened;
    uint64_t id = wtq_stream_id(st);
    wtq_stream_release(st);
    /* The driver call has returned, but session_open/abort still borrows. */
    if (admission_borrow.drv->api_depth != 0)
        admission_borrow.unsafe_publications++;
    QUIC_CONNECTION_EVENT ev = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
    (void)wtq_msq_conn_callback(NULL, admission_borrow.drv, &ev);
    (void)wtq_session_service_stream_admission(s);
    if (g_pr.opened != before || wtq_stream_id(st) != id)
        admission_borrow.unsafe_publications++;
}

static void pr_on_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                                bool bidi, void *u)
{
    (void)s;
    (void)st;
    (void)bidi;
    (void)u;
    g_pr.opened++;
    if (admission_borrow.endpoint_depth) admission_borrow.unsafe_publications++;
    g_pr.stream = st;
    if (g_pr.retain_stream)
        wtq_stream_add_ref(st);
    if (g_pr.pause_open)
        g_pr.pause_result = wtq_stream_pause_receive(st);
    if (g_pr.opened_hook) g_pr.opened_hook(s);
}

static void pr_on_stream_data(wtq_session_t *s, wtq_stream_t *st,
                              const uint8_t *d, size_t n, bool fin, void *u)
{
    (void)s;
    (void)st;
    (void)u;
    g_pr.data_calls++;
    if (fin)
        g_pr.fin_calls++;
    for (size_t i = 0; i < n && g_pr.buf_len < sizeof(g_pr.buf); i++)
        g_pr.buf[g_pr.buf_len++] = d[i];
    if (g_pr.patterned)
        for (size_t i = 0; i < n; i++)
            if (d[i] != (uint8_t)((g_pr.bytes + i) % 251))
                g_pr.bad_bytes++;
    g_pr.bytes += n;
    if (n > g_pr.max_payload)
        g_pr.max_payload = n;
    if (g_pr.pause_at_call == g_pr.data_calls)
        g_pr.pause_result = wtq_stream_pause_receive(st);
}

static void pr_on_stream_reset(wtq_session_t *s, wtq_stream_t *st, uint32_t code, void *u)
{
    (void)s; (void)st; (void)code; (void)u;
    g_pr.terminal_order = g_pr.terminal_order * 10 + 1;
    g_pr.reset_code = code;
}

static void pr_on_stream_stop(wtq_session_t *s, wtq_stream_t *st, uint32_t code, void *u)
{
    (void)s; (void)st; (void)code; (void)u;
    g_pr.terminal_order = g_pr.terminal_order * 10 + 2;
    g_pr.stop_code = code;
}

/* Deliver a RECEIVE carrying exactly `data[0..len)` (single buffer, or a
 * bare FIN when len == 0). Returns the TotalBufferLength the callback
 * left — 0 == arrested, len == accepted. */
static uint64_t recv_deliver_bytes(struct wtq_dstream *ds,
                                   const uint8_t *data, uint32_t len,
                                   bool fin)
{
    QUIC_BUFFER qb;
    QUIC_STREAM_EVENT ev;

    memset(&ev, 0, sizeof(ev));
    ev.Type = QUIC_STREAM_EVENT_RECEIVE;
    ev.RECEIVE.TotalBufferLength = len;
    if (len > 0) {
        qb.Buffer = (uint8_t *)data;
        qb.Length = len;
        ev.RECEIVE.Buffers = &qb;
        ev.RECEIVE.BufferCount = 1;
    }
    ev.RECEIVE.Flags = fin ? QUIC_RECEIVE_FLAG_FIN : 0;
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &ev);
    return ev.RECEIVE.TotalBufferLength;
}

/* Bring a client session to ESTABLISHED over the fake table (mirrors the
 * CONNECT flow the error-record rigs use, answered with a 200), wiring the
 * pause-relevant events. Returns the driver or NULL. */
static struct wtq_driver *pause_estab_mode(QUIC_API_TABLE *api,
                                      wtq_session_t **out_sess,
                                      const wtq_alloc_t *alloc, bool bounded)
{
    ord_api(api);
    api->ConnectionShutdown = rec_conn_shutdown;
    api->StreamOpen = rec_stream_open;
    api->StreamStart = rec_stream_start;
    api->StreamSend = rec_stream_send;
    api->StreamReceiveSetEnabled = rec_recv_set_enabled;

    struct wtq_driver *drv =
        wtq_msq_conn_new(alloc, api, true);
    if (drv == NULL)
        return NULL;
    drv->conn = (HQUIC)(void *)drv;
    g_sent_n = 0;
    g_rse_calls = 0;
    g_rse_fail = 0;
    memset(&g_pr, 0, sizeof(g_pr));

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    ev.on_established = pr_on_established;
    ev.on_stream_opened = pr_on_stream_opened;
    ev.on_stream_data = pr_on_stream_data;
    ev.on_stream_closed = pr_on_stream_closed;
    ev.on_stream_reset = pr_on_stream_reset;
    ev.on_stream_stop = pr_on_stream_stop;
    wtq_api_session_cfg_t scfg = {
        .alloc = alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = NULL,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *sess = NULL;
    wtq_msquic_tuning_t tuning;
    wtq_msquic_tuning_init(&tuning);
    wtq_result_t create_rc = bounded
        ? wtq_msq_session_create_bounded(drv, &scfg, &tuning, &sess)
        : wtq_api_session_create(&scfg, &sess);
    if (create_rc != WTQ_OK) {
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return NULL;
    }
    drv->session = sess;
    wtq_conn_t *ec = wtq_api_session_conn(sess);

    QUIC_CONNECTION_EVENT cev;
    memset(&cev, 0, sizeof(cev));
    cev.Type = QUIC_CONNECTION_EVENT_CONNECTED;
    (void)wtq_msq_conn_callback((HQUIC)(void *)drv, drv, &cev);

    wtq_connect_config_t ccfg;
    wtq_connect_config_init(&ccfg);
    ccfg.authority = "example.com";
    ccfg.path = "/app";
    if (wtq_api_session_connect(sess, &ccfg) != WTQ_OK)
        goto fail;

    /* peer SETTINGS (WebTransport) -> the engine sends CONNECT */
    uint8_t sbuf[128];
    wtq_h3_settings_encode_cfg_t setcfg = { true, false };
    size_t flen = 0;
    sbuf[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&setcfg, sbuf + 1, sizeof(sbuf) - 1,
                                     &flen) != 0)
        goto fail;
    struct wtq_dstream *pds = wtq_msq_stream_new(drv, false, false, 3);
    if (pds == NULL)
        goto fail;
    wtq_estream_t *pes = NULL;
    wtq_api_session_enter(sess);
    if (bounded) {
        (void)wtq_conn_peer_admission_init(ec, &pds->admission, pds, 3,
            false, (unsigned)(pds - drv->peers));
        size_t consumed = 0;
        (void)wtq_msq_stream_input(pds, sbuf, 1 + flen, false, &consumed);
    } else {
        (void)wtq_conn_on_peer_uni_opened(ec, pds, 3, &pes);
        pds->ectx = pes;
        (void)wtq_conn_on_stream_bytes(ec, pes, sbuf, 1 + flen, false, 1000);
    }
    wtq_msq_conn_leave_and_poll(drv);
    complete_all_sends();

    /* answer the CONNECT (local bidi) with a 200 -> ESTABLISHED */
    uint8_t section[256];
    uint8_t resp[300];
    size_t slen = 0;
    if (wtq_connect_encode_response(200, NULL, section, sizeof(section),
                                    &slen) != 0)
        goto fail;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, resp,
                                   sizeof(resp), &hl) != 0)
        goto fail;
    memcpy(resp + hl, section, slen);
    struct wtq_dstream *bidi = NULL;
    for (struct wtq_dstream *it = drv->streams; it != NULL; it = it->next)
        if (it->is_local && it->is_bidi)
            bidi = it;
    if (bidi == NULL || bidi->ectx == NULL)
        goto fail;
    wtq_api_session_enter(sess);
    (void)wtq_conn_on_stream_bytes(ec, bidi->ectx, resp, hl + slen, false,
                                   2000);
    wtq_msq_conn_leave_and_poll(drv);

    if (g_pr.established != 1)
        goto fail;
    *out_sess = sess;
    return drv;

fail:
    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return NULL;
}

static struct wtq_driver *pause_estab(QUIC_API_TABLE *api,
                                      wtq_session_t **out_sess)
{
    return pause_estab_mode(api, out_sess, wtq_alloc_default(), false);
}

static struct wtq_driver *pause_estab_with_alloc(QUIC_API_TABLE *api,
    wtq_session_t **out_sess, const wtq_alloc_t *alloc)
{
    return pause_estab_mode(api, out_sess, alloc, false);
}

/* Open the peer's WT unidirectional data stream and drive it to the
 * app-visible ES_WT state via its preamble (WT uni type 0x54, session 0).
 * Returns the backend stream, with its engine ctx published. */
static struct wtq_dstream *pause_open_wt_uni(struct wtq_driver *drv,
                                             wtq_conn_t *ec, uint64_t id)
{
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, false, id);
    if (ds == NULL)
        return NULL;
    ds->stream = (HQUIC)(void *)ds;
    wtq_estream_t *es = NULL;
    if (wtq_conn_on_peer_uni_opened(ec, ds, id, &es) != WTQ_OK)
        return NULL;
    ds->ectx = es;
    /* WT uni preamble: type 0x54 (a 2-byte varint) + session id 0 */
    uint8_t pre[8];
    size_t pre_len = 0;
    if (wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 0, pre, sizeof(pre),
                            &pre_len) != WTQ_PREAMBLE_OK)
        return NULL;
    (void)recv_deliver_bytes(ds, pre, (uint32_t)pre_len, false);
    return ds;
}

/* Engine isolation + redelivery: while paused a payload RECEIVE is
 * arrested and neither the engine nor on_stream_data observes it; after
 * resume MsQuic re-indicates the held bytes and they arrive exactly once,
 * byte-exact and in order. */
static int test_recv_established_isolation_redelivery(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    wtq_conn_t *ec = wtq_api_session_conn(sess);

    struct wtq_dstream *ds = pause_open_wt_uni(drv, ec, 7);
    WTQ_TEST_CHECK(ds != NULL);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1); /* app saw the stream */
    if (ds == NULL) {
        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
        return failures + 1;
    }

    /* pause; a payload RECEIVE queued behind it is arrested and the
     * engine/app observe NOTHING */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    const uint8_t hello[5] = { 'h', 'e', 'l', 'l', 'o' };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, hello, 5, false), 0);
    WTQ_TEST_CHECK(ds->recv_held_data);
    WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 0);
    WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 0);

    /* resume; MsQuic re-indicates the held bytes ONCE: delivered exactly
     * once, byte-exact */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true), WTQ_OK);
    WTQ_TEST_CHECK(!ds->recv_held_data);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, hello, 5, false), 5);
    WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
    WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 5);
    WTQ_TEST_CHECK(g_pr.buf_len == 5 && memcmp(g_pr.buf, hello, 5) == 0);

    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

/* FIN handling while paused: a pure zero-byte FIN is DEFERRED, a graceful
 * PEER_SEND_SHUTDOWN behind the pause is SUPPRESSED (no duplicate), and on
 * resume the FIN is replayed to the app exactly once, after the data. */
static int test_recv_fin_deferred_while_paused(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab(&api, &sess);

    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures + 1;
    wtq_conn_t *ec = wtq_api_session_conn(sess);

    struct wtq_dstream *ds = pause_open_wt_uni(drv, ec, 7);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds == NULL) {
        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
        return failures + 1;
    }

    /* some data lands first (running), so ordering is observable */
    const uint8_t hi[2] = { 'h', 'i' };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, hi, 2, false), 2);
    WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);

    /* pause; a pure zero-byte FIN queued behind it is DEFERRED */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, false), WTQ_OK);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, NULL, 0, true), 0);
    WTQ_TEST_CHECK(ds->fin_pending);
    WTQ_TEST_CHECK(!ds->fin_delivered);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0); /* not delivered while paused */

    /* a graceful PEER_SEND_SHUTDOWN behind the pause is suppressed */
    QUIC_STREAM_EVENT sev;
    memset(&sev, 0, sizeof(sev));
    sev.Type = QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN;
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &sev);
    WTQ_TEST_CHECK(!ds->fin_delivered);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);

    /* resume: the FIN is replayed exactly once, after the data */
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, ds, true), WTQ_OK);
    WTQ_TEST_CHECK(ds->fin_delivered);
    WTQ_TEST_CHECK(!ds->fin_pending);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
    WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 2); /* FIN carried no phantom bytes */

    /* a late graceful shutdown does not double-deliver the FIN */
    (void)wtq_msq_stream_callback((HQUIC)ds->stream, ds, &sev);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);

    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

/* The settings translation stamps the receive-side invariants: send
 * buffering off (per tuning) and, where the preview ABI exposes it,
 * non-multi-receive mode pinned OFF with its IsSet bit. */
static int test_settings_non_multi_receive(void)
{
    int failures = 0;
    QUIC_SETTINGS qs;
    wtq_msquic_tuning_t t;

    wtq_msquic_tuning_init(&t);
    wtq_msq_settings_init(&qs, &t);
    WTQ_TEST_CHECK(qs.IsSet.SendBufferingEnabled == TRUE);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    WTQ_TEST_CHECK(qs.StreamMultiReceiveEnabled == FALSE);
    WTQ_TEST_CHECK(qs.IsSet.StreamMultiReceiveEnabled == TRUE);
#endif
    return failures;
}

/* Same RECEIVE, two buffers: accepting the first must not consume the
 * second after the application successfully pauses in its callback. */
static int test_recv_callback_pause_multibuffer(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab(&api, &sess);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    g_pr.retain_stream = true;
    struct wtq_dstream *ds = pause_open_wt_uni(drv,
                                               wtq_api_session_conn(sess), 7);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        uint8_t data[] = { 'a', 'b', 'c', 'd', 'e' };
        QUIC_BUFFER buffers[] = {
            { .Length = 2, .Buffer = data },
            { .Length = 3, .Buffer = data + 2 },
        };
        QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_RECEIVE };
        ev.RECEIVE.TotalBufferLength = sizeof(data);
        ev.RECEIVE.BufferCount = 2;
        ev.RECEIVE.Buffers = buffers;
        ev.RECEIVE.Flags = QUIC_RECEIVE_FLAG_FIN;
        g_pr.pause_at_call = 1;
        g_pr.pause_result = WTQ_ERR_STATE;
        (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
        WTQ_TEST_CHECK_EQ_INT(g_pr.pause_result, WTQ_OK);
        WTQ_TEST_CHECK_EQ_U64(ev.RECEIVE.TotalBufferLength, 2);
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 2);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.buf_len, 2);
        WTQ_TEST_CHECK(memcmp(g_pr.buf, data, 2) == 0);
        g_pr.pause_at_call = 2;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
        buffers[0].Buffer = data + 2;
        buffers[0].Length = 1;
        buffers[1].Buffer = data + 3;
        buffers[1].Length = 2;
        ev.RECEIVE.TotalBufferLength = 3;
        (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
        WTQ_TEST_CHECK_EQ_U64(ev.RECEIVE.TotalBufferLength, 1);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 3);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, data + 3, 2, true), 2);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 5);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.buf_len, 5);
        WTQ_TEST_CHECK(memcmp(g_pr.buf, data, 5) == 0);
    }
    if (g_pr.stream != NULL)
        wtq_stream_release(g_pr.stream);
    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

/* The preamble and first payload share one buffer. Pausing in opened
 * accepts only the preamble, not the as-yet-undelivered application tail. */
static int test_recv_callback_pause_opened_case(bool bidi, bool bare)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab(&api, &sess);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    uint64_t id = bidi ? 1 : 7;
    struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, bidi, id);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        ds->stream = (HQUIC)(void *)ds;
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK_EQ_INT(bidi ? wtq_conn_on_peer_bidi_opened(
            wtq_api_session_conn(sess), ds, id, &es) :
            wtq_conn_on_peer_uni_opened(wtq_api_session_conn(sess), ds, id, &es),
            WTQ_OK);
        ds->ectx = es;
        uint8_t wire[32];
        size_t pre_len = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI : WTQ_PREAMBLE_KIND_UNI,
            0, wire, sizeof(wire), &pre_len), WTQ_PREAMBLE_OK);
        memcpy(wire + pre_len, "abcde", 5);
        g_pr.pause_open = true;
        g_pr.retain_stream = true;
        g_pr.pause_result = WTQ_ERR_STATE;
        uint32_t payload = bare ? 0 : 5;
        uint64_t accepted = recv_deliver_bytes(ds, wire,
                                                (uint32_t)pre_len + payload, true);
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
        WTQ_TEST_CHECK_EQ_INT(g_pr.pause_result, WTQ_OK);
        WTQ_TEST_CHECK_EQ_U64(accepted, pre_len);
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 0);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
        if (!bare)
            WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, wire + pre_len, payload, true), payload);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, payload);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.buf_len, payload);
        WTQ_TEST_CHECK(memcmp(g_pr.buf, "abcde", payload) == 0);
    }
    if (g_pr.stream != NULL)
        wtq_stream_release(g_pr.stream);
    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

static int test_recv_callback_pause_opened(void)
{
    int failures = test_recv_callback_pause_opened_case(false, false);
    failures += test_recv_callback_pause_opened_case(true, false);
    failures += test_recv_callback_pause_opened_case(false, true);
    failures += test_recv_callback_pause_opened_case(true, true);
    return failures;
}

static int test_recv_callback_quantum(void)
{
    int failures = 0;
    uint8_t payload[65536];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i % 251);
    for (uint32_t n = 65534; n <= 65536; n++) {
        QUIC_API_TABLE api;
        wtq_session_t *sess = NULL;
        struct wtq_driver *drv = pause_estab(&api, &sess);
        WTQ_TEST_CHECK(drv != NULL);
        if (drv == NULL)
            continue;
        struct wtq_dstream *ds = pause_open_wt_uni(drv,
                                                   wtq_api_session_conn(sess), 7);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            g_pr.patterned = true;
            WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, payload, n, true), n);
            WTQ_TEST_CHECK(g_pr.max_payload <= 65535);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, n);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, n > 65535 ? 2 : 1);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bad_bytes, 0);
        }
        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

static int test_recv_quantum_pause_and_empty_tail(void)
{
    int failures = 0;
    uint8_t payload[65536];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i % 251);
    for (int empty_tail = 0; empty_tail < 2; empty_tail++) {
        QUIC_API_TABLE api;
        wtq_session_t *sess = NULL;
        struct wtq_driver *drv = pause_estab(&api, &sess);
        WTQ_TEST_CHECK(drv != NULL);
        if (drv == NULL)
            continue;
        g_pr.retain_stream = true;
        g_pr.patterned = true;
        g_pr.pause_at_call = 1;
        struct wtq_dstream *ds = pause_open_wt_uni(drv,
            wtq_api_session_conn(sess), 7);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds != NULL) {
            QUIC_BUFFER buffers[] = {
                { .Length = empty_tail ? 5 : 65536, .Buffer = payload },
                { .Length = 0, .Buffer = NULL },
            };
            QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_RECEIVE };
            ev.RECEIVE.TotalBufferLength = buffers[0].Length;
            ev.RECEIVE.Buffers = buffers;
            ev.RECEIVE.BufferCount = empty_tail ? 2 : 1;
            ev.RECEIVE.Flags = QUIC_RECEIVE_FLAG_FIN;
            (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
            size_t prefix = empty_tail ? 5 : 65535;
            WTQ_TEST_CHECK_EQ_U64(ev.RECEIVE.TotalBufferLength, prefix);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, prefix);
            WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
            WTQ_TEST_CHECK_EQ_INT(g_pr.pause_result, WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
            if (!empty_tail)
                WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds,
                    payload + prefix, 1, true), 1);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, buffers[0].Length);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bad_bytes, 0);
        }
        if (g_pr.stream != NULL)
            wtq_stream_release(g_pr.stream);
        wtq_session_release(sess);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

static int test_recv_legacy_and_accounted_contracts(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab(&api, &sess);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    wtq_conn_t *ec = wtq_api_session_conn(sess);
    struct wtq_dstream *ds = pause_open_wt_uni(drv, ec, 7);
    WTQ_TEST_CHECK(ds != NULL);
    if (ds != NULL) {
        static const uint8_t payload[65536] = { 0 };
        g_rse_fail = 1;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(g_pr.stream), WTQ_ERR_BACKEND);
        size_t consumed = 123;
        wtq_api_session_enter(sess);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(ec, ds->ectx,
            payload, 1, false, 0, &consumed), WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 1);
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
        g_pr.data_calls = 0;
        g_rse_fail = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(g_pr.stream), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes(ec, ds->ectx,
            payload, sizeof(payload), false, 0), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.max_payload, sizeof(payload));
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(ec, ds->ectx,
            payload, sizeof(payload), true, 0, &consumed), WTQ_ERR_WOULD_BLOCK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 1);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        g_rse_fail = 1;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_ERR_BACKEND);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(ec, ds->ectx,
            NULL, 0, true, 0, &consumed), WTQ_ERR_WOULD_BLOCK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        g_rse_fail = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
        g_pr.max_payload = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(ec, ds->ectx,
            payload, sizeof(payload), true, 0, &consumed), WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, sizeof(payload));
        WTQ_TEST_CHECK_EQ_INT(g_pr.data_calls, 3);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.max_payload, 65535);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(ec, NULL,
            payload, sizeof(payload), true, 0, &consumed), WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
        (void)wtq_api_session_leave(sess);
    }
    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

static size_t stream_record_count(struct wtq_driver *drv)
{
    size_t n = 0;
    for (struct wtq_dstream *ds = drv->streams; ds != NULL; ds = ds->next)
        n++;
    return n;
}

static void lifetime_poll(struct wtq_driver *drv)
{
    QUIC_CONNECTION_EVENT ev = { .Type = QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE };
    (void)wtq_msq_conn_callback(NULL, drv, &ev);
}

static struct {
    size_t live;
    size_t records;
    size_t peak_records;
    size_t allocated_records;
    size_t frees;
    size_t forbidden_frees;
    int borrowing;
    int closes;
    struct wtq_driver *drv;
    bool nested_close;
    bool nested_api;
    void *send_context;
    bool fail_send;
    bool sync_send;
    struct wtq_dstream *sending;
} lifetime;

static void *lifetime_alloc(size_t n, void *ctx)
{
    (void)ctx;
    void *p = malloc(n);
    if (p != NULL) {
        lifetime.live++;
        if (n == sizeof(struct wtq_dstream)) {
            lifetime.records++;
            lifetime.allocated_records++;
            if (lifetime.records > lifetime.peak_records)
                lifetime.peak_records = lifetime.records;
        }
    }
    return p;
}

static void lifetime_free(void *p, size_t n, void *ctx)
{
    (void)ctx;
    if (n == sizeof(struct wtq_dstream)) {
        lifetime.records--;
        lifetime.frees++;
        if (lifetime.borrowing)
            lifetime.forbidden_frees++;
    }
    lifetime.live--;
    free(p);
}

static void QUIC_API lifetime_close(HQUIC h)
{
    (void)h;
    lifetime.closes++;
    if (lifetime.nested_close) {
        lifetime.borrowing++;
        lifetime_poll(lifetime.drv);
        lifetime.borrowing--;
    }
}

static QUIC_STATUS QUIC_API lifetime_enable(HQUIC h, BOOLEAN enabled)
{
    (void)h; (void)enabled;
    if (lifetime.nested_api) {
        lifetime.borrowing++;
        lifetime_poll(lifetime.drv);
        lifetime.borrowing--;
    }
    return QUIC_STATUS_SUCCESS;
}

static void QUIC_API lifetime_conn_shutdown(HQUIC h,
    QUIC_CONNECTION_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    (void)h; (void)flags; (void)code;
    lifetime.borrowing++;
    lifetime_poll(lifetime.drv);
    lifetime.borrowing--;
}

static QUIC_STATUS QUIC_API lifetime_send(HQUIC h, const QUIC_BUFFER *bufs,
    uint32_t count, QUIC_SEND_FLAGS flags, void *ctx)
{
    (void)h; (void)bufs; (void)count; (void)flags;
    if (lifetime.fail_send)
        return QUIC_STATUS_INVALID_STATE;
    lifetime.send_context = ctx;
    if (lifetime.sync_send) {
        lifetime.borrowing++;
        QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE };
        (void)wtq_msq_stream_callback(h, lifetime.sending, &ev);
        ev.Type = QUIC_STREAM_EVENT_SEND_COMPLETE;
        ev.SEND_COMPLETE.ClientContext = ctx;
        ev.SEND_COMPLETE.Canceled = TRUE;
        (void)wtq_msq_stream_callback(h, lifetime.sending, &ev);
        lifetime_poll(lifetime.drv);
        lifetime.borrowing--;
    }
    return QUIC_STATUS_SUCCESS;
}

static void lifetime_shutdown(struct wtq_dstream *ds)
{
    QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE };
    (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
}

static int test_stream_record_lifetime(void)
{
    int failures = 0;
    memset(&lifetime, 0, sizeof(lifetime));
    wtq_alloc_t alloc = { .alloc = lifetime_alloc, .free = lifetime_free };
    QUIC_API_TABLE api = { .StreamClose = lifetime_close,
        .StreamReceiveSetEnabled = lifetime_enable, .StreamSend = lifetime_send,
        .ConnectionShutdown = lifetime_conn_shutdown };
    struct wtq_driver *drv = wtq_msq_conn_new(&alloc, &api, true);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    lifetime.drv = drv;
    int native_handle;
    wtq_estream_t *key = (wtq_estream_t *)(void *)drv;
    for (int order = 0; order < 2; order++) {
        struct wtq_dstream *ds = wtq_msq_stream_new(drv, false, false, 7);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds == NULL)
            break;
        ds->stream = (HQUIC)(void *)&native_handle; /* deliberately reused */
        ds->ectx = key;
        if (order == 0)
            OPS()->detach(drv, ds, key);
        else
            lifetime_shutdown(ds);
        lifetime_poll(drv);
        WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1);
        if (order == 0) {
            lifetime.nested_close = true;
            lifetime_shutdown(ds);
            lifetime.nested_close = false;
        } else {
            OPS()->detach(drv, ds, (wtq_estream_t *)(void *)&native_handle);
            lifetime_poll(drv);
            WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1);
            OPS()->detach(drv, ds, key);
        }
        WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1); /* defer past this frame */
        lifetime_poll(drv);
        WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 0);
    }
    /* No engine owner (refused stream); nested provider callbacks during a
     * separate API call must not reap this retired record either. */
    struct wtq_dstream *refused = wtq_msq_stream_new(drv, false, false, 11);
    refused->stream = (HQUIC)(void *)&native_handle;
    lifetime_shutdown(refused);
    struct wtq_dstream *live = wtq_msq_stream_new(drv, false, false, 15);
    live->stream = (HQUIC)(void *)&native_handle;
    lifetime.nested_api = true;
    WTQ_TEST_CHECK_EQ_INT(OPS()->recv_enable(drv, live, false), WTQ_OK);
    lifetime.nested_api = false;
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 2);
    lifetime_poll(drv);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1);
    lifetime_shutdown(live);
    lifetime_poll(drv);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 0);

    /* Outstanding zero-byte gather and copied sends are lifetime references,
     * not an inflight-byte count. Hold completion past terminal synthetically. */
    for (int gather = 0; gather < 2; gather++) {
        struct wtq_dstream *ds = wtq_msq_stream_new(drv, true, false, 2);
        ds->stream = (HQUIC)(void *)&native_handle;
        static const uint8_t byte = 0;
        wtq_span_t span = { .data = &byte, .len = 0 };
        int cookie;
        WTQ_TEST_CHECK_EQ_INT(gather ? OPS()->send_gather(drv, ds, &span, 1,
            true, &cookie) : OPS()->send(drv, ds, &byte, 1, true), WTQ_OK);
        lifetime_shutdown(ds);
        lifetime_poll(drv);
        WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1);
        QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_SEND_COMPLETE };
        ev.SEND_COMPLETE.ClientContext = lifetime.send_context;
        ev.SEND_COMPLETE.Canceled = TRUE;
        drv->shutdown_when_flushed = true;
        (void)wtq_msq_stream_callback(NULL, ds, &ev);
        drv->shutdown_when_flushed = false;
        drv->shutdown_started = false;
        lifetime_poll(drv);
        WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 0);
    }
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.forbidden_frees, 0);
    WTQ_TEST_CHECK_EQ_INT(lifetime.closes, 6);
    for (int gather = 0; gather < 2; gather++) {
        for (int fail = 0; fail < 2; fail++) {
            struct wtq_dstream *ds = wtq_msq_stream_new(drv, true, false, 2);
            ds->stream = (HQUIC)(void *)&native_handle;
            lifetime.sending = ds;
            lifetime.sync_send = !fail;
            lifetime.fail_send = fail;
            static const uint8_t byte = 0;
            wtq_span_t span = { .data = &byte, .len = 0 };
            int cookie;
            WTQ_TEST_CHECK_EQ_INT(gather ? OPS()->send_gather(drv, ds, &span,
                1, true, &cookie) : OPS()->send(drv, ds, &byte, 1, true),
                fail ? WTQ_ERR_BACKEND : WTQ_OK);
            WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 1);
            WTQ_TEST_CHECK_EQ_INT(drv->pending_sends, 0);
            WTQ_TEST_CHECK_EQ_U64(ds->inflight_bytes, 0);
            lifetime.sync_send = false;
            lifetime.fail_send = false;
            if (fail)
                lifetime_shutdown(ds);
            lifetime_poll(drv);
            WTQ_TEST_CHECK_EQ_SIZE(lifetime.records, 0);
        }
    }
    /* The final sweep owns a still-live record, and Close may call back
     * synchronously while the sweep is unlinking/freeing its list. */
    struct wtq_dstream *swept = wtq_msq_stream_new(drv, false, false, 19);
    swept->stream = (HQUIC)(void *)&native_handle;
    lifetime.nested_close = true;
    wtq_msq_conn_free(drv);
    lifetime.nested_close = false;
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.live, 0);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.forbidden_frees, 0);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.frees, lifetime.allocated_records);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.frees, 11);
    return failures;
}

static int test_stream_record_churn(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    memset(&lifetime, 0, sizeof(lifetime));
    wtq_alloc_t alloc = { .alloc = lifetime_alloc, .free = lifetime_free };
    struct wtq_driver *drv = pause_estab_with_alloc(&api, &sess, &alloc);
    WTQ_TEST_CHECK(drv != NULL);
    if (drv == NULL)
        return failures;
    size_t baseline = stream_record_count(drv);
    size_t peak = baseline;
    for (uint64_t i = 0; i < 1000; i++) {
        struct wtq_dstream *ds = pause_open_wt_uni(drv,
            wtq_api_session_conn(sess), 7 + 4 * i);
        WTQ_TEST_CHECK(ds != NULL);
        if (ds == NULL)
            break;
        const uint8_t byte = 42;
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, &byte, 1, true), 1);
        lifetime_shutdown(ds);
        size_t count = stream_record_count(drv);
        if (count > peak)
            peak = count;
    }
    WTQ_TEST_CHECK(peak <= baseline + 1);
    WTQ_TEST_CHECK(lifetime.peak_records <= baseline + 2);
    printf("record churn: completed=1000 baseline=%zu post_callback_peak=%zu "
           "allocation_peak=%zu\n", baseline, peak, lifetime.peak_records);
    WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 1000);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1000);
    lifetime_poll(drv);
    WTQ_TEST_CHECK_EQ_SIZE(stream_record_count(drv), baseline);
    wtq_session_release(sess);
    drv->conn = NULL;
    drv->session = NULL;
    wtq_msq_conn_free(drv);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.live, 0);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.frees, lifetime.allocated_records);
    return failures;
}

static HQUIC admission_credit_handle;
static int admission_credit_closes;
static void QUIC_API admission_close(HQUIC handle)
{
    if (handle == admission_credit_handle) admission_credit_closes++;
}

static int test_bounded_admission_borrow_and_credit(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
    WTQ_TEST_CHECK(drv != NULL);
    if (!drv) return failures;
    size_t quantum = 0;
    wtq_receive_pause_mode_t mode = WTQ_RECEIVE_PAUSE_UNSUPPORTED;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(sess, &quantum, &mode), WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(quantum, 65535);
    wtq_stream_t *locals[12] = { 0 };
    for (size_t i = 0; i < 12; ++i) {
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
        wtq_stream_add_ref(locals[i]);
    }
    complete_all_sends();
    g_ord.n = 0;
    QUIC_CONNECTION_EVENT start = { .Type = QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED };
    start.PEER_STREAM_STARTED.Stream = (HQUIC)(void *)&start;
    start.PEER_STREAM_STARTED.Flags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    g_peer_id = 7;
    (void)wtq_msq_conn_callback(NULL, drv, &start);
    WTQ_TEST_CHECK(start.PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES);
    struct wtq_dstream *ds = g_ord.call[0].ctx;
    WTQ_TEST_CHECK(ds != NULL && ds->pooled);
    const uint8_t bytes[] = { 0x40, 0x54, 0, 'a', 'b' };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, bytes, sizeof(bytes), true), 3);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    WTQ_TEST_CHECK(ds->admission.es == NULL && ds->recv_held_data);
    admission_borrow.drv = drv;
    admission_borrow.active = true;
    admission_borrow.endpoint_depth = 1;
    admission_borrow.unsafe_publications = 0;
    admission_borrow.probes = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[0], 0), WTQ_OK);
    locals[0] = NULL; /* terminal callback released the app lease */
    WTQ_TEST_CHECK_EQ_INT(admission_borrow.probes, 1);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0); /* public API exit is not a root */
    WTQ_TEST_CHECK_EQ_INT(admission_borrow.unsafe_publications, 0);
    admission_borrow.endpoint_depth = 0;
    admission_borrow.active = false;
    g_pr.retain_stream = true;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
    WTQ_TEST_CHECK_EQ_INT(admission_borrow.unsafe_publications, 0);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, bytes + 3, 2, true), 2);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
    WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 2);
    admission_credit_handle = ds->stream;
    admission_credit_closes = 0;
    api.StreamClose = admission_close;
    QUIC_STREAM_EVENT done = { .Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE };
    (void)wtq_msq_stream_callback(ds->stream, ds, &done);
    WTQ_TEST_CHECK_EQ_INT(admission_credit_closes, 0);
    WTQ_TEST_CHECK(ds->occupied && ds->credit_held);
    wtq_stream_release(g_pr.stream);
    WTQ_TEST_CHECK_EQ_INT(admission_credit_closes, 0); /* last release only marks */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(admission_credit_closes, 1);
    WTQ_TEST_CHECK(!ds->occupied);
    for (size_t i = 1; i < 12; ++i) wtq_stream_release(locals[i]);
    wtq_api_session_admission_detach(sess);
    wtq_session_release(sess);
    drv->session = NULL;
    drv->conn = NULL;
    wtq_msq_conn_free(drv);
    memset(&admission_borrow, 0, sizeof(admission_borrow));
    return failures;
}

static int test_bounded_handle_debt(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
    WTQ_TEST_CHECK(drv != NULL);
    if (!drv) return failures;
    wtq_stream_t *held[16] = { 0 };
    for (size_t i = 0; i < 16; ++i) {
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &held[i]), WTQ_OK);
        wtq_stream_add_ref(held[i]);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(held[i], NULL, 0, WTQ_SEND_FIN, NULL), WTQ_OK);
        complete_all_sends();
    }
    uint64_t local_count = drv->local_uni_count;
    wtq_stream_t *extra = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &extra), WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK(extra == NULL);
    WTQ_TEST_CHECK_EQ_U64(drv->local_uni_count, local_count);
    struct wtq_dstream *queued[2];
    const uint8_t prefix[] = { 0x40, 0x54, 0 };
    for (unsigned i = 0; i < 2; ++i) {
        g_ord.n = 0;
        feed_peer_stream_started(drv, (HQUIC)(void *)&queued[i], false, 7u + 4u * i);
        queued[i] = g_ord.call[0].ctx;
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(queued[i], prefix, sizeof(prefix), true), 3);
        WTQ_TEST_CHECK(queued[i]->fin_pending && queued[i]->admission.es == NULL);
    }
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    /* A prefix-only FIN may complete the native stream before an API slot
     * exists. Native shutdown must not retire this unpublished FIN debt. */
    lifetime_shutdown(queued[0]);
    lifetime_shutdown(queued[1]);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK(queued[0]->occupied && queued[1]->occupied);
    int native_enables = g_rse_calls;
    g_rse_fail = 1; /* a native-terminal handle cannot be enabled again */
    wtq_stream_release(held[0]); held[0] = NULL;
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    g_pr.retain_stream = true;
    g_pr.pause_open = true;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
    g_pr.pause_open = false;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1); /* terminal held lease still consumes API slot */
    wtq_stream_release(g_pr.stream);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 2);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 2); /* no new RECEIVE/packet was delivered */
    WTQ_TEST_CHECK_EQ_INT(g_rse_calls, native_enables);
    g_rse_fail = 0;
    wtq_stream_release(g_pr.stream);
    for (size_t i = 1; i < 16; ++i) wtq_stream_release(held[i]);
    wtq_api_session_admission_detach(sess);
    wtq_session_release(sess);
    drv->session = NULL; drv->conn = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

static struct {
    struct wtq_driver *drv;
    wtq_stream_t *lease;
    struct wtq_dstream *created;
    int failures;
} admission_nested;

static void admission_create_nested(wtq_session_t *sess)
{
    int failures = 0;
    g_pr.opened_hook = NULL;
    wtq_stream_release(admission_nested.lease);
    g_ord.n = 0;
    feed_peer_stream_started(admission_nested.drv,
        (HQUIC)(void *)&admission_nested, false, 15);
    admission_nested.created = g_ord.call[0].ctx;
    const uint8_t prefix[] = { 0x40, 0x54, 0 };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(admission_nested.created,
        prefix, sizeof(prefix), true), 3);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
    admission_nested.failures += failures;
}

static int test_bounded_snapshot_continuation(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
    WTQ_TEST_CHECK(drv != NULL);
    if (!drv) return failures;
    wtq_stream_t *held[16] = { 0 };
    for (size_t i = 0; i < 16; ++i) {
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &held[i]), WTQ_OK);
        wtq_stream_add_ref(held[i]);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(held[i], NULL, 0, WTQ_SEND_FIN, NULL), WTQ_OK);
        complete_all_sends();
    }
    struct wtq_dstream *peers[2];
    for (unsigned i = 0; i < 2; ++i) {
        g_ord.n = 0;
        feed_peer_stream_started(drv, (HQUIC)(void *)&peers[i], false, 7u + 4u * i);
        peers[i] = g_ord.call[0].ctx;
    }
    const uint8_t incomplete[] = { 0xc0 };
    const uint8_t prefix[] = { 0x40, 0x54, 0 };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(peers[0], incomplete, 1, false), 1);
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(peers[1], prefix, sizeof(prefix), true), 3);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    wtq_stream_release(held[0]); held[0] = NULL;
    admission_nested.drv = drv;
    admission_nested.lease = held[1]; held[1] = NULL;
    admission_nested.failures = 0;
    g_pr.opened_hook = admission_create_nested;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    failures += admission_nested.failures;
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
    WTQ_TEST_CHECK(peers[0]->admission.es == NULL);
    WTQ_TEST_CHECK(admission_nested.created->admission.state == 1);
    /* The adapter coalesces this later explicit pass; no new packet is needed. */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 2);
    WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 2);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 2);
    for (size_t i = 2; i < 16; ++i) wtq_stream_release(held[i]);
    wtq_api_session_admission_detach(sess);
    wtq_session_release(sess);
    drv->session = NULL; drv->conn = NULL;
    wtq_msq_conn_free(drv);
    memset(&admission_nested, 0, sizeof(admission_nested));
    return failures;
}

static int test_bounded_resident_reuse(void)
{
    int failures = 0;
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
    WTQ_TEST_CHECK(drv != NULL);
    if (!drv) return failures;
    struct wtq_dstream *peers[7];
    for (unsigned i = 0; i < 7; ++i) {
        g_ord.n = 0;
        feed_peer_stream_started(drv, (HQUIC)(void *)&peers[i], true, 1u + 4u * i);
        peers[i] = g_ord.call[0].ctx;
        const uint8_t prefix = 0xc0;
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(peers[i], &prefix, 1, false), 1);
        WTQ_TEST_CHECK_EQ_INT(peers[i]->admission.reservation, 8 + i);
    }
    uint64_t generation = peers[1]->generation;
    QUIC_STREAM_EVENT reset = { .Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED };
    (void)wtq_msq_stream_callback(peers[1]->stream, peers[1], &reset);
    lifetime_shutdown(peers[1]);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
    WTQ_TEST_CHECK(!peers[1]->occupied);
    g_ord.n = 0;
    feed_peer_stream_started(drv, (HQUIC)(void *)&peers, true, 29);
    struct wtq_dstream *replacement = g_ord.call[0].ctx;
    WTQ_TEST_CHECK(replacement == peers[1] && replacement != peers[0]);
    WTQ_TEST_CHECK(replacement->generation != generation);
    WTQ_TEST_CHECK_EQ_INT(replacement->admission.reservation, 9);
    WTQ_TEST_CHECK_EQ_U64(peers[0]->id, 1);
    WTQ_TEST_CHECK_EQ_INT(peers[0]->admission.fill, 1);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    wtq_api_session_admission_detach(sess);
    wtq_session_release(sess);
    drv->session = NULL; drv->conn = NULL;
    wtq_msq_conn_free(drv);
    return failures;
}

static int test_bounded_queued_terminals(void)
{
    int failures = 0;
    for (unsigned order = 0; order < 2; ++order) {
        QUIC_API_TABLE api;
        wtq_session_t *sess = NULL;
        struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
        WTQ_TEST_CHECK(drv != NULL);
        if (!drv) return failures;
        wtq_stream_t *locals[12] = { 0 };
        for (size_t i = 0; i < 12; ++i)
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
        complete_all_sends();
        g_ord.n = 0;
        feed_peer_stream_started(drv, (HQUIC)(void *)&locals, true, 1);
        struct wtq_dstream *ds = g_ord.call[0].ctx;
        const uint8_t prefix[] = { 0x40, 0x41, 0 };
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, prefix, sizeof(prefix), false), 3);
        for (unsigned i = 0; i < 2; ++i) {
            QUIC_STREAM_EVENT terminal = { .Type = i == order
                ? QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                : QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED };
            if (i == order) terminal.PEER_SEND_ABORTED.ErrorCode = wtq_app_error_to_h3(131);
            else terminal.PEER_RECEIVE_ABORTED.ErrorCode = wtq_app_error_to_h3(241);
            (void)wtq_msq_stream_callback(ds->stream, ds, &terminal);
        }
        lifetime_shutdown(ds);
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
        WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[0], 0), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
        WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, order == 0 ? 12 : 21);
        WTQ_TEST_CHECK_EQ_INT(g_pr.reset_code, 131);
        WTQ_TEST_CHECK_EQ_INT(g_pr.stop_code, 241);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        wtq_api_session_admission_detach(sess);
        wtq_session_release(sess);
        drv->session = NULL; drv->conn = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

static void admission_poison_free(void *p, size_t n, void *ctx)
{
    memset(p, 0xdd, n);
    lifetime_free(p, n, ctx);
}

static int test_bounded_final_shutdown(void)
{
    int failures = 0;
    memset(&lifetime, 0, sizeof(lifetime));
    const wtq_alloc_t alloc = { .alloc = lifetime_alloc, .free = admission_poison_free };
    QUIC_API_TABLE api;
    wtq_session_t *sess = NULL;
    struct wtq_driver *drv = pause_estab_mode(&api, &sess, &alloc, true);
    WTQ_TEST_CHECK(drv != NULL);
    if (!drv) return failures;
    wtq_session_add_ref(sess); /* keep the public certificate after backend free */
    wtq_stream_t *locals[12] = { 0 };
    for (size_t i = 0; i < 12; ++i) {
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
        wtq_stream_add_ref(locals[i]);
    }
    complete_all_sends();
    g_ord.n = 0;
    feed_peer_stream_started(drv, (HQUIC)(void *)&locals, false, 7);
    struct wtq_dstream *ds = g_ord.call[0].ctx;
    const uint8_t prefix[] = { 0x40, 0x54, 0 };
    WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, prefix, sizeof(prefix), true), 3);
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    QUIC_CONNECTION_EVENT done = { .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE };
    done.SHUTDOWN_COMPLETE.AppCloseInProgress = TRUE;
    (void)wtq_msq_conn_callback(NULL, drv, &done); /* poisons and frees drv */
    WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
    size_t quantum = 0;
    wtq_receive_pause_mode_t mode = WTQ_RECEIVE_PAUSE_UNSUPPORTED;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(sess, &quantum, &mode), WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(quantum, 65535);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_ERR_CLOSED);
    for (size_t i = 0; i < 12; ++i) wtq_stream_release(locals[i]);
    wtq_session_release(sess);
    WTQ_TEST_CHECK_EQ_SIZE(lifetime.live, 0);
    return failures;
}

static unsigned admission_enable_attempts;
static QUIC_STATUS QUIC_API admission_counted_enable(HQUIC h, BOOLEAN enabled)
{
    admission_enable_attempts++;
    return rec_recv_set_enabled(h, enabled);
}

static int test_admission_resume_failure(void)
{
    int failures = 0;
    for (unsigned root = 0; root < 5; ++root) {
        QUIC_API_TABLE api;
        wtq_session_t *sess = NULL;
        struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
        WTQ_TEST_CHECK(drv != NULL);
        if (!drv) return failures;
        wtq_stream_t *locals[12] = { 0 };
        for (size_t i = 0; i < 12; ++i)
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
        complete_all_sends();
        g_ord.n = 0;
        feed_peer_stream_started(drv, (HQUIC)(void *)&locals, false, 7);
        struct wtq_dstream *ds = g_ord.call[0].ctx;
        const uint8_t wire[] = { 0x40, 0x54, 0, 'x', 'y' };
        WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, wire, sizeof(wire), true), 3);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[0], 0), WTQ_OK);
        api.StreamReceiveSetEnabled = admission_counted_enable;
        admission_enable_attempts = 0;
        g_rse_fail = 2;
        if (root == 0 || root >= 3) {
            QUIC_CONNECTION_EVENT ev = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
            (void)wtq_msq_conn_callback(NULL, drv, &ev);
        } else if (root == 1) {
            QUIC_STREAM_EVENT ev = { .Type = QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE };
            (void)wtq_msq_stream_callback(ds->stream, ds, &ev);
        } else {
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_ERR_BACKEND);
        }
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
        WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 1);
        WTQ_TEST_CHECK(ds->recv_held_data && !drv->shutdown_started);
        WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 0);
        WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
        if (root == 4) {
            unsigned closed = g_pr.closed_calls;
            QUIC_STREAM_EVENT reset = { .Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED };
            reset.PEER_SEND_ABORTED.ErrorCode = wtq_app_error_to_h3(131);
            (void)wtq_msq_stream_callback(ds->stream, ds, &reset);
            (void)wtq_msq_stream_callback(ds->stream, ds, &reset);
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.closed_calls, closed + 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.reset_code, 131);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 0);
        } else {
            if (root == 3) {
                g_rse_fail = 0;
                WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(g_pr.stream), WTQ_OK);
                WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
                WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 2);
                WTQ_TEST_CHECK(ds->recv_disabled && ds->recv_held_data);
                WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(g_pr.stream), WTQ_OK);
            } else {
                WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_ERR_BACKEND);
                WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 2);
                WTQ_TEST_CHECK(ds->recv_held_data);
                WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            }
            WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 3);
            WTQ_TEST_CHECK(!ds->recv_held_data && !drv->shutdown_started);
            WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
            /* Native redelivery of the original buffer, not fresh network input. */
            WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, wire + 3, 2, true), 2);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 2);
            WTQ_TEST_CHECK(g_pr.buf_len == 2 && memcmp(g_pr.buf, "xy", 2) == 0);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 1);
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 3);
            WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
        }
        wtq_api_session_admission_detach(sess);
        wtq_session_release(sess);
        drv->session = NULL; drv->conn = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

static int test_admission_bidi_reset(void)
{
    int failures = 0;
    for (unsigned deferred = 0; deferred < 2; ++deferred) {
        for (unsigned root = 0; root < 3; ++root) {
            QUIC_API_TABLE api;
            wtq_session_t *sess = NULL;
            struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
            WTQ_TEST_CHECK(drv != NULL);
            if (!drv) return failures;
            wtq_stream_t *locals[12] = { 0 };
            for (size_t i = 0; i < 12; ++i)
                WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
            complete_all_sends();
            g_ord.n = 0;
            feed_peer_stream_started(drv, (HQUIC)(void *)&locals, true, 1);
            struct wtq_dstream *ds = g_ord.call[0].ctx;
            /* The send recorder uses its fake native handle as callback ctx. */
            ds->stream = (HQUIC)(void *)ds;
            const uint8_t wire[] = { 0x40, 0x41, 0, 'x', 'y' };
            WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(ds, wire, sizeof(wire), true), 3);
            api.StreamReceiveSetEnabled = admission_counted_enable;
            admission_enable_attempts = 0;
            g_rse_fail = 100;
            QUIC_STREAM_EVENT reset = { .Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED };
            reset.PEER_SEND_ABORTED.ErrorCode = wtq_app_error_to_h3(131);
            if (deferred) {
                (void)wtq_msq_stream_callback(ds->stream, ds, &reset);
                WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 0);
                WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, 0);
            }
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[0], 0), WTQ_OK);
            unsigned closed = g_pr.closed_calls;
            QUIC_CONNECTION_EVENT conn_ev = { .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED };
            QUIC_STREAM_EVENT stream_ev = { .Type = QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE };
            if (root == 0)
                (void)wtq_msq_conn_callback(NULL, drv, &conn_ev);
            else if (root == 1)
                (void)wtq_msq_stream_callback(ds->stream, ds, &stream_ev);
            else
                WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess),
                    deferred ? WTQ_OK : WTQ_ERR_BACKEND);
            WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
            if (!deferred) {
                WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, 1);
                WTQ_TEST_CHECK(ds->recv_held_data && ds->admission_resume_pending);
                (void)wtq_msq_stream_callback(ds->stream, ds, &reset);
            }
            /* RESET ends receive only; all safe roots must now be quiescent. */
            (void)wtq_msq_conn_callback(NULL, drv, &conn_ev);
            (void)wtq_msq_stream_callback(ds->stream, ds, &stream_ev);
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, deferred ? 0 : 1);
            WTQ_TEST_CHECK(!ds->admission_resume_pending && !ds->recv_held_data &&
                !ds->fin_pending && !ds->recv_disabled);
            WTQ_TEST_CHECK(ds->ectx != NULL && !drv->shutdown_started);
            WTQ_TEST_CHECK_EQ_INT(g_pr.closed_calls, closed);
            WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.reset_code, 131);
            WTQ_TEST_CHECK_EQ_SIZE(g_pr.bytes, 0);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
            const uint8_t reply[] = { 'o', 'k' };
            wtq_span_t span = { .data = reply, .len = sizeof(reply) };
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(g_pr.stream, &span, 1, 0, NULL), WTQ_OK);
            complete_all_sends();
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(admission_enable_attempts, deferred ? 0 : 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.closed_calls, closed);
            WTQ_TEST_CHECK_EQ_INT(g_pr.terminal_order, 1);
            WTQ_TEST_CHECK_EQ_INT(g_pr.fin_calls, 0);
            wtq_api_session_admission_detach(sess);
            wtq_session_release(sess);
            drv->session = NULL; drv->conn = NULL;
            wtq_msq_conn_free(drv);
        }
    }
    return failures;
}

static int test_admission_fifo(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 4; ++row) {
        QUIC_API_TABLE api;
        wtq_session_t *sess = NULL;
        struct wtq_driver *drv = pause_estab_mode(&api, &sess, wtq_alloc_default(), true);
        WTQ_TEST_CHECK(drv != NULL);
        if (!drv) return failures;
        wtq_stream_t *locals[12] = { 0 };
        for (size_t i = 0; i < 12; ++i)
            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(sess, &locals[i]), WTQ_OK);
        complete_all_sends();
        struct wtq_dstream *peers[2];
        const bool bidi[2] = { row == 1, row >= 2 };
        uint64_t ids[2] = { bidi[0] ? 1u : 7u, bidi[1] ? 1u : 11u };
        for (unsigned i = 0; i < 2; ++i) {
            g_ord.n = 0;
            feed_peer_stream_started(drv, (HQUIC)(void *)&peers[i], bidi[i], ids[i]);
            peers[i] = g_ord.call[0].ctx;
        }
        if (row == 0) {
            QUIC_STREAM_EVENT reset = { .Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED };
            (void)wtq_msq_stream_callback(peers[0]->stream, peers[0], &reset);
            lifetime_shutdown(peers[0]);
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
            g_ord.n = 0;
            feed_peer_stream_started(drv, (HQUIC)(void *)&peers[0], false, 15);
            peers[0] = g_ord.call[0].ctx;
            ids[0] = 15;
        }
        unsigned first = row == 0 || row == 3 ? 1u : 0u;
        for (unsigned n = 0; n < 2; ++n) {
            unsigned i = n == 0 ? first : 1u - first;
            const uint8_t wire[] = { 0x40, bidi[i] ? 0x41 : 0x54, 0 };
            WTQ_TEST_CHECK_EQ_U64(recv_deliver_bytes(peers[i], wire, sizeof(wire), false), 3);
        }
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[0], 0), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 1);
        WTQ_TEST_CHECK_EQ_U64(wtq_stream_id(g_pr.stream), ids[first]);
        WTQ_TEST_CHECK_EQ_INT(wtq_stream_abort(locals[1], 0), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(sess), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(g_pr.opened, 2);
        WTQ_TEST_CHECK_EQ_U64(wtq_stream_id(g_pr.stream), ids[1u - first]);
        wtq_api_session_admission_detach(sess);
        wtq_session_release(sess);
        drv->session = NULL; drv->conn = NULL;
        wtq_msq_conn_free(drv);
    }
    return failures;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--admission-bidi-reset") == 0)
        return test_admission_bidi_reset();
    if (argc == 2 && strcmp(argv[1], "--admission-resume-failure") == 0)
        return test_admission_resume_failure();
    if (argc == 2 && strcmp(argv[1], "--admission-fifo") == 0)
        return test_admission_fifo();
    if (argc == 2 && strcmp(argv[1], "--bounded-admission") == 0)
        return test_bounded_admission_borrow_and_credit() + test_bounded_handle_debt() +
            test_bounded_snapshot_continuation() + test_bounded_resident_reuse() +
            test_bounded_final_shutdown() + test_bounded_queued_terminals();
    if (argc == 2 && strcmp(argv[1], "--record-lifetime") == 0)
        return test_stream_record_lifetime();
    if (argc == 2 && strcmp(argv[1], "--record-churn") == 0)
        return test_stream_record_churn();
    if (argc == 2 && strcmp(argv[1], "--admission-multibuffer") == 0)
        return test_recv_callback_pause_multibuffer();
    if (argc == 2 && strcmp(argv[1], "--admission-opened") == 0)
        return test_recv_callback_pause_opened();
    if (argc == 2 && strcmp(argv[1], "--admission-quantum") == 0)
        return test_recv_callback_quantum();
    bool baseline = argc == 2 && strcmp(argv[1], "--baseline") == 0;
    int failures = 0;
    failures += test_peer_stream_started_handler_before_shutdown();
    failures += test_peer_stream_started_accepted();
    test_tuning_stream_credits(&failures);

    failures += test_dgram_len_sum_overflow();
    failures += test_recv_enable_dead_stream();
    failures += test_gather_budget_is_depth_not_size();
    failures += test_writable_arming();
    failures += test_transport_error_population();
    failures += test_local_shutdown_no_initiated_event();
    failures += test_env_close_classification();
    failures += test_engine_fatal_precedence();
    failures += test_first_causal_survives_later_events();
    failures += test_env_close_exact_code();
    failures += test_stream_id_mismatch_detail();
    failures += test_cleanup_preserves_sealed_none();

    failures += test_recv_pause_arrest();
    failures += test_recv_pause_failure();
    failures += test_recv_resume_failure();
    failures += test_recv_reset_while_paused();
    failures += test_recv_established_isolation_redelivery();
    failures += test_recv_fin_deferred_while_paused();
    failures += test_settings_non_multi_receive();
    if (!baseline) {
        failures += test_recv_callback_pause_multibuffer();
        failures += test_recv_callback_pause_opened();
        failures += test_recv_callback_quantum();
        failures += test_recv_legacy_and_accounted_contracts();
        failures += test_recv_quantum_pause_and_empty_tail();
        failures += test_stream_record_lifetime();
        failures += test_stream_record_churn();
        failures += test_bounded_admission_borrow_and_credit();
        failures += test_bounded_handle_debt();
        failures += test_bounded_snapshot_continuation();
        failures += test_bounded_resident_reuse();
        failures += test_bounded_final_shutdown();
        failures += test_bounded_queued_terminals();
        failures += test_admission_resume_failure();
        failures += test_admission_bidi_reset();
        failures += test_admission_fifo();
    }

    WTQ_TEST_PASS("msquic_ops");
    return failures;
}
