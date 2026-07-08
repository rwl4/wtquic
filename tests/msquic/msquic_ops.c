/*
 * White-box driver-op edge cases: exercises the backend ops directly,
 * below the engine's own argument guards, so the ops' defensive checks
 * are provably load-bearing on their own.
 */

#include <stdint.h>
#include <string.h>

#include "msq_internal.h"

#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

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
                       (void *)wtq_msq_stream_callback);

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

int main(void)
{
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

    WTQ_TEST_PASS("msquic_ops");
    return failures;
}
