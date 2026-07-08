#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"
#include "proto/varint.h"

#include "test_support.h"

/*
 * WT datagrams: RFC 9297 quarter-stream-id association, spec-backed
 * rejection behavior, size accounting, zero-copy receive, zero-alloc
 * both directions. Plus the draft-15 s4 session-id validity rule
 * (session ids MUST be client-initiated bidi stream ids) on streams.
 */

typedef struct app_state {
    int established_events;
    int error_events;
    uint64_t last_error;
    int closed_events;
    int wt_opened_events;

    int dgram_events;
    const uint8_t *dgram_ptr; /* pointer identity: passthrough proof */
    size_t dgram_len;
    uint8_t dgram_bytes[64];
} app_state_t;

static void cb_error(wtq_conn_t *c, uint64_t e, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->error_events++;
    st->last_error = e;
}

static void cb_established(wtq_conn_t *c, const char *sel, size_t len,
                           void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)sel;
    (void)len;
    st->established_events++;
}

static void cb_closed(wtq_conn_t *c, uint32_t code, const uint8_t *reason,
                      size_t reason_len, bool clean, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)code;
    (void)reason;
    (void)reason_len;
    (void)clean;
    st->closed_events++;
}

static void cb_wt_opened(wtq_conn_t *c, wtq_estream_t *es, bool bidi,
                         uint64_t id, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)es;
    (void)bidi;
    (void)id;
    st->wt_opened_events++;
}

static void cb_dgram(wtq_conn_t *c, const uint8_t *data, size_t len,
                     void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->dgram_events++;
    st->dgram_ptr = data;
    st->dgram_len = len;
    if (len > 0 && len <= sizeof(st->dgram_bytes))
        memcpy(st->dgram_bytes, data, len);
}

typedef struct counting_alloc {
    int allocs;
    int frees;
} counting_alloc_t;

static void *count_alloc(size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    ca->allocs++;
    return malloc(size);
}

static void count_free(void *ptr, size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    (void)size;
    ca->frees++;
    free(ptr);
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    app_state_t app;
    wtq_estream_t *sess_es;
    struct wtq_dstream *sess_ds;
    counting_alloc_t ca;
    wtq_alloc_t alloc;
} rig_t;

static void rig_up(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    memset(&r->ca, 0, sizeof(r->ca));
    r->alloc = (wtq_alloc_t){ &r->ca, count_alloc, NULL, count_free };
    r->sess_es = NULL;
    r->sess_ds = NULL;
    fake_driver_init(&r->drv, persp == WTQ_PERSPECTIVE_CLIENT);

    wtq_conn_cfg_t cfg = {
        .alloc = &r->alloc,
        .perspective = persp,
        .enable_connect_protocol = true,
        .callbacks = { .on_conn_error = cb_error,
                       .on_session_established = cb_established,
                       .on_session_closed = cb_closed,
                       .on_wt_stream_opened = cb_wt_opened,
                       .on_wt_datagram = cb_dgram,
                       .ctx = &r->app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r->drv, fake_driver_ops(),
                                   &r->conn) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r->conn, 1000) == WTQ_OK);
    *fp += failures;
}

static void rig_down(rig_t *r, int *fp)
{
    int failures = 0;

    wtq_conn_destroy(r->conn);
    WTQ_TEST_CHECK(r->ca.allocs == r->ca.frees);
    *fp += failures;
}

static void deliver_peer_settings(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;

    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    bool is_client = (r->drv.is_client);
    struct wtq_dstream *ds =
        fake_driver_add_peer_stream(&r->drv, is_client ? 3 : 2);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, ds,
                                               is_client ? 3 : 2, &es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r->conn, es, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);
    *fp += failures;
}

static struct wtq_dstream *find_local_bidi(rig_t *r)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            return &r->drv.streams[i];
    return NULL;
}

static const char *const OFFER[] = { "moqt-18" };

static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[256];
    size_t slen = 0;
    wtq_sf_str_t sel = { proto, proto ? strlen(proto) : 0 };

    if (wtq_connect_encode_response(status, proto ? &sel : NULL, section,
                                    sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

static size_t build_request(uint8_t *dst, size_t cap, const char *path)
{
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t offer[1] = { { "moqt-18", 7 } };

    if (wtq_connect_encode_request("example.com", 11, path, strlen(path),
                                   NULL, 0, offer, 1, section,
                                   sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

static void establish_client(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_client_connect_cfg_t ccfg = {
        "example.com", "/moq", NULL, OFFER, 1, false, 0,
    };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r->conn, &ccfg) == WTQ_OK);
    deliver_peer_settings(r, fp);
    r->sess_ds = find_local_bidi(r);
    WTQ_TEST_CHECK(r->sess_ds != NULL && r->sess_ds->ectx != NULL);
    if (r->sess_ds == NULL) {
        *fp += failures;
        return;
    }
    r->sess_es = r->sess_ds->ectx;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
    (void)wtq_conn_on_stream_bytes(r->conn, r->sess_es, resp, rlen, false,
                                   2000);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    *fp += failures;
}

/* Server whose session rides request stream id (default 0). */
static void establish_server_sid(rig_t *r, uint64_t sid, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_SERVER, fp);
    wtq_server_path_cfg_t path = { "/moq", OFFER, 1, false };
    WTQ_TEST_CHECK(wtq_conn_server_set_paths(r->conn, &path, 1) ==
                   WTQ_OK);
    deliver_peer_settings(r, fp);
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq");
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, sid);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r->conn, ds, sid, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r->conn, es, req, qlen, false, 2000);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    r->sess_es = es;
    r->sess_ds = ds;
    *fp += failures;
}

/* --- send path ---------------------------------------------------------- */

/* The wire is qsid varint + the spans, byte-exact. Session stream 0
 * -> quarter stream id 0 -> one-byte prefix 0x00. */
static void test_dgram_send_basic(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    static const uint8_t a[3] = { 'd', 'g', '1' };
    static const uint8_t b[2] = { '!', '?' };
    wtq_span_t spans[2] = { { a, 3 }, { b, 2 } };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, spans, 2) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgram_count, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgrams[0].len, 6);
    WTQ_TEST_CHECK(memcmp(r.drv.dgrams[0].bytes, "\x00" "dg1!?", 6) == 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* A session on stream id 4 has quarter stream id 1. */
static void test_dgram_send_nonzero_sid(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server_sid(&r, 4, fp);
    WTQ_TEST_CHECK(wtq_conn_session_id(r.conn) == 4);
    static const uint8_t p[2] = { 'h', 'i' };
    wtq_span_t span = { p, 2 };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgram_count, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgrams[0].len, 3);
    WTQ_TEST_CHECK(memcmp(r.drv.dgrams[0].bytes, "\x01hi", 3) == 0);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_dgram_send_errors(int *fp)
{
    int failures = 0;

    /* before establishment: state error */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        static const uint8_t p[1] = { 1 };
        wtq_span_t span = { p, 1 };
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                       WTQ_ERR_STATE);
        rig_down(&r, fp);
    }
    /* after termination: draft-15 s6 MUST NOT send */
    {
        rig_t r;
        establish_client(&r, fp);
        WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) ==
                       WTQ_OK);
        static const uint8_t p[1] = { 1 };
        wtq_span_t span = { p, 1 };
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                       WTQ_ERR_CLOSED);
        rig_down(&r, fp);
    }
    /* transport without datagram capacity */
    {
        rig_t r;
        establish_client(&r, fp);
        r.drv.dgram_max = 0;
        static const uint8_t p[1] = { 1 };
        wtq_span_t span = { p, 1 };
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                       WTQ_ERR_DGRAM_DISABLED);
        rig_down(&r, fp);
    }
    /* transport queue full: WOULD_BLOCK passthrough */
    {
        rig_t r;
        establish_client(&r, fp);
        r.drv.fail_dgram = true;
        static const uint8_t p[1] = { 1 };
        wtq_span_t span = { p, 1 };
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                       WTQ_ERR_WOULD_BLOCK);
        rig_down(&r, fp);
    }
    /* too many spans */
    {
        rig_t r;
        establish_client(&r, fp);
        static const uint8_t p[1] = { 1 };
        wtq_span_t spans[WTQ_DGRAM_MAX_SPANS + 1];
        for (size_t i = 0; i < WTQ_DGRAM_MAX_SPANS + 1; i++)
            spans[i] = (wtq_span_t){ p, 1 };
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, spans,
                                           WTQ_DGRAM_MAX_SPANS + 1) ==
                       WTQ_ERR_INVALID_ARG);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* Max payload = transport max minus the encoded prefix; the boundary
 * sends, one past it does not. */
static void test_dgram_max_size(int *fp)
{
    int failures = 0;
    rig_t r;

    /* not established yet: 0 */
    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK_EQ_SIZE(wtq_conn_dgram_max_size(r.conn), 0);
    rig_down(&r, fp);

    establish_client(&r, fp); /* qsid 0: one-byte prefix */
    WTQ_TEST_CHECK_EQ_SIZE(wtq_conn_dgram_max_size(r.conn), 1199);

    static uint8_t big[1200];
    wtq_span_t span = { big, 1199 };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) == WTQ_OK);
    span.len = 1200;
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                   WTQ_ERR_TOO_LARGE);

    /* transport reports no capacity: 0 */
    r.drv.dgram_max = 0;
    WTQ_TEST_CHECK_EQ_SIZE(wtq_conn_dgram_max_size(r.conn), 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* A hostile span list whose lengths wrap size_t must be rejected
 * before the backend is ever called. */
static void test_dgram_send_overflow(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    static const uint8_t p[1] = { 1 };
    wtq_span_t spans[3] = {
        { p, SIZE_MAX - 1 },
        { p, 2 }, /* wraps the sum to 0 */
        { p, 1 },
    };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, spans, 3) ==
                   WTQ_ERR_TOO_LARGE);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgram_count, 0); /* backend untouched */
    rig_down(&r, fp);
    *fp += failures;
}

/* transport max == prefix length: the only legal payload is empty —
 * receive already accepts empty WT datagrams, so send must too. */
static void test_dgram_send_empty_at_boundary(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp); /* qsid 0: one-byte prefix */
    r.drv.dgram_max = 1;
    WTQ_TEST_CHECK_EQ_SIZE(wtq_conn_dgram_max_size(r.conn), 0);
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgram_count, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgrams[0].len, 1);
    WTQ_TEST_CHECK(r.drv.dgrams[0].bytes[0] == 0x00);

    static const uint8_t p[1] = { 1 };
    wtq_span_t span = { p, 1 };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) ==
                   WTQ_ERR_TOO_LARGE);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- receive path ------------------------------------------------------- */

/* Payload is a pointer into the received buffer (zero copy), prefix
 * stripped; empty payloads are legal. */
static void test_dgram_recv_basic(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t dg[4] = { 0x00, 'y', 'o', '!' };
    WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 4, 3000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.dgram_len, 3);
    WTQ_TEST_CHECK(memcmp(r.app.dgram_bytes, "yo!", 3) == 0);
    WTQ_TEST_CHECK(r.app.dgram_ptr == dg + 1); /* zero copy */

    uint8_t empty[1] = { 0x00 };
    WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, empty, 1, 3100) ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 2);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.dgram_len, 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* A non-minimal (but valid) qsid encoding of the session still
 * matches — varints are varints (RFC 9000 s16 note). */
static void test_dgram_recv_nonminimal_qsid(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t dg[3] = { 0x40, 0x00, 'x' }; /* 2-byte encoding of 0 */
    WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 3, 3000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.dgram_len, 1);
    WTQ_TEST_CHECK(r.app.dgram_ptr == dg + 2);
    rig_down(&r, fp);
    *fp += failures;
}

/* Datagrams for a session we don't know: counted and dropped, never
 * fatal (draft-15 s4.6 / RFC 9297 s2.1 drop-or-buffer; we buffer 0). */
static void test_dgram_recv_unknown_session(int *fp)
{
    int failures = 0;

    /* wrong qsid on an active session */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t dg[3] = { 0x01, 'n', 'o' }; /* qsid 1 != 0 */
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 3, 3000) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 0);
        WTQ_TEST_CHECK(wtq_conn_dgrams_dropped(r.conn) == 1);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r, fp);
    }
    /* before establishment */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        deliver_peer_settings(&r, fp);
        uint8_t dg[2] = { 0x00, 'x' };
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 2, 3000) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 0);
        WTQ_TEST_CHECK(wtq_conn_dgrams_dropped(r.conn) == 1);
        rig_down(&r, fp);
    }
    /* after termination (s6: data for closed sessions is discarded) */
    {
        rig_t r;
        establish_client(&r, fp);
        WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) ==
                       WTQ_OK);
        uint8_t dg[2] = { 0x00, 'x' };
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 2, 3000) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 0);
        WTQ_TEST_CHECK(wtq_conn_dgrams_dropped(r.conn) == 1);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* A datagram whose payload cannot carry a complete qsid varint is a
 * connection error (RFC 9297 s2.1: H3_DATAGRAM_ERROR). */
static void test_dgram_recv_malformed(int *fp)
{
    int failures = 0;

    /* empty datagram: no varint at all */
    {
        rig_t r;
        establish_client(&r, fp);
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, NULL, 0, 3000) ==
                       WTQ_ERR_PROTO);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_DATAGRAM_ERROR);
        rig_down(&r, fp);
    }
    /* truncated varint: first byte declares 2, only 1 present */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t dg[1] = { 0x40 };
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 1, 3000) ==
                       WTQ_ERR_PROTO);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_DATAGRAM_ERROR);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* DRAIN is advisory: datagrams keep flowing both ways. */
static void test_dgram_during_drain(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* receive DRAIN on the session stream */
    uint8_t cap_buf[8];
    size_t clen = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf),
                                            &clen) == 0);
    uint8_t wire[16];
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, clen,
                                              wire, sizeof(wire),
                                              &hl) == 0);
    memcpy(wire + hl, cap_buf, clen);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, hl + clen,
                                   false, 3000);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                   WTQ_SESSION_DRAINING);

    static const uint8_t p[2] = { 'o', 'k' };
    wtq_span_t span = { p, 2 };
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) == WTQ_OK);
    uint8_t dg[2] = { 0x00, 'z' };
    WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 2, 3100) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.dgram_events, 1);
    rig_down(&r, fp);
    *fp += failures;
}

/* Send + receive allocate nothing. */
static void test_dgram_zero_alloc(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    int allocs = r.ca.allocs;
    static const uint8_t p[16] = { 0 };
    wtq_span_t span = { p, 16 };
    uint8_t dg[8] = { 0x00, 1, 2, 3, 4, 5, 6, 7 };
    for (int i = 0; i < 100; i++) {
        r.drv.dgram_count = 0; /* recycle the fake's log */
        WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &span, 1) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_on_datagram(r.conn, dg, 8, 3000 + i) ==
                       WTQ_OK);
    }
    WTQ_TEST_CHECK(r.ca.allocs == allocs);
    WTQ_TEST_CHECK(r.ca.allocs == 1);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- draft-15 s4: session ids MUST be client-initiated bidi ids -------- */

/* A stream preamble whose session id is not a client-initiated bidi
 * stream id (id % 4 != 0) MUST close the connection with H3_ID_ERROR. */
static void test_stream_sid_validity(int *fp)
{
    int failures = 0;

    /* uni preamble, sid 1 (client uni space) */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t pre[8];
        size_t plen = 0;
        WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 1, pre,
                                           sizeof(pre), &plen) == 0);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false,
                                       3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_ID_ERROR);
        rig_down(&r, fp);
    }
    /* bidi preamble, sid 2 (server uni space) */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t pre[8];
        size_t plen = 0;
        WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_BIDI, 2, pre,
                                           sizeof(pre), &plen) == 0);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false,
                                       3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_ID_ERROR);
        rig_down(&r, fp);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_dgram_send_basic(&failures);
    test_dgram_send_nonzero_sid(&failures);
    test_dgram_send_errors(&failures);
    test_dgram_max_size(&failures);
    test_dgram_send_overflow(&failures);
    test_dgram_send_empty_at_boundary(&failures);
    test_dgram_recv_basic(&failures);
    test_dgram_recv_nonminimal_qsid(&failures);
    test_dgram_recv_unknown_session(&failures);
    test_dgram_recv_malformed(&failures);
    test_dgram_during_drain(&failures);
    test_dgram_zero_alloc(&failures);
    test_stream_sid_validity(&failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_engine_dgram (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_engine_dgram\n");
    return 0;
}
