#include <stdio.h>
#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/qpack_static.h"
#include "proto/varint.h"

#include "test_support.h"

typedef struct app_state {
    int settings_events;
    int established_events;
    char selected[512];
    size_t selected_len;
    int rejected_events;
    uint16_t rejected_status;
    int failed_events;
    int failed_reason;
    int error_events;
    uint64_t last_error;
    int closed_events;
    bool closed_clean;
} app_state_t;

static void cb_settings(wtq_conn_t *c, bool wt, void *ctx)
{
    (void)c;
    (void)wt;
    ((app_state_t *)ctx)->settings_events++;
}

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
    st->established_events++;
    st->selected_len = len < sizeof(st->selected) ? len : 0;
    if (st->selected_len > 0)
        memcpy(st->selected, sel, st->selected_len);
}

static void cb_rejected(wtq_conn_t *c, uint16_t status, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->rejected_events++;
    st->rejected_status = status;
}

static void cb_failed(wtq_conn_t *c, wtq_session_fail_reason_t r,
                      void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->failed_events++;
    st->failed_reason = (int)r;
}

static void cb_closed(wtq_conn_t *c, uint32_t code, const uint8_t *reason,
                      size_t reason_len, bool clean, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)code;
    (void)reason;
    (void)reason_len;
    st->closed_events++;
    st->closed_clean = clean;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    app_state_t app;
} rig_t;

typedef struct setting_pair {
    uint64_t id;
    uint64_t value;
} setting_pair_t;

static void rig_up(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    fake_driver_init(&r->drv, persp == WTQ_PERSPECTIVE_CLIENT);

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = persp,
        .enable_connect_protocol = true,
        .callbacks = { .on_peer_settings = cb_settings,
                       .on_conn_error = cb_error,
                       .on_session_established = cb_established,
                       .on_session_rejected = cb_rejected,
                       .on_session_failed = cb_failed,
                       .on_session_closed = cb_closed,
                       .ctx = &r->app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r->drv, fake_driver_ops(),
                                   &r->conn) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r->conn, 1000) == WTQ_OK);
    *fp += failures;
}

static void rig_down(rig_t *r)
{
    wtq_conn_destroy(r->conn);
}

static size_t build_settings_frame(uint8_t *dst, size_t cap,
                                   const setting_pair_t *settings,
                                   size_t count)
{
    uint8_t payload[128];
    size_t off = 0;

    for (size_t i = 0; i < count; i++) {
        size_t c = 0;
        if (wtq_varint_encode(settings[i].id, payload + off,
                              sizeof(payload) - off, &c) !=
            WTQ_VARINT_OK)
            return 0;
        off += c;
        if (wtq_varint_encode(settings[i].value, payload + off,
                              sizeof(payload) - off, &c) !=
            WTQ_VARINT_OK)
            return 0;
        off += c;
    }

    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_SETTINGS, off, dst, cap,
                                   &hl) != 0 ||
        cap - hl < off)
        return 0;
    memcpy(dst + hl, payload, off);
    return hl + off;
}

static void deliver_peer_settings_frame(rig_t *r, const uint8_t *frame,
                                        size_t flen, int *fp)
{
    int failures = 0;
    uint8_t buf[128];

    WTQ_TEST_CHECK(flen + 1 <= sizeof(buf));
    if (flen + 1 > sizeof(buf)) {
        *fp += failures;
        return;
    }

    buf[0] = 0x00;
    memcpy(buf + 1, frame, flen);
    bool is_client = (r->drv.is_client);
    struct wtq_dstream *ds =
        fake_driver_add_peer_stream(&r->drv, is_client ? 3 : 2);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, ds,
                                               is_client ? 3 : 2, &es) ==
                   WTQ_OK);
    /* the engine reports WTQ_ERR_PROTO when the SETTINGS kill the
     * connection — the caller asserts the outcome it expects */
    (void)wtq_conn_on_stream_bytes(r->conn, es, buf, 1 + flen, false,
                                   1500);
    *fp += failures;
}

/* Deliver a peer control stream with WT-capable SETTINGS. */
static void deliver_peer_settings(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t frame[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;

    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, frame,
                                                sizeof(frame), &flen) ==
                   WTQ_H3_SETTINGS_OK);
    if (flen > 0)
        deliver_peer_settings_frame(r, frame, flen, fp);
    /* a WT-capable SETTINGS frame must never kill the connection */
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r->conn));
    *fp += failures;
}

static void deliver_peer_settings_pairs(rig_t *r,
                                        const setting_pair_t *settings,
                                        size_t count, int *fp)
{
    int failures = 0;
    uint8_t frame[128];
    size_t flen = build_settings_frame(frame, sizeof(frame), settings,
                                       count);

    WTQ_TEST_CHECK(flen > 0);
    if (flen > 0)
        deliver_peer_settings_frame(r, frame, flen, fp);
    *fp += failures;
}

/* Find the client's local bidi stream (the CONNECT stream), if any. */
static struct wtq_dstream *find_local_bidi(rig_t *r)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            return &r->drv.streams[i];
    return NULL;
}

static const char *const OFFER[] = { "moqt-18", "moqt-16" };

static wtq_result_t do_connect(rig_t *r, bool require)
{
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, require, 0 };
    return wtq_conn_client_connect(r->conn, &cfg);
}

/* #6: the WebTransport profile is LATCHED at client_connect, committed
 * BEFORE the control-stream SETTINGS are emitted at start, and a
 * non-default profile requested after start is WTQ_ERR_STATE. */
static bool ctrl_contains(const struct wtq_dstream *ctrl,
                          const uint8_t *pat, size_t plen)
{
    if (ctrl == NULL || ctrl->len < plen)
        return false;
    for (size_t i = 0; i + plen <= ctrl->len; i++)
        if (memcmp(ctrl->bytes + i, pat, plen) == 0)
            return true;
    return false;
}

static void test_profile_latch(int *fp)
{
    int failures = 0;
    /* WT_ENABLED (0x2c7cf000) and WT_MAX_SESSIONS (0x14e9cd29) wire ids. */
    static const uint8_t WT_ENABLED_ID[] = { 0xac, 0x7c, 0xf0, 0x00 };
    static const uint8_t WT_MAXSESS_ID[] = { 0x94, 0xe9, 0xcd, 0x29 };

    /* (a) PRE-START compat connect (production order): latched, and the
     * emitted SETTINGS carry WT_MAX_SESSIONS, not WT_ENABLED. */
    {
        rig_t r;
        memset(&r.app, 0, sizeof(r.app));
        fake_driver_init(&r.drv, true);
        wtq_conn_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .enable_connect_protocol = true,
            .callbacks = { .ctx = &r.app },
        };
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r.drv, fake_driver_ops(),
                                       &r.conn) == WTQ_OK);
        wtq_client_connect_cfg_t cc = {
            "example.com", "/moq", NULL, OFFER, 2, false,
            (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cc) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_start(r.conn, 1000) == WTQ_OK);
        const struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        WTQ_TEST_CHECK(ctrl_contains(ctrl, WT_MAXSESS_ID,
                                     sizeof(WT_MAXSESS_ID)));
        WTQ_TEST_CHECK(!ctrl_contains(ctrl, WT_ENABLED_ID,
                                      sizeof(WT_ENABLED_ID)));
        rig_down(&r);
    }

    /* (b) default (current) client: SETTINGS carry WT_ENABLED only. */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        const struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        WTQ_TEST_CHECK(ctrl_contains(ctrl, WT_ENABLED_ID,
                                     sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_contains(ctrl, WT_MAXSESS_ID,
                                      sizeof(WT_MAXSESS_ID)));
        /* (c) POST-START: a compat connect is WTQ_ERR_STATE (SETTINGS
         * already out as current); a current connect still proceeds. */
        wtq_client_connect_cfg_t compat = {
            "example.com", "/moq", NULL, OFFER, 2, false,
            (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &compat) ==
                       WTQ_ERR_STATE);
        /* zero effect: a current-profile connect afterwards still works */
        WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
        rig_down(&r);
    }

    /* (d) an out-of-range profile value is WTQ_ERR_INVALID_ARG. */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_client_connect_cfg_t bad = {
            "example.com", "/moq", NULL, OFFER, 2, false, 99 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &bad) ==
                       WTQ_ERR_INVALID_ARG);
        rig_down(&r);
    }

    /* (e) ZERO EFFECT on preflight failure: a compat connect whose offer
     * fails DURING preflight (a malformed sf-string) must not commit the
     * compat profile — a later valid CURRENT connect + start must emit
     * WT_ENABLED, never WT_MAX_SESSIONS. (Pre-start order so SETTINGS
     * reflect the committed profile.) */
    {
        rig_t r;
        memset(&r.app, 0, sizeof(r.app));
        fake_driver_init(&r.drv, true);
        wtq_conn_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .enable_connect_protocol = true,
            .callbacks = { .ctx = &r.app },
        };
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r.drv, fake_driver_ops(),
                                       &r.conn) == WTQ_OK);
        /* a control char is not a valid Structured-Fields string, so
         * this fails in protocol_check (preflight), after the latch. */
        static const char *const BAD_OFFER[] = { "\x01" "bad" };
        wtq_client_connect_cfg_t poison = {
            "example.com", "/moq", NULL, BAD_OFFER, 1, false,
            (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &poison) ==
                       WTQ_ERR_INVALID_ARG);
        /* start DIRECTLY after the failed compat connect (no intervening
         * valid connect to overwrite a poisoned profile): SETTINGS must
         * be the default CURRENT profile, never the failed request's
         * compat WT_MAX_SESSIONS. */
        WTQ_TEST_CHECK(wtq_conn_start(r.conn, 1000) == WTQ_OK);
        const struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        WTQ_TEST_CHECK(ctrl_contains(ctrl, WT_ENABLED_ID,
                                     sizeof(WT_ENABLED_ID)));
        WTQ_TEST_CHECK(!ctrl_contains(ctrl, WT_MAXSESS_ID,
                                      sizeof(WT_MAXSESS_ID)));
        rig_down(&r);
    }

    *fp += failures;
}

/* Build a response field section wrapped in a HEADERS frame. */
static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[512];
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

/* Feed response bytes back to the client's CONNECT stream in chunks. */
static void feed_response(rig_t *r, const uint8_t *bytes, size_t len,
                          size_t chunk, int *fp)
{
    int failures = 0;
    struct wtq_dstream *bidi = find_local_bidi(r);

    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    if (bidi == NULL || bidi->ectx == NULL) {
        *fp += failures;
        return;
    }
    size_t off = 0;
    while (off < len) {
        size_t nn = len - off < chunk ? len - off : chunk;
        (void)wtq_conn_on_stream_bytes(r->conn, bidi->ectx, bytes + off,
                                       nn, false, 2500);
        off += nn;
    }
    *fp += failures;
}

/* --- client tests ------------------------------------------------------ */

/* CONNECT is deferred until peer SETTINGS prove WT support */
static void test_connect_deferred(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
    /* no CONNECT bytes may exist yet */
    WTQ_TEST_CHECK(find_local_bidi(&r) == NULL);

    deliver_peer_settings(&r, fp);
    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL);
    WTQ_TEST_CHECK(bidi->len > 0);
    WTQ_TEST_CHECK(bidi->bytes[0] == 0x01); /* HEADERS frame type */

    /* the request decodes as a valid extended CONNECT */
    wtq_h3_frame_t hdr;
    WTQ_TEST_CHECK(wtq_h3_frame_decode_header(bidi->bytes, bidi->len,
                                              &hdr) == 0);
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 0;
    char scratch[512];
    wtq_connect_opts_t opts = { false, false };
    WTQ_TEST_CHECK(wtq_connect_decode_request(
                       bidi->bytes + hdr.header_len, (size_t)hdr.length,
                       &opts, &req, protos, 4, &nproto, scratch,
                       sizeof(scratch)) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 2);

    rig_down(&r);
    *fp += failures;
}

/* peer without WT support: session fails, no stream is opened */
static void test_connect_no_wt(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);

    /* SETTINGS without WT_ENABLED/H3_DATAGRAM: bare legal settings */
    uint8_t buf[64];
    buf[0] = 0x00;
    buf[1] = 0x04; /* SETTINGS frame */
    buf[2] = 0x02; /* len 2 */
    buf[3] = 0x01; /* QPACK_MAX_TABLE_CAPACITY = 0 */
    buf[4] = 0x00;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 3, &es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es, buf, 5, false,
                                            1500) == WTQ_OK);

    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                          WTQ_SESSION_FAIL_NO_WT_SUPPORT);
    WTQ_TEST_CHECK(find_local_bidi(&r) == NULL);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));

    rig_down(&r);
    *fp += failures;
}

/* happy path with negotiation; split across every byte boundary */
static void test_connect_established(int *fp)
{
    int failures = 0;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");

    WTQ_TEST_CHECK(rlen > 0);
    for (size_t chunk = 1; chunk <= rlen; chunk++) {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, true) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        feed_response(&r, resp, rlen, chunk, fp);

        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
        WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, 7);
        WTQ_TEST_CHECK(memcmp(r.app.selected, "moqt-18", 7) == 0);
        size_t sl = 0;
        const char *sel = wtq_conn_selected_protocol(r.conn, &sl);
        WTQ_TEST_CHECK(sl == 7 && memcmp(sel, "moqt-18", 7) == 0);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* 200 without subprotocol: fine when not required */
static void test_connect_no_protocol_ok(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, NULL);

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
    deliver_peer_settings(&r, fp);
    feed_response(&r, resp, rlen, 7, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    size_t sl = 99;
    (void)wtq_conn_selected_protocol(r.conn, &sl);
    WTQ_TEST_CHECK_EQ_SIZE(sl, 0);
    rig_down(&r);
    *fp += failures;
}

/* required protocol missing or unoffered -> NO_PROTOCOL failure */
static void test_connect_protocol_failures(int *fp)
{
    int failures = 0;

    {
        rig_t r;
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 200, NULL);
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, true) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        feed_response(&r, resp, rlen, 5, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                              WTQ_SESSION_FAIL_NO_PROTOCOL);
        rig_down(&r);
    }
    {
        rig_t r;
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 200, "h3-dgram");
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, true) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        feed_response(&r, resp, rlen, 5, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                              WTQ_SESSION_FAIL_NO_PROTOCOL);
        rig_down(&r);
    }
    *fp += failures;
}

/* non-2xx is a clean rejection */
static void test_connect_rejected(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 404, NULL);

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
    deliver_peer_settings(&r, fp);
    feed_response(&r, resp, rlen, 3, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.rejected_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.rejected_status, 404);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* malformed response section -> deterministic failure */
static void test_connect_bad_response(int *fp)
{
    int failures = 0;
    rig_t r;
    /* HEADERS frame whose payload is dynamic-table QPACK garbage */
    const uint8_t resp[] = { 0x01, 0x03, 0x00, 0x00, 0x81 };

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
    deliver_peer_settings(&r, fp);
    feed_response(&r, resp, sizeof(resp), 2, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_MESSAGE_ERROR);
    rig_down(&r);
    *fp += failures;
}

/* frame-sequence violations on the CONNECT stream */
static void test_connect_stream_frames(int *fp)
{
    int failures = 0;

    /* DATA before response HEADERS -> FRAME_UNEXPECTED */
    {
        rig_t r;
        const uint8_t data_first[] = { 0x00, 0x01, 0xAA };
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        feed_response(&r, data_first, sizeof(data_first), 1, fp);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_UNEXPECTED);
        rig_down(&r);
    }
    /* SETTINGS on a request stream -> FRAME_UNEXPECTED */
    {
        rig_t r;
        const uint8_t settings[] = { 0x04, 0x00 };
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        feed_response(&r, settings, sizeof(settings), 1, fp);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_UNEXPECTED);
        rig_down(&r);
    }
    *fp += failures;
}

/* a server-initiated bidi stream that is NOT a WT stream is a
 * connection error at the client. Classification is deferred to the
 * first bytes (a 0x41 WT preamble is the one legal case), so the error
 * fires when the type varint completes on something else. */
static void test_server_bidi_to_client(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    uint8_t headers[2] = { 0x01, 0x00 }; /* an H3 HEADERS frame */
    (void)wtq_conn_on_stream_bytes(r.conn, es, headers, 2, false, 2000);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_STREAM_CREATION_ERROR);
    rig_down(&r);
    *fp += failures;
}

/* --- server tests ------------------------------------------------------ */

static const char *const SUPPORTED[] = { "moqt-16", "moqt-18" };

static void server_paths_up(rig_t *r, bool require, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_SERVER, fp);
    wtq_server_path_cfg_t path = { "/moq", SUPPORTED, 2, require };
    WTQ_TEST_CHECK(wtq_conn_server_set_paths(r->conn, &path, 1) ==
                   WTQ_OK);
    *fp += failures;
}

static void server_up(rig_t *r, bool require, int *fp)
{
    server_paths_up(r, require, fp);
    deliver_peer_settings(r, fp);
}

/* Build a request stream: HEADERS frame around an encoded CONNECT. */
static size_t build_request(uint8_t *dst, size_t cap, const char *path,
                            const char *const *protos, size_t nproto)
{
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t offer[8];

    for (size_t i = 0; i < nproto; i++) {
        offer[i].data = protos[i];
        offer[i].len = strlen(protos[i]);
    }
    if (wtq_connect_encode_request("example.com", 11, path, strlen(path),
                                   NULL, 0, offer, nproto, section,
                                   sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

/* Open a peer bidi request stream and feed it, optionally FIN-ing on
 * the final chunk; the engine stream is reported via es_out for tests
 * that keep feeding the same stream. Returns the peer ds. */
static struct wtq_dstream *feed_request_es(rig_t *r, uint64_t id,
                                           const uint8_t *bytes,
                                           size_t len, size_t chunk,
                                           bool fin,
                                           wtq_estream_t **es_out,
                                           int *fp)
{
    int failures = 0;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, id);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r->conn, ds, id, &es) ==
                   WTQ_OK);
    if (es != NULL) {
        size_t off = 0;
        while (off < len) {
            size_t nn = len - off < chunk ? len - off : chunk;
            (void)wtq_conn_on_stream_bytes(r->conn, es, bytes + off, nn,
                                           fin && off + nn == len, 2500);
            off += nn;
        }
    }
    if (es_out != NULL)
        *es_out = es;
    *fp += failures;
    return ds;
}

/* Open a peer bidi request stream and feed it. Returns the peer ds. */
static struct wtq_dstream *feed_request(rig_t *r, uint64_t id,
                                        const uint8_t *bytes, size_t len,
                                        size_t chunk, int *fp)
{
    return feed_request_es(r, id, bytes, len, chunk, false, NULL, fp);
}

static void expect_response_status(struct wtq_dstream *ds, uint16_t status,
                                   int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK(ds != NULL && ds->len > 0);
    if (ds == NULL || ds->len == 0) {
        *fp += failures;
        return;
    }

    wtq_h3_frame_t hdr;
    int frc = wtq_h3_frame_decode_header(ds->bytes, ds->len, &hdr);
    WTQ_TEST_CHECK(frc == 0);
    if (frc != 0) {
        *fp += failures;
        return;
    }
    WTQ_TEST_CHECK_EQ_U64(hdr.type, WTQ_H3_FRAME_HEADERS);
    WTQ_TEST_CHECK(ds->len >= hdr.header_len + (size_t)hdr.length);
    if (ds->len < hdr.header_len + (size_t)hdr.length) {
        *fp += failures;
        return;
    }

    wtq_connect_resp_t resp;
    char scratch[512];
    wtq_connect_opts_t opts = { false, false };
    wtq_connect_status_t cst = wtq_connect_decode_response(
        ds->bytes + hdr.header_len, (size_t)hdr.length, &opts, &resp,
        scratch, sizeof(scratch));
    WTQ_TEST_CHECK(cst == WTQ_CONNECT_OK);
    if (cst == WTQ_CONNECT_OK)
        WTQ_TEST_CHECK_EQ_INT(resp.status, status);
    *fp += failures;
}

/* server accepts /moq, selects first client-preferred protocol, and
 * responds 200 — across every request chunking */
static void test_server_accept(int *fp)
{
    int failures = 0;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    WTQ_TEST_CHECK(qlen > 0);
    for (size_t chunk = 1; chunk <= qlen; chunk += 3) {
        rig_t r;
        server_up(&r, true, fp);
        struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, chunk,
                                              fp);

        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
        WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));
        /* client preference order: moqt-18 first */
        WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, 7);
        WTQ_TEST_CHECK(memcmp(r.app.selected, "moqt-18", 7) == 0);
        size_t pl = 0;
        const char *p = wtq_conn_request_path(r.conn, &pl);
        WTQ_TEST_CHECK(pl == 4 && memcmp(p, "/moq", 4) == 0);
        const char *a = wtq_conn_request_authority(r.conn, &pl);
        WTQ_TEST_CHECK(pl == 11 && memcmp(a, "example.com", 11) == 0);

        /* a 200 response with wt-protocol went out on the stream */
        WTQ_TEST_CHECK(ds->len > 0);
        wtq_h3_frame_t hdr;
        WTQ_TEST_CHECK(wtq_h3_frame_decode_header(ds->bytes, ds->len,
                                                  &hdr) == 0);
        WTQ_TEST_CHECK_EQ_U64(hdr.type, WTQ_H3_FRAME_HEADERS);
        wtq_connect_resp_t resp;
        char scratch[512];
        wtq_connect_opts_t opts = { false, false };
        WTQ_TEST_CHECK(wtq_connect_decode_response(
                           ds->bytes + hdr.header_len,
                           (size_t)hdr.length, &opts, &resp, scratch,
                           sizeof(scratch)) == WTQ_CONNECT_OK);
        WTQ_TEST_CHECK_EQ_INT(resp.status, 200);
        WTQ_TEST_CHECK(resp.has_protocol);
        rig_down(&r);
    }
    *fp += failures;
}

/* Build a request stream with an EXPLICIT extended-CONNECT :protocol token
 * (webtransport-h3 vs the bare webtransport), to exercise the server's
 * per-profile token acceptance. */
static size_t build_request_token(uint8_t *dst, size_t cap, const char *path,
                                  const char *const *protos, size_t nproto,
                                  const char *token)
{
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t offer[8];

    for (size_t i = 0; i < nproto; i++) {
        offer[i].data = protos[i];
        offer[i].len = strlen(protos[i]);
    }
    if (wtq_connect_encode_request_ex("example.com", 11, path, strlen(path),
                                      NULL, 0, offer, nproto, token,
                                      strlen(token), section,
                                      sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

/* Bring up a SERVER rig latched to a specific WebTransport wire profile,
 * started, with /moq served. */
static void server_up_profile(rig_t *r, int profile, bool require, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    fake_driver_init(&r->drv, false);
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_SERVER,
        .enable_connect_protocol = true,
        .webtransport_profile = profile,
        .callbacks = { .on_peer_settings = cb_settings,
                       .on_conn_error = cb_error,
                       .on_session_established = cb_established,
                       .on_session_rejected = cb_rejected,
                       .on_session_failed = cb_failed,
                       .on_session_closed = cb_closed,
                       .ctx = &r->app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r->drv, fake_driver_ops(),
                                   &r->conn) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_start(r->conn, 1000) == WTQ_OK);
    wtq_server_path_cfg_t path = { "/moq", SUPPORTED, 2, require };
    WTQ_TEST_CHECK(wtq_conn_server_set_paths(r->conn, &path, 1) == WTQ_OK);
    *fp += failures;
}

/*
 * Server profile symmetry: the server latches its listener's profile at
 * create, emits THAT profile's WT SETTINGS (on the deferred open, which the
 * peer's SETTINGS stream triggers BEFORE the CONNECT is processed), and
 * honours ONLY that profile's extended-CONNECT :protocol token. The
 * cross-profile token is answered with a generic 400 — the server never
 * emits one profile's SETTINGS while accepting the other's token.
 */
static void test_server_profile_symmetry(int *fp)
{
    int failures = 0;
    static const uint8_t WT_ENABLED_ID[] = { 0xac, 0x7c, 0xf0, 0x00 };
    static const uint8_t WT_MAXSESS_ID[] = { 0x94, 0xe9, 0xcd, 0x29 };
    /* Peer (client) SETTINGS that satisfy each profile's server-side WT
     * predicate (WT signal + H3_DATAGRAM; ECP is not required of a client). */
    static const setting_pair_t CUR_CLIENT[] = {
        { WTQ_H3_SET_WT_ENABLED, 1 }, { WTQ_H3_SET_H3_DATAGRAM, 1 } };
    static const setting_pair_t CMP_CLIENT[] = {
        { WTQ_H3_SET_WT_MAX_SESSIONS_D13, 1 }, { WTQ_H3_SET_H3_DATAGRAM, 1 } };

    static const struct {
        int profile;
        const setting_pair_t *client;
        const char *token;
        uint16_t status; /* expected response */
        int established;
        bool emits_maxsess; /* server's own SETTINGS carry WT_MAX_SESSIONS */
    } cases[] = {
        /* current server: webtransport-h3 accepted, bare webtransport rejected */
        { (int)WTQ_H3_WT_PROFILE_CURRENT, CUR_CLIENT,
          WTQ_CONNECT_PROTOCOL_TOKEN, 200, 1, false },
        { (int)WTQ_H3_WT_PROFILE_CURRENT, CUR_CLIENT,
          WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY, 400, 0, false },
        /* compat server: bare webtransport accepted, webtransport-h3 rejected */
        { (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, CMP_CLIENT,
          WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY, 200, 1, true },
        { (int)WTQ_H3_WT_PROFILE_D13_14_COMPAT, CMP_CLIENT,
          WTQ_CONNECT_PROTOCOL_TOKEN, 400, 0, true },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        server_up_profile(&r, cases[i].profile, false, fp);
        /* Client SETTINGS arrive first; the deferred open makes the server
         * emit ITS SETTINGS now — before any CONNECT is processed. */
        deliver_peer_settings_pairs(&r, cases[i].client, 2, fp);
        const struct wtq_dstream *ctrl = fake_driver_local(&r.drv, 0);
        WTQ_TEST_CHECK(ctrl != NULL);
        WTQ_TEST_CHECK(ctrl_contains(ctrl, WT_MAXSESS_ID,
                                     sizeof(WT_MAXSESS_ID)) ==
                       cases[i].emits_maxsess);
        WTQ_TEST_CHECK(ctrl_contains(ctrl, WT_ENABLED_ID,
                                     sizeof(WT_ENABLED_ID)) ==
                       !cases[i].emits_maxsess);

        uint8_t req[512];
        size_t qlen = build_request_token(req, sizeof(req), "/moq", OFFER, 2,
                                          cases[i].token);
        WTQ_TEST_CHECK(qlen > 0);
        struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, qlen, fp);
        expect_response_status(ds, cases[i].status, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, cases[i].established);
        rig_down(&r);
    }

    /* An out-of-range server profile fails conn create (mirrors the client
     * range check), before any stream or SETTINGS could be emitted. */
    {
        rig_t r;
        wtq_conn_t *conn = NULL;
        memset(&r.app, 0, sizeof(r.app));
        fake_driver_init(&r.drv, false);
        wtq_conn_cfg_t bad = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_SERVER,
            .enable_connect_protocol = true,
            .webtransport_profile = 99,
            .callbacks = { .ctx = &r.app },
        };
        WTQ_TEST_CHECK(wtq_conn_create(&bad, &r.drv, fake_driver_ops(),
                                       &conn) == WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK(conn == NULL);
    }

    *fp += failures;
}

/* A completed CONNECT before peer SETTINGS is deferred, not answered
 * (draft-15 s3.1: requests must not be processed until the client's
 * SETTINGS arrive) — no response bytes and no policy signal until
 * SETTINGS release it, at which point the normal outcome applies. */
static void test_server_defer_before_settings(int *fp)
{
    int failures = 0;
    static const char *const MISMATCH[] = { "chat" };
    static const struct {
        const char *path;
        const char *const *protos;
        size_t nproto;
        uint16_t status; /* after WT-capable SETTINGS */
    } cases[] = {
        { "/moq", OFFER, 2, 200 },
        { "/nope", OFFER, 2, 404 },
        { "/moq", MISMATCH, 1, 400 }, /* require-protocol mismatch */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        uint8_t req[512];
        size_t qlen = build_request(req, sizeof(req), cases[i].path,
                                    cases[i].protos, cases[i].nproto);

        WTQ_TEST_CHECK(qlen > 0);
        server_paths_up(&r, true, fp);
        struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 11, fp);

        /* parked: nothing sent, nothing decided, connection healthy */
        WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
        WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

        deliver_peer_settings(&r, fp);

        expect_response_status(ds, cases[i].status, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events,
                              cases[i].status == 200 ? 1 : 0);
        WTQ_TEST_CHECK(wtq_conn_session_established(r.conn) ==
                       (cases[i].status == 200));
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

        rig_down(&r);
    }
    *fp += failures;
}

/* deferred request + SETTINGS without WT support -> 400, no session */
static void test_server_defer_nonwt_settings(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    static const setting_pair_t omit_wt[] = {
        { WTQ_H3_SET_QPACK_MAX_TABLE_CAPACITY, 0 },
    };

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 11, fp);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);

    deliver_peer_settings_pairs(&r, omit_wt, 1, fp);

    expect_response_status(ds, 400, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    rig_down(&r);
    *fp += failures;
}

/* FIN right after a deferred CONNECT: on release the request is
 * accepted and the FIN then means what it means post-accept — clean
 * session close (draft-15 s6), exactly one closed callback. */
static void test_server_defer_fin_before_settings(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    struct wtq_dstream *ds =
        feed_request_es(&r, 0, req, qlen, 11, true, NULL, fp);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 0);

    deliver_peer_settings(&r, fp);

    expect_response_status(ds, 200, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_clean);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    rig_down(&r);
    *fp += failures;
}

/* One parked request is the bound: additional pre-SETTINGS CONNECTs
 * get a generic stream refusal — identical whether their path exists
 * or not — and the parked one still resolves normally. */
static void test_server_defer_overbound(int *fp)
{
    int failures = 0;
    static const char *const SECOND[] = { "/moq", "/nope" };

    for (size_t i = 0; i < sizeof(SECOND) / sizeof(SECOND[0]); i++) {
        rig_t r;
        uint8_t req1[512];
        uint8_t req2[512];
        size_t qlen1 = build_request(req1, sizeof(req1), "/moq", OFFER, 2);
        size_t qlen2 =
            build_request(req2, sizeof(req2), SECOND[i], OFFER, 2);

        WTQ_TEST_CHECK(qlen1 > 0 && qlen2 > 0);
        server_paths_up(&r, true, fp);
        struct wtq_dstream *ds1 = feed_request(&r, 0, req1, qlen1, 11, fp);
        struct wtq_dstream *ds2 = feed_request(&r, 4, req2, qlen2, 11, fp);

        /* second: generic stream refusal — no HTTP response may be
         * sent before the client's SETTINGS, and no policy may leak */
        WTQ_TEST_CHECK_EQ_U64(ds2->len, 0);
        WTQ_TEST_CHECK(ds2->reset);
        WTQ_TEST_CHECK(ds2->stopped);
        WTQ_TEST_CHECK_EQ_U64(ds2->reset_err, WTQ_H3_REQUEST_REJECTED);
        /* first: still parked */
        WTQ_TEST_CHECK_EQ_U64(ds1->len, 0);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

        deliver_peer_settings(&r, fp);

        expect_response_status(ds1, 200, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* Peer STOP_SENDING on a parked request stream aborts the response
 * direction: the deferred request can never be answered, so it is
 * cancelled — no response, no establishment at replay — and the slot
 * still leaves room for a fresh CONNECT to establish normally. */
static void test_server_defer_stop_sending_cancels(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    struct wtq_dstream *ds =
        feed_request_es(&r, 0, req, qlen, 11, false, &es, fp);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK(es != NULL);

    /* client aborts the response direction (H3_REQUEST_CANCELLED) */
    WTQ_TEST_CHECK(wtq_conn_on_stop_sending(r.conn, es,
                                            UINT64_C(0x010c),
                                            2600) == WTQ_OK);
    WTQ_TEST_CHECK(ds->reset); /* RESET_STREAM answers STOP_SENDING */
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_REQUEST_REJECTED);

    deliver_peer_settings(&r, fp);

    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    /* a fresh CONNECT still establishes */
    struct wtq_dstream *ds2 = feed_request(&r, 4, req, qlen, 11, fp);
    expect_response_status(ds2, 200, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));

    rig_down(&r);
    *fp += failures;
}

/* Parked CONNECT + FIN, then STOP_SENDING: the request cancels AND the
 * slot comes back — the FIN was already consumed, so no later event
 * can free an absorber. Repetition across the whole pool proves the
 * release; SETTINGS then replay nothing and a fresh CONNECT works. */
static void test_server_defer_fin_stop_released(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    for (uint64_t i = 0; i < 16; i++) {
        wtq_estream_t *es = NULL;
        struct wtq_dstream *ds = feed_request_es(&r, i * 4, req, qlen,
                                                 32, true, &es, fp);
        WTQ_TEST_CHECK(es != NULL); /* the pool must not exhaust */
        if (es == NULL)
            break;
        WTQ_TEST_CHECK(wtq_conn_on_stop_sending(r.conn, es,
                                                UINT64_C(0x010c),
                                                2600) == WTQ_OK);
        WTQ_TEST_CHECK(ds->reset);
        WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    }

    deliver_peer_settings(&r, fp);

    /* none of the cancelled requests replays */
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    struct wtq_dstream *ds2 = feed_request(&r, 200, req, qlen, 11, fp);
    expect_response_status(ds2, 200, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    rig_down(&r);
    *fp += failures;
}

/* Peer RESET_STREAM on a fully parked request: the park dies with the
 * stream, SETTINGS replay nothing, and a fresh CONNECT establishes. */
static void test_server_defer_reset_then_fresh(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    struct wtq_dstream *ds =
        feed_request_es(&r, 0, req, qlen, 11, false, &es, fp);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK(es != NULL);

    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, es,
                                            UINT64_C(0x010c),
                                            2600) == WTQ_OK);

    deliver_peer_settings(&r, fp);

    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    struct wtq_dstream *ds2 = feed_request(&r, 4, req, qlen, 11, fp);
    expect_response_status(ds2, 200, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));

    rig_down(&r);
    *fp += failures;
}

/* DATA on a parked request stream (capsule bytes the engine cannot yet
 * attribute to a session) refuses the stream explicitly — reset+stop,
 * no buffering, no silent skip — without killing the connection. */
static void test_server_defer_data_rejected(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(qlen > 0);
    server_paths_up(&r, true, fp);
    struct wtq_dstream *ds =
        feed_request_es(&r, 0, req, qlen, 11, false, &es, fp);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK(es != NULL);

    uint8_t frame[16];
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, 3, frame,
                                              sizeof(frame), &hl) == 0);
    memcpy(frame + hl, "abc", 3);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es, frame, hl + 3,
                                            false, 2600) == WTQ_OK);

    WTQ_TEST_CHECK(ds->reset);
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_REQUEST_REJECTED);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    deliver_peer_settings(&r, fp);

    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

    rig_down(&r);
    *fp += failures;
}

/* legal SETTINGS that omit or disable WT/H3 datagrams cannot authorize
 * server-side CONNECT acceptance */
static void test_server_reject_without_peer_wt_settings(int *fp)
{
    int failures = 0;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    static const setting_pair_t omit_wt_and_dgram[] = {
        { WTQ_H3_SET_QPACK_MAX_TABLE_CAPACITY, 0 },
    };
    static const setting_pair_t disable_dgram[] = {
        { WTQ_H3_SET_H3_DATAGRAM, 0 },
        { WTQ_H3_SET_WT_ENABLED, 1 },
    };
    static const setting_pair_t disable_wt[] = {
        { WTQ_H3_SET_H3_DATAGRAM, 1 },
        { WTQ_H3_SET_WT_ENABLED, 0 },
    };
    static const struct {
        const setting_pair_t *settings;
        size_t count;
    } cases[] = {
        { omit_wt_and_dgram,
          sizeof(omit_wt_and_dgram) / sizeof(omit_wt_and_dgram[0]) },
        { disable_dgram,
          sizeof(disable_dgram) / sizeof(disable_dgram[0]) },
        { disable_wt, sizeof(disable_wt) / sizeof(disable_wt[0]) },
    };

    WTQ_TEST_CHECK(qlen > 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        server_paths_up(&r, true, fp);
        deliver_peer_settings_pairs(&r, cases[i].settings,
                                    cases[i].count, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
        WTQ_TEST_CHECK(wtq_conn_peer_settings_received(r.conn));
        WTQ_TEST_CHECK(!wtq_conn_peer_supports_wt(r.conn));

        struct wtq_dstream *ds =
            feed_request(&r, 0, req, qlen, 11, fp);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
        WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        expect_response_status(ds, 400, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* Wrap a field list in a HEADERS frame. */
static size_t build_headers(uint8_t *dst, size_t cap,
                            const wtq_qpack_field_t *f, size_t n)
{
    uint8_t section[512];
    size_t slen = 0;

    if (wtq_qpack_encode_section(f, n, section, sizeof(section), &slen) !=
        0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0 ||
        cap - hl < slen)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

/* No session, no metadata, no connection-level error — for any stream
 * the server refused. */
static void expect_no_session_state(rig_t *r, int *fp)
{
    int failures = 0;
    size_t alen = 99;
    size_t plen = 99;

    WTQ_TEST_CHECK_EQ_INT(r->app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r->conn));
    WTQ_TEST_CHECK_EQ_INT(r->app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r->conn));
    (void)wtq_conn_request_authority(r->conn, &alen);
    (void)wtq_conn_request_path(r->conn, &plen);
    WTQ_TEST_CHECK_EQ_SIZE(alen, 0);
    WTQ_TEST_CHECK_EQ_SIZE(plen, 0);
    *fp += failures;
}

/* Feed a valid WT CONNECT on a fresh stream and require establishment —
 * every rejection category must leave the connection fully usable. */
static void expect_fresh_connect_works(rig_t *r, uint64_t id, int *fp)
{
    int failures = 0;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    WTQ_TEST_CHECK(qlen > 0);
    struct wtq_dstream *ds = feed_request(r, id, req, qlen, 16, fp);
    expect_response_status(ds, 200, fp);
    WTQ_TEST_CHECK_EQ_INT(r->app.established_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    *fp += failures;
}

/* A valid HTTP request that is not WebTransport gets one generic 400 —
 * no path or subprotocol policy is consulted or revealed — and the
 * connection stays fully usable. */
static void test_server_non_wt_request(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t GET_F[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false }, /* a CONFIGURED path */
    };
    static const wtq_qpack_field_t TUNNEL_F[] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":authority", 10, "example.com:443", 15, false },
    };
    static const wtq_qpack_field_t WS_F[] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "websocket", 9, false },
    };
    static const struct {
        const wtq_qpack_field_t *f;
        size_t n;
    } cases[] = {
        { GET_F, 4 }, { TUNNEL_F, 2 }, { WS_F, 5 },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        uint8_t req[512];
        size_t qlen = build_headers(req, sizeof(req), cases[i].f,
                                    cases[i].n);

        WTQ_TEST_CHECK(qlen > 0);
        server_up(&r, true, fp); /* require_subprotocol: never consulted */
        struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 7, fp);

        expect_response_status(ds, 400, fp);
        expect_no_session_state(&r, fp);
        expect_fresh_connect_works(&r, 4, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* A malformed request is a STREAM error (RFC 9114 s4.1.2): reset+stop
 * with H3_MESSAGE_ERROR, no response, no connection error. */
static void test_server_malformed_contained(int *fp)
{
    int failures = 0;
    /* HEADERS whose payload is a dynamic-table reference */
    static const uint8_t BAD_QPACK[] = { 0x01, 0x03, 0x00, 0x00, 0x81 };
    static const wtq_qpack_field_t INJECT_F[] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "a\r\nx-evil: 1", 12, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "webtransport-h3", 15, false },
    };
    /* GET with :protocol: structurally invalid, not merely non-WT */
    static const wtq_qpack_field_t BAD_PSEUDO_F[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "webtransport-h3", 15, false },
    };

    for (int which = 0; which < 3; which++) {
        rig_t r;
        uint8_t req[512];
        size_t qlen = 0;

        if (which == 0) {
            memcpy(req, BAD_QPACK, sizeof(BAD_QPACK));
            qlen = sizeof(BAD_QPACK);
        } else if (which == 1) {
            qlen = build_headers(req, sizeof(req), INJECT_F, 5);
        } else {
            qlen = build_headers(req, sizeof(req), BAD_PSEUDO_F, 5);
        }
        WTQ_TEST_CHECK(qlen > 0);

        server_up(&r, false, fp);
        struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 2, fp);

        WTQ_TEST_CHECK(ds->reset);
        WTQ_TEST_CHECK(ds->stopped);
        WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_MESSAGE_ERROR);
        /* request refusal is ONE whole-stream transaction, exact code */
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
        WTQ_TEST_CHECK(ds->last_shutdown.mode ==
                       WTQ_SHUTDOWN_WHOLE_STREAM);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_send &&
                       ds->last_shutdown.abort_recv);
        WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.send_err,
                              WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK_EQ_U64(ds->len, 0); /* no response */
        expect_no_session_state(&r, fp);
        expect_fresh_connect_works(&r, 4, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* A request that fits the frame cap but exhausts the decoder's field
 * capacity is a LOCAL limit, not a peer protocol violation: it gets the
 * same stream-local H3_EXCESSIVE_LOAD as an oversized HEADERS frame. */
static void test_server_decoder_capacity(int *fp)
{
    int failures = 0;
    rig_t r;
    static wtq_qpack_field_t f[WTQ_CONNECT_MAX_FIELDS + 1];
    static char names[WTQ_CONNECT_MAX_FIELDS + 1][8];
    static const wtq_qpack_field_t BASE[] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "webtransport-h3", 15, false },
    };
    size_t n = 5;

    memcpy(f, BASE, sizeof(BASE));
    while (n < WTQ_CONNECT_MAX_FIELDS + 1) {
        snprintf(names[n], sizeof(names[n]), "x-%02zu", n);
        f[n] = (wtq_qpack_field_t){ names[n], strlen(names[n]), "v", 1,
                                    false };
        n++;
    }

    uint8_t req[512];
    size_t qlen = build_headers(req, sizeof(req), f, n);
    WTQ_TEST_CHECK(qlen > 0);
    /* it really does fit inside the engine's HEADERS cap */
    WTQ_TEST_CHECK(qlen <= 512);

    server_up(&r, false, fp);
    struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 32, fp);

    WTQ_TEST_CHECK(ds->reset);
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_EXCESSIVE_LOAD);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    expect_no_session_state(&r, fp);
    expect_fresh_connect_works(&r, 4, fp);
    rig_down(&r);
    *fp += failures;
}

/* An initial HEADERS frame over the local cap is contained to its
 * stream with H3_EXCESSIVE_LOAD, never a connection error. */
static void test_server_oversized_headers(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t frame[16];
    size_t hl = 0;

    /* declare a payload past WTQ_CONN_SETTINGS_CAP (512) */
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, 4096,
                                              frame, sizeof(frame),
                                              &hl) == 0);
    server_up(&r, false, fp);
    struct wtq_dstream *ds = feed_request(&r, 0, frame, hl, 1, fp);

    WTQ_TEST_CHECK(ds->reset);
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_EXCESSIVE_LOAD);
    WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
    expect_no_session_state(&r, fp);
    expect_fresh_connect_works(&r, 4, fp);
    rig_down(&r);
    *fp += failures;
}

/* Bytes queued behind a rejected request — in the same delivery and in
 * a later one — are discarded without applying frame-sequence rules:
 * forbidden frames and trailers can no longer kill the connection. */
static void test_server_dead_stream_discards(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t GET_F[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/x", 2, false },
    };

    for (int later = 0; later < 2; later++) {
        rig_t r;
        uint8_t buf[640];
        size_t qlen = build_headers(buf, sizeof(buf), GET_F, 4);

        WTQ_TEST_CHECK(qlen > 0);
        /* a SETTINGS frame (forbidden on a request stream) plus a
         * second HEADERS (trailers) behind the rejected request */
        size_t off = qlen;
        size_t hl = 0;
        WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_SETTINGS,
                                                  0, buf + off,
                                                  sizeof(buf) - off,
                                                  &hl) == 0);
        off += hl;
        size_t tlen = build_headers(buf + off, sizeof(buf) - off, GET_F,
                                    4);
        WTQ_TEST_CHECK(tlen > 0);
        off += tlen;

        server_up(&r, false, fp);
        wtq_estream_t *es = NULL;
        struct wtq_dstream *ds;
        if (later == 0) {
            /* one delivery carrying request + trailing garbage */
            ds = feed_request_es(&r, 0, buf, off, 512, false, &es, fp);
        } else {
            /* the garbage arrives in a LATER delivery */
            ds = feed_request_es(&r, 0, buf, qlen, 512, false, &es, fp);
            WTQ_TEST_CHECK(es != NULL);
            if (es != NULL)
                WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(
                                   r.conn, es, buf + qlen, off - qlen,
                                   false, 2700) == WTQ_OK);
        }
        expect_response_status(ds, 400, fp);
        expect_no_session_state(&r, fp);
        expect_fresh_connect_works(&r, 4, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* Rejected streams release their engine slot on FIN (and on RESET), so
 * a peer hammering the server with them cannot exhaust the pool. */
static void test_server_rejected_streams_no_slot_leak(int *fp)
{
    int failures = 0;
    rig_t r;
    static const wtq_qpack_field_t GET_F[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/x", 2, false },
    };
    uint8_t req[512];
    size_t qlen = build_headers(req, sizeof(req), GET_F, 4);
    /* HEADERS whose payload is a dynamic-table reference */
    static const uint8_t BAD_QPACK[] = { 0x01, 0x03, 0x00, 0x00, 0x81 };

    WTQ_TEST_CHECK(qlen > 0);
    server_up(&r, false, fp);
    for (uint64_t i = 0; i < 24; i++) {
        wtq_estream_t *es = NULL;
        if (i % 2 == 0) {
            /* non-WT, ended by a clean FIN */
            (void)feed_request_es(&r, i * 4, req, qlen, 64, true, &es,
                                  fp);
        } else {
            /* malformed, ended by a peer RESET */
            (void)feed_request_es(&r, i * 4, BAD_QPACK,
                                  sizeof(BAD_QPACK), 64, false, &es, fp);
            WTQ_TEST_CHECK(es != NULL);
            if (es != NULL)
                (void)wtq_conn_on_stream_reset(r.conn, es,
                                               UINT64_C(0x010c), 2800);
        }
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    }
    expect_no_session_state(&r, fp);
    expect_fresh_connect_works(&r, 500, fp);
    rig_down(&r);
    *fp += failures;
}

/* --- wtq_conn_start is one-shot ----------------------------------------- */

/* Total bytes the engine has written across every fake stream. */
static size_t wire_bytes(const struct wtq_driver *drv)
{
    size_t n = 0;

    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (drv->streams[i].in_use)
            n += drv->streams[i].len;
    return n;
}

/*
 * wtq_conn_start() opens three critical streams and writes their
 * prefaces. A failure at ANY of those six boundaries leaves wire-visible
 * state behind that cannot be rolled back, so the attempt is consumed:
 * the first call returns the driver's error, and every later call
 * returns WTQ_ERR_STATE without touching the driver.
 */
static void test_start_is_one_shot(int *fp)
{
    int failures = 0;
    static const struct {
        const char *what;
        int open_at;  /* 1-based Nth open_uni to fail (0 = none) */
        int send_at;  /* 1-based Nth send to fail (0 = none) */
        wtq_result_t want;
    } cases[] = {
        { "control open", 1, 0, WTQ_ERR_STREAM_LIMIT },
        { "control send", 0, 1, WTQ_ERR_WOULD_BLOCK },
        { "qpack enc open", 2, 0, WTQ_ERR_STREAM_LIMIT },
        { "qpack enc send", 0, 2, WTQ_ERR_WOULD_BLOCK },
        { "qpack dec open", 3, 0, WTQ_ERR_STREAM_LIMIT },
        { "qpack dec send", 0, 3, WTQ_ERR_WOULD_BLOCK },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        int fail2 = 0;

        /* a rig that has NOT been started */
        memset(&r.app, 0, sizeof(r.app));
        fake_driver_init(&r.drv, true);
        r.drv.fail_open_at = cases[i].open_at;
        r.drv.fail_send_at = cases[i].send_at;

        wtq_conn_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .enable_connect_protocol = true,
            .callbacks = { .on_conn_error = cb_error, .ctx = &r.app },
        };
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r.drv, fake_driver_ops(),
                                       &r.conn) == WTQ_OK);

        /* the injected driver error propagates verbatim */
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_start(r.conn, 1000),
                              cases[i].want);

        int opens = r.drv.open_calls;
        int sends = r.drv.send_calls;
        size_t bytes = wire_bytes(&r.drv);
        WTQ_TEST_CHECK(opens > 0);

        /* clear the fault and retry: the attempt was already spent */
        r.drv.fail_open_at = 0;
        r.drv.fail_send_at = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_start(r.conn, 1100),
                              WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_start(r.conn, 1200),
                              WTQ_ERR_STATE);

        /* no driver op ran, so no duplicate stream and no extra byte */
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
        WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
        WTQ_TEST_CHECK_EQ_SIZE(wire_bytes(&r.drv), bytes);
        /* start failure is not a connection error callback */
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);

        wtq_conn_destroy(r.conn);
        *fp += fail2;
    }
    *fp += failures;
}

/* A successful start is unchanged, and a second call still refuses. */
static void test_start_success_retry(int *fp)
{
    int failures = 0;
    rig_t r;

    memset(&r.app, 0, sizeof(r.app));
    fake_driver_init(&r.drv, true);
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .enable_connect_protocol = true,
        .callbacks = { .on_conn_error = cb_error, .ctx = &r.app },
    };
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &r.drv, fake_driver_ops(),
                                   &r.conn) == WTQ_OK);

    WTQ_TEST_CHECK(wtq_conn_start(r.conn, 1000) == WTQ_OK);
    int opens = r.drv.open_calls;
    int sends = r.drv.send_calls;
    size_t bytes = wire_bytes(&r.drv);
    WTQ_TEST_CHECK_EQ_INT(opens, 3); /* control + 2 QPACK */
    WTQ_TEST_CHECK_EQ_INT(sends, 3);

    WTQ_TEST_CHECK_EQ_INT(wtq_conn_start(r.conn, 1100), WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
    WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
    WTQ_TEST_CHECK_EQ_SIZE(wire_bytes(&r.drv), bytes);

    wtq_conn_destroy(r.conn);
    *fp += failures;
}

/* --- peer-stream pool exhaustion ---------------------------------------- */

/* Open peer uni streams until the engine pool is full. Returns how many
 * were accepted. */
static size_t fill_peer_uni(rig_t *r, size_t want, int *fp)
{
    int failures = 0;
    size_t n = 0;

    for (size_t i = 0; i < want; i++) {
        uint64_t id = 3 + 4 * (uint64_t)i;
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, id);
        wtq_estream_t *es = NULL;

        WTQ_TEST_CHECK(ds != NULL);
        if (ds == NULL)
            break;
        if (wtq_conn_on_peer_uni_opened(r->conn, ds, id, &es) != WTQ_OK)
            break;
        WTQ_TEST_CHECK(es != NULL);
        ds->ectx = es;
        n++;
    }
    *fp += failures;
    return n;
}

/* A peer stream the engine cannot hold is REJECTED on the wire with the
 * exact WebTransport codepoint — never accepted and silently drained.
 * Uni gets STOP_SENDING; bidi gets RESET_STREAM and STOP_SENDING. */
static void test_peer_pool_overflow(int *fp)
{
    int failures = 0;

    for (int bidi = 0; bidi < 2; bidi++) {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        size_t got = fill_peer_uni(&r, 64, fp);
        WTQ_TEST_CHECK_EQ_SIZE(got, 16); /* the whole fixed pool */

        struct wtq_dstream *ds =
            fake_driver_add_peer_stream(&r.drv, 1000);
        wtq_estream_t *es = (wtq_estream_t *)(void *)&r; /* poison */
        WTQ_TEST_CHECK(ds != NULL);

        wtq_result_t rc =
            bidi ? wtq_conn_on_peer_bidi_opened(r.conn, ds, 1000, &es)
                 : wtq_conn_on_peer_uni_opened(r.conn, ds, 1000, &es);

        WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_STREAM_LIMIT);
        WTQ_TEST_CHECK(es == NULL);
        WTQ_TEST_CHECK(ds->stopped);
        WTQ_TEST_CHECK_EQ_HEX(ds->stop_err,
                              WTQ_WT_BUFFERED_STREAM_REJECTED);
        if (bidi) {
            WTQ_TEST_CHECK(ds->reset);
            WTQ_TEST_CHECK_EQ_HEX(ds->reset_err,
                                  WTQ_WT_BUFFERED_STREAM_REJECTED);
        } else {
            WTQ_TEST_CHECK(!ds->reset); /* nothing to reset on a uni */
        }
        /* pool rejection is ONE whole-stream transaction, exact code */
        WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
        WTQ_TEST_CHECK(ds->last_shutdown.mode ==
                       WTQ_SHUTDOWN_WHOLE_STREAM);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_recv);
        WTQ_TEST_CHECK(ds->last_shutdown.abort_send == (bidi != 0));
        WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.recv_err,
                              WTQ_WT_BUFFERED_STREAM_REJECTED);
        /* the connection survives and nothing was surfaced */
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        rig_down(&r);
    }
    *fp += failures;
}

/* Fifteen occupied slots still leave the sixteenth for the peer's
 * control stream, so SETTINGS are processed rather than blackholed. */
static void test_pool_leaves_room_for_control(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK_EQ_SIZE(fill_peer_uni(&r, 15, fp), 15);

    deliver_peer_settings(&r, fp); /* takes the 16th slot */
    WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
    WTQ_TEST_CHECK(wtq_conn_peer_settings_received(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* Releasing one slot admits a fresh legitimate stream. */
static void test_pool_release_frees_slot(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK_EQ_SIZE(fill_peer_uni(&r, 16, fp), 16);

    /* the pool is full */
    struct wtq_dstream *full = fake_driver_add_peer_stream(&r.drv, 900);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, full, 900, &es) ==
                   WTQ_ERR_STREAM_LIMIT);

    /* end one of the occupants (bare FIN on an unclassified uni is
     * tolerated and releases its slot) */
    struct wtq_dstream *first = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && !r.drv.streams[i].is_local &&
            r.drv.streams[i].ectx != NULL) {
            first = &r.drv.streams[i];
            break;
        }
    WTQ_TEST_CHECK(first != NULL);
    if (first != NULL)
        WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, first->ectx, NULL,
                                                0, true, 3000) == WTQ_OK);

    /* the freed slot admits a new stream */
    struct wtq_dstream *fresh = fake_driver_add_peer_stream(&r.drv, 904);
    wtq_estream_t *es2 = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, fresh, 904, &es2) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(es2 != NULL);
    WTQ_TEST_CHECK(!fresh->stopped);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* A peer SETTINGS carrying an invalid boolean value (H3_DATAGRAM or
 * ENABLE_CONNECT_PROTOCOL > 1) is a connection error of type
 * H3_SETTINGS_ERROR (RFC 9297 s2.1.1, RFC 8441 s3) — on BOTH
 * perspectives, with no peer-settings callback and nothing established.
 * A parked CONNECT must not replay and must never be answered. */
static void test_invalid_boolean_settings(int *fp)
{
    int failures = 0;
    static const setting_pair_t DGRAM_2[] = {
        { WTQ_H3_SET_H3_DATAGRAM, 2 },
        { WTQ_H3_SET_WT_ENABLED, 1 },
    };
    static const setting_pair_t ECP_2[] = {
        { WTQ_H3_SET_ENABLE_CONNECT_PROTOCOL, 2 },
        { WTQ_H3_SET_H3_DATAGRAM, 1 },
        { WTQ_H3_SET_WT_ENABLED, 1 },
    };
    static const setting_pair_t DGRAM_MAX[] = {
        { WTQ_H3_SET_H3_DATAGRAM, UINT64_C(0x3FFFFFFFFFFFFFFF) },
    };
    static const struct {
        const setting_pair_t *s;
        size_t n;
    } cases[] = {
        { DGRAM_2, 2 }, { ECP_2, 3 }, { DGRAM_MAX, 1 },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* server perspective, with a CONNECT already parked */
        {
            rig_t r;
            uint8_t req[512];
            size_t qlen = build_request(req, sizeof(req), "/moq", OFFER,
                                        2);

            WTQ_TEST_CHECK(qlen > 0);
            server_paths_up(&r, true, fp);
            struct wtq_dstream *ds =
                feed_request(&r, 0, req, qlen, 16, fp);
            WTQ_TEST_CHECK_EQ_U64(ds->len, 0); /* parked */

            deliver_peer_settings_pairs(&r, cases[i].s, cases[i].n, fp);

            WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
            WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                                  WTQ_H3_SETTINGS_ERROR);
            WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 0);
            WTQ_TEST_CHECK(!wtq_conn_peer_settings_received(r.conn));
            WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
            WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
            /* the parked request never replayed, never answered */
            WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
            rig_down(&r);
        }
        /* client perspective */
        {
            rig_t r;

            rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
            wtq_client_connect_cfg_t cfg = {
                "example.com", "/moq", NULL, OFFER, 2, false, 0 };
            WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) ==
                           WTQ_OK);
            deliver_peer_settings_pairs(&r, cases[i].s, cases[i].n, fp);

            WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
            WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                                  WTQ_H3_SETTINGS_ERROR);
            WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 0);
            WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
            /* the deferred CONNECT was never sent */
            WTQ_TEST_CHECK(find_local_bidi(&r) == NULL);
            rig_down(&r);
        }
    }

    /* value 0 and 1 still decode on both settings */
    {
        rig_t r;
        static const setting_pair_t OK_PAIRS[] = {
            { WTQ_H3_SET_ENABLE_CONNECT_PROTOCOL, 0 },
            { WTQ_H3_SET_H3_DATAGRAM, 1 },
            { WTQ_H3_SET_WT_ENABLED, 1 },
        };
        server_paths_up(&r, true, fp);
        deliver_peer_settings_pairs(&r, OK_PAIRS, 3, fp);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.settings_events, 1);
        WTQ_TEST_CHECK(wtq_conn_peer_settings_received(r.conn));
        rig_down(&r);
    }
    *fp += failures;
}

/* --- trailers (RFC 9114 s4.1/s4.3) -------------------------------------- */

/* Establish a server session; hand back its CONNECT stream. */
static void establish_server_session(rig_t *r, wtq_estream_t **es_out,
                                     struct wtq_dstream **ds_out, int *fp)
{
    int failures = 0;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    WTQ_TEST_CHECK(qlen > 0);
    server_up(r, false, fp);
    struct wtq_dstream *ds =
        feed_request_es(r, 0, req, qlen, 16, false, es_out, fp);
    expect_response_status(ds, 200, fp);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    if (ds_out != NULL)
        *ds_out = ds;
    *fp += failures;
}

/* One trailing HEADERS after the initial one is legal, carries only
 * regular fields, and is never surfaced to the application. */
static void test_trailers_valid(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t TRAIL[] = {
        { "x-checksum", 10, "abc123", 6, false },
        { "x-note", 6, "", 0, false }, /* empty value stays legal */
    };

    for (int variant = 0; variant < 3; variant++) {
        rig_t r;
        wtq_estream_t *es = NULL;
        uint8_t buf[512];
        size_t tlen;

        establish_server_session(&r, &es, NULL, fp);
        WTQ_TEST_CHECK(es != NULL);
        if (es == NULL) {
            rig_down(&r);
            continue;
        }
        /* 0 = normal, 1 = EMPTY field section, 2 = fragmented */
        tlen = build_headers(buf, sizeof(buf), TRAIL,
                             variant == 1 ? 0 : 2);
        WTQ_TEST_CHECK(tlen > 0);
        size_t chunk = (variant == 2) ? 1 : tlen;
        for (size_t off = 0; off < tlen; off += chunk) {
            size_t nn = tlen - off < chunk ? tlen - off : chunk;
            WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es,
                                                    buf + off, nn, false,
                                                    3000 + off) ==
                           WTQ_OK);
        }

        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 0);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_ESTABLISHED);
        rig_down(&r);
    }
    *fp += failures;
}

/* Malformed trailers are a STREAM error on the session's CONNECT
 * stream: reset+stop with H3_MESSAGE_ERROR, exactly one UNCLEAN
 * session terminal, the slot released through detachment so no late
 * event can reach it — and never a connection error. */
static void test_trailers_malformed(int *fp)
{
    int failures = 0;
    /* a pseudo-header in trailers (RFC 9114 s4.3) */
    static const wtq_qpack_field_t PSEUDO[] = {
        { ":status", 7, "200", 3, false },
    };
    /* a forbidden octet in a trailer value */
    static const wtq_qpack_field_t BADVAL[] = {
        { "x-t", 3, "a\r\nx: 1", 7, false },
    };
    /* HEADERS payload that is a dynamic-table reference */
    static const uint8_t BAD_QPACK[] = { 0x01, 0x03, 0x00, 0x00, 0x81 };

    for (int which = 0; which < 3; which++) {
        rig_t r;
        wtq_estream_t *es = NULL;
        struct wtq_dstream *ds = NULL;
        uint8_t buf[512];
        size_t tlen = 0;

        establish_server_session(&r, &es, &ds, fp);
        WTQ_TEST_CHECK(es != NULL && ds != NULL);
        if (es == NULL || ds == NULL) {
            rig_down(&r);
            continue;
        }
        int detach_before = ds->detach_count;

        if (which == 0)
            tlen = build_headers(buf, sizeof(buf), PSEUDO, 1);
        else if (which == 1)
            tlen = build_headers(buf, sizeof(buf), BADVAL, 1);
        else {
            memcpy(buf, BAD_QPACK, sizeof(BAD_QPACK));
            tlen = sizeof(BAD_QPACK);
        }
        WTQ_TEST_CHECK(tlen > 0);
        (void)wtq_conn_on_stream_bytes(r.conn, es, buf, tlen, false,
                                       3000);

        WTQ_TEST_CHECK(ds->reset);
        WTQ_TEST_CHECK(ds->stopped);
        WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));   /* stream-local */
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1); /* exactly once */
        WTQ_TEST_CHECK(!r.app.closed_clean);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_CLOSED);
        /* the slot was released through detachment */
        WTQ_TEST_CHECK_EQ_INT(ds->detach_count, detach_before + 1);
        /* late bytes/FIN on the old transport stream reach nobody */
        WTQ_TEST_CHECK(!fake_driver_deliver_bytes(r.conn, ds,
                                                  (const uint8_t *)"x", 1,
                                                  false, 3100));
        WTQ_TEST_CHECK(!fake_driver_deliver_reset(r.conn, ds, 0, 3200));
        WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
        rig_down(&r);
    }
    *fp += failures;
}

/* Trailer size / decoder-capacity limits are LOCAL: stream-local
 * H3_EXCESSIVE_LOAD, never H3_MESSAGE_ERROR and never conn_fatal. */
static void test_trailers_capacity(int *fp)
{
    int failures = 0;

    for (int oversized = 0; oversized < 2; oversized++) {
        rig_t r;
        wtq_estream_t *es = NULL;
        struct wtq_dstream *ds = NULL;
        uint8_t buf[640];
        size_t tlen = 0;

        establish_server_session(&r, &es, &ds, fp);
        WTQ_TEST_CHECK(es != NULL && ds != NULL);
        if (es == NULL || ds == NULL) {
            rig_down(&r);
            continue;
        }
        if (oversized) {
            /* a trailer HEADERS frame past the local cap */
            size_t hl = 0;
            WTQ_TEST_CHECK(wtq_h3_frame_encode_header(
                               WTQ_H3_FRAME_HEADERS, 4096, buf,
                               sizeof(buf), &hl) == 0);
            tlen = hl;
        } else {
            /* more trailer fields than the decoder can hold */
            static wtq_qpack_field_t f[WTQ_CONNECT_MAX_FIELDS + 1];
            static char names[WTQ_CONNECT_MAX_FIELDS + 1][8];
            size_t n = 0;
            while (n < WTQ_CONNECT_MAX_FIELDS + 1) {
                snprintf(names[n], sizeof(names[n]), "x-%02zu", n);
                f[n] = (wtq_qpack_field_t){ names[n], strlen(names[n]),
                                            "v", 1, false };
                n++;
            }
            tlen = build_headers(buf, sizeof(buf), f, n);
        }
        WTQ_TEST_CHECK(tlen > 0);
        (void)wtq_conn_on_stream_bytes(r.conn, es, buf, tlen, false,
                                       3000);

        WTQ_TEST_CHECK(ds->reset);
        WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_EXCESSIVE_LOAD);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
        WTQ_TEST_CHECK(!r.app.closed_clean);
        rig_down(&r);
    }
    *fp += failures;
}

/* After valid trailers the frame sequence still binds (RFC 9114 s4.1):
 * unknown frames skip, DATA and a third HEADERS are connection errors. */
static void test_after_trailers_frame_rules(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t TRAIL[] = {
        { "x-t", 3, "v", 1, false },
    };

    for (int which = 0; which < 3; which++) {
        rig_t r;
        wtq_estream_t *es = NULL;
        uint8_t buf[512];

        establish_server_session(&r, &es, NULL, fp);
        WTQ_TEST_CHECK(es != NULL);
        if (es == NULL) {
            rig_down(&r);
            continue;
        }
        size_t tlen = build_headers(buf, sizeof(buf), TRAIL, 1);
        WTQ_TEST_CHECK(tlen > 0);
        WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es, buf, tlen,
                                                false, 3000) == WTQ_OK);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

        uint8_t next[512];
        size_t nlen = 0;
        size_t hl = 0;
        if (which == 0) {
            /* an unknown (grease) frame is still skippable */
            WTQ_TEST_CHECK(wtq_h3_frame_encode_header(UINT64_C(0x21), 2,
                                                      next, sizeof(next),
                                                      &hl) == 0);
            next[hl] = 0xAA;
            next[hl + 1] = 0xBB;
            nlen = hl + 2;
        } else if (which == 1) {
            /* DATA after trailers */
            WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA,
                                                      1, next,
                                                      sizeof(next),
                                                      &hl) == 0);
            next[hl] = 0x00;
            nlen = hl + 1;
        } else {
            /* a third HEADERS */
            nlen = build_headers(next, sizeof(next), TRAIL, 1);
        }
        WTQ_TEST_CHECK(nlen > 0);
        (void)wtq_conn_on_stream_bytes(r.conn, es, next, nlen, false,
                                       3100);

        if (which == 0) {
            WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
            WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
            WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                           WTQ_SESSION_ESTABLISHED);
        } else {
            WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
            WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                                  WTQ_H3_FRAME_UNEXPECTED);
        }
        rig_down(&r);
    }
    *fp += failures;
}

/* Trailers on a request parked awaiting SETTINGS must not clobber the
 * buffered initial request. Valid ones are consumed and the request
 * still replays; malformed ones cancel it without establishment. */
static void test_trailers_while_parked(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t TRAIL[] = {
        { "x-t", 3, "v", 1, false },
    };
    static const wtq_qpack_field_t PSEUDO[] = {
        { ":method", 7, "GET", 3, false },
    };

    for (int bad = 0; bad < 2; bad++) {
        rig_t r;
        uint8_t req[512];
        size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
        wtq_estream_t *es = NULL;

        WTQ_TEST_CHECK(qlen > 0);
        server_paths_up(&r, true, fp); /* no peer SETTINGS yet */
        struct wtq_dstream *ds =
            feed_request_es(&r, 0, req, qlen, 16, false, &es, fp);
        WTQ_TEST_CHECK_EQ_U64(ds->len, 0); /* parked: no response */
        WTQ_TEST_CHECK(es != NULL);
        if (es == NULL) {
            rig_down(&r);
            continue;
        }

        uint8_t buf[512];
        size_t tlen = build_headers(buf, sizeof(buf),
                                    bad ? PSEUDO : TRAIL, 1);
        WTQ_TEST_CHECK(tlen > 0);
        (void)wtq_conn_on_stream_bytes(r.conn, es, buf, tlen, false,
                                       2700);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

        if (bad) {
            WTQ_TEST_CHECK(ds->reset);
            WTQ_TEST_CHECK_EQ_U64(ds->reset_err, WTQ_H3_MESSAGE_ERROR);
        } else {
            WTQ_TEST_CHECK(!ds->reset);
            WTQ_TEST_CHECK_EQ_U64(ds->len, 0); /* still parked */
        }

        deliver_peer_settings(&r, fp);

        if (bad) {
            /* the parked request was cancelled: nothing replays */
            WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
            WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
            WTQ_TEST_CHECK_EQ_U64(ds->len, 0);
        } else {
            /* the ORIGINAL request replays, unclobbered */
            expect_response_status(ds, 200, fp);
            WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
            WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));
        }
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        rig_down(&r);
    }
    *fp += failures;
}

/* The client's CONNECT stream validates response trailers the same way. */
static void test_client_response_trailers(int *fp)
{
    int failures = 0;
    static const wtq_qpack_field_t TRAIL[] = {
        { "x-t", 3, "v", 1, false },
    };
    static const wtq_qpack_field_t PSEUDO[] = {
        { ":status", 7, "200", 3, false },
    };

    for (int bad = 0; bad < 2; bad++) {
        rig_t r;
        int fp2 = 0;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, OFFER, 2, false, 0 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
        feed_response(&r, resp, rlen, 64, &fp2);
        *fp += fp2;
        WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));

        struct wtq_dstream *bidi = find_local_bidi(&r);
        WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
        if (bidi == NULL || bidi->ectx == NULL) {
            rig_down(&r);
            continue;
        }
        uint8_t buf[512];
        size_t tlen = build_headers(buf, sizeof(buf),
                                    bad ? PSEUDO : TRAIL, 1);
        WTQ_TEST_CHECK(tlen > 0);
        (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, buf, tlen,
                                       false, 3000);

        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
        if (bad) {
            WTQ_TEST_CHECK(bidi->reset);
            WTQ_TEST_CHECK_EQ_U64(bidi->reset_err, WTQ_H3_MESSAGE_ERROR);
            WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
            WTQ_TEST_CHECK(!r.app.closed_clean);
        } else {
            WTQ_TEST_CHECK(!bidi->reset);
            WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 0);
            WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                           WTQ_SESSION_ESTABLISHED);
        }
        rig_down(&r);
    }
    *fp += failures;
}

/* A rejected stream keeps discarding: trailers on it are never even
 * validated, and repeating the pattern cannot exhaust the slot pool. */
static void test_trailers_on_dead_stream(int *fp)
{
    int failures = 0;
    rig_t r;
    static const wtq_qpack_field_t GET_F[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/x", 2, false },
    };
    /* a trailer that WOULD be malformed if it were ever validated */
    static const wtq_qpack_field_t PSEUDO[] = {
        { ":status", 7, "200", 3, false },
    };

    server_up(&r, false, fp);
    for (uint64_t i = 0; i < 24; i++) {
        uint8_t buf[512];
        size_t qlen = build_headers(buf, sizeof(buf), GET_F, 4);
        size_t tlen = build_headers(buf + qlen, sizeof(buf) - qlen,
                                    PSEUDO, 1);
        WTQ_TEST_CHECK(qlen > 0 && tlen > 0);

        wtq_estream_t *es = NULL;
        struct wtq_dstream *ds =
            feed_request_es(&r, i * 4, buf, qlen + tlen, 64, true, &es,
                            fp);
        expect_response_status(ds, 400, fp);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_INT(r.app.error_events, 0);
    }
    expect_fresh_connect_works(&r, 500, fp);
    rig_down(&r);
    *fp += failures;
}

/* unknown path -> 404 response, no session */
static void test_server_unknown_path(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/nope", OFFER, 2);

    server_up(&r, false, fp);
    struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 9, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    wtq_h3_frame_t hdr;
    WTQ_TEST_CHECK(wtq_h3_frame_decode_header(ds->bytes, ds->len, &hdr) ==
                   0);
    wtq_connect_resp_t resp;
    char scratch[512];
    wtq_connect_opts_t opts = { false, false };
    WTQ_TEST_CHECK(wtq_connect_decode_response(ds->bytes + hdr.header_len,
                                               (size_t)hdr.length, &opts,
                                               &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_INT(resp.status, 404);
    rig_down(&r);
    *fp += failures;
}

/* no protocol overlap with require_protocol -> 400, no session */
static void test_server_no_overlap(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    static const char *const OTHER[] = { "chat" };
    size_t qlen = build_request(req, sizeof(req), "/moq", OTHER, 1);

    server_up(&r, true, fp);
    struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 9, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    wtq_h3_frame_t hdr;
    WTQ_TEST_CHECK(wtq_h3_frame_decode_header(ds->bytes, ds->len, &hdr) ==
                   0);
    wtq_connect_resp_t resp;
    char scratch[512];
    wtq_connect_opts_t opts = { false, false };
    WTQ_TEST_CHECK(wtq_connect_decode_response(ds->bytes + hdr.header_len,
                                               (size_t)hdr.length, &opts,
                                               &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_INT(resp.status, 400);
    rig_down(&r);
    *fp += failures;
}

/* malformed request section -> H3_MESSAGE_ERROR */
/* A malformed request no longer kills the connection: see
 * test_server_malformed_contained for the stream-error behavior. The
 * CLIENT's CONNECT stream is a different matter — a malformed response
 * there stays connection-fatal (test_client_bad_response). */

/* one session per connection: a second CONNECT is reset, first
 * session survives */
static void test_server_second_connect(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    server_up(&r, false, fp);
    (void)feed_request(&r, 0, req, qlen, 16, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);

    struct wtq_dstream *ds2 = feed_request(&r, 4, req, qlen, 16, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1); /* still one */
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(ds2->reset);
    WTQ_TEST_CHECK_EQ_HEX(ds2->reset_err, WTQ_H3_REQUEST_REJECTED);
    WTQ_TEST_CHECK(ds2->stopped);
    rig_down(&r);
    *fp += failures;
}

/* request stream reset before establishment leaves no session state */
static void test_request_reset_before_establish(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    server_up(&r, false, fp);
    /* deliver only half the request, then reset */
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 0);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen / 2, false,
                                   2500);
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, es, 0, 2600) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);

    /* a fresh CONNECT afterwards still establishes */
    (void)feed_request(&r, 4, req, qlen, 16, fp);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* FIN must not hide truncated frames or incomplete requests
 * (RFC 9114 s7.1: truncated last frame -> H3_FRAME_ERROR; s8.1:
 * a request stream ending without a full request ->
 * H3_REQUEST_INCOMPLETE) */
static void test_fin_truncation(int *fp)
{
    int failures = 0;
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);

    /* server: clean FIN with no HEADERS at all -> REQUEST_INCOMPLETE */
    {
        rig_t r;
        server_up(&r, false, fp);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 0);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, NULL, 0, true, 2500);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_REQUEST_INCOMPLETE);
        rig_down(&r);
    }
    /* server: partial frame header + FIN -> FRAME_ERROR */
    {
        rig_t r;
        server_up(&r, false, fp);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 0);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0, &es) ==
                       WTQ_OK);
        const uint8_t partial_hdr[] = { 0x01 };
        (void)wtq_conn_on_stream_bytes(r.conn, es, partial_hdr, 1, true,
                                       2500);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_ERROR);
        rig_down(&r);
    }
    /* server: HEADERS declaring more payload than delivered + FIN */
    {
        rig_t r;
        server_up(&r, false, fp);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 0);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen / 2, false,
                                       2500);
        (void)wtq_conn_on_stream_bytes(r.conn, es, NULL, 0, true, 2600);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_ERROR);
        rig_down(&r);
    }
    /* client: partial response frame header + FIN -> FRAME_ERROR */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        struct wtq_dstream *bidi = find_local_bidi(&r);
        WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
        const uint8_t partial_hdr[] = { 0x01 };
        (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, partial_hdr, 1,
                                       true, 2500);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_ERROR);
        rig_down(&r);
    }
    /* client: partial response HEADERS payload + FIN -> FRAME_ERROR */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(do_connect(&r, false) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        struct wtq_dstream *bidi = find_local_bidi(&r);
        WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
        (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, resp, rlen / 2,
                                       false, 2500);
        (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, NULL, 0, true,
                                       2600);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_ERROR);
        rig_down(&r);
    }
    *fp += failures;
}

/* NULL-hostile config surfaces return INVALID_ARG, never crash */
static void test_config_validation(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    {
        wtq_client_connect_cfg_t cfg = {
            "a", "/", NULL, NULL, 2, false, /* NULL protocols, count 2 */
            0,
        };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) ==
                       WTQ_ERR_INVALID_ARG);
    }
    {
        static const char *const holey[] = { "moqt-18", NULL };
        wtq_client_connect_cfg_t cfg = { "a", "/", NULL, holey, 2,
                                         false, 0 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) ==
                       WTQ_ERR_INVALID_ARG);
    }
    rig_down(&r);

    rig_t s;
    rig_up(&s, WTQ_PERSPECTIVE_SERVER, fp);
    {
        wtq_server_path_cfg_t path = { NULL, NULL, 0, false };
        WTQ_TEST_CHECK(wtq_conn_server_set_paths(s.conn, &path, 1) ==
                       WTQ_ERR_INVALID_ARG);
    }
    {
        wtq_server_path_cfg_t path = { "/x", NULL, 2, false };
        WTQ_TEST_CHECK(wtq_conn_server_set_paths(s.conn, &path, 1) ==
                       WTQ_ERR_INVALID_ARG);
    }
    {
        static const char *const holey[] = { "moqt-18", NULL };
        wtq_server_path_cfg_t path = { "/x", holey, 2, false };
        WTQ_TEST_CHECK(wtq_conn_server_set_paths(s.conn, &path, 1) ==
                       WTQ_ERR_INVALID_ARG);
    }
    {
        /* oversized count with a 1-entry array: the bound check must
         * fire before any protocols[j] access walks past the array */
        static const char *const one[] = { "moqt-18" };
        wtq_server_path_cfg_t path = { "/x", one,
                                       WTQ_CONN_MAX_OFFERED + 1, false };
        WTQ_TEST_CHECK(wtq_conn_server_set_paths(s.conn, &path, 1) ==
                       WTQ_ERR_TOO_LARGE);
    }
    rig_down(&s);
    *fp += failures;
}


/* --- long negotiated subprotocols --------------------------------------- */

/*
 * There is no single raw-length maximum: a Structured Fields String may
 * contain '"' and '\\' (draft-15 s3.3), which double when escaped, and
 * the request also carries :authority, :path, origin and the other
 * offers. So these tests never assume a constant — they probe the engine
 * for the first accepted / first rejected length of each CONTENT SHAPE.
 */

/* content shapes: 0 plain, 1 quote-heavy, 2 backslash-heavy,
 * 3 ALL quote, 4 ALL backslash (maximal escaping: every byte doubles) */
#define PROTO_SHAPES 5
static void fill_proto(char *buf, size_t n, int shape)
{
    for (size_t i = 0; i < n; i++) {
        switch (shape) {
        case 1: buf[i] = (i % 2) ? '"' : 'a'; break;
        case 2: buf[i] = (i % 2) ? '\\' : 'a'; break;
        case 3: buf[i] = '"'; break;
        case 4: buf[i] = '\\'; break;
        default: buf[i] = (char)('a' + (i % 26)); break;
        }
    }
    buf[n] = '\0';
}

/* Configure a SERVER policy with this one protocol; returns the rc. */
static wtq_result_t server_policy_rc(const char *proto)
{
    rig_t r;
    int fp = 0;
    const char *const supported[] = { proto };

    rig_up(&r, WTQ_PERSPECTIVE_SERVER, &fp);
    wtq_server_path_cfg_t path = { "/moq", supported, 1, true };
    wtq_result_t rc = wtq_conn_server_set_paths(r.conn, &path, 1);
    rig_down(&r);
    return rc;
}

/* Offer this one protocol as a CLIENT; returns the rc. Also asserts the
 * rejection is inert: IDLE state, no driver op, no wire byte. */
static wtq_result_t client_offer_rc(const char *proto, const char *auth,
                                    const char *path_s, int *fp)
{
    int failures = 0;
    rig_t r;
    const char *const offer[] = { proto };

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    int opens = r.drv.open_calls;
    int sends = r.drv.send_calls;
    size_t bytes = wire_bytes(&r.drv);

    wtq_client_connect_cfg_t cfg = { auth, path_s, NULL, offer, 1, true, 0 };
    wtq_result_t rc = wtq_conn_client_connect(r.conn, &cfg);

    if (rc != WTQ_OK) {
        WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_TOO_LARGE);
        /* rejected: nothing moved */
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_IDLE);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
        WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
        WTQ_TEST_CHECK_EQ_SIZE(wire_bytes(&r.drv), bytes);
    }
    rig_down(&r);
    *fp += failures;
    return rc;
}

/* Decode a 200 response carrying `proto` exactly as this engine's client
 * path would, and require the bytes to survive. This is what a server's
 * policy validation promises: the value it may select is encodable into a
 * response and decodable by this engine. (It need not also be offerable
 * by our own client — a request carries far more fields.) */
static void expect_response_decodes(const char *proto, size_t n, int *fp)
{
    int failures = 0;
    uint8_t section[512];
    char scratch[512];
    wtq_sf_str_t sel = { proto, n };
    wtq_connect_resp_t resp;
    wtq_connect_opts_t opts = { false, false };
    size_t slen = 0;

    WTQ_TEST_CHECK_EQ_INT(wtq_connect_encode_response(200, &sel, section,
                                                      sizeof(section),
                                                      &slen),
                          WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_connect_decode_response(section, slen,
                                                      &opts, &resp,
                                                      scratch,
                                                      sizeof(scratch)),
                          WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(resp.has_protocol);
    WTQ_TEST_CHECK_EQ_SIZE(resp.protocol.len, n);
    WTQ_TEST_CHECK(memcmp(resp.protocol.data, proto, n) == 0);
    *fp += failures;
}

/* Non-asserting probe: can a client offer this protocol at all? */
static wtq_result_t client_offer_probe(const char *proto)
{
    rig_t r;
    int fp = 0;
    const char *const offer[] = { proto };

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, &fp);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, offer, 1, true, 0 };
    wtq_result_t rc = wtq_conn_client_connect(r.conn, &cfg);
    rig_down(&r);
    return rc;
}

/* Establish server-side with `proto` and assert the exact bytes reach
 * the callback and the query. */
static void server_selects(const char *proto, size_t n, int *fp)
{
    int failures = 0;
    rig_t r;
    const char *const supported[] = { proto };
    const char *const offer[] = { proto };

    rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
    wtq_server_path_cfg_t path = { "/moq", supported, 1, true };
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_server_set_paths(r.conn, &path, 1),
                          WTQ_OK);
    deliver_peer_settings(&r, fp);

    uint8_t req[1024];
    size_t qlen = build_request(req, sizeof(req), "/moq", offer, 1);
    WTQ_TEST_CHECK(qlen > 0);
    struct wtq_dstream *ds = feed_request(&r, 0, req, qlen, 64, fp);
    expect_response_status(ds, 200, fp);

    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, n);
    WTQ_TEST_CHECK(memcmp(r.app.selected, proto, n) == 0);

    size_t qn = 99;
    const char *q = wtq_conn_selected_protocol(r.conn, &qn);
    WTQ_TEST_CHECK_EQ_SIZE(qn, n);
    WTQ_TEST_CHECK(memcmp(q, proto, n) == 0);

    rig_down(&r);
    *fp += failures;
}

/* Establish client-side: the server's 200 carries `proto`, and the real
 * client decode path must surface it verbatim. */
static void client_records(const char *proto, size_t n, int *fp)
{
    int failures = 0;
    rig_t r;
    const char *const offer[] = { proto };

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, offer, 1, true, 0 };
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_client_connect(r.conn, &cfg), WTQ_OK);
    deliver_peer_settings(&r, fp);

    uint8_t resp[1024];
    size_t rlen = build_response(resp, sizeof(resp), 200, proto);
    WTQ_TEST_CHECK(rlen > 0);
    feed_response(&r, resp, rlen, 64, fp);

    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.failed_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.selected_len, n);
    WTQ_TEST_CHECK(memcmp(r.app.selected, proto, n) == 0);

    size_t qn = 99;
    const char *q = wtq_conn_selected_protocol(r.conn, &qn);
    WTQ_TEST_CHECK_EQ_SIZE(qn, n);
    WTQ_TEST_CHECK(memcmp(q, proto, n) == 0);

    rig_down(&r);
    *fp += failures;
}

/* Ordinary values across the old 128-byte buffer boundary. */
static void test_subprotocol_128_129(int *fp)
{
    int failures = 0;
    char buf[600];

    for (size_t n = 128; n <= 129; n++) {
        fill_proto(buf, n, 0);
        server_selects(buf, n, fp);
        client_records(buf, n, fp);
    }
    *fp += failures;
}

/*
 * The engine has TWO distinct capacities, and they are not the same
 * number:
 *   - a SERVER policy value must encode into a 200 response and decode
 *     back (that is all the server can check when its policy is set);
 *   - a CLIENT offer must additionally survive the whole generated
 *     CONNECT, which also carries :authority, :path and the other offers.
 *
 * Both depend on CONTENT, since '"' and '\\' double when escaped. These
 * tests probe each boundary for each shape rather than assume a number,
 * and prove the last accepted value works end to end while the first
 * rejected one is refused inertly at configuration.
 */
static void test_subprotocol_boundaries(int *fp)
{
    int failures = 0;

    for (int shape = 0; shape < PROTO_SHAPES; shape++) {
        char buf[600];

        /* --- client-offer boundary: bounded by the whole CONNECT --- */
        size_t c_bad = 0;
        for (size_t n = 1; n < 560; n++) {
            fill_proto(buf, n, shape);
            if (client_offer_probe(buf) != WTQ_OK) {
                c_bad = n;
                break;
            }
        }
        WTQ_TEST_CHECK(c_bad > 1);
        if (c_bad > 1) {
            size_t last_ok = c_bad - 1;

            /* the last accepted offer works end to end, exact bytes,
             * through BOTH real codec paths */
            fill_proto(buf, last_ok, shape);
            WTQ_TEST_CHECK_EQ_INT(
                client_offer_rc(buf, "example.com", "/moq", fp), WTQ_OK);
            server_selects(buf, last_ok, fp);
            client_records(buf, last_ok, fp);

            /* the first rejected offer: TOO_LARGE, IDLE, no wire byte */
            fill_proto(buf, c_bad, shape);
            WTQ_TEST_CHECK_EQ_INT(
                client_offer_rc(buf, "example.com", "/moq", fp),
                WTQ_ERR_TOO_LARGE);
        }

        /* --- server-policy boundary: bounded by the 200 response --- */
        size_t s_bad = 0;
        for (size_t n = 1; n < 560; n++) {
            fill_proto(buf, n, shape);
            if (server_policy_rc(buf) != WTQ_OK) {
                s_bad = n;
                break;
            }
        }
        WTQ_TEST_CHECK(s_bad > 1);
        if (s_bad > 1) {
            /* the last accepted policy value really does survive this
             * engine's response encode + decode */
            fill_proto(buf, s_bad - 1, shape);
            expect_response_decodes(buf, s_bad - 1, fp);

            fill_proto(buf, s_bad, shape);
            WTQ_TEST_CHECK_EQ_INT(server_policy_rc(buf),
                                  WTQ_ERR_TOO_LARGE);
        }

        /* a policy may legitimately accept more than a client can offer:
         * the server cannot predict remote request composition */
        WTQ_TEST_CHECK(s_bad >= c_bad);

        /* escaping bites: the escape-heavy shapes cap sooner than plain */
        if (shape == 0) {
            char e[600];
            fill_proto(e, c_bad - 1, 1);
            WTQ_TEST_CHECK(client_offer_probe(e) != WTQ_OK);
        }
    }
    *fp += failures;
}

/* A long authority/path eats the same decode budget as the offer, so the
 * client must refuse a combination its own engine could not decode —
 * before touching session state or the wire. */
static void test_subprotocol_with_long_authority(int *fp)
{
    int failures = 0;
    char proto[600];
    char auth[400];
    char path_s[400];

    /* an offer that is fine on its own */
    fill_proto(proto, 128, 0);
    WTQ_TEST_CHECK_EQ_INT(
        client_offer_rc(proto, "example.com", "/moq", fp), WTQ_OK);

    /* ...but not alongside a large authority and path */
    memset(auth, 'h', sizeof(auth) - 1);
    auth[sizeof(auth) - 1] = '\0';
    path_s[0] = '/';
    memset(path_s + 1, 'p', sizeof(path_s) - 2);
    path_s[sizeof(path_s) - 1] = '\0';
    WTQ_TEST_CHECK_EQ_INT(client_offer_rc(proto, auth, path_s, fp),
                          WTQ_ERR_TOO_LARGE);
    *fp += failures;
}

/* Several offers near aggregate capacity: accepted while they all decode
 * back byte-exact, refused as a whole once they do not. */
static void test_subprotocol_multiple_offers(int *fp)
{
    int failures = 0;
    static char p[4][300];
    const char *offer[4];
    size_t first_bad = 0;

    for (size_t n = 8; n < 300; n++) {
        rig_t r;
        for (int i = 0; i < 4; i++) {
            fill_proto(p[i], n, 0);
            p[i][0] = (char)('A' + i); /* keep them distinct */
            offer[i] = p[i];
        }
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        /* baseline after start(): the control-plane prefaces */
        size_t before = wire_bytes(&r.drv);
        int opens = r.drv.open_calls;
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, offer, 4, true, 0 };
        wtq_result_t rc = wtq_conn_client_connect(r.conn, &cfg);
        if (rc != WTQ_OK) {
            WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_TOO_LARGE);
            WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                           WTQ_SESSION_IDLE);
            WTQ_TEST_CHECK_EQ_SIZE(wire_bytes(&r.drv), before);
            WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
            first_bad = n;
        }
        rig_down(&r);
        if (first_bad != 0)
            break;
    }
    /* the aggregate limit exists and is smaller than a single offer's */
    WTQ_TEST_CHECK(first_bad > 8);
    *fp += failures;
}

/* An accepted server policy must survive the REAL client decode path:
 * the 200 it emits is fed to a client that offered the same value. */
static void test_accepted_policy_decodes_on_client(int *fp)
{
    int failures = 0;

    for (int shape = 0; shape < PROTO_SHAPES; shape++) {
        char buf[600];
        size_t last_ok = 0;

        for (size_t n = 1; n < 560; n++) {
            fill_proto(buf, n, shape);
            if (server_policy_rc(buf) != WTQ_OK)
                break;
            last_ok = n;
        }
        WTQ_TEST_CHECK(last_ok > 0);
        if (last_ok == 0)
            continue;
        fill_proto(buf, last_ok, shape);
        expect_response_decodes(buf, last_ok, fp);
    }
    *fp += failures;
}


/* Content the Structured Fields grammar forbids (CR, LF, NUL-range CTLs,
 * DEL) is MALFORMED, not oversized: WTQ_ERR_INVALID_ARG from both
 * configuration paths, with no state change and no wire byte. */
static void test_subprotocol_malformed_content(int *fp)
{
    int failures = 0;
    static const char *const BAD[] = {
        "moqt\r18", "moqt\n18", "moqt\x01" "18", "moqt\x7f" "18",
        "moqt\t18",
    };

    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        /* server policy */
        WTQ_TEST_CHECK_EQ_INT(server_policy_rc(BAD[i]),
                              WTQ_ERR_INVALID_ARG);

        /* client offer: INVALID_ARG, IDLE, nothing sent */
        rig_t r;
        const char *const offer[] = { BAD[i] };

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        size_t before = wire_bytes(&r.drv);
        int opens = r.drv.open_calls;
        int sends = r.drv.send_calls;
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, offer, 1, true, 0 };
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_client_connect(r.conn, &cfg),
                              WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_IDLE);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
        WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
        WTQ_TEST_CHECK_EQ_SIZE(wire_bytes(&r.drv), before);
        rig_down(&r);
    }

    /* the shared validator agrees, and reports structure separately */
    {
        const char *const bad[] = { "moqt\r18" };
        const char *const good[] = { "moqt-18" };
        const char *const nullp[] = { NULL };

        WTQ_TEST_CHECK_EQ_INT(wtq_conn_validate_protocols(bad, 1),
                              WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_validate_protocols(nullp, 1),
                              WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_validate_protocols(NULL, 1),
                              WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_validate_protocols(good, 1),
                              WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_validate_protocols(good, 0),
                              WTQ_OK);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_subprotocol_malformed_content(&failures);
    test_subprotocol_128_129(&failures);
    test_subprotocol_boundaries(&failures);
    test_subprotocol_with_long_authority(&failures);
    test_subprotocol_multiple_offers(&failures);
    test_accepted_policy_decodes_on_client(&failures);

    test_fin_truncation(&failures);
    test_config_validation(&failures);
    test_connect_deferred(&failures);
    test_connect_no_wt(&failures);
    test_connect_established(&failures);
    test_connect_no_protocol_ok(&failures);
    test_connect_protocol_failures(&failures);
    test_connect_rejected(&failures);
    test_connect_bad_response(&failures);
    test_connect_stream_frames(&failures);
    test_server_bidi_to_client(&failures);
    test_server_accept(&failures);
    test_server_defer_before_settings(&failures);
    test_server_defer_nonwt_settings(&failures);
    test_server_defer_fin_before_settings(&failures);
    test_server_defer_overbound(&failures);
    test_server_defer_stop_sending_cancels(&failures);
    test_server_defer_fin_stop_released(&failures);
    test_server_defer_reset_then_fresh(&failures);
    test_server_defer_data_rejected(&failures);
    test_server_reject_without_peer_wt_settings(&failures);
    test_server_non_wt_request(&failures);
    test_server_malformed_contained(&failures);
    test_server_oversized_headers(&failures);
    test_server_decoder_capacity(&failures);
    test_server_dead_stream_discards(&failures);
    test_server_rejected_streams_no_slot_leak(&failures);
    test_start_is_one_shot(&failures);
    test_start_success_retry(&failures);
    test_peer_pool_overflow(&failures);
    test_pool_leaves_room_for_control(&failures);
    test_pool_release_frees_slot(&failures);
    test_invalid_boolean_settings(&failures);
    test_trailers_valid(&failures);
    test_trailers_malformed(&failures);
    test_trailers_capacity(&failures);
    test_after_trailers_frame_rules(&failures);
    test_trailers_while_parked(&failures);
    test_client_response_trailers(&failures);
    test_trailers_on_dead_stream(&failures);
    test_server_unknown_path(&failures);
    test_server_no_overlap(&failures);
    test_server_second_connect(&failures);
    test_request_reset_before_establish(&failures);
    test_profile_latch(&failures);
    test_server_profile_symmetry(&failures);

    WTQ_TEST_PASS("test_engine_connect");
    return failures;
}
