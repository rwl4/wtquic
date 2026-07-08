#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

/*
 * Session lifecycle over the CONNECT stream: capsules (CLOSE/DRAIN/
 * unknown), clean-FIN and reset semantics, the exactly-once terminal
 * callback, and the local close/drain surface.
 */

typedef struct app_state {
    int seq;                /* global event counter (ordering asserts) */
    int established_events;
    int rejected_events;
    int failed_events;
    int failed_seq;
    int failed_reason;
    int error_events;
    int error_seq;
    uint64_t last_error;
    int closed_events;
    int closed_seq;
    uint32_t closed_code;
    uint8_t closed_reason[1200];
    size_t closed_reason_len;
    bool closed_clean;
    int draining_events;
    /* reentrancy fixture: close the session from inside on_draining */
    bool close_in_draining;
    wtq_conn_t *draining_conn;
} app_state_t;

static void cb_error(wtq_conn_t *c, uint64_t e, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->error_events++;
    st->error_seq = ++st->seq;
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
    st->seq++;
}

static void cb_rejected(wtq_conn_t *c, uint16_t status, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)status;
    st->rejected_events++;
    st->seq++;
}

static void cb_failed(wtq_conn_t *c, wtq_session_fail_reason_t r,
                      void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->failed_events++;
    st->failed_seq = ++st->seq;
    st->failed_reason = (int)r;
}

static void cb_closed(wtq_conn_t *c, uint32_t code, const uint8_t *reason,
                      size_t reason_len, bool clean, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->closed_events++;
    st->closed_seq = ++st->seq;
    st->closed_code = code;
    st->closed_reason_len =
        reason_len <= sizeof(st->closed_reason) ? reason_len : 0;
    if (st->closed_reason_len > 0)
        memcpy(st->closed_reason, reason, st->closed_reason_len);
    st->closed_clean = clean;
}

static void cb_draining(wtq_conn_t *c, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->draining_events++;
    st->seq++;
    if (st->close_in_draining && st->draining_conn != NULL)
        (void)wtq_conn_session_close(st->draining_conn, 5, NULL, 0);
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    app_state_t app;
    wtq_estream_t *sess_es; /* the CONNECT/request stream's engine ctx */
    struct wtq_dstream *sess_ds;
} rig_t;

static void rig_up(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;

    memset(&r->app, 0, sizeof(r->app));
    r->sess_es = NULL;
    r->sess_ds = NULL;
    fake_driver_init(&r->drv, persp == WTQ_PERSPECTIVE_CLIENT);

    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = persp,
        .enable_connect_protocol = true,
        .callbacks = { .on_conn_error = cb_error,
                       .on_session_established = cb_established,
                       .on_session_rejected = cb_rejected,
                       .on_session_failed = cb_failed,
                       .on_session_closed = cb_closed,
                       .on_session_draining = cb_draining,
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

/* A peer control stream whose SETTINGS are legal but carry no
 * WebTransport support (H3_DATAGRAM present and 0). */
static void deliver_peer_settings_nowt(rig_t *r, int *fp)
{
    int failures = 0;
    /* stream type 0x00, SETTINGS frame (0x04) len 2: id 0x33 = 0 */
    uint8_t buf[5] = { 0x00, 0x04, 0x02, 0x33, 0x00 };
    bool is_client = (r->drv.is_client);
    struct wtq_dstream *ds =
        fake_driver_add_peer_stream(&r->drv, is_client ? 3 : 2);
    wtq_estream_t *es = NULL;

    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r->conn, ds,
                                               is_client ? 3 : 2, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r->conn, es, buf, sizeof(buf), false,
                                   1500);
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

static const char *const OFFER[] = { "moqt-18", "moqt-16" };
static const char *const SUPPORTED[] = { "moqt-18", "moqt-17" };

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

/* Establish a client-side session; sess_es/sess_ds point at the CONNECT
 * stream afterwards. */
static void establish_client(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, false, 0 };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r->conn, &cfg) == WTQ_OK);
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
    WTQ_TEST_CHECK(rlen > 0);
    (void)wtq_conn_on_stream_bytes(r->conn, r->sess_es, resp, rlen, false,
                                   2000);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    WTQ_TEST_CHECK(wtq_conn_session_state(r->conn) ==
                   WTQ_SESSION_ESTABLISHED);
    *fp += failures;
}

/* Establish a server-side session on peer bidi stream 0. */
static void establish_server(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_SERVER, fp);
    wtq_server_path_cfg_t path = { "/moq", SUPPORTED, 2, false };
    WTQ_TEST_CHECK(wtq_conn_server_set_paths(r->conn, &path, 1) ==
                   WTQ_OK);
    deliver_peer_settings(r, fp);

    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq", OFFER, 2);
    WTQ_TEST_CHECK(qlen > 0);

    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, 0);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r->conn, ds, 0, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r->conn, es, req, qlen, false, 2000);
    WTQ_TEST_CHECK(wtq_conn_session_established(r->conn));
    r->sess_es = es;
    r->sess_ds = ds;
    *fp += failures;
}

/* Wrap payload bytes in a DATA frame. */
static size_t build_data_frame(const uint8_t *payload, size_t plen,
                               uint8_t *dst, size_t cap)
{
    size_t hl = 0;

    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, plen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, payload, plen);
    return hl + plen;
}

static size_t build_close_in_data(uint32_t code, const char *reason,
                                  uint8_t *dst, size_t cap)
{
    uint8_t cap_buf[1100];
    size_t clen = 0;

    if (wtq_capsule_encode_close(code, (const uint8_t *)reason,
                                 reason ? strlen(reason) : 0, cap_buf,
                                 sizeof(cap_buf), &clen) != 0)
        return 0;
    return build_data_frame(cap_buf, clen, dst, cap);
}

static size_t build_drain_in_data(uint8_t *dst, size_t cap)
{
    uint8_t cap_buf[8];
    size_t clen = 0;

    if (wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf), &clen) != 0)
        return 0;
    return build_data_frame(cap_buf, clen, dst, cap);
}

/* A DRAIN capsule whose payload length is 1 — it MUST be 0 (draft-15
 * s5), so the capsule is malformed. Writes the raw capsule (not a DATA
 * frame) and returns its length. */
static size_t build_malformed_capsule(uint8_t *out, size_t cap)
{
    uint8_t cap_buf[8];
    size_t clen = 0;

    if (wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf), &clen) != 0 ||
        clen == 0 || clen + 1 > cap)
        return 0;
    memcpy(out, cap_buf, clen);
    out[clen - 1] = 0x01; /* payload length 1 instead of 0 */
    out[clen] = 0xff;     /* the illegal payload byte */
    return clen + 1;
}

/* A COMPLETE DATA frame carrying only the first bytes of a capsule
 * header: the frame is whole, the capsule inside is truncated. */
static size_t build_capsule_prefix_in_data(uint8_t *dst, size_t cap)
{
    uint8_t cap_buf[8];
    size_t clen = 0;

    if (wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf), &clen) != 0 ||
        clen < 3)
        return 0;
    /* type varint only — the length byte never arrives */
    return build_data_frame(cap_buf, clen - 1, dst, cap);
}

/* --- post-local-close capsule containment -------------------------------- */

/* Establish a client session, then close it locally. sess_es/sess_ds
 * remain the CONNECT stream; the session is terminal (SS_CLOSED). */
static void establish_then_local_close(rig_t *r, int *fp)
{
    int failures = 0;

    establish_client(r, fp);
    WTQ_TEST_CHECK(wtq_conn_session_close(r->conn, 7,
                                          (const uint8_t *)"bye", 3) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_session_state(r->conn) ==
                   WTQ_SESSION_CLOSED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r->app.closed_events, 1);
    WTQ_TEST_CHECK(r->app.closed_clean);
    *fp += failures;
}

/* A peer DRAIN that arrives after we closed locally is consumed
 * silently: no on_session_draining, no state regression, no second
 * terminal, no connection error. */
static void test_post_close_drain(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t wire[64];

    establish_then_local_close(&r, fp);
    size_t wlen = build_drain_in_data(wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);

    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_CLOSED);
    rig_down(&r);
    *fp += failures;
}

/* A valid peer CLOSE after local close is consumed idempotently, and
 * the FIN that follows brings no second terminal callback. */
static void test_post_close_peer_close(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t wire[64];

    establish_then_local_close(&r, fp);
    size_t wlen = build_close_in_data(9, "peer", wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_HEX((uint64_t)r.app.closed_code, 7); /* OUR code stands */
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    /* the peer's FIN completes the stream, still exactly one terminal */
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                   3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* Unknown (but well-formed) capsules after local close are skipped. */
static void test_post_close_unknown_capsule(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t payload[32];
    uint8_t wire[64];
    size_t hl = 0;

    establish_then_local_close(&r, fp);
    WTQ_TEST_CHECK(wtq_capsule_encode_header(UINT64_C(0x4242), 3, payload,
                                             sizeof(payload), &hl) == 0);
    payload[hl] = 'a';
    payload[hl + 1] = 'b';
    payload[hl + 2] = 'c';
    size_t wlen = build_data_frame(payload, hl + 3, wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);

    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* A malformed capsule after local close is a STREAM error: reset/stop
 * with H3_MESSAGE_ERROR, connection open, one terminal, and the
 * estream released through detachment so nothing late can reach it. */
static void test_post_close_malformed_capsule(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t payload[16];
    uint8_t wire[32];

    establish_then_local_close(&r, fp);
    int detach_before = r.sess_ds->detach_count;
    size_t plen = build_malformed_capsule(payload, sizeof(payload));
    WTQ_TEST_CHECK(plen > 0);
    size_t wlen = build_data_frame(payload, plen, wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);

    WTQ_TEST_CHECK(r.sess_ds->reset);
    WTQ_TEST_CHECK(r.sess_ds->stopped);
    WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->reset_err, WTQ_H3_MESSAGE_ERROR);
    /* the poisoned session stream dies in ONE whole-stream transaction */
    WTQ_TEST_CHECK_EQ_INT(r.sess_ds->shutdown_count, 1);
    WTQ_TEST_CHECK(r.sess_ds->last_shutdown.mode ==
                   WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(r.sess_ds->last_shutdown.abort_send &&
                   r.sess_ds->last_shutdown.abort_recv);
    WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->last_shutdown.send_err,
                          WTQ_H3_MESSAGE_ERROR);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn)); /* connection lives */
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.sess_ds->detach_count, detach_before + 1);
    /* late bytes / reset on the old transport stream reach nobody */
    WTQ_TEST_CHECK(!fake_driver_deliver_bytes(r.conn, r.sess_ds,
                                              (const uint8_t *)"x", 1,
                                              false, 3100));
    WTQ_TEST_CHECK(!fake_driver_deliver_reset(r.conn, r.sess_ds, 0,
                                              3200));
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* A capsule split across the local close follows the post-close rules:
 * its first bytes arrive while established, the rest after. */
static void test_post_close_fragmented_capsule(int *fp)
{
    int failures = 0;

    /* the tail completes a DRAIN -> must NOT fire on_session_draining */
    {
        rig_t r;
        uint8_t cap_buf[8];
        size_t clen = 0;
        uint8_t wire[32];

        establish_client(&r, fp);
        WTQ_TEST_CHECK(wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf),
                                                &clen) == 0);
        WTQ_TEST_CHECK(clen >= 2);
        size_t wlen = build_data_frame(cap_buf, clen, wire,
                                       sizeof(wire));
        WTQ_TEST_CHECK(wlen > 0);
        /* everything but the capsule's final byte */
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen - 1,
                                       false, 3000);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 0);

        WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 7, NULL, 0) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);

        /* the capsule completes AFTER the local close */
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es,
                                       wire + wlen - 1, 1, false, 3100);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        rig_down(&r);
    }
    /* the tail completes a MALFORMED capsule -> stream-local error */
    {
        rig_t r;
        uint8_t payload[16];
        uint8_t wire[32];

        establish_client(&r, fp);
        size_t plen = build_malformed_capsule(payload, sizeof(payload));
        WTQ_TEST_CHECK(plen > 0);
        size_t wlen = build_data_frame(payload, plen, wire,
                                       sizeof(wire));
        WTQ_TEST_CHECK(wlen > 2);
        /* stop INSIDE the capsule header (before its length byte), so
         * the shape is only judged after the local close */
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen - 2,
                                       false, 3000);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

        WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 7, NULL, 0) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es,
                                       wire + wlen - 2, 2, false, 3100);

        WTQ_TEST_CHECK(r.sess_ds->reset);
        WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->reset_err,
                              WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        rig_down(&r);
    }
    *fp += failures;
}

/* Reentrancy: on_session_draining closes the session while MORE
 * capsules remain in the same DATA frame. Those must take the terminal
 * path — a trailing malformed capsule becomes a stream error, not the
 * connection error it would have been pre-terminal. */
static void test_post_close_reentrant(int *fp)
{
    int failures = 0;
    rig_t r;
    uint8_t cap_buf[8];
    size_t clen = 0;
    uint8_t payload[32];
    uint8_t wire[64];

    establish_client(&r, fp);
    r.app.close_in_draining = true;
    r.app.draining_conn = r.conn;

    /* DRAIN (its callback closes the session) followed, in the SAME
     * DATA frame, by a malformed capsule (DRAIN with nonzero length) */
    WTQ_TEST_CHECK(wtq_capsule_encode_drain(cap_buf, sizeof(cap_buf),
                                            &clen) == 0);
    memcpy(payload, cap_buf, clen);
    size_t blen = build_malformed_capsule(payload + clen,
                                          sizeof(payload) - clen);
    WTQ_TEST_CHECK(blen > 0);
    size_t wlen = build_data_frame(payload, clen + blen, wire,
                                   sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);

    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    /* the trailing malformed capsule was contained to the stream */
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(r.sess_ds->reset);
    WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->reset_err, WTQ_H3_MESSAGE_ERROR);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_CLOSED);

    r.app.close_in_draining = false;
    rig_down(&r);
    *fp += failures;
}

/* A peer FIN that reveals a truncated capsule AFTER the session closed
 * locally is contained to the stream: reset/stop with H3_MESSAGE_ERROR,
 * connection open, no on_conn_error, the single clean terminal from the
 * local close still stands, and exactly ONE detach. Covers both the
 * capsule prefix arriving after the close and before it. */
static void test_post_close_fin_truncated_capsule(int *fp)
{
    int failures = 0;

    for (int prefix_first = 0; prefix_first < 2; prefix_first++) {
        rig_t r;
        uint8_t wire[32];
        size_t wlen;

        if (prefix_first) {
            /* the capsule prefix arrives while still established */
            establish_client(&r, fp);
            wlen = build_capsule_prefix_in_data(wire, sizeof(wire));
            WTQ_TEST_CHECK(wlen > 0);
            (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen,
                                           false, 3000);
            WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
            WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 7, NULL, 0) ==
                           WTQ_OK);
        } else {
            establish_then_local_close(&r, fp);
            wlen = build_capsule_prefix_in_data(wire, sizeof(wire));
            WTQ_TEST_CHECK(wlen > 0);
            (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen,
                                           false, 3000);
        }
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        int detach_before = r.sess_ds->detach_count;

        /* the FIN exposes the truncated capsule */
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                       3100);

        WTQ_TEST_CHECK(r.sess_ds->reset);
        WTQ_TEST_CHECK(r.sess_ds->stopped);
        WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->reset_err,
                              WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK(r.app.closed_clean); /* the local close stands */
        /* the FIN path releases the slot exactly once */
        WTQ_TEST_CHECK_EQ_INT(r.sess_ds->detach_count, detach_before + 1);
        WTQ_TEST_CHECK(!fake_driver_deliver_bytes(r.conn, r.sess_ds,
                                                  (const uint8_t *)"x", 1,
                                                  false, 3200));
        rig_down(&r);
    }
    *fp += failures;
}

/* --- lifecycle: clean FIN / reset -------------------------------------- */

/* draft-15 s6: a clean CONNECT FIN without a CLOSE capsule == CLOSE
 * with code 0 and an empty reason. Both perspectives. */
static void test_clean_fin_closes_session(int *fp)
{
    int failures = 0;

    for (int persp = 0; persp < 2; persp++) {
        rig_t r;
        if (persp == 0)
            establish_client(&r, fp);
        else
            establish_server(&r, fp);

        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                       3000);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn)); /* no H3 error */
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK(r.app.closed_code == 0);
        WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 0);
        WTQ_TEST_CHECK(r.app.closed_clean);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_CLOSED);
        rig_down(&r);
    }
    *fp += failures;
}

/* RESET on the established CONNECT stream: abrupt termination. */
static void test_connect_reset_closes_session(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    (void)wtq_conn_on_stream_reset(r.conn, r.sess_es, 0x10b, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_code == 0);
    WTQ_TEST_CHECK(!r.app.closed_clean);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_CLOSED);
    rig_down(&r);
    *fp += failures;
}

/* --- capsules ----------------------------------------------------------- */

/* CLOSE capsule: code + byte-exact reason, clean close, FIN follows. */
static void test_close_capsule(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t wire[1200];
    size_t wlen = build_close_in_data(77, "bye now", wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_code == 77);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 7);
    WTQ_TEST_CHECK(memcmp(r.app.closed_reason, "bye now", 7) == 0);
    WTQ_TEST_CHECK(r.app.closed_clean);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    /* the expected FIN after the capsule is quiet */
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                   3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* Max-length (1024-byte) reason survives byte-exact. */
static void test_close_capsule_max_reason(int *fp)
{
    int failures = 0;
    rig_t r;
    char reason[1025];

    memset(reason, 'r', 1024);
    reason[1024] = '\0';
    establish_client(&r, fp);
    uint8_t wire[1200];
    size_t wlen = build_close_in_data(1, reason, wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 1024);
    WTQ_TEST_CHECK(memcmp(r.app.closed_reason, reason, 1024) == 0);
    rig_down(&r);
    *fp += failures;
}

/* The capsule layer survives every chunk boundary (frame header,
 * capsule header, code, reason all split arbitrarily). */
static void test_close_capsule_every_split(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t wire[256];
    size_t wlen = build_close_in_data(0xabcd0123u, "split me", wire,
                                      sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    for (size_t i = 0; i < wlen; i++)
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire + i, 1,
                                       false, 3000 + i);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_code == 0xabcd0123u);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 8);
    WTQ_TEST_CHECK(memcmp(r.app.closed_reason, "split me", 8) == 0);
    rig_down(&r);
    *fp += failures;
}

/* One DATA frame carrying several capsules: unknown skipped, DRAIN
 * fires, then CLOSE in a second DATA frame still parses. */
static void test_multiple_capsules(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);

    uint8_t payload[64];
    size_t plen = 0;
    /* unknown/grease capsule with 3 payload bytes */
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_header(0x1f7, 3, payload,
                                             sizeof(payload), &hl) == 0);
    plen = hl;
    payload[plen++] = 0xaa;
    payload[plen++] = 0xbb;
    payload[plen++] = 0xcc;
    size_t clen = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_drain(payload + plen,
                                            sizeof(payload) - plen,
                                            &clen) == 0);
    plen += clen;

    uint8_t wire[128];
    size_t wlen = build_data_frame(payload, plen, wire, sizeof(wire));
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                   WTQ_SESSION_DRAINING);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);

    wlen = build_close_in_data(9, "", wire, sizeof(wire));
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_code == 9);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 0);
    rig_down(&r);
    *fp += failures;
}

/* DRAIN is advisory and fires at most once. */
static void test_drain_capsule(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t wire[32];
    size_t wlen = build_drain_in_data(wire, sizeof(wire));
    WTQ_TEST_CHECK(wlen > 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 1);
    WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));

    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.draining_events, 1);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r);
    *fp += failures;
}

/* Malformed known capsules are a connection error (0x10e), and the
 * terminal callback still fires exactly once (unclean). */
static void test_malformed_capsules(int *fp)
{
    int failures = 0;

    /* CLOSE with a 2-byte payload (< the 32-bit code) */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t payload[8];
        size_t hl = 0;
        WTQ_TEST_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_CLOSE_SESSION,
                                                 2, payload,
                                                 sizeof(payload),
                                                 &hl) == 0);
        payload[hl] = 0x00;
        payload[hl + 1] = 0x01;
        uint8_t wire[32];
        size_t wlen = build_data_frame(payload, hl + 2, wire,
                                       sizeof(wire));
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen,
                                       false, 3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK(!r.app.closed_clean);
        rig_down(&r);
    }
    /* DRAIN with a nonzero payload length */
    {
        rig_t r;
        establish_server(&r, fp);
        uint8_t payload[8];
        size_t hl = 0;
        WTQ_TEST_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_DRAIN_SESSION,
                                                 1, payload,
                                                 sizeof(payload),
                                                 &hl) == 0);
        payload[hl] = 0x00;
        uint8_t wire[32];
        size_t wlen = build_data_frame(payload, hl + 1, wire,
                                       sizeof(wire));
        (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen,
                                       false, 3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_MESSAGE_ERROR);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
        WTQ_TEST_CHECK(!r.app.closed_clean);
        rig_down(&r);
    }
    *fp += failures;
}

/* draft-15 s6: stream data after a received CLOSE capsule -> the stream
 * is reset with H3_MESSAGE_ERROR. Not a connection error; the terminal
 * callback does not fire again. */
static void test_data_after_close_capsule(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t wire[64];
    size_t wlen = build_close_in_data(3, "x", wire, sizeof(wire));
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);

    uint8_t extra[4] = { 0x00, 0x01, 0xaa, 0xbb };
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, extra, 4, false,
                                   3100);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(r.sess_ds->reset);
    WTQ_TEST_CHECK_EQ_HEX(r.sess_ds->reset_err, WTQ_H3_MESSAGE_ERROR);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* FIN with an incomplete capsule (all DATA frames complete): the
 * message is truncated mid-capsule -> H3_MESSAGE_ERROR. */
static void test_fin_mid_capsule(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t cap_buf[64];
    size_t clen = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_close(5, (const uint8_t *)"hello",
                                            5, cap_buf, sizeof(cap_buf),
                                            &clen) == 0);
    /* a complete DATA frame carrying only a capsule PREFIX */
    uint8_t wire[64];
    size_t wlen = build_data_frame(cap_buf, clen - 3, wire, sizeof(wire));
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, wlen, false,
                                   3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                   3100);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_MESSAGE_ERROR);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(!r.app.closed_clean);
    rig_down(&r);
    *fp += failures;
}

/* FIN mid-DATA-frame on the established session stream keeps the
 * frame-truncation rule (H3_FRAME_ERROR). */
static void test_fin_mid_data_frame(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t wire[8] = { 0x00, 0x0a, 0x01, 0x02 }; /* DATA len 10, 2 sent */
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, 4, false,
                                   3000);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, NULL, 0, true,
                                   3100);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn), WTQ_H3_FRAME_ERROR);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    rig_down(&r);
    *fp += failures;
}

/* --- terminal exactly-once under connection failure --------------------- */

/* An H3 connection error after establishment: on_session_closed
 * (unclean) fires exactly once and BEFORE on_conn_error. */
static void test_conn_error_closes_session(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* a forbidden frame on the session stream: FRAME_UNEXPECTED.
     * (Trailers are legal now — a malformed one is a STREAM error, so
     * it cannot drive this connection-error ordering check.) */
    uint8_t forbidden[2] = { 0x04, 0x00 }; /* SETTINGS on a request */
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, forbidden, 2, false,
                                   3000);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_FRAME_UNEXPECTED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(!r.app.closed_clean);
    WTQ_TEST_CHECK(r.app.closed_seq < r.app.error_seq);
    rig_down(&r);
    *fp += failures;
}

/* Transport-level close after establishment: terminal callback once. */
static void test_transport_close_closes_session(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    wtq_conn_on_conn_closed(r.conn, 0, true, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(!r.app.closed_clean);
    WTQ_TEST_CHECK(r.app.closed_seq < r.app.error_seq);
    rig_down(&r);
    *fp += failures;
}

/* --- local close / drain ------------------------------------------------ */

static void test_local_session_close(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    size_t wire_before = r.sess_ds->len;
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 42,
                                          (const uint8_t *)"done", 4) ==
                   WTQ_OK);

    /* terminal callback fired locally, exactly once, clean */
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.app.closed_code == 42);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.closed_reason_len, 4);
    WTQ_TEST_CHECK(r.app.closed_clean);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_CLOSED);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    /* wire: DATA frame wrapping the byte-exact CLOSE capsule, then FIN */
    uint8_t expect[64];
    size_t elen = build_close_in_data(42, "done", expect, sizeof(expect));
    WTQ_TEST_CHECK_EQ_SIZE(r.sess_ds->len - wire_before, elen);
    WTQ_TEST_CHECK(memcmp(r.sess_ds->bytes + wire_before, expect,
                          elen) == 0);
    WTQ_TEST_CHECK(r.sess_ds->fin);

    /* repeated close is a state error, no second event */
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 1, NULL, 0) ==
                   WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    rig_down(&r);
    *fp += failures;
}

static void test_local_session_close_bounds(int *fp)
{
    int failures = 0;
    rig_t r;
    static uint8_t big[1025];

    establish_server(&r, fp);
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 1, big, 1025) ==
                   WTQ_ERR_TOO_LARGE);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);
    rig_down(&r);
    *fp += failures;
}

static void test_local_session_close_before_establish(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) ==
                   WTQ_ERR_STATE);
    WTQ_TEST_CHECK(wtq_conn_session_drain(r.conn) == WTQ_ERR_STATE);
    rig_down(&r);
    *fp += failures;
}

static void test_local_drain(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    size_t wire_before = r.sess_ds->len;
    WTQ_TEST_CHECK(wtq_conn_session_drain(r.conn) == WTQ_OK);

    uint8_t expect[32];
    size_t elen = build_drain_in_data(expect, sizeof(expect));
    WTQ_TEST_CHECK_EQ_SIZE(r.sess_ds->len - wire_before, elen);
    WTQ_TEST_CHECK(memcmp(r.sess_ds->bytes + wire_before, expect,
                          elen) == 0);
    WTQ_TEST_CHECK(!r.sess_ds->fin);
    /* local state does not change; the session keeps working */
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                   WTQ_SESSION_ESTABLISHED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);
    rig_down(&r);
    *fp += failures;
}

/* --- rejected/dead request streams stay validated ----------------------- */

/* Policy: once a request stream is rejected, everything the peer keeps
 * sending on it is discarded WITHOUT frame-sequence rules (the bytes
 * were written before the peer could see the refusal), and its FIN
 * carries no truncation or completeness meaning. */
static void test_dead_stream_policy(int *fp)
{
    int failures = 0;

    /* 404-rejected stream: a forbidden frame behind the rejection is
     * discarded, never a connection error */
    {
        rig_t r;
        establish_server(&r, fp); /* uses path /moq */
        uint8_t req[512];
        size_t qlen = build_request(req, sizeof(req), "/nope", OFFER, 2);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen, false,
                                       3000);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

        uint8_t settings_frame[3] = { 0x04, 0x01, 0x00 };
        (void)wtq_conn_on_stream_bytes(r.conn, es, settings_frame, 3,
                                       false, 3100);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
        rig_down(&r);
    }
    /* 404-rejected stream: truncated FIN is tolerated */
    {
        rig_t r;
        establish_server(&r, fp);
        uint8_t req[512];
        size_t qlen = build_request(req, sizeof(req), "/nope", OFFER, 2);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen, false,
                                       3000);
        uint8_t partial[2] = { 0x00, 0x0a }; /* DATA declaring 10 */
        (void)wtq_conn_on_stream_bytes(r.conn, es, partial, 2, false,
                                       3100);
        (void)wtq_conn_on_stream_bytes(r.conn, es, NULL, 0, true, 3200);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);
        rig_down(&r);
    }
    *fp += failures;
}

/* Session-state walkthrough via the query. */
static void test_session_state_query(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_IDLE);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, false, 0 };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_PENDING);
    deliver_peer_settings(&r, fp);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_SENT);

    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
    (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, resp, rlen, false,
                                   2500);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                   WTQ_SESSION_ESTABLISHED);
    WTQ_TEST_CHECK(wtq_conn_session_id(r.conn) == bidi->id);
    rig_down(&r);
    *fp += failures;
}


/* --- pre-establishment connection death --------------------------------- */

/* Every connection death before establishment must give a session
 * outcome: state FAILED, exactly one on_session_failed(CONNECTION),
 * fired BEFORE on_conn_error. Nothing else must fire. */
static void expect_conn_failed(rig_t *r, int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK(wtq_conn_session_state(r->conn) ==
                   WTQ_SESSION_FAILED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r->app.failed_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r->app.failed_reason,
                          (int)WTQ_SESSION_FAIL_CONNECTION);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r->app.closed_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r->app.error_events, 1);
    WTQ_TEST_CHECK(r->app.failed_seq < r->app.error_seq);
    *fp += failures;
}

/* IDLE (nothing requested yet) and PENDING (awaiting peer SETTINGS). */
static void test_conn_lost_idle_and_pending(int *fp)
{
    int failures = 0;

    /* IDLE: a client that never called connect */
    {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_IDLE);
        wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
        expect_conn_failed(&r, fp);
        rig_down(&r);
    }
    /* PENDING: connect requested, peer SETTINGS never arrived */
    {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, OFFER, 2, false, 0 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_PENDING);
        wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
        expect_conn_failed(&r, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* SENT: the CONNECT went out, the response never came. */
static void test_conn_lost_sent(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, false, 0 };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
    deliver_peer_settings(&r, fp); /* releases the deferred CONNECT */
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_SENT);

    wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
    expect_conn_failed(&r, fp);
    rig_down(&r);
    *fp += failures;
}

/* A server before establishment, with and without a parked request. */
static void test_conn_lost_server(int *fp)
{
    int failures = 0;

    for (int parked = 0; parked < 2; parked++) {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
        wtq_server_path_cfg_t path = { "/moq", SUPPORTED, 2, false };
        WTQ_TEST_CHECK(wtq_conn_server_set_paths(r.conn, &path, 1) ==
                       WTQ_OK);
        if (parked) {
            /* a CONNECT arrives BEFORE the peer's SETTINGS: parked */
            uint8_t req[512];
            size_t qlen = build_request(req, sizeof(req), "/moq", OFFER,
                                        2);
            WTQ_TEST_CHECK(qlen > 0);
            struct wtq_dstream *ds =
                fake_driver_add_peer_stream(&r.drv, 0);
            wtq_estream_t *es = NULL;
            WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 0,
                                                        &es) == WTQ_OK);
            (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen, false,
                                           2500);
            WTQ_TEST_CHECK_EQ_U64(ds->len, 0); /* parked, unanswered */
        }
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_IDLE);

        wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
        expect_conn_failed(&r, fp);
        rig_down(&r);
    }
    *fp += failures;
}

/* A PROTOCOL-fatal death before establishment takes the same path. */
static void test_conn_fatal_before_establishment(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_client_connect_cfg_t cfg = {
        "example.com", "/moq", NULL, OFFER, 2, false, 0 };
    WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);

    /* the peer's control stream opens with a non-SETTINGS frame:
     * H3_MISSING_SETTINGS, a connection error */
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 3, &es) ==
                   WTQ_OK);
    uint8_t bad[3] = { 0x00, 0x07, 0x00 }; /* control type, GOAWAY */
    (void)wtq_conn_on_stream_bytes(r.conn, es, bad, 3, false, 2500);

    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    expect_conn_failed(&r, fp);
    rig_down(&r);
    *fp += failures;
}

/* An already-terminal session keeps its own outcome: the specific
 * reason stays authoritative and no second outcome fires. */
static void test_conn_lost_after_terminal(int *fp)
{
    int failures = 0;

    /* already FAILED (peer SETTINGS lack WT) */
    {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, OFFER, 2, false, 0 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
        deliver_peer_settings_nowt(&r, fp);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                              (int)WTQ_SESSION_FAIL_NO_WT_SUPPORT);

        wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
        /* the specific reason stands; no second outcome */
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.failed_events, 1);
        WTQ_TEST_CHECK_EQ_INT(r.app.failed_reason,
                              (int)WTQ_SESSION_FAIL_NO_WT_SUPPORT);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 1);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_FAILED);
        rig_down(&r);
    }
    /* already REJECTED (non-2xx response) */
    {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        wtq_client_connect_cfg_t cfg = {
            "example.com", "/moq", NULL, OFFER, 2, false, 0 };
        WTQ_TEST_CHECK(wtq_conn_client_connect(r.conn, &cfg) == WTQ_OK);
        deliver_peer_settings(&r, fp);
        struct wtq_dstream *bidi = find_local_bidi(&r);
        WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
        if (bidi != NULL && bidi->ectx != NULL) {
            uint8_t resp[256];
            size_t rlen = build_response(resp, sizeof(resp), 404, NULL);
            (void)wtq_conn_on_stream_bytes(r.conn, bidi->ectx, resp, rlen,
                                           false, 2600);
        }
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.rejected_events, 1);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_REJECTED);

        wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.failed_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 0);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.rejected_events, 1);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 1);
        WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) ==
                       WTQ_SESSION_REJECTED); /* not overwritten */
        rig_down(&r);
    }
    *fp += failures;
}

/* An ESTABLISHED session's death is unchanged: one unclean closed, then
 * on_conn_error, and never a failed callback. */
static void test_conn_lost_established_unchanged(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_conn_on_conn_closed(r.conn, 0x102, true, 3000);

    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(!r.app.closed_clean);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.failed_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 1);
    WTQ_TEST_CHECK(r.app.closed_seq < r.app.error_seq);
    WTQ_TEST_CHECK(wtq_conn_session_state(r.conn) == WTQ_SESSION_CLOSED);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_conn_lost_idle_and_pending(&failures);
    test_conn_lost_sent(&failures);
    test_conn_lost_server(&failures);
    test_conn_fatal_before_establishment(&failures);
    test_conn_lost_after_terminal(&failures);
    test_conn_lost_established_unchanged(&failures);

    test_post_close_drain(&failures);
    test_post_close_peer_close(&failures);
    test_post_close_unknown_capsule(&failures);
    test_post_close_malformed_capsule(&failures);
    test_post_close_fragmented_capsule(&failures);
    test_post_close_reentrant(&failures);
    test_post_close_fin_truncated_capsule(&failures);

    test_clean_fin_closes_session(&failures);
    test_connect_reset_closes_session(&failures);
    test_close_capsule(&failures);
    test_close_capsule_max_reason(&failures);
    test_close_capsule_every_split(&failures);
    test_multiple_capsules(&failures);
    test_drain_capsule(&failures);
    test_malformed_capsules(&failures);
    test_data_after_close_capsule(&failures);
    test_fin_mid_capsule(&failures);
    test_fin_mid_data_frame(&failures);
    test_conn_error_closes_session(&failures);
    test_transport_close_closes_session(&failures);
    test_local_session_close(&failures);
    test_local_session_close_bounds(&failures);
    test_local_session_close_before_establish(&failures);
    test_local_drain(&failures);
    test_dead_stream_policy(&failures);
    test_session_state_query(&failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_engine_session (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_engine_session\n");
    return 0;
}
