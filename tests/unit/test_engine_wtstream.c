#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "fake_driver.h"
#include "wt_driver.h"

#include <wtquic/stream.h> /* WTQ_STREAM_MAX_SPANS */

#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

#include "test_support.h"

/*
 * WT stream association: preamble demux for peer streams, payload
 * passthrough (zero copies, zero allocations), local stream opens, the
 * gather/completion send contract, and reset/stop code mapping.
 */

#define MAX_COOKIES 8
#define MAX_DATA_EVENTS 8

typedef struct app_state {
    int established_events;
    int error_events;
    uint64_t last_error;
    int closed_events;

    int wt_opened_events;
    wtq_estream_t *wt_last_es;
    bool wt_last_bidi;
    uint64_t wt_last_id;

    int wt_data_events;
    struct {
        const uint8_t *ptr; /* pointer identity: passthrough proof */
        size_t len;
        bool fin;
        uint8_t bytes[64];
    } data[MAX_DATA_EVENTS];

    int wt_reset_events;
    uint32_t wt_reset_code;
    int wt_stop_events;
    uint32_t wt_stop_code;
    int wt_terminal_events;
    wtq_estream_t *wt_terminal_es;

    struct {
        void *cookie;
        int completions;
        bool canceled;
    } cookies[MAX_COOKIES];
    size_t cookie_count;

    /* reentrant-callback fixtures */
    wtq_conn_t *stop_conn; /* when set with stop_on_fin: wt_stop from
                              inside on_wt_stream_data(fin=true) */
    bool stop_on_fin;
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
    st->wt_opened_events++;
    st->wt_last_es = es;
    st->wt_last_bidi = bidi;
    st->wt_last_id = id;
}

static void cb_wt_data(wtq_conn_t *c, wtq_estream_t *es,
                       const uint8_t *data, size_t len, bool fin,
                       void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    if (fin && st->stop_on_fin && st->stop_conn != NULL)
        (void)wtq_conn_wt_stop(st->stop_conn, es, 7);
    if (st->wt_data_events < MAX_DATA_EVENTS) {
        st->data[st->wt_data_events].ptr = data;
        st->data[st->wt_data_events].len = len;
        st->data[st->wt_data_events].fin = fin;
        if (len > 0 && len <= 64)
            memcpy(st->data[st->wt_data_events].bytes, data, len);
    }
    st->wt_data_events++;
}

static void cb_wt_reset(wtq_conn_t *c, wtq_estream_t *es,
                        uint32_t app_code, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)es;
    st->wt_reset_events++;
    st->wt_reset_code = app_code;
}

static void cb_wt_stop(wtq_conn_t *c, wtq_estream_t *es,
                       uint32_t app_code, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    (void)es;
    st->wt_stop_events++;
    st->wt_stop_code = app_code;
}

static void cb_wt_terminal(wtq_conn_t *c, wtq_estream_t *es, void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    st->wt_terminal_events++;
    st->wt_terminal_es = es;
}

static void cb_send_complete(wtq_conn_t *c, void *cookie, bool canceled,
                             void *ctx)
{
    app_state_t *st = ctx;

    (void)c;
    for (size_t i = 0; i < st->cookie_count; i++)
        if (st->cookies[i].cookie == cookie) {
            st->cookies[i].completions++;
            st->cookies[i].canceled = canceled;
            return;
        }
    if (st->cookie_count < MAX_COOKIES) {
        st->cookies[st->cookie_count].cookie = cookie;
        st->cookies[st->cookie_count].completions = 1;
        st->cookies[st->cookie_count].canceled = canceled;
        st->cookie_count++;
    }
}

/* completions for a cookie (0 when never seen) */
static int completions_for(const app_state_t *st, void *cookie,
                           bool *canceled_out)
{
    for (size_t i = 0; i < st->cookie_count; i++)
        if (st->cookies[i].cookie == cookie) {
            if (canceled_out != NULL)
                *canceled_out = st->cookies[i].canceled;
            return st->cookies[i].completions;
        }
    return 0;
}

/* --- counting allocator (zero-steady-state-alloc proof) ----------------- */

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
                       .on_wt_stream_data = cb_wt_data,
                       .on_wt_stream_reset = cb_wt_reset,
                       .on_wt_stream_stop = cb_wt_stop,
                       .on_wt_send_complete = cb_send_complete,
                       .on_wt_stream_terminal = cb_wt_terminal,
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
    WTQ_TEST_CHECK(r->ca.allocs == r->ca.frees); /* balance 0 */
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

static void establish_server(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_SERVER, fp);
    wtq_server_path_cfg_t path = { "/moq", OFFER, 1, false };
    WTQ_TEST_CHECK(wtq_conn_server_set_paths(r->conn, &path, 1) ==
                   WTQ_OK);
    deliver_peer_settings(r, fp);
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq");
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

/* Encode the association preamble for a peer stream. */
static size_t enc_preamble(bool bidi, uint64_t sid, uint8_t *dst,
                           size_t cap)
{
    size_t n = 0;

    if (wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                 : WTQ_PREAMBLE_KIND_UNI,
                            sid, dst, cap, &n) != 0)
        return 0;
    return n;
}

/* --- peer WT stream demux ----------------------------------------------- */

/* Peer uni WT stream, preamble split at every byte: the stream opens
 * exactly once, only after the full preamble. */
static void test_peer_uni_preamble_split(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t pre[16];
    size_t plen = enc_preamble(false, sid, pre, sizeof(pre));
    WTQ_TEST_CHECK(plen == 3); /* 2-byte type + 1-byte sid 0 */
    if (plen != 3) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }

    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 3 + 4);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 3 + 4, &es) ==
                   WTQ_OK);
    for (size_t i = 0; i < plen; i++) {
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre + i, 1, false,
                                       3000 + i);
    }
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    WTQ_TEST_CHECK(!r.app.wt_last_bidi);
    WTQ_TEST_CHECK(r.app.wt_last_id == 3 + 4);

    /* payload passthrough */
    uint8_t payload[4] = { 'p', 'i', 'n', 'g' };
    (void)wtq_conn_on_stream_bytes(r.conn, es, payload, 4, true, 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.data[0].len, 4);
    WTQ_TEST_CHECK(r.app.data[0].fin);
    WTQ_TEST_CHECK(memcmp(r.app.data[0].bytes, "ping", 4) == 0);
    WTQ_TEST_CHECK(r.app.data[0].ptr == payload); /* zero copy */
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* Peer bidi WT stream (server-initiated toward the client), preamble
 * split at every byte; payload in the same delivery as the preamble
 * tail is delivered without copying. */
static void test_peer_bidi_preamble_split(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t wire[32];
    size_t plen = enc_preamble(true, sid, wire, sizeof(wire));
    WTQ_TEST_CHECK(plen == 3);
    if (plen != 3) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }
    memcpy(wire + plen, "hello", 5);

    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    /* first two preamble bytes one at a time */
    for (size_t i = 0; i < plen - 1; i++) {
        (void)wtq_conn_on_stream_bytes(r.conn, es, wire + i, 1, false,
                                       3000 + i);
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
    }
    /* preamble tail + payload in one delivery */
    (void)wtq_conn_on_stream_bytes(r.conn, es, wire + plen - 1, 1 + 5,
                                   false, 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    WTQ_TEST_CHECK(r.app.wt_last_bidi);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.data[0].len, 5);
    WTQ_TEST_CHECK(memcmp(r.app.data[0].bytes, "hello", 5) == 0);
    /* pointer identity into the caller's buffer (offset past the
     * preamble byte consumed from this chunk) */
    WTQ_TEST_CHECK(r.app.data[0].ptr == wire + plen);
    rig_down(&r, fp);
    *fp += failures;
}

/* A client-initiated WT bidi stream demuxes on the server. */
static void test_server_peer_bidi_wt(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    WTQ_TEST_CHECK(sid == 0);
    uint8_t wire[32];
    size_t plen = enc_preamble(true, sid, wire, sizeof(wire));
    memcpy(wire + plen, "up", 2);

    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, wire, plen + 2, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    WTQ_TEST_CHECK(r.app.wt_last_bidi);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK(memcmp(r.app.data[0].bytes, "up", 2) == 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* Zero-length WT stream: preamble + FIN, no payload. */
static void test_wt_stream_empty_fin(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 6);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 6, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, true, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.app.data[0].len, 0);
    WTQ_TEST_CHECK(r.app.data[0].fin);
    rig_down(&r, fp);
    *fp += failures;
}

/* A non-WT bidi stream toward the CLIENT is still a connection error
 * (H3 never negotiates server-initiated bidi). */
static void test_client_bidi_not_wt(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    uint8_t headers[2] = { 0x01, 0x00 };
    (void)wtq_conn_on_stream_bytes(r.conn, es, headers, 2, false, 3000);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                          WTQ_H3_STREAM_CREATION_ERROR);
    rig_down(&r, fp);
    *fp += failures;
}

/* The server's bidi classifier must REPLAY non-WT first bytes into the
 * request walk: a second CONNECT still gets rejected exactly as before
 * even though classification now happens first. */
static void test_server_bidi_request_replay(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq");
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                   WTQ_OK);
    /* one byte at a time through the classification boundary */
    for (size_t i = 0; i < qlen; i++)
        (void)wtq_conn_on_stream_bytes(r.conn, es, req + i, 1, false,
                                       3000 + i);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(ds->reset);
    WTQ_TEST_CHECK_EQ_HEX(ds->reset_err, WTQ_H3_REQUEST_REJECTED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* Unknown peer uni types are still drained quietly. */
static void test_unknown_uni_still_drained(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    uint8_t junk[8] = { 0x21, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22 };
    (void)wtq_conn_on_stream_bytes(r.conn, es, junk, 8, false, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- session-id validation ---------------------------------------------- */

/* WT stream before any session: rejected deterministically with
 * WT_BUFFERED_STREAM_REJECTED (we buffer zero streams; draft-15 s4.6
 * requires only a limit). Uni gets STOP_SENDING; bidi both directions. */
static void test_wt_stream_before_session(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_SERVER, fp);
    deliver_peer_settings(&r, fp);

    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *uni = fake_driver_add_peer_stream(&r.drv, 2);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, uni, 2, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(uni->stopped);
    WTQ_TEST_CHECK_EQ_HEX(uni->stop_err, WTQ_WT_BUFFERED_STREAM_REJECTED);
    WTQ_TEST_CHECK(!uni->reset); /* peer uni has no local send side */
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);

    plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *bidi = fake_driver_add_peer_stream(&r.drv, 0);
    es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, bidi, 0, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3100);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(bidi->stopped && bidi->reset);
    WTQ_TEST_CHECK_EQ_HEX(bidi->stop_err,
                          WTQ_WT_BUFFERED_STREAM_REJECTED);
    WTQ_TEST_CHECK_EQ_HEX(bidi->reset_err,
                          WTQ_WT_BUFFERED_STREAM_REJECTED);
    rig_down(&r, fp);
    *fp += failures;
}

/* A session id that is not THE session: same deterministic rejection. */
static void test_wt_stream_wrong_sid(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 4, pre, sizeof(pre)); /* sid 4 != 0 */
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_HEX(ds->stop_err, WTQ_WT_BUFFERED_STREAM_REJECTED);
    /* association demotion is ONE whole-stream transaction: the peer
     * uni's only (receive) half, exact wire code */
    WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
    WTQ_TEST_CHECK(ds->last_shutdown.mode == WTQ_SHUTDOWN_WHOLE_STREAM);
    WTQ_TEST_CHECK(ds->last_shutdown.abort_recv &&
                   !ds->last_shutdown.abort_send);
    WTQ_TEST_CHECK_EQ_HEX(ds->last_shutdown.recv_err,
                          WTQ_WT_BUFFERED_STREAM_REJECTED);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* A WT stream for the TERMINATED session: WT_SESSION_GONE. */
static void test_wt_stream_after_close(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) == WTQ_OK);

    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_HEX(ds->stop_err, WTQ_WT_SESSION_GONE);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- preamble FIN/reset edges ------------------------------------------- */

static void test_preamble_fin_edges(int *fp)
{
    int failures = 0;

    /* uni FIN mid-preamble: tolerated (RFC 9114 s6.2 MUST) */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t pre[3] = { 0x40, 0x54, 0x00 };
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, 2, true, 3000);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
        rig_down(&r, fp);
    }
    /* bidi FIN mid-session-id (0x41 seen): truncated association */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t pre[2] = { 0x40, 0x41 };
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, 2, true, 3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_FRAME_ERROR);
        rig_down(&r, fp);
    }
    /* bidi FIN before the type completes: client = creation error */
    {
        rig_t r;
        establish_client(&r, fp);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, NULL, 0, true, 3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_STREAM_CREATION_ERROR);
        rig_down(&r, fp);
    }
    /* bidi FIN before the type completes: server = incomplete request */
    {
        rig_t r;
        establish_server(&r, fp);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, NULL, 0, true, 3000);
        WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_HEX(wtq_conn_close_code(r.conn),
                              WTQ_H3_REQUEST_INCOMPLETE);
        rig_down(&r, fp);
    }
    /* reset mid-preamble: silent release, no callbacks */
    {
        rig_t r;
        establish_client(&r, fp);
        uint8_t pre[1] = { 0x40 };
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                       WTQ_OK);
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, 1, false, 3000);
        (void)wtq_conn_on_stream_reset(r.conn, es, 0, 3100);
        WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 0);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* --- WT stream reset/stop code mapping ---------------------------------- */

static void test_wt_reset_mapping(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    /* in-range wire code maps to the app error */
    (void)wtq_conn_on_stream_reset(r.conn, r.app.wt_last_es,
                                   wtq_app_error_to_h3(1234), 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 1);
    WTQ_TEST_CHECK(r.app.wt_reset_code == 1234);

    /* out-of-range wire code delivers app code 0 */
    plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *b = fake_driver_add_peer_stream(&r.drv, 1);
    es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, b, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3200);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 2);
    (void)wtq_conn_on_stream_reset(r.conn, r.app.wt_last_es, 0x10, 3300);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 2);
    WTQ_TEST_CHECK(r.app.wt_reset_code == 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- local WT streams + the gather/completion contract ------------------ */

static void test_wt_open_local(int *fp)
{
    int failures = 0;
    rig_t r;

    /* pre-establishment opens are a state error */
    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_ERR_STATE);
    rig_down(&r, fp);

    establish_client(&r, fp);
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    WTQ_TEST_CHECK(es != NULL);
    struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
    /* locals 0..3: control, qpack enc, qpack dec, CONNECT */
    WTQ_TEST_CHECK(uni != NULL && !uni->is_bidi);
    if (uni == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    uint8_t expect[8];
    size_t plen = enc_preamble(false, wtq_conn_session_id(r.conn), expect,
                               sizeof(expect));
    WTQ_TEST_CHECK_EQ_SIZE(uni->len, plen);
    WTQ_TEST_CHECK(memcmp(uni->bytes, expect, plen) == 0);

    wtq_estream_t *bes = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &bes) == WTQ_OK);
    struct wtq_dstream *bidi = fake_driver_local(&r.drv, 5);
    WTQ_TEST_CHECK(bidi != NULL && bidi->is_bidi);
    if (bidi == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    plen = enc_preamble(true, wtq_conn_session_id(r.conn), expect,
                        sizeof(expect));
    WTQ_TEST_CHECK_EQ_SIZE(bidi->len, plen);
    WTQ_TEST_CHECK(memcmp(bidi->bytes, expect, plen) == 0);

    /* user ctx roundtrip */
    int marker = 7;
    wtq_estream_set_user(es, &marker);
    WTQ_TEST_CHECK(wtq_estream_get_user(es) == &marker);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_wt_send_success(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(uni != NULL);
    if (uni == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }
    size_t pre_len = uni->len;

    static const uint8_t a[3] = { 1, 2, 3 };
    static const uint8_t b[2] = { 4, 5 };
    wtq_span_t spans[2] = { { a, 3 }, { b, 2 } };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, spans, 2, true,
                                    &cookie) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(uni->len - pre_len, 5);
    WTQ_TEST_CHECK(memcmp(uni->bytes + pre_len, "\x01\x02\x03\x04\x05",
                          5) == 0);
    WTQ_TEST_CHECK(uni->fin);

    /* completion: exactly once, not canceled */
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, NULL) == 0);
    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 1);
    bool canceled = true;
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
    WTQ_TEST_CHECK(!canceled);
    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 0);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_wt_send_errors(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* receive-only stream: peer uni */
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    static const uint8_t p[1] = { 9 };
    wtq_span_t span = { p, 1 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    false, &cookie) == WTQ_ERR_STATE);

    /* failed transport send: no completion ever fires */
    wtq_estream_t *les = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &les) == WTQ_OK);
    r.drv.fail_send = true;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &span, 1, false,
                                    &cookie) == WTQ_ERR_WOULD_BLOCK);
    r.drv.fail_send = false;
    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 0);
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, NULL) == 0);

    /* the documented span contract (stream.h): a count beyond
     * WTQ_STREAM_MAX_SPANS is refused BEFORE the array is read (the
     * one-element array is legal exactly because rejection precedes
     * traversal); a nonempty span without data is malformed; hostile
     * lengths must not wrap the aggregate */
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &span,
                                    (size_t)WTQ_STREAM_MAX_SPANS + 1,
                                    false,
                                    &cookie) == WTQ_ERR_INVALID_ARG);
    wtq_span_t nodata = { NULL, 3 };
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &nodata, 1, false,
                                    &cookie) == WTQ_ERR_INVALID_ARG);
    wtq_span_t wrap[2] = { { p, SIZE_MAX }, { p, 2 } };
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, wrap, 2, false,
                                    &cookie) == WTQ_ERR_TOO_LARGE);
    /* the same nonempty-data rule for datagram spans */
    WTQ_TEST_CHECK(wtq_conn_dgram_send(r.conn, &nodata, 1) ==
                   WTQ_ERR_INVALID_ARG);
    /* nothing above was accepted: zero completions owed */
    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 0);
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, NULL) == 0);
    rig_down(&r, fp);
    *fp += failures;
}

/* Local reset cancels the pending completion (exactly once, canceled),
 * and the wire carries the mapped WT application error. */
static void test_wt_send_then_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(uni != NULL);
    if (uni == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }

    static const uint8_t p[4] = { 1, 2, 3, 4 };
    wtq_span_t span = { p, 4 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, false,
                                    &cookie) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, es, 555) == WTQ_OK);
    WTQ_TEST_CHECK(uni->reset);
    WTQ_TEST_CHECK_EQ_HEX(uni->reset_err, wtq_app_error_to_h3(555));

    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 1);
    bool canceled = false;
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
    WTQ_TEST_CHECK(canceled);
    rig_down(&r, fp);
    *fp += failures;
}

/* Session close tears down WT streams (reset/stop with SESSION_GONE)
 * and cancels pending sends. */
static void test_session_close_teardown(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* one local uni (send side), one peer uni (receive side) */
    wtq_estream_t *les = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &les) == WTQ_OK);
    struct wtq_dstream *luni = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(luni != NULL);
    if (luni == NULL) {
        rig_down(&r, fp);
        *fp += failures + 1;
        return;
    }

    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *puni = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, puni, 7, &pes) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, pes, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    static const uint8_t p[2] = { 8, 9 };
    wtq_span_t span = { p, 2 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &span, 1, false,
                                    &cookie) == WTQ_OK);

    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 1, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK(luni->reset);
    WTQ_TEST_CHECK_EQ_HEX(luni->reset_err, WTQ_WT_SESSION_GONE);
    WTQ_TEST_CHECK(puni->stopped);
    WTQ_TEST_CHECK_EQ_HEX(puni->stop_err, WTQ_WT_SESSION_GONE);

    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 1);
    bool canceled = false;
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
    WTQ_TEST_CHECK(canceled);

    /* the dead session refuses new work */
    wtq_estream_t *es2 = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es2) == WTQ_ERR_STATE);
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &span, 1, false,
                                    &cookie) == WTQ_ERR_CLOSED);
    rig_down(&r, fp);
    *fp += failures;
}

/* Connection close with a send in flight: the completion still reaches
 * the app exactly once (canceled). */
static void test_wt_send_then_conn_close(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    static const uint8_t p[2] = { 6, 7 };
    wtq_span_t span = { p, 2 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, false,
                                    &cookie) == WTQ_OK);

    /* force a connection error: a forbidden frame on the session
     * stream (a malformed trailer would only be a STREAM error) */
    uint8_t forbidden[2] = { 0x04, 0x00 }; /* SETTINGS on a request */
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, forbidden, 2, false,
                                   3000);
    WTQ_TEST_CHECK(wtq_conn_is_closed(r.conn));

    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn), 1);
    bool canceled = false;
    WTQ_TEST_CHECK(completions_for(&r.app, &cookie, &canceled) == 1);
    WTQ_TEST_CHECK(canceled);
    rig_down(&r, fp);
    *fp += failures;
}

/* wt_stop maps the app code onto STOP_SENDING; the peer's STOP_SENDING
 * input surfaces as on_wt_stream_stop with the mapped code and the
 * stream stays usable. */
static void test_wt_stop_paths(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* local stop of a peer uni */
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *puni = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, puni, 7, &pes) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, pes, pre, plen, false, 3000);
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 99) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(puni->stopped);
    WTQ_TEST_CHECK_EQ_HEX(puni->stop_err, wtq_app_error_to_h3(99));

    /* peer STOP_SENDING against a local uni */
    wtq_estream_t *les = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &les) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stop_sending(r.conn, les,
                                            wtq_app_error_to_h3(42),
                                            3100) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_stop_events, 1);
    WTQ_TEST_CHECK(r.app.wt_stop_code == 42);
    /* still usable: a send after stop is legal until reset */
    static const uint8_t p[1] = { 1 };
    wtq_span_t span = { p, 1 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &span, 1, false,
                                    &cookie) == WTQ_OK);
    rig_down(&r, fp);
    *fp += failures;
}

/* Draining still allows opens and sends (draft-15 s4.7). */
static void test_draining_still_works(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* receive DRAIN */
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

    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    static const uint8_t p[1] = { 2 };
    wtq_span_t span = { p, 1 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, true,
                                    &cookie) == WTQ_OK);
    rig_down(&r, fp);
    *fp += failures;
}

/* The whole data path allocates nothing after connection create. */
static void test_zero_alloc_data_path(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    int allocs_after_establish = r.ca.allocs;

    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    static const uint8_t p[16] = { 0 };
    wtq_span_t span = { p, 16 };
    int cookie = 0;
    for (int i = 0; i < 100; i++) {
        struct wtq_dstream *uni = fake_driver_local(&r.drv, 4);
        if (uni == NULL)
            break;
        uni->len = 0; /* recycle the fake's wire log */
        WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, false,
                                        &cookie) == WTQ_OK);
        (void)fake_driver_complete_sends(&r.drv, r.conn);
    }
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *b = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *bes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, b, 1, &bes) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, bes, pre, plen, false, 4000);
    uint8_t payload[32] = { 0 };
    for (int i = 0; i < 100; i++)
        (void)wtq_conn_on_stream_bytes(r.conn, bes, payload, 32, false,
                                       4100 + i);
    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) == WTQ_OK);

    WTQ_TEST_CHECK(r.ca.allocs == allocs_after_establish);
    WTQ_TEST_CHECK(r.ca.allocs == 1); /* the connection itself */
    rig_down(&r, fp);
    *fp += failures;
}

/* --- per-direction WT stream lifetime ----------------------------------- */

/* Bidi half-close: the peer's FIN closes only the receive side; the
 * app can still answer on its send side, and the estream is released
 * only when BOTH directions are done. */
static void test_bidi_half_close(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t wire[32];
    size_t plen = enc_preamble(true, 0, wire, sizeof(wire));
    memcpy(wire + plen, "req", 3);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, wire, plen + 3, true,
                                   3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK(r.app.data[0].fin);

    /* receive side closed by FIN; the send side must still work */
    static const uint8_t resp[4] = { 'r', 'e', 's', 'p' };
    wtq_span_t span = { resp, 4 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    true, &cookie) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(ds->len, 4);
    WTQ_TEST_CHECK(memcmp(ds->bytes, "resp", 4) == 0);
    WTQ_TEST_CHECK(ds->fin);

    /* fin=true closed the send side too: no further sends */
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    false, &cookie) == WTQ_ERR_STATE);
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* wt_send(fin=true) closes the send side on a local uni stream. */
static void test_send_fin_closes_send_side(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es) == WTQ_OK);
    static const uint8_t p[2] = { 1, 2 };
    wtq_span_t span = { p, 2 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, true,
                                    &cookie) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es, &span, 1, false,
                                    &cookie) == WTQ_ERR_STATE);
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* A local reset closes the send side but preserves the receive side
 * of a bidi stream. */
static void test_reset_preserves_receive(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    WTQ_TEST_CHECK(wtq_conn_wt_reset(r.conn, r.app.wt_last_es, 5) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(ds->reset);

    /* no further sends after the reset */
    static const uint8_t p[1] = { 9 };
    wtq_span_t span = { p, 1 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    false, &cookie) == WTQ_ERR_STATE);

    /* the receive side keeps delivering until FIN */
    uint8_t payload[3] = { 'a', 'b', 'c' };
    (void)wtq_conn_on_stream_bytes(r.conn, r.app.wt_last_es, payload, 3,
                                   false, 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 1);
    WTQ_TEST_CHECK(memcmp(r.app.data[0].bytes, "abc", 3) == 0);
    (void)wtq_conn_on_stream_bytes(r.conn, r.app.wt_last_es, NULL, 0,
                                   true, 3200);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* A peer reset of a bidi stream closes only the receive side: the
 * estream stays valid through (and after) on_wt_stream_reset, and the
 * send side still accepts data. */
static void test_peer_reset_bidi_send_survives(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    (void)wtq_conn_on_stream_reset(r.conn, r.app.wt_last_es,
                                   wtq_app_error_to_h3(3), 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 1);
    WTQ_TEST_CHECK(r.app.wt_reset_code == 3);

    static const uint8_t p[2] = { 7, 8 };
    wtq_span_t span = { p, 2 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    true, &cookie) == WTQ_OK);
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* wt_stop closes the receive side exactly once: repeat stops are
 * state errors, and late in-flight bytes are absorbed quietly (QUIC
 * keeps delivering until the peer's RESET answers our STOP_SENDING)
 * without reaching on_wt_stream_data. */
static void test_wt_stop_closes_receive(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 11) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(ds->stop_count == 1);
    /* the receive side is closed: a second stop is a state error */
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 11) ==
                   WTQ_ERR_STATE);
    WTQ_TEST_CHECK(ds->stop_count == 1);

    /* late in-flight bytes + FIN: absorbed, no callbacks, no errors */
    uint8_t late[4] = { 1, 2, 3, 4 };
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, r.app.wt_last_es,
                                            late, 4, false, 3100) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, r.app.wt_last_es,
                                            NULL, 0, true, 3200) ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* The peer's RESET answering our STOP is also absorbed quietly: the
 * receive side already closed once, so no on_wt_stream_reset fires. */
static void test_wt_stop_then_peer_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 11) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, r.app.wt_last_es,
                                            wtq_app_error_to_h3(11),
                                            3100) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* Stopping a bidi's receive side leaves the send side fully usable
 * while late peer bytes drain quietly. */
static void test_wt_stop_bidi_send_survives(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);

    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 11) ==
                   WTQ_OK);
    /* late peer bytes: drained */
    uint8_t late[2] = { 1, 2 };
    (void)wtq_conn_on_stream_bytes(r.conn, r.app.wt_last_es, late, 2,
                                   false, 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 0);
    /* the send side still accepts data */
    static const uint8_t p[2] = { 7, 8 };
    wtq_span_t span = { p, 2 };
    int cookie = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, r.app.wt_last_es, &span, 1,
                                    false, &cookie) == WTQ_OK);
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* Session close never re-stops a receive side the app already
 * stopped. */
static void test_wt_stop_no_duplicate_on_session_close(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK(wtq_conn_wt_stop(r.conn, r.app.wt_last_es, 11) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(ds->stop_count == 1);

    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) == WTQ_OK);
    /* the still-open send side gets its SESSION_GONE reset, but the
     * already-stopped receive side is NOT stopped again */
    WTQ_TEST_CHECK(ds->reset);
    WTQ_TEST_CHECK_EQ_HEX(ds->reset_err, WTQ_WT_SESSION_GONE);
    WTQ_TEST_CHECK(ds->stop_count == 1);
    rig_down(&r, fp);
    *fp += failures;
}

/* Session teardown must not force-free stream slots: the backend can
 * still deliver in-flight bytes against the old ectx after the
 * SESSION_GONE reset/stop, and the slot must not be reused while it
 * can. Streams drain quietly until the peer's FIN/RESET lands. */
static void test_session_close_leaves_absorbers(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(false, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    wtq_estream_t *old_es = r.app.wt_last_es;

    WTQ_TEST_CHECK(wtq_conn_session_close(r.conn, 0, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK(ds->stopped);
    WTQ_TEST_CHECK_EQ_HEX(ds->stop_err, WTQ_WT_SESSION_GONE);

    /* a NEW peer stream must not land in the still-draining slot */
    struct wtq_dstream *nds = fake_driver_add_peer_stream(&r.drv, 11);
    wtq_estream_t *nes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, nds, 11, &nes) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(nes != NULL && nes != old_es);

    /* late in-flight bytes + FIN against the old ectx: absorbed */
    uint8_t late[3] = { 1, 2, 3 };
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, old_es, late, 3,
                                            false, 3100) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, old_es, NULL, 0,
                                            true, 3200) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* The same absorber discipline when the PEER terminates the session
 * with a CLOSE capsule, with the peer's RESET clearing the drain. */
static void test_peer_close_leaves_absorbers(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    uint8_t pre[8];
    size_t plen = enc_preamble(true, 0, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 4);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 4, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    wtq_estream_t *old_es = r.app.wt_last_es;

    /* peer CLOSE capsule terminates the session */
    uint8_t cap_buf[64];
    size_t clen = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_close(9, NULL, 0, cap_buf,
                                            sizeof(cap_buf), &clen) == 0);
    uint8_t wire[64];
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, clen,
                                              wire, sizeof(wire),
                                              &hl) == 0);
    memcpy(wire + hl, cap_buf, clen);
    (void)wtq_conn_on_stream_bytes(r.conn, r.sess_es, wire, hl + clen,
                                   false, 3100);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(ds->reset && ds->stopped);

    /* late bytes against the torn-down stream: absorbed quietly */
    uint8_t late[2] = { 5, 6 };
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, old_es, late, 2,
                                            false, 3200) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events, 0);
    /* the peer's RESET clears the drain without a reset callback */
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, old_es,
                                            WTQ_WT_SESSION_GONE,
                                            3300) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/*
 * wtq_conn_on_stream_terminal contract: whole-stream transport
 * certainty resolves TRANSPORT-WAITING absorbers (an abort's receive
 * drain, an ES_DRAIN sink, a dead request-stream absorber) — release +
 * exactly-once detach — while live streams, criticals, and the CONNECT
 * stream are untouched. Stale input (a released slot) is INVALID_ARG,
 * matching the reset input.
 */
static void test_terminal_resolves_abort_drain(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &es) == WTQ_OK);
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r.drv.streams[i].in_use && r.drv.streams[i].is_local &&
            r.drv.streams[i].is_bidi && &r.drv.streams[i] != r.sess_ds)
            ds = &r.drv.streams[i];
    WTQ_TEST_CHECK(ds != NULL);
    if (es == NULL || ds == NULL) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }
    /* whole-stream abort: both halves close; the receive side becomes
     * a drain awaiting a peer answer the transport may never deliver */
    WTQ_TEST_CHECK(wtq_conn_wt_abort(r.conn, es, 7) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 0);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 1); /* exactly once */
    /* the abort already terminaled the app view: no duplicate */
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_terminal_events, 0);
    /* the slot released: stale re-delivery is INVALID_ARG */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

static void test_terminal_releases_es_drain(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* unknown uni type: classified into an ES_DRAIN byte sink */
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 7);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, 7, &es) ==
                   WTQ_OK);
    uint8_t unknown_type = 0x2a;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es, &unknown_type, 1,
                                            false, 3000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 0);
    /* the transport stream ceased whole (e.g. a local reject cancel
     * whose peer answer can never be delivered): the sink releases */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 1);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) ==
                   WTQ_ERR_INVALID_ARG);
    /* the slot is reusable by a new peer stream */
    struct wtq_dstream *nds = fake_driver_add_peer_stream(&r.drv, 11);
    wtq_estream_t *nes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, nds, 11, &nes) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(nes != NULL);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

static void test_terminal_releases_request_dead(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    /* a SECOND CONNECT request: rejected, the stream becomes a dead
     * request absorber (we sent our refusal; the absorber waits out
     * the peer) */
    uint8_t req[512];
    size_t qlen = build_request(req, sizeof(req), "/moq");
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 8);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 8, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, req, qlen, false, 3000);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 0);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 1);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, es) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* Whole terminal on a LIVE stream (both halves open): the remaining
 * halves close, the app sees ONE terminal notification, no reset or
 * stop is fabricated, the estream releases exactly once, and the
 * connection stays fully usable. */
static void test_terminal_closes_live(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t pre[16];
    size_t plen = enc_preamble(true, sid, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_opened_events, 1);
    wtq_estream_t *wt = r.app.wt_last_es;
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, wt) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_terminal_events, 1);
    WTQ_TEST_CHECK(r.app.wt_terminal_es == wt);
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_reset_events, 0); /* nothing forged */
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_stop_events, 0);
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 1); /* released, once */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, wt) ==
                   WTQ_ERR_INVALID_ARG); /* stale after release */

    /* the CONNECT stream stays untouched */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, r.sess_es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_session_established(r.conn));
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));

    /* the connection remains fully usable: open and use another */
    wtq_estream_t *les = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &les) == WTQ_OK);
    static const uint8_t p2[1] = { 7 };
    wtq_span_t sp2 = { p2, 1 };
    int cookie2 = 0;
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, les, &sp2, 1, false,
                                    &cookie2) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(fake_driver_complete_sends(&r.drv, r.conn),
                           1);

    /* argument contract */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(NULL, wt) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, NULL) ==
                   WTQ_ERR_INVALID_ARG);
    rig_down(&r, fp);
    *fp += failures;
}

/* Peer reset closed the receive half through the NORMAL event; the
 * whole terminal then closes the remaining send half: one terminal
 * notification, one release, no duplicates. */
static void test_terminal_after_peer_reset(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t pre[16];
    size_t plen = enc_preamble(true, sid, pre, sizeof(pre));
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 1);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, 1, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false, 3000);
    wtq_estream_t *wt = r.app.wt_last_es;
    WTQ_TEST_CHECK(wtq_conn_on_stream_reset(r.conn, wt, 0x77, 3100) ==
                   WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_reset_events, 1); /* the real one */
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 0); /* send half lives */
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, wt) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_terminal_events, 1);
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_reset_events, 1); /* no second */
    WTQ_TEST_CHECK_EQ_INT(ds->detach_count, 1);
    WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(r.conn, wt) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* Pool boundedness under terminal churn: peer streams live -> whole
 * terminal, far beyond the pool size — every slot recycles. */
static void test_terminal_slot_churn(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t pre[16];
    size_t plen = enc_preamble(true, sid, pre, sizeof(pre));
    for (int i = 0; i < 40; i++) {
        uint64_t id = 1 + 4u * (unsigned)i;
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, id);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(wtq_conn_on_peer_bidi_opened(r.conn, ds, id,
                                                    &es) == WTQ_OK);
        if (es == NULL)
            break;
        (void)wtq_conn_on_stream_bytes(r.conn, es, pre, plen, false,
                                       3000 + i);
        WTQ_TEST_CHECK(wtq_conn_on_stream_terminal(
                           r.conn, r.app.wt_last_es) == WTQ_OK);
        ds->in_use = false; /* the transport slot recycles too */
    }
    WTQ_TEST_CHECK_EQ_INT(r.app.wt_terminal_events, 40);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* Backends must provide every unconditionally-used op. */
static void test_create_requires_ops(int *fp)
{
    int failures = 0;
    struct wtq_driver drv;
    app_state_t app;
    wtq_conn_t *conn = NULL;

    memset(&app, 0, sizeof(app));
    fake_driver_init(&drv, true);
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .enable_connect_protocol = true,
        .callbacks = { .ctx = &app },
    };
    const wtq_driver_ops_t *full = fake_driver_ops();
    struct {
        size_t offset;
    } required[] = {
        { offsetof(wtq_driver_ops_t, open_uni) },
        { offsetof(wtq_driver_ops_t, open_bidi) },
        { offsetof(wtq_driver_ops_t, send) },
        { offsetof(wtq_driver_ops_t, shutdown_stream) },
        { offsetof(wtq_driver_ops_t, conn_close) },
        { offsetof(wtq_driver_ops_t, detach) },
    };
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        wtq_driver_ops_t partial;
        memcpy(&partial, full, sizeof(partial));
        memset((uint8_t *)&partial + required[i].offset, 0,
               sizeof(void (*)(void)));
        WTQ_TEST_CHECK(wtq_conn_create(&cfg, &drv, &partial, &conn) ==
                       WTQ_ERR_INVALID_ARG);
    }
    /* send_gather stays optional */
    wtq_driver_ops_t no_gather;
    memcpy(&no_gather, full, sizeof(no_gather));
    no_gather.send_gather = NULL;
    WTQ_TEST_CHECK(wtq_conn_create(&cfg, &drv, &no_gather, &conn) ==
                   WTQ_OK);
    wtq_conn_destroy(conn);
    *fp += failures;
}

/* --- estream detachment seam -------------------------------------------- */

/* The fake local dstream whose engine ctx is es (NULL if none). */
static struct wtq_dstream *local_ds_for(rig_t *r, wtq_estream_t *es)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].ectx == es)
            return &r->drv.streams[i];
    return NULL;
}

/* A freed-and-reused estream slot must be unreachable through the OLD
 * transport stream. Local uni: the FIN-accept frees the slot while the
 * gather is still in flight; the peer's late STOP_SENDING lands on the
 * old dstream and must deliver nothing. */
static void test_stale_stop_after_slot_reuse(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es1 = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es1) == WTQ_OK);
    struct wtq_dstream *ds1 = local_ds_for(&r, es1);
    WTQ_TEST_CHECK(ds1 != NULL);
    if (ds1 == NULL) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }
    /* bare FIN: send side closes on accept; uni recv was born closed —
     * the slot is released with the gather still pending */
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es1, NULL, 0, true,
                                    (void *)&r) == WTQ_OK);

    wtq_estream_t *es2 = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_uni(r.conn, &es2) == WTQ_OK);
    WTQ_TEST_CHECK(es2 == es1); /* the slot was reused */

    /* the peer's STOP_SENDING for the OLD stream arrives late */
    bool delivered =
        fake_driver_deliver_stop(r.conn, ds1, wtq_app_error_to_h3(3),
                                 5000);
    WTQ_TEST_CHECK(!delivered);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_stop_events, 0);
    /* the new stream is untouched */
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es2, &span, 1, false,
                                    NULL) == WTQ_OK);
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* Same seam, bidi + RESET flavor: a late RESET_STREAM on the old
 * transport stream must not force-close (or fire callbacks on) the
 * slot's new occupant. */
static void test_stale_reset_after_slot_reuse(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    wtq_estream_t *es1 = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &es1) == WTQ_OK);
    struct wtq_dstream *ds1 = local_ds_for(&r, es1);
    WTQ_TEST_CHECK(ds1 != NULL);
    if (ds1 == NULL) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }
    /* peer FIN closes receive; our FIN closes send: slot released */
    WTQ_TEST_CHECK(fake_driver_deliver_bytes(r.conn, ds1, NULL, 0, true,
                                             5000));
    WTQ_TEST_CHECK(wtq_conn_wt_send(r.conn, es1, NULL, 0, true,
                                    (void *)&r) == WTQ_OK);

    wtq_estream_t *es2 = NULL;
    WTQ_TEST_CHECK(wtq_conn_wt_open_bidi(r.conn, &es2) == WTQ_OK);
    WTQ_TEST_CHECK(es2 == es1);

    /* the peer's late RESET for the OLD stream (legal after its FIN) */
    bool delivered =
        fake_driver_deliver_reset(r.conn, ds1, wtq_app_error_to_h3(4),
                                  5100);
    WTQ_TEST_CHECK(!delivered);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_reset_events, 0);
    /* the new stream's receive side is still open: peer bytes arrive */
    struct wtq_dstream *ds2 = local_ds_for(&r, es2);
    WTQ_TEST_CHECK(ds2 != NULL && ds2 != ds1);
    if (ds2 != NULL) {
        int before = r.app.wt_data_events;
        WTQ_TEST_CHECK(fake_driver_deliver_bytes(
            r.conn, ds2, (const uint8_t *)"ok", 2, false, 5200));
        WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.wt_data_events,
                               (size_t)before + 1);
    }
    (void)fake_driver_complete_sends(&r.drv, r.conn);
    rig_down(&r, fp);
    *fp += failures;
}

/* session_stream_poisoned() must release the slot THROUGH detachment:
 * in-flight bytes still delivered against the old CONNECT stream must
 * not reach (or reclassify) the slot's next occupant. */
static void test_poisoned_stream_late_bytes(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_server(&r, fp);
    r.sess_ds->ectx = r.sess_es; /* as a backend records it */

    /* DATA frame carrying CLOSE capsule + one trailing byte: the
     * session closes cleanly and the stream is poisoned in the same
     * delivery (slot freed while bytes may still be in flight) */
    uint8_t cap[64];
    size_t clen = 0;
    WTQ_TEST_CHECK(wtq_capsule_encode_close(0, NULL, 0, cap, sizeof(cap),
                                            &clen) == WTQ_CAPSULE_OK);
    uint8_t frame[96];
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, clen + 1,
                                              frame, sizeof(frame),
                                              &hl) == 0);
    memcpy(frame + hl, cap, clen);
    frame[hl + clen] = 0xFF;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, r.sess_es, frame,
                                            hl + clen + 1, false,
                                            5000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.closed_events, 1);
    WTQ_TEST_CHECK(r.sess_ds->reset); /* poison reset the stream */

    /* a new peer uni stream takes the freed slot */
    struct wtq_dstream *ds2 = fake_driver_add_peer_stream(&r.drv, 6);
    wtq_estream_t *es2 = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds2, 6, &es2) ==
                   WTQ_OK);
    ds2->ectx = es2;

    /* in-flight bytes for the poisoned CONNECT stream arrive: 0x00
     * would classify the new occupant as a SECOND control stream — a
     * connection-fatal misdelivery */
    uint8_t stale = 0x00;
    bool delivered =
        fake_driver_deliver_bytes(r.conn, r.sess_ds, &stale, 1, false,
                                  5100);
    WTQ_TEST_CHECK(!delivered);
    WTQ_TEST_CHECK_EQ_SIZE((size_t)r.app.error_events, 0);
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

/* wt_stop from inside on_wt_stream_data(fin=true): the FIN being
 * delivered satisfies the drain the stop just requested — the slot
 * must come back. Repetition across the whole pool proves it. */
static void test_stop_on_fin_no_slot_leak(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.app.stop_conn = r.conn;
    r.app.stop_on_fin = true;

    uint64_t sid = wtq_conn_session_id(r.conn);
    uint8_t pre[16];
    size_t plen = enc_preamble(false, sid, pre, sizeof(pre));
    WTQ_TEST_CHECK(plen > 0);

    for (uint64_t i = 0; i < 16; i++) {
        uint64_t id = 3 + 4 * i;
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, id);
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK(ds != NULL);
        WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(r.conn, ds, id,
                                                   &es) == WTQ_OK);
        WTQ_TEST_CHECK(es != NULL);
        if (es == NULL)
            break;
        uint8_t buf[24];
        memcpy(buf, pre, plen);
        buf[plen] = 'z';
        WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(r.conn, es, buf, plen + 1,
                                                true, 5000 + i) ==
                       WTQ_OK);
    }
    WTQ_TEST_CHECK(!wtq_conn_is_closed(r.conn));
    rig_down(&r, fp);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_session_close_leaves_absorbers(&failures);
    test_peer_close_leaves_absorbers(&failures);
    test_wt_stop_closes_receive(&failures);
    test_wt_stop_then_peer_reset(&failures);
    test_wt_stop_bidi_send_survives(&failures);
    test_wt_stop_no_duplicate_on_session_close(&failures);
    test_bidi_half_close(&failures);
    test_send_fin_closes_send_side(&failures);
    test_reset_preserves_receive(&failures);
    test_peer_reset_bidi_send_survives(&failures);
    test_create_requires_ops(&failures);
    test_peer_uni_preamble_split(&failures);
    test_peer_bidi_preamble_split(&failures);
    test_server_peer_bidi_wt(&failures);
    test_wt_stream_empty_fin(&failures);
    test_client_bidi_not_wt(&failures);
    test_server_bidi_request_replay(&failures);
    test_unknown_uni_still_drained(&failures);
    test_wt_stream_before_session(&failures);
    test_wt_stream_wrong_sid(&failures);
    test_wt_stream_after_close(&failures);
    test_preamble_fin_edges(&failures);
    test_wt_reset_mapping(&failures);
    test_wt_open_local(&failures);
    test_wt_send_success(&failures);
    test_wt_send_errors(&failures);
    test_wt_send_then_reset(&failures);
    test_session_close_teardown(&failures);
    test_wt_send_then_conn_close(&failures);
    test_wt_stop_paths(&failures);
    test_draining_still_works(&failures);
    test_zero_alloc_data_path(&failures);
    test_stale_stop_after_slot_reuse(&failures);
    test_stale_reset_after_slot_reuse(&failures);
    test_poisoned_stream_late_bytes(&failures);
    test_stop_on_fin_no_slot_leak(&failures);
    test_terminal_resolves_abort_drain(&failures);
    test_terminal_releases_es_drain(&failures);
    test_terminal_releases_request_dead(&failures);
    test_terminal_closes_live(&failures);
    test_terminal_after_peer_reset(&failures);
    test_terminal_slot_churn(&failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_engine_wtstream (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_engine_wtstream\n");
    return 0;
}
