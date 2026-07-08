/*
 * Transport-error record: first-causal precedence, latch-before-callbacks,
 * synthesized fallback, caller-sized public query (design §6).
 *
 * The record is WRITE-ONCE across both origins: an engine conn_fatal
 * latches {QUIC_APP, h3_err} before invoking any callback, a backend's
 * wtq_conn_set_transport_error latches full-fidelity detail before the
 * terminal input it explains, and whichever ran FIRST wins. When neither
 * ran, the terminal input synthesizes {kind, quic_code} from err/remote.
 */
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

typedef struct log_state {
    int established;
    int closed;
    int refused;
    int failed;
    uint32_t closed_code;
    /* the record as read from INSIDE the terminal callback */
    wtq_result_t cb_query_rc;
    wtq_transport_error_t cb_err;
} log_state_t;

static void cb_query(wtq_session_t *s, log_state_t *lg)
{
    memset(&lg->cb_err, 0, sizeof(lg->cb_err));
    lg->cb_err.struct_size = (uint32_t)sizeof(lg->cb_err);
    lg->cb_query_rc = wtq_session_transport_error(s, &lg->cb_err);
}

static void on_refused(wtq_session_t *s, uint16_t status, void *user)
{
    log_state_t *lg = user;

    (void)status;
    lg->refused++;
    cb_query(s, lg);
}

static void on_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    log_state_t *lg = user;

    (void)why;
    lg->failed++;
    cb_query(s, lg);
}

static void on_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    (void)s;
    (void)sub;
    ((log_state_t *)user)->established++;
}

static void on_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t reason_len, bool clean,
                      void *user)
{
    log_state_t *lg = user;

    (void)reason;
    (void)reason_len;
    (void)clean;
    lg->closed++;
    lg->closed_code = code;
    /* the record must already be latched (or sealed) HERE, inside the
     * first terminal callback */
    cb_query(s, lg);
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_session_t *s;
    log_state_t lg;
    wtq_estream_t *peer_ctrl; /* the peer control stream's engine ctx */
} rig_t;

static const char *const OFFER[] = { "moqt-18" };

static void rig_up(rig_t *r, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(&r->lg, 0, sizeof(r->lg));
    fake_driver_init(&r->drv, true);
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
    ev.on_closed = on_closed;
    ev.on_refused = on_refused;
    ev.on_failed = on_failed;

    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &r->lg,
        .drv = &r->drv,
        .ops = fake_driver_ops(),
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r->s) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_api_session_start(r->s, 1000) == WTQ_OK);

    wtq_connect_config_t ccfg;
    wtq_connect_config_init(&ccfg);
    ccfg.authority = "example.com";
    ccfg.path = "/app";
    ccfg.subprotocols = OFFER;
    ccfg.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(r->s, &ccfg) == WTQ_OK);

    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);
    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    struct wtq_dstream *pds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *pes = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, pds, 3, &pes) ==
                   WTQ_OK);
    pds->ectx = pes;
    r->peer_ctrl = pes;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, pes, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);
    *fp += failures;
}

static void respond(rig_t *r, int status, const char *subproto, int *fp)
{
    int failures = 0;
    uint8_t section[256];
    uint8_t resp[300];
    size_t slen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);
    wtq_sf_str_t sel = { subproto, subproto ? strlen(subproto) : 0 };

    WTQ_TEST_CHECK(wtq_connect_encode_response((uint16_t)status,
                                               subproto ? &sel : NULL,
                                               section, sizeof(section),
                                               &slen) == 0);
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen,
                                              resp, sizeof(resp),
                                              &hl) == 0);
    memcpy(resp + hl, section, slen);
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            bidi = &r->drv.streams[i];
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, bidi->ectx, resp,
                                            hl + slen, false, 2000) ==
                   WTQ_OK);
    *fp += failures;
}

static void establish(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, fp);
    respond(r, 200, "moqt-18", fp);
    WTQ_TEST_CHECK_EQ_INT(r->lg.established, 1);
    *fp += failures;
}

static void rig_down(rig_t *r)
{
    wtq_session_release(r->s);
}

/* Before any terminal event: kind NONE; undersized query rejected. */
static void test_query_before_terminal(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_transport_error_t e;
    memset(&e, 0xEE, sizeof(e));
    e.struct_size = (uint32_t)sizeof(e);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_NONE);
    WTQ_TEST_CHECK(e.quic_code == 0);
    WTQ_TEST_CHECK(e.native_domain == WTQ_ERRDOM_NONE);

    /* too small to hold `kind`: rejected, nothing written */
    memset(&e, 0xEE, sizeof(e));
    e.struct_size = (uint32_t)sizeof(uint32_t);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, NULL) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(wtq_session_transport_error(NULL, &e) ==
                   WTQ_ERR_INVALID_ARG);
    rig_down(&r);
    *fp += failures;
}

/* Engine conn_fatal: latched {QUIC_APP, h3_err} BEFORE any callback,
 * and a backend set arriving later is ignored (write-once). */
static void test_fatal_latches_before_callbacks(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_conn_t *conn = wtq_api_session_conn(r.s);

    /* a SECOND SETTINGS frame on the control stream is FRAME_UNEXPECTED:
     * deterministic engine conn_fatal */
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf, sizeof(buf),
                                                &flen) == 0);
    (void)wtq_conn_on_stream_bytes(conn, r.peer_ctrl, buf, flen, false,
                                   3000);
    WTQ_TEST_CHECK_EQ_INT(r.lg.closed, 1);

    /* the record was ALREADY latched when on_closed ran */
    WTQ_TEST_CHECK(r.lg.cb_query_rc == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)r.lg.cb_err.kind,
                          (int)WTQ_ERR_KIND_QUIC_APP);
    WTQ_TEST_CHECK_EQ_HEX(r.lg.cb_err.quic_code, WTQ_H3_FRAME_UNEXPECTED);
    WTQ_TEST_CHECK(r.lg.cb_err.native_domain == WTQ_ERRDOM_NONE);

    /* a backend detail arriving during/after the teardown is IGNORED */
    wtq_transport_error_t late = {
        .struct_size = (uint32_t)sizeof(late),
        .kind = WTQ_ERR_KIND_LOCAL,
        .quic_code = 999,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = -1,
    };
    wtq_conn_set_transport_error(conn, &late);
    wtq_transport_error_t e;
    memset(&e, 0, sizeof(e));
    e.struct_size = (uint32_t)sizeof(e);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_QUIC_APP);
    WTQ_TEST_CHECK_EQ_HEX(e.quic_code, WTQ_H3_FRAME_UNEXPECTED);
    rig_down(&r);
    *fp += failures;
}

/* Backend detail set before the terminal input wins over synthesis,
 * and over any second set (first causal error wins). */
static void test_backend_detail_first_causal(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_conn_t *conn = wtq_api_session_conn(r.s);

    wtq_transport_error_t first = {
        .struct_size = (uint32_t)sizeof(first),
        .kind = WTQ_ERR_KIND_QUIC_TRANSPORT,
        .quic_code = 7,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = -123,
    };
    wtq_conn_set_transport_error(conn, &first);
    wtq_transport_error_t second = {
        .struct_size = (uint32_t)sizeof(second),
        .kind = WTQ_ERR_KIND_LOCAL,
        .quic_code = 42,
        .native_domain = WTQ_ERRDOM_BACKEND,
        .native_code = 9,
    };
    wtq_conn_set_transport_error(conn, &second); /* ignored */

    wtq_conn_on_conn_closed(conn, 9, true, 4000);
    WTQ_TEST_CHECK_EQ_INT(r.lg.closed, 1);
    /* inside the callback AND after it: the FIRST record, not the
     * synthesized {QUIC_APP, 9} and not the second set */
    WTQ_TEST_CHECK_EQ_INT((int)r.lg.cb_err.kind,
                          (int)WTQ_ERR_KIND_QUIC_TRANSPORT);
    WTQ_TEST_CHECK_EQ_HEX(r.lg.cb_err.quic_code, 7);
    WTQ_TEST_CHECK(r.lg.cb_err.native_domain == WTQ_ERRDOM_MSQUIC);
    WTQ_TEST_CHECK(r.lg.cb_err.native_code == -123);
    rig_down(&r);
    *fp += failures;
}

/* No backend detail: the terminal input synthesizes kind from remote. */
static void test_synthesized_fallback(int *fp)
{
    int failures = 0;

    /* remote close -> QUIC_APP */
    {
        rig_t r;
        establish(&r, fp);
        wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 5, true, 4000);
        WTQ_TEST_CHECK_EQ_INT((int)r.lg.cb_err.kind,
                              (int)WTQ_ERR_KIND_QUIC_APP);
        WTQ_TEST_CHECK_EQ_HEX(r.lg.cb_err.quic_code, 5);
        WTQ_TEST_CHECK(r.lg.cb_err.native_domain == WTQ_ERRDOM_NONE);
        rig_down(&r);
    }
    /* local close -> LOCAL */
    {
        rig_t r;
        establish(&r, fp);
        wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 6, false, 4000);
        WTQ_TEST_CHECK_EQ_INT((int)r.lg.cb_err.kind,
                              (int)WTQ_ERR_KIND_LOCAL);
        WTQ_TEST_CHECK_EQ_HEX(r.lg.cb_err.quic_code, 6);
        rig_down(&r);
    }
    *fp += failures;
}

/* Caller-sized copy-out: only the declared bytes are written; trailing
 * fields keep their poison; struct_size is preserved either way. */
static void test_caller_sized_query(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    wtq_transport_error_t detail = {
        .struct_size = (uint32_t)sizeof(detail),
        .kind = WTQ_ERR_KIND_QUIC_TRANSPORT,
        .quic_code = 0x1234,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = -55,
    };
    wtq_conn_set_transport_error(conn, &detail);
    wtq_conn_on_conn_closed(conn, 0x1234, false, 4000);

    /* prefix-only window: kind visible, quic_code and beyond untouched */
    wtq_transport_error_t e;
    memset(&e, 0xEE, sizeof(e));
    e.struct_size = (uint32_t)offsetof(wtq_transport_error_t, quic_code);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) == WTQ_OK);
    WTQ_TEST_CHECK(e.struct_size ==
                   (uint32_t)offsetof(wtq_transport_error_t, quic_code));
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_QUIC_TRANSPORT);
    WTQ_TEST_CHECK(e.quic_code == 0xEEEEEEEEEEEEEEEEull); /* untouched */
    WTQ_TEST_CHECK(e.native_code == (int64_t)0xEEEEEEEEEEEEEEEEull);

    /* oversized window: full record filled, size preserved */
    struct {
        wtq_transport_error_t e;
        uint64_t tail;
    } big;
    memset(&big, 0xEE, sizeof(big));
    big.e.struct_size = (uint32_t)sizeof(big);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &big.e) == WTQ_OK);
    WTQ_TEST_CHECK(big.e.struct_size == (uint32_t)sizeof(big));
    WTQ_TEST_CHECK_EQ_HEX(big.e.quic_code, 0x1234);
    WTQ_TEST_CHECK(big.e.native_code == -55);
    WTQ_TEST_CHECK(big.tail == 0xEEEEEEEEEEEEEEEEull); /* untouched */
    rig_down(&r);
    *fp += failures;
}

/* After a terminal WITHOUT a transport cause the record is SEALED as
 * NONE: late backend detail and late transport events change nothing. */
static void check_sealed_none(rig_t *r, int *fp)
{
    int failures = 0;

    /* sealed NONE was already visible inside the terminal callback */
    WTQ_TEST_CHECK(r->lg.cb_query_rc == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)r->lg.cb_err.kind, (int)WTQ_ERR_KIND_NONE);

    /* attempted late backend detail + late transport close: ignored */
    wtq_conn_t *conn = wtq_api_session_conn(r->s);
    wtq_transport_error_t late = {
        .struct_size = (uint32_t)sizeof(late),
        .kind = WTQ_ERR_KIND_LOCAL,
        .quic_code = 777,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = -9,
    };
    wtq_conn_set_transport_error(conn, &late);
    wtq_conn_on_conn_closed(conn, 888, true, 9000);

    wtq_transport_error_t e;
    memset(&e, 0, sizeof(e));
    e.struct_size = (uint32_t)sizeof(e);
    WTQ_TEST_CHECK(wtq_session_transport_error(r->s, &e) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_NONE);
    WTQ_TEST_CHECK(e.quic_code == 0);
    WTQ_TEST_CHECK(e.native_domain == WTQ_ERRDOM_NONE);
    *fp += failures;
}

static void test_clean_close_sealed_none(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    WTQ_TEST_CHECK(wtq_session_close(r.s, 0, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.closed, 1);
    check_sealed_none(&r, fp);
    rig_down(&r);
    *fp += failures;
}

static void test_rejected_sealed_none(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, fp);
    respond(&r, 403, NULL, fp);
    WTQ_TEST_CHECK_EQ_INT(r.lg.refused, 1);
    check_sealed_none(&r, fp);
    rig_down(&r);
    *fp += failures;
}

static void test_failed_sealed_none(int *fp)
{
    int failures = 0;
    rig_t r;

    /* a 200 selecting a subprotocol we never offered: a non-transport
     * session failure (NO_PROTOCOL) */
    rig_up(&r, fp);
    respond(&r, 200, "bogus", fp);
    WTQ_TEST_CHECK_EQ_INT(r.lg.failed, 1);
    WTQ_TEST_CHECK_EQ_INT(r.lg.established, 0);
    check_sealed_none(&r, fp);
    rig_down(&r);
    *fp += failures;
}

/* Public minimum window: through `kind` (six bytes). Five is rejected;
 * six succeeds with every later byte untouched. */
static void test_min_size_boundary(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 5, true, 4000);

    wtq_transport_error_t e;
    memset(&e, 0xEE, sizeof(e));
    e.struct_size = 5;
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) ==
                   WTQ_ERR_INVALID_ARG);

    memset(&e, 0xEE, sizeof(e));
    e.struct_size =
        (uint32_t)(offsetof(wtq_transport_error_t, kind) + sizeof(e.kind));
    WTQ_TEST_CHECK(e.struct_size == 6);
    WTQ_TEST_CHECK(wtq_session_transport_error(r.s, &e) == WTQ_OK);
    WTQ_TEST_CHECK(e.struct_size == 6); /* preserved */
    WTQ_TEST_CHECK_EQ_INT((int)e.kind, (int)WTQ_ERR_KIND_QUIC_APP);
    WTQ_TEST_CHECK(e.reserved0 == 0xEEEE);               /* untouched */
    WTQ_TEST_CHECK(e.quic_code == 0xEEEEEEEEEEEEEEEEull);
    WTQ_TEST_CHECK(e.native_code == (int64_t)0xEEEEEEEEEEEEEEEEull);
    rig_down(&r);
    *fp += failures;
}

/* A kind==NONE (or out-of-range) SPI record is ignored entirely: it
 * cannot consume the write-once latch, so later synthesis still runs. */
static void test_spi_rejects_non_error_kinds(int *fp)
{
    int failures = 0;
    rig_t r;

    establish(&r, fp);
    wtq_conn_t *conn = wtq_api_session_conn(r.s);

    wtq_transport_error_t none_rec = {
        .struct_size = (uint32_t)sizeof(none_rec),
        .kind = WTQ_ERR_KIND_NONE,
        .quic_code = 5,
        .native_domain = WTQ_ERRDOM_MSQUIC,
        .native_code = 1,
    };
    wtq_conn_set_transport_error(conn, &none_rec); /* ignored */
    wtq_transport_error_t bad_rec = none_rec;
    bad_rec.kind = 200;                            /* out of range */
    wtq_conn_set_transport_error(conn, &bad_rec);  /* ignored */

    wtq_conn_on_conn_closed(conn, 7, true, 4000);
    /* synthesis was NOT suppressed */
    WTQ_TEST_CHECK_EQ_INT((int)r.lg.cb_err.kind,
                          (int)WTQ_ERR_KIND_QUIC_APP);
    WTQ_TEST_CHECK_EQ_HEX(r.lg.cb_err.quic_code, 7);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_query_before_terminal(&failures);
    test_clean_close_sealed_none(&failures);
    test_rejected_sealed_none(&failures);
    test_failed_sealed_none(&failures);
    test_min_size_boundary(&failures);
    test_spi_rejects_non_error_kinds(&failures);
    test_fatal_latches_before_callbacks(&failures);
    test_backend_detail_first_causal(&failures);
    test_synthesized_fallback(&failures);
    test_caller_sized_query(&failures);

    WTQ_TEST_PASS("test_api_transport_error");
    return failures;
}
