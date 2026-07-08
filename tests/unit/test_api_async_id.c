/*
 * Asynchronous native stream ids (public API level).
 *
 * Pins the wtq_stream_id() contract over an async-id transport:
 *   - UNKNOWN -> known transition is visible through the PUBLIC handle
 *     (read-through while attached, no notification machinery);
 *   - a retained handle stays queryable after the stream closes, reading
 *     the FROZEN final value — the known id, or WTQ_STREAM_ID_UNKNOWN
 *     forever when the transport never reported one.
 */
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

typedef struct log_state {
    int established;
    int stream_closed;
    wtq_stream_t *last_closed;
} log_state_t;

static void on_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    (void)s;
    (void)sub;
    ((log_state_t *)user)->established++;
}

static void on_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    log_state_t *lg = user;

    (void)s;
    lg->stream_closed++;
    lg->last_closed = st;
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_session_t *s;
    log_state_t lg;
} rig_t;

static const char *const OFFER[] = { "moqt-18" };

static void rig_up_async(rig_t *r, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(&r->lg, 0, sizeof(r->lg));
    fake_driver_init(&r->drv, true /* client */);
    r->drv.async_ids = true;
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
    ev.on_stream_closed = on_stream_closed;

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

static void deliver_peer_settings(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);

    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, ds, 3, &es) ==
                   WTQ_OK);
    ds->ectx = es;
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, es, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);
    *fp += failures;
}

static void establish_async(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t section[256];
    uint8_t resp[300];
    size_t slen = 0;
    wtq_sf_str_t sel = { "moqt-18", 7 };

    rig_up_async(r, fp);
    deliver_peer_settings(r, fp);
    struct wtq_dstream *bidi = find_local_bidi(r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(wtq_api_session_conn(r->s),
                                                 bidi, 1600));
    WTQ_TEST_CHECK(wtq_connect_encode_response(200, &sel, section,
                                               sizeof(section),
                                               &slen) == 0);
    size_t hl = 0;
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen,
                                              resp, sizeof(resp),
                                              &hl) == 0);
    memcpy(resp + hl, section, slen);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(wtq_api_session_conn(r->s),
                                            bidi->ectx, resp, hl + slen,
                                            false, 2000) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r->lg.established, 1);
    *fp += failures;
}

static void rig_down(rig_t *r)
{
    wtq_session_release(r->s);
}

/* UNKNOWN -> known, visible through the public handle (read-through). */
static void test_public_unknown_to_known(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_async(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_id(st) == WTQ_STREAM_ID_UNKNOWN);

    struct wtq_dstream *ds = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(ds != NULL && ds->ectx != NULL);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(wtq_api_session_conn(r.s),
                                                 ds, 2100));
    WTQ_TEST_CHECK(wtq_stream_id(st) == ds->id);
    WTQ_TEST_CHECK(wtq_stream_id(st) != WTQ_STREAM_ID_UNKNOWN);
    rig_down(&r);
    *fp += failures;
}

/* Retained handle after terminal: frozen KNOWN id stays queryable. */
static void test_retained_terminal_known(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_async(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    struct wtq_dstream *ds = fake_driver_local(&r.drv, 4);
    WTQ_TEST_CHECK(ds != NULL);
    WTQ_TEST_CHECK(fake_driver_deliver_native_id(wtq_api_session_conn(r.s),
                                                 ds, 2100));
    uint64_t known = wtq_stream_id(st);
    WTQ_TEST_CHECK(known == ds->id);

    wtq_stream_add_ref(st);
    WTQ_TEST_CHECK(wtq_stream_reset(st, 0) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    /* backlink severed; the FROZEN value answers the retained handle */
    WTQ_TEST_CHECK(wtq_stream_id(st) == known);
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

/* Retained handle when the id NEVER arrived: frozen UNKNOWN, forever. */
static void test_retained_terminal_never_known(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_async(&r, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_id(st) == WTQ_STREAM_ID_UNKNOWN);

    wtq_stream_add_ref(st);
    WTQ_TEST_CHECK(wtq_stream_reset(st, 0) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(r.lg.stream_closed, 1);
    WTQ_TEST_CHECK(wtq_stream_id(st) == WTQ_STREAM_ID_UNKNOWN);
    wtq_stream_release(st);
    rig_down(&r);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_public_unknown_to_known(&failures);
    test_retained_terminal_known(&failures);
    test_retained_terminal_never_known(&failures);

    WTQ_TEST_PASS("test_api_async_id");
    return failures;
}
