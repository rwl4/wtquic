/*
 * Receive pause/resume over the public API against the fake backend:
 * return codes, the recv_enable passthrough's recorded state, guard
 * ordering against the sibling stream ops, dead-but-valid handles, and
 * a backend without the capability.
 */

#include <string.h>

#include <wtquic/wtquic.h>

#include "api/api_internal.h"
#include "fake_driver.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

struct pause_side {
    int established;
    int closed;
};

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    struct pause_side *ps = user;

    (void)s;
    (void)sub;
    ps->established++;
}

static void cb_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t rlen, bool clean,
                      void *user)
{
    struct pause_side *ps = user;

    (void)s;
    (void)code;
    (void)reason;
    (void)rlen;
    (void)clean;
    ps->closed++;
}

/* Bring a client session to ESTABLISHED over the fake driver: deliver
 * the peer's SETTINGS (triggering the deferred CONNECT) and answer the
 * CONNECT with a plain 200. */
static int session_up(const wtq_driver_ops_t *ops, struct wtq_driver *drv,
                      struct pause_side *ps, wtq_session_t **s_out)
{
    wtq_session_events_t ev;

    fake_driver_init(drv, true);
    memset(ps, 0, sizeof(*ps));
    wtq_session_events_init(&ev);
    ev.on_established = cb_established;
    ev.on_closed = cb_closed;

    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = ps,
        .drv = drv,
        .ops = ops,
    };
    if (wtq_api_session_create(&cfg, s_out) != WTQ_OK)
        return -1;
    wtq_session_t *s = *s_out;
    if (wtq_api_session_start(s, 1000) != WTQ_OK)
        return -1;

    wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
    cc.authority = "h";
    cc.path = "/p";
    if (wtq_api_session_connect(s, &cc) != WTQ_OK)
        return -1;

    /* peer SETTINGS with WebTransport support -> CONNECT goes out */
    uint8_t st[64];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    st[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&scfg, st + 1, sizeof(st) - 1,
                                     &flen) != WTQ_H3_SETTINGS_OK)
        return -1;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, 3);
    wtq_estream_t *es = NULL;
    wtq_conn_t *conn = wtq_api_session_conn(s);
    wtq_api_session_enter(s);
    if (wtq_conn_on_peer_uni_opened(conn, ds, 3, &es) != WTQ_OK ||
        es == NULL ||
        wtq_conn_on_stream_bytes(conn, es, st, 1 + flen, false, 1000) !=
            WTQ_OK) {
        (void)wtq_api_session_leave(s);
        return -1;
    }
    (void)wtq_api_session_leave(s);

    /* answer the CONNECT (the first local bidi stream) with a 200 */
    wtq_estream_t *connect_es = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (drv->streams[i].in_use && drv->streams[i].is_local &&
            drv->streams[i].is_bidi)
            connect_es = drv->streams[i].ectx;
    if (connect_es == NULL)
        return -1;

    uint8_t section[128];
    size_t slen = 0;
    if (wtq_connect_encode_response(200, NULL, section, sizeof(section),
                                    &slen) != WTQ_CONNECT_OK)
        return -1;
    uint8_t hdr[16];
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, hdr,
                                   sizeof(hdr), &hl) != 0)
        return -1;
    wtq_api_session_enter(s);
    if (wtq_conn_on_stream_bytes(conn, connect_es, hdr, hl, false,
                                 1000) != WTQ_OK ||
        wtq_conn_on_stream_bytes(conn, connect_es, section, slen, false,
                                 1000) != WTQ_OK) {
        (void)wtq_api_session_leave(s);
        return -1;
    }
    (void)wtq_api_session_leave(s);
    return ps->established == 1 ? 0 : -1;
}

/* Find the fake stream record for the (non-CONNECT) WT bidi stream. */
static struct wtq_dstream *wt_bidi_ds(struct wtq_driver *drv,
                                      uint64_t id)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (drv->streams[i].in_use && drv->streams[i].is_local &&
            drv->streams[i].is_bidi && drv->streams[i].id == id)
            return &drv->streams[i];
    return NULL;
}

int main(void)
{
    int failures = 0;

    /* NULL handle */
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(NULL),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(NULL),
                          WTQ_ERR_INVALID_ARG);

    /* --- backend with recv_enable ------------------------------------ */
    {
        struct wtq_driver drv;
        struct pause_side ps;
        wtq_session_t *s = NULL;

        WTQ_TEST_CHECK_EQ_INT(
            session_up(fake_driver_ops(), &drv, &ps, &s), 0);
        if (s != NULL) {
            wtq_stream_t *st = NULL;

            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_bidi(s, &st), WTQ_OK);
            struct wtq_dstream *ds = wt_bidi_ds(&drv, wtq_stream_id(st));
            WTQ_TEST_CHECK(ds != NULL);

            WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(st), WTQ_OK);
            WTQ_TEST_CHECK(ds != NULL && ds->recv_disabled);
            WTQ_TEST_CHECK_EQ_INT(ds != NULL ? ds->recv_enable_count : 0,
                                  1);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(st), WTQ_OK);
            WTQ_TEST_CHECK(ds != NULL && !ds->recv_disabled);
            WTQ_TEST_CHECK_EQ_INT(ds != NULL ? ds->recv_enable_count : 0,
                                  2);

            /* a finished receive side is STATE, like the sibling ops */
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_stop_sending(st, 0), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(st),
                                  WTQ_ERR_STATE);

            /* a retained handle past the session terminal is CLOSED */
            wtq_stream_add_ref(st);
            WTQ_TEST_CHECK_EQ_INT(wtq_session_close(s, 0, NULL, 0),
                                  WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(ps.closed, 1);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(st),
                                  WTQ_ERR_CLOSED);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(st),
                                  WTQ_ERR_CLOSED);
            wtq_stream_release(st);
            wtq_session_release(s);
        }
    }

    /* --- backend without recv_enable ---------------------------------- */
    {
        wtq_driver_ops_t ops = *fake_driver_ops();
        struct wtq_driver drv;
        struct pause_side ps;
        wtq_session_t *s = NULL;

        ops.recv_enable = NULL;
        WTQ_TEST_CHECK_EQ_INT(session_up(&ops, &drv, &ps, &s), 0);
        if (s != NULL) {
            wtq_stream_t *st = NULL;

            WTQ_TEST_CHECK_EQ_INT(wtq_session_open_bidi(s, &st), WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_pause_receive(st),
                                  WTQ_ERR_UNSUPPORTED);
            WTQ_TEST_CHECK_EQ_INT(wtq_stream_resume_receive(st),
                                  WTQ_ERR_UNSUPPORTED);
            /* the capability gate leaves the fake untouched */
            struct wtq_dstream *ds = wt_bidi_ds(&drv, wtq_stream_id(st));
            WTQ_TEST_CHECK(ds != NULL && ds->recv_enable_count == 0);
            wtq_session_release(s);
        }
    }

    WTQ_TEST_PASS("api_pause");
    return failures;
}
