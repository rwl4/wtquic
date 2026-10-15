#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "test_support.h"
#include "wtq_fault_alloc.h"

typedef struct rig {
    struct wtq_driver drv;
    wtq_driver_ops_t ops;
    wtq_session_t *session;
    wtq_fault_alloc_t alloc;
    int failures;
    int commits, closes, returns, canceled, session_closes;
    char order[128];
    size_t order_len;
    bool close_in_commit, release_in_commit;
    int other_closes;
    wtq_result_t reset_in_commit;
} rig_t;

/* Independently frozen baseline layout, including its complete tail padding. */
typedef struct events_v1 {
    uint32_t struct_size;
    void (*on_established)(wtq_session_t *, wtq_str_t, void *);
    void (*on_refused)(wtq_session_t *, uint16_t, void *);
    void (*on_failed)(wtq_session_t *, wtq_connect_failure_t, void *);
    void (*on_draining)(wtq_session_t *, void *);
    void (*on_closed)(wtq_session_t *, uint32_t, const uint8_t *, size_t, bool, void *);
    void (*on_stream_opened)(wtq_session_t *, wtq_stream_t *, bool, void *);
    void (*on_stream_data)(wtq_session_t *, wtq_stream_t *, const uint8_t *, size_t, bool, void *);
    void (*on_stream_reset)(wtq_session_t *, wtq_stream_t *, uint32_t, void *);
    void (*on_stream_stop)(wtq_session_t *, wtq_stream_t *, uint32_t, void *);
    void (*on_stream_closed)(wtq_session_t *, wtq_stream_t *, void *);
    void (*on_send_complete)(wtq_session_t *, void *, bool, void *);
    void (*on_datagram)(wtq_session_t *, const uint8_t *, size_t, void *);
    void (*on_stream_writable)(wtq_session_t *, wtq_stream_t *, void *);
} events_v1_t;

static void committed(wtq_session_t *, wtq_stream_t *, void *);
static void stream_closed(wtq_session_t *, wtq_stream_t *, void *);

static void event_abi(int *fp)
{
    int failures = 0;
    WTQ_TEST_CHECK(offsetof(wtq_session_events_t, on_stream_send_committed) >= sizeof(events_v1_t));
#define CHECK_OFFSET(member) WTQ_TEST_CHECK(offsetof(events_v1_t, member) == offsetof(wtq_session_events_t, member))
    CHECK_OFFSET(struct_size);
    CHECK_OFFSET(on_established); CHECK_OFFSET(on_refused); CHECK_OFFSET(on_failed);
    CHECK_OFFSET(on_draining); CHECK_OFFSET(on_closed); CHECK_OFFSET(on_stream_opened);
    CHECK_OFFSET(on_stream_data); CHECK_OFFSET(on_stream_reset); CHECK_OFFSET(on_stream_stop);
    CHECK_OFFSET(on_stream_closed); CHECK_OFFSET(on_send_complete); CHECK_OFFSET(on_datagram);
    CHECK_OFFSET(on_stream_writable);
#undef CHECK_OFFSET
    struct { events_v1_t value; unsigned char tail[24]; } old;
    memset(&old, 0xa5, sizeof(old));
    void (*bare)(wtq_session_events_t *) = &wtq_session_events_init;
    bare((wtq_session_events_t *)&old.value);
    WTQ_TEST_CHECK_EQ_SIZE(old.value.struct_size, sizeof(events_v1_t));
    WTQ_TEST_CHECK(old.value.on_stream_writable == NULL);
    for (size_t i = sizeof(events_v1_t); i < sizeof(old); ++i)
        WTQ_TEST_CHECK(((const unsigned char *)&old)[i] == 0xa5);
    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    WTQ_TEST_CHECK_EQ_SIZE(ev.struct_size, sizeof(ev));
    WTQ_TEST_CHECK(ev.on_stream_send_committed == NULL);
    struct { wtq_session_events_t value; unsigned char tail[17]; } future;
    for (size_t size = 0; size <= sizeof(future); ++size) {
        memset(&future, 0xa5, sizeof(future));
        wtq_session_events_init_ex(&future.value, size);
        size_t written = size < sizeof(ev) ? size : sizeof(ev);
        if (size >= sizeof(uint32_t)) WTQ_TEST_CHECK_EQ_SIZE(future.value.struct_size, written);
        for (size_t i = written; i < sizeof(future); ++i)
            WTQ_TEST_CHECK(((const unsigned char *)&future)[i] == 0xa5);
    }
    wtq_session_events_init(NULL);
    wtq_session_events_init_ex(NULL, 99);
    bare(NULL);
    events_v1_t physical_old = { .struct_size = sizeof(physical_old),
        .on_stream_closed = stream_closed };
    wtq_session_events_t copied;
    wtq_session_events_copy(&copied, (const wtq_session_events_t *)&physical_old);
    WTQ_TEST_CHECK(copied.on_stream_closed == stream_closed);
    WTQ_TEST_CHECK(copied.on_stream_send_committed == NULL);
    memset(&future, 0xa5, sizeof(future));
    future.value = ev;
    future.value.struct_size = sizeof(future);
    future.value.on_stream_send_committed = committed;
    wtq_session_events_copy(&copied, &future.value);
    WTQ_TEST_CHECK(copied.on_stream_send_committed == committed);
    for (size_t i = sizeof(future.value); i < sizeof(future); ++i)
        WTQ_TEST_CHECK(((const unsigned char *)&future)[i] == 0xa5);
    *fp += failures;
}

static void event(rig_t *r, char tag)
{
    if (r->order_len < sizeof(r->order)) r->order[r->order_len++] = tag;
}

static void committed(wtq_session_t *s, wtq_stream_t *st, void *user)
{
    rig_t *r = user;
    r->commits++;
    event(r, 'C');
    r->reset_in_commit = wtq_stream_reset(st, 9);
    if (r->close_in_commit) {
        uint8_t reason[1024];
        memset(reason, 'r', sizeof(reason));
        if (wtq_session_close(s, 42, reason, sizeof(reason)) != WTQ_OK)
            r->failures++;
        memset(reason, 0, sizeof(reason));
        if (r->session_closes != 0 || r->closes != r->other_closes) r->failures++;
    }
    if (r->release_in_commit) {
        wtq_stream_release(st);
        wtq_session_release(s);
    }
    event(r, 'c');
}

static void stream_closed(wtq_session_t *s, wtq_stream_t *st, void *user)
{
    (void)s;
    (void)st;
    rig_t *r = user;
    r->closes++;
    event(r, 'X');
}

static void session_closed(wtq_session_t *s, uint32_t code,
                            const uint8_t *reason, size_t len, bool clean, void *user)
{
    (void)s;
    rig_t *r = user;
    r->session_closes++;
    event(r, 'S');
    if (r->close_in_commit) {
        if (code != 42 || !clean || len != 1024) r->failures++;
        for (size_t i = 0; i < len; ++i)
            if (reason[i] != 'r') r->failures++;
    }
}

static void returned(wtq_session_t *s, void *cookie, bool canceled, void *user)
{
    (void)s;
    (void)cookie;
    rig_t *r = user;
    r->returns++;
    r->canceled += canceled;
    event(r, 'B');
}

static void setup(rig_t *r, bool capable, uint32_t event_size, bool callback, int *fp)
{
    int failures = 0;
    memset(r, 0, sizeof(*r));
    wtq_fault_alloc_init(&r->alloc);
    fake_driver_init(&r->drv, true);
    r->ops = *fake_driver_ops();
    if (capable) r->ops.caps |= WTQ_DCAP_SEND_COMMIT_ACK_FIN;
    wtq_session_events_t ev = WTQ_SESSION_EVENTS_INIT;
    ev.struct_size = event_size;
    ev.on_stream_send_committed = callback ? committed : NULL;
    ev.on_stream_closed = stream_closed;
    ev.on_closed = session_closed;
    ev.on_send_complete = returned;
    wtq_api_session_cfg_t cfg = {
        .alloc = &r->alloc.vtable, .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev, .user = r, .drv = &r->drv, .ops = &r->ops,
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r->session) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_api_session_start(r->session, 1) == WTQ_OK);
    wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
    cc.authority = "example.com";
    cc.path = "/moq";
    WTQ_TEST_CHECK(wtq_api_session_connect(r->session, &cc) == WTQ_OK);
    wtq_conn_t *conn = wtq_api_session_conn(r->session);
    uint8_t bytes[128];
    size_t len = 0;
    wtq_h3_settings_encode_cfg_t sc = { true, false };
    bytes[0] = 0;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&sc, bytes + 1, sizeof(bytes) - 1,
                                               &len) == WTQ_H3_SETTINGS_OK);
    struct wtq_dstream *peer = fake_driver_add_peer_stream(&r->drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, peer, 3, &es) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, es, bytes, len + 1, false, 2) == WTQ_OK);
    struct wtq_dstream *connect = fake_driver_local(&r->drv, 3);
    uint8_t section[64];
    size_t slen = 0, hlen = 0;
    WTQ_TEST_CHECK(wtq_connect_encode_response(200, NULL, section, sizeof(section),
                                               &slen) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, bytes,
                                              sizeof(bytes), &hlen) == 0);
    memcpy(bytes + hlen, section, slen);
    WTQ_TEST_CHECK(connect != NULL && connect->ectx != NULL);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, connect->ectx, bytes, hlen + slen,
                                            false, 3) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_session_status(r->session) == WTQ_SESSION_STATUS_ESTABLISHED);
    *fp += failures;
}

static struct wtq_dstream *newest(rig_t *r)
{
    return fake_driver_local(&r->drv, (size_t)r->drv.open_count - 1);
}

static void ack(rig_t *r, struct wtq_dstream *ds, wtq_estream_t *es, uint64_t generation)
{
    wtq_api_session_enter(r->session);
    wtq_conn_on_stream_send_shutdown_v1(wtq_api_session_conn(r->session), es, ds, generation, true);
    wtq_api_session_leave(r->session);
}

static void finish(rig_t *r, bool released, int *fp)
{
    int failures = r->failures;
    if (!released) wtq_session_release(r->session);
    WTQ_TEST_CHECK_EQ_INT(r->alloc.live, 0);
    WTQ_TEST_CHECK_EQ_INT(r->alloc.errors, 0);
    *fp += failures;
}

static void availability(int *fp)
{
    int failures = 0;
    WTQ_TEST_CHECK(wtq_session_send_commit_mode(NULL) == WTQ_SEND_COMMIT_UNSUPPORTED);
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(NULL) == WTQ_ERR_INVALID_ARG);
    const size_t offset = offsetof(wtq_session_events_t, on_stream_send_committed);
    for (int row = 0; row < 5; ++row) {
        static rig_t r;
        uint32_t size = sizeof(wtq_session_events_t);
        if (row == 2) size = (uint32_t)offset;
        if (row == 3) size = (uint32_t)sizeof(wtq_session_events_t) - 1;
        setup(&r, row != 0, size, row != 1, fp);
        WTQ_TEST_CHECK(wtq_session_send_commit_mode(r.session) ==
            (row == 0 ? WTQ_SEND_COMMIT_UNSUPPORTED : WTQ_SEND_COMMIT_LOCAL_UNI_ACK_FIN_RESETTABLE));
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
        if (row != 4) WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_ERR_UNSUPPORTED);
        /* Row4 registers the callback but deliberately does not opt in. */
        WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(r.closes, 1);
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
        finish(&r, false, fp);
    }
    static rig_t r;
    for (size_t n = 0; n < sizeof(((wtq_session_events_t *)0)->on_stream_send_committed); ++n) {
        setup(&r, true, (uint32_t)(offset + n), true, fp);
        wtq_stream_t *partial = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &partial) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(partial) == WTQ_ERR_UNSUPPORTED);
        WTQ_TEST_CHECK(wtq_stream_send(partial, NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(r.closes, 1);
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
        finish(&r, false, fp);
    }
    setup(&r, true, sizeof(wtq_session_events_t), true, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(r.session, &st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_ERR_STATE);
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
    r.drv.fail_send = true;
    WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_ERR_WOULD_BLOCK);
    r.drv.fail_send = false;
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_reset(st, 0) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, 0, NULL) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_ERR_STATE);
    finish(&r, false, fp);
    *fp += failures;
}

static void cookie_and_early_ack(int *fp)
{
    int failures = 0;
    for (int row = 0; row < 3; ++row) {
        static rig_t r;
        setup(&r, true, sizeof(wtq_session_events_t), true, fp);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
        wtq_stream_add_ref(st);
        struct wtq_dstream *ds = newest(&r);
        wtq_estream_t *es = ds->ectx;
        uint64_t generation = wtq_estream_generation_v1(es);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_OK);
        uint8_t data[] = { 1, 2, 3, 4 };
        wtq_span_t span = { data, sizeof(data) };
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, &r) == WTQ_OK);
        ack(&r, ds, es, generation); /* even a malformed early success cannot commit */
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0);
        fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.session));
        WTQ_TEST_CHECK_EQ_INT(r.returns, 1);
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0); /* data returned/ACKed, no FIN */
        WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, st) == WTQ_OK);
        if (row == 0) {
            ack(&r, ds, es, generation); /* commit may precede buffer return */
            WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
            WTQ_TEST_CHECK_EQ_INT(r.returns, 1);
        } else if (row == 1) {
            WTQ_TEST_CHECK(wtq_stream_reset(st, 7) == WTQ_OK);
        } else {
            wtq_conn_on_conn_closed(wtq_api_session_conn(r.session), 1, false, 4);
            fake_driver_cancel_pending(&r.drv);
        }
        fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.session));
        WTQ_TEST_CHECK_EQ_INT(r.returns, 2);
        WTQ_TEST_CHECK_EQ_INT(r.canceled, row == 0 ? 0 : 1);
        ack(&r, ds, es, generation);
        WTQ_TEST_CHECK_EQ_INT(r.commits, row == 0 ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT(r.closes, 1);
        wtq_stream_release(st);
        finish(&r, false, fp);
    }
    *fp += failures;
}

static void outcomes(int *fp)
{
    int failures = 0;
    for (int row = 0; row < 7; ++row) {
        static rig_t r;
        setup(&r, true, sizeof(wtq_session_events_t), true, fp);
        wtq_stream_t *st = NULL;
        WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
        wtq_stream_add_ref(st);
        struct wtq_dstream *ds = newest(&r);
        wtq_estream_t *es = ds->ectx;
        uint64_t generation = wtq_estream_generation_v1(es);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_OK);
        const uint8_t data[] = { 1, 2, 3 };
        wtq_span_t span = { data, sizeof(data) };
        WTQ_TEST_CHECK(wtq_stream_send(st, row == 0 ? NULL : &span, row == 0 ? 0 : 1,
                                        WTQ_SEND_FIN, &r) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(r.closes, 0);
        WTQ_TEST_CHECK(ds->ectx == es);
        WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_ERR_STATE);
        fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.session));
        WTQ_TEST_CHECK_EQ_INT(r.returns, 1);
        WTQ_TEST_CHECK_EQ_INT(r.commits, 0); /* buffer return is not ACK+FIN */
        if (row == 2 || row == 3) {
            WTQ_TEST_CHECK((row == 2 ? wtq_stream_reset(st, 42) : wtq_stream_abort(st, 42)) == WTQ_OK);
            WTQ_TEST_CHECK_EQ_INT(ds->shutdown_count, 1);
            WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
            WTQ_TEST_CHECK_EQ_U64(ds->last_shutdown.send_err, wtq_app_error_to_h3(42));
        } else if (row == 4) {
            WTQ_TEST_CHECK(fake_driver_deliver_stop(wtq_api_session_conn(r.session), ds,
                                                   wtq_app_error_to_h3(9), 4));
        } else if (row == 5) {
            WTQ_TEST_CHECK(wtq_session_close(r.session, 0, NULL, 0) == WTQ_OK);
            WTQ_TEST_CHECK(ds->last_shutdown.abort_send);
        } else if (row == 6) {
            r.close_in_commit = true;
            r.release_in_commit = true;
        }
        ack(&r, ds, es, generation);
        bool success = row < 2 || row == 6;
        WTQ_TEST_CHECK_EQ_INT(r.commits, success ? 1 : 0);
        WTQ_TEST_CHECK_EQ_INT(r.closes, 1);
        if (success) WTQ_TEST_CHECK(r.reset_in_commit == WTQ_ERR_CLOSED);
        if (row != 6) {
            ack(&r, ds, es, generation);
            WTQ_TEST_CHECK_EQ_INT(r.commits, success ? 1 : 0);
            WTQ_TEST_CHECK_EQ_INT(r.closes, 1);
            wtq_stream_release(st);
        } else {
            WTQ_TEST_CHECK_EQ_SIZE(r.order_len, 5);
            WTQ_TEST_CHECK(memcmp(r.order, "BCcXS", 5) == 0);
        }
        finish(&r, row == 6, fp);
    }
    *fp += failures;
}

static void capacity_and_stale(int *fp)
{
    int failures = 0;
    static rig_t r;
    setup(&r, true, sizeof(wtq_session_events_t), true, fp);
    wtq_stream_t *held[16];
    struct wtq_dstream *native[16];
    wtq_estream_t *engine[16];
    uint64_t generations[16];
    size_t count = 0;
    wtq_result_t rc = WTQ_OK;
    for (; count < 16; ++count) {
        rc = wtq_session_open_uni(r.session, &held[count]);
        if (rc != WTQ_OK) break;
        wtq_stream_add_ref(held[count]);
        native[count] = newest(&r);
        engine[count] = native[count]->ectx;
        generations[count] = wtq_estream_generation_v1(engine[count]);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(held[count]) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_stream_send(held[count], NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
    }
    WTQ_TEST_CHECK(count > 0 && count <= 16);
    wtq_stream_t *extra = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &extra) == WTQ_ERR_STREAM_LIMIT);
    WTQ_TEST_CHECK_EQ_INT(r.closes, 0);
    ack(&r, native[0], engine[0], generations[0]);
    wtq_stream_release(held[0]);
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &extra) == WTQ_OK);
    struct wtq_dstream *replacement = newest(&r);
    wtq_estream_t *new_es = replacement->ectx;
    uint64_t new_generation = wtq_estream_generation_v1(new_es);
    WTQ_TEST_CHECK(new_es == engine[0] && new_generation != generations[0]);
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(extra) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_send(extra, NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
    ack(&r, native[0], engine[0], generations[0]);
    ack(&r, replacement, new_es, generations[0]);
    wtq_conn_on_stream_send_shutdown_v1(wtq_api_session_conn(r.session), new_es,
        replacement, generations[0], false);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
    ack(&r, replacement, new_es, new_generation);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 2);
    for (size_t i = 1; i < count; ++i) {
        WTQ_TEST_CHECK(wtq_stream_reset(held[i], 0) == WTQ_OK);
        wtq_stream_release(held[i]);
    }
    finish(&r, false, fp);
    *fp += failures;
}

static void retained_and_reentrant(int *fp)
{
    int failures = 0;
    static rig_t r;
    setup(&r, true, sizeof(wtq_session_events_t), true, fp);
    wtq_stream_t *held[16];
    for (size_t i = 0; i < 16; ++i) {
        WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &held[i]) == WTQ_OK);
        wtq_stream_add_ref(held[i]);
        struct wtq_dstream *ds = newest(&r);
        wtq_estream_t *es = ds->ectx;
        uint64_t generation = wtq_estream_generation_v1(es);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(held[i]) == WTQ_OK);
        WTQ_TEST_CHECK(wtq_stream_send(held[i], NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
        fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.session));
        ack(&r, ds, es, generation);
        WTQ_TEST_CHECK(wtq_stream_enable_send_commit(held[i]) == WTQ_ERR_STATE);
    }
    WTQ_TEST_CHECK_EQ_INT(r.commits, 16);
    wtq_stream_t *extra = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &extra) == WTQ_ERR_STREAM_LIMIT);
    wtq_stream_release(held[0]);
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &extra) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_reset(extra, 0) == WTQ_OK);
    for (size_t i = 1; i < 16; ++i) wtq_stream_release(held[i]);
    finish(&r, false, fp);

    setup(&r, true, sizeof(wtq_session_events_t), true, fp);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &st) == WTQ_OK);
    wtq_stream_add_ref(st);
    struct wtq_dstream *ds = newest(&r);
    wtq_estream_t *es = ds->ectx;
    uint64_t generation = wtq_estream_generation_v1(es);
    WTQ_TEST_CHECK(wtq_stream_enable_send_commit(st) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, NULL) == WTQ_OK);
    fake_driver_complete_sends(&r.drv, wtq_api_session_conn(r.session));
    WTQ_TEST_CHECK(wtq_session_open_uni(r.session, &extra) == WTQ_OK);
    r.other_closes = 1;
    r.close_in_commit = r.release_in_commit = true;
    ack(&r, ds, es, generation);
    WTQ_TEST_CHECK_EQ_INT(r.commits, 1);
    WTQ_TEST_CHECK_EQ_INT(r.closes, 2);
    WTQ_TEST_CHECK_EQ_INT(r.session_closes, 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.order_len, 6);
    WTQ_TEST_CHECK(memcmp(r.order, "BCXcXS", 6) == 0);
    finish(&r, true, fp);
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    event_abi(&failures);
    availability(&failures);
    outcomes(&failures);
    cookie_and_early_ack(&failures);
    capacity_and_stale(&failures);
    retained_and_reentrant(&failures);
    printf("api_send_commit: failures=%d\n", failures);
    return failures ? 1 : 0;
}
