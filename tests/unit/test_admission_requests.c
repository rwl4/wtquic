#include "../../src/engine/conn.c"
#define main legacy_request_main
#include "test_engine_connect.c"
#undef main

static struct wtq_dstream *admission_request(rig_t *r,
    wtq_peer_admission_t *p, unsigned slot, const uint8_t *bytes,
    size_t len, bool fin, int *fp)
{
    int failures = 0;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, slot * 4u);
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(r->conn, p, ds,
        ds->id, true, 8 + slot), WTQ_OK);
    size_t used = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r->conn, p,
        bytes, len, fin, 0, &used), WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(used, len);
    ds->ectx = p->es;
    *fp += failures;
    return ds;
}

static void admission_settings(rig_t *r, wtq_peer_admission_t *p,
    unsigned reservation, int *fp)
{
    int failures = 0;
    uint8_t bytes[128] = { 0 };
    wtq_h3_settings_encode_cfg_t cfg = { true, false };
    size_t len = 0, used = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_h3_settings_encode_frame(&cfg,
        bytes + 1, sizeof(bytes) - 1, &len), WTQ_H3_SETTINGS_OK);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r->drv, 2);
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(r->conn, p, ds, 2,
        false, reservation), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r->conn, p,
        bytes, len + 1, false, 0, &used), WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(used, len + 1);
    *fp += failures;
}

static int requests_and_wt(unsigned row)
{
    int failures = 0;
    rig_t r;
    server_paths_up(&r, true, &failures);
    wtq_conn_enable_admission(r.conn);
    wtq_peer_admission_t control;
    admission_settings(&r, &control, 0, &failures);
    wtq_peer_admission_t peers[7];
    uint8_t request[512];
    size_t len = build_request(request, sizeof(request), "/moq", OFFER, 2);
    struct wtq_dstream *session = admission_request(&r, &peers[0], 0,
        request, len, false, &failures);
    expect_response_status(session, 200, &failures);
    WTQ_TEST_CHECK(r.conn->session_es == &r.conn->peer[3]);
    for (size_t i = 0; i < 6; ++i) {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_open_uni(r.conn, &es), WTQ_OK);
        WTQ_TEST_CHECK(es >= &r.conn->peer[10] && es < &r.conn->peer[16]);
    }
    static const wtq_qpack_field_t fields[] = {
        { ":method", 7, "GET", 3, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "example.com", 11, false },
        { ":path", 5, "/moq", 4, false },
    };
    len = build_headers(request, sizeof(request), fields, 4);
    uint64_t refusal = 0;
    if (row == 1) {
        static const uint8_t malformed[] = { 1, 3, 0, 0, 0x81 };
        memcpy(request, malformed, sizeof(malformed));
        len = sizeof(malformed);
        refusal = WTQ_H3_MESSAGE_ERROR;
    } else if (row == 2) {
        WTQ_TEST_CHECK_EQ_INT(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS,
            4096, request, sizeof(request), &len), 0);
        refusal = WTQ_H3_EXCESSIVE_LOAD;
    } else if (row >= 3) {
        len = build_request(request, sizeof(request),
            row == 3 ? "/absent" : "/moq", OFFER, 2);
        /* Established-session refusal precedes path lookup. */
        refusal = WTQ_H3_REQUEST_REJECTED;
    }
    struct wtq_dstream *requests[6];
    for (unsigned i = 1; i < 7; ++i) {
        requests[i - 1] = admission_request(&r, &peers[i], i,
            request, 1, false, &failures);
        WTQ_TEST_CHECK(peers[i].es == &r.conn->peer[3 + i]);
    }
    wtq_peer_admission_t qpack[2];
    for (unsigned i = 0; i < 2; ++i) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 6 + 4u * i);
        size_t used = 0;
        uint8_t type = (uint8_t)(2 + i);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(r.conn,
            &qpack[i], ds, ds->id, false, i + 1), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn,
            &qpack[i], &type, 1, false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK(qpack[i].es == &r.conn->peer[i + 1]);
    }
    wtq_estream_t *extra = NULL;
    int opens = r.drv.open_count;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_open_uni(r.conn, &extra), WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(r.drv.open_count, opens);
    for (unsigned i = 1; i < 7; ++i) {
        size_t used = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn, &peers[i],
            request + 1, len - 1, false, 0, &used), WTQ_OK);
        if (refusal) {
            WTQ_TEST_CHECK(requests[i - 1]->reset && requests[i - 1]->stopped);
            WTQ_TEST_CHECK_EQ_U64(requests[i - 1]->reset_err, refusal);
            WTQ_TEST_CHECK_EQ_INT(requests[i - 1]->shutdown_count, 1);
            WTQ_TEST_CHECK_EQ_SIZE(requests[i - 1]->len, 0);
        } else expect_response_status(requests[i - 1], 400, &failures);
        WTQ_TEST_CHECK(peers[i].es->request_dead);
    }
    WTQ_TEST_CHECK(!r.conn->closed);
    rig_down(&r);
    return failures;
}

static int before_settings(unsigned row)
{
    int failures = 0;
    rig_t r;
    server_paths_up(&r, true, &failures);
    wtq_conn_enable_admission(r.conn);
    wtq_peer_admission_t peers[7];
    uint8_t request[512];
    size_t len = build_request(request, sizeof(request), "/moq", OFFER, 2);
    for (unsigned i = 0; i < 7; ++i)
        (void)admission_request(&r, &peers[i], i, request,
            i == 1 ? len : 1, false, &failures);
    WTQ_TEST_CHECK(r.conn->parked_es == peers[1].es);
    WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    WTQ_TEST_CHECK_EQ_SIZE(peers[1].ds->len, 0);
    for (unsigned i = 0; i < 7; ++i)
        WTQ_TEST_CHECK(peers[i].es == &r.conn->peer[3 + i]);
    size_t used = 0;
    if (row == 1) {
        uint8_t original[512];
        size_t original_len = r.conn->parked_fill;
        memcpy(original, r.conn->parked_buf, original_len);
        uint8_t trailers[64];
        size_t trailer_len = build_headers(trailers, sizeof(trailers), NULL, 0);
        WTQ_TEST_CHECK(trailer_len > 0);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn, &peers[1],
            trailers, trailer_len, true, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK(r.conn->parked_fin);
        WTQ_TEST_CHECK(r.conn->parked_fill == original_len &&
            memcmp(original, r.conn->parked_buf, original_len) == 0);
    } else if (row == 2) {
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_reset(r.conn, peers[1].es,
            UINT64_C(0x010c), 0), WTQ_OK);
        WTQ_TEST_CHECK(r.conn->parked_es == NULL);
    } else if (row == 3) {
        const uint8_t data[] = { 0, 1, 0xa5 };
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn, &peers[1],
            data, sizeof(data), false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK(peers[1].ds->reset && peers[1].ds->stopped);
        WTQ_TEST_CHECK_EQ_U64(peers[1].ds->reset_err, WTQ_H3_REQUEST_REJECTED);
        WTQ_TEST_CHECK(r.conn->parked_es == NULL);
    } else if (row == 4) {
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn, &peers[2],
            request + 1, len - 1, false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK(peers[2].ds->reset && peers[2].ds->stopped);
        WTQ_TEST_CHECK_EQ_U64(peers[2].ds->reset_err, WTQ_H3_REQUEST_REJECTED);
        WTQ_TEST_CHECK_EQ_SIZE(peers[2].ds->len, 0);
    }
    wtq_peer_admission_t uni[3];
    for (unsigned i = 0; i < 2; ++i) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 6u + 4u * i);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(r.conn, &uni[i], ds,
            ds->id, false, i), WTQ_OK);
        uint8_t prefix = i == 0 ? 0x21 : 0xc0;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(r.conn, &uni[i],
            &prefix, 1, false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK(uni[i].es == NULL);
    }
    admission_settings(&r, &uni[2], 2, &failures);
    if (row == 2 || row == 3) {
        WTQ_TEST_CHECK_EQ_SIZE(peers[1].ds->len, 0);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 0);
    } else {
        expect_response_status(peers[1].ds, 200, &failures);
        WTQ_TEST_CHECK_EQ_INT(r.app.established_events, 1);
        if (row == 1) {
            WTQ_TEST_CHECK_EQ_INT(r.app.closed_events, 1);
            WTQ_TEST_CHECK(r.app.closed_clean);
        } else WTQ_TEST_CHECK(r.conn->session_es == peers[1].es);
    }
    WTQ_TEST_CHECK(!r.conn->closed);
    rig_down(&r);
    return failures;
}

int main(void)
{
    int failures = 0;
    for (unsigned row = 0; row < 5; ++row) failures += requests_and_wt(row);
    for (unsigned row = 0; row < 5; ++row) failures += before_settings(row);
    return failures;
}
