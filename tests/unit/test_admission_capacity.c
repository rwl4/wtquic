/* Real engine occupancy, without exported test seams. */
#include <stdlib.h>
#include "../../src/engine/conn.c"
#include "fake_driver.h"
#include "test_support.h"

static size_t occupied(const wtq_conn_t *conn)
{
    size_t count = 0;
    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; ++i)
        count += conn->peer[i].kind != ES_FREE;
    return count;
}

static int prefix_reserve(void)
{
    int failures = 0;
    struct wtq_driver *drv = calloc(1, sizeof(*drv));
    wtq_conn_t *conn = calloc(1, sizeof(*conn));
    WTQ_TEST_CHECK(drv != NULL && conn != NULL);
    if (!drv || !conn) { free(drv); free(conn); return failures; }
    fake_driver_init(drv, true);
    conn->drv = drv;
    conn->ops = *fake_driver_ops();
    conn->persp = WTQ_PERSPECTIVE_CLIENT;
    conn->session_established = true;
    conn->sess_state = SS_ESTABLISHED;
    wtq_conn_enable_admission(conn);
    /* CONNECT and peer control are persistent protocol owners. */
    conn->peer[3].kind = ES_CONNECT;
    conn->peer[0].kind = ES_CONTROL;
    conn->peer_control_seen = true;
    for (size_t i = 0; i < 12; ++i) {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_open_uni(conn, &es), WTQ_OK);
    }
    WTQ_TEST_CHECK_EQ_SIZE(occupied(conn), 14);
    wtq_peer_admission_t peers[4];
    for (size_t i = 0; i < 2; ++i) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, 7 + i * 4);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(conn, &peers[i], ds,
            ds->id, false, (unsigned)i), WTQ_OK);
        const uint8_t prefix = 0xc0;
        size_t used = 99;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &peers[i],
            &prefix, 1, false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE(used, 1);
    }
    /* An incomplete type must not consume either late critical reserve. */
    WTQ_TEST_CHECK_EQ_SIZE(occupied(conn), 14);
    for (uint8_t type = 2; type <= 3; ++type) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, 15 + (type - 2) * 4);
        wtq_result_t rc = wtq_conn_peer_admission_init(conn, &peers[type], ds,
            ds->id, false, type);
        WTQ_TEST_CHECK_EQ_INT(rc, WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(ds->stop_count, 0);
        if (rc == WTQ_OK) {
            size_t used = 99;
            WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &peers[type],
                &type, 1, false, 0, &used), WTQ_OK);
            WTQ_TEST_CHECK_EQ_SIZE(used, 1);
        }
    }
    WTQ_TEST_CHECK(!conn->closed);
    free(conn); free(drv);
    return failures;
}

static int unknown_and_fin(wtq_perspective_t role)
{
    int failures = 0;
    struct wtq_driver *drv = calloc(1, sizeof(*drv));
    wtq_conn_t *conn = calloc(1, sizeof(*conn));
    if (!drv || !conn) { free(drv); free(conn); return 1; }
    fake_driver_init(drv, role == WTQ_PERSPECTIVE_CLIENT);
    conn->drv = drv;
    conn->ops = *fake_driver_ops();
    conn->persp = role;
    conn->session_established = true;
    conn->sess_state = SS_ESTABLISHED;
    wtq_conn_enable_admission(conn);
    unsigned capacity = role == WTQ_PERSPECTIVE_CLIENT ? 12u : 6u;
    for (unsigned i = 0; i < capacity; ++i) {
        wtq_estream_t *es = NULL;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_open_uni(conn, &es), WTQ_OK);
    }
    wtq_peer_admission_t peers[5];
    for (unsigned i = 0; i < 5; ++i) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, i * 4u + 2u);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(conn, &peers[i], ds,
            ds->id, false, i), WTQ_OK);
        uint8_t bytes[] = { i < 2 ? 0x21 : i == 2 ? 0 : (uint8_t)(i - 1), 0xa5 };
        size_t used = 99;
        size_t len = i < 2 ? sizeof(bytes) : 1;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &peers[i],
            bytes, len, false, 0, &used), WTQ_OK);
        WTQ_TEST_CHECK_EQ_SIZE(used, len);
        if (i < 2) WTQ_TEST_CHECK(peers[i].es == NULL);
        else WTQ_TEST_CHECK(peers[i].es == &conn->peer[i - 2]);
    }
    WTQ_TEST_CHECK_EQ_SIZE(occupied(conn), capacity + 3);
    WTQ_TEST_CHECK(!conn->closed);
    wtq_peer_admission_t duplicate;
    struct wtq_dstream *dup_ds = fake_driver_add_peer_stream(drv, 22);
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(conn, &duplicate, dup_ds,
        22, false, 5), WTQ_OK);
    const uint8_t duplicate_type = 2;
    size_t duplicate_used = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &duplicate,
        &duplicate_type, 1, false, 0, &duplicate_used), WTQ_ERR_PROTO);
    WTQ_TEST_CHECK_EQ_U64(conn->close_code, WTQ_H3_STREAM_CREATION_ERROR);
    free(conn); free(drv);

    for (unsigned row = 0; row < 4; ++row) {
        drv = calloc(1, sizeof(*drv));
        conn = calloc(1, sizeof(*conn));
        if (!drv || !conn) { free(drv); free(conn); return failures + 1; }
        fake_driver_init(drv, role == WTQ_PERSPECTIVE_CLIENT);
        conn->drv = drv; conn->ops = *fake_driver_ops(); conn->persp = role;
        wtq_conn_enable_admission(conn);
        bool bidi = row == 1 || row == 2;
        wtq_peer_admission_t p;
        struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, bidi ? 0 : 2);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(conn, &p, ds,
            ds->id, bidi, bidi ? 8 : 0), WTQ_OK);
        const uint8_t partial[] = { 0x40, 0x41, 0xc0 };
        const uint8_t type = row == 3 ? 1 : 0xc0;
        size_t used = 0;
        wtq_result_t rc = wtq_conn_peer_admission_bytes(conn, &p,
            row == 2 ? partial : &type, row == 2 ? 3 : 1, true, 0, &used);
        WTQ_TEST_CHECK_EQ_INT(rc, row != 0 ? WTQ_ERR_PROTO : WTQ_OK);
        if (bidi) WTQ_TEST_CHECK_EQ_U64(conn->close_code,
            row == 2 ? WTQ_H3_FRAME_ERROR : role == WTQ_PERSPECTIVE_SERVER
            ? WTQ_H3_REQUEST_INCOMPLETE : WTQ_H3_STREAM_CREATION_ERROR);
        else if (row == 3) WTQ_TEST_CHECK_EQ_U64(conn->close_code,
            role == WTQ_PERSPECTIVE_SERVER ? WTQ_H3_STREAM_CREATION_ERROR : WTQ_H3_ID_ERROR);
        else WTQ_TEST_CHECK(!conn->closed);
        free(conn); free(drv);
    }
    return failures;
}

static wtq_conn_t *opening_conn;
static wtq_estream_t *nested_entry;
static bool opening_nested;
static wtq_result_t nested_open(wtq_driver_t *drv, wtq_estream_t *es,
    wtq_dstream_t **out, uint64_t *id)
{
    if (!opening_nested) {
        opening_nested = true;
        wtq_result_t rc = wtq_conn_wt_open_uni(opening_conn, &nested_entry);
        if (rc != WTQ_OK) return rc;
    }
    return fake_driver_ops()->open_uni(drv, es, out, id);
}

static int local_reservation(void)
{
    int failures = 0;
    struct wtq_driver *drv = calloc(1, sizeof(*drv));
    wtq_conn_t *conn = calloc(1, sizeof(*conn));
    if (!drv || !conn) { free(drv); free(conn); return 1; }
    fake_driver_init(drv, true);
    conn->drv = drv; conn->ops = *fake_driver_ops();
    conn->ops.open_uni = nested_open;
    conn->persp = WTQ_PERSPECTIVE_CLIENT;
    conn->sess_state = SS_ESTABLISHED;
    wtq_conn_enable_admission(conn);
    opening_conn = conn; nested_entry = NULL; opening_nested = false;
    wtq_estream_t *outer = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_wt_open_uni(conn, &outer), WTQ_OK);
    WTQ_TEST_CHECK(outer && nested_entry && outer != nested_entry);
    WTQ_TEST_CHECK_EQ_SIZE(occupied(conn), 2);
    free(conn); free(drv);
    opening_conn = NULL;
    return failures;
}

static int every_prefix_split(void)
{
    int failures = 0;
    struct wtq_driver *drv = calloc(1, sizeof(*drv));
    wtq_conn_t *conn = calloc(1, sizeof(*conn));
    if (!drv || !conn) { free(drv); free(conn); return 1; }
    fake_driver_init(drv, true);
    conn->drv = drv; conn->ops = *fake_driver_ops();
    conn->persp = WTQ_PERSPECTIVE_CLIENT;
    conn->sess_state = SS_ESTABLISHED; conn->session_established = true;
    conn->session_id = UINT64_C(1) << 60;
    wtq_conn_enable_admission(conn);
    const uint8_t wire[17] = { 0xc0, 0, 0, 0, 0, 0, 0, 0x54,
                              0xd0, 0, 0, 0, 0, 0, 0, 0, 0xab };
    for (size_t split = 0; split <= 16; ++split) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, 7 + 4 * split);
        wtq_peer_admission_t p;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_init(conn, &p, ds,
            ds->id, false, 0), WTQ_OK);
        size_t first = 99, second = 99;
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &p, wire,
            split, false, 0, &first), split == 16 ? WTQ_ERR_WOULD_BLOCK : WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_peer_admission_bytes(conn, &p, wire + split,
            sizeof(wire) - split, true, 0, &second), WTQ_ERR_WOULD_BLOCK);
        WTQ_TEST_CHECK_EQ_SIZE(first + second, 16);
        WTQ_TEST_CHECK(p.fill == 16 && p.es == NULL && p.state == 1);
        WTQ_TEST_CHECK_EQ_SIZE(occupied(conn), 0);
        wtq_conn_peer_admission_forget(conn, &p);
    }
    free(conn); free(drv);
    return failures;
}

int main(void)
{
    return prefix_reserve() + unknown_and_fin(WTQ_PERSPECTIVE_CLIENT) +
        unknown_and_fin(WTQ_PERSPECTIVE_SERVER) + local_reservation() + every_prefix_split();
}
