/*
 * fuzz_engine_connect — hostile extended-CONNECT request/response bytes.
 *
 * data[0] picks the direction:
 *   even -> a SERVER engine at peer-SETTINGS with a path registered;
 *           the fuzzer input is a peer bidi request stream (its bytes
 *           feed the HEADERS/CONNECT decode and the request frame walk).
 *   odd  -> a CLIENT engine that has sent its CONNECT; the fuzzer input
 *           is the response stream on the CONNECT bidi.
 * The body is fed in fuzzer-chosen chunk sizes.
 *
 * Invariants (abort => crash): no UB/crash; balance-checking allocator
 * shows zero live allocations after destroy and no invalid frees.
 */

#include <string.h>

#include "wtq_fuzz_util.h"

#include "engine/wt_driver.h"
#include "fake_driver.h"
#include "proto/h3_settings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Deliver a valid WT SETTINGS control stream to prove WebTransport
 * support (so CONNECT / requests are accepted). */
static void deliver_settings(wtq_conn_t *conn, struct wtq_driver *drv,
                             bool client)
{
    uint8_t st[64];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;

    st[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&scfg, st + 1, sizeof(st) - 1,
                                     &flen) != 0)
        return;
    uint64_t id = client ? 3 : 2;
    struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, id);
    wtq_estream_t *es = NULL;
    if (ds == NULL)
        return;
    if (wtq_conn_on_peer_uni_opened(conn, ds, id, &es) == WTQ_OK &&
        es != NULL)
        (void)wtq_conn_on_stream_bytes(conn, es, st, 1 + flen, false,
                                       1000);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    if (size > 4096)
        size = 4096;

    wtq_fault_alloc_t fa;
    struct wtq_driver drv;
    bool client = (data[0] & 1) != 0;
    fz_t r;

    fz_init(&r, data, size);
    (void)fz_u8(&r);
    fake_driver_init(&drv, client);

    wtq_conn_cfg_t cfg = {
        .alloc = fz_alloc(&fa),
        .perspective = client ? WTQ_PERSPECTIVE_CLIENT
                              : WTQ_PERSPECTIVE_SERVER,
        .enable_connect_protocol = true,
    };
    wtq_conn_t *conn = NULL;
    if (wtq_conn_create(&cfg, &drv, fake_driver_ops(), &conn) != WTQ_OK)
        return 0;
    if (wtq_conn_start(conn, 1000) != WTQ_OK) {
        wtq_conn_destroy(conn);
        fz_alloc_check(&fa);
        return 0;
    }

    wtq_estream_t *target = NULL;

    if (client) {
        static const char *const offer[] = { "moqt-18", "moqt-16" };
        wtq_client_connect_cfg_t cc = {
            .authority = "h", .path = "/p", .origin = NULL,
            .protocols = offer, .protocol_count = 2,
            .require_protocol = false,
        };
        (void)wtq_conn_client_connect(conn, &cc);
        deliver_settings(conn, &drv, true); /* triggers deferred CONNECT */
        for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
            if (drv.streams[i].in_use && drv.streams[i].is_local &&
                drv.streams[i].is_bidi)
                target = drv.streams[i].ectx;
    } else {
        static const char *const supported[] = { "moqt-18" };
        wtq_server_path_cfg_t path = {
            .path = "/p", .protocols = supported, .protocol_count = 1,
            .require_protocol = false,
        };
        (void)wtq_conn_server_set_paths(conn, &path, 1);
        deliver_settings(conn, &drv, false);
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&drv, 0);
        if (ds != NULL) {
            wtq_estream_t *es = NULL;
            if (wtq_conn_on_peer_bidi_opened(conn, ds, 0, &es) == WTQ_OK)
                target = es;
        }
    }

    /* feed the fuzzer body to the request/response stream in chunks */
    while (target != NULL && fz_more(&r) && !wtq_conn_is_closed(conn)) {
        const uint8_t *p;
        size_t n = fz_bytes(&r, &p, 64);
        bool fin = n == 0;
        int was = wtq_conn_is_closed(conn);
        wtq_result_t rc =
            wtq_conn_on_stream_bytes(conn, target, p, n, fin, 1000);
        fz_check_fatal(conn, was, rc);
        if (fin)
            break;
    }

    wtq_conn_destroy(conn);
    fz_alloc_check(&fa);
    return 0;
}
