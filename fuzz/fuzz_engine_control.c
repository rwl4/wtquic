/*
 * fuzz_engine_control — hostile peer control/uni-stream bytes into a
 * fresh engine (client or server per data[0]).
 *
 * The fuzzer input drives a peer unidirectional stream: the first bytes
 * are its stream-type varint (0x00 control, 0x02/0x03 QPACK, 0x54 WT,
 * or anything), and the rest is the stream body, fed in fuzzer-chosen
 * chunk sizes. This exercises stream classification, SETTINGS parsing,
 * control-frame legality, and the drain paths. A second selector byte
 * optionally opens a second peer uni from the same input to hit the
 * "duplicate critical stream" branches.
 *
 * Invariants (abort => crash): no UB/crash; the engine allocates
 * nothing after create, so the balance-checking allocator must show
 * exactly one live allocation (the conn) until destroy and zero after.
 */

#include <string.h>

#include "wtq_fuzz_util.h"

#include "engine/wt_driver.h"
#include "fake_driver.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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
    (void)fz_u8(&r); /* perspective byte */
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

    /* Up to two peer uni streams from the same input. */
    uint64_t id = client ? 3 : 2;
    for (int s = 0; s < 2 && fz_more(&r) && !wtq_conn_is_closed(conn);
         s++) {
        struct wtq_dstream *ds = fake_driver_add_peer_stream(&drv, id);
        id += 4;
        if (ds == NULL)
            break;
        wtq_estream_t *es = NULL;
        if (wtq_conn_on_peer_uni_opened(conn, ds, ds->id, &es) != WTQ_OK ||
            es == NULL)
            continue;
        /* feed the body in fuzzer-chosen chunks */
        while (fz_more(&r) && !wtq_conn_is_closed(conn)) {
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 64);
            bool fin = n == 0; /* an empty chunk marks end-of-stream */
            int was = wtq_conn_is_closed(conn);
            wtq_result_t rc =
                wtq_conn_on_stream_bytes(conn, es, p, n, fin, 1000);
            fz_check_fatal(conn, was, rc); /* fatal must not return OK */
            if (fin)
                break;
        }
    }

    wtq_conn_destroy(conn);
    fz_alloc_check(&fa);
    return 0;
}
