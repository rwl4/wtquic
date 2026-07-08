#ifndef WTQ_TEST_FAKE_DRIVER_H
#define WTQ_TEST_FAKE_DRIVER_H

/*
 * Recording fake backend for the engine driver SPI.
 *
 * The fake IS the backend, so it defines the opaque backend structs.
 * Engine ops append into per-stream byte logs (plus op counters); the
 * simpair/test harness reads those logs and delivers them into a peer
 * engine deterministically.
 */

#include "wt_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FAKE_MAX_STREAMS 48
#define FAKE_STREAM_CAP 4096
#define FAKE_MAX_PENDING 32
#define FAKE_MAX_DGRAMS 32
#define FAKE_DGRAM_CAP 2048

struct wtq_dstream {
    bool in_use;
    bool is_local;         /* opened by the owning engine */
    bool is_bidi;
    struct wtq_dstream *linked; /* simpair: the peer-side twin (bidi) */
    uint64_t id;
    wtq_estream_t *ectx;   /* engine ctx (receiver side) */
    uint8_t bytes[FAKE_STREAM_CAP];
    size_t len;            /* bytes appended by the engine (local) */
    size_t delivered;      /* bytes already delivered to the peer */
    bool fin;
    bool fin_delivered;
    uint64_t reset_err;
    bool reset;
    int reset_count;
    uint64_t stop_err;
    bool stopped;
    /* the structured shutdown requests this stream received */
    int shutdown_count;
    wtq_shutdown_t last_shutdown;
    int stop_count;
    bool recv_disabled;    /* recv_enable(false) seen last */
    int recv_enable_count;
    int detach_count;
    /* pump bookkeeping: closures propagate to the peer exactly once */
    bool reset_delivered;
    bool stop_delivered;
};

/* One accepted send_gather awaiting completion. The fake mimics the
 * MsQuic contract: an accepted send completes exactly once; a stream
 * reset or connection close cancels the still-pending ones. */
struct fake_pending_send {
    bool in_use;
    struct wtq_dstream *ds;
    void *cookie;
    bool canceled;
};

struct wtq_driver {
    bool is_client;
    uint64_t next_uni_id;  /* client: 2,6,10... server: 3,7,11... */
    uint64_t next_bidi_id; /* client: 0,4,8...  server: 1,5,9...  */
    struct wtq_dstream streams[FAKE_MAX_STREAMS];
    bool closed;
    uint64_t close_err;
    int open_count;
    int send_count;
    int gather_count;
    int close_count;
    struct fake_pending_send pending[FAKE_MAX_PENDING];
    size_t pending_head; /* completion is FIFO */
    size_t pending_tail;
    /* datagrams: a log of sent datagrams (the sim's wire) */
    struct {
        uint8_t bytes[FAKE_DGRAM_CAP];
        size_t len;
    } dgrams[FAKE_MAX_DGRAMS];
    size_t dgram_count;
    size_t dgram_delivered; /* consumed by the simpair */
    size_t dgram_max;       /* dgram_max_size() result; 0 = disabled */
    /* Async-id transport mode: open_* returns WTQ_STREAM_ID_UNKNOWN and
     * the computed id is stashed on the dstream for a later
     * fake_driver_deliver_native_id (mirrors Network.framework). */
    bool async_ids;
    /* fault injection for RED/edge tests */
    bool fail_open;
    bool fail_send;
    bool fail_dgram;
    /* Deterministic fail-at-Nth-call injection (1-based; 0 = off).
     * Orthogonal to the boolean always-fail controls above. */
    int fail_open_at;
    int fail_send_at;
    /* shutdown fault injection (see fake_shutdown_stream) */
    bool fail_shutdown_before;
    bool fail_shutdown_after_first;
    /* Every attempted call, failed ones included (open_count/send_count
     * only tally the calls that succeeded). */
    int open_calls;
    int send_calls;
};

void fake_driver_init(struct wtq_driver *drv, bool is_client);
const wtq_driver_ops_t *fake_driver_ops(void);

/* Mark every still-pending send as canceled, as a real transport does
 * when the connection is lost. The completions are delivered (canceled)
 * on the next fake_driver_complete_sends. */
void fake_driver_cancel_pending(struct wtq_driver *drv);

/* Allocate a receiver-side stream slot (for peer-opened streams). */
struct wtq_dstream *fake_driver_add_peer_stream(struct wtq_driver *drv,
                                                uint64_t id);

/* Find a local stream by creation order (0 = first opened). */
struct wtq_dstream *fake_driver_local(struct wtq_driver *drv,
                                      size_t index);

/* Deliver all pending send_gather completions into the engine (FIFO,
 * exactly once each). Returns how many were delivered. Backends do this
 * asynchronously; tests/simpair call it explicitly. */
size_t fake_driver_complete_sends(struct wtq_driver *drv, wtq_conn_t *conn);

/* Deliver a transport event the way a real backend does: keyed by the
 * dstream's recorded engine ctx (ds->ectx). A stream with no linkage —
 * never attached, or detached by the engine — delivers NOTHING and the
 * helper returns false. Peer-side dstreams get ectx recorded by the
 * caller after wtq_conn_on_peer_*_opened, exactly as a backend records
 * it. These are the seam the stale-ectx regression tests drive. */
bool fake_driver_deliver_bytes(wtq_conn_t *conn, struct wtq_dstream *ds,
                               const uint8_t *data, size_t len, bool fin,
                               uint64_t now_us);
bool fake_driver_deliver_reset(wtq_conn_t *conn, struct wtq_dstream *ds,
                               uint64_t quic_err, uint64_t now_us);
bool fake_driver_deliver_stop(wtq_conn_t *conn, struct wtq_dstream *ds,
                              uint64_t quic_err, uint64_t now_us);

/* Async-id mode: report the stream's stashed native id through the
 * CURRENT ds->ectx (identity-checked exactly like the deliveries above;
 * detached streams deliver nothing and return false). */
bool fake_driver_deliver_native_id(wtq_conn_t *conn, struct wtq_dstream *ds,
                                   uint64_t now_us);
/* Same, but with an arbitrary id — the invalid-report RED tests. */
bool fake_driver_deliver_native_id_as(wtq_conn_t *conn,
                                      struct wtq_dstream *ds, uint64_t id,
                                      uint64_t now_us);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_FAKE_DRIVER_H */
