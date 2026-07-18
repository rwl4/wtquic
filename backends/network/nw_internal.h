/*
 * Network.framework client backend — INTERNAL header (attach core,
 * production slice 5 of the stream-identity design).
 *
 * Everything here is backend-internal: the library is built on Apple
 * only and is NOT installed or exported. The public managed lifecycle
 * (create / retain / release / post / stop_begin / join, §7.2 of the
 * design) lives in <wtquic/wtquic_network.h>; the constructor and
 * blocking rundown below are its TEST-ONLY composition.
 *
 * Threading model (§7.1): one backend-owned SERIAL dispatch queue per
 * connection is the serialization domain. Every driver operation the
 * engine invokes and every engine input the backend delivers runs on
 * that queue; there is no caller-supplied queue and no synchronous
 * cross-thread entry.
 */
#ifndef WTQ_NW_INTERNAL_H
#define WTQ_NW_INTERNAL_H

#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <Network/Network.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_network.h>

#include "api/api_internal.h"
#include "engine/wt_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bounded send window (§3.3): a fixed per-stream ring of two-phase
 * records plus a byte cap. send_gather beyond either bound returns
 * WTQ_ERR_WOULD_BLOCK. A slot is reusable only once BOTH references
 * dropped: the app reference (engine completion delivered exactly once,
 * real or synthetic-deduped) and the transport reference (Apple's copy
 * of the completion block disposed — observed via the ARC holder's
 * dealloc, never inferred).
 */
#define WTQ_NW_SEND_RECORDS 16
#define WTQ_NW_SEND_BYTES_MAX (1u << 20)

struct wtq_nw_send_rec {
    bool in_use;
    bool app_done;        /* engine completion delivered (APP_COMPLETED) */
    bool transport_done;  /* block disposed (TRANSPORT_RETIRED)          */
    void *cookie;
    size_t bytes;
    struct wtq_dstream *ds; /* owning stream (alive while !transport_done) */
};

/*
 * One entry in a stream's SEND CHAIN. NW loses bytes when multiple
 * sends are in flight on a freshly-ready stream (measured, both
 * orders: a preamble or a gather in a back-to-back pair intermittently
 * never reaches the wire even though its completion fires) — so the
 * backend keeps AT MOST ONE nw_connection_send outstanding per stream:
 * every send is queued and the next is issued from the previous one's
 * completion. Sends before `ready` queue the same way.
 */
struct wtq_nw_pending_send {
    dispatch_data_t d;              /* retained; NULL = FIN-only send */
    bool fin;                       /* is_complete on the stream ctx */
    struct wtq_nw_send_rec *rec;    /* gather record, NULL for plain */
    struct wtq_nw_send_batch *batch; /* PREALLOCATED batch memory: the
                                        accepted-send contract forbids
                                        post-accept allocation failure
                                        paths; the pump uses the first
                                        entry's and frees the rest */
    struct wtq_nw_pending_send *next;
};

/*
 * One coalesced send: everything queued at pump time goes to NW as a
 * SINGLE nw_connection_send (probe-proven single-send reliability at
 * ready; back-to-back sends on a fresh stream intermittently lose one
 * even when chained through completions — measured). The batch fans
 * the completion out to every gather record it carried.
 */
struct wtq_nw_send_batch {
    struct wtq_dstream *ds;
    int nrecs;
    struct wtq_nw_send_rec *recs[WTQ_NW_SEND_RECORDS];
    int phases_done; /* completion + retire each count once; free at 2 */
};

struct wtq_dstream {
    struct wtq_driver *drv;
    nw_connection_t conn;    /* retained; NULL once released            */
    wtq_estream_t *ectx;     /* engine ctx; NULL = critical/detached    */
    struct wtq_dstream *next;
    uint64_t id;             /* native id; WTQ_STREAM_ID_UNKNOWN until
                                the transport reports one at ready      */
    bool is_local;
    bool is_bidi;
    bool ready_seen;
    bool failed_seen;        /* `failed` observed: effects applied once */
    bool terminal;           /* `cancelled` observed — the ONLY final
                                state: NW can deliver failed AND then
                                cancelled, and refuses handler changes
                                after cancel, so memory captured by the
                                state handler is freeable only here    */
    bool cancel_issued;
    bool cancel_deferred;    /* shutdown requested before ready: the
                                stamp needs metadata, so the stamped
                                cancel is applied AT ready (the probe
                                rule: never stamp a stream whose
                                identity is not established) */
    uint64_t cancel_code;
    bool hidden;             /* NW's own hidden local stream (e.g. the
                                multiplex group's client-bidi 0): never
                                surfaced to the engine, occupies NO
                                engine pool slot — backend-parked only  */
    bool recv_enabled;
    bool recv_pending;       /* a receive block is outstanding          */
    /*
     * Bounded backend-local deferred receive (pause contract). A receive
     * completion that arrives while the app has paused the stream is held
     * here instead of reaching the engine: op_recv_enable(false) only
     * stops FUTURE arms, so the ONE already-outstanding receive can still
     * complete after pause returned. At most one completion is ever held —
     * only one nw_connection_receive is armed at a time — so this is a
     * single slot, never a queue; a second deferral is an invariant
     * failure. Resume replays it to the engine exactly once, in order,
     * then releases it. Zero-copy: the transport dispatch_data_t is
     * RETAINED, never copied.
     */
    bool recv_deferred;      /* a completion is held (paused)            */
    bool recv_deferred_fin;  /* the held completion carried the FIN      */
    bool recv_deferred_errored; /* the held completion carried a receive
                                   error (NW may deliver data received
                                   before the error): resume delivers the
                                   content once but never re-arms          */
    dispatch_data_t recv_deferred_data; /* retained buffer; NULL = pure FIN */
    bool send_blocked;       /* a gather was refused WOULD_BLOCK; the
                                writable edge is armed until capacity
                                frees (edge semantics are the backend's) */
    bool fin_delivered;
    bool reset_delivered;
    struct wtq_nw_pending_send *pending_sends;      /* FIFO head */
    struct wtq_nw_pending_send *pending_sends_tail;
    bool send_inflight;      /* one nw_connection_send outstanding */

    struct wtq_nw_send_rec recs[WTQ_NW_SEND_RECORDS];
    size_t inflight_bytes;
    int recs_unretired;      /* records not yet TRANSPORT_RETIRED       */
    int batches_live;        /* batches whose completion or retirement
                                has not yet run: EVERY in-flight batch
                                (records or not) pins the stream — a
                                marshaled retirement dereferences it    */
    bool reap_scheduled;     /* exactly one deferred reap queued */
    bool handler_detached;   /* phase 1 ran: state handler removed */
    bool engine_known;       /* the engine stored this ds (es->ds or a
                                critical-stream pointer): the STRUCT
                                must outlive that linkage — msquic
                                policy (handle releases at terminal,
                                struct lives until detach or the
                                connection terminal)                  */
    bool engine_detached;    /* op_detach ran (identity-checked): no
                                estream names this ds anymore         */
    bool quarantined;        /* variant C: held until group terminal */
    size_t bytes_issued;     /* total content handed to nw_connection_send
                                (diagnostic: proves what left the pump) */
    int recs_app_pending;    /* records not yet APP_COMPLETED           */
};

struct wtq_driver {
    wtq_alloc_t alloc;
    dispatch_queue_t queue;          /* the serialization domain        */
    nw_connection_group_t group;
    nw_connection_t dgram;           /* the QUIC datagram flow          */
    wtq_session_t *session;          /* backend-held ref; NULL once dropped */
    struct wtq_dstream *streams;

    /*
     * THE OWNERSHIP SPLIT (§7.2/§7.3 rule 4). `pub` is the PUBLIC
     * handle (refcounted by the application; freed when its refs hit
     * zero AND the lifecycle finished). The driver is the INTERNAL
     * transport root: it stays alive while `pins` > 0 — one pin for
     * the lifecycle itself (dropped after on_stopped), one per live
     * stream shell, one for the datagram flow. An undisposed send-
     * completion holder pins its shell, the shell pins the driver, and
     * the driver holds the queue: a late disposal always lands on live
     * memory, however long ago join returned and the public handle was
     * released. All pin traffic is on-domain (non-atomic by design).
     */
    struct wtq_nw_conn *pub;         /* public handle (never freed
                                        before lifecycle_over)          */
    int pins;                        /* internal-root pin count         */
    bool lifecycle_pin_dropped;
    bool stop_started;               /* mirrored from the handle (domain
                                        copy, set by the stop worker)   */
    bool terminal_done;              /* group_handle_terminal ran       */
    bool finish_scheduled;           /* on_stopped delivery queued once */

    bool started;                    /* group reached ready once        */
    bool group_terminal;
    bool dgram_ready;
    bool dgram_terminal;             /* `cancelled` observed — like the
                                        streams, the ONLY final state:
                                        `failed` converges via cancel   */
    bool dgram_cancel_issued;
    bool dgram_recv_pending;
    bool dgram_reap_scheduled;       /* exactly one deferred dgram reap */
    bool dgram_handler_detached;     /* dgram phase 1 ran               */

    int dgram_inflight;              /* datagram sends awaiting completion */
    bool closed_fed;                 /* wtq_conn_on_conn_closed delivered */
    bool shutdown_started;           /* group cancel issued             */
    bool rundown;                    /* internal rundown in progress    */
    dispatch_semaphore_t rundown_done;

    /* Callback-frame accounting: incremented for the duration of every
     * Network.framework-delivered callback body. Destruction of NW
     * objects and their contexts must only happen at depth 0 (a later
     * queue turn) — releasing a connection inside its own callback
     * frame is the caller-lifetime hazard under investigation. */
    int callback_depth;

    /* first-causal error detail staged for the record (single-domain
     * state: written on the queue only) */
    bool err_staged;
    uint16_t err_kind;
    uint32_t err_domain;
    int64_t err_code;
};

/*
 * TEST-ONLY constructor (slice 5 has no public API). Builds the queue,
 * QUIC parameters (ALPN h3; system trust unless insecure_no_verify),
 * multiplex group, datagram flow, driver, and session; requests the
 * WebTransport CONNECT; starts the group. Returns the caller's session
 * reference (the backend holds its own) plus the driver for rundown.
 */
typedef struct wtq_nw_test_cfg {
    const wtq_alloc_t *alloc;              /* required */
    const wtq_session_events_t *events;    /* required */
    void *user;
    const char *host;                      /* required */
    uint16_t port;                         /* required */
    bool insecure_no_verify;               /* TEST-ONLY trust bypass */
    const wtq_connect_config_t *connect;   /* required */
} wtq_nw_test_cfg_t;

wtq_result_t wtq_nw_conn_create_internal(const wtq_nw_test_cfg_t *cfg,
                                         struct wtq_driver **drv_out,
                                         wtq_session_t **session_out);

/*
 * TEST-ONLY blocking rundown (the internal analogue of slice 6's
 * stop_begin+join). OFF-DOMAIN ONLY. Cancels every stream (forcing
 * pending send completions to flush — the measured path), the datagram
 * flow, and the group; synthesizes deduplicated completions for any
 * straggler; drops the backend session reference; waits for rundown
 * completion. Returns false on timeout (resources intentionally leaked
 * rather than freed under a live callback). Frees the driver on
 * success.
 */
bool wtq_nw_conn_rundown_internal(struct wtq_driver *drv, int timeout_ms);

/*
 * ObjC ARC helper (nw_send_holder.m): issue a gather send whose
 * completion block strongly captures a holder object; `on_complete`
 * fires at invocation (canceled = error present), `on_retire` fires
 * from the holder's dealloc exactly when Apple disposes its copy of
 * the block — invoked or not. Disposal is never inferred.
 */
void wtqi_nw_send_with_holder(nw_connection_t c, dispatch_queue_t queue,
                             dispatch_data_t content, bool is_complete,
                             void (*on_complete)(void *ctx, bool canceled),
                             void (*on_retire)(void *ctx), void *ctx);

/*
 * Which callback DETECTED reap eligibility (latched the deferred reap):
 * the terminal-order permutations each make a different gate close
 * last, and the directed order tests assert their intended gate was
 * genuinely the one that fired.
 */
enum wtq_nw_reap_src {
    WTQ_NW_REAP_SRC_STATE = 0,   /* stream/dgram state handler (cancelled) */
    WTQ_NW_REAP_SRC_RECV,        /* receive completion */
    WTQ_NW_REAP_SRC_COMPLETE,    /* send-batch completion */
    WTQ_NW_REAP_SRC_RETIRE,      /* holder disposal (transport retirement) */
    WTQ_NW_REAP_SRC_RUNDOWN,     /* rundown nudge */
    WTQ_NW_REAP_SRC_DETACH,      /* engine severed its linkage */
    WTQ_NW_REAP_SRC__N
};

/*
 * Everything below is DIAGNOSTIC/TEST instrumentation, compiled only
 * when WTQ_NW_TESTING is defined (the tests' CMake defines it on the
 * backend target; a production consumer gets none of it). The
 * WTQ_NW_TEST() macro discards its statement in production builds so
 * the hot paths carry no counter code.
 */
#ifdef WTQ_NW_TESTING
#define WTQ_NW_TEST(stmt)                                                    \
    do {                                                                     \
        stmt;                                                                \
    } while (0)

/* TEST SEAM: skip N pump concat attempts, then force the next M to
 * fail like OOM (see nw_conn.c). */
extern int wtq_nw_test_force_concat_failures;
/* Earliest-domain-block hook: dispatched onto the serialization domain
 * BEFORE the connection group starts, so it runs ahead of every
 * transport callback — proves the output handle is published (and
 * usable for post/stop_begin) before anything can observe the conn. */
extern void (*wtq_nw_test_on_earliest)(void *ctx);
extern void *wtq_nw_test_on_earliest_ctx;
extern int wtq_nw_test_concat_skip;

/* Main-thread START GATE hook: called on the main thread by the start
 * trampoline BEFORE nw_connection_group_start(), so a test can hold an
 * off-main-created group in the QUEUED/STARTING state while it injects
 * post()/stop_begin() and observes the ordered, exactly-once start+stop.
 * Never a production seam. */
extern void (*wtq_nw_test_main_start_gate)(void *ctx);
extern void *wtq_nw_test_main_start_gate_ctx;

/* TEST-VISIBLE reap accounting (accumulated across connections):
 * every stream destruction runs through the deferred reaper; any
 * destruction executed inside a callback frame counts as a violation. */
extern int wtq_nw_test_reaps_run;
extern int wtq_nw_test_reaps_in_callback;
extern int wtq_nw_test_park_reaps; /* diagnostic: never destroy */

/*
 * Teardown-variant knob (DIAGNOSTIC ONLY):
 *  0 = TWO-PHASE (production): a queue turn after cancelled, re-check
 *      eligibility, detach the state handler; ANOTHER turn later
 *      release the connection (the shell frees once the engine
 *      linkage is severed too).
 *  2 = retain-until-group-terminal (quarantine): keeps one NW handle
 *      per HISTORICAL stream — the linear-growth comparison arm,
 *      never production.
 * (The rejected experiment arms — reinsert-after-cancel and one-turn
 * release without detach — are gone.)
 */
extern int wtq_nw_test_teardown_variant;
extern int wtq_nw_test_detach_in_cb;   /* handler removals at depth>0 */
extern int wtq_nw_test_release_in_cb;  /* releases at depth>0 */
extern int wtq_nw_test_order_bad;      /* release before detach */
extern int wtq_nw_test_quarantined_peak; /* variant-C boundedness */

extern int wtq_nw_test_reap_src[WTQ_NW_REAP_SRC__N];

/* White-box access for the managed-lifecycle tests: the driver behind
 * a public handle (walks under dispatch_sync on its queue), and a
 * LIVE-DRIVER counter (create ++, internal-root free --) the tests use
 * to bound-wait for full internal quiescence — join deliberately does
 * not wait for TRANSPORT_RETIRED stragglers. */
struct wtq_driver *wtq_nw_test_conn_driver(wtq_nw_conn_t *c);
extern _Atomic int wtq_nw_test_live_drivers;

/* Straggler-holder model: an extra internal-root pin, taken and
 * returned ON THE DOMAIN (dispatch there yourself). */
void wtq_nw_test_pin(struct wtq_driver *drv);
void wtq_nw_test_unpin(struct wtq_driver *drv);

/* TEST SEAM: override the BACKEND-OWNED allocator (the managed
 * handle, post nodes, driver root, shells, batches, send-chain nodes)
 * for subsequently created connections — fault injection for the
 * paths cfg.alloc deliberately never touches. NULL = default. */
extern const wtq_alloc_t *wtq_nw_test_backend_alloc;

/* Peer-open outcome accounting (cumulative): the reject-churn tests
 * pace on these — a REJECTED peer stream never surfaces to the app,
 * so only the backend can observe that the attempt happened. */
extern int wtq_nw_test_peer_opens;
extern int wtq_nw_test_peer_rejects;
extern int wtq_nw_test_adopts;

/*
 * TEST SEAM: deny QUIC metadata at ready for a specific STREAM CLASS
 * (deterministic by construction — never by ready ordering). Bits
 * consume one-shot per class:
 *   1 = h3 critical uni (local, no engine ctx, opened at start)
 *   2 = local bidi — the CONNECT stream when the test opens no app
 *       bidi in the window
 *   4 = app stream (local, engine ctx attached)
 * Denial drives the measured BACKEND INVARIANT FAILURE path: fail the
 * connection, one deterministic outcome; a silent stream cancel would
 * strand a CONNECT/critical stream's session state.
 */
#define WTQ_NW_META_DENY_CRITICAL 0x1
#define WTQ_NW_META_DENY_LOCAL_BIDI 0x2
#define WTQ_NW_META_DENY_APP 0x4
extern int wtq_nw_test_meta_deny;

/*
 * TEST HOOK (nw_send_holder.m): create a holder capturing `on_retire`/
 * `ctx` exactly as a send would, copy the completion block, and
 * dispose that copy on a FOREIGN (non-domain) thread WITHOUT invoking
 * it — the ARC dealloc must marshal the retirement onto `queue`
 * exactly once. Proves the disposal path's thread contract without
 * depending on where Network.framework happens to drop its copies.
 */
void wtq_nw_test_holder_foreign_dispose(dispatch_queue_t queue,
                                        void (*on_retire)(void *),
                                        void *ctx);


/* Datagram-flow two-phase reap accounting (the dgram flow is torn down
 * with the same detach-then-release discipline as the streams). */
extern int wtq_nw_test_dgram_reaps_run;
extern int wtq_nw_test_dgram_detach_in_cb;
extern int wtq_nw_test_dgram_release_in_cb;
extern int wtq_nw_test_dgram_reap_src[WTQ_NW_REAP_SRC__N];

/* TEST SPI: cancel the multiplex group directly on the domain WITHOUT
 * cancelling the child streams first — forces the group-terminal-
 * before-child-terminal teardown order (children are then torn down
 * from the group-terminal path). */
void wtq_nw_test_cancel_group(struct wtq_driver *drv);

/*
 * TEST SEAM: run the receive-completion body directly on the serialization
 * domain — the production path is Apple's nw_connection_receive callback,
 * not externally schedulable, so this lets a test inject a completion
 * (bytes / FIN / error / cancel) at a controlled moment and prove the
 * pause deferral deterministically. `content` is borrowed for the call
 * (retained internally when deferred). NOT a production seam.
 */
void wtq_nw_test_deliver_recv(struct wtq_dstream *ds, dispatch_data_t content,
                             bool fin, bool errored, bool cancelled);

/* TEST-VISIBLE invariant counter: a completion was deferred while one was
 * already held (the single-outstanding-receive invariant was violated). It
 * fails the connection; the counter only records that it fired. */
extern int wtq_nw_test_recv_defer_overflow;

/* TEST-VISIBLE: nw_connection_receive arms actually issued (cumulative). */
extern int wtq_nw_test_recv_arms;

/*
 * TEST SEAM: drive the peer-reset (stream `failed`) transition on the
 * domain — sets failed_seen, runs the failure handler (which emits
 * on_stream_reset), and converges to cancelled — so the reset-reentrancy
 * path (a resume attempted from inside on_stream_reset) is testable
 * without a cooperating peer.
 */
void wtq_nw_test_stream_fail(struct wtq_driver *drv, struct wtq_dstream *ds);

/*
 * TEST SEAM: call op_recv_enable directly on the domain, bypassing the
 * session/engine layers, so the backend's reject-without-mutation guard
 * (failed/cancelled/terminal/handleless) can be proven on its own.
 */
wtq_result_t wtq_nw_test_recv_enable(struct wtq_driver *drv,
                                     struct wtq_dstream *ds, bool enabled);

#else /* !WTQ_NW_TESTING */
#define WTQ_NW_TEST(stmt) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* WTQ_NW_INTERNAL_H */
