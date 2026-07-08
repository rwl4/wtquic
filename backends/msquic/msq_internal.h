#ifndef WTQ_BACKENDS_MSQUIC_INTERNAL_H
#define WTQ_BACKENDS_MSQUIC_INTERNAL_H

/*
 * MsQuic backend internals — shared between the backend's translation
 * units, never installed.
 *
 * THREADING MODEL
 *   MsQuic serializes all callbacks for one connection and never makes
 *   recursive callbacks, so per-connection state needs no locking. The
 *   entry points that run on application threads (env/listener open and
 *   close, client_connect) only touch state before the connection
 *   starts or after MsQuic guarantees quiescence (the Close calls
 *   block).
 *
 * CONNECTION TEARDOWN ORDER (the load-bearing sequence)
 *   MsQuic guarantees: every stream gets its SHUTDOWN_COMPLETE (and a
 *   SEND_COMPLETE for every accepted send, canceled if need be) BEFORE
 *   the connection's SHUTDOWN_COMPLETE, which is the last event ever
 *   delivered. The backend leans on that:
 *
 *   1. On SHUTDOWN_INITIATED_BY_{TRANSPORT,PEER} the engine is told the
 *      transport is gone (wtq_conn_on_conn_closed). From then on the
 *      engine calls NO driver ops (every engine input checks its closed
 *      flag first), so backend stream state may die safely afterwards.
 *   2. Stream SHUTDOWN_COMPLETE closes the HQUIC stream (StreamClose)
 *      and marks the backend stream transport-dead; the struct itself
 *      stays allocated because engine stream slots may still hold the
 *      wtq_dstream_t pointer (driver ops on it become no-ops).
 *   3. Connection SHUTDOWN_COMPLETE: feed wtq_conn_on_conn_closed once
 *      more (idempotent — covers locally-initiated shutdowns that get
 *      no INITIATED event), drop the backend's session reference inside
 *      the enter/leave bracket, then free every backend stream struct,
 *      ConnectionClose exactly once, and free the backend connection.
 *
 * SESSION LINKAGE (two owners, resolved by ordering)
 *   The backend holds one session reference from creation to step 3, so
 *   an app release can never destroy the session while MsQuic can still
 *   deliver an event. Because that reference is dropped inside the
 *   final enter/leave bracket, the deferred destroy runs on the worker
 *   thread with nothing else in flight; wtq_api_session_leave() returns
 *   true at most there, never in an intermediate batch.
 *
 * STREAM IDS
 *   The frozen driver SPI wants the QUIC stream id synchronously from
 *   open_uni/open_bidi, but MsQuic's StreamStart is always queued (it
 *   returns PENDING; GetParam(STREAM_ID) is INVALID_STATE until the op
 *   drains). The backend therefore computes the id itself — MsQuic
 *   assigns type + (count << 2) in StreamStart order, the backend is
 *   the only opener of local streams, and per-connection serialization
 *   fixes the order — and verifies every id against the stream's
 *   START_COMPLETE event, killing the connection on a mismatch.
 */

#include <pthread.h>
#include <stdatomic.h>

#include <wtquic/wtquic_msquic.h>

#include "api/api_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* wtq_cfg_has() (struct_size-gated field presence) is shared with the core;
 * it lives in api/api_internal.h, included above. */

/*
 * FROZEN v1 (07570ae) config layouts. These mirror EXACTLY the fields the
 * client/listener configs had before the managed-domain tail was added. The
 * bare *_cfg_init symbols write sizeof(one of these); the connect /
 * listener_start prefix checks require at least this size; and the ABI tests
 * allocate exactly this size. Deriving the v1 size from the CURRENT struct
 * (offsetof of the first v2 field) would instead let a future prefix change
 * enlarge the legacy write AND its test buffer together — hiding an overflow —
 * and could drift from the old struct's sizeof when a new tail field carries
 * stronger alignment. The static asserts below pin every current v1 field to
 * its frozen offset and require the v2 tail to begin at or after sizeof(v1)
 * (>=, not ==: alignment padding before the tail is legal).
 */
typedef struct wtq_msquic_client_cfg_v1 {
    uint32_t struct_size;
    const char *server_name;
    uint16_t port;
    bool insecure_skip_verify;
    const wtq_connect_config_t *connect;
    const wtq_session_events_t *events;
    void *user;
} wtq_msquic_client_cfg_v1_t;

typedef struct wtq_msquic_listener_cfg_v1 {
    uint32_t struct_size;
    const char *bind_address;
    uint16_t port;
    const char *cert_file;
    const char *key_file;
    const wtq_serve_config_t *paths;
    size_t path_count;
    const wtq_session_events_t *events;
    void *user;
} wtq_msquic_listener_cfg_v1_t;

#define WTQ_MSQ_FROZEN_OFF(cur, v1, f)                                       \
    _Static_assert(offsetof(cur, f) == offsetof(v1, f),                     \
                   "v1 field " #f " moved from its frozen 07570ae offset")

WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t,
                   struct_size);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t,
                   server_name);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t, port);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t,
                   insecure_skip_verify);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t,
                   connect);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t, events);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_client_cfg_t, wtq_msquic_client_cfg_v1_t, user);
/* The v2 tail begins at or after the end of frozen v1 — >=, not ==, because an
 * ABI with stronger-aligned function pointers may pad before the tail. v1
 * remains fully contained in sizeof(v1); the tail is read at its own current
 * offset. (Equality would wrongly reject such a platform.) */
_Static_assert(offsetof(wtq_msquic_client_cfg_t, guard) >=
                   sizeof(wtq_msquic_client_cfg_v1_t),
               "client v2 tail must not begin before the end of frozen v1");

WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   struct_size);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   bind_address);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   port);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   cert_file);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   key_file);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   paths);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   path_count);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   events);
WTQ_MSQ_FROZEN_OFF(wtq_msquic_listener_cfg_t, wtq_msquic_listener_cfg_v1_t,
                   user);
/* >=, not ==: padding before the v2 tail is legal (see the client note). */
_Static_assert(offsetof(wtq_msquic_listener_cfg_t, accept_prepare) >=
                   sizeof(wtq_msquic_listener_cfg_v1_t),
               "listener v2 tail must not begin before the end of frozen v1");
/* The v3 profile field must sit AFTER the whole v2 managed-domain tail (past
 * frozen v1 too), so an old v2 caller's struct_size can never reach it and it
 * always gates to current — and immediately after on_transport_quiesced with
 * no gap, so no v2-caller padding is ever read as a profile. */
_Static_assert(offsetof(wtq_msquic_listener_cfg_t, webtransport_profile) ==
                   offsetof(wtq_msquic_listener_cfg_t, on_transport_quiesced) +
                       sizeof(wtq_msquic_transport_quiesced_fn),
               "listener v3 profile must directly follow the v2 tail");
_Static_assert(offsetof(wtq_msquic_listener_cfg_t, webtransport_profile) >=
                   sizeof(wtq_msquic_listener_cfg_v1_t),
               "listener v3 profile must begin at or after frozen v1");

/* Mirrors of the engine's accept-policy limits (wtq_conn copies the
 * table with these bounds at serve time). */
#define WTQ_MSQ_MAX_PATHS 4
#define WTQ_MSQ_MAX_PROTOS 8
#define WTQ_MSQ_PATH_CAP 128
#define WTQ_MSQ_PROTO_CAP 256

struct wtq_msquic_env {
    wtq_alloc_t alloc;
    const QUIC_API_TABLE *api;
    HQUIC registration;
    bool owns_api;
    bool owns_registration;
    char *app_name;          /* owned copy passed to RegistrationOpen */
    size_t app_name_size;    /* allocation size, for sized free */
    wtq_msquic_tuning_t tuning;

    /* Child tracking for the blocking close contract. mu guards the
     * lists, counts and the closing latch — held only for O(1)-ish
     * bookkeeping and the queue-only ConnectionShutdown calls, NEVER
     * across a blocking MsQuic close or an application callback. cv
     * signals conn_count reaching zero. */
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool closing;            /* refuse new listeners/clients/accepts */
    size_t conn_count;
    struct wtq_driver *conns;               /* intrusive, via env_* */
    struct wtq_msquic_listener *listeners;  /* intrusive, via env_next */
};

/* Pooled gather-record capacity; sends with more spans fall back to a
 * one-off allocation sized for the count. */
#define WTQ_MSQ_GATHER_SPANS 8
#define WTQ_MSQ_GATHER_CHUNK 16
/* Per-stream in-flight send floor: MsQuic queues unboundedly, so the
 * backend refuses (WOULD_BLOCK) beyond max(this, IDEAL_SEND_BUFFER_SIZE).
 * With SendBufferingEnabled=FALSE a SEND_COMPLETE is a FULL
 * acknowledgment, so the floor must cover bandwidth times the peer's
 * delayed-ACK window or a caller that fills it serializes at one
 * ACK-timer cycle per refused send; 64 KiB measurably did exactly
 * that for 64 KiB writes over loopback. */
#define WTQ_MSQ_SEND_BUDGET_MIN (1024u * 1024u)
/* Unfinalized datagram sends allowed in flight (same rationale). */
#define WTQ_MSQ_DGRAM_INFLIGHT_MAX 64

/* Discriminates the two SEND_COMPLETE contexts; first member of both
 * record types. */
struct wtq_msq_send_hdr {
    bool gather;
};

/* One in-flight borrow-during-call send: the QUIC_BUFFER and a copy of
 * the bytes, alive until the stream's SEND_COMPLETE. */
struct wtq_msq_send_rec {
    struct wtq_msq_send_hdr h;   /* .gather = false */
    QUIC_BUFFER buf;
    size_t alloc_size;
    /* copied payload follows the struct */
};

/*
 * One in-flight gather send: the QUIC_BUFFER array MsQuic borrows until
 * SEND_COMPLETE. The span DATA is the application's, borrowed until the
 * engine's completion for the cookie — nothing here is copied. Pooled
 * (chunk-grown freelist) for the steady state; span counts above the
 * pooled capacity use a one-off allocation with the array in the tail.
 */
struct wtq_msq_gather_rec {
    struct wtq_msq_send_hdr h;   /* .gather = true */
    void *cookie;
    struct wtq_dstream *ds;      /* in-flight byte accounting */
    uint64_t bytes;
    size_t alloc_size;           /* 0 = pooled; else sized free */
    struct wtq_msq_gather_rec *next; /* pool freelist */
    QUIC_BUFFER *bufs;           /* inline_bufs, or the heap tail */
    QUIC_BUFFER inline_bufs[WTQ_MSQ_GATHER_SPANS];
};

struct wtq_msq_gather_chunk {
    struct wtq_msq_gather_chunk *next;
    struct wtq_msq_gather_rec recs[WTQ_MSQ_GATHER_CHUNK];
};

/* One in-flight datagram: the datagram-send contract is borrow-during-
 * call (the engine's association prefix lives on its stack), so the
 * bytes are copied here and the record lives until MsQuic reports a
 * FINAL send state for it — every accepted datagram gets exactly one,
 * canceled ones at connection shutdown included. */
struct wtq_msq_dgram_rec {
    QUIC_BUFFER buf;
    size_t alloc_size;
    /* copied prefix + payload bytes follow */
};

/* Backend stream context (the driver SPI's wtq_dstream_t). Freed only
 * in the connection sweep — engine stream slots may hold the pointer
 * past the stream's transport death. */
struct wtq_dstream {
    struct wtq_driver *drv;
    HQUIC stream;            /* NULL once the stream shut down */
    wtq_estream_t *ectx;     /* engine ctx; NULL = engine refused it */
    struct wtq_dstream *next;
    uint64_t id;
    uint64_t inflight_bytes; /* accepted gather bytes awaiting completion */
    uint64_t ideal_send;     /* last IDEAL_SEND_BUFFER_SIZE (0 = none) */
    bool send_blocked;       /* a gather was refused WOULD_BLOCK; armed
                                until the writable edge is delivered */
    bool is_local;
    bool is_bidi;
    bool fin_delivered;      /* engine got this stream's FIN already */
};

/* Backend connection context (the driver SPI's wtq_driver_t). */
struct wtq_driver {
    wtq_alloc_t alloc;
    const QUIC_API_TABLE *api;
    HQUIC conn;
    wtq_session_t *session;  /* backend-held reference; NULL once dropped */
    struct wtq_dstream *streams;
    struct wtq_msq_gather_rec *gather_free;
    struct wtq_msq_gather_chunk *gather_chunks;
    int pending_sends;       /* send records awaiting SEND_COMPLETE
                                (cold and gather both — the close flush
                                gate waits for all of them) */
    int dgram_inflight;      /* datagram records awaiting a final state */
    uint64_t dgram_max;      /* transport datagram limit (0 = disabled) */
    uint64_t local_uni_count;  /* local streams opened, by type — the */
    uint64_t local_bidi_count; /* id-computation counters */
    /* The FIRST-CAUSAL tuple staged for the error record. Once
     * close_kind is assigned the whole tuple is immutable — later
     * transport events must never rewrite the cause. */
    uint16_t close_kind;     /* wtq_error_kind_t (NONE = nothing staged) */
    uint64_t close_err;      /* causal wire/app code */
    int64_t close_status;    /* causal native MsQuic status */
    bool close_cleanup;      /* the local shutdown was post-terminal
                                CLEANUP (session already over), not a
                                causal error: stage no record for it */
    /* The LATEST transport-event code, kept separately for the legacy
     * terminal input (engine close_code). event_err_set records whether
     * any transport event delivered one: at completion the latest event
     * code wins when present, else the staged local causal code. */
    uint64_t event_err;
    bool event_err_set;
    bool close_remote;
    /* Environment-close intent, handed from the env-closing thread to
     * the MsQuic worker. One of two cross-thread members (the other is
     * `abandon`): the worker consumes it (atomic exchange) before
     * classifying any shutdown event, so the causal tuple itself is
     * mutated exclusively on the connection's serialization domain. */
    atomic_bool env_close_req;
    bool is_client;
    bool shutdown_started;   /* worker-side ConnectionShutdown issued
                                (env_close may add its own idempotent
                                one without setting this) */
    bool shutdown_when_flushed; /* shut down at pending_sends == 0 */
    atomic_bool abandon;     /* opened-but-never-started/published cleanup:
                                the close-time SHUTDOWN_COMPLETE is ignored
                                WITHOUT entering the guard (no session is
                                attached, no events fire), and the
                                wtq_msq_conn_abandon() caller is the single
                                owner of the driver free. Set by that caller
                                before ConnectionClose; consumed by the terminal
                                callback, which MsQuic may deliver on a worker
                                thread — hence atomic (release store / acquire
                                load), like env_close_req. */

    /* Managed-domain contract (all zero = legacy callback-only). Copied
     * from the client/listener cfg at connect/accept. The guard brackets
     * every callback dispatch (guard.ctx is the caller's lane, outliving
     * this driver); the quiescence hook fires once at SHUTDOWN_COMPLETE
     * before the backend session-ref drop. */
    wtq_guard_t guard;
    wtq_msquic_transport_quiesced_fn on_transport_quiesced;
    void *quiesced_user;

    /* environment tracking (guarded by env->mu; env NULL = untracked,
     * e.g. backend-internal unit rigs) */
    wtq_msquic_env_t *env;
    struct wtq_driver *env_next;
    struct wtq_driver *env_prev;
};

struct wtq_msquic_listener {
    wtq_alloc_t alloc;
    wtq_msquic_env_t *env;
    struct wtq_msquic_listener *env_next; /* env tracking (env->mu) */
    struct wtq_msquic_listener *env_prev;
    bool tracked;            /* still on the env list (env->mu) */
    HQUIC listener;
    HQUIC configuration;     /* server config, credentials loaded */
    wtq_session_events_t events; /* applied to every accepted session */
    void *user;
    /* Managed-domain admission + quiescence (copied from the cfg; all
     * NULL = legacy). accept_abandon is required iff accept_prepare set. */
    wtq_msquic_accept_prepare_fn accept_prepare;
    wtq_msquic_accept_abandon_fn accept_abandon;
    wtq_msquic_transport_quiesced_fn on_transport_quiesced;
    /* WebTransport wire profile every accepted connection speaks (copied
     * from the cfg's struct_size-gated tail; 0 = current draft-16). */
    int webtransport_profile;
    size_t path_count;
    struct {
        char path[WTQ_MSQ_PATH_CAP + 1];
        char protos[WTQ_MSQ_PROTO_CAP + WTQ_MSQ_MAX_PROTOS]; /* NUL-joined */
        const char *proto_ptr[WTQ_MSQ_MAX_PROTOS];
        size_t proto_count;
        bool require;
    } paths[WTQ_MSQ_MAX_PATHS];
};

/* msq_settings.c — tuning to QUIC_SETTINGS (values + IsSet bits). */
void wtq_msq_settings_init(QUIC_SETTINGS *qs,
                           const wtq_msquic_tuning_t *tuning);

/* msq_env.c — child tracking (all take env->mu internally).
 * conn_register returns false when the environment is closing (the
 * caller must refuse the connection); unregister is exactly-once per
 * registered child and clears the child's env backlink. */
/* Accept-registration for inbound connections: refuse when closing,
 * else publish session + connection handle + list membership in one
 * critical section. The tracked list never contains a driver without
 * a shutdown-capable handle. */
bool wtq_msq_env_conn_accept(wtq_msquic_env_t *env,
                             struct wtq_driver *drv,
                             wtq_session_t *session, HQUIC conn);
bool wtq_msq_env_conn_register(wtq_msquic_env_t *env,
                               struct wtq_driver *drv);
void wtq_msq_env_conn_unregister(struct wtq_driver *drv);
bool wtq_msq_env_listener_register(wtq_msquic_env_t *env,
                                   struct wtq_msquic_listener *l);
void wtq_msq_env_listener_unregister(struct wtq_msquic_listener *l);

/* msq_listener.c — stop + free WITHOUT env-list bookkeeping (the
 * caller already detached it); blocks for in-flight accepts. */
void wtq_msq_listener_free(struct wtq_msquic_listener *l);

/* msq_conn.c */
uint64_t wtq_msq_now_us(void);
const wtq_driver_ops_t *wtq_msq_driver_ops(void);
struct wtq_driver *wtq_msq_conn_new(const wtq_alloc_t *alloc,
                                    const QUIC_API_TABLE *api,
                                    bool is_client);
/* Free the backend connection: sweep stream structs, ConnectionClose
 * (when drv->conn is still set), free. The session linkage must already
 * be dropped. */
void wtq_msq_conn_free(struct wtq_driver *drv);

/* Discard a connection that was opened but never successfully started or
 * published (no session attached): mark it abandoned so the synchronous
 * SHUTDOWN_COMPLETE that ConnectionClose delivers is ignored without entering
 * the guard, then free it here as the single owner. Use this instead of
 * wtq_msq_conn_free() on the client-connect failure paths, where a caller may
 * hold the guard across the connect and the re-entrant callback would
 * otherwise deadlock (guard held) or double-free (guard absent). */
void wtq_msq_conn_abandon(struct wtq_driver *drv);

/*
 * Stage a CAUSAL local error {LOCAL, code, MSQUIC, status} for the
 * transport-error record — the one entry point for every direct local
 * shutdown cause (environment close, backend invariant failure, engine
 * conn_close). First cause wins: a no-op once a cause is staged or the
 * shutdown was classified as post-terminal cleanup.
 */
void wtq_msq_conn_stage_local_cause(struct wtq_driver *drv, uint64_t code,
                                    int64_t status);

/*
 * Deliver the staged causal tuple to the engine (write-once there),
 * immediately before a terminal input. Shared by every delivery path —
 * initiated events, SHUTDOWN_COMPLETE, and direct causal shutdown sites
 * (stream-ID divergence) — so they cannot drift apart. An un-attributed
 * non-cleanup completion is classified {LOCAL, latest event code}.
 */
void wtq_msq_conn_put_error_detail(struct wtq_driver *drv);
/* The connection event handler (client: via ConnectionOpen; server: via
 * SetCallbackHandler at accept). Context is the struct wtq_driver. */
QUIC_STATUS QUIC_API wtq_msq_conn_callback(HQUIC conn, void *ctx,
                                           QUIC_CONNECTION_EVENT *ev);
/* Leave the session bracket; on deferred destroy drop the linkage.
 * Otherwise apply the shutdown policy (terminal session -> shut the
 * connection down once pending sends flush). */
void wtq_msq_conn_leave_and_poll(struct wtq_driver *drv);
/* Return a gather record (from the pool or a one-off allocation). */
void wtq_msq_gather_put(struct wtq_driver *drv,
                        struct wtq_msq_gather_rec *rec);

/* msq_stream.c */
/* Deliver the writable edge for a budget-blocked stream: called where
 * budget frees (SEND_COMPLETE) or the ceiling grows (ideal-size
 * advice). No-op unless armed and the stream still has engine + session
 * linkage. */
void wtq_msq_stream_writable_check(struct wtq_driver *drv,
                                   struct wtq_dstream *ds);

QUIC_STATUS QUIC_API wtq_msq_stream_callback(HQUIC stream, void *ctx,
                                             QUIC_STREAM_EVENT *ev);
struct wtq_dstream *wtq_msq_stream_new(struct wtq_driver *drv,
                                       bool is_local, bool is_bidi,
                                       uint64_t id);

#ifdef __cplusplus
}
#endif

#ifdef WTQ_MSQ_TESTING
/* Test-only (white-box builds compile the backend sources with this
 * define; no shipped library carries it): fail the next N accept-path
 * ConnectionSetConfiguration calls to drive the unwind. */
#include <stdatomic.h>
extern _Atomic int wtq_msq_test_fail_set_configuration;
/* Force a post-admission failure at a chosen stage so accept_abandon can be
 * exercised on every documented path: 1=driver alloc, 2=session create,
 * 3=serve, 4=env-closing refusal. Consumed once per accept. */
extern _Atomic int wtq_msq_test_fail_admit_stage;
#endif

#endif /* WTQ_BACKENDS_MSQUIC_INTERNAL_H */
