#ifndef WTQ_WTQUIC_MSQUIC_H
#define WTQ_WTQUIC_MSQUIC_H

/*
 * wtquic MsQuic backend — public entry points.
 *
 * This header is transport-specific: it names MsQuic handles and so
 * includes <msquic.h>. It is deliberately NOT pulled in by the core
 * umbrella <wtquic/wtquic.h>, which stays free of any transport
 * dependency. Link against the wtquic-msquic library (CMake target
 * wtq::msquic) to use it.
 *
 * The environment is the root object: it owns (or borrows) the MsQuic
 * API function table and a Registration, and carries the performance
 * tuning that later connections apply to their QUIC configuration.
 */

#include <wtquic/error.h>
#include <wtquic/session.h>
#include <wtquic/types.h>

#include <msquic.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * THREADING AND SESSION OWNERSHIP
 *
 * Session events fire on MsQuic's worker threads, serialized per
 * connection and never concurrently for one session. Neither the
 * session handles nor their reference counts are internally locked, so
 * the confinement contract is strict:
 *
 *   - Call wtq_session_* / wtq_stream_* functions (including add_ref /
 *     release and the queries) only from inside that session's event
 *     callbacks — that context is the serialization domain.
 *   - The one exception: after wtq_msquic_env_close() returns, every
 *     connection under the environment has fully torn down and the
 *     backend will never touch a session again, so a still-held session
 *     reference may be inspected and released from any thread.
 *
 * The connection's lifetime is the session's lifetime: when a session
 * reaches its terminal event (on_closed / on_refused / on_failed), the
 * backend finishes flushing its pending writes, shuts the QUIC
 * connection down, and releases its own reference to the session. A
 * session that is never closed holds its connection open until the idle
 * timeout — close sessions promptly, then release them.
 *
 * Reference ownership:
 *   - wtq_msquic_client_connect returns a session carrying one
 *     app-owned reference; release it when done (from a callback, or
 *     from anywhere once wtq_msquic_env_close has returned).
 *   - Server sessions are backend-owned. The app first sees the handle
 *     in a callback (typically on_established) and may retain it with
 *     wtq_session_add_ref; without a retain, the handle must not be
 *     used after its terminal callback returns.
 */

/* The MsQuic environment: API table + Registration + shared tuning. */
typedef struct wtq_msquic_env wtq_msquic_env_t;
/* A listening server socket: accepts connections and builds a
 * WebTransport session on each (one session per connection). */
typedef struct wtq_msquic_listener wtq_msquic_listener_t;

/*
 * Transport tuning applied to a connection's QUIC configuration. The
 * defaults ARE the performance posture — zero-copy sends and media-scale
 * flow-control windows — so most callers leave this untouched. Use
 * WTQ_MSQUIC_TUNING_INIT / wtq_msquic_tuning_init; a tuning left with
 * struct_size == 0 is treated as "use defaults".
 *
 * STREAM CREDITS AND THE ENGINE POOL
 *   wtquic's protocol engine holds streams in a FIXED, allocation-free
 *   pool of 16 slots per connection, SHARED by HTTP/3's three critical
 *   unidirectional streams, the CONNECT stream, WebTransport streams the
 *   peer opens, and WebTransport streams this application opens locally.
 *
 *   The default credits (8 unidirectional + 7 bidirectional = 15,
 *   leaving one slot for a client's local CONNECT stream) bound the
 *   streams the TRANSPORT will let the peer open. They do not reserve
 *   those slots: streams opened locally consume the same pool, so a
 *   peer stream can still find the pool full even within its credit.
 *
 *   RAISING THESE COUNTS DOES NOT ENLARGE THE ENGINE OR API POOLS. A
 *   stream that arrives with no slot free is rejected explicitly on the
 *   wire (STOP_SENDING, plus RESET_STREAM for a bidirectional stream) —
 *   never accepted, never delivered, never silently discarded. A local
 *   open with no slot free fails with WTQ_ERR_STREAM_LIMIT. Grant larger
 *   credits only if your application genuinely prefers that rejection to
 *   transport-level backpressure.
 */
typedef struct wtq_msquic_tuning {
    uint32_t struct_size;

    /* Let MsQuic buffer send data internally (a copy). Off by default so
     * send buffers are borrowed until acknowledged — true zero copy. */
    bool     send_buffering;
    /* Unidirectional streams the peer may open toward us: three for
     * HTTP/3's critical streams plus five application streams. Bounded
     * by the engine's fixed pool — see above. */
    uint16_t peer_unidi_stream_count;
    /* Bidirectional streams the peer may open toward us (the CONNECT
     * stream on a server, plus application streams). Bounded by the
     * engine's fixed pool — see above. */
    uint16_t peer_bidi_stream_count;
    /* Per-stream receive window in bytes. Media-scale by default. */
    uint32_t stream_recv_window;
    /* Connection-wide flow-control window in bytes. */
    uint32_t conn_flow_control_window;
    /* Accept QUIC datagrams (WebTransport datagrams ride these). */
    bool     datagram_receive_enabled;
    /* Idle timeout in milliseconds before the connection is torn down. */
    uint32_t idle_timeout_ms;
} wtq_msquic_tuning_t;

#define WTQ_MSQUIC_TUNING_INIT                                    \
    { (uint32_t)sizeof(wtq_msquic_tuning_t), false, 8, 7,         \
      16u * 1024u * 1024u, 32u * 1024u * 1024u, true, 30000u }

WTQ_API void wtq_msquic_tuning_init(wtq_msquic_tuning_t *tuning);

/*
 * Environment configuration.
 *
 * OWNERSHIP
 *   - alloc: optional; NULL uses the default allocator. Copied by value.
 *   - existing_api: optional. When set, the environment BORROWS this
 *     API table and never closes it; the caller keeps ownership. When
 *     NULL, the environment opens (and later closes) its own.
 *   - existing_registration: optional. When set, the environment BORROWS
 *     this Registration and never closes it; it REQUIRES existing_api
 *     (a Registration is only usable through the table that owns it).
 *     When NULL, the environment opens (and later closes) its own
 *     Registration through the selected API table.
 *   - app_name: optional label for an owned Registration (ignored when a
 *     Registration is borrowed). Copied during the call.
 *   - tuning: performance posture; see wtq_msquic_tuning_t.
 *
 * Use WTQ_MSQUIC_ENV_CFG_INIT / wtq_msquic_env_cfg_init.
 */
typedef struct wtq_msquic_env_cfg {
    uint32_t struct_size;
    const wtq_alloc_t *alloc;
    const QUIC_API_TABLE *existing_api;
    HQUIC existing_registration;
    const char *app_name;
    wtq_msquic_tuning_t tuning;
} wtq_msquic_env_cfg_t;

#define WTQ_MSQUIC_ENV_CFG_INIT                                  \
    { (uint32_t)sizeof(wtq_msquic_env_cfg_t), NULL, NULL, NULL,  \
      NULL, WTQ_MSQUIC_TUNING_INIT }

WTQ_API void wtq_msquic_env_cfg_init(wtq_msquic_env_cfg_t *cfg);

/*
 * Open an environment. On success *env_out owns whatever the config did
 * not hand it to borrow. On any failure *env_out is set to NULL and
 * every resource acquired along the way is released.
 *
 * WTQ_ERR_INVALID_ARG for a bad config (e.g. a borrowed registration
 * without an API table); WTQ_ERR_NOMEM on allocation failure;
 * WTQ_ERR_BACKEND when a MsQuic call fails.
 */
WTQ_API wtq_result_t wtq_msquic_env_open(const wtq_msquic_env_cfg_t *cfg,
                                         wtq_msquic_env_t **env_out);

/*
 * Close an environment: the application's synchronization point for
 * teardown. NULL is accepted and ignored. In order it
 *
 *   1. refuses new listeners, client connects, and accepted
 *      connections under this environment,
 *   2. stops and FREES every listener still open under it — listener
 *      handles are invalid after this call returns; a listener already
 *      stopped with wtq_msquic_listener_stop is unaffected,
 *   3. actively shuts down every connection created under it (also
 *      under a borrowed Registration, and regardless of idle timeout),
 *   4. BLOCKS until each has fully torn down and released its session,
 *   5. only then closes owned resources (Registration then API table)
 *      and frees the object.
 *
 * Borrowed Registration/API handles are left untouched and remain
 * usable, and unrelated connections sharing a borrowed Registration are
 * not shut down — only this environment's children are.
 *
 * Must not be called from an event callback (it would wait on its own
 * thread), nor concurrently with other calls on the same environment.
 */
WTQ_API void wtq_msquic_env_close(wtq_msquic_env_t *env);

/*
 * Listener configuration. Strings and tables are copied during
 * wtq_msquic_listener_start; the caller's storage may go away after the
 * call. Use WTQ_MSQUIC_LISTENER_CFG_INIT / wtq_msquic_listener_cfg_init.
 *
 *   - bind_address: dotted/hex literal to bind ("127.0.0.1", "::1");
 *     NULL binds the wildcard address.
 *   - port: UDP port; 0 picks an ephemeral port (read it back with
 *     wtq_msquic_listener_port).
 *   - cert_file / key_file: server certificate chain and private key,
 *     PEM files. Both required.
 *   - paths / path_count: the accept policy — which request paths this
 *     server serves and with which application subprotocols (count <= 4,
 *     path <= 128 bytes; see wtq_serve_config_t).
 *   - events / user: the event table and context every accepted session
 *     is created with. The app first sees a session in its callbacks
 *     (normally on_established); distinguish concurrent sessions by the
 *     session pointer or wtq_session_set_user from inside a callback.
 */
typedef struct wtq_msquic_listener_cfg {
    uint32_t struct_size;
    const char *bind_address;
    uint16_t port;
    const char *cert_file;
    const char *key_file;
    const wtq_serve_config_t *paths;
    size_t path_count;
    const wtq_session_events_t *events;
    void *user;
} wtq_msquic_listener_cfg_t;

#define WTQ_MSQUIC_LISTENER_CFG_INIT                              \
    { (uint32_t)sizeof(wtq_msquic_listener_cfg_t), NULL, 0, NULL, \
      NULL, NULL, 0, NULL, NULL }

WTQ_API void wtq_msquic_listener_cfg_init(wtq_msquic_listener_cfg_t *cfg);

/*
 * Start listening. On success *listener_out accepts connections until
 * wtq_msquic_listener_stop. On failure *listener_out is NULL and
 * everything acquired is released. WTQ_ERR_INVALID_ARG for a bad
 * config; WTQ_ERR_NOMEM; WTQ_ERR_BACKEND when MsQuic refuses (bad
 * credentials, port in use).
 */
WTQ_API wtq_result_t wtq_msquic_listener_start(
    wtq_msquic_env_t *env, const wtq_msquic_listener_cfg_t *cfg,
    wtq_msquic_listener_t **listener_out);

/*
 * Stop accepting and free the listener. Connections already accepted
 * live on independently (each tears down with its session). Blocks
 * until in-flight accept callbacks finish; must not be called from an
 * event callback. NULL is accepted and ignored.
 */
WTQ_API void wtq_msquic_listener_stop(wtq_msquic_listener_t *listener);

/* The locally bound UDP port (useful after binding port 0). */
WTQ_API uint16_t wtq_msquic_listener_port(
    const wtq_msquic_listener_t *listener);

/*
 * Client connect configuration. Strings are copied during the call.
 * Use WTQ_MSQUIC_CLIENT_CFG_INIT / wtq_msquic_client_cfg_init.
 *
 *   - server_name / port: where to dial; server_name is also the TLS
 *     SNI and certificate-validation name.
 *   - insecure_skip_verify: accept any server certificate. Loopback
 *     and development ONLY.
 *   - connect: the WebTransport request (authority/path/subprotocols;
 *     see wtq_connect_config_t). Required.
 *   - events / user: the session's event table and context. Required.
 */
typedef struct wtq_msquic_client_cfg {
    uint32_t struct_size;
    const char *server_name;
    uint16_t port;
    bool insecure_skip_verify;
    const wtq_connect_config_t *connect;
    const wtq_session_events_t *events;
    void *user;
} wtq_msquic_client_cfg_t;

#define WTQ_MSQUIC_CLIENT_CFG_INIT                                 \
    { (uint32_t)sizeof(wtq_msquic_client_cfg_t), NULL, 0, false,   \
      NULL, NULL, NULL }

WTQ_API void wtq_msquic_client_cfg_init(wtq_msquic_client_cfg_t *cfg);

/*
 * Dial a server and request a WebTransport session over it. Returns as
 * soon as the connection attempt is underway; the outcome arrives via
 * the session events (on_established / on_refused / on_failed).
 *
 * On success *session_out carries one app-owned reference (see the
 * ownership rules above). On failure *session_out is NULL and
 * everything acquired is released.
 */
WTQ_API wtq_result_t wtq_msquic_client_connect(
    wtq_msquic_env_t *env, const wtq_msquic_client_cfg_t *cfg,
    wtq_session_t **session_out);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_WTQUIC_MSQUIC_H */
