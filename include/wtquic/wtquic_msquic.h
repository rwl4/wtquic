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
 *   - The managed-domain EXTENSION: a session created with a wtq_guard_t
 *     (see MANAGED-DOMAIN CONTRACT below) lets the caller run that
 *     session's operations from any thread WHILE it holds the guard —
 *     the backend brackets every one of that session's callbacks with the
 *     same guard, so the caller's lane lock becomes the serialization
 *     domain. Without a guard, the callback-only rule above stands.
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
 * MANAGED-DOMAIN CONTRACT (optional; all fields below are struct_size-gated
 * so an old caller passing a smaller config gets exactly today's behavior).
 *
 * The MsQuic backend is callback-only: without these, wtq_session_* may run
 * only from inside a session's callbacks (see THREADING above). A managed
 * host supplies a wtq_guard_t (client cfg / accept decision) whose ctx is
 * its own lane lock; the backend then brackets every callback dispatch with
 * it, and the host may run guarded wtq_session_* from any thread.
 */

/*
 * Transport-quiescence notification (MsQuic-specific — NOT a generic
 * wtq_session_events_t member). Fires EXACTLY ONCE per connection that ran,
 * under the session's guard, at final teardown: after the session's
 * terminal event and all final engine processing, and BEFORE the backend
 * releases its own session reference. It MARKS quiescence — the session
 * handle is still valid — and MUST NOT release the app's reference. After
 * it returns, no callback carrying this user is ever dispatched again.
 * `user` is the client cfg's user, or the accept decision's per-child user.
 * The fn pointer and its user are copied into the backend connection, so
 * they must outlive listener destruction (a connection can outlive its
 * listener), up to the guarded reap after env_close.
 */
typedef void (*wtq_msquic_transport_quiesced_fn)(wtq_session_t *session,
                                          void *user);

/*
 * Server admission (optional; both accept_prepare and accept_abandon set,
 * or neither). accept_prepare runs at QUIC NEW_CONNECTION, BEFORE any
 * wtquic session or driver is allocated, so a server can bound admission
 * and bind per-connection state before any event can fire. It receives
 * only transport-level facts (peer address, negotiated ALPN) — the WT
 * path/subprotocol are NOT yet negotiated — and NO session handle (none
 * exists). It MUST NOT call any wtq_session_* / wtq_stream_*.
 *
 *   WTQ_OK  + out->accepted=true   admit; the session is CONSTRUCTED with
 *                                  out->user (per-child) and out->guard.
 *   WTQ_OK  + out->accepted=false  refuse -> QUIC_STATUS_CONNECTION_REFUSED;
 *                                  nothing constructed, NO abandon.
 *   WTQ_ERR_NOMEM                  refuse -> QUIC_STATUS_OUT_OF_MEMORY.
 *   other WTQ_ERR_*                refuse -> QUIC_STATUS_INTERNAL_ERROR.
 *
 * accept_abandon fires EXACTLY ONCE, under out->guard, for every ADMITTED
 * connection that then fails before delivering any callback (driver alloc,
 * session create, serve, env-closing race, or ConnectionSetConfiguration
 * failure). It is the counterpart of on_transport_quiesced, which fires for
 * every admitted connection that DID run — exactly one of the two per
 * admitted child. accept_abandon MAY free out->user (the backend copies
 * {leave, ctx} before invoking it).
 */
typedef struct wtq_msquic_accept_info {
    uint32_t struct_size;
    const void *peer_address;   /* QUIC_ADDR *; borrowed for the call */
    size_t peer_address_len;
    wtq_str_t alpn;             /* negotiated ALPN; borrowed for the call */
} wtq_msquic_accept_info_t;

typedef struct wtq_msquic_accept_decision {
    bool accepted;
    wtq_guard_t guard;          /* installed on the constructed session */
    void *user;                 /* per-child user passed into construction */
} wtq_msquic_accept_decision_t;

typedef wtq_result_t (*wtq_msquic_accept_prepare_fn)(
    void *listener_user, const wtq_msquic_accept_info_t *info,
    wtq_msquic_accept_decision_t *out);
typedef void (*wtq_msquic_accept_abandon_fn)(void *listener_user, void *user);

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
    /* v2 (struct_size-gated): managed-domain admission + quiescence.
     * NULL/absent ⇒ today's behavior (shared user, no guard, no hooks). */
    wtq_msquic_accept_prepare_fn accept_prepare;
    wtq_msquic_accept_abandon_fn accept_abandon;
    wtq_msquic_transport_quiesced_fn on_transport_quiesced;
    /* v3 (struct_size-gated): the WebTransport wire profile EVERY accepted
     * connection speaks (wtq_webtransport_profile_t; see session.h). It is
     * listener-wide, not per served path: one profile per listener, fixed
     * for the lifetime of each connection, never auto-negotiated. A partial
     * or absent tail — every caller compiled before this field — defaults to
     * WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT (0). An out-of-range value fails
     * wtq_msquic_listener_start with WTQ_ERR_INVALID_ARG. */
    uint32_t webtransport_profile;
} wtq_msquic_listener_cfg_t;

#define WTQ_MSQUIC_LISTENER_CFG_INIT                              \
    { (uint32_t)sizeof(wtq_msquic_listener_cfg_t), NULL, 0, NULL, \
      NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, 0 }

/*
 * Initialise a listener config. Same ABI rule as the client (see above):
 *   - wtq_msquic_listener_cfg_init(cfg): the macro forwards the CONCRETE type
 *     size (sizeof(wtq_msquic_listener_cfg_t)), so a caller gets a config fully
 *     initialised for its compiled version, including the admission/quiescence
 *     tail — and cfg_init(NULL) stays a compiling no-op (the function accepts
 *     NULL; sizeof *(cfg) would not compile for a null pointer under pedantic).
 *   - wtq_msquic_listener_cfg_init_ex(cfg, struct_size): initialises exactly
 *     struct_size bytes (clamped) and records that size.
 * The bare symbol is FROZEN to the pre-managed-domain prefix so an old binary
 * that linked it is never written past its smaller object. As with the client,
 * &wtq_msquic_listener_cfg_init is the frozen v1 initialiser; use
 * &wtq_msquic_listener_cfg_init_ex for a current-size function pointer.
 */
WTQ_API void wtq_msquic_listener_cfg_init(wtq_msquic_listener_cfg_t *cfg);
WTQ_API void wtq_msquic_listener_cfg_init_ex(wtq_msquic_listener_cfg_t *cfg,
                                             size_t struct_size);
/* Concrete type size so cfg_init(NULL) still compiles and stays a no-op. */
#define wtq_msquic_listener_cfg_init(cfg) \
    wtq_msquic_listener_cfg_init_ex((cfg), sizeof(wtq_msquic_listener_cfg_t))

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
    /* v2 (struct_size-gated): managed-domain guard + quiescence. The guard
     * is installed before ConnectionOpen. A guarded client caller MUST hold
     * the guard across wtq_msquic_client_connect AND through publishing the
     * returned handle to wherever its callbacks will read it: holding it
     * makes the connect-time callbacks block on the caller's lane until it
     * is released, so the handle is always visible before any event runs on
     * it. Releasing the guard before publication is a use-before-publish
     * race. NULL/absent ⇒ today's behavior. */
    wtq_guard_t guard;
    wtq_msquic_transport_quiesced_fn on_transport_quiesced;
} wtq_msquic_client_cfg_t;

#define WTQ_MSQUIC_CLIENT_CFG_INIT                                 \
    { (uint32_t)sizeof(wtq_msquic_client_cfg_t), NULL, 0, false,   \
      NULL, NULL, NULL, { NULL, NULL, NULL }, NULL }

/*
 * Initialise a client config. Two entry points, one ABI rule:
 *   - wtq_msquic_client_cfg_init(cfg): the ergonomic form. The macro below
 *     forwards the CONCRETE type size (sizeof(wtq_msquic_client_cfg_t)), so a
 *     caller ALWAYS gets a config fully initialised for the version it compiled
 *     against — including the managed-domain tail (guard, on_transport_quiesced)
 *     — and cfg_init(NULL) stays a compiling no-op (sizeof *(cfg) would not
 *     compile for a null pointer under pedantic C/C++).
 *   - wtq_msquic_client_cfg_init_ex(cfg, struct_size): initialises exactly
 *     struct_size bytes (clamped to what this library knows) and records that
 *     size in cfg->struct_size.
 *
 * The exported bare symbol wtq_msquic_client_cfg_init is FROZEN to the
 * pre-managed-domain layout: it writes only that prefix, so a binary compiled
 * against the older, smaller struct — which links the bare symbol — is never
 * written past its object. New source never reaches the bare symbol as a call:
 * the macro below routes every call through _ex with the current type size
 * (which is a no-op for a NULL argument, exactly like the function).
 *
 * TAKING THE ADDRESS selects the bare symbol, NOT the macro: &wtq_msquic_
 * client_cfg_init is the FROZEN v1 initialiser. A caller needing a
 * current-size function pointer must take &wtq_msquic_client_cfg_init_ex.
 */
WTQ_API void wtq_msquic_client_cfg_init(wtq_msquic_client_cfg_t *cfg);
WTQ_API void wtq_msquic_client_cfg_init_ex(wtq_msquic_client_cfg_t *cfg,
                                           size_t struct_size);
/* Concrete type size (not sizeof *(cfg)) so cfg_init(NULL) still compiles
 * under pedantic C/C++ and stays a no-op. */
#define wtq_msquic_client_cfg_init(cfg) \
    wtq_msquic_client_cfg_init_ex((cfg), sizeof(wtq_msquic_client_cfg_t))

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
