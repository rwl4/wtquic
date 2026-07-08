#ifndef WTQ_SESSION_H
#define WTQ_SESSION_H

/*
 * WebTransport session.
 *
 * A session is created by a backend entry point (or, in tests, over a
 * fake transport) and delivers everything through the typed callbacks
 * in wtq_session_events_t. The API is callback-first: events fire from
 * transport context; there is no event queue to poll.
 *
 * HANDLE LIFETIME
 *   The creator owns one reference; wtq_session_release() drops it and
 *   the last release destroys the session (releasing from inside any
 *   callback is legal — the free is deferred until the callback stack
 *   unwinds). After the terminal event (on_closed / on_refused /
 *   on_failed) a still-referenced handle is dead-but-valid: operations
 *   return WTQ_ERR_CLOSED; queries stay usable; the final release
 *   frees. Every wtq_stream_add_ref also pins the session, so a
 *   RETAINED stream can never outlive its session's memory; a stream
 *   handle the app never retained needs no such pin (it is unusable by
 *   definition once the session is gone).
 *
 * THREADING (the minimum contract every backend guarantees)
 *   Events for one session never fire concurrently — the backend
 *   serializes them, and that serialization is the session's ONE
 *   domain. Every wtq_session_* / wtq_stream_* operation on a session
 *   or its streams — including add_ref/release and the queries — must
 *   run inside that domain: nothing here is internally locked or
 *   atomic. Calls from inside the session's own callbacks are always
 *   legal (full reentrancy); an operation from anywhere else must not
 *   run concurrently with callback dispatch or with any other
 *   operation on the same session.
 *
 *   How an application enters the domain from OUTSIDE a callback is
 *   backend-defined; consult the backend's header for what it
 *   provides. On the MsQuic backend (<wtquic/wtquic_msquic.h>) an
 *   UNGUARDED session is callback-only: operations run solely inside
 *   that session's callbacks, with one documented exception after
 *   wtq_msquic_env_close() returns. A session created with a
 *   wtq_guard_t (below) widens this — while the caller holds the guard
 *   it may run that session's operations from ANY thread, because the
 *   guard IS the domain the backend brackets its callbacks with.
 */

#include "error.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wtq_session wtq_session_t;
typedef struct wtq_stream wtq_stream_t;

/* Why establishment failed (on_failed). */
typedef enum wtq_connect_failure {
    WTQ_CONNECT_FAILURE_NO_WT_SUPPORT = 1, /* peer lacks WebTransport */
    WTQ_CONNECT_FAILURE_NO_SUBPROTOCOL = 2, /* required subprotocol not
                                               negotiable */
    WTQ_CONNECT_FAILURE_BAD_RESPONSE = 3,  /* malformed peer response */
    WTQ_CONNECT_FAILURE_CONNECTION = 4,    /* the connection failed
                                              before establishment */
} wtq_connect_failure_t;

typedef enum wtq_session_status {
    WTQ_SESSION_STATUS_CONNECTING = 0,
    WTQ_SESSION_STATUS_ESTABLISHED,
    WTQ_SESSION_STATUS_DRAINING, /* peer asked for graceful shutdown;
                                    traffic still flows */
    WTQ_SESSION_STATUS_CLOSED,   /* terminal (was established) */
    WTQ_SESSION_STATUS_FAILED,   /* terminal (never established) */
} wtq_session_status_t;

/*
 * Caller-owned serialization-domain guard (optional; whether a backend
 * honors it is backend-defined — see the backend header). When a session
 * is created with a guard, the backend calls enter(ctx) BEFORE dispatching
 * any of that session's events and leave(ctx) AFTER the dispatch unwinds,
 * so the caller's own lock becomes the session's ONE domain (see THREADING
 * above). The guarded EXTENSION to the callback-only confinement contract:
 * while that lock is held, the caller may additionally run this session's
 * wtq_session_* / wtq_stream_* operations from any thread.
 *
 * CONTRACT
 *   - enter and leave are BOTH NULL (no guard) or BOTH non-NULL.
 *   - ctx must OUTLIVE the backend object bound to the session — it is the
 *     caller's lock/lane, never a per-connection object: the backend may
 *     call leave(ctx) after a callback has freed the per-connection state,
 *     so it copies {leave, ctx} before dispatch. The last dispatch the
 *     backend brackets is the session's terminal callback (and, on MsQuic,
 *     the transport-quiescence hook that fires under the guard right after
 *     it); ctx must stay valid through that final leave.
 *   - Legal lock order is guard -> any backend-internal lock. The caller
 *     must NEVER hold the guard across a blocking teardown call (e.g.
 *     wtq_msquic_env_close / wtq_msquic_listener_stop), which waits on the
 *     backend workers that must themselves take the guard.
 */
typedef struct wtq_guard {
    void (*enter)(void *ctx);
    void (*leave)(void *ctx);
    void *ctx;
} wtq_guard_t;

/*
 * Typed event callbacks. Set struct_size (use WTQ_SESSION_EVENTS_INIT)
 * so the struct can grow without breaking old callers; NULL members are
 * skipped. `user` is the pointer given at session creation.
 *
 * Exactly one terminal event fires per session: on_closed when an
 * established session ends (however it ends — a close from either side,
 * clean stream end, abrupt reset, or connection failure), on_refused /
 * on_failed when establishment never completed. By the time on_closed
 * fires, every live stream has already received its on_stream_closed.
 *
 * BORROWED DATA: subprotocol/reason/data pointers are valid only for
 * the duration of the callback — copy what must outlive it.
 */
typedef struct wtq_session_events {
    uint32_t struct_size;

    /* The session is up. subprotocol is the negotiated value ("" when
     * none was negotiated). */
    void (*on_established)(wtq_session_t *session, wtq_str_t subprotocol,
                           void *user);
    /* Client only: the server answered with a non-success status. */
    void (*on_refused)(wtq_session_t *session, uint16_t http_status,
                       void *user);
    /* Establishment failed for a non-HTTP reason. */
    void (*on_failed)(wtq_session_t *session, wtq_connect_failure_t why,
                      void *user);
    /* The peer requested graceful shutdown. Advisory: streams and
     * datagrams keep working; finish up and close soon. */
    void (*on_draining)(wtq_session_t *session, void *user);
    /* THE terminal event for an established session. clean is true for
     * an orderly close (a close message or clean end from either side),
     * false for abrupt termination. code/reason are the application
     * close data (0/"" when none was carried). */
    void (*on_closed)(wtq_session_t *session, uint32_t code,
                      const uint8_t *reason, size_t reason_len,
                      bool clean, void *user);

    /* The peer opened a stream. The handle is valid until its
     * on_stream_closed returns; call wtq_stream_add_ref to retain it
     * beyond that. */
    void (*on_stream_opened)(wtq_session_t *session, wtq_stream_t *stream,
                             bool bidi, void *user);
    /* Incoming stream payload, delivered as the transport's own buffer
     * (zero copy) and consumed when the callback returns. len may be 0
     * (bare end-of-stream). fin means the peer finished this stream's
     * data. */
    void (*on_stream_data)(wtq_session_t *session, wtq_stream_t *stream,
                           const uint8_t *data, size_t len, bool fin,
                           void *user);
    /* The peer abruptly ended the stream's incoming direction.
     * app_code is the peer's application error code (0 when it did not
     * carry one). A bidirectional stream's outgoing direction remains
     * usable. */
    void (*on_stream_reset)(wtq_session_t *session, wtq_stream_t *stream,
                            uint32_t app_code, void *user);
    /* The peer asked us to stop sending on this stream. The stream
     * remains usable until reset or finished; typically respond with
     * wtq_stream_reset() — or wtq_stream_abort() on transports where an
     * exact single-half reset of a fully-open bidi is unsupported
     * (wtq_stream_reset returns WTQ_ERR_UNSUPPORTED there). */
    void (*on_stream_stop)(wtq_session_t *session, wtq_stream_t *stream,
                           uint32_t app_code, void *user);
    /* THE terminal event for a stream: both directions are done (or
     * the session/connection ended). Fires exactly once per stream;
     * afterwards an un-retained handle is gone. */
    void (*on_stream_closed)(wtq_session_t *session, wtq_stream_t *stream,
                             void *user);

    /* A wtq_stream_send() completed: the send's data buffers belong to
     * the application again. Fires exactly once per accepted send —
     * canceled=true when the stream/session/connection ended first. */
    void (*on_send_complete)(wtq_session_t *session, void *send_ctx,
                             bool canceled, void *user);
    /* A datagram arrived. data points into the received buffer —
     * borrowed for the duration of the callback, never copied. */
    void (*on_datagram)(wtq_session_t *session, const uint8_t *data,
                        size_t len, void *user);

    /* A send this stream refused with WTQ_ERR_WOULD_BLOCK can be
     * retried: the transport released in-flight budget or raised its
     * buffering advice. Edge-triggered — fires once per
     * blocked-to-writable transition and re-arms on the next
     * WTQ_ERR_WOULD_BLOCK. Backends without send budgeting never fire
     * it; a NULL member is skipped like any other. */
    void (*on_stream_writable)(wtq_session_t *session,
                               wtq_stream_t *stream, void *user);
} wtq_session_events_t;

#define WTQ_SESSION_EVENTS_INIT \
    { (uint32_t)sizeof(wtq_session_events_t), 0, 0, 0, 0, 0, \
      0, 0, 0, 0, 0, 0, 0, 0 }

WTQ_API void wtq_session_events_init(wtq_session_events_t *events);

/*
 * The WebTransport-over-HTTP/3 client profile: which WT wire dialect the
 * connection speaks. Latched at connect and committed BEFORE the control
 * stream's SETTINGS are emitted; it cannot change afterwards.
 *
 * These are two distinct, mutually-exclusive wire profiles — never mixed
 * on one connection, never auto-negotiated. The compatibility profile is
 * an explicit opt-in for peers speaking the historical native-H3
 * WebTransport SETTINGS dialect; it is NOT a superset, and enabling it
 * does not also advertise the current settings.
 */
typedef enum wtq_webtransport_profile {
    /*
     * The active draft-16 profile (the default; zero-initialised
     * connects get this):
     *   - extended CONNECT :protocol = "webtransport-h3"
     *   - the draft-16 WebTransport-enabled control signal
     */
    WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT = 0,

    /*
     * Opt-in native-H3 compatibility profile (drafts 13/14 WebTransport
     * SETTINGS dialect), for peers such as proxygen/moxygen and the
     * picoquic h3zero family:
     *   - extended CONNECT :protocol = "webtransport"
     *   - the drafts 13/14 WebTransport max-sessions control signal
     *   - no WT flow-control settings, so WT flow control stays disabled.
     * Note: in the current architecture bare "webtransport" also names
     * capsule-based WebTransport; this profile is safe only because it is
     * EXPLICIT and paired with the historical H3 SETTINGS dialect above.
     */
    WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT = 1
} wtq_webtransport_profile_t;

/*
 * Client connect parameters (what to CONNECT to and which application
 * subprotocols to offer). Strings are copied during the call.
 *
 * ABI: struct_size versions this. The frozen v1 prefix ends at
 * `require_subprotocol`; `webtransport_profile` is a v2 tail field that
 * begins AT the frozen v1 sizeof (never inside v1's tail padding, so an
 * old caller's struct_size can never expose uninitialised padding as the
 * profile). Zero (a partial or absent tail) means H3_CURRENT.
 *
 * Use WTQ_CONNECT_CONFIG_INIT / wtq_connect_config_init (frozen v1) or
 * wtq_connect_config_init_ex(cfg, struct_size) for the current size.
 */
typedef struct wtq_connect_config {
    uint32_t struct_size;
    const char *authority;            /* required, e.g. "example.com" */
    const char *path;                 /* required, e.g. "/app" */
    const char *origin;               /* optional (NULL = absent) */
    const char *const *subprotocols;  /* offered, in preference order */
    size_t subprotocol_count;
    bool require_subprotocol;         /* fail unless one is selected */
    /* Filler that pushes the v2 tail past v1's natural tail padding: a
     * bare uint32_t would align into that padding (offset 52 on LP64),
     * which an old caller's struct_size=sizeof(v1) would then expose as
     * uninitialised. With this filler `webtransport_profile` begins at
     * sizeof(v1) — asserted in session.c. Reserved; must stay zero. */
    uint32_t _reserved_v1_tail;
    /* ---- v2 tail (begins at sizeof(v1)) ---- */
    uint32_t webtransport_profile;    /* wtq_webtransport_profile_t;
                                         0 = H3_CURRENT */
} wtq_connect_config_t;

/* The frozen v1 shadow struct is INTERNAL (defined in session.c, with
 * the layout static-asserts); the bare wtq_connect_config_init writes
 * exactly sizeof(v1), so an old binary that linked it is never written
 * past its smaller object. It is deliberately NOT part of the public
 * surface. */

#define WTQ_CONNECT_CONFIG_INIT \
    { (uint32_t)sizeof(wtq_connect_config_t), 0, 0, 0, 0, 0, 0, 0, 0 }

/*
 * Initialise a connect config. Same ABI rule as the MsQuic cfgs:
 *   - wtq_connect_config_init(cfg): the header macro forwards the CONCRETE
 *     type size (sizeof(wtq_connect_config_t)) so new source gets a config
 *     initialised for its compiled version (profile field included), and
 *     cfg_init(NULL) stays a compiling no-op.
 *   - wtq_connect_config_init_ex(cfg, struct_size): initialises exactly
 *     struct_size bytes (clamped) and records that size.
 * The bare symbol is FROZEN to the v1 prefix; &wtq_connect_config_init is
 * the frozen v1 initialiser, &wtq_connect_config_init_ex the sized one.
 */
WTQ_API void wtq_connect_config_init(wtq_connect_config_t *cfg);
WTQ_API void wtq_connect_config_init_ex(wtq_connect_config_t *cfg,
                                        size_t struct_size);
/* Concrete type size so cfg_init(NULL) still compiles and stays a no-op. */
#define wtq_connect_config_init(cfg) \
    wtq_connect_config_init_ex((cfg), sizeof(wtq_connect_config_t))

/*
 * One server path registration: which request path to accept and which
 * subprotocols it supports. Use WTQ_SERVE_CONFIG_INIT.
 */
typedef struct wtq_serve_config {
    uint32_t struct_size;
    const char *path;                 /* exact match */
    const char *const *subprotocols;  /* supported (server order) */
    size_t subprotocol_count;
    bool require_subprotocol;         /* refuse when no overlap */
} wtq_serve_config_t;

#define WTQ_SERVE_CONFIG_INIT \
    { (uint32_t)sizeof(wtq_serve_config_t), 0, 0, 0, 0 }

WTQ_API void wtq_serve_config_init(wtq_serve_config_t *cfg);

/* --- lifetime ----------------------------------------------------------- */

WTQ_API void wtq_session_add_ref(wtq_session_t *session);
WTQ_API void wtq_session_release(wtq_session_t *session);

/* --- session lifecycle --------------------------------------------------- */

/*
 * Close the session with an application code and optional reason
 * (reason_len <= 1024 -> WTQ_ERR_TOO_LARGE). Delivers on_closed
 * (clean=true) before returning; every open stream gets its
 * on_stream_closed first. WTQ_ERR_STATE unless established/draining.
 */
WTQ_API wtq_result_t wtq_session_close(wtq_session_t *session,
                                       uint32_t code,
                                       const uint8_t *reason,
                                       size_t reason_len);

/* Ask the peer to wind down gracefully. Local state does not change;
 * traffic continues. */
WTQ_API wtq_result_t wtq_session_drain(wtq_session_t *session);

/* --- streams -------------------------------------------------------------- */

/*
 * Open a stream on the established session. The returned handle is
 * valid until its on_stream_closed returns (retain with
 * wtq_stream_add_ref). WTQ_ERR_STREAM_LIMIT when stream credit or the
 * handle pool is exhausted; WTQ_ERR_CLOSED after the session ended.
 */
WTQ_API wtq_result_t wtq_session_open_uni(wtq_session_t *session,
                                          wtq_stream_t **stream_out);
WTQ_API wtq_result_t wtq_session_open_bidi(wtq_session_t *session,
                                           wtq_stream_t **stream_out);

/* --- datagrams ------------------------------------------------------------ */

/*
 * Send a datagram (the spans concatenated; count <= 8). Borrow-during-
 * call: buffers are the caller's again when this returns. Returns
 * WTQ_ERR_TOO_LARGE over wtq_session_datagram_max_size(),
 * WTQ_ERR_DGRAM_DISABLED when datagrams are unavailable,
 * WTQ_ERR_WOULD_BLOCK when the transport's queue is momentarily full,
 * WTQ_ERR_CLOSED after the session ended.
 */
WTQ_API wtq_result_t wtq_session_send_datagram(wtq_session_t *session,
                                               const wtq_span_t *spans,
                                               size_t count);

/*
 * Largest datagram payload currently sendable (the transport's limit
 * minus wtquic's per-datagram association overhead; it can change with
 * path MTU). 0 usually means datagrams are unavailable — but on an
 * active session it can also mean "only an empty datagram fits", and
 * an empty send still succeeds. wtq_session_send_datagram's
 * WTQ_ERR_DGRAM_DISABLED is the availability signal.
 */
WTQ_API size_t wtq_session_datagram_max_size(const wtq_session_t *session);

/* --- queries -------------------------------------------------------------- */

WTQ_API wtq_session_status_t wtq_session_status(const wtq_session_t *session);

/*
 * The FIRST CAUSAL transport-level terminal error, dual-fidelity.
 *
 * The caller sets out->struct_size; the library copies the record's
 * leading bytes up to that size (fields beyond it are left untouched).
 * The record is SEALED at the session's first terminal transition:
 * immediately before on_failed / on_refused / on_closed fires, either
 * the causal error latched earlier or an explicit NONE is locked in,
 * and no later transport event can change it. The value read inside
 * those callbacks or any time after (same serialization domain) is
 * therefore final; kind == WTQ_ERR_KIND_NONE means the session ended
 * without a transport-level cause. Before any terminal event it also
 * reports kind == WTQ_ERR_KIND_NONE.
 *
 * Returns WTQ_ERR_INVALID_ARG when session/out is NULL or
 * out->struct_size cannot hold the `kind` field (the minimum is
 * offsetof(kind) + sizeof(kind) bytes).
 */
WTQ_API wtq_result_t wtq_session_transport_error(
    const wtq_session_t *session, wtq_transport_error_t *out);
/* Negotiated subprotocol ("" when none); borrowed until the session is
 * destroyed. */
WTQ_API wtq_str_t wtq_session_subprotocol(const wtq_session_t *session);

WTQ_API void wtq_session_set_user(wtq_session_t *session, void *user);
WTQ_API void *wtq_session_get_user(const wtq_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_SESSION_H */
