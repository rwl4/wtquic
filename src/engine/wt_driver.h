#ifndef WTQ_ENGINE_WT_DRIVER_H
#define WTQ_ENGINE_WT_DRIVER_H

/*
 * Driver SPI v0 + engine input surface — INTERNAL, never installed.
 *
 * The engine is sans-I/O and callback-driven: it invokes driver ops
 * synchronously from inside engine-input processing, and the backend
 * feeds transport events in through the wtq_conn_on_* functions. Time
 * is always passed in as now_us; the engine reads no clock, uses no
 * globals, and allocates only through the configured allocator.
 *
 * Two send contracts coexist: the plain `send` op is borrow-during-
 * call (backend copies/transmits before returning) and carries the
 * small, cold control-plane bytes (SETTINGS, CONNECT, capsules,
 * preambles); `send_gather` is the WT data-path contract — span data
 * borrowed until the completion cookie comes back, zero copies in the
 * engine.
 *
 * Reentrancy contract:
 *   - The backend MUST NOT call any wtq_conn_* input from inside a
 *     driver op (MsQuic never makes recursive callbacks; other
 *     backends defer).
 *   - The engine MAY call driver ops from inside any wtq_conn_* input.
 *   - All calls for one connection are serialized by the backend.
 */

#include <wtquic/error.h>
#include <wtquic/types.h>

#include "../proto/h3_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The backend seam crosses the shared-library boundary (backend
 * libraries link against the core), so the functions a backend calls
 * carry default visibility. This is NOT public API: the header is never
 * installed, and the core symbol-policy test pins the exported set.
 */
#if defined(__GNUC__) || defined(__clang__)
#define WTQ_SPI __attribute__((visibility("default")))
#else
#define WTQ_SPI
#endif

typedef struct wtq_conn wtq_conn_t;
typedef struct wtq_estream wtq_estream_t; /* engine per-stream state */
typedef struct wtq_driver wtq_driver_t;   /* backend connection ctx */
typedef struct wtq_dstream wtq_dstream_t; /* backend stream ctx */

/*
 * STORAGE capacity for the negotiated subprotocol, in bytes.
 *
 * This is a buffer size, NOT a protocol maximum. draft-15 s3.3 allows any
 * Structured Fields String, quotes and backslashes included, and this
 * engine does not narrow that grammar. What a value costs on the wire and
 * in the decoder depends on its CONTENT (escaping doubles `"` and `\`)
 * and on the rest of the message (:authority, :path, origin, the other
 * offers), so no single raw-length ceiling is meaningful.
 *
 * Instead, whether a subprotocol is usable is decided by ACTUALLY
 * encoding and decoding it: wtq_conn_server_set_paths and
 * wtq_conn_client_connect round-trip each configured value (and, for the
 * client, the whole generated CONNECT) through this engine's own codec
 * and bounded scratch, and refuse anything that would not survive with
 * WTQ_ERR_TOO_LARGE.
 *
 * A value that reaches establishment therefore came out of this engine's
 * decoder, whose unescaped output cannot exceed its scratch — so this
 * storage holds every value that can legitimately get here.
 */
#define WTQ_CONN_PROTOCOL_STORAGE 512u

/* WebTransport stream-rejection error codes (draft-15 s8.3; used as raw
 * QUIC reset/stop codes on streams that never join a session). */
#define WTQ_WT_BUFFERED_STREAM_REJECTED UINT64_C(0x3994bd84)
#define WTQ_WT_SESSION_GONE UINT64_C(0x170d7b68)

/* Session lifecycle states (one WT session per connection in v1).
 * ESTABLISHED -> DRAINING is advisory (draft-15 s4.7: streams may still
 * open); CLOSED is terminal and is entered exactly once, always
 * alongside the single on_session_closed callback. */
typedef enum wtq_session_state {
    WTQ_SESSION_IDLE = 0,
    WTQ_SESSION_PENDING,     /* client: connect requested, awaiting
                                peer SETTINGS */
    WTQ_SESSION_SENT,        /* client: CONNECT HEADERS on the wire */
    WTQ_SESSION_ESTABLISHED,
    WTQ_SESSION_DRAINING,    /* established + peer DRAIN received */
    WTQ_SESSION_CLOSED,      /* terminal (only from ESTABLISHED/DRAINING) */
    WTQ_SESSION_REJECTED,    /* client: non-2xx (never established) */
    WTQ_SESSION_FAILED,      /* never established (see fail reasons) */
} wtq_session_state_t;

/* How a shutdown_stream request is meant. */
typedef enum wtq_shutdown_mode {
    /*
     * Abort every still-open half with ONE code (send_err == recv_err;
     * the engine sets abort_send/abort_recv to exactly the halves that
     * are still open). The portable baseline: every backend supports it
     * for every stream shape, including a bidi with one half already
     * closed.
     */
    WTQ_SHUTDOWN_WHOLE_STREAM = 0,
    /*
     * Abort exactly the requested halves with independent codes. The
     * engine only issues this for the capability-gated shapes (a single
     * half of a fully-open bidi, or both halves with different codes);
     * everything else is normalized to WHOLE_STREAM first.
     */
    WTQ_SHUTDOWN_EXACT_HALVES = 1,
} wtq_shutdown_mode_t;

typedef struct wtq_shutdown {
    uint8_t mode;      /* wtq_shutdown_mode_t */
    bool abort_send;   /* RESET_STREAM our send half */
    bool abort_recv;   /* STOP_SENDING their send half */
    uint64_t send_err;
    uint64_t recv_err; /* WHOLE_STREAM: == send_err */
} wtq_shutdown_t;

/*
 * Capability bits. Only the genuinely backend-dependent shapes are
 * capabilities; WHOLE_STREAM and a uni stream's only half are baseline
 * obligations of every backend.
 */
typedef enum wtq_driver_cap {
    WTQ_DCAP_SHUT_BIDI_SEND   = 1u << 0, /* fully-open bidi: RESET alone */
    WTQ_DCAP_SHUT_BIDI_RECV   = 1u << 1, /* fully-open bidi: STOP alone  */
    WTQ_DCAP_SHUT_SPLIT_CODES = 1u << 2, /* both halves, different codes */
} wtq_driver_cap_t;

typedef struct wtq_driver_ops {
    /*
     * Capability word (wtq_driver_cap_t bits). The ENGINE decides
     * support from this BEFORE calling shutdown_stream; a request that
     * reaches the backend has already been accepted, so the backend
     * never returns WTQ_ERR_UNSUPPORTED.
     */
    uint32_t caps;

    /*
     * Open a LOCAL unidirectional stream. ectx becomes the stream's
     * engine context (handed back on future events for this stream).
     *
     * *id_out: the native QUIC stream id when the transport assigns it
     * synchronously, else WTQ_STREAM_ID_UNKNOWN — in which case the
     * backend MUST later report it via wtq_conn_on_stream_native_id()
     * (see its contract), unless the stream detaches first.
     * ectx == NULL (H3 critical streams): the engine discards the id
     * and no later report is possible or permitted.
     */
    wtq_result_t (*open_uni)(wtq_driver_t *drv, wtq_estream_t *ectx,
                             wtq_dstream_t **out, uint64_t *id_out);

    /*
     * Send bytes on a stream. v0: data is borrowed for the duration of
     * the call only (backend copies/queues before returning).
     * All-or-nothing.
     */
    wtq_result_t (*send)(wtq_driver_t *drv, wtq_dstream_t *ds,
                         const uint8_t *data, size_t len, bool fin);

    /*
     * Abort stream halves — ONE transaction (replaces the former
     * reset_stream/stop_sending pair). The engine has already decided
     * support (caps above), so the backend executes exactly the request:
     *   WTQ_OK          done (RESET for abort_send / STOP for abort_recv,
     *                   with the requested codes);
     *   WTQ_ERR_CLOSED  the transport is already dead; nothing sent,
     *                   nothing owed (benign);
     *   anything else   a runtime failure — possibly after PARTIAL
     *                   application (e.g. the second call of a split-code
     *                   sequence). The backend does NOT roll back; the
     *                   engine responds by failing the connection.
     * Idempotent per direction.
     */
    wtq_result_t (*shutdown_stream)(wtq_driver_t *drv, wtq_dstream_t *ds,
                                    const wtq_shutdown_t *req);

    /* Application-layer CONNECTION_CLOSE with an H3 error code. */
    wtq_result_t (*conn_close)(wtq_driver_t *drv, uint64_t h3_err);

    /* Open a LOCAL bidirectional stream (client CONNECT / WT bidi).
     * Same id contract as open_uni. */
    wtq_result_t (*open_bidi)(wtq_driver_t *drv, wtq_estream_t *ectx,
                              wtq_dstream_t **out, uint64_t *id_out);

    /*
     * Send one QUIC datagram (the spans concatenated). Borrow-during-
     * call: the backend copies or transmits before returning.
     * WTQ_ERR_WOULD_BLOCK when the transport's datagram queue is full.
     * OPTIONAL — NULL when the backend has no datagram support.
     */
    wtq_result_t (*dgram_send)(wtq_driver_t *drv, const wtq_span_t *spans,
                               size_t count);
    /*
     * Current maximum QUIC datagram payload the transport can carry
     * (0 = datagrams unavailable/disabled). May change over the
     * connection's life (path MTU). OPTIONAL, paired with dgram_send.
     */
    size_t (*dgram_max_size)(wtq_driver_t *drv);

    /*
     * Gather send with a completion cookie (the WT data-path contract).
     * The span ARRAY is borrowed for the duration of the call only; the
     * span DATA is borrowed until the backend reports completion via
     * wtq_conn_on_send_complete(cookie, canceled). All-or-nothing:
     *   WTQ_OK       -> accepted; exactly ONE completion will follow
     *                   (canceled=true if the stream resets or the
     *                   connection closes before the data is done).
     *   any error    -> NOT accepted; NO completion will ever fire;
     *                   ownership of the data stays with the caller
     *                   immediately.
     */
    wtq_result_t (*send_gather)(wtq_driver_t *drv, wtq_dstream_t *ds,
                                const wtq_span_t *spans, size_t count,
                                bool fin, void *cookie);

    /*
     * Enable/disable delivery of received data on a stream. Disabling
     * stops FUTURE indications only — bytes already being delivered
     * still arrive and the engine consumes them as always; the
     * transport buffers what keeps arriving and its flow control
     * eventually pushes back on the peer. OPTIONAL — NULL when the
     * backend cannot pause reads (the engine reports UNSUPPORTED).
     */
    wtq_result_t (*recv_enable)(wtq_driver_t *drv, wtq_dstream_t *ds,
                                bool enabled);

    /*
     * Sever the backend stream's engine linkage. The engine calls this
     * exactly when it releases ds's estream slot for reuse; from that
     * point the backend MUST NOT deliver ANY event for ds — bytes, FIN,
     * reset, STOP_SENDING, writable — against that estream. (Gather
     * completions are cookie-keyed, not estream-keyed, and still fire.)
     * IDENTITY-CHECKED: the backend drops its recorded ctx only if it
     * still equals es, so a stale stream's late detach can never sever
     * a slot that has since been attached to a new stream. Required.
     */
    void (*detach)(wtq_driver_t *drv, wtq_dstream_t *ds,
                   wtq_estream_t *es);
} wtq_driver_ops_t;

/* Session outcome reasons for on_session_failed. */
typedef enum wtq_session_fail_reason {
    WTQ_SESSION_FAIL_NO_WT_SUPPORT = 1, /* peer SETTINGS lack WT */
    WTQ_SESSION_FAIL_NO_PROTOCOL = 2,   /* required subprotocol missing
                                           or not from our offer */
    WTQ_SESSION_FAIL_BAD_RESPONSE = 3,  /* malformed response section */
    WTQ_SESSION_FAIL_CONNECTION = 4,    /* the connection died before the
                                           session could be established
                                           (transport loss or a protocol
                                           error); the more specific
                                           reasons above win when one of
                                           them already fired */
} wtq_session_fail_reason_t;

/* Engine→app callbacks. */
typedef struct wtq_conn_callbacks {
    /* Peer SETTINGS fully received and validated. */
    void (*on_peer_settings)(wtq_conn_t *conn, bool wt_supported,
                             void *ctx);
    /* The engine closed (or observed the close of) the connection. */
    void (*on_conn_error)(wtq_conn_t *conn, uint64_t h3_err, void *ctx);
    /* The WT session is established (2xx exchanged). selected is the
     * negotiated subprotocol ("" when none), borrowed until the
     * connection is destroyed. */
    void (*on_session_established)(wtq_conn_t *conn, const char *selected,
                                   size_t selected_len, void *ctx);
    /* Client only: the server answered non-2xx. */
    void (*on_session_rejected)(wtq_conn_t *conn, uint16_t status,
                                void *ctx);
    /* The session cannot be established (see the reason enum). */
    void (*on_session_failed)(wtq_conn_t *conn,
                              wtq_session_fail_reason_t reason, void *ctx);

    /*
     * THE terminal session callback: fires exactly once per established
     * session, whatever ends it (CLOSE capsule either direction, clean
     * CONNECT FIN, CONNECT reset, H3 connection error, transport
     * close). clean=true only for the capsule/clean-FIN paths. reason
     * is borrowed for the duration of the callback ("" when empty; a
     * clean FIN without a capsule is code 0 + empty reason per draft-15
     * s6). By return, every stream associated with the session has been
     * reset/stopped with WT_SESSION_GONE and released.
     */
    void (*on_session_closed)(wtq_conn_t *conn, uint32_t code,
                              const uint8_t *reason, size_t reason_len,
                              bool clean, void *ctx);
    /* Peer sent WT_DRAIN_SESSION: graceful-shutdown request. Advisory
     * (draft-15 s4.7): the session and its streams keep working. Fires
     * at most once. */
    void (*on_session_draining)(wtq_conn_t *conn, void *ctx);

    /* Peer opened a WT stream on the established session (preamble
     * fully parsed and validated). es is the engine handle for the
     * wtq_conn_wt_* calls; payload bytes follow via on_wt_stream_data. */
    void (*on_wt_stream_opened)(wtq_conn_t *conn, wtq_estream_t *es,
                                bool bidi, uint64_t id, void *ctx);
    /* WT stream payload passthrough: data is the transport's buffer,
     * borrowed for the duration of the callback; the engine never
     * copies or re-buffers it. len may be 0 (bare FIN). */
    void (*on_wt_stream_data)(wtq_conn_t *conn, wtq_estream_t *es,
                              const uint8_t *data, size_t len, bool fin,
                              void *ctx);
    /* Peer reset a WT stream. app_code is the mapped WT application
     * error, 0 when the wire code is outside the WT range (draft-15
     * s4.4: delivered as "no application error code"). A reset closes
     * the RECEIVE side only: es stays valid through the callback, and
     * a bidi stream's send side keeps working; es is released once its
     * last direction closes (immediately after the callback for a
     * receive-only stream). */
    void (*on_wt_stream_reset)(wtq_conn_t *conn, wtq_estream_t *es,
                               uint32_t app_code, void *ctx);
    /* Peer sent STOP_SENDING for a WT stream we write to (same code
     * mapping as on_wt_stream_reset). The stream stays usable until
     * reset/FIN. */
    void (*on_wt_stream_stop)(wtq_conn_t *conn, wtq_estream_t *es,
                              uint32_t app_code, void *ctx);
    /* A send_gather completion: the cookie's data buffers are released
     * back to the app. Fires exactly once per accepted send, including
     * after session/connection teardown (canceled=true). */
    void (*on_wt_send_complete)(wtq_conn_t *conn, void *cookie,
                                bool canceled, void *ctx);
    /* A datagram for the established session (association prefix
     * already stripped). data points INTO the received datagram's
     * buffer — borrowed for the duration of the callback, never
     * copied. len may be 0. */
    void (*on_wt_datagram)(wtq_conn_t *conn, const uint8_t *data,
                           size_t len, void *ctx);
    /* A WT stream whose send path reported WOULD_BLOCK can accept
     * data again (budget released / transport advice grew). Appended
     * after v0; backends without send budgeting never call the
     * matching input, and a NULL member is skipped. */
    void (*on_wt_stream_writable)(wtq_conn_t *conn, wtq_estream_t *es,
                                  void *ctx);
    /* The transport stream ceased WHOLE (wtq_conn_on_stream_terminal):
     * no operation or event can follow, and no RESET_STREAM or
     * STOP_SENDING code is implied or fabricated. Fired ONLY when an
     * app-visible live stream still needed terminalization — a stream
     * whose halves all closed through normal events never sees it.
     * Accepted sends have already completed/canceled by the terminal.
     * The estream is released immediately after the callback returns:
     * es is valid for the callback's duration only. */
    void (*on_wt_stream_terminal)(wtq_conn_t *conn, wtq_estream_t *es,
                                  void *ctx);
    void *ctx;
} wtq_conn_callbacks_t;

typedef struct wtq_conn_cfg {
    const wtq_alloc_t *alloc;        /* required; copied */
    wtq_perspective_t perspective;
    bool enable_connect_protocol;    /* outgoing SETTINGS knob */
    /* wtq_h3_wt_profile_t: 0 = current (draft-16), 1 = D13/14 compat.
     * The WebTransport wire profile this connection speaks. For a SERVER
     * it is latched here at create — before any SETTINGS can be emitted —
     * and fixes both the outgoing SETTINGS dialect and which extended
     * CONNECT :protocol token inbound requests must carry. A CLIENT passes
     * current (0) here and latches its real profile later in
     * wtq_conn_client_connect (which runs before start emits SETTINGS);
     * out-of-range is WTQ_ERR_INVALID_ARG. */
    int webtransport_profile;
    wtq_conn_callbacks_t callbacks;  /* copied */
} wtq_conn_cfg_t;

/*
 * Lifecycle. Allocations: one wtq_conn (with its inline peer-stream
 * pool) at create; nothing on the receive path afterwards.
 */
wtq_result_t wtq_conn_create(const wtq_conn_cfg_t *cfg, wtq_driver_t *drv,
                             const wtq_driver_ops_t *ops,
                             wtq_conn_t **out);
void wtq_conn_destroy(wtq_conn_t *conn);

/*
 * Transport ready. PERSPECTIVE-SPLIT bootstrap:
 *
 *   CLIENT: opens the local control stream (type 0x00) and sends the
 *   SETTINGS frame, then opens the QPACK encoder (0x02) and decoder
 *   (0x03) streams with their one-byte prefaces (no dynamic QPACK ever
 *   follows) — all before start returns; driver failures are returned
 *   here.
 *
 *   SERVER: start only latches the attempt; the same three opens are
 *   DEFERRED to the peer's first inbound event (uni, bidi, or
 *   datagram) so they can never race the client transport's own
 *   readiness (the measured Network.framework ready-transition stream
 *   drop). A deferred failure therefore surfaces as a CONNECTION-FATAL
 *   H3_INTERNAL_ERROR through on_conn_error at that first inbound
 *   event — exactly one terminal outcome, the triggering event never
 *   processed — not as a start return value.
 *
 * ONE-SHOT either way. The attempt is consumed before the first driver
 * operation runs and NOTHING is rolled back on failure: streams already
 * opened, and any SETTINGS bytes already handed to the transport,
 * cannot be un-sent. The connection is unusable — destroy it and build
 * a new one; do not retry. Every later call (after success or failure)
 * returns WTQ_ERR_STATE without invoking a single driver operation.
 */
wtq_result_t wtq_conn_start(wtq_conn_t *conn, uint64_t now_us);

/*
 * Peer opened a unidirectional stream. The engine returns its stream
 * context in *ectx_out; the backend attaches it and hands it back with
 * every future event for that stream.
 *
 * WTQ_ERR_STREAM_LIMIT with *ectx_out == NULL when the engine's fixed
 * peer-stream pool is exhausted. Before returning, the engine has
 * ACTIVELY rejected the stream through the driver ops — STOP_SENDING
 * (uni), or RESET_STREAM plus STOP_SENDING (bidi), always with the
 * WebTransport codepoint WTQ_WT_BUFFERED_STREAM_REJECTED.
 *
 * BACKEND CONTRACT: a stream with no engine context has no one to
 * deliver to, so the backend discards bytes that arrive on it — but
 * only for as long as the in-flight rejection takes to reach the peer.
 * It is never a silent, permanent sink: the peer has been told, and it
 * must never be left waiting on a stream nobody will read. A backend
 * that acknowledges flow control for such bytes must not do so
 * indefinitely.
 */
WTQ_SPI wtq_result_t wtq_conn_on_peer_uni_opened(wtq_conn_t *conn,
                                         wtq_dstream_t *ds, uint64_t id,
                                         wtq_estream_t **ectx_out);

/*
 * Bytes received on a peer uni stream (any chunking). The engine
 * consumes everything offered. Errors have already been acted on via
 * conn_close by the time a negative status returns.
 */
WTQ_SPI wtq_result_t wtq_conn_on_stream_bytes(wtq_conn_t *conn,
                                      wtq_estream_t *es,
                                      const uint8_t *data, size_t len,
                                      bool fin, uint64_t now_us);

/* Peer reset one of its uni streams. */
WTQ_SPI wtq_result_t wtq_conn_on_stream_reset(wtq_conn_t *conn,
                                      wtq_estream_t *es,
                                      uint64_t quic_err, uint64_t now_us);

/*
 * Whole-stream transport terminal: the backend's stream object reached
 * a state after which NOTHING further can ever be delivered (no bytes,
 * FIN, or reset). Absorber tombstones — a receive drain, an
 * unknown-type byte sink, a dead request absorber — release
 * immediately (their awaited peer answer can never arrive). Still-live
 * WT halves are CLOSED, with no RESET_STREAM or STOP_SENDING code
 * fabricated: on_wt_stream_terminal fires instead, and only when an
 * app-visible live stream still needed terminalization. Critical
 * streams, the CONNECT stream, and live HTTP request semantics are
 * untouched. Backends whose stream terminal is silent about the peer's
 * answer call this at that terminal so absorbers and live shells
 * cannot pin for the connection's life; backends that always deliver
 * the answering FIN/RESET never need it.
 */
WTQ_SPI wtq_result_t wtq_conn_on_stream_terminal(wtq_conn_t *conn,
                                                 wtq_estream_t *es);

/* Transport-level close observed (peer or local transport). */
WTQ_SPI void wtq_conn_on_conn_closed(wtq_conn_t *conn, uint64_t err, bool remote,
                             uint64_t now_us);

/*
 * Backend -> engine: full-fidelity detail for the FIRST CAUSAL transport-
 * level terminal error. Call at most once, on the serialization domain,
 * BEFORE the terminal input (wtq_conn_on_conn_closed / the failure path)
 * it explains. The engine stores it write-once: the first call wins and
 * every later call is ignored — a locally-generated cancellation error
 * arriving during teardown can never overwrite the remote/root cause.
 * Engine-originated fatals participate in the SAME precedence: conn_fatal
 * latches its own record before invoking any callback, so a backend
 * status produced while executing the engine-requested teardown loses.
 * Never calling it is legal: the engine synthesizes {kind, quic_code}
 * from the terminal input's err/remote (native domain NONE).
 * Only fields within e->struct_size are read; the rest default to zero.
 * The accepted minimum prefix runs through `kind`
 * (offsetof(kind) + sizeof(kind) bytes); records smaller than that, and
 * records whose kind is not one of QUIC_TRANSPORT / QUIC_APP / LOCAL,
 * are ignored entirely — a kind==NONE input can never consume the
 * write-once latch and suppress later synthesis.
 */
WTQ_SPI void wtq_conn_set_transport_error(wtq_conn_t *conn,
                                          const wtq_transport_error_t *e);

/*
 * The latched record (engine-internal, for the API query). NULL until a
 * record was latched. NOT WTQ_SPI: not part of the backend contract.
 */
const wtq_transport_error_t *wtq_conn_transport_error(const wtq_conn_t *conn);

/*
 * Seal the record at the session's first public terminal transition
 * (engine-internal, called by the API layer immediately before
 * on_failed / on_refused / on_closed). If no error was latched, an
 * explicit NONE record is latched so every later engine or backend
 * write is ignored — the value a terminal callback observed can never
 * change afterwards. A connection error causing the terminal latched
 * before this and wins.
 */
void wtq_conn_seal_transport_error(wtq_conn_t *conn);

/* --- CONNECT / session establishment ----------------------------------- */

#define WTQ_CONN_MAX_OFFERED 8
#define WTQ_CONN_MAX_PATHS 4
/* Aggregate bytes of subprotocol text the engine stores per served path. */
#define WTQ_CONN_PATH_PROTO_STORAGE 256u

/*
 * Validate one served path's subprotocol list, transport-neutrally: the
 * SAME rules wtq_conn_server_set_paths applies, so a backend can reject
 * an impossible policy at listener-configuration time instead of failing
 * every accepted connection later. Backend-agnostic on purpose — the
 * MsQuic listener and any future adapter call exactly this.
 *
 * Checks, in order: structure (count bound, non-NULL pointers), content
 * (nonempty, a valid Structured Fields String), aggregate storage, and a
 * real response encode/decode round-trip through this engine's codec.
 *
 *   WTQ_ERR_INVALID_ARG - structure or malformed content
 *   WTQ_ERR_TOO_LARGE   - storage or codec capacity
 */
WTQ_SPI wtq_result_t wtq_conn_validate_protocols(
    const char *const *protocols, size_t count);

/*
 * Client: request a WebTransport session. Strings are copied into
 * connection-owned storage during the call. The CONNECT is sent
 * immediately when the peer's SETTINGS already proved WT support, and
 * is otherwise DEFERRED until they arrive; peers without WT support
 * fail the session (NO_WT_SUPPORT) without opening a stream.
 * require_protocol: a 2xx without a WT-Protocol chosen from our offer
 * fails the session (NO_PROTOCOL) instead of establishing.
 */
typedef struct wtq_client_connect_cfg {
    const char *authority;      /* required */
    const char *path;           /* required */
    const char *origin;         /* optional (NULL = absent) */
    const char *const *protocols;
    size_t protocol_count;      /* <= WTQ_CONN_MAX_OFFERED */
    bool require_protocol;
    /* wtq_h3_wt_profile_t: 0 = current (draft-16), 1 = D13/14 compat.
     * Latched before SETTINGS are emitted; a compat request after the
     * client has already started (SETTINGS out) is WTQ_ERR_STATE. */
    int webtransport_profile;
} wtq_client_connect_cfg_t;

wtq_result_t wtq_conn_client_connect(wtq_conn_t *conn,
                                     const wtq_client_connect_cfg_t *cfg);

/*
 * Server: the accept policy for incoming CONNECTs (copied; call before
 * the request arrives). Exact path match; the response selects the
 * first client-offered protocol present in the path's list;
 * require_protocol rejects (400) when there is no overlap. Unknown
 * paths get a 404. One WT session per connection: a second valid
 * CONNECT is reset/stopped with H3_REQUEST_REJECTED and never becomes
 * a session.
 */
typedef struct wtq_server_path_cfg {
    const char *path;
    const char *const *protocols;
    size_t protocol_count;      /* <= WTQ_CONN_MAX_OFFERED */
    bool require_protocol;
} wtq_server_path_cfg_t;

wtq_result_t wtq_conn_server_set_paths(wtq_conn_t *conn,
                                       const wtq_server_path_cfg_t *paths,
                                       size_t count);

/*
 * Peer opened a bidirectional stream. Classification is deferred to
 * the first bytes: a 0x41 WT association preamble joins the session
 * (both perspectives — WT is how a server opens bidi streams at all);
 * anything else is a request stream on the server and
 * H3_STREAM_CREATION_ERROR on the client (RFC 9114 s6.1: H3 itself
 * never negotiates server-initiated bidi).
 */
WTQ_SPI wtq_result_t wtq_conn_on_peer_bidi_opened(wtq_conn_t *conn,
                                          wtq_dstream_t *ds, uint64_t id,
                                          wtq_estream_t **ectx_out);

/* --- session runtime (established sessions) ---------------------------- */

/*
 * Close the WT session: WT_CLOSE_SESSION capsule (code + reason,
 * reason_len <= 1024 -> WTQ_ERR_TOO_LARGE) in a DATA frame, then FIN,
 * on the CONNECT stream (draft-15 s6). Fires on_session_closed
 * (clean=true) before returning and tears down associated WT streams
 * with WT_SESSION_GONE. WTQ_ERR_STATE unless ESTABLISHED/DRAINING.
 */
wtq_result_t wtq_conn_session_close(wtq_conn_t *conn, uint32_t code,
                                    const uint8_t *reason,
                                    size_t reason_len);

/* Send WT_DRAIN_SESSION (graceful-shutdown request). The local session
 * state does not change; traffic continues (draft-15 s4.7). */
wtq_result_t wtq_conn_session_drain(wtq_conn_t *conn);

/*
 * Open a local WT stream on the established session. The engine sends
 * the association preamble before returning; *es_out is the handle for
 * wtq_conn_wt_send/reset/stop. WTQ_ERR_STATE unless
 * ESTABLISHED/DRAINING; WTQ_ERR_STREAM_LIMIT when the stream pool or
 * the transport's credit is exhausted.
 */
wtq_result_t wtq_conn_wt_open_uni(wtq_conn_t *conn, wtq_estream_t **es_out);
wtq_result_t wtq_conn_wt_open_bidi(wtq_conn_t *conn,
                                   wtq_estream_t **es_out);

/*
 * Gather send on a WT stream (send_gather op contract: span data
 * borrowed until the on_wt_send_complete for this cookie; a non-OK
 * return means no completion will fire and the caller keeps ownership
 * immediately). WTQ_ERR_STATE on a receive-only stream (peer uni) or
 * when the driver lacks send_gather; WTQ_ERR_CLOSED after the session
 * terminated.
 */
wtq_result_t wtq_conn_wt_send(wtq_conn_t *conn, wtq_estream_t *es,
                              const wtq_span_t *spans, size_t count,
                              bool fin, void *cookie);

/* Reset the send side / stop the receive side of a WT stream with a
 * 32-bit WT application error (mapped to the wire per s4.4). Each
 * direction closes exactly once — reset (like send fin=true) closes
 * the send side and later sends return WTQ_ERR_STATE; the estream is
 * released when its last direction is torn down. */
/*
 * General half-stream shutdown on a WT stream. WHOLE_STREAM aborts every
 * still-open half with one code (baseline everywhere). EXACT_HALVES on a
 * FULLY-OPEN bidi requires the matching WTQ_DCAP_SHUT_* capability and
 * returns WTQ_ERR_UNSUPPORTED — decided before any effect, zero state
 * change — when the backend lacks it; a single half that is the stream's
 * only remaining open half is normalized to WHOLE_STREAM (baseline).
 * Split codes (both halves, different codes) require
 * WTQ_DCAP_SHUT_SPLIT_CODES. Codes here are raw H3/WT wire codes.
 * A backend runtime failure after acceptance fails the connection.
 */
wtq_result_t wtq_conn_wt_shutdown(wtq_conn_t *conn, wtq_estream_t *es,
                                  const wtq_shutdown_t *req);

/*
 * Abort the stream in both directions with one APPLICATION error code
 * (mapped to the WT wire space) — the portable whole-stream teardown,
 * exact on every backend.
 */
wtq_result_t wtq_conn_wt_abort(wtq_conn_t *conn, wtq_estream_t *es,
                                uint32_t app_code);

wtq_result_t wtq_conn_wt_reset(wtq_conn_t *conn, wtq_estream_t *es,
                               uint32_t app_code);
wtq_result_t wtq_conn_wt_stop(wtq_conn_t *conn, wtq_estream_t *es,
                              uint32_t app_code);

/*
 * Pause/resume delivery on a WT stream's receive side (recv_enable op
 * passthrough — the engine keeps no pause state and keeps consuming
 * whatever is still delivered). WTQ_ERR_STATE on a send-only or
 * already-finished receive side; WTQ_ERR_UNSUPPORTED when the backend
 * has no recv_enable op; WTQ_ERR_CLOSED after connection close.
 */
wtq_result_t wtq_conn_wt_recv_enable(wtq_conn_t *conn, wtq_estream_t *es,
                                     bool enabled);

/*
 * Reject an ASSOCIATED WT stream that the layer above the engine cannot
 * hold (e.g. the API adapter's handle pool is exhausted). Resets the
 * send side and stops the receive side with the exact WebTransport
 * codepoint WTQ_WT_BUFFERED_STREAM_REJECTED — never an application
 * error mapped through wtq_app_error_to_h3(), because no application
 * ever owned this stream. The estream becomes a drain tombstone: bytes
 * already queued in the same receive event are absorbed rather than
 * delivered, and the slot is released once the peer's FIN/RESET answers.
 * Idempotent; a no-op on a non-WT or already-dead stream.
 *
 * Internal to libwtquic (the API adapter calls it); like the other
 * wtq_conn_wt_* operations it is NOT part of the backend seam, so it
 * carries no WTQ_SPI and is never exported.
 */
void wtq_conn_wt_reject(wtq_conn_t *conn, wtq_estream_t *es);

/* Per-stream app context (valid while the estream is live). */
void wtq_estream_set_user(wtq_estream_t *es, void *user);
void *wtq_estream_get_user(const wtq_estream_t *es);
/* The stream's QUIC stream id. */
uint64_t wtq_estream_id(const wtq_estream_t *es);

/* Datagrams (RFC 9297 HTTP Datagrams: quarter-stream-id varint + raw
 * WT payload; the quarter stream id is the session's CONNECT stream id
 * divided by 4). */

#define WTQ_DGRAM_MAX_SPANS 8

/*
 * Send a WT datagram: the engine prepends the session's association
 * prefix and hands prefix+payload to the dgram_send op (borrow-during-
 * call). count <= WTQ_DGRAM_MAX_SPANS. WTQ_ERR_STATE before
 * establishment; WTQ_ERR_CLOSED after termination (draft-15 s6: MUST
 * NOT send after close); WTQ_ERR_DGRAM_DISABLED when the backend lacks
 * datagram ops or the transport reports no capacity; WTQ_ERR_TOO_LARGE
 * when the payload exceeds wtq_conn_dgram_max_size().
 */
wtq_result_t wtq_conn_dgram_send(wtq_conn_t *conn, const wtq_span_t *spans,
                                 size_t count);

/*
 * Largest WT datagram payload currently sendable: the transport's max
 * QUIC datagram payload minus the encoded association prefix. Also 0
 * when the session is not active or datagrams are unavailable — but a
 * 0 on an active session can equally mean "exactly the prefix fits",
 * where the empty WT datagram (dgram_send with count 0) still sends.
 * Distinguish availability with the send call's WTQ_ERR_DGRAM_DISABLED.
 */
size_t wtq_conn_dgram_max_size(const wtq_conn_t *conn);

/* Datagrams dropped on receive (unknown/closed/not-yet-established
 * session — draft-15 s4.6 requires only a buffering LIMIT; wtquic
 * buffers zero and counts the drops). */
uint64_t wtq_conn_dgrams_dropped(const wtq_conn_t *conn);

/* Backend inputs for the WT data path. */

/*
 * One received QUIC datagram (a complete HTTP/3 datagram payload).
 * Malformed association prefix (payload too short to parse the
 * quarter-stream-id varint) closes the connection with
 * H3_DATAGRAM_ERROR per RFC 9297 s2.1; datagrams for any session
 * other than the active one are counted and dropped.
 */
WTQ_SPI wtq_result_t wtq_conn_on_datagram(wtq_conn_t *conn,
                                          const uint8_t *data, size_t len,
                                          uint64_t now_us);

/* A send_gather completion. Forwarded to on_wt_send_complete even
 * after connection teardown (cookie release must reach the app). */
/*
 * Backend -> engine: the native id for a locally-opened stream whose
 * open_* reported WTQ_STREAM_ID_UNKNOWN. Session input: same
 * serialization domain as every other wtq_conn_* input, never from
 * inside a driver op.
 *
 * DELIVERY IS KEYED THROUGH THE BACKEND STREAM's CURRENT ds->ectx at the
 * moment the transport reports the id — exactly like on_stream_bytes: if
 * ectx is NULL (the stream detached; the engine slot may already be
 * REUSED for a different stream) the backend DROPS the report. An
 * estream pointer cached at open time MUST NOT be used for delivery.
 *
 * The engine validates the report (pending state, varint range, local
 * initiator + direction bits, uniqueness against KNOWN ids only — id 0
 * is valid) and treats any violation as a backend defect:
 * WTQ_H3_INTERNAL_ERROR connection failure. Ordering: when the id
 * becomes available it must be reported before the first ordinary
 * stream-scoped delivery for the stream; send completions
 * (cookie-scoped) and terminal failure are permitted while the id is
 * still pending.
 */
WTQ_SPI void wtq_conn_on_stream_native_id(wtq_conn_t *conn,
                                          wtq_estream_t *es,
                                          uint64_t native_id);

WTQ_SPI void wtq_conn_on_send_complete(wtq_conn_t *conn, void *cookie,
                                       bool canceled);

/* Peer STOP_SENDING observed on a stream we write to. */
WTQ_SPI wtq_result_t wtq_conn_on_stop_sending(wtq_conn_t *conn, wtq_estream_t *es,
                                      uint64_t quic_err, uint64_t now_us);

/* A WT stream that refused a send with WOULD_BLOCK became writable
 * (budget released / buffering advice grew). Edge semantics are the
 * BACKEND's: it calls this once per blocked-to-writable transition.
 * Ignored for non-WT streams and closed connections. */
WTQ_SPI void wtq_conn_on_stream_writable(wtq_conn_t *conn,
                                         wtq_estream_t *es);

/* --- queries ---------------------------------------------------------- */

bool wtq_conn_session_established(const wtq_conn_t *conn);
WTQ_SPI wtq_session_state_t wtq_conn_session_state(const wtq_conn_t *conn);
/* The session id (== CONNECT stream id) once established. */
uint64_t wtq_conn_session_id(const wtq_conn_t *conn);
/* Negotiated subprotocol ("" when none); borrowed until destroy. */
const char *wtq_conn_selected_protocol(const wtq_conn_t *conn,
                                       size_t *len_out);
/* Server: the accepted request's path/authority (borrowed). */
const char *wtq_conn_request_path(const wtq_conn_t *conn,
                                  size_t *len_out);
const char *wtq_conn_request_authority(const wtq_conn_t *conn,
                                       size_t *len_out);

bool wtq_conn_peer_settings_received(const wtq_conn_t *conn);
bool wtq_conn_peer_supports_wt(const wtq_conn_t *conn);
const wtq_h3_settings_t *wtq_conn_peer_settings(const wtq_conn_t *conn);
WTQ_SPI bool wtq_conn_is_closed(const wtq_conn_t *conn);
WTQ_SPI uint64_t wtq_conn_close_code(const wtq_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_ENGINE_WT_DRIVER_H */
