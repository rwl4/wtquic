/*
 * Raw MsQuic observer peer for Network.framework tests and diagnostics.
 *
 * A bare QUIC server that reports what actually crosses the wire, so the
 * Network.framework client-side API calls are validated by peer
 * observation rather than by local getter readback. (Apple's stream and
 * connection application-error GETTERS are receive-side; the SETTERS are
 * send-side. Only a peer can confirm transmission.)
 *
 * It speaks no HTTP/3 and no WebTransport: it accepts any stream, drains it,
 * and records QUIC-level events. A peer-side protocol rejection therefore can
 * never be mistaken for an Apple API property.
 *
 * Design rules:
 *   - Every field written from an MsQuic callback is guarded by `mu`.
 *   - Observations are per-stream records keyed by the exact QUIC stream id.
 *     There is no global "last event" state to race on.
 *   - Callers block on a condition variable with a bounded deadline. No
 *     verdict is ever derived from a sleep.
 *   - Stream handles are NEVER closed from a callback. SHUTDOWN_COMPLETE only
 *     marks the record terminal. raw_peer_stop() shuts the connection down,
 *     WAITS for its SHUTDOWN_COMPLETE, and only then closes each HQUIC exactly
 *     once. That removes the lookup-then-use race: a handle found under `mu`
 *     cannot be freed while it is being passed to MsQuic.
 *   - Markers are length-delimited and reassembled across RECEIVE fragments.
 *     Duplicate markers are a hard error.
 *   - Stream-table overflow is a hard, visible failure, never a silent drop.
 *
 * Public MsQuic APIs only. Nothing here is installed or exported.
 */
#ifndef WTQ_TEST_NW_RAW_PEER_H
#define WTQ_TEST_NW_RAW_PEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct raw_peer raw_peer_t;

#define RAW_PEER_NO_CODE UINT64_MAX

/*
 * Marker wire format: the payload, then '\n'. The peer reassembles RECEIVE
 * fragments until the terminator arrives, so a marker split across events
 * still matches exactly.
 */
#define RAW_PEER_MARKER_TERM '\n'

typedef enum {
    RAW_PEER_CLOSE_NONE = 0,
    RAW_PEER_CLOSE_BY_APP,       /* CONNECTION_CLOSE, application frame */
    RAW_PEER_CLOSE_BY_TRANSPORT, /* CONNECTION_CLOSE, transport frame   */
} raw_peer_close_kind_t;

/* What the peer saw on one stream, once that stream is terminal. */
typedef struct {
    bool terminal;   /* MsQuic reported SHUTDOWN_COMPLETE for this stream */
    bool saw_fin;
    bool saw_reset;
    uint64_t reset_code;
    bool saw_stop;
    uint64_t stop_code;
} raw_peer_stream_events_t;

raw_peer_t *raw_peer_start(const char *cert_file, const char *key_file,
                           uint16_t *port_out, void (*log)(const char *));
/*
 * Tear down. Shuts the connection down, WAITS (bounded) for its
 * SHUTDOWN_COMPLETE, then closes every stream handle exactly once, then the
 * connection, configuration and registration in that required order.
 * Returns false if the connection never reached SHUTDOWN_COMPLETE, in which
 * case handles are deliberately left open rather than closed under MsQuic.
 */
bool raw_peer_stop(raw_peer_t *p);

/* Wait until a stream whose reassembled marker equals `marker` is seen. */
bool raw_peer_wait_marker(raw_peer_t *p, const char *marker, uint64_t *id_out,
                          int timeout_ms);

/* Per-stream actions, keyed by exact id. */
bool raw_peer_reset_stream(raw_peer_t *p, uint64_t id, uint64_t code);
bool raw_peer_stop_sending(raw_peer_t *p, uint64_t id, uint64_t code);
bool raw_peer_send_on_stream(raw_peer_t *p, uint64_t id, const void *buf,
                             size_t len, bool fin);

/* Open a peer-initiated (server) stream. Its id is returned immediately. */
bool raw_peer_open_stream(raw_peer_t *p, bool unidirectional, uint64_t *id_out,
                          int timeout_ms);

/*
 * Wait until the exact stream is TERMINAL, then return everything the peer
 * observed on it. This is how expected-absence is asserted: no arbitrary
 * window, just "the stream finished and no RESET was ever seen".
 */
bool raw_peer_wait_stream_terminal(raw_peer_t *p, uint64_t id,
                                   raw_peer_stream_events_t *out,
                                   int timeout_ms);

/* Snapshot without waiting for terminal (for events that must arrive first). */
bool raw_peer_wait_reset(raw_peer_t *p, uint64_t id, uint64_t *code_out,
                         int timeout_ms);
bool raw_peer_wait_stop(raw_peer_t *p, uint64_t id, uint64_t *code_out,
                        int timeout_ms);

/* Datagrams. Send blocks for a terminal DATAGRAM_SEND_STATE_CHANGED. */
bool raw_peer_send_datagram(raw_peer_t *p, const void *buf, size_t len,
                            int timeout_ms);
bool raw_peer_wait_datagram(raw_peer_t *p, const char *payload, int timeout_ms);

bool raw_peer_wait_close(raw_peer_t *p, raw_peer_close_kind_t *kind_out,
                         uint64_t *code_out, int timeout_ms);

/* Hard failures: table overflow, or two streams claiming the same marker. */
bool raw_peer_failed(const raw_peer_t *p, const char **why);

#endif /* WTQ_TEST_NW_RAW_PEER_H */
