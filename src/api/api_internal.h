#ifndef WTQ_API_INTERNAL_H
#define WTQ_API_INTERNAL_H

/*
 * Constructor seam between the public session/stream API and the
 * engine — INTERNAL, never installed. Backends (and the test rails)
 * create sessions here; applications only ever see the backend entry
 * points plus the public wtq_session_* / wtq_stream_* surface.
 *
 * The API layer is a thin adapter: it owns the wtq_conn_t, registers
 * itself as the engine's callback sink, and forwards events to the
 * app's wtq_session_events_t after maintaining the public handle
 * lifetime rules (refcounts, per-direction stream state, exactly-once
 * terminal events).
 *
 * ALLOCATIONS: exactly two per session, both at create — the
 * wtq_session (which embeds the stream-handle pool) and the engine's
 * wtq_conn. Nothing on any data path.
 */

#include <wtquic/session.h>
#include <wtquic/stream.h>

#include "../engine/wt_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wtq_api_session_cfg {
    const wtq_alloc_t *alloc;        /* required; copied */
    wtq_perspective_t perspective;
    const wtq_session_events_t *events; /* struct_size-checked; copied */
    void *user;                      /* handed to every event */
    wtq_driver_t *drv;               /* backend connection context */
    const wtq_driver_ops_t *ops;     /* backend vtable */
} wtq_api_session_cfg_t;

/* Create a session (refcount 1, owned by the caller) over a driver.
 * No I/O happens until wtq_api_session_start. */
WTQ_SPI wtq_result_t wtq_api_session_create(const wtq_api_session_cfg_t *cfg,
                                    wtq_session_t **out);

/* Transport ready: brings up the engine's control plane. ONE-SHOT — a
 * session gets exactly one start attempt. CLIENTS open their control/
 * QPACK streams here and a failure returns the driver's error; SERVERS
 * defer those opens to the peer's first inbound event (see
 * wtq_conn_start), so a deferred failure surfaces there as a
 * connection-fatal H3_INTERNAL_ERROR via the session's terminal
 * callbacks, never as a start return. Either way the attempt leaves
 * wire-visible state that cannot be undone: release the session and
 * build a new connection rather than retrying. Every later call
 * returns WTQ_ERR_STATE and runs no driver operation. */
WTQ_SPI wtq_result_t wtq_api_session_start(wtq_session_t *session,
                                   uint64_t now_us);

/* Client: request the session (deferred internally until the peer
 * proves WebTransport support). */
WTQ_SPI wtq_result_t wtq_api_session_connect(wtq_session_t *session,
                                     const wtq_connect_config_t *cfg);

/* Server: register the accept policy (max 4 paths). */
WTQ_SPI wtq_result_t wtq_api_session_serve(wtq_session_t *session,
                                   const wtq_serve_config_t *paths,
                                   size_t count);

/* The underlying engine connection — for backends to feed transport
 * events into (wtq_conn_on_*). */
WTQ_SPI wtq_conn_t *wtq_api_session_conn(wtq_session_t *session);

/*
 * REQUIRED bracket around every batch of engine inputs the backend
 * delivers: enter before the first wtq_conn_on_* call, leave after the
 * last one returns. The app may release its final session reference
 * from inside any callback; the bracket is what defers the destroy
 * past the ENGINE stack frames the callbacks fired from. leave()
 * returns true when it performed the deferred destroy — the session
 * (and its wtq_conn) are gone; the backend must stop using both.
 */
WTQ_SPI void wtq_api_session_enter(wtq_session_t *session);
WTQ_SPI bool wtq_api_session_leave(wtq_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_API_INTERNAL_H */
