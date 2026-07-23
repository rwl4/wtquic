#ifndef WTQ_STREAM_H
#define WTQ_STREAM_H

/*
 * WebTransport stream.
 *
 * Stream handles come from two places: wtq_session_open_uni/_bidi
 * (local) and on_stream_opened (peer). Either way the library holds
 * one reference from creation and drops it when the stream's terminal
 * event — on_stream_closed — returns. An application that never calls
 * wtq_stream_add_ref therefore gets the simple model: the handle is
 * valid from open/on_stream_opened until on_stream_closed returns,
 * with zero extra calls. Retaining past that needs add_ref; a retained
 * handle after terminal is dead-but-valid (operations return
 * WTQ_ERR_CLOSED, queries keep working) until the final release.
 *
 * DIRECTIONS close independently:
 *   outgoing: wtq_stream_send with WTQ_SEND_FIN, or wtq_stream_reset.
 *   incoming: peer fin (on_stream_data fin=true), peer reset
 *             (on_stream_reset), or wtq_stream_stop_sending.
 * When the last open direction closes, on_stream_closed fires. A
 * unidirectional stream has only its one direction.
 *
 * SEND OWNERSHIP: wtq_stream_send borrows the span DATA until the
 * matching on_send_complete(send_ctx) — exactly one per accepted send,
 * even across teardown (canceled=true). The span ARRAY itself is
 * borrowed only for the duration of the call. A send that returns an
 * error was not accepted: no completion will fire and the buffers are
 * immediately the caller's again.
 */

#include "error.h"
#include "session.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- lifetime ----------------------------------------------------------- */

WTQ_API void wtq_stream_add_ref(wtq_stream_t *stream);
WTQ_API void wtq_stream_release(wtq_stream_t *stream);

/* --- sending -------------------------------------------------------------- */

#define WTQ_SEND_FIN 0x1u /* finish the outgoing direction after this */

/*
 * The documented span-count contract for one gather send: a count
 * beyond this is refused (WTQ_ERR_INVALID_ARG) BEFORE the span array
 * is read, so a corrupt count can never drive a wild traversal. The
 * bound is deliberately generous — a gather assembles one message's
 * header/payload pieces, not a scatter list of an entire buffer pool.
 */
#define WTQ_STREAM_MAX_SPANS 4096u

/*
 * Gather send. All-or-nothing: WTQ_OK means every span was accepted
 * and exactly one on_send_complete(send_ctx) will follow;
 * WTQ_ERR_WOULD_BLOCK means nothing was accepted (retry later);
 * WTQ_ERR_STATE on a receive-only stream or an already-finished/reset
 * outgoing direction; WTQ_ERR_CLOSED after stream/session end.
 * WTQ_ERR_INVALID_ARG when count exceeds WTQ_STREAM_MAX_SPANS or any
 * span has len > 0 with data == NULL; WTQ_ERR_TOO_LARGE when the
 * aggregate length cannot be represented.
 */
WTQ_API wtq_result_t wtq_stream_send(wtq_stream_t *stream,
                                     const wtq_span_t *spans, size_t count,
                                     uint32_t flags, void *send_ctx);

/*
 * Abort the stream in BOTH directions with one application error code —
 * the portable whole-stream teardown, exact on every transport backend
 * (on a unidirectional stream it aborts the single existing half). The
 * handle goes terminal once accepted, and every accepted-but-unfinished
 * send on the stream completes canceled (exactly once, as always).
 */
WTQ_API wtq_result_t wtq_stream_abort(wtq_stream_t *stream,
                                      uint32_t app_error);

/* Abruptly end the outgoing direction with an application error code.
 * Pending sends complete canceled.
 *
 * wtq_stream_reset / wtq_stream_stop_sending abort EXACTLY one half.
 * On a FULLY-OPEN bidirectional stream some transports cannot abort a
 * single half independently; there these return WTQ_ERR_UNSUPPORTED with
 * ZERO effect (stream state unchanged) — use wtq_stream_abort or finish
 * the direction normally instead. On unidirectional streams, and on a
 * bidi whose other half is already closed, they are supported on every
 * backend. */
WTQ_API wtq_result_t wtq_stream_reset(wtq_stream_t *stream,
                                      uint32_t app_code);

/* Tell the peer to stop sending on this stream (application error
 * code). Closes the incoming direction locally: no more
 * on_stream_data will fire for it. */
WTQ_API wtq_result_t wtq_stream_stop_sending(wtq_stream_t *stream,
                                             uint32_t app_code);

/*
 * Pause / resume delivery of incoming data on this stream. Pausing
 * stops future on_stream_data events; data already being delivered
 * still arrives (the borrowed-during-callback contract is unchanged).
 * Resume re-opens the tap and delivery continues in order, FIN
 * included.
 *
 * The GUARANTEED, portable effect is delivery suppression: while paused
 * the application sees no further on_stream_data. Whether that also
 * imposes hard transport-level flow-control backpressure on the peer is
 * BACKEND-DEPENDENT — query wtq_stream_receive_pause_mode() to find out.
 * A delivery-only backend keeps consuming, ACKing, and expanding receive
 * credit while paused, so a paused peer is not flow-control-bounded and
 * bytes may accumulate below wtquic (in the transport). A resource-
 * sensitive caller must consult the mode before relying on pause for
 * bounded memory.
 *
 * WTQ_ERR_UNSUPPORTED when the transport backend cannot pause delivery
 * (see WTQ_RECEIVE_PAUSE_UNSUPPORTED); WTQ_ERR_STATE when the incoming
 * direction is already finished; WTQ_ERR_CLOSED after stream/session end.
 */
WTQ_API wtq_result_t wtq_stream_pause_receive(wtq_stream_t *stream);
WTQ_API wtq_result_t wtq_stream_resume_receive(wtq_stream_t *stream);

/*
 * What wtq_stream_pause_receive actually achieves on this stream's
 * backend. A connection-wide, static property of the transport backend; it
 * does not change over a stream's life and stays queryable on a retained
 * handle after the stream has ended (the backend mode is reported for the
 * whole life of the handle, terminal or not). A backend that cannot pause
 * delivery reports WTQ_RECEIVE_PAUSE_UNSUPPORTED; a NULL handle also
 * reports it, for lack of a backend to name.
 */
typedef enum wtq_receive_pause_mode {
    /* Pause cannot suppress delivery at all — do not rely on it. */
    WTQ_RECEIVE_PAUSE_UNSUPPORTED = 0,
    /* Pause suppresses application delivery, but the transport may keep
     * consuming, ACKing, and expanding receive credit while paused: no
     * hard flow-control bound on the peer, bytes may buffer below
     * wtquic. (Apple Network.framework.) */
    WTQ_RECEIVE_PAUSE_DELIVERY_ONLY = 1,
    /* Pause suppresses delivery AND stops transport consumption without
     * extending receive credit, so the peer is eventually blocked by
     * QUIC flow control — real backpressure, nothing buffered by
     * wtquic. */
    WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED = 2,
} wtq_receive_pause_mode_t;

WTQ_API wtq_receive_pause_mode_t
wtq_stream_receive_pause_mode(const wtq_stream_t *stream);

/* --- queries -------------------------------------------------------------- */

/*
 * The stream's native QUIC stream id, or WTQ_STREAM_ID_UNKNOWN while the
 * transport has not yet assigned/reported one. Always known from delivery
 * for peer-initiated streams. For locally-opened streams the id may become
 * known only after wtq_session_open_* returns (transport-dependent); once
 * known it is stable, and the final value stays queryable on a retained
 * handle after the stream closes — including a final value of
 * WTQ_STREAM_ID_UNKNOWN when the transport never reported one. Diagnostic
 * metadata: no wtquic behavior depends on the caller reading it.
 */
WTQ_API uint64_t wtq_stream_id(const wtq_stream_t *stream);
WTQ_API bool wtq_stream_is_bidi(const wtq_stream_t *stream);
WTQ_API bool wtq_stream_is_local(const wtq_stream_t *stream);
WTQ_API wtq_session_t *wtq_stream_session(const wtq_stream_t *stream);

WTQ_API void wtq_stream_set_user(wtq_stream_t *stream, void *user);
WTQ_API void *wtq_stream_get_user(const wtq_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_STREAM_H */
