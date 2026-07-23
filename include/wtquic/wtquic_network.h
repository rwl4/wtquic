#ifndef WTQ_WTQUIC_NETWORK_H
#define WTQ_WTQUIC_NETWORK_H

/*
 * wtquic Network.framework backend — public managed lifecycle.
 *
 * APPLE ONLY. Requires macOS 13.0 / iOS 16.0 or later (QUIC multiplex
 * connection groups). This header is deliberately free of any
 * Network.framework or libdispatch type: the backend creates and OWNS
 * one serial dispatch queue per connection — the connection's
 * SERIALIZATION DOMAIN — and no caller-supplied queue is accepted.
 * Link against the wtquic-network library (CMake target wtq::network);
 * it is not pulled in by the core umbrella <wtquic/wtquic.h>.
 *
 * DOMAIN MEMBERSHIP
 *   You are on a connection's domain exactly when (a) inside any wtquic
 *   session/stream callback delivered by this backend, or (b) inside a
 *   function submitted via wtq_nw_conn_post(). Every wtq_session_* /
 *   wtq_stream_* call for this connection (including add_ref/release
 *   and the queries) must happen on its domain; there is deliberately
 *   NO synchronous run-on-domain helper and NO blocking stop.
 *
 * SESSION OWNERSHIP
 *   The backend owns its wtq_session_t. Callbacks receive it as usual;
 *   posted functions may borrow it via wtq_nw_conn_session() (below).
 *   A caller who retains the session with wtq_session_add_ref must
 *   still confine every use (and the final release) to the domain —
 *   the session is never a cross-thread entry point. CLEANUP
 *   DEADLINE: once stop_begin has latched, the only remaining
 *   on-domain opportunities are the already-accepted posts and the
 *   session's own callbacks, ending with on_stopped — release every
 *   retained session/stream handle there AT THE LATEST.
 */

#include <wtquic/error.h>
#include <wtquic/session.h>
#include <wtquic/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One managed connection: the public handle over the backend's
 * internal transport root. Reference-counted (create returns one
 * reference; retain/release from any thread). After stop completes the
 * handle is DEAD-BUT-VALID until the final release: posts are
 * rejected, queries stay safe, release is legal from any thread.
 */
typedef struct wtq_nw_conn wtq_nw_conn_t;

/*
 * Creation config. Use WTQ_NW_CONN_CFG_INIT / wtq_nw_conn_cfg_init;
 * struct_size versions the struct: the v1 prefix (through `user`) is
 * required, the fields after it are optional tails read only when
 * their complete field fits (absent tails default: alloc = default
 * allocator, on_stopped/stopped_ctx = none), and a larger future
 * struct is accepted with its unknown tail ignored.
 *
 *   - server_name / port: where to dial; server_name is also the TLS
 *     SNI and certificate-validation name. Certificate validation uses
 *     SYSTEM TRUST by default.
 *   - insecure_skip_verify: accept any server certificate. Loopback
 *     and development ONLY — never ship it enabled.
 *   - connect: the WebTransport request (authority/path/subprotocols).
 *     Required; copied where the API contract says so.
 *   - events / user: the session's event table and context. Required.
 *     Events fire ON THE DOMAIN.
 *   - alloc: optional allocator (NULL = default) for the API
 *     SESSION/STREAM objects only. The backend's own references to
 *     them are released before on_stopped begins; handles the
 *     application retained are the application's responsibility
 *     (release them by the end of on_stopped at the latest — the
 *     cleanup deadline above), after which the allocator context may
 *     safely die. The managed connection handle itself, post nodes,
 *     and every backend-internal object live on the backend's own
 *     allocator and NEVER touch this one — the free that follows
 *     on_stopped's return, a rejected post, and transport-retirement
 *     stragglers are all allocator-safe however early the context
 *     dies. Used from the domain and from creation/teardown; a custom
 *     allocator must tolerate the calling thread varying across
 *     those.
 *   - on_stopped / stopped_ctx: optional terminal notification. Runs
 *     on the domain, exactly once, after rundown completes — the FINAL
 *     application-visible block for the connection. It may release the
 *     caller's last reference (the backend holds its own through the
 *     callback's return). Actor/executor hosts await this instead of
 *     ever blocking.
 */
typedef struct wtq_nw_conn_cfg {
    uint32_t struct_size;
    const char *server_name;
    uint16_t port;
    bool insecure_skip_verify;
    const wtq_connect_config_t *connect;
    const wtq_session_events_t *events;
    void *user;
    const wtq_alloc_t *alloc;
    void (*on_stopped)(void *stopped_ctx);
    void *stopped_ctx;
    /*
     * Optional doorbell (versioned tail): a PREALLOCATED, coalescing
     * wake. When configured, wtq_nw_conn_doorbell_ring() delivers
     * on_doorbell(doorbell_ctx) on the domain — rings between
     * deliveries collapse into ONE invocation, and a ring during an
     * invocation re-arms exactly one more (level-retained, never
     * lost while the connection lives). The source is created and
     * activated before anything can start transport callbacks, so
     * the earliest published handle can already ring it. It never
     * fires during or after on_stopped.
     */
    void (*on_doorbell)(void *ctx);
    void *doorbell_ctx;
} wtq_nw_conn_cfg_t;

#define WTQ_NW_CONN_CFG_INIT                                        \
    { (uint32_t)sizeof(wtq_nw_conn_cfg_t), NULL, 0, false, NULL,    \
      NULL, NULL, NULL, NULL, NULL, NULL, NULL }

WTQ_API void wtq_nw_conn_cfg_init(wtq_nw_conn_cfg_t *cfg);

/*
 * Dial and request a WebTransport session. Returns as soon as the
 * attempt is underway; the outcome arrives via the session events
 * (on_established / on_refused / on_failed) on the domain. On success
 * *conn_out carries one reference. On failure *conn_out is NULL and
 * everything acquired is released.
 *
 * ORDERING: on success, *conn_out is published BEFORE anything that
 * can schedule a callback — callbacks may run before this call
 * returns, but never before the output handle is visible, so a
 * callback acting through the owner's handle variable (post,
 * stop_begin, is_on_domain) always finds it set. An internal
 * construction reference keeps the handle alive across the start even
 * if such a callback stops and the owner releases immediately.
 *
 * THREADING (start): Network.framework reliably delivers inbound
 * streams that are pending at the connection group's READY only when
 * nw_connection_group_start() runs on the MAIN thread (a measured
 * platform limitation; the group's create thread and a serviced
 * non-main run loop do NOT change it). Therefore:
 *   - A caller ALREADY on the process main thread starts the group
 *     directly, before this call returns.
 *   - A caller OFF the main thread has the start SCHEDULED as one
 *     asynchronous block on the MAIN dispatch queue; create() still
 *     returns as soon as the attempt is scheduled, and *conn_out is
 *     published immediately (usable at once for post()/stop_begin()/
 *     is_on_domain(); join() blocks until the stop converges, as always,
 *     which for an off-main creator requires the scheduled start to run
 *     first). Such a caller MUST have a serviced main dispatch queue: if
 *     the process main thread never runs the main queue, the group never
 *     starts (and an off-main join() never returns). stop_begin() before
 *     the queued start is safe — it latches CLOSED and the stop is
 *     ordered after the start (after any accepted post()); it never
 *     cancels an unstarted group.
 * No synchronous main-queue hop is performed, so an off-main caller may
 * block on join()/a condvar without self-deadlock, provided the process
 * MAIN THREAD services the main dispatch queue.
 */
WTQ_API wtq_result_t wtq_nw_conn_create(const wtq_nw_conn_cfg_t *cfg,
                                        wtq_nw_conn_t **conn_out);

/*
 * Ring the configured doorbell: NON-ALLOCATING and INFALLIBLE, from
 * any thread including the domain. Delivery is coalesced (see
 * cfg.on_doorbell). Once stop_begin() wins the acceptance latch no
 * delivery is promised — a racing ring may be absorbed by teardown —
 * and NULL, unconfigured, stopped, and post-join handles are harmless
 * no-ops while the caller still holds a valid reference.
 */
WTQ_API void wtq_nw_conn_doorbell_ring(wtq_nw_conn_t *c);

/*
 * Schedule the SAME configured doorbell (cfg.on_doorbell) to ring once
 * after delay_us microseconds, without allocating a callback closure or
 * a timer thread — the timer is preallocated with the doorbell. This
 * arms on_doorbell on the domain; it does NOT itself call any wtquic
 * session service, and it infers no application deadline. What runs
 * after the delay is exactly the immediate doorbell delivery.
 *
 * There is exactly ONE delayed slot per connection. A successful call
 * REPLACES any previous delayed arm (only the latest governs delivery);
 * wtq_nw_conn_doorbell_cancel_after() clears it. The ordinary
 * wtq_nw_conn_doorbell_ring() is independent — it neither arms nor
 * cancels the delayed slot.
 *
 * Returns:
 *   WTQ_ERR_INVALID_ARG  conn is NULL;
 *   WTQ_ERR_CLOSED       stop_begin has latched (or a dead-but-valid
 *                        post-join handle) — no arm is made;
 *   WTQ_ERR_UNSUPPORTED  cfg.on_doorbell was not configured;
 *   WTQ_OK               the delayed ring was armed.
 * WTQ_OK means armed, NOT delivered: the arm may still be replaced,
 * canceled, coalesced into the immediate doorbell, or absorbed by
 * teardown before it fires. delay_us == 0 replaces/disarms any pending
 * delayed arm and promotes directly into the immediate doorbell (a
 * deferred delivery on the domain — never an inline on_doorbell call).
 * The delay is measured in host uptime (a suspended system does not
 * consume it); excessive delays are clamped to the largest representable
 * timer value.
 *
 * ALLOCATION: no per-arm wtquic object and no callback closure are
 * created, and no call is made through the configured/backend wtquic
 * allocator — the timer source is preallocated at connection
 * construction. (This makes no claim about libdispatch's own internals.)
 *
 * LIFETIME: legal only while the caller owns a valid, retained
 * wtq_nw_conn_t. A NULL handle returns WTQ_ERR_INVALID_ARG; a released or
 * otherwise stale pointer is invalid (undefined). A retained post-join
 * handle stays safe and returns WTQ_ERR_CLOSED. Nonblocking and callable
 * from any thread, INCLUDING the connection domain (a posted job or the
 * doorbell callback itself). Like the immediate doorbell, the scheduled
 * ring never runs during or after on_stopped.
 */
WTQ_API wtq_result_t wtq_nw_conn_doorbell_ring_after(wtq_nw_conn_t *conn,
                                                     uint64_t delay_us);

/*
 * Cancel a pending delayed doorbell arm (from wtq_nw_conn_doorbell_ring_
 * after). Idempotent: a no-op when nothing is armed, on an unconfigured
 * doorbell, and on a NULL/stopped/post-join handle. It affects ONLY a
 * delayed arm that has not yet been promoted — once the timer has merged
 * the ring into the immediate doorbell, normal doorbell coalescing
 * applies and this cannot retract it. It never touches the immediate
 * wtq_nw_conn_doorbell_ring() path, and it makes no configured/backend
 * allocator call.
 *
 * LIFETIME: like ring_after, legal only while the caller owns a valid,
 * retained handle (NULL is the documented no-op; a released/stale pointer
 * is invalid), from any thread including the domain; a retained post-join
 * handle stays safe.
 */
WTQ_API void wtq_nw_conn_doorbell_cancel_after(wtq_nw_conn_t *conn);

WTQ_API void wtq_nw_conn_retain(wtq_nw_conn_t *c);
/*
 * Drop one reference (any thread; over-release is refused, not fatal).
 * FAIL-SAFE MISUSE POLICY: releasing the LAST public reference before
 * wtq_nw_conn_stop_begin() implicitly begins a nonblocking stop — the
 * transport runs down internally exactly as if stop_begin had been
 * called (on_stopped still fires), and the handle memory is reclaimed
 * once that completes. Prefer the explicit stop_begin (+ join or
 * on_stopped) sequence; the implicit path exists so a dropped handle
 * can never leak a live transport or dangle a callback.
 */
WTQ_API void wtq_nw_conn_release(wtq_nw_conn_t *c);

/*
 * The ONLY cross-thread entry:
 *   WTQ_OK          fn WILL run exactly once on the domain, even if
 *                   stop begins first (it may observe a dead-but-valid
 *                   session). Acceptance retains the connection handle
 *                   until fn returns.
 *   WTQ_ERR_CLOSED  rejected synchronously (stop already requested);
 *                   fn will NEVER run.
 *   WTQ_ERR_NOMEM   nothing was queued; fn will never run.
 * Legal only while the caller holds its own reference. Ordering:
 * submission order (serialized across threads), interleaved with
 * transport callbacks at block granularity; post from ON the domain
 * enqueues behind the current block — never inline.
 */
WTQ_API wtq_result_t wtq_nw_conn_post(wtq_nw_conn_t *c,
                                      void (*fn)(void *ctx), void *ctx);

WTQ_API bool wtq_nw_conn_is_on_domain(const wtq_nw_conn_t *c);

/*
 * Borrowed session access for posted functions: returns the
 * connection's session ONLY when called on the domain (NULL off-domain
 * — the session is not a cross-thread entry point), and NULL once the
 * connection reached its terminal (dead-but-valid phase). The borrow
 * is valid for the current block only; retain on the domain to keep it
 * (and release on the domain too).
 */
WTQ_API wtq_session_t *wtq_nw_conn_session(wtq_nw_conn_t *c);

/*
 * LIFECYCLE IS SPLIT (a blocking stop callable from the domain would
 * wait on the very queue executing it):
 *
 * wtq_nw_conn_stop_begin() — NONBLOCKING, callable from ANY thread
 *   including the domain itself (callbacks and posted functions).
 *   Latches CLOSED before returning (subsequent posts are rejected),
 *   then asynchronously: every previously accepted post runs, streams
 *   tear down, the transport is cancelled, and on_stopped is delivered
 *   once RUNDOWN IS COMPLETE.
 *
 *   RUNDOWN COMPLETION := the transport reached its terminal state AND
 *   every accepted send is APP_COMPLETED (real or synthetic, exactly
 *   once). It deliberately does NOT wait for every transport-side
 *   completion block to be disposed: an anomalous never-disposed block
 *   must not hang application shutdown. Such stragglers keep only the
 *   backend's INTERNAL root (records + queue) alive until their
 *   disposal arrives; they can never delay on_stopped/join and never
 *   make the released public handle unsafe.
 *   Idempotent; returns whether THIS call initiated the stop.
 *
 * wtq_nw_conn_join() — BLOCKING wait for rundown completion.
 *   OFF-DOMAIN ONLY: called on the domain it returns WTQ_ERR_STATE
 *   immediately (it would deadlock by definition). Multiple joiners
 *   are fine. After join (or after on_stopped), the connection is
 *   dead-but-valid.
 */
WTQ_API bool wtq_nw_conn_stop_begin(wtq_nw_conn_t *c);
WTQ_API wtq_result_t wtq_nw_conn_join(wtq_nw_conn_t *c);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_WTQUIC_NETWORK_H */
