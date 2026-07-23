#include "api_internal.h"

#include <string.h>

/*
 * The public session/stream API: a thin adapter over the engine.
 *
 * Two allocations per session, both at create: this struct (embedding
 * the stream-handle pool) and the engine's wtq_conn. Data paths
 * allocate nothing.
 *
 * Handle lifetime is refcounted. The session starts at 1 (creator's
 * ref); every live stream slot holds one session ref so a retained
 * stream can never dangle. Stream slots start at 1 (the library's ref,
 * dropped after on_stream_closed returns); slots recycle at refcount
 * 0. Frees are deferred while any callback (or public entry point) is
 * on the stack, so releasing from inside callbacks is always legal.
 *
 * The adapter mirrors each stream's per-direction state (send/recv
 * open) from the same events the engine acts on, and NEVER touches the
 * engine estream after the handle's terminal — the engine may have
 * released or re-used its slot by then.
 */

#define WTQ_API_MAX_STREAMS 16
#define WTQ_API_MAX_PATHS 4

struct wtq_stream {
    uint32_t refs;      /* total slot occupancy; 0 = slot free. Sum of
                           the library baseline, transient internal
                           holds, and app_refs. */
    uint32_t app_refs;  /* app-owned refs (wtq_stream_add_ref); each
                           also pins the session. Only these gate public
                           release — the baseline and internal holds are
                           not the app's to drop. */
    bool alive;         /* pre-terminal: engine linkage valid */
    bool send_open;
    bool recv_open;
    bool bidi;
    bool local;
    uint64_t id;
    wtq_estream_t *es;  /* NULL once terminal */
    wtq_session_t *session;
    void *user;
};

struct wtq_session {
    uint32_t refs;
    wtq_alloc_t alloc;
    wtq_conn_t *conn;
    wtq_session_events_t ev; /* normalized (size-checked) copy */
    void *user;

    int cb_depth;            /* public entries + event adapters */
    bool terminal_fired;     /* exactly-one terminal event guard */
    bool established_seen;
    bool failed;             /* terminal without establishment */

    struct wtq_stream streams[WTQ_API_MAX_STREAMS];
};

/* --- config helpers ------------------------------------------------------ */

void wtq_session_events_init(wtq_session_events_t *events)
{
    if (events != NULL) {
        memset(events, 0, sizeof(*events));
        events->struct_size = (uint32_t)sizeof(*events);
    }
}

/* Frozen v1 shadow of wtq_connect_config_t (through require_subprotocol),
 * INTERNAL to this TU. The bare wtq_connect_config_init writes exactly
 * sizeof this struct; the static-asserts below pin that every v1 field
 * keeps its offset and that the v2 tail (webtransport_profile) begins at
 * or after the end of frozen v1. Never exposed publicly. */
typedef struct wtq_connect_config_v1 {
    uint32_t struct_size;
    const char *authority;
    const char *path;
    const char *origin;
    const char *const *subprotocols;
    size_t subprotocol_count;
    bool require_subprotocol;
} wtq_connect_config_v1_t;

void wtq_connect_config_init_ex(wtq_connect_config_t *cfg, size_t struct_size)
{
    static const wtq_connect_config_t def = WTQ_CONNECT_CONFIG_INIT;
    /* Never write beyond the smaller of the caller's object and the
     * current type — an oversized struct_size (a future larger struct)
     * is accepted but only the current fields are written; the tail is
     * the caller's. def is fully zero-initialised, so the copied prefix
     * is zeroed. (Exactly the MsQuic cfg_init_ex pattern.) */
    size_t n = struct_size < sizeof(def) ? struct_size : sizeof(def);

    if (cfg == NULL)
        return;
    memcpy(cfg, &def, n);
    /* Record what was actually initialised, so a smaller (older) object
     * never claims to carry the profile tail it has no room for. */
    if (n >= sizeof(cfg->struct_size))
        cfg->struct_size = (uint32_t)n;
}

/* ABI-frozen entry: initialises ONLY the v1 prefix (through
 * require_subprotocol), so an old binary that linked this symbol against
 * the smaller struct is never written past its object. New source reaches
 * the current-size path through the header macro (-> _ex with sizeof *cfg). */
#undef wtq_connect_config_init
void wtq_connect_config_init(wtq_connect_config_t *cfg)
{
    wtq_connect_config_init_ex(cfg, sizeof(wtq_connect_config_v1_t));
}

/* Pin the ABI: every frozen v1 field keeps its offset, and the v2 tail
 * begins AT OR AFTER the end of frozen v1 (>=, not ==: alignment padding
 * before the tail is legal) — never inside v1's tail padding, so an old
 * caller's struct_size can never expose uninitialised padding as the
 * profile field. */
_Static_assert(offsetof(wtq_connect_config_t, struct_size) ==
                   offsetof(wtq_connect_config_v1_t, struct_size),
               "connect struct_size offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, authority) ==
                   offsetof(wtq_connect_config_v1_t, authority),
               "connect authority offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, path) ==
                   offsetof(wtq_connect_config_v1_t, path),
               "connect path offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, origin) ==
                   offsetof(wtq_connect_config_v1_t, origin),
               "connect origin offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, subprotocols) ==
                   offsetof(wtq_connect_config_v1_t, subprotocols),
               "connect subprotocols offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, subprotocol_count) ==
                   offsetof(wtq_connect_config_v1_t, subprotocol_count),
               "connect subprotocol_count offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, require_subprotocol) ==
                   offsetof(wtq_connect_config_v1_t, require_subprotocol),
               "connect require_subprotocol offset frozen");
_Static_assert(offsetof(wtq_connect_config_t, webtransport_profile) >=
                   sizeof(wtq_connect_config_v1_t),
               "connect v2 tail must not begin before the end of frozen v1");

void wtq_serve_config_init(wtq_serve_config_t *cfg)
{
    if (cfg != NULL) {
        memset(cfg, 0, sizeof(*cfg));
        cfg->struct_size = (uint32_t)sizeof(*cfg);
    }
}

/* Copy a struct_size-prefixed struct into a full-size zeroed local:
 * fields past the caller's (older) size read as zero/NULL. */
static void cfg_copy(void *dst, size_t dst_size, const void *src,
                     uint32_t src_size)
{
    size_t n = src_size < dst_size ? src_size : dst_size;

    memset(dst, 0, dst_size);
    memcpy(dst, src, n);
}

void wtq_session_events_copy(wtq_session_events_t *dst,
                             const wtq_session_events_t *src)
{
    const uint32_t ss = src->struct_size;
    const size_t full = sizeof(*dst);

    memset(dst, 0, full);
    memcpy(dst, src, ss < full ? ss : full);
    /*
     * Drop any callback the caller's struct_size does not cover WHOLE — a
     * member the size only straddles was byte-copied to a truncated, non-NULL
     * pointer. Each member is gated INDEPENDENTLY on its own offset and size:
     * no assumption that callback pointer types share a size or that members
     * are unpadded. A cleanly shorter (older-ABI) table keeps its complete
     * prefix; every straddled or absent member ends up NULL.
     */
#define WTQ_EV_GATE(m)                                                     \
    do {                                                                   \
        if (!wtq_cfg_has(ss, offsetof(wtq_session_events_t, m),            \
                         sizeof(dst->m)))                                  \
            dst->m = NULL;                                                 \
    } while (0)
    WTQ_EV_GATE(on_established);
    WTQ_EV_GATE(on_refused);
    WTQ_EV_GATE(on_failed);
    WTQ_EV_GATE(on_draining);
    WTQ_EV_GATE(on_closed);
    WTQ_EV_GATE(on_stream_opened);
    WTQ_EV_GATE(on_stream_data);
    WTQ_EV_GATE(on_stream_reset);
    WTQ_EV_GATE(on_stream_stop);
    WTQ_EV_GATE(on_stream_closed);
    WTQ_EV_GATE(on_send_complete);
    WTQ_EV_GATE(on_datagram);
    WTQ_EV_GATE(on_stream_writable);
#undef WTQ_EV_GATE
    dst->struct_size = (uint32_t)full;
}

/* --- deferred destroy ----------------------------------------------------- */

static void session_destroy(wtq_session_t *s)
{
    wtq_alloc_t alloc = s->alloc;

    if (s->conn != NULL)
        wtq_conn_destroy(s->conn);
    alloc.free(s, sizeof(*s), alloc.ctx);
}

static void session_enter(wtq_session_t *s)
{
    s->cb_depth++;
}

/* Destruction is canonical on refs == 0 AND no bracket held: a release
 * to zero inside a callback defers to the outermost exit, and ANY
 * re-reference before that exit (wtq_session_add_ref, or the session
 * pin wtq_stream_add_ref takes) cancels the pending destruction — the
 * live count is re-checked at the exit, never latched. */
static void session_exit(wtq_session_t *s)
{
    s->cb_depth--;
    if (s->cb_depth == 0 && s->refs == 0)
        session_destroy(s);
}

static void session_ref(wtq_session_t *s)
{
    s->refs++;
}

static void session_unref(wtq_session_t *s)
{
    if (s->refs == 0)
        return; /* over-release: refuse to double-free */
    s->refs--;
    if (s->refs == 0 && s->cb_depth == 0)
        session_destroy(s);
}

/* --- stream slot pool ----------------------------------------------------- */

static struct wtq_stream *stream_acquire(wtq_session_t *s,
                                         wtq_estream_t *es, bool bidi,
                                         bool local, uint64_t id)
{
    for (size_t i = 0; i < WTQ_API_MAX_STREAMS; i++) {
        struct wtq_stream *st = &s->streams[i];
        if (st->refs == 0) {
            memset(st, 0, sizeof(*st));
            st->refs = 1; /* the library's ref */
            st->alive = true;
            st->bidi = bidi;
            st->local = local;
            st->send_open = local || bidi;
            st->recv_open = !local || bidi;
            st->id = id;
            st->es = es;
            st->session = s;
            /* NOTE: the library's baseline ref does not pin the
             * session — only app-held refs do (wtq_stream_add_ref).
             * Slot memory lives inside the session allocation, and a
             * destroyed session destroys the engine first, so no
             * callback can reach an unpinned slot afterwards. */
            return st;
        }
    }
    return NULL;
}

/* Drop the LIBRARY's baseline ref (no session pin attached). */
static void stream_slot_release(struct wtq_stream *st)
{
    if (st->refs > 0)
        st->refs--;
}

/* A transient internal ref (no session pin) held across a callback so
 * a reentrant terminal cannot free the slot and let a fresh stream
 * reuse it before the adapter finishes its post-callback bookkeeping. */
static void stream_hold(struct wtq_stream *st)
{
    st->refs++;
}

static void stream_drop(struct wtq_stream *st)
{
    if (st->refs > 0)
        st->refs--;
}

/* Terminal: both directions done (or the session/connection ended).
 * Fires on_stream_closed exactly once, severs the engine linkage, and
 * drops the library's ref. */
static void stream_terminal(wtq_session_t *s, struct wtq_stream *st)
{
    if (!st->alive)
        return;
    st->alive = false;
    if (st->es != NULL) {
        /* freeze the final native id first: retained handles keep
         * querying it after the backlink is severed (possibly the
         * final value WTQ_STREAM_ID_UNKNOWN, if it never arrived) */
        st->id = wtq_estream_id(st->es);
        /* sever engine->adapter too: the estream may survive as a
         * drain tombstone, and a late engine event on it must not
         * dispatch onto this slot's next occupant */
        wtq_estream_set_user(st->es, NULL);
        st->es = NULL;
    }
    if (s->ev.on_stream_closed != NULL)
        s->ev.on_stream_closed(s, st, s->user);
    stream_slot_release(st);
}

static void stream_maybe_terminal(wtq_session_t *s, struct wtq_stream *st)
{
    if (st->alive && !st->send_open && !st->recv_open)
        stream_terminal(s, st);
}

/* Every live stream ends when the session does (the engine has already
 * reset/stopped the wire side). */
static void streams_teardown(wtq_session_t *s)
{
    for (size_t i = 0; i < WTQ_API_MAX_STREAMS; i++) {
        struct wtq_stream *st = &s->streams[i];
        if (st->refs > 0 && st->alive) {
            st->send_open = false;
            st->recv_open = false;
            stream_terminal(s, st);
        }
    }
}

/* --- engine event adapters ------------------------------------------------ */

static struct wtq_stream *handle_of(wtq_estream_t *es)
{
    return (struct wtq_stream *)wtq_estream_get_user(es);
}

static void adapt_established(wtq_conn_t *conn, const char *sel,
                              size_t sel_len, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)conn;
    session_enter(s);
    s->established_seen = true;
    if (s->ev.on_established != NULL) {
        wtq_str_t sub = { sel, sel_len };
        s->ev.on_established(s, sub, s->user);
    }
    session_exit(s);
}

static void adapt_rejected(wtq_conn_t *conn, uint16_t status, void *ctx)
{
    wtq_session_t *s = ctx;

    session_enter(s);
    if (!s->terminal_fired) {
        s->terminal_fired = true;
        s->failed = true;
        wtq_conn_seal_transport_error(conn);
        if (s->ev.on_refused != NULL)
            s->ev.on_refused(s, status, s->user);
    }
    session_exit(s);
}

static void adapt_failed(wtq_conn_t *conn, wtq_session_fail_reason_t why,
                         void *ctx)
{
    wtq_session_t *s = ctx;

    session_enter(s);
    if (!s->terminal_fired) {
        s->terminal_fired = true;
        s->failed = true;
        wtq_conn_seal_transport_error(conn);
        if (s->ev.on_failed != NULL) {
            wtq_connect_failure_t f;
            switch (why) {
            case WTQ_SESSION_FAIL_NO_WT_SUPPORT:
                f = WTQ_CONNECT_FAILURE_NO_WT_SUPPORT;
                break;
            case WTQ_SESSION_FAIL_NO_PROTOCOL:
                f = WTQ_CONNECT_FAILURE_NO_SUBPROTOCOL;
                break;
            case WTQ_SESSION_FAIL_CONNECTION:
                f = WTQ_CONNECT_FAILURE_CONNECTION;
                break;
            default:
                f = WTQ_CONNECT_FAILURE_BAD_RESPONSE;
                break;
            }
            s->ev.on_failed(s, f, s->user);
        }
    }
    session_exit(s);
}

static void adapt_draining(wtq_conn_t *conn, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)conn;
    session_enter(s);
    if (s->ev.on_draining != NULL)
        s->ev.on_draining(s, s->user);
    session_exit(s);
}

static void adapt_session_closed(wtq_conn_t *conn, uint32_t code,
                                 const uint8_t *reason, size_t reason_len,
                                 bool clean, void *ctx)
{
    wtq_session_t *s = ctx;

    session_enter(s);
    if (!s->terminal_fired) {
        s->terminal_fired = true;
        wtq_conn_seal_transport_error(conn);
        streams_teardown(s);
        if (s->ev.on_closed != NULL)
            s->ev.on_closed(s, code, reason, reason_len, clean, s->user);
    }
    session_exit(s);
}

static void adapt_conn_error(wtq_conn_t *conn, uint64_t h3_err, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)h3_err;
    session_enter(s);
    /* Defensive fallback. Every engine path now fires a session outcome
     * before on_conn_error — adapt_session_closed for an established
     * session, adapt_failed(CONNECTION) before that — so terminal_fired
     * is normally already set by the time we get here. This covers a
     * driver that reports a connection error without one. */
    if (!s->terminal_fired) {
        s->terminal_fired = true;
        s->failed = true;
        wtq_conn_seal_transport_error(conn);
        streams_teardown(s);
        if (s->ev.on_failed != NULL)
            s->ev.on_failed(s, WTQ_CONNECT_FAILURE_CONNECTION, s->user);
    }
    session_exit(s);
}

static void adapt_stream_opened(wtq_conn_t *conn, wtq_estream_t *es,
                                bool bidi, uint64_t id, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)conn;
    session_enter(s);
    struct wtq_stream *st = stream_acquire(s, es, bidi, false, id);
    if (st == NULL) {
        /* Handle pool exhausted: refuse the stream at the engine with
         * the protocol's rejection codepoint. The estream becomes a
         * drain tombstone, so bytes riding this same receive event
         * cannot reach an application callback. */
        wtq_conn_wt_reject(s->conn, es);
        session_exit(s);
        return;
    }
    wtq_estream_set_user(es, st);
    if (s->ev.on_stream_opened != NULL)
        s->ev.on_stream_opened(s, st, bidi, s->user);
    session_exit(s);
}

static void adapt_stream_data(wtq_conn_t *conn, wtq_estream_t *es,
                              const uint8_t *data, size_t len, bool fin,
                              void *ctx)
{
    wtq_session_t *s = ctx;
    struct wtq_stream *st = handle_of(es);

    (void)conn;
    if (st == NULL)
        return;
    session_enter(s);
    stream_hold(st);
    if (s->ev.on_stream_data != NULL)
        s->ev.on_stream_data(s, st, data, len, fin, s->user);
    /* the app may have terminaled this stream from inside the callback
     * (st->alive == false); the slot is pinned by our hold, so st is
     * still the SAME stream — just skip the now-moot recv update */
    if (fin && st->alive) {
        st->recv_open = false;
        stream_maybe_terminal(s, st);
    }
    stream_drop(st);
    session_exit(s);
}

static void adapt_stream_reset(wtq_conn_t *conn, wtq_estream_t *es,
                               uint32_t app_code, void *ctx)
{
    wtq_session_t *s = ctx;
    struct wtq_stream *st = handle_of(es);

    (void)conn;
    if (st == NULL)
        return;
    session_enter(s);
    stream_hold(st);
    if (s->ev.on_stream_reset != NULL)
        s->ev.on_stream_reset(s, st, app_code, s->user);
    if (st->alive) {
        st->recv_open = false;
        stream_maybe_terminal(s, st);
    }
    stream_drop(st);
    session_exit(s);
}

static void adapt_stream_stop(wtq_conn_t *conn, wtq_estream_t *es,
                              uint32_t app_code, void *ctx)
{
    wtq_session_t *s = ctx;
    struct wtq_stream *st = handle_of(es);

    (void)conn;
    if (st == NULL)
        return;
    session_enter(s);
    stream_hold(st);
    if (s->ev.on_stream_stop != NULL)
        s->ev.on_stream_stop(s, st, app_code, s->user);
    stream_drop(st);
    session_exit(s);
}

/*
 * Whole-stream transport terminal against a still-live public handle:
 * both public halves close and the ONE existing on_stream_closed fires
 * (stream_terminal also freezes the native-id snapshot for retained
 * handles and severs the backlink). No reset/stop event is fabricated.
 * A handle the app already drove terminal was severed from the estream
 * (handle_of == NULL) and can never see a duplicate.
 */
static void adapt_stream_terminal(wtq_conn_t *conn, wtq_estream_t *es,
                                  void *ctx)
{
    wtq_session_t *s = ctx;
    struct wtq_stream *st = handle_of(es);

    (void)conn;
    if (st == NULL)
        return;
    session_enter(s);
    stream_hold(st);
    if (st->alive) {
        st->send_open = false;
        st->recv_open = false;
        stream_maybe_terminal(s, st); /* exactly one closed event */
    }
    stream_drop(st);
    session_exit(s);
}

static void adapt_send_complete(wtq_conn_t *conn, void *cookie,
                                bool canceled, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)conn;
    session_enter(s);
    if (s->ev.on_send_complete != NULL)
        s->ev.on_send_complete(s, cookie, canceled, s->user);
    session_exit(s);
}

static void adapt_stream_writable(wtq_conn_t *conn, wtq_estream_t *es,
                                  void *ctx)
{
    wtq_session_t *s = ctx;
    struct wtq_stream *st = handle_of(es);

    (void)conn;
    if (st == NULL)
        return;
    session_enter(s);
    stream_hold(st);
    if (s->ev.on_stream_writable != NULL)
        s->ev.on_stream_writable(s, st, s->user);
    stream_drop(st);
    session_exit(s);
}

static void adapt_datagram(wtq_conn_t *conn, const uint8_t *data,
                           size_t len, void *ctx)
{
    wtq_session_t *s = ctx;

    (void)conn;
    session_enter(s);
    if (s->ev.on_datagram != NULL)
        s->ev.on_datagram(s, data, len, s->user);
    session_exit(s);
}

/* --- constructor seam ----------------------------------------------------- */

wtq_result_t wtq_api_session_create(const wtq_api_session_cfg_t *cfg,
                                    wtq_session_t **out)
{
    if (out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *out = NULL;
    if (cfg == NULL || cfg->alloc == NULL || cfg->alloc->alloc == NULL ||
        cfg->alloc->free == NULL || cfg->events == NULL ||
        cfg->events->struct_size == 0 || cfg->drv == NULL ||
        cfg->ops == NULL)
        return WTQ_ERR_INVALID_ARG;

    wtq_session_t *s =
        cfg->alloc->alloc(sizeof(wtq_session_t), cfg->alloc->ctx);
    if (s == NULL)
        return WTQ_ERR_NOMEM;
    memset(s, 0, sizeof(*s));
    s->refs = 1;
    s->alloc = *cfg->alloc;
    s->user = cfg->user;
    wtq_session_events_copy(&s->ev, cfg->events);

    wtq_conn_cfg_t ccfg = {
        .alloc = &s->alloc,
        .perspective = cfg->perspective,
        .enable_connect_protocol = true,
        .webtransport_profile = cfg->webtransport_profile,
        .callbacks = { .on_conn_error = adapt_conn_error,
                       .on_session_established = adapt_established,
                       .on_session_rejected = adapt_rejected,
                       .on_session_failed = adapt_failed,
                       .on_session_closed = adapt_session_closed,
                       .on_session_draining = adapt_draining,
                       .on_wt_stream_opened = adapt_stream_opened,
                       .on_wt_stream_data = adapt_stream_data,
                       .on_wt_stream_reset = adapt_stream_reset,
                       .on_wt_stream_stop = adapt_stream_stop,
                       .on_wt_send_complete = adapt_send_complete,
                       .on_wt_datagram = adapt_datagram,
                       .on_wt_stream_writable = adapt_stream_writable,
                       .on_wt_stream_terminal = adapt_stream_terminal,
                       .ctx = s },
    };
    wtq_result_t rc = wtq_conn_create(&ccfg, cfg->drv, cfg->ops, &s->conn);
    if (rc != WTQ_OK) {
        s->alloc.free(s, sizeof(*s), s->alloc.ctx);
        return rc;
    }
    *out = s;
    return WTQ_OK;
}

wtq_result_t wtq_api_session_start(wtq_session_t *s, uint64_t now_us)
{
    if (s == NULL)
        return WTQ_ERR_INVALID_ARG;
    session_enter(s);
    wtq_result_t rc = wtq_conn_start(s->conn, now_us);
    session_exit(s);
    return rc;
}

wtq_result_t wtq_api_session_connect(wtq_session_t *s,
                                     const wtq_connect_config_t *cfg)
{
    if (s == NULL || cfg == NULL)
        return WTQ_ERR_INVALID_ARG;
    /* authority and path are required and dereferenced downstream; a
     * struct_size that does not cover them WHOLE cannot be trusted. */
    if (!wtq_cfg_has(cfg->struct_size, offsetof(wtq_connect_config_t, path),
                     sizeof(((wtq_connect_config_t *)0)->path)))
        return WTQ_ERR_INVALID_ARG;

    wtq_connect_config_t c;
    cfg_copy(&c, sizeof(c), cfg, cfg->struct_size);
    /* Optional fields honoured only when wholly present: a truncated origin
     * pointer, or a subprotocols/count pair the size only straddles, is
     * dropped rather than used as a partial value. */
    if (!wtq_cfg_has(cfg->struct_size, offsetof(wtq_connect_config_t, origin),
                     sizeof(c.origin)))
        c.origin = NULL;
    if (!wtq_cfg_has(cfg->struct_size,
                     offsetof(wtq_connect_config_t, subprotocol_count),
                     sizeof(c.subprotocol_count))) {
        c.subprotocols = NULL;
        c.subprotocol_count = 0;
    }
    if (c.authority == NULL || c.path == NULL)
        return WTQ_ERR_INVALID_ARG;

    /* The profile tail is honoured only when WHOLLY present; a partial or
     * absent tail defaults to current (0). An out-of-range complete value
     * is rejected before any effect (the engine re-validates too). */
    uint32_t profile = 0;
    if (wtq_cfg_has(cfg->struct_size,
                    offsetof(wtq_connect_config_t, webtransport_profile),
                    sizeof(c.webtransport_profile))) {
        profile = c.webtransport_profile;
        if (profile != WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT &&
            profile != WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT)
            return WTQ_ERR_INVALID_ARG;
    }

    wtq_client_connect_cfg_t ecfg = {
        .authority = c.authority,
        .path = c.path,
        .origin = c.origin,
        .protocols = c.subprotocols,
        .protocol_count = c.subprotocol_count,
        .require_protocol = c.require_subprotocol,
        .webtransport_profile = (int)profile,
    };
    session_enter(s);
    wtq_result_t rc = wtq_conn_client_connect(s->conn, &ecfg);
    session_exit(s);
    return rc;
}

wtq_result_t wtq_api_session_serve(wtq_session_t *s,
                                   const wtq_serve_config_t *paths,
                                   size_t count)
{
    if (s == NULL || (paths == NULL && count > 0) ||
        count > WTQ_API_MAX_PATHS)
        return WTQ_ERR_INVALID_ARG;

    wtq_server_path_cfg_t ecfg[WTQ_API_MAX_PATHS];
    for (size_t i = 0; i < count; i++) {
        if (paths[i].struct_size == 0)
            return WTQ_ERR_INVALID_ARG;
        /* path is required and dereferenced; reject a size that does not
         * cover it whole. */
        if (!wtq_cfg_has(paths[i].struct_size,
                         offsetof(wtq_serve_config_t, path),
                         sizeof(((wtq_serve_config_t *)0)->path)))
            return WTQ_ERR_INVALID_ARG;
        wtq_serve_config_t p;
        cfg_copy(&p, sizeof(p), &paths[i], paths[i].struct_size);
        /* Drop the subprotocols/count pair unless BOTH are wholly present, so
         * a size straddling the pointer or the count never yields a partial. */
        if (!wtq_cfg_has(paths[i].struct_size,
                         offsetof(wtq_serve_config_t, subprotocol_count),
                         sizeof(p.subprotocol_count))) {
            p.subprotocols = NULL;
            p.subprotocol_count = 0;
        }
        ecfg[i].path = p.path;
        ecfg[i].protocols = p.subprotocols;
        ecfg[i].protocol_count = p.subprotocol_count;
        ecfg[i].require_protocol = p.require_subprotocol;
    }
    session_enter(s);
    wtq_result_t rc = wtq_conn_server_set_paths(s->conn, ecfg, count);
    session_exit(s);
    return rc;
}

wtq_conn_t *wtq_api_session_conn(wtq_session_t *s)
{
    return s != NULL ? s->conn : NULL;
}

void wtq_api_session_enter(wtq_session_t *s)
{
    if (s != NULL)
        session_enter(s);
}

bool wtq_api_session_leave(wtq_session_t *s)
{
    if (s == NULL)
        return false;
    /* true only when THIS leave is the destroying one: last bracket
     * out with no refs left */
    bool doomed = s->refs == 0 && s->cb_depth == 1;
    session_exit(s);
    return doomed;
}

/* --- public session surface ------------------------------------------------ */

void wtq_session_add_ref(wtq_session_t *s)
{
    if (s != NULL)
        session_ref(s);
}

void wtq_session_release(wtq_session_t *s)
{
    if (s != NULL)
        session_unref(s);
}

wtq_result_t wtq_session_close(wtq_session_t *s, uint32_t code,
                               const uint8_t *reason, size_t reason_len)
{
    if (s == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (s->terminal_fired)
        return WTQ_ERR_CLOSED;
    session_enter(s);
    wtq_result_t rc = wtq_conn_session_close(s->conn, code, reason,
                                             reason_len);
    session_exit(s);
    return rc;
}

wtq_result_t wtq_session_drain(wtq_session_t *s)
{
    if (s == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (s->terminal_fired)
        return WTQ_ERR_CLOSED;
    session_enter(s);
    wtq_result_t rc = wtq_conn_session_drain(s->conn);
    session_exit(s);
    return rc;
}

static wtq_result_t session_open(wtq_session_t *s, bool bidi,
                                 wtq_stream_t **out)
{
    if (s == NULL || out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *out = NULL;
    if (s->terminal_fired)
        return WTQ_ERR_CLOSED;

    session_enter(s);
    wtq_estream_t *es = NULL;
    wtq_result_t rc = bidi ? wtq_conn_wt_open_bidi(s->conn, &es)
                           : wtq_conn_wt_open_uni(s->conn, &es);
    if (rc != WTQ_OK) {
        session_exit(s);
        return rc == WTQ_ERR_STATE && s->terminal_fired ? WTQ_ERR_CLOSED
                                                        : rc;
    }
    struct wtq_stream *st =
        stream_acquire(s, es, bidi, true, wtq_estream_id(es));
    if (st == NULL) {
        /* the engine opened both directions; with no public handle,
         * tear DOWN both — reset the send side and stop the receive
         * side (a bidi's receive side would otherwise stay open in the
         * engine, same as the peer-rejection path). */
        (void)wtq_conn_wt_abort(s->conn, es, 0);
        session_exit(s);
        return WTQ_ERR_STREAM_LIMIT;
    }
    wtq_estream_set_user(es, st);
    *out = st;
    session_exit(s);
    return WTQ_OK;
}

wtq_result_t wtq_session_open_uni(wtq_session_t *s, wtq_stream_t **out)
{
    return session_open(s, false, out);
}

wtq_result_t wtq_session_open_bidi(wtq_session_t *s, wtq_stream_t **out)
{
    return session_open(s, true, out);
}

wtq_result_t wtq_session_send_datagram(wtq_session_t *s,
                                       const wtq_span_t *spans,
                                       size_t count)
{
    if (s == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (s->terminal_fired)
        return WTQ_ERR_CLOSED;
    session_enter(s);
    wtq_result_t rc = wtq_conn_dgram_send(s->conn, spans, count);
    session_exit(s);
    return rc;
}

size_t wtq_session_datagram_max_size(const wtq_session_t *s)
{
    if (s == NULL)
        return 0;
    return wtq_conn_dgram_max_size(s->conn);
}

wtq_result_t wtq_session_transport_error(const wtq_session_t *s,
                                         wtq_transport_error_t *out)
{
    if (s == NULL || out == NULL ||
        out->struct_size < offsetof(wtq_transport_error_t, kind) +
                               sizeof(out->kind))
        return WTQ_ERR_INVALID_ARG;

    wtq_transport_error_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.kind = WTQ_ERR_KIND_NONE;
    const wtq_transport_error_t *latched =
        s->conn != NULL ? wtq_conn_transport_error(s->conn) : NULL;
    if (latched != NULL)
        rec = *latched;

    /* Caller-sized copy-out: fill only the bytes that fit, preserving
     * the caller's struct_size and leaving trailing fields untouched. */
    uint32_t caller_size = out->struct_size;
    size_t n = caller_size < sizeof(rec) ? caller_size : sizeof(rec);
    memcpy(out, &rec, n);
    out->struct_size = caller_size;
    return WTQ_OK;
}

wtq_session_status_t wtq_session_status(const wtq_session_t *s)
{
    if (s == NULL)
        return WTQ_SESSION_STATUS_FAILED;
    if (s->failed)
        return WTQ_SESSION_STATUS_FAILED;
    switch (wtq_conn_session_state(s->conn)) {
    case WTQ_SESSION_ESTABLISHED:
        return WTQ_SESSION_STATUS_ESTABLISHED;
    case WTQ_SESSION_DRAINING:
        return WTQ_SESSION_STATUS_DRAINING;
    case WTQ_SESSION_CLOSED:
        return WTQ_SESSION_STATUS_CLOSED;
    case WTQ_SESSION_REJECTED:
    case WTQ_SESSION_FAILED:
        return WTQ_SESSION_STATUS_FAILED;
    default:
        return WTQ_SESSION_STATUS_CONNECTING;
    }
}

wtq_str_t wtq_session_subprotocol(const wtq_session_t *s)
{
    wtq_str_t sub = { "", 0 };

    if (s != NULL)
        sub.data = wtq_conn_selected_protocol(s->conn, &sub.len);
    return sub;
}

void wtq_session_set_user(wtq_session_t *s, void *user)
{
    if (s != NULL)
        s->user = user;
}

void *wtq_session_get_user(const wtq_session_t *s)
{
    return s != NULL ? s->user : NULL;
}

/* --- public stream surface -------------------------------------------------- */

void wtq_stream_add_ref(wtq_stream_t *st)
{
    if (st != NULL && st->refs > 0) { /* a live/dead-but-valid slot */
        st->refs++;
        st->app_refs++;
        session_ref(st->session); /* app refs pin the session */
    }
}

void wtq_stream_release(wtq_stream_t *st)
{
    if (st == NULL || st->app_refs == 0)
        return; /* only app-owned refs are the app's to drop */
    wtq_session_t *s = st->session;
    st->app_refs--;
    st->refs--;
    session_unref(s); /* may free the session (and this slot) */
}

wtq_result_t wtq_stream_send(wtq_stream_t *st, const wtq_span_t *spans,
                             size_t count, uint32_t flags, void *send_ctx)
{
    if (st == NULL || (spans == NULL && count > 0))
        return WTQ_ERR_INVALID_ARG;
    if (!st->alive)
        return WTQ_ERR_CLOSED;
    if (!st->send_open)
        return WTQ_ERR_STATE;

    wtq_session_t *s = st->session;
    bool fin = (flags & WTQ_SEND_FIN) != 0;
    session_enter(s);
    wtq_result_t rc =
        wtq_conn_wt_send(s->conn, st->es, spans, count, fin, send_ctx);
    if (rc == WTQ_OK && fin) {
        st->send_open = false;
        stream_maybe_terminal(s, st);
    }
    session_exit(s);
    return rc;
}

wtq_result_t wtq_stream_reset(wtq_stream_t *st, uint32_t app_code)
{
    if (st == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (!st->alive)
        return WTQ_ERR_CLOSED;
    if (!st->send_open)
        return WTQ_ERR_STATE;

    wtq_session_t *s = st->session;
    session_enter(s);
    wtq_result_t rc = wtq_conn_wt_reset(s->conn, st->es, app_code);
    if (rc == WTQ_OK) {
        st->send_open = false;
        stream_maybe_terminal(s, st);
    }
    session_exit(s);
    return rc;
}

wtq_result_t wtq_stream_stop_sending(wtq_stream_t *st, uint32_t app_code)
{
    if (st == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (!st->alive)
        return WTQ_ERR_CLOSED;
    if (!st->recv_open)
        return WTQ_ERR_STATE;

    wtq_session_t *s = st->session;
    session_enter(s);
    wtq_result_t rc = wtq_conn_wt_stop(s->conn, st->es, app_code);
    if (rc == WTQ_OK) {
        st->recv_open = false;
        stream_maybe_terminal(s, st);
    }
    session_exit(s);
    return rc;
}

wtq_result_t wtq_stream_abort(wtq_stream_t *st, uint32_t app_code)
{
    if (st == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (!st->alive)
        return WTQ_ERR_CLOSED;
    if (!st->send_open && !st->recv_open)
        return WTQ_ERR_STATE;

    wtq_session_t *s = st->session;
    session_enter(s);
    wtq_result_t rc = wtq_conn_wt_abort(s->conn, st->es, app_code);
    if (rc == WTQ_OK) {
        st->send_open = false;
        st->recv_open = false;
        stream_maybe_terminal(s, st);
    }
    session_exit(s);
    return rc;
}

static wtq_result_t stream_recv_enable(wtq_stream_t *st, bool enabled)
{
    if (st == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (!st->alive)
        return WTQ_ERR_CLOSED;
    if (!st->recv_open)
        return WTQ_ERR_STATE;

    wtq_session_t *s = st->session;
    session_enter(s);
    wtq_result_t rc = wtq_conn_wt_recv_enable(s->conn, st->es, enabled);
    session_exit(s);
    return rc;
}

wtq_result_t wtq_stream_pause_receive(wtq_stream_t *st)
{
    return stream_recv_enable(st, false);
}

wtq_result_t wtq_stream_resume_receive(wtq_stream_t *st)
{
    return stream_recv_enable(st, true);
}

wtq_receive_pause_mode_t wtq_stream_receive_pause_mode(const wtq_stream_t *st)
{
    /* A static property of the transport backend (recv_enable presence +
     * capability bit), stable for the connection's life, so no lock and no
     * liveness requirement — but a NULL stream or one with no session has no
     * backend to report. */
    if (st == NULL || st->session == NULL)
        return WTQ_RECEIVE_PAUSE_UNSUPPORTED;
    return (wtq_receive_pause_mode_t)wtq_conn_recv_pause_mode(
        st->session->conn);
}

uint64_t wtq_stream_id(const wtq_stream_t *st)
{
    if (st == NULL)
        return WTQ_STREAM_ID_UNKNOWN;
    /* Read through while attached: an id assigned after open becomes
     * visible; stream_terminal froze st->id for the detached case. */
    return st->es != NULL ? wtq_estream_id(st->es) : st->id;
}

bool wtq_stream_is_bidi(const wtq_stream_t *st)
{
    return st != NULL && st->bidi;
}

bool wtq_stream_is_local(const wtq_stream_t *st)
{
    return st != NULL && st->local;
}

wtq_session_t *wtq_stream_session(const wtq_stream_t *st)
{
    return st != NULL ? st->session : NULL;
}

void wtq_stream_set_user(wtq_stream_t *st, void *user)
{
    if (st != NULL)
        st->user = user;
}

void *wtq_stream_get_user(const wtq_stream_t *st)
{
    return st != NULL ? st->user : NULL;
}
