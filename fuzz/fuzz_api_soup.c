/*
 * fuzz_api_soup — adversarial lifecycle fuzzing of the public session/
 * stream API over the engine.
 *
 * A client session is brought to ESTABLISHED, then the fuzzer input is
 * an interleaved op stream mixing public API calls (open/send/reset/
 * stop/add_ref/release/datagram/close/drain) with raw peer-side event
 * injection (WT streams, stream bytes, resets, stop-sending, datagrams)
 * and send completions.
 *
 * The harness ENFORCES the public contracts, not just "does not crash":
 *   - every table handle is retained (add_ref) on capture and released
 *     at teardown, so a stream pointer is always valid (dead-but-valid
 *     after terminal) — never a stale/reused slot;
 *   - send-completion accounting: exactly one completion per accepted
 *     wtq_stream_send, and never a completion for a rejected send;
 *   - every raw engine input that fatally closes the connection must
 *     return a non-OK status (fz_check_fatal) — no swallowed fatals;
 *   - ZERO allocations during the op stream;
 *   - the allocator balances to zero with no invalid/double free.
 * Any violation aborts (a libFuzzer crash).
 */

#include <stddef.h>
#include <string.h>

#include "wtq_fuzz_util.h"

#include "api_internal.h"
#include "fake_driver.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define TABLE_MAX 16
#define COOKIES 32

typedef struct app {
    wtq_session_t *s;
    struct {
        wtq_stream_t *st;
        int refs; /* harness-held refs (>=1 baseline until teardown) */
    } tab[TABLE_MAX];
    int ntab;
    char cookie_pool[COOKIES];
    /* One slot per in-flight accepted send: 1 between accept and its
     * single completion, 0 otherwise. A unique slot per accepted send
     * means a duplicate completion and a missing completion can never
     * cancel out. */
    int cookie_used[COOKIES];
} app_t;

static void tab_add(app_t *a, wtq_stream_t *st)
{
    if (st != NULL && a->ntab < TABLE_MAX) {
        wtq_stream_add_ref(st); /* keep it valid past its terminal */
        a->tab[a->ntab].st = st;
        a->tab[a->ntab].refs = 1;
        a->ntab++;
    }
}

static void on_opened(wtq_session_t *s, wtq_stream_t *st, bool bidi,
                      void *user)
{
    (void)s;
    (void)bidi;
    tab_add(user, st);
}

static void on_send_done(wtq_session_t *s, void *ctx, bool canceled,
                         void *user)
{
    app_t *a = user;

    (void)s;
    (void)canceled;
    if (ctx == NULL)
        return;
    ptrdiff_t slot = (char *)ctx - a->cookie_pool;
    if (slot < 0 || slot >= COOKIES)
        abort(); /* completion for a cookie we never issued */
    if (a->cookie_used[slot] == 0)
        abort(); /* duplicate, or a completion for a rejected send */
    a->cookie_used[slot] = 0; /* this send's one-and-only completion */
}

/* Remaining callbacks: no-ops. */
static void on_data(wtq_session_t *s, wtq_stream_t *st, const uint8_t *d,
                    size_t n, bool fin, void *u)
{ (void)s; (void)st; (void)d; (void)n; (void)fin; (void)u; }
static void on_reset(wtq_session_t *s, wtq_stream_t *st, uint32_t c,
                     void *u)
{ (void)s; (void)st; (void)c; (void)u; }
static void on_stop(wtq_session_t *s, wtq_stream_t *st, uint32_t c, void *u)
{ (void)s; (void)st; (void)c; (void)u; }
static void on_sclosed(wtq_session_t *s, wtq_stream_t *st, void *u)
{ (void)s; (void)st; (void)u; }
static void on_established(wtq_session_t *s, wtq_str_t sub, void *u)
{ (void)s; (void)sub; (void)u; }
static void on_closed(wtq_session_t *s, uint32_t c, const uint8_t *r,
                      size_t n, bool clean, void *u)
{ (void)s; (void)c; (void)r; (void)n; (void)clean; (void)u; }
static void on_dgram(wtq_session_t *s, const uint8_t *d, size_t n, void *u)
{ (void)s; (void)d; (void)n; (void)u; }
static void on_draining(wtq_session_t *s, void *u) { (void)s; (void)u; }
static void on_refused(wtq_session_t *s, uint16_t st, void *u)
{ (void)s; (void)st; (void)u; }
static void on_failed(wtq_session_t *s, wtq_connect_failure_t w, void *u)
{ (void)s; (void)w; (void)u; }

/* --- bracketed raw injection (harness = the fake backend) ---------------- */

/* Deliver bytes to a live estream inside the bracket, checking that a
 * fatal close never returns OK. */
static void deliver(app_t *a, wtq_estream_t *es, const uint8_t *d,
                    size_t n, bool fin)
{
    wtq_conn_t *conn = wtq_api_session_conn(a->s);
    if (conn == NULL || es == NULL)
        return;
    int was = wtq_conn_is_closed(conn);
    wtq_api_session_enter(a->s);
    wtq_result_t rc = wtq_conn_on_stream_bytes(conn, es, d, n, fin, 1000);
    (void)wtq_api_session_leave(a->s);
    fz_check_fatal(conn, was, rc);
}

/* --- establishment ------------------------------------------------------- */

static wtq_estream_t *establish(app_t *a, struct wtq_driver *drv)
{
    wtq_conn_t *conn = wtq_api_session_conn(a->s);
    static const char *const offer[] = { "moqt-18" };
    wtq_connect_config_t cc;

    wtq_connect_config_init(&cc);
    cc.authority = "h";
    cc.path = "/p";
    cc.subprotocols = offer;
    cc.subprotocol_count = 1;
    if (wtq_api_session_connect(a->s, &cc) != WTQ_OK)
        return NULL;

    uint8_t st[64];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    st[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&scfg, st + 1, sizeof(st) - 1,
                                     &flen) != 0)
        return NULL;
    struct wtq_dstream *cds = fake_driver_add_peer_stream(drv, 3);
    wtq_estream_t *ces = NULL;
    if (cds == NULL)
        return NULL;
    wtq_api_session_enter(a->s);
    (void)wtq_conn_on_peer_uni_opened(conn, cds, 3, &ces);
    if (ces != NULL)
        (void)wtq_conn_on_stream_bytes(conn, ces, st, 1 + flen, false,
                                       1000);
    (void)wtq_api_session_leave(a->s);

    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (drv->streams[i].in_use && drv->streams[i].is_local &&
            drv->streams[i].is_bidi)
            bidi = &drv->streams[i];
    if (bidi == NULL || bidi->ectx == NULL)
        return NULL;

    uint8_t resp[128];
    uint8_t section[96];
    size_t slen = 0;
    wtq_sf_str_t sel = { "moqt-18", 7 };
    if (wtq_connect_encode_response(200, &sel, section, sizeof(section),
                                    &slen) != 0)
        return NULL;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, resp,
                                   sizeof(resp), &hl) != 0)
        return NULL;
    memcpy(resp + hl, section, slen);
    deliver(a, bidi->ectx, resp, hl + slen, false);
    if (wtq_session_status(a->s) != WTQ_SESSION_STATUS_ESTABLISHED)
        return NULL;
    return bidi->ectx;
}

/* Inject a peer WT stream (uni or bidi) with a preamble + fuzzer body. */
static wtq_estream_t *inject_wt(app_t *a, struct wtq_driver *drv,
                                uint64_t id, bool bidi, const uint8_t *p,
                                size_t n, bool fin)
{
    uint8_t wire[64];
    size_t pl = 0;
    if (wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                 : WTQ_PREAMBLE_KIND_UNI,
                            0, wire, sizeof(wire), &pl) != 0)
        return NULL;
    if (n > sizeof(wire) - pl)
        n = sizeof(wire) - pl;
    memcpy(wire + pl, p, n);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(drv, id);
    if (ds == NULL)
        return NULL;
    ds->is_bidi = bidi;
    wtq_conn_t *conn = wtq_api_session_conn(a->s);
    wtq_estream_t *es = NULL;
    int was = wtq_conn_is_closed(conn);
    wtq_api_session_enter(a->s);
    wtq_result_t rc =
        bidi ? wtq_conn_on_peer_bidi_opened(conn, ds, id, &es)
             : wtq_conn_on_peer_uni_opened(conn, ds, id, &es);
    ds->ectx = es;
    if (es != NULL) {
        wtq_result_t rb =
            wtq_conn_on_stream_bytes(conn, es, wire, pl + n, fin, 1000);
        if (rc == WTQ_OK)
            rc = rb;
    }
    (void)wtq_api_session_leave(a->s);
    fz_check_fatal(conn, was, rc);
    return es;
}

/* --- the op loop --------------------------------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 4096)
        size = 4096;

    wtq_fault_alloc_t fa;
    struct wtq_driver drv;
    app_t app;
    wtq_session_events_t ev;

    memset(&app, 0, sizeof(app));
    fake_driver_init(&drv, true);
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
    ev.on_refused = on_refused;
    ev.on_failed = on_failed;
    ev.on_draining = on_draining;
    ev.on_closed = on_closed;
    ev.on_stream_opened = on_opened;
    ev.on_stream_data = on_data;
    ev.on_stream_reset = on_reset;
    ev.on_stream_stop = on_stop;
    ev.on_stream_closed = on_sclosed;
    ev.on_send_complete = on_send_done;
    ev.on_datagram = on_dgram;

    wtq_api_session_cfg_t cfg = {
        .alloc = fz_alloc(&fa),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &app,
        .drv = &drv,
        .ops = fake_driver_ops(),
    };
    if (wtq_api_session_create(&cfg, &app.s) != WTQ_OK)
        return 0;
    (void)wtq_api_session_start(app.s, 1000);

    if (establish(&app, &drv) == NULL) {
        for (int i = 0; i < app.ntab; i++)
            while (app.tab[i].refs > 0) {
                wtq_stream_release(app.tab[i].st);
                app.tab[i].refs--;
            }
        wtq_session_release(app.s);
        fz_alloc_check(&fa);
        return 0;
    }

    int allocs_after_setup = fa.attempts;
    uint64_t next_peer_uni = 7;   /* client peer uni ids: 7,11,...     */
    uint64_t next_peer_bidi = 1;  /* server-initiated bidi ids: 1,5,.. */
    wtq_estream_t *last_peer_es = NULL;

    fz_t r;
    fz_init(&r, data, size);
    while (fz_more(&r)) {
        uint8_t op = fz_u8(&r);
        uint8_t arg = fz_u8(&r);
        int idx = app.ntab > 0 ? arg % app.ntab : -1;
        wtq_stream_t *st = idx >= 0 ? app.tab[idx].st : NULL;

        switch (op % 16) {
        case 0: { /* open uni */
            wtq_stream_t *ns = NULL;
            if (wtq_session_open_uni(app.s, &ns) == WTQ_OK)
                tab_add(&app, ns);
            break;
        }
        case 1: { /* open bidi */
            wtq_stream_t *ns = NULL;
            if (wtq_session_open_bidi(app.s, &ns) == WTQ_OK)
                tab_add(&app, ns);
            break;
        }
        case 2: { /* send (accepted -> exactly one completion) */
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 32);
            wtq_span_t span = { p, n };
            uint32_t flags = (arg & 1) ? WTQ_SEND_FIN : 0;
            /* a unique free cookie slot per accepted send; skip the send
             * entirely when the bounded table is full so we never have
             * an untracked accepted send */
            int slot = -1;
            for (int i = 0; i < COOKIES; i++)
                if (!app.cookie_used[i]) {
                    slot = i;
                    break;
                }
            if (slot < 0)
                break;
            wtq_result_t rc = wtq_stream_send(st, &span, 1, flags,
                                              &app.cookie_pool[slot]);
            if (rc == WTQ_OK)
                app.cookie_used[slot] = 1;
            break;
        }
        case 3: /* local reset */
            (void)wtq_stream_reset(st, arg);
            break;
        case 4: /* local stop_sending */
            (void)wtq_stream_stop_sending(st, arg);
            break;
        case 5: /* add_ref */
            if (idx >= 0) {
                wtq_stream_add_ref(st);
                app.tab[idx].refs++;
            }
            break;
        case 6: /* release a harness ref (never below the baseline 1) */
            if (idx >= 0 && app.tab[idx].refs > 1) {
                wtq_stream_release(st);
                app.tab[idx].refs--;
            }
            break;
        case 7: { /* inject a peer WT uni */
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 24);
            last_peer_es = inject_wt(&app, &drv, next_peer_uni, false, p,
                                     n, arg & 1);
            next_peer_uni += 4;
            break;
        }
        case 8: { /* inject a peer WT bidi */
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 24);
            last_peer_es = inject_wt(&app, &drv, next_peer_bidi, true, p,
                                     n, arg & 1);
            next_peer_bidi += 4;
            break;
        }
        case 9: { /* peer reset the last injected peer stream */
            wtq_conn_t *conn = wtq_api_session_conn(app.s);
            if (conn != NULL && last_peer_es != NULL) {
                int was = wtq_conn_is_closed(conn);
                wtq_api_session_enter(app.s);
                wtq_result_t rc = wtq_conn_on_stream_reset(
                    conn, last_peer_es, arg, 1000);
                (void)wtq_api_session_leave(app.s);
                fz_check_fatal(conn, was, rc);
                last_peer_es = NULL;
            }
            break;
        }
        case 10: { /* peer STOP_SENDING on a local stream */
            struct wtq_dstream *loc = fake_driver_local(&drv, arg % 8);
            wtq_conn_t *conn = wtq_api_session_conn(app.s);
            if (conn != NULL && loc != NULL && loc->ectx != NULL) {
                int was = wtq_conn_is_closed(conn);
                wtq_api_session_enter(app.s);
                wtq_result_t rc =
                    wtq_conn_on_stop_sending(conn, loc->ectx, arg, 1000);
                (void)wtq_api_session_leave(app.s);
                fz_check_fatal(conn, was, rc);
            }
            break;
        }
        case 11: { /* inject a datagram (sometimes hostile) */
            uint8_t dg[40];
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 32);
            size_t dlen;
            if (arg & 1) {
                dlen = n < sizeof(dg) ? n : sizeof(dg);
                memcpy(dg, p, dlen);
            } else {
                dg[0] = 0x00;
                memcpy(dg + 1, p, n);
                dlen = 1 + n;
            }
            wtq_conn_t *conn = wtq_api_session_conn(app.s);
            if (conn != NULL) {
                int was = wtq_conn_is_closed(conn);
                wtq_api_session_enter(app.s);
                wtq_result_t rc =
                    wtq_conn_on_datagram(conn, dg, dlen, 1000);
                (void)wtq_api_session_leave(app.s);
                fz_check_fatal(conn, was, rc);
            }
            break;
        }
        case 12: { /* send a datagram (API) */
            const uint8_t *p;
            size_t n = fz_bytes(&r, &p, 32);
            wtq_span_t span = { p, n };
            (void)wtq_session_send_datagram(app.s, &span, 1);
            break;
        }
        case 13: /* complete pending sends */
            (void)fake_driver_complete_sends(&drv,
                                             wtq_api_session_conn(app.s));
            break;
        case 14: /* session close */
            (void)wtq_session_close(app.s, arg, NULL, 0);
            break;
        case 15: /* session drain */
            (void)wtq_session_drain(app.s);
            break;
        }
    }

    /* ZERO steady-state allocations. */
    if (fa.attempts != allocs_after_setup)
        abort();

    /* Flush any still-pending completions (a real backend fires them
     * on teardown), then enforce: exactly one completion per accepted
     * send. */
    (void)fake_driver_complete_sends(&drv, wtq_api_session_conn(app.s));
    for (int i = 0; i < COOKIES; i++)
        if (app.cookie_used[i] != 0)
            abort(); /* an accepted send never completed */

    for (int i = 0; i < app.ntab; i++)
        while (app.tab[i].refs > 0) {
            wtq_stream_release(app.tab[i].st);
            app.tab[i].refs--;
        }
    wtq_session_release(app.s);
    fz_alloc_check(&fa);
    return 0;
}
