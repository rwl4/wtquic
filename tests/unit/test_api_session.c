#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"

#include "test_support.h"

/*
 * Public session API: config discipline, refcounts, exactly-once
 * terminal events, callback ordering, datagram lifetime, allocation
 * accounting. Everything goes through the public surface; the engine
 * appears only as the wire-feeding seam (wtq_api_session_conn).
 */

#define EV_MAX 32

typedef struct events_log {
    int count;
    struct {
        char kind[16];
        uint64_t a;
        uint64_t b;
    } ev[EV_MAX];
    wtq_session_t *session;
    wtq_stream_t *last_stream;
    uint32_t closed_code;
    uint8_t closed_reason[64];
    size_t closed_reason_len;
    bool closed_clean;
    const uint8_t *dgram_ptr;
    uint8_t dgram_bytes[32];
    size_t dgram_len;
    char subprotocol[512];
    size_t subprotocol_len;
    bool release_session_in_closed; /* reentrancy: release from cb */
    bool resurrect_in_closed;       /* release final ref, then re-add */
    bool resurrect_in_established;
} events_log_t;

static void log_ev(events_log_t *lg, const char *kind, uint64_t a,
                   uint64_t b)
{
    if (lg->count < EV_MAX) {
        strncpy(lg->ev[lg->count].kind, kind,
                sizeof(lg->ev[lg->count].kind) - 1);
        lg->ev[lg->count].kind[sizeof(lg->ev[lg->count].kind) - 1] = 0;
        lg->ev[lg->count].a = a;
        lg->ev[lg->count].b = b;
    }
    lg->count++;
}

static int ev_count(const events_log_t *lg, const char *kind)
{
    int n = 0;

    for (int i = 0; i < lg->count && i < EV_MAX; i++)
        if (strcmp(lg->ev[i].kind, kind) == 0)
            n++;
    return n;
}

static int ev_index(const events_log_t *lg, const char *kind)
{
    for (int i = 0; i < lg->count && i < EV_MAX; i++)
        if (strcmp(lg->ev[i].kind, kind) == 0)
            return i;
    return -1;
}

static void on_established(wtq_session_t *s, wtq_str_t subprotocol,
                           void *user)
{
    events_log_t *lg = user;

    (void)s;
    log_ev(lg, "established", subprotocol.len, 0);
    lg->subprotocol_len =
        subprotocol.len < sizeof(lg->subprotocol) ? subprotocol.len : 0;
    if (lg->subprotocol_len > 0)
        memcpy(lg->subprotocol, subprotocol.data, lg->subprotocol_len);
    if (lg->resurrect_in_established) {
        wtq_session_release(s); /* the only ref: destroy goes pending */
        wtq_session_add_ref(s); /* ...and must be cancelled here */
    }
}

static void on_refused(wtq_session_t *s, uint16_t status, void *user)
{
    (void)s;
    log_ev(user, "refused", status, 0);
}

static void on_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    (void)s;
    log_ev(user, "failed", (uint64_t)why, 0);
}

static void on_draining(wtq_session_t *s, void *user)
{
    (void)s;
    log_ev(user, "draining", 0, 0);
}

static void on_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t reason_len,
                      bool clean, void *user)
{
    events_log_t *lg = user;

    log_ev(lg, "closed", code, clean ? 1 : 0);
    lg->closed_code = code;
    lg->closed_reason_len =
        reason_len < sizeof(lg->closed_reason) ? reason_len : 0;
    if (lg->closed_reason_len > 0)
        memcpy(lg->closed_reason, reason, lg->closed_reason_len);
    lg->closed_clean = clean;
    if (lg->release_session_in_closed)
        wtq_session_release(s);
    if (lg->resurrect_in_closed) {
        wtq_session_release(s); /* the only ref: destroy goes pending */
        wtq_session_add_ref(s); /* ...and must be cancelled here */
    }
}

static void on_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                             bool bidi, void *user)
{
    events_log_t *lg = user;

    (void)s;
    log_ev(lg, "stream_opened", bidi ? 1 : 0, wtq_stream_id(st));
    lg->last_stream = st;
}

static void on_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    (void)s;
    log_ev(user, "stream_closed", wtq_stream_id(st), 0);
}

static void on_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    events_log_t *lg = user;

    (void)s;
    log_ev(lg, "datagram", len, 0);
    lg->dgram_ptr = data;
    lg->dgram_len = len < sizeof(lg->dgram_bytes) ? len : 0;
    if (lg->dgram_len > 0)
        memcpy(lg->dgram_bytes, data, lg->dgram_len);
}

typedef struct counting_alloc {
    int allocs;
    int frees;
} counting_alloc_t;

static void *count_alloc(size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    ca->allocs++;
    return malloc(size);
}

static void count_free(void *ptr, size_t size, void *ctx)
{
    counting_alloc_t *ca = ctx;

    (void)size;
    ca->frees++;
    free(ptr);
}

typedef struct rig {
    struct wtq_driver drv;
    wtq_session_t *s;
    events_log_t lg;
    counting_alloc_t ca;
    wtq_alloc_t alloc;
    wtq_estream_t *sess_es;
    struct wtq_dstream *sess_ds;
} rig_t;

static void base_events(wtq_session_events_t *ev)
{
    wtq_session_events_init(ev);
    ev->on_established = on_established;
    ev->on_refused = on_refused;
    ev->on_failed = on_failed;
    ev->on_draining = on_draining;
    ev->on_closed = on_closed;
    ev->on_stream_opened = on_stream_opened;
    ev->on_stream_closed = on_stream_closed;
    ev->on_datagram = on_datagram;
}

/* Type-correct no-ops for the members base_events leaves unset, so an event
 * table can be fully populated for the normalisation boundary test. */
static void nop_stream_data(wtq_session_t *s, wtq_stream_t *st,
                            const uint8_t *d, size_t l, bool fin, void *u)
{ (void)s; (void)st; (void)d; (void)l; (void)fin; (void)u; }
static void nop_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                             uint32_t code, void *u)
{ (void)s; (void)st; (void)code; (void)u; }
static void nop_stream_stop(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *u)
{ (void)s; (void)st; (void)code; (void)u; }
static void nop_send_complete(wtq_session_t *s, void *sctx, bool canceled,
                              void *u)
{ (void)s; (void)sctx; (void)canceled; (void)u; }
static void nop_stream_writable(wtq_session_t *s, wtq_stream_t *st, void *u)
{ (void)s; (void)st; (void)u; }

static void all_events(wtq_session_events_t *ev)
{
    base_events(ev);
    ev->on_stream_data = nop_stream_data;
    ev->on_stream_reset = nop_stream_reset;
    ev->on_stream_stop = nop_stream_stop;
    ev->on_send_complete = nop_send_complete;
    ev->on_stream_writable = nop_stream_writable;
}

/* Create the session but do NOT start it (start is one-shot, so tests
 * that drive it themselves must own the single attempt). */
static void rig_up_nostart(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(&r->lg, 0, sizeof(r->lg));
    memset(&r->ca, 0, sizeof(r->ca));
    r->alloc = (wtq_alloc_t){ &r->ca, count_alloc, NULL, count_free };
    r->sess_es = NULL;
    r->sess_ds = NULL;
    fake_driver_init(&r->drv, persp == WTQ_PERSPECTIVE_CLIENT);
    base_events(&ev);

    wtq_api_session_cfg_t cfg = {
        .alloc = &r->alloc,
        .perspective = persp,
        .events = &ev,
        .user = &r->lg,
        .drv = &r->drv,
        .ops = fake_driver_ops(),
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r->s) == WTQ_OK);
    WTQ_TEST_CHECK(r->s != NULL);
    if (r->s != NULL)
        r->lg.session = r->s;
    *fp += failures;
}

static void rig_up(rig_t *r, wtq_perspective_t persp, int *fp)
{
    int failures = 0;

    rig_up_nostart(r, persp, fp);
    if (r->s == NULL) {
        *fp += failures + 1;
        return;
    }
    WTQ_TEST_CHECK(wtq_api_session_start(r->s, 1000) == WTQ_OK);
    *fp += failures;
}

static void rig_down(rig_t *r, int *fp)
{
    int failures = 0;

    if (r->s != NULL)
        wtq_session_release(r->s);
    WTQ_TEST_CHECK(r->ca.allocs == r->ca.frees); /* balance 0 */
    *fp += failures;
}

static void deliver_peer_settings(rig_t *r, int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;
    wtq_conn_t *conn = wtq_api_session_conn(r->s);

    WTQ_TEST_CHECK(conn != NULL);
    if (conn == NULL) {
        *fp += failures + 1;
        return;
    }
    buf[0] = 0x00;
    WTQ_TEST_CHECK(wtq_h3_settings_encode_frame(&scfg, buf + 1,
                                                sizeof(buf) - 1,
                                                &flen) == 0);
    bool is_client = (r->drv.is_client);
    struct wtq_dstream *ds =
        fake_driver_add_peer_stream(&r->drv, is_client ? 3 : 2);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, ds,
                                               is_client ? 3 : 2, &es) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(wtq_conn_on_stream_bytes(conn, es, buf, 1 + flen,
                                            false, 1500) == WTQ_OK);
    *fp += failures;
}

static struct wtq_dstream *find_local_bidi(rig_t *r)
{
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (r->drv.streams[i].in_use && r->drv.streams[i].is_local &&
            r->drv.streams[i].is_bidi)
            return &r->drv.streams[i];
    return NULL;
}

static const char *const OFFER[] = { "moqt-18" };

static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t sel = { proto, proto ? strlen(proto) : 0 };

    if (wtq_connect_encode_response(status, proto ? &sel : NULL, section,
                                    sizeof(section), &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

static void do_connect(rig_t *r, int *fp)
{
    int failures = 0;
    wtq_connect_config_t cfg;

    wtq_connect_config_init(&cfg);
    cfg.authority = "example.com";
    cfg.path = "/app";
    cfg.subprotocols = OFFER;
    cfg.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(r->s, &cfg) == WTQ_OK);
    *fp += failures;
}

static void establish_client(rig_t *r, int *fp)
{
    int failures = 0;

    rig_up(r, WTQ_PERSPECTIVE_CLIENT, fp);
    do_connect(r, fp);
    deliver_peer_settings(r, fp);
    r->sess_ds = find_local_bidi(r);
    WTQ_TEST_CHECK(r->sess_ds != NULL && r->sess_ds->ectx != NULL);
    if (r->sess_ds == NULL) {
        *fp += failures + 1;
        return;
    }
    r->sess_es = r->sess_ds->ectx;
    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
    (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r->s), r->sess_es,
                                   resp, rlen, false, 2000);
    WTQ_TEST_CHECK(wtq_session_status(r->s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    *fp += failures;
}

/* --- config discipline --------------------------------------------------- */

static void test_config_init(int *fp)
{
    int failures = 0;

    wtq_session_events_t ev;
    memset(&ev, 0xa5, sizeof(ev));
    wtq_session_events_init(&ev);
    WTQ_TEST_CHECK(ev.struct_size == sizeof(ev));
    WTQ_TEST_CHECK(ev.on_established == NULL);
    WTQ_TEST_CHECK(ev.on_datagram == NULL);

    wtq_session_events_t ev2 = WTQ_SESSION_EVENTS_INIT;
    WTQ_TEST_CHECK(ev2.struct_size == sizeof(ev2));
    WTQ_TEST_CHECK(ev2.on_closed == NULL);

    wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
    WTQ_TEST_CHECK(cc.struct_size == sizeof(cc));
    WTQ_TEST_CHECK(cc.authority == NULL);

    wtq_serve_config_t sc = WTQ_SERVE_CONFIG_INIT;
    WTQ_TEST_CHECK(sc.struct_size == sizeof(sc));
    WTQ_TEST_CHECK(sc.path == NULL);
    *fp += failures;
}

/* An OLD-LAYOUT (v1) connect config, defined by the TEST — deliberately
 * independent of the implementation's internal shadow so it cannot drift
 * with it. Matches the frozen v1 prefix (through require_subprotocol). */
typedef struct test_connect_cfg_v1 {
    uint32_t struct_size;
    const char *authority;
    const char *path;
    const char *origin;
    const char *const *subprotocols;
    size_t subprotocol_count;
    bool require_subprotocol;
} test_connect_cfg_v1_t;

/* The connect-config profile ABI: the frozen v1 initialiser cannot
 * overflow a v1-sized object; init_ex records the size; and the tail
 * default is current. */
static void test_connect_profile_abi(int *fp)
{
    int failures = 0;
    const size_t v1sz = sizeof(test_connect_cfg_v1_t);

    /* The macro-form init writes the CURRENT size and zeroes the tail
     * (profile defaults to current). */
    wtq_connect_config_t cc;
    memset(&cc, 0xEE, sizeof(cc));
    wtq_connect_config_init(&cc);
    WTQ_TEST_CHECK_EQ_SIZE(cc.struct_size, sizeof(cc));
    WTQ_TEST_CHECK_EQ_INT((int)cc.webtransport_profile,
                          (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT);

    /* #9: the BARE frozen symbol writes ONLY the v1 prefix — a v1-sized
     * heap object plus a canary proves it never overflows. */
    {
        typedef void (*bare_init_fn)(wtq_connect_config_t *);
        bare_init_fn bare = &wtq_connect_config_init; /* frozen symbol */
        const size_t v1 = v1sz;
        unsigned char *buf = malloc(v1 + 8);
        WTQ_TEST_CHECK(buf != NULL);
        if (buf != NULL) {
            memset(buf + v1, 0x5A, 8); /* canary */
            bare((wtq_connect_config_t *)buf);
            for (int i = 0; i < 8; i++)
                WTQ_TEST_CHECK(buf[v1 + i] == 0x5A); /* untouched */
            uint32_t ss;
            memcpy(&ss, buf, sizeof(ss));
            WTQ_TEST_CHECK_EQ_SIZE(ss, v1); /* records the v1 size */
            free(buf);
        }
    }

    /* #10: init_ex records exactly the requested size (clamped to
     * current); init(NULL)/init_ex(NULL) are compiling no-ops. */
    wtq_connect_config_init(NULL);
    wtq_connect_config_init_ex(NULL, 999);
    {
        wtq_connect_config_t x;
        wtq_connect_config_init_ex(&x, v1sz);
        WTQ_TEST_CHECK_EQ_SIZE(x.struct_size, v1sz);
        /* an oversized request is clamped to the current type size */
        wtq_connect_config_init_ex(&x, sizeof(x) + 1000);
        WTQ_TEST_CHECK_EQ_SIZE(x.struct_size, sizeof(x));
    }

    *fp += failures;
}

/* A SHORTER (older-ABI) events struct works: trailing callbacks read
 * as absent, prefix callbacks still fire. */
static void test_events_struct_size_compat(int *fp)
{
    int failures = 0;
    rig_t r;
    wtq_session_events_t ev;

    memset(&r.lg, 0, sizeof(r.lg));
    memset(&r.ca, 0, sizeof(r.ca));
    r.alloc = (wtq_alloc_t){ &r.ca, count_alloc, NULL, count_free };
    fake_driver_init(&r.drv, true);

    base_events(&ev);
    /* pretend the caller was built when the struct ended after
     * on_established */
    ev.struct_size = (uint32_t)(offsetof(wtq_session_events_t,
                                         on_refused));

    wtq_api_session_cfg_t cfg = {
        .alloc = &r.alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &r.lg,
        .drv = &r.drv,
        .ops = fake_driver_ops(),
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &r.s) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_api_session_start(r.s, 1000) == WTQ_OK);
    r.lg.session = r.s;

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "a";
    cc.path = "/";
    WTQ_TEST_CHECK(wtq_api_session_connect(r.s, &cc) == WTQ_OK);
    deliver_peer_settings(&r, fp);
    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    if (bidi != NULL) {
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 200, NULL);
        (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s),
                                       bidi->ectx, resp, rlen, false,
                                       2000);
    }
    /* the in-range callback fired; out-of-range ones read as NULL */
    WTQ_TEST_CHECK(ev_count(&r.lg, "established") == 1);
    WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    rig_down(&r, fp);
    *fp += failures;
}

/* The offset of every wtq_session_events_t callback member, in declaration
 * order. Used to cut the caller's struct_size inside EACH one. */
static const size_t ev_member_off[] = {
    offsetof(wtq_session_events_t, on_established),
    offsetof(wtq_session_events_t, on_refused),
    offsetof(wtq_session_events_t, on_failed),
    offsetof(wtq_session_events_t, on_draining),
    offsetof(wtq_session_events_t, on_closed),
    offsetof(wtq_session_events_t, on_stream_opened),
    offsetof(wtq_session_events_t, on_stream_data),
    offsetof(wtq_session_events_t, on_stream_reset),
    offsetof(wtq_session_events_t, on_stream_stop),
    offsetof(wtq_session_events_t, on_stream_closed),
    offsetof(wtq_session_events_t, on_send_complete),
    offsetof(wtq_session_events_t, on_datagram),
    offsetof(wtq_session_events_t, on_stream_writable),
};

/* Typed, member-specific state of callback `idx` (declaration order, matching
 * ev_member_off) in a normalised table: 1 = preserved (equals the template's
 * typed value), 0 = NULL, -1 = corrupt (neither). Each case is a direct typed
 * pointer comparison — no byte representation or uniform-pointer-size
 * assumption. Order MUST match ev_member_off. */
static int ev_member_state(const wtq_session_events_t *d,
                           const wtq_session_events_t *t, size_t idx)
{
#define S(m) (d->m == NULL ? 0 : (d->m == t->m ? 1 : -1))
    switch (idx) {
    case 0:  return S(on_established);
    case 1:  return S(on_refused);
    case 2:  return S(on_failed);
    case 3:  return S(on_draining);
    case 4:  return S(on_closed);
    case 5:  return S(on_stream_opened);
    case 6:  return S(on_stream_data);
    case 7:  return S(on_stream_reset);
    case 8:  return S(on_stream_stop);
    case 9:  return S(on_stream_closed);
    case 10: return S(on_send_complete);
    case 11: return S(on_datagram);
    case 12: return S(on_stream_writable);
    default: return -1;
    }
#undef S
}

/* Cut the caller's struct_size ONE byte into each callback member in turn: the
 * straddled member (and everything after it) must normalise to NULL, while
 * every cleanly-complete earlier member is preserved with its exact typed
 * value. The source holds REAL typed callbacks, so a straddled member is a
 * truncated real pointer (not a synthetic pattern). Heap-backed. RED-prove:
 * drop any WTQ_EV_GATE and the cut straddling that member reports corrupt. */
static void test_events_partial_callback_zeroed(int *fp)
{
    int failures = 0;
    const size_t n = sizeof(ev_member_off) / sizeof(ev_member_off[0]);
    wtq_session_events_t tmpl;

    all_events(&tmpl);   /* every member a distinct typed no-op */
    for (size_t cut = 0; cut < n; cut++) {
        const size_t sz = ev_member_off[cut] + 1;   /* 1 byte into member cut */
        unsigned char *buf = malloc(sz);
        WTQ_TEST_CHECK(buf != NULL);
        if (buf == NULL)
            continue;
        memcpy(buf, &tmpl, sz);   /* real fn ptrs, truncated exactly at sz */
        ((wtq_session_events_t *)buf)->struct_size = (uint32_t)sz;
        wtq_session_events_t dst;
        wtq_session_events_copy(&dst, (const wtq_session_events_t *)buf);
        for (size_t j = 0; j < n; j++) {
            int st = ev_member_state(&dst, &tmpl, j);
            if (j < cut)
                WTQ_TEST_CHECK(st == 1);   /* complete prefix: preserved */
            else
                WTQ_TEST_CHECK(st == 0);   /* straddled or absent: NULL */
        }
        WTQ_TEST_CHECK(dst.struct_size == (uint32_t)sizeof(dst));
        free(buf);
    }
    *fp += failures;
}

/* Exact-size heap event table: a fully-present table is copied verbatim, no
 * over-read past the caller's object. */
static void test_events_exact_size_heap(int *fp)
{
    int failures = 0;
    const size_t sz = sizeof(wtq_session_events_t);
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf != NULL) {
        wtq_session_events_t *e = (wtq_session_events_t *)buf;
        wtq_session_events_init(e);
        e->on_established = on_established;
        e->on_closed = on_closed;
        wtq_session_events_t dst;
        wtq_session_events_copy(&dst, e);
        WTQ_TEST_CHECK(dst.on_established == on_established);
        WTQ_TEST_CHECK(dst.on_closed == on_closed);
        WTQ_TEST_CHECK(dst.struct_size == (uint32_t)sizeof(dst));
        free(buf);
    }
    *fp += failures;
}

/* connect/serve configs whose struct_size ends INSIDE a required pointer are
 * rejected before the truncated pointer is dereferenced. Heap-backed and
 * garbage-filled: RED-prove by removing the gate — the truncated pointer then
 * passes the NULL check and reaches the engine. */
static void test_connect_serve_config_boundaries(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    if (r.s != NULL) {
        /* connect: struct_size cuts mid-`path` (its low half is garbage). */
        const size_t csz = offsetof(wtq_connect_config_t, path)
            + sizeof(((wtq_connect_config_t *)0)->path) / 2;
        unsigned char *cbuf = malloc(csz);
        WTQ_TEST_CHECK(cbuf != NULL);
        if (cbuf != NULL) {
            memset(cbuf, 0xEE, csz);
            /* struct_size is the first member; write it with memcpy —
             * a struct-typed lvalue over this PARTIAL allocation is an
             * out-of-bounds object access (gcc -Werror=array-bounds
             * rejects it, and rightly so). */
            const uint32_t csz32 = (uint32_t)csz;
            WTQ_TEST_CHECK(offsetof(wtq_connect_config_t, struct_size) == 0);
            memcpy(cbuf, &csz32, sizeof(csz32));
            WTQ_TEST_CHECK(wtq_api_session_connect(
                               r.s, (const wtq_connect_config_t *)cbuf) ==
                           WTQ_ERR_INVALID_ARG);
            free(cbuf);
        }
        /* serve: struct_size cuts mid-`path`. */
        const size_t ssz = offsetof(wtq_serve_config_t, path)
            + sizeof(((wtq_serve_config_t *)0)->path) / 2;
        unsigned char *sbuf = malloc(ssz);
        WTQ_TEST_CHECK(sbuf != NULL);
        if (sbuf != NULL) {
            memset(sbuf, 0xEE, ssz);
            /* same memcpy discipline as the connect buffer above */
            const uint32_t ssz32 = (uint32_t)ssz;
            WTQ_TEST_CHECK(offsetof(wtq_serve_config_t, struct_size) == 0);
            memcpy(sbuf, &ssz32, sizeof(ssz32));
            WTQ_TEST_CHECK(wtq_api_session_serve(
                               r.s, (const wtq_serve_config_t *)sbuf, 1) ==
                           WTQ_ERR_INVALID_ARG);
            free(sbuf);
        }
    }
    rig_down(&r, fp);
    *fp += failures;
}

/* NULL/hostile configs are rejected with no partial state. */
static void test_config_rejection(int *fp)
{
    int failures = 0;
    counting_alloc_t ca = { 0, 0 };
    wtq_alloc_t alloc = { &ca, count_alloc, NULL, count_free };
    struct wtq_driver drv;
    wtq_session_t *s = NULL;
    wtq_session_events_t ev;

    fake_driver_init(&drv, true);
    base_events(&ev);

    wtq_api_session_cfg_t good = {
        .alloc = &alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = NULL,
        .drv = &drv,
        .ops = fake_driver_ops(),
    };
    wtq_api_session_cfg_t bad;

    WTQ_TEST_CHECK(wtq_api_session_create(NULL, &s) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(wtq_api_session_create(&good, NULL) ==
                   WTQ_ERR_INVALID_ARG);
    bad = good;
    bad.alloc = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&bad, &s) ==
                   WTQ_ERR_INVALID_ARG);
    bad = good;
    bad.events = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&bad, &s) ==
                   WTQ_ERR_INVALID_ARG);
    bad = good;
    bad.drv = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&bad, &s) ==
                   WTQ_ERR_INVALID_ARG);
    bad = good;
    bad.ops = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&bad, &s) ==
                   WTQ_ERR_INVALID_ARG);
    /* zero struct_size events */
    wtq_session_events_t zev;
    memset(&zev, 0, sizeof(zev));
    bad = good;
    bad.events = &zev;
    WTQ_TEST_CHECK(wtq_api_session_create(&bad, &s) ==
                   WTQ_ERR_INVALID_ARG);

    /* every rejection left nothing allocated */
    WTQ_TEST_CHECK(ca.allocs == 0);
    WTQ_TEST_CHECK(s == NULL);

    /* connect-config rejection: no partial state (a valid connect
     * afterwards still works) */
    wtq_session_t *ok = NULL;
    WTQ_TEST_CHECK(wtq_api_session_create(&good, &ok) == WTQ_OK);
    WTQ_TEST_CHECK(wtq_api_session_start(ok, 1000) == WTQ_OK);
    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    WTQ_TEST_CHECK(wtq_api_session_connect(ok, NULL) ==
                   WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(wtq_api_session_connect(ok, &cc) ==
                   WTQ_ERR_INVALID_ARG); /* missing authority/path */
    cc.authority = "a";
    cc.path = "/";
    WTQ_TEST_CHECK(wtq_api_session_connect(ok, &cc) == WTQ_OK);
    wtq_session_release(ok);
    WTQ_TEST_CHECK(ca.allocs == ca.frees);
    *fp += failures;
}

/* --- allocation accounting ------------------------------------------------ */

/* Exactly two allocations per session (the session object and the
 * engine connection), both at create; nothing afterwards. */
static void test_allocation_budget(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    WTQ_TEST_CHECK(r.ca.allocs == 2);

    /* steady state: datagrams both ways, close — still 2 */
    static const uint8_t p[8] = { 0 };
    wtq_span_t span = { p, 8 };
    uint8_t dg[4] = { 0x00, 1, 2, 3 };
    for (int i = 0; i < 50; i++) {
        r.drv.dgram_count = 0;
        WTQ_TEST_CHECK(wtq_session_send_datagram(r.s, &span, 1) ==
                       WTQ_OK);
        WTQ_TEST_CHECK(wtq_conn_on_datagram(wtq_api_session_conn(r.s),
                                            dg, 4, 3000 + i) == WTQ_OK);
    }
    WTQ_TEST_CHECK(wtq_session_close(r.s, 0, NULL, 0) == WTQ_OK);
    WTQ_TEST_CHECK(r.ca.allocs == 2);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- refcounts ------------------------------------------------------------ */

static void test_session_refcount(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    /* retain twice; the object must survive until the LAST release */
    wtq_session_add_ref(r.s);
    wtq_session_add_ref(r.s);
    wtq_session_release(r.s);
    /* still valid: queries work */
    WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    wtq_session_release(r.s);
    WTQ_TEST_CHECK(r.ca.frees == 0); /* creator's ref still held */
    wtq_session_release(r.s);
    r.s = NULL;
    WTQ_TEST_CHECK(r.ca.allocs == r.ca.frees);
    rig_down(&r, fp);
    *fp += failures;
}

/* Releasing the last ref from inside the terminal callback is legal:
 * the free is deferred until the callback stack unwinds. */
static void test_release_from_callback(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.lg.release_session_in_closed = true;
    /* peer FIN ends the session; on_closed releases the only ref.
     * The backend bracket is what makes that legal: the destroy is
     * deferred past the engine frames and happens at leave(). */
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    wtq_api_session_enter(r.s);
    (void)wtq_conn_on_stream_bytes(conn, r.sess_es, NULL, 0, true, 3000);
    WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 1);
    WTQ_TEST_CHECK(r.ca.frees == 0); /* still alive inside the bracket */
    WTQ_TEST_CHECK(wtq_api_session_leave(r.s)); /* destroyed HERE */
    WTQ_TEST_CHECK(r.ca.allocs == r.ca.frees);
    r.s = NULL;
    *fp += failures;
}

/* Releasing the final ref inside on_closed and re-adding one cancels
 * the deferred destruction: the outer leave reports NOT destroyed, the
 * dead-but-valid session stays queryable, and the later final release
 * frees exactly once. */
static void test_resurrect_in_closed(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    r.lg.resurrect_in_closed = true;
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    wtq_api_session_enter(r.s);
    (void)wtq_conn_on_stream_bytes(conn, r.sess_es, NULL, 0, true, 3000);
    WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 1);
    bool destroyed = wtq_api_session_leave(r.s);
    WTQ_TEST_CHECK(!destroyed);
    WTQ_TEST_CHECK(r.ca.frees == 0);
    if (destroyed || r.ca.frees != 0) {
        /* freed under the re-added ref: do not touch it again */
        r.s = NULL;
        *fp += failures;
        return;
    }
    WTQ_TEST_CHECK(wtq_session_status(r.s) == WTQ_SESSION_STATUS_CLOSED);
    wtq_session_release(r.s); /* the re-added ref was the last one */
    r.s = NULL;
    WTQ_TEST_CHECK(r.ca.allocs == r.ca.frees); /* freed exactly once */
    *fp += failures;
}

/* Release-then-reacquire inside on_established: the session must be
 * fully operational after the callback. */
static void test_resurrect_in_established(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    do_connect(&r, fp);
    deliver_peer_settings(&r, fp);
    r.sess_ds = find_local_bidi(&r);
    WTQ_TEST_CHECK(r.sess_ds != NULL && r.sess_ds->ectx != NULL);
    if (r.sess_ds == NULL) {
        *fp += failures + 1;
        return;
    }
    r.sess_es = r.sess_ds->ectx;
    r.lg.resurrect_in_established = true;

    uint8_t resp[256];
    size_t rlen = build_response(resp, sizeof(resp), 200, "moqt-18");
    wtq_api_session_enter(r.s);
    (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s), r.sess_es,
                                   resp, rlen, false, 2000);
    WTQ_TEST_CHECK(ev_count(&r.lg, "established") == 1);
    bool destroyed = wtq_api_session_leave(r.s);
    WTQ_TEST_CHECK(!destroyed);
    WTQ_TEST_CHECK(r.ca.frees == 0);
    if (destroyed || r.ca.frees != 0) {
        r.s = NULL;
        *fp += failures;
        return;
    }
    WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                   WTQ_SESSION_STATUS_ESTABLISHED);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_OK);
    rig_down(&r, fp);
    *fp += failures;
}

/* --- terminal events + ordering ------------------------------------------- */

static void test_established_then_closed_ordering(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    WTQ_TEST_CHECK(ev_count(&r.lg, "established") == 1);
    WTQ_TEST_CHECK_EQ_SIZE(r.lg.subprotocol_len, 7);
    WTQ_TEST_CHECK(memcmp(r.lg.subprotocol, "moqt-18", 7) == 0);

    /* peer drain then close */
    /* draining rides the session stream via the engine seam */
    uint8_t drain_frame[16];
    /* DATA frame carrying the drain message, built via the engine's
     * own encoder on the peer side is overkill here: reuse the close
     * path instead — drain is covered by the pair test. Close: */
    (void)drain_frame;
    WTQ_TEST_CHECK(wtq_session_close(r.s, 42, (const uint8_t *)"bye", 3) ==
                   WTQ_OK);
    WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 1);
    WTQ_TEST_CHECK(r.lg.closed_code == 42);
    WTQ_TEST_CHECK_EQ_SIZE(r.lg.closed_reason_len, 3);
    WTQ_TEST_CHECK(r.lg.closed_clean);
    WTQ_TEST_CHECK(ev_index(&r.lg, "established") <
                   ev_index(&r.lg, "closed"));
    WTQ_TEST_CHECK(wtq_session_status(r.s) == WTQ_SESSION_STATUS_CLOSED);

    /* dead-but-valid: operations refuse, queries keep working */
    WTQ_TEST_CHECK(wtq_session_close(r.s, 0, NULL, 0) == WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK(wtq_session_drain(r.s) == WTQ_ERR_CLOSED);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_uni(r.s, &st) == WTQ_ERR_CLOSED);
    wtq_span_t sp = { (const uint8_t *)"x", 1 };
    WTQ_TEST_CHECK(wtq_session_send_datagram(r.s, &sp, 1) ==
                   WTQ_ERR_CLOSED);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_refused(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    do_connect(&r, fp);
    deliver_peer_settings(&r, fp);
    struct wtq_dstream *bidi = find_local_bidi(&r);
    WTQ_TEST_CHECK(bidi != NULL && bidi->ectx != NULL);
    if (bidi != NULL) {
        uint8_t resp[256];
        size_t rlen = build_response(resp, sizeof(resp), 404, NULL);
        (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s),
                                       bidi->ectx, resp, rlen, false,
                                       2000);
    }
    WTQ_TEST_CHECK(ev_count(&r.lg, "refused") == 1);
    WTQ_TEST_CHECK(r.lg.ev[ev_index(&r.lg, "refused")].a == 404);
    WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 0);
    WTQ_TEST_CHECK(wtq_session_status(r.s) == WTQ_SESSION_STATUS_FAILED);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_failed_no_wt(int *fp)
{
    int failures = 0;
    rig_t r;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    do_connect(&r, fp);
    /* SETTINGS without WebTransport support */
    uint8_t buf[8] = { 0x00, 0x04, 0x02, 0x01, 0x00 };
    wtq_conn_t *conn = wtq_api_session_conn(r.s);
    struct wtq_dstream *ds = fake_driver_add_peer_stream(&r.drv, 3);
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK(wtq_conn_on_peer_uni_opened(conn, ds, 3, &es) ==
                   WTQ_OK);
    (void)wtq_conn_on_stream_bytes(conn, es, buf, 5, false, 1500);
    WTQ_TEST_CHECK(ev_count(&r.lg, "failed") == 1);
    WTQ_TEST_CHECK(r.lg.ev[ev_index(&r.lg, "failed")].a ==
                   WTQ_CONNECT_FAILURE_NO_WT_SUPPORT);
    WTQ_TEST_CHECK(wtq_session_status(r.s) == WTQ_SESSION_STATUS_FAILED);
    rig_down(&r, fp);
    *fp += failures;
}

/* A transport/protocol failure before establishment maps to on_failed
 * (CONNECTION), and one after establishment folds into the single
 * on_closed (unclean) — never two terminal events. */
static void test_connection_failure_terminals(int *fp)
{
    int failures = 0;

    /* before establishment */
    {
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        do_connect(&r, fp);
        wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 0, true, 2000);
        WTQ_TEST_CHECK(ev_count(&r.lg, "failed") == 1);
        WTQ_TEST_CHECK(r.lg.ev[ev_index(&r.lg, "failed")].a ==
                       WTQ_CONNECT_FAILURE_CONNECTION);
        WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 0);
        WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                       WTQ_SESSION_STATUS_FAILED);
        rig_down(&r, fp);
    }
    /* after establishment */
    {
        rig_t r;
        establish_client(&r, fp);
        wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 0, true, 3000);
        WTQ_TEST_CHECK(ev_count(&r.lg, "closed") == 1);
        WTQ_TEST_CHECK(!r.lg.closed_clean);
        WTQ_TEST_CHECK(ev_count(&r.lg, "failed") == 0);
        WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                       WTQ_SESSION_STATUS_CLOSED);
        rig_down(&r, fp);
    }
    *fp += failures;
}

/* --- datagrams ------------------------------------------------------------ */

/* Receive is callback-borrowed zero-copy (pointer into the received
 * buffer); send is byte-exact on the wire. */
static void test_datagram_lifetime(int *fp)
{
    int failures = 0;
    rig_t r;

    establish_client(&r, fp);
    uint8_t dg[5] = { 0x00, 'd', 'a', 't', 'a' };
    WTQ_TEST_CHECK(wtq_conn_on_datagram(wtq_api_session_conn(r.s), dg, 5,
                                        3000) == WTQ_OK);
    WTQ_TEST_CHECK(ev_count(&r.lg, "datagram") == 1);
    WTQ_TEST_CHECK(r.lg.dgram_ptr == dg + 1); /* zero copy */
    WTQ_TEST_CHECK_EQ_SIZE(r.lg.dgram_len, 4);
    WTQ_TEST_CHECK(memcmp(r.lg.dgram_bytes, "data", 4) == 0);

    static const uint8_t a[2] = { 'h', 'i' };
    wtq_span_t span = { a, 2 };
    WTQ_TEST_CHECK(wtq_session_send_datagram(r.s, &span, 1) == WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(r.drv.dgram_count, 1);
    WTQ_TEST_CHECK(memcmp(r.drv.dgrams[0].bytes, "\x00hi", 3) == 0);

    WTQ_TEST_CHECK(wtq_session_datagram_max_size(r.s) == 1199);
    rig_down(&r, fp);
    *fp += failures;
}


/* wtq_api_session_start is one-shot too: a failed start consumes the
 * attempt, and every later call refuses without touching the driver. */
static void test_api_start_one_shot(int *fp)
{
    int failures = 0;

    /* failed start */
    {
        rig_t r;

        rig_up_nostart(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        r.drv.fail_open_at = 2; /* the QPACK encoder stream */
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_start(r.s, 1000),
                              WTQ_ERR_STREAM_LIMIT);
        int opens = r.drv.open_calls;
        int sends = r.drv.send_calls;

        r.drv.fail_open_at = 0;
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_start(r.s, 1100),
                              WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
        WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
        rig_down(&r, fp);
    }
    /* successful start, then a second call */
    {
        rig_t r;

        rig_up_nostart(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_start(r.s, 1000), WTQ_OK);
        int opens = r.drv.open_calls;
        int sends = r.drv.send_calls;
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_start(r.s, 1100),
                              WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT(r.drv.open_calls, opens);
        WTQ_TEST_CHECK_EQ_INT(r.drv.send_calls, sends);
        rig_down(&r, fp);
    }
    *fp += failures;
}


/* The public adapter emits exactly one WTQ_CONNECT_FAILURE_CONNECTION
 * for every pre-establishment connection death — never both failed and
 * closed — and the ENGINE (not the adapter's defensive fallback) is
 * what produced it: the engine's own session state reads FAILED. */
static void test_api_pre_establishment_conn_failure(int *fp)
{
    int failures = 0;

    for (int stage = 0; stage < 3; stage++) {
        rig_t r;

        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        if (stage >= 1)
            do_connect(&r, fp);            /* PENDING */
        if (stage == 2)
            deliver_peer_settings(&r, fp); /* SENT */

        wtq_conn_t *conn = wtq_api_session_conn(r.s);
        WTQ_TEST_CHECK(conn != NULL);
        wtq_conn_on_conn_closed(conn, 0x102, true, 2500);

        /* the engine gave the session its outcome */
        WTQ_TEST_CHECK(wtq_conn_session_state(conn) ==
                       WTQ_SESSION_FAILED);
        /* the adapter reported it once, as a connect failure */
        WTQ_TEST_CHECK_EQ_INT(ev_count(&r.lg, "failed"), 1);
        WTQ_TEST_CHECK(r.lg.ev[ev_index(&r.lg, "failed")].a ==
                       WTQ_CONNECT_FAILURE_CONNECTION);
        WTQ_TEST_CHECK_EQ_INT(ev_count(&r.lg, "closed"), 0);
        WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                       WTQ_SESSION_STATUS_FAILED);
        rig_down(&r, fp);
    }
    *fp += failures;
}


/* A long negotiated subprotocol survives the whole public path: the
 * on_established callback bytes/length and wtq_session_subprotocol().
 * No raw-length constant is assumed — the accepted boundary is probed,
 * for plain and for escape-heavy content. */
static void fill_sub(char *b, size_t n, int shape)
{
    for (size_t i = 0; i < n; i++) {
        if (shape == 1)
            b[i] = (i % 2) ? '"' : 'a';
        else if (shape == 2)
            b[i] = (i % 2) ? '\\' : 'a';
        else
            b[i] = (char)('a' + (i % 26));
    }
    b[n] = '\0';
}

/* Offer `proto` and return the connect rc (session left untouched on
 * rejection). */
static wtq_result_t api_offer_probe(const char *proto)
{
    rig_t r;
    int fp = 0;
    const char *const offer[] = { proto };
    wtq_connect_config_t cc;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, &fp);
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = offer;
    cc.subprotocol_count = 1;
    cc.require_subprotocol = true;
    wtq_result_t rc = wtq_api_session_connect(r.s, &cc);
    rig_down(&r, &fp);
    return rc;
}

/* Establish through the public API with `proto` and check every byte. */
static void api_establishes_with(const char *proto, size_t n, int *fp)
{
    int failures = 0;
    rig_t r;
    const char *const offer[] = { proto };
    wtq_connect_config_t cc;

    rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = offer;
    cc.subprotocol_count = 1;
    cc.require_subprotocol = true;
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_connect(r.s, &cc), WTQ_OK);
    deliver_peer_settings(&r, fp);

    r.sess_ds = find_local_bidi(&r);
    WTQ_TEST_CHECK(r.sess_ds != NULL && r.sess_ds->ectx != NULL);
    if (r.sess_ds == NULL || r.sess_ds->ectx == NULL) {
        rig_down(&r, fp);
        *fp += failures;
        return;
    }
    r.sess_es = r.sess_ds->ectx;
    uint8_t resp[1024];
    size_t rlen = build_response(resp, sizeof(resp), 200, proto);
    WTQ_TEST_CHECK(rlen > 0);
    (void)wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s), r.sess_es,
                                   resp, rlen, false, 2000);

    WTQ_TEST_CHECK_EQ_INT(ev_count(&r.lg, "established"), 1);
    WTQ_TEST_CHECK_EQ_INT(ev_count(&r.lg, "failed"), 0);
    WTQ_TEST_CHECK_EQ_SIZE(r.lg.subprotocol_len, n);
    WTQ_TEST_CHECK(memcmp(r.lg.subprotocol, proto, n) == 0);

    wtq_str_t sub = wtq_session_subprotocol(r.s);
    WTQ_TEST_CHECK_EQ_SIZE(sub.len, n);
    WTQ_TEST_CHECK(memcmp(sub.data, proto, n) == 0);
    rig_down(&r, fp);
    *fp += failures;
}

static void test_api_long_subprotocol(int *fp)
{
    int failures = 0;
    char buf[600];

    /* the old 128-byte buffer boundary, both sides of it */
    for (size_t n = 128; n <= 129; n++) {
        fill_sub(buf, n, 0);
        WTQ_TEST_CHECK_EQ_INT(api_offer_probe(buf), WTQ_OK);
        api_establishes_with(buf, n, fp);
    }

    /* per-shape accepted/rejected boundary through the public API */
    for (int shape = 0; shape < 3; shape++) {
        size_t bad = 0;

        for (size_t n = 1; n < 560; n++) {
            fill_sub(buf, n, shape);
            if (api_offer_probe(buf) != WTQ_OK) {
                bad = n;
                break;
            }
        }
        WTQ_TEST_CHECK(bad > 1);
        if (bad <= 1)
            continue;

        /* last accepted: exact bytes all the way to the public query */
        fill_sub(buf, bad - 1, shape);
        api_establishes_with(buf, bad - 1, fp);

        /* first rejected: TOO_LARGE (never INVALID_ARG), nothing sent */
        fill_sub(buf, bad, shape);
        rig_t r;
        rig_up(&r, WTQ_PERSPECTIVE_CLIENT, fp);
        size_t before = 0;
        for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
            if (r.drv.streams[i].in_use)
                before += r.drv.streams[i].len;
        const char *const offer[] = { buf };
        wtq_connect_config_t cc;
        wtq_connect_config_init(&cc);
        cc.authority = "example.com";
        cc.path = "/app";
        cc.subprotocols = offer;
        cc.subprotocol_count = 1;
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_connect(r.s, &cc),
                              WTQ_ERR_TOO_LARGE);
        WTQ_TEST_CHECK(wtq_session_status(r.s) ==
                       WTQ_SESSION_STATUS_CONNECTING);
        size_t after = 0;
        for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
            if (r.drv.streams[i].in_use)
                after += r.drv.streams[i].len;
        WTQ_TEST_CHECK_EQ_SIZE(after, before);
        rig_down(&r, fp);
    }
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_api_long_subprotocol(&failures);
    test_api_pre_establishment_conn_failure(&failures);
    test_api_start_one_shot(&failures);

    test_config_init(&failures);
    test_connect_profile_abi(&failures);
    test_events_struct_size_compat(&failures);
    test_events_partial_callback_zeroed(&failures);
    test_events_exact_size_heap(&failures);
    test_connect_serve_config_boundaries(&failures);
    test_config_rejection(&failures);
    test_allocation_budget(&failures);
    test_session_refcount(&failures);
    test_release_from_callback(&failures);
    test_resurrect_in_closed(&failures);
    test_resurrect_in_established(&failures);
    test_established_then_closed_ordering(&failures);
    test_refused(&failures);
    test_failed_no_wt(&failures);
    test_connection_failure_terminals(&failures);
    test_datagram_lifetime(&failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_api_session (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_api_session\n");
    return 0;
}
