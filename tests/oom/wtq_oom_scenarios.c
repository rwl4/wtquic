#include <stdio.h>
#include <string.h>

#include "wtq_apipair.h"
#include "wtq_fault_alloc.h"

#include "api_internal.h"
#include "fake_driver.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

/*
 * Fail-at-N OOM sweeps for the public-API / engine surface. wtquic
 * allocates exactly twice per session (the session object and the
 * engine connection), both at create; data paths allocate nothing.
 * So the sweep is complete, not sampled: for a create scenario it runs
 * fail-at-N for every N from 1 through the observed attempt count plus
 * a no-fail baseline, and every failed run must balance to zero with
 * no invalid/double free and a NULL output pointer. Steady-state
 * scenarios snapshot the attempt count after setup and assert it does
 * not move.
 */

#define SC_CHECK(expr)                                                  \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #expr,      \
                    __FILE__, __LINE__);                                \
            failures++;                                                 \
        }                                                               \
    } while (0)

static const char *const OFFER[] = { "moqt-18" };
static const char *const SUPPORTED[] = { "moqt-18" };

/* --- single-session helper ----------------------------------------------- */

typedef struct one_session {
    struct wtq_driver drv;
    wtq_session_t *s;
} one_session_t;

static wtq_result_t make_session(wtq_fault_alloc_t *fa, bool client,
                                 one_session_t *o)
{
    wtq_session_events_t ev;

    memset(o, 0, sizeof(*o));
    fake_driver_init(&o->drv, client);
    wtq_session_events_init(&ev);

    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_fault_alloc_vtable(fa),
        .perspective = client ? WTQ_PERSPECTIVE_CLIENT
                              : WTQ_PERSPECTIVE_SERVER,
        .events = &ev,
        .user = NULL,
        .drv = &o->drv,
        .ops = fake_driver_ops(),
    };
    return wtq_api_session_create(&cfg, &o->s);
}

/* --- wire builders (for the establish/fatal scenarios) ------------------- */

static size_t build_settings(uint8_t *dst, size_t cap)
{
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t flen = 0;

    dst[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&scfg, dst + 1, cap - 1, &flen) != 0)
        return 0;
    return 1 + flen;
}

static size_t build_response(uint8_t *dst, size_t cap)
{
    uint8_t section[256];
    size_t slen = 0;
    wtq_sf_str_t sel = { "moqt-18", 7 };

    if (wtq_connect_encode_response(200, &sel, section, sizeof(section),
                                    &slen) != 0)
        return 0;
    size_t hl = 0;
    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, section, slen);
    return hl + slen;
}

/* Establish the pair (no faults); the caller owns teardown. */
static int establish(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_serve_config_t path;
    wtq_connect_config_t cc;

    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = SUPPORTED;
    path.subprotocol_count = 1;
    SC_CHECK(wtq_api_session_serve(p->s.s, &path, 1) == WTQ_OK);
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    SC_CHECK(wtq_api_session_connect(p->c.s, &cc) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.established == 1 && p->s.established == 1);
    return failures;
}

/* Bring a single client session to established via injection; return
 * its CONNECT-stream engine ctx. */
static wtq_estream_t *established_client(wtq_apipair_t *p, int *fp)
{
    int failures = 0;
    wtq_connect_config_t cc;

    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    SC_CHECK(wtq_api_session_connect(p->c.s, &cc) == WTQ_OK);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st));
    wtq_apipair_inject_stream(p, 'c', 3, false, st, stl, false, 0);
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi)
            bidi = &p->c.drv.streams[i];
    wtq_estream_t *es = bidi != NULL ? bidi->ectx : NULL;
    if (es != NULL) {
        uint8_t resp[256];
        size_t rl = build_response(resp, sizeof(resp));
        (void)wtq_apipair_deliver(p, 'c', es, resp, rl, false);
    }
    SC_CHECK(p->c.established == 1);
    *fp += failures;
    return es;
}

/* --- create scenarios (sweep fail-at-N) ---------------------------------- */

static int oom_create_client(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    one_session_t o;
    wtq_result_t rc = make_session(fa, true, &o);

    if (rc == WTQ_OK) {
        SC_CHECK(o.s != NULL);
        wtq_session_release(o.s);
    } else {
        /* a failed create returns a defined error and a NULL handle */
        SC_CHECK(rc == WTQ_ERR_NOMEM);
        SC_CHECK(o.s == NULL);
    }
    return failures;
}

static int oom_create_server(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    one_session_t o;
    wtq_result_t rc = make_session(fa, false, &o);

    if (rc == WTQ_OK) {
        SC_CHECK(o.s != NULL);
        wtq_session_release(o.s);
    } else {
        SC_CHECK(rc == WTQ_ERR_NOMEM);
        SC_CHECK(o.s == NULL);
    }
    return failures;
}

static int oom_apipair_create(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;
    int rc = wtq_apipair_create_alloc(&p, 0x0011, wtq_fault_alloc_vtable(fa));

    if (rc == 0) {
        wtq_apipair_destroy(&p);
    } else {
        /* A failed create must clean up after itself: both sides NULL
         * and no leak, WITHOUT the caller calling destroy. The
         * allocator-balance check (in the runner) is what proves no
         * leak; this pins the caller-visible contract. */
        SC_CHECK(p.c.s == NULL);
        SC_CHECK(p.s.s == NULL);
    }
    return failures;
}

static int oom_establish_pair(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;
    int rc = wtq_apipair_create_alloc(&p, 0x0022, wtq_fault_alloc_vtable(fa));

    if (rc == 0) {
        failures += establish(&p);
        wtq_apipair_destroy(&p);
    } else {
        SC_CHECK(p.c.s == NULL && p.s.s == NULL);
    }
    return failures;
}

/* --- config scenarios (prove zero allocation) ---------------------------- */

static int oom_connect_config(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    one_session_t o;
    wtq_connect_config_t cc;

    SC_CHECK(make_session(fa, true, &o) == WTQ_OK);
    if (o.s == NULL)
        return failures + 1;
    SC_CHECK(wtq_api_session_start(o.s, 1000) == WTQ_OK);
    int before = fa->attempts;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    SC_CHECK(wtq_api_session_connect(o.s, &cc) == WTQ_OK);
    /* connect copies into the pre-allocated session; no allocation */
    SC_CHECK(fa->attempts == before);
    wtq_session_release(o.s);
    return failures;
}

static int oom_serve_config(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    one_session_t o;
    wtq_serve_config_t path;

    SC_CHECK(make_session(fa, false, &o) == WTQ_OK);
    if (o.s == NULL)
        return failures + 1;
    SC_CHECK(wtq_api_session_start(o.s, 1000) == WTQ_OK);
    int before = fa->attempts;
    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = SUPPORTED;
    path.subprotocol_count = 1;
    SC_CHECK(wtq_api_session_serve(o.s, &path, 1) == WTQ_OK);
    SC_CHECK(fa->attempts == before);
    wtq_session_release(o.s);
    return failures;
}

/* --- steady-state zero-alloc scenarios ----------------------------------- */

static int oom_stream_data_steady(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;

    SC_CHECK(wtq_apipair_create_alloc(&p, 0x0033,
                                      wtq_fault_alloc_vtable(fa)) == 0);
    failures += establish(&p);
    int before = fa->attempts;
    /* Every steady-state action must allocate nothing — including the
     * peer's RECEIVE path: open, send, DELIVER via the pump (which
     * exercises the server's stream-open, receive, datagram, and
     * completion callbacks), close, and deliver the close. */
    for (int i = 0; i < 10; i++) {
        wtq_stream_t *st = NULL;
        SC_CHECK(wtq_session_open_uni(p.c.s, &st) == WTQ_OK);
        wtq_span_t span = { (const uint8_t *)"ping", 4 };
        SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) ==
                 WTQ_OK);
        wtq_span_t dg = { (const uint8_t *)"dgm", 3 };
        SC_CHECK(wtq_session_send_datagram(p.c.s, &dg, 1) == WTQ_OK);
        wtq_apipair_pump(&p); /* bytes + datagram + completions cross */
        SC_CHECK(p.s.stream_opened == i + 1);
        SC_CHECK(p.s.dgram_events == i + 1);
    }
    /* the peer actually received the stream payload (10 x "ping") */
    SC_CHECK(p.s.data_len == 40);
    SC_CHECK(memcmp(p.s.data,
                    "pingpingpingpingpingpingpingpingpingping", 40) == 0);
    SC_CHECK(p.s.stream_closed == 10);
    SC_CHECK(p.s.dgram_len == 3 && memcmp(p.s.dgram, "dgm", 3) == 0);
    SC_CHECK(wtq_session_close(p.c.s, 0, NULL, 0) == WTQ_OK);
    wtq_apipair_pump(&p); /* the close crosses to the server */
    SC_CHECK(p.s.closed == 1);
    SC_CHECK(fa->attempts == before);
    wtq_apipair_destroy(&p);
    return failures;
}

static int oom_close_with_live_streams(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;

    SC_CHECK(wtq_apipair_create_alloc(&p, 0x0044,
                                      wtq_fault_alloc_vtable(fa)) == 0);
    failures += establish(&p);
    /* open streams with pending sends, then close: the teardown +
     * cancel path allocates nothing */
    wtq_stream_t *a = NULL, *b = NULL;
    SC_CHECK(wtq_session_open_uni(p.c.s, &a) == WTQ_OK);
    SC_CHECK(wtq_session_open_bidi(p.c.s, &b) == WTQ_OK);
    int c0 = 0, c1 = 0;
    wtq_span_t span = { (const uint8_t *)"pending", 7 };
    SC_CHECK(wtq_stream_send(a, &span, 1, 0, &c0) == WTQ_OK);
    SC_CHECK(wtq_stream_send(b, &span, 1, 0, &c1) == WTQ_OK);
    int before = fa->attempts;
    SC_CHECK(wtq_session_close(p.c.s, 1, (const uint8_t *)"x", 1) ==
             WTQ_OK);
    (void)fake_driver_complete_sends(&p.c.drv, wtq_apipair_conn(&p, 'c'));
    SC_CHECK(p.c.send_cancels == 2);
    SC_CHECK(fa->attempts == before);
    wtq_apipair_destroy(&p);
    return failures;
}

static int oom_protocol_fatal_teardown(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;

    SC_CHECK(wtq_apipair_create_alloc(&p, 0x0055,
                                      wtq_fault_alloc_vtable(fa)) == 0);
    wtq_estream_t *es = established_client(&p, &failures);
    (void)es;
    int before = fa->attempts;
    /* a truncated datagram qsid -> H3_DATAGRAM_ERROR fatal teardown */
    uint8_t dg[1] = { 0x40 };
    SC_CHECK(wtq_apipair_inject_datagram(&p, 'c', dg, 1) == WTQ_ERR_PROTO);
    SC_CHECK(p.c.closed == 1 && !p.c.closed_clean);
    SC_CHECK(fa->attempts == before);
    wtq_apipair_destroy(&p);
    return failures;
}

static int oom_retained_release(wtq_fault_alloc_t *fa)
{
    int failures = 0;
    static wtq_apipair_t p;

    SC_CHECK(wtq_apipair_create_alloc(&p, 0x0066,
                                      wtq_fault_alloc_vtable(fa)) == 0);
    failures += establish(&p);
    /* the server sends a uni; the client retains it, it terminals, and
     * releasing the dead-but-valid handle afterwards allocates nothing */
    p.c.retain_streams = true;
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p.s.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) == WTQ_OK);
    wtq_apipair_pump(&p);
    SC_CHECK(p.c.stream_closed == 1);
    SC_CHECK(p.c.retained_count == 1);
    int before = fa->attempts;
    /* wtq_apipair_destroy releases the retained handle + the session */
    wtq_apipair_destroy(&p);
    SC_CHECK(fa->attempts == before);
    return failures;
}

/* --- runner -------------------------------------------------------------- */

typedef int (*oom_fn)(wtq_fault_alloc_t *fa);

typedef struct oom_scenario {
    const char *name;
    oom_fn fn;
    bool sweep; /* true: sweep fail-at-N; false: single no-fail run */
} oom_scenario_t;

static const oom_scenario_t SCENARIOS[] = {
    { "create_client_session", oom_create_client, true },
    { "create_server_session", oom_create_server, true },
    { "apipair_create", oom_apipair_create, true },
    { "establish_pair", oom_establish_pair, true },
    { "connect_config", oom_connect_config, false },
    { "serve_config", oom_serve_config, false },
    { "stream_data_steady", oom_stream_data_steady, false },
    { "close_with_live_streams", oom_close_with_live_streams, false },
    { "protocol_fatal_teardown", oom_protocol_fatal_teardown, false },
    { "retained_stream_release", oom_retained_release, false },
};

#define SCENARIO_COUNT (sizeof(SCENARIOS) / sizeof(SCENARIOS[0]))

/* Run fn once at a given fault point; verify balance and no bad frees. */
static int run_at(const oom_scenario_t *sc, wtq_fault_alloc_t *fa,
                  int fail_at)
{
    int failures = 0;

    wtq_fault_alloc_arm(fa, fail_at, false);
    failures += sc->fn(fa);
    if (fa->live != 0) {
        fprintf(stderr, "  [%s] leak at fail_at=%d: live=%d bytes=%zu\n",
                sc->name, fail_at, fa->live, fa->live_bytes);
        failures++;
    }
    if (fa->errors != 0) {
        fprintf(stderr, "  [%s] alloc errors at fail_at=%d: %d\n",
                sc->name, fail_at, fa->errors);
        failures++;
    }
    return failures;
}

static int run_scenario(const oom_scenario_t *sc)
{
    static wtq_fault_alloc_t fa;
    int failures = 0;

    wtq_fault_alloc_init(&fa);
    /* baseline: no faults, observe the attempt count */
    failures += run_at(sc, &fa, 0);
    int maxn = fa.attempts;

    if (sc->sweep) {
        for (int n = 1; n <= maxn; n++)
            failures += run_at(sc, &fa, n);
    }
    /* steady-state scenarios are validated by their own attempt
     * snapshot inside fn during the baseline run */
    return failures;
}

int main(int argc, char **argv)
{
    int failures = 0;
    const char *filter = argc > 1 ? argv[1] : NULL;
    size_t ran = 0;

    for (size_t i = 0; i < SCENARIO_COUNT; i++) {
        if (filter != NULL && strcmp(filter, SCENARIOS[i].name) != 0)
            continue;
        int f = run_scenario(&SCENARIOS[i]);
        if (f > 0)
            fprintf(stderr, "FAIL scenario %s (%d)\n", SCENARIOS[i].name,
                    f);
        failures += f;
        ran++;
    }
    if (filter != NULL && ran == 0) {
        fprintf(stderr, "no scenario named '%s'\n", filter);
        return 2;
    }
    if (failures > 0) {
        fprintf(stderr, "FAILED: oom (%d across %zu scenarios)\n",
                failures, ran);
        return 1;
    }
    printf("PASS: oom (%zu scenarios)\n", ran);
    return 0;
}
