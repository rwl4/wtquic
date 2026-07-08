#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wtq_apipair.h"
#include "wtq_scenario.h"

#include "api_internal.h"
#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/h3_err.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"

/*
 * The conformance scenario table: every scenario drives the public
 * wtquic API over the deterministic fake-transport rail. Each is
 * runnable by name, run across several seeds, and checked for
 * same-seed trace reproducibility, cross-seed semantic stability
 * (where deterministic), and an exact engine_errors count. A stable
 * subset carries a golden semantic hash.
 */

#define SC_OK 0
#define SC_FAIL 1

/* A scenario returns a failure count; it asserts with SC_CHECK. */
#define SC_CHECK(expr)                                                  \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #expr,      \
                    __FILE__, __LINE__);                                \
            failures++;                                                 \
        }                                                               \
    } while (0)

static const char *const OFFER2[] = { "moqt-18", "moqt-16" };
static const char *const SUPPORTED[] = { "moqt-16", "moqt-18" };

/* --- wire builders (for injection scenarios) ----------------------------- */

static size_t build_settings(uint8_t *dst, size_t cap, bool wt)
{
    wtq_h3_settings_encode_cfg_t scfg = { wt, false };
    size_t flen = 0;

    dst[0] = 0x00; /* control stream type */
    if (wtq_h3_settings_encode_frame(&scfg, dst + 1, cap - 1, &flen) != 0)
        return 0;
    return 1 + flen;
}

static size_t build_response(uint8_t *dst, size_t cap, uint16_t status,
                             const char *proto)
{
    uint8_t section[256];
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

static size_t build_preamble(uint8_t *dst, size_t cap, bool bidi,
                             uint64_t sid)
{
    size_t n = 0;

    if (wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                 : WTQ_PREAMBLE_KIND_UNI,
                            sid, dst, cap, &n) != 0)
        return 0;
    return n;
}

static size_t wrap_data(const uint8_t *payload, size_t plen, uint8_t *dst,
                        size_t cap)
{
    size_t hl = 0;

    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, plen, dst, cap,
                                   &hl) != 0)
        return 0;
    memcpy(dst + hl, payload, plen);
    return hl + plen;
}

/* --- single-sided client establishment (via injection) ------------------- */

/* Feed WT SETTINGS to the client and return its CONNECT-stream engine
 * context (the local bidi's ectx), after issuing the connect. */
static wtq_estream_t *client_bring_up(wtq_apipair_t *p, int require,
                                      int *fp)
{
    int failures = 0;
    wtq_connect_config_t cc;

    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER2;
    cc.subprotocol_count = 2;
    cc.require_subprotocol = require != 0;
    SC_CHECK(wtq_api_session_connect(p->c.s, &cc) == WTQ_OK);

    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream(p, 'c', 3, false, st, stl, false, 0);

    /* the CONNECT stream is now the client's only local bidi */
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi)
            bidi = &p->c.drv.streams[i];
    *fp += failures;
    return bidi != NULL ? bidi->ectx : NULL;
}

/* Deliver a HEADERS response onto the client's CONNECT stream. */
static void client_response(wtq_apipair_t *p, wtq_estream_t *es,
                            uint16_t status, const char *proto,
                            bool fin)
{
    uint8_t resp[256];
    size_t rl = build_response(resp, sizeof(resp), status, proto);

    (void)wtq_apipair_deliver(p, 'c', es, resp, rl, fin);
}

/* --- happy paths --------------------------------------------------------- */

static void serve_moq(wtq_apipair_t *p, bool require, int *fp)
{
    int failures = 0;
    wtq_serve_config_t path;

    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = SUPPORTED;
    path.subprotocol_count = 2;
    path.require_subprotocol = require;
    SC_CHECK(wtq_api_session_serve(p->s.s, &path, 1) == WTQ_OK);
    *fp += failures;
}

static void connect_moq(wtq_apipair_t *p, const char *path, bool require,
                        int *fp)
{
    int failures = 0;
    wtq_connect_config_t cc;

    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = path;
    cc.subprotocols = OFFER2;
    cc.subprotocol_count = 2;
    cc.require_subprotocol = require;
    SC_CHECK(wtq_api_session_connect(p->c.s, &cc) == WTQ_OK);
    *fp += failures;
}

static int sc_happy_connect(wtq_apipair_t *p)
{
    int failures = 0;

    serve_moq(p, false, &failures);
    connect_moq(p, "/app", false, &failures);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.established == 1);
    SC_CHECK(p->s.established == 1);
    SC_CHECK(p->c.sub_len == 7 && memcmp(p->c.sub, "moqt-18", 7) == 0);
    SC_CHECK(p->s.sub_len == 7 && memcmp(p->s.sub, "moqt-18", 7) == 0);
    return failures;
}

static int sc_no_wt_support(wtq_apipair_t *p)
{
    int failures = 0;

    connect_moq(p, "/app", false, &failures);
    uint8_t st[64];
    size_t stl = build_settings(st, sizeof(st), false); /* no WT */
    wtq_apipair_inject_stream(p, 'c', 3, false, st, stl, false, 0);
    SC_CHECK(p->c.failed == 1);
    SC_CHECK(p->c.failed_reason == WTQ_CONNECT_FAILURE_NO_WT_SUPPORT);
    SC_CHECK(wtq_session_status(p->c.s) == WTQ_SESSION_STATUS_FAILED);
    return failures;
}

static int sc_no_subprotocol_required(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_serve_config_t path;
    static const char *const only_x[] = { "other-proto" };

    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = only_x;
    path.subprotocol_count = 1;
    path.require_subprotocol = true;
    SC_CHECK(wtq_api_session_serve(p->s.s, &path, 1) == WTQ_OK);
    connect_moq(p, "/app", true, &failures);
    wtq_apipair_pump(p);
    /* server has no overlap under require -> 400 -> client refused */
    SC_CHECK(p->c.refused == 1);
    SC_CHECK(p->c.refused_status == 400);
    SC_CHECK(p->s.established == 0);
    return failures;
}

static int sc_server_404(wtq_apipair_t *p)
{
    int failures = 0;

    serve_moq(p, false, &failures);
    connect_moq(p, "/nope", false, &failures);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.refused == 1);
    SC_CHECK(p->c.refused_status == 404);
    SC_CHECK(p->s.established == 0);
    return failures;
}

/* --- session lifecycle --------------------------------------------------- */

static void establish_pair(wtq_apipair_t *p, int *fp)
{
    int failures = 0;

    serve_moq(p, false, fp);
    connect_moq(p, "/app", false, fp);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.established == 1 && p->s.established == 1);
    *fp += failures;
}

static int sc_drain_advisory(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    SC_CHECK(wtq_session_drain(p->s.s) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.draining == 1);
    SC_CHECK(wtq_session_status(p->c.s) == WTQ_SESSION_STATUS_DRAINING);
    /* traffic continues: a datagram still flows */
    wtq_span_t dg = { (const uint8_t *)"ok", 2 };
    SC_CHECK(wtq_session_send_datagram(p->c.s, &dg, 1) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.dgram_events == 1);
    return failures;
}

static int sc_close_capsule(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    SC_CHECK(wtq_session_close(p->c.s, 7, (const uint8_t *)"done", 4) ==
             WTQ_OK);
    SC_CHECK(p->c.closed == 1 && p->c.closed_clean);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.closed == 1);
    SC_CHECK(p->s.closed_code == 7);
    SC_CHECK(p->s.closed_reason_len == 4 &&
             memcmp(p->s.closed_reason, "done", 4) == 0);
    SC_CHECK(p->s.closed_clean);
    return failures;
}

static int sc_connect_fin_clean(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = client_bring_up(p, 0, &failures);

    SC_CHECK(es != NULL);
    client_response(p, es, 200, "moqt-18", false);
    SC_CHECK(p->c.established == 1);
    /* a bare FIN with no CLOSE capsule -> clean close, code 0, "" */
    (void)wtq_apipair_deliver(p, 'c', es, NULL, 0, true);
    SC_CHECK(p->c.closed == 1);
    SC_CHECK(p->c.closed_code == 0);
    SC_CHECK(p->c.closed_reason_len == 0);
    SC_CHECK(p->c.closed_clean);
    return failures;
}

static int sc_connect_reset_unclean(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = client_bring_up(p, 0, &failures);

    SC_CHECK(es != NULL);
    client_response(p, es, 200, "moqt-18", false);
    SC_CHECK(p->c.established == 1);
    (void)wtq_apipair_reset(p, 'c', es, 0x10b);
    SC_CHECK(p->c.closed == 1);
    SC_CHECK(!p->c.closed_clean);
    return failures;
}

static int sc_malformed_capsule(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = client_bring_up(p, 0, &failures);

    SC_CHECK(es != NULL);
    client_response(p, es, 200, "moqt-18", false);
    SC_CHECK(p->c.established == 1);
    /* CLOSE capsule with a 2-byte payload (< the 32-bit code) */
    uint8_t payload[8];
    size_t hl = 0;
    SC_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_CLOSE_SESSION, 2,
                                       payload, sizeof(payload), &hl) == 0);
    payload[hl] = 0x00;
    payload[hl + 1] = 0x01;
    uint8_t wire[32];
    size_t wl = wrap_data(payload, hl + 2, wire, sizeof(wire));
    (void)wtq_apipair_deliver(p, 'c', es, wire, wl, false);
    SC_CHECK(p->c.closed == 1 && !p->c.closed_clean);
    SC_CHECK(wtq_conn_close_code(wtq_api_session_conn(p->c.s)) ==
             WTQ_H3_MESSAGE_ERROR);
    return failures;
}

/* --- WT streams ---------------------------------------------------------- */

static int sc_peer_uni_data(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    /* server opens a WT uni toward the client and sends "hello" + FIN */
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->s.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"hello", 5 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.stream_opened == 1 && !p->c.last_stream_bidi);
    SC_CHECK(p->c.data_len == 5 && memcmp(p->c.data, "hello", 5) == 0);
    SC_CHECK(p->c.fin_events == 1);
    SC_CHECK(p->c.stream_closed == 1);
    return failures;
}

static int sc_bidi_ping_pong(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    p->s.echo_bidi = true; /* server echoes "pong" from on_stream_data */
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_bidi(p->c.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"ping", 4 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.stream_opened == 1 && p->s.last_stream_bidi);
    SC_CHECK(p->s.data_len == 4 && memcmp(p->s.data, "ping", 4) == 0);
    SC_CHECK(p->c.data_len == 4 && memcmp(p->c.data, "pong", 4) == 0);
    SC_CHECK(p->c.stream_closed == 1 && p->s.stream_closed == 1);
    return failures;
}

static int sc_peer_reset_maps_code(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    SC_CHECK(p->c.established == 1);
    /* inject a peer WT uni, then reset it with a mapped app code */
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 0);
    wtq_apipair_inject_stream(p, 'c', 7, false, pre, pl, false, 0);
    SC_CHECK(p->c.stream_opened == 1);
    /* the peer-side dstream slot for id 7 carries the engine ctx */
    wtq_estream_t *es = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && !p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].id == 7)
            es = p->c.drv.streams[i].ectx;
    SC_CHECK(es != NULL);
    if (es != NULL)
        (void)wtq_apipair_reset(p, 'c', es, wtq_app_error_to_h3(1234));
    SC_CHECK(p->c.stream_reset == 1);
    SC_CHECK(p->c.last_reset_code == 1234);
    SC_CHECK(p->c.stream_closed == 1);
    return failures;
}

static int sc_peer_stop_maps_code(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    SC_CHECK(p->c.established == 1);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    struct wtq_dstream *uni = fake_driver_local(&p->c.drv, 4);
    SC_CHECK(uni != NULL && uni->ectx != NULL);
    if (uni != NULL && uni->ectx != NULL)
        (void)wtq_apipair_stop(p, 'c', uni->ectx,
                               wtq_app_error_to_h3(42));
    SC_CHECK(p->c.stream_stop == 1);
    SC_CHECK(p->c.last_stop_code == 42);
    return failures;
}

static int sc_local_send_fin(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"bye", 3 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, &cookie) ==
             WTQ_OK);
    /* send-fin was the only direction -> stream terminal */
    SC_CHECK(p->c.stream_closed == 1);
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_api_session_conn(p->c.s)) == 1);
    SC_CHECK(p->c.send_completions == 1 && p->c.send_cancels == 0);
    return failures;
}

static int sc_local_reset_cancels_send(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"pending", 7 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) == WTQ_OK);
    SC_CHECK(wtq_stream_reset(st, 5) == WTQ_OK);
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_api_session_conn(p->c.s)) == 1);
    SC_CHECK(p->c.send_completions == 1 && p->c.send_cancels == 1);
    return failures;
}

static int sc_close_cancels_sends(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"pending", 7 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) == WTQ_OK);
    SC_CHECK(wtq_session_close(p->c.s, 0, NULL, 0) == WTQ_OK);
    SC_CHECK(p->c.stream_closed == 1 && p->c.closed == 1);
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_api_session_conn(p->c.s)) == 1);
    SC_CHECK(p->c.send_completions == 1 && p->c.send_cancels == 1);
    return failures;
}

/* --- datagrams ----------------------------------------------------------- */

static int sc_datagrams_both_ways(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    wtq_span_t up = { (const uint8_t *)"dg-c", 4 };
    wtq_span_t dn = { (const uint8_t *)"dg-s", 4 };
    SC_CHECK(wtq_session_send_datagram(p->c.s, &up, 1) == WTQ_OK);
    SC_CHECK(wtq_session_send_datagram(p->s.s, &dn, 1) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.dgram_events == 1 &&
             memcmp(p->s.dgram, "dg-c", 4) == 0);
    SC_CHECK(p->c.dgram_events == 1 &&
             memcmp(p->c.dgram, "dg-s", 4) == 0);
    return failures;
}

static int sc_datagram_unknown_dropped(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    /* a datagram for quarter-stream-id 1 (not this session's 0) */
    uint8_t dg[3] = { 0x01, 'n', 'o' };
    SC_CHECK(wtq_apipair_inject_datagram(p, 'c', dg, 3) == WTQ_OK);
    SC_CHECK(p->c.dgram_events == 0);
    SC_CHECK(wtq_conn_dgrams_dropped(wtq_api_session_conn(p->c.s)) == 1);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    return failures;
}

static int sc_datagram_malformed(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    uint8_t dg[1] = { 0x40 }; /* truncated qsid varint */
    SC_CHECK(wtq_apipair_inject_datagram(p, 'c', dg, 1) == WTQ_ERR_PROTO);
    SC_CHECK(wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    SC_CHECK(wtq_conn_close_code(wtq_api_session_conn(p->c.s)) ==
             WTQ_H3_DATAGRAM_ERROR);
    SC_CHECK(p->engine_errors == 1);
    return failures;
}

static int sc_datagram_zero_len(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    uint8_t dg[1] = { 0x00 }; /* qsid 0, empty payload */
    SC_CHECK(wtq_apipair_inject_datagram(p, 'c', dg, 1) == WTQ_OK);
    SC_CHECK(p->c.dgram_events == 1);
    SC_CHECK(p->c.dgram_len == 0);
    return failures;
}

/* A peer uni that ends (bare FIN, no bytes) before its stream header:
 * tolerated per RFC 9114 s6.2, no WT stream, no error. Exercises the
 * inject_stream(NULL, 0, fin) path under ASan/UBSan. */
static int sc_empty_stream_fin(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    wtq_apipair_inject_stream(p, 'c', 7, false, NULL, 0, true, 0);
    SC_CHECK(p->c.stream_opened == 0);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    return failures;
}

/* --- split-boundary demux ------------------------------------------------ */

static int sc_preamble_split_uni(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    uint8_t wire[16];
    size_t pl = build_preamble(wire, sizeof(wire), false, 0);
    memcpy(wire + pl, "hi", 2);
    /* one byte at a time: stream opens only after the full preamble */
    wtq_apipair_inject_stream(p, 'c', 7, false, wire, pl + 2, true, 1);
    SC_CHECK(p->c.stream_opened == 1);
    SC_CHECK(p->c.data_len == 2 && memcmp(p->c.data, "hi", 2) == 0);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    return failures;
}

static int sc_preamble_split_bidi(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    uint8_t wire[16];
    size_t pl = build_preamble(wire, sizeof(wire), true, 0);
    memcpy(wire + pl, "yo", 2);
    wtq_apipair_inject_stream(p, 'c', 1, true, wire, pl + 2, false, 1);
    SC_CHECK(p->c.stream_opened == 1 && p->c.last_stream_bidi);
    SC_CHECK(p->c.data_len == 2 && memcmp(p->c.data, "yo", 2) == 0);
    return failures;
}

static int sc_response_split(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = client_bring_up(p, 0, &failures);
    uint8_t resp[256];
    size_t rl = build_response(resp, sizeof(resp), 200, "moqt-18");

    SC_CHECK(es != NULL);
    /* one byte at a time */
    for (size_t i = 0; i < rl; i++)
        (void)wtq_apipair_deliver(p, 'c', es, resp + i, 1, false);
    SC_CHECK(p->c.established == 1);
    return failures;
}

static int sc_settings_split(wtq_apipair_t *p)
{
    int failures = 0;

    connect_moq(p, "/app", false, &failures);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    /* SETTINGS delivered one byte at a time */
    wtq_apipair_inject_stream(p, 'c', 3, false, st, stl, false, 1);
    /* the CONNECT was deferred until settings proved WT; now it exists */
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi)
            bidi = &p->c.drv.streams[i];
    SC_CHECK(bidi != NULL);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    return failures;
}

/* --- protocol-error demux ------------------------------------------------ */

static int sc_second_connect_rejected(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    /* a second CONNECT request stream on the server: reset, first
     * session untouched */
    uint8_t req[512];
    uint8_t section[512];
    size_t slen = 0;
    wtq_sf_str_t offer = { "moqt-18", 7 };
    SC_CHECK(wtq_connect_encode_request("example.com", 11, "/app", 4, NULL,
                                        0, &offer, 1, section,
                                        sizeof(section), &slen) == 0);
    size_t hl = 0;
    SC_CHECK(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, req,
                                        sizeof(req), &hl) == 0);
    memcpy(req + hl, section, slen);
    wtq_apipair_inject_stream(p, 's', 4, true, req, hl + slen, false, 0);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->s.s)));
    SC_CHECK(p->s.established == 1); /* first session intact */
    /* the second request stream was reset with REQUEST_REJECTED */
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->s.drv.streams[i].in_use && p->s.drv.streams[i].id == 4)
            ds = &p->s.drv.streams[i];
    SC_CHECK(ds != NULL && ds->reset);
    if (ds != NULL)
        SC_CHECK(ds->reset_err == WTQ_H3_REQUEST_REJECTED);
    return failures;
}

static int sc_server_bidi_to_client(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    /* a non-WT server-initiated bidi at the client -> creation error */
    uint8_t headers[2] = { 0x01, 0x00 };
    wtq_apipair_inject_stream(p, 'c', 1, true, headers, 2, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    SC_CHECK(wtq_conn_close_code(wtq_api_session_conn(p->c.s)) ==
             WTQ_H3_STREAM_CREATION_ERROR);
    SC_CHECK(p->engine_errors >= 1);
    return failures;
}

static int sc_invalid_session_id(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    /* a WT uni preamble with session id 1 (not a client bidi id) */
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 1);
    wtq_apipair_inject_stream(p, 'c', 7, false, pre, pl, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_api_session_conn(p->c.s)));
    SC_CHECK(wtq_conn_close_code(wtq_api_session_conn(p->c.s)) ==
             WTQ_H3_ID_ERROR);
    SC_CHECK(p->engine_errors >= 1);
    return failures;
}

/* --- handle lifetime ----------------------------------------------------- */

static int sc_pool_exhaustion(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    /* saturate the API handle pool with retained terminal handles */
    size_t n = 0;
    for (; n < 16; n++) {
        wtq_stream_t *st = NULL;
        if (wtq_session_open_uni(p->c.s, &st) != WTQ_OK || st == NULL)
            break;
        wtq_stream_add_ref(st);
        if (p->c.retained_count < FAKE_MAX_STREAMS)
            p->c.retained[p->c.retained_count++] = st;
        (void)wtq_stream_reset(st, 0);
    }
    SC_CHECK(n == 16);
    wtq_stream_t *extra = NULL;
    SC_CHECK(wtq_session_open_bidi(p->c.s, &extra) == WTQ_ERR_STREAM_LIMIT);
    /* the engine bidi it opened was torn down BOTH directions */
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi && p->c.drv.streams[i].reset)
            ds = &p->c.drv.streams[i];
    SC_CHECK(ds != NULL);
    if (ds != NULL)
        SC_CHECK(ds->reset && ds->stopped);
    return failures;
}

static int sc_retained_dead_but_valid(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    p->c.retain_streams = true;
    /* server sends a uni; the client retains it, then it terminals */
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->s.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.stream_opened == 1);
    SC_CHECK(p->c.stream_closed == 1);
    /* the retained handle is dead-but-valid: queries work, ops refuse */
    SC_CHECK(p->c.retained_count == 1);
    if (p->c.retained_count == 1) {
        wtq_stream_t *held = p->c.retained[0];
        SC_CHECK(wtq_stream_session(held) == p->c.s);
        wtq_span_t sp = { (const uint8_t *)"y", 1 };
        SC_CHECK(wtq_stream_send(held, &sp, 1, 0, NULL) == WTQ_ERR_CLOSED);
    }
    return failures;
}

static int sc_reentrant_close_in_data(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    p->s.close_in_data = true;
    p->s.behavior_code = 9;
    /* client uni delivers data; the server closes the session from
     * inside its data callback */
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"z", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.closed == 1);
    SC_CHECK(p->s.closed_code == 9);
    SC_CHECK(!wtq_conn_is_closed(wtq_api_session_conn(p->s.s)) ||
             p->s.closed == 1);
    return failures;
}

/* --- connection failure terminals ---------------------------------------- */

static int sc_conn_close_pre_establish(wtq_apipair_t *p)
{
    int failures = 0;

    connect_moq(p, "/app", false, &failures);
    wtq_apipair_conn_closed(p, 'c', 0);
    SC_CHECK(p->c.failed == 1);
    SC_CHECK(p->c.failed_reason == WTQ_CONNECT_FAILURE_CONNECTION);
    SC_CHECK(p->c.closed == 0);
    return failures;
}

static int sc_conn_close_post_establish(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    wtq_apipair_conn_closed(p, 'c', 0);
    SC_CHECK(p->c.closed == 1 && !p->c.closed_clean);
    SC_CHECK(p->c.failed == 0);
    return failures;
}

static int sc_duplicate_terminal_suppressed(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    SC_CHECK(wtq_session_close(p->c.s, 1, NULL, 0) == WTQ_OK);
    SC_CHECK(p->c.closed == 1);
    /* a subsequent connection close must NOT fire a second terminal */
    wtq_apipair_conn_closed(p, 'c', 0);
    SC_CHECK(p->c.closed == 1);
    return failures;
}

static int sc_send_rejected_no_completion(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *ces = client_bring_up(p, 0, &failures);

    SC_CHECK(ces != NULL);
    client_response(p, ces, 200, "moqt-18", false);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    p->c.drv.fail_send = true; /* transport refuses */
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
             WTQ_ERR_WOULD_BLOCK);
    p->c.drv.fail_send = false;
    /* a rejected send fires NO completion */
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_api_session_conn(p->c.s)) == 0);
    SC_CHECK(p->c.send_completions == 0);
    return failures;
}

/* --- allocation snapshot ------------------------------------------------- */

static int sc_zero_alloc_steady(wtq_apipair_t *p)
{
    int failures = 0;

    establish_pair(p, &failures);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_bidi(p->c.s, &st) == WTQ_OK);
    /* snapshot after setup: the steady-state stream/datagram path must
     * not allocate (both sessions share the rail's counting allocator) */
    int allocs_before = p->allocs;
    for (int i = 0; i < 50; i++) {
        wtq_span_t span = { (const uint8_t *)"chunk", 5 };
        SC_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_OK);
        (void)fake_driver_complete_sends(&p->c.drv,
                                         wtq_api_session_conn(p->c.s));
        wtq_span_t dg = { (const uint8_t *)"d", 1 };
        p->c.drv.dgram_count = 0;
        SC_CHECK(wtq_session_send_datagram(p->c.s, &dg, 1) == WTQ_OK);
        uint8_t rxdg[2] = { 0x00, 'x' };
        SC_CHECK(wtq_apipair_inject_datagram(p, 'c', rxdg, 2) == WTQ_OK);
    }
    SC_CHECK(p->allocs == allocs_before); /* zero steady-state allocs */
    SC_CHECK(p->engine_errors == 0);
    return failures;
}

/* --- the table ----------------------------------------------------------- */

static const wtq_scenario_t SCENARIOS[] = {
    { "happy_connect", sc_happy_connect, 0, true, 0xfa021ecb98cdccf5 },
    { "no_wt_support", sc_no_wt_support, 0, true, 0xd969073b581fc3ac },
    { "no_subprotocol_required", sc_no_subprotocol_required, 0, true, 0 },
    { "server_404", sc_server_404, 0, true, 0xfa756b87742987b6 },
    { "drain_advisory", sc_drain_advisory, 0, true, 0 },
    { "close_capsule", sc_close_capsule, 0, true, 0x9ea05c0aa23ad375 },
    { "connect_fin_clean", sc_connect_fin_clean, 0, true, 0 },
    { "connect_reset_unclean", sc_connect_reset_unclean, 0, true, 0 },
    { "malformed_capsule", sc_malformed_capsule, 1, true, 0 },
    /* stream payload is chunked by the seeded pump, so the number of
     * on_stream_data callbacks (hence the trace) varies by seed; the
     * assembled outcome is asserted in the body and IS seed-stable */
    { "peer_uni_data", sc_peer_uni_data, 0, false, 0 },
    { "bidi_ping_pong", sc_bidi_ping_pong, 0, false, 0 },
    { "peer_reset_maps_code", sc_peer_reset_maps_code, 0, true, 0 },
    { "peer_stop_maps_code", sc_peer_stop_maps_code, 0, true, 0 },
    { "local_send_fin", sc_local_send_fin, 0, true, 0 },
    { "local_reset_cancels_send", sc_local_reset_cancels_send, 0, true, 0 },
    { "close_cancels_sends", sc_close_cancels_sends, 0, true, 0 },
    { "datagrams_both_ways", sc_datagrams_both_ways, 0, true, 0 },
    { "datagram_unknown_dropped", sc_datagram_unknown_dropped, 0, true, 0 },
    { "datagram_malformed", sc_datagram_malformed, 1, true, 0xbaa29a9bf2f04696 },
    { "datagram_zero_len", sc_datagram_zero_len, 0, true, 0 },
    { "empty_stream_fin", sc_empty_stream_fin, 0, true, 0 },
    { "preamble_split_uni", sc_preamble_split_uni, 0, true, 0 },
    { "preamble_split_bidi", sc_preamble_split_bidi, 0, true, 0 },
    { "response_split", sc_response_split, 0, true, 0 },
    { "settings_split", sc_settings_split, 0, true, 0 },
    { "second_connect_rejected", sc_second_connect_rejected, 0, true, 0 },
    { "server_bidi_to_client", sc_server_bidi_to_client, 1, true, 0 },
    { "invalid_session_id", sc_invalid_session_id, 1, true, 0xfc3c6d92b6b969e1 },
    { "pool_exhaustion", sc_pool_exhaustion, 0, true, 0 },
    { "retained_dead_but_valid", sc_retained_dead_but_valid, 0, true, 0 },
    { "reentrant_close_in_data", sc_reentrant_close_in_data, 0, true, 0 },
    { "conn_close_pre_establish", sc_conn_close_pre_establish, 0, true, 0 },
    { "conn_close_post_establish", sc_conn_close_post_establish, 0, true,
      0 },
    { "duplicate_terminal_suppressed", sc_duplicate_terminal_suppressed, 0,
      true, 0 },
    { "send_rejected_no_completion", sc_send_rejected_no_completion, 0,
      true, 0 },
    { "zero_alloc_steady", sc_zero_alloc_steady, 0, true, 0 },
};

#define SCENARIO_COUNT (sizeof(SCENARIOS) / sizeof(SCENARIOS[0]))

static const uint64_t SEEDS[] = { 0x1111, 0xBEEF, 0xD00DFEED };
#define SEED_COUNT (sizeof(SEEDS) / sizeof(SEEDS[0]))

int main(int argc, char **argv)
{
    return wtq_scenario_main(SCENARIOS, SCENARIO_COUNT, SEEDS, SEED_COUNT,
                             "conformance", argc, argv);
}
