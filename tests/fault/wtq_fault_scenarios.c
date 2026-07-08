#include <stdio.h>
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
 * Seeded fault scenarios over the public-API rail: hostile transport
 * behavior and delivery boundaries, held to the same discipline as the
 * conformance suite (seeded reproducibility, semantic stability where
 * expected, exact engine-error accounting, allocator balance, ASan/
 * UBSan cleanliness). Split scenarios use the rail's seeded-chunk
 * injection so every seed cuts the wire at different offsets; every
 * outcome is still a stable set of semantic events.
 */

#define SC_CHECK(expr)                                                  \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #expr,      \
                    __FILE__, __LINE__);                                \
            failures++;                                                 \
        }                                                               \
    } while (0)

static const char *const OFFER[] = { "moqt-18", "moqt-16" };
static const char *const SUPPORTED[] = { "moqt-16", "moqt-18" };

/* --- wire builders ------------------------------------------------------- */

static size_t build_settings(uint8_t *dst, size_t cap, bool wt)
{
    wtq_h3_settings_encode_cfg_t scfg = { wt, false };
    size_t flen = 0;

    dst[0] = 0x00;
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

/* A HEADERS frame wrapping an invalid QPACK field section (a required
 * prefix that cannot decode). Deliberately malformed. */
static size_t build_headers_garbage(uint8_t *dst, size_t cap)
{
    const uint8_t garbage[] = { 0xff, 0xff, 0xff, 0xff };
    size_t hl = 0;

    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, sizeof(garbage),
                                   dst, cap, &hl) != 0)
        return 0;
    memcpy(dst + hl, garbage, sizeof(garbage));
    return hl + sizeof(garbage);
}

/* Build a control stream: type 0x00 + a valid SETTINGS frame + extra. */
static size_t build_control(uint8_t *dst, size_t cap, const uint8_t *extra,
                            size_t extra_len)
{
    size_t stl = build_settings(dst, cap, true);

    if (stl == 0 || stl + extra_len > cap)
        return 0;
    memcpy(dst + stl, extra, extra_len);
    return stl + extra_len;
}

/* --- establishment glue -------------------------------------------------- */

static int rail_serve(wtq_apipair_t *p, bool require)
{
    int failures = 0;
    wtq_serve_config_t path;

    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = SUPPORTED;
    path.subprotocol_count = 2;
    path.require_subprotocol = require;
    SC_CHECK(wtq_api_session_serve(p->s.s, &path, 1) == WTQ_OK);
    return failures;
}

static int rail_connect(wtq_apipair_t *p, const char *path, bool require)
{
    int failures = 0;
    wtq_connect_config_t cc;

    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = path;
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 2;
    cc.require_subprotocol = require;
    SC_CHECK(wtq_api_session_connect(p->c.s, &cc) == WTQ_OK);
    return failures;
}

static int rail_establish_pair(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_serve(p, false);
    failures += rail_connect(p, "/app", false);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.established == 1 && p->s.established == 1);
    return failures;
}

/* Bring a client up to peer-SETTINGS (CONNECT sent); return its
 * CONNECT-stream engine ctx. */
static wtq_estream_t *rail_bring_up(wtq_apipair_t *p, int *fp)
{
    int failures = 0;

    failures += rail_connect(p, "/app", false);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream(p, 'c', 3, false, st, stl, false, 0);
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi)
            bidi = &p->c.drv.streams[i];
    *fp += failures;
    return bidi != NULL ? bidi->ectx : NULL;
}

/* Bring a client all the way to established; return its CONNECT es. */
static wtq_estream_t *rail_established_client(wtq_apipair_t *p, int *fp)
{
    int failures = 0;
    wtq_estream_t *es = rail_bring_up(p, fp);

    if (es != NULL) {
        uint8_t resp[256];
        size_t rl = build_response(resp, sizeof(resp), 200, "moqt-18");
        (void)wtq_apipair_deliver(p, 'c', es, resp, rl, false);
    }
    SC_CHECK(p->c.established == 1);
    *fp += failures;
    return es;
}

/* --- split faults (seeded chunking) -------------------------------------- */

static int f_settings_split(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_connect(p, "/app", false);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream_seeded(p, 'c', 3, false, st, stl, false, 1);
    struct wtq_dstream *bidi = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].is_local &&
            p->c.drv.streams[i].is_bidi)
            bidi = &p->c.drv.streams[i];
    SC_CHECK(bidi != NULL);
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    return failures;
}

static int f_response_split(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_bring_up(p, &failures);

    SC_CHECK(es != NULL);
    uint8_t resp[256];
    size_t rl = build_response(resp, sizeof(resp), 200, "moqt-18");
    (void)wtq_apipair_deliver_seeded(p, 'c', es, resp, rl, false, 2);
    SC_CHECK(p->c.established == 1);
    return failures;
}

static int f_preamble_split_uni(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 0);
    wtq_apipair_inject_stream_seeded(p, 'c', 7, false, pre, pl, true, 3);
    SC_CHECK(p->c.stream_opened == 1);
    SC_CHECK(p->c.fin_events == 1);
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    return failures;
}

static int f_preamble_split_bidi(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), true, 0);
    wtq_apipair_inject_stream_seeded(p, 'c', 1, true, pre, pl, true, 4);
    SC_CHECK(p->c.stream_opened == 1 && p->c.last_stream_bidi);
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    return failures;
}

static int f_capsule_split(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t cap[64];
    size_t cl = 0;

    SC_CHECK(wtq_capsule_encode_close(9, (const uint8_t *)"bye", 3, cap,
                                      sizeof(cap), &cl) == 0);
    uint8_t wire[80];
    size_t wl = wrap_data(cap, cl, wire, sizeof(wire));
    (void)wtq_apipair_deliver_seeded(p, 'c', es, wire, wl, false, 5);
    SC_CHECK(p->c.closed == 1 && p->c.closed_clean);
    SC_CHECK(p->c.closed_code == 9);
    SC_CHECK(p->c.closed_reason_len == 3 &&
             memcmp(p->c.closed_reason, "bye", 3) == 0);
    return failures;
}

/* --- truncation / FIN faults --------------------------------------------- */

static int f_fin_mid_frame_header(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t partial[1] = { 0x01 };

    (void)wtq_apipair_deliver(p, 'c', es, partial, 1, true);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_FRAME_ERROR);
    return failures;
}

static int f_fin_mid_frame_payload(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t wire[4] = { 0x00, 0x0a, 0x01, 0x02 };

    (void)wtq_apipair_deliver(p, 'c', es, wire, 4, true);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_FRAME_ERROR);
    return failures;
}

static int f_fin_mid_capsule(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t cap[64];
    size_t cl = 0;

    SC_CHECK(wtq_capsule_encode_close(5, (const uint8_t *)"hello", 5, cap,
                                      sizeof(cap), &cl) == 0);
    uint8_t wire[64];
    size_t wl = wrap_data(cap, cl - 3, wire, sizeof(wire));
    (void)wtq_apipair_deliver(p, 'c', es, wire, wl, false);
    (void)wtq_apipair_deliver(p, 'c', es, NULL, 0, true);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_MESSAGE_ERROR);
    SC_CHECK(p->c.closed == 1 && !p->c.closed_clean);
    return failures;
}

static int f_fin_mid_preamble_uni(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    /* uni 0x54 type varint partial, then FIN: tolerated (s6.2) */
    uint8_t pre[2] = { 0x40, 0x54 };
    wtq_apipair_inject_stream(p, 'c', 7, false, pre, 2, true, 0);
    SC_CHECK(p->c.stream_opened == 0);
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    return failures;
}

static int f_fin_mid_preamble_bidi(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    /* bidi 0x41 seen, session id truncated, then FIN -> FRAME_ERROR */
    uint8_t pre[2] = { 0x40, 0x41 };
    wtq_apipair_inject_stream(p, 'c', 1, true, pre, 2, true, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_FRAME_ERROR);
    return failures;
}

/* --- mutation faults ----------------------------------------------------- */

static int f_forbidden_control_frame(wtq_apipair_t *p)
{
    int failures = 0;
    uint8_t data_frame[2] = { 0x00, 0x00 }; /* DATA, len 0: forbidden */
    uint8_t wire[160];
    size_t wl = build_control(wire, sizeof(wire), data_frame, 2);

    SC_CHECK(wl > 0);
    wtq_apipair_inject_stream(p, 'c', 3, false, wire, wl, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_FRAME_UNEXPECTED);
    return failures;
}

static int f_duplicate_settings(wtq_apipair_t *p)
{
    int failures = 0;
    uint8_t second[64];
    wtq_h3_settings_encode_cfg_t scfg = { true, false };
    size_t sl = 0;

    SC_CHECK(wtq_h3_settings_encode_frame(&scfg, second, sizeof(second),
                                          &sl) == 0);
    uint8_t wire[200];
    size_t wl = build_control(wire, sizeof(wire), second, sl);
    SC_CHECK(wl > 0);
    wtq_apipair_inject_stream(p, 'c', 3, false, wire, wl, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_FRAME_UNEXPECTED);
    return failures;
}

static int f_bad_settings_payload(wtq_apipair_t *p)
{
    int failures = 0;
    /* control type 0x00 + SETTINGS (0x04) whose payload repeats a
     * setting id -> H3_SETTINGS_ERROR. Hand-built malformed shape. */
    uint8_t wire[8] = { 0x00, 0x04, 0x04, 0x33, 0x01, 0x33, 0x01 };

    wtq_apipair_inject_stream(p, 'c', 3, false, wire, 7, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_SETTINGS_ERROR);
    return failures;
}

static int f_malformed_request_qpack(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_serve(p, false);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream(p, 's', 2, false, st, stl, false, 0);
    uint8_t req[64];
    size_t rl = build_headers_garbage(req, sizeof(req));
    wtq_apipair_inject_stream(p, 's', 0, true, req, rl, false, 0);
    /* RFC 9114 s4.1.2: a malformed request is a STREAM error — the
     * offending request stream is reset, the connection lives on and
     * no session is established. */
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 's')));
    SC_CHECK(!wtq_conn_session_established(wtq_apipair_conn(p, 's')));
    return failures;
}

static int f_malformed_response_qpack(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_bring_up(p, &failures);

    SC_CHECK(es != NULL);
    uint8_t resp[64];
    size_t rl = build_headers_garbage(resp, sizeof(resp));
    (void)wtq_apipair_deliver(p, 'c', es, resp, rl, false);
    SC_CHECK(p->c.failed == 1);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_MESSAGE_ERROR);
    return failures;
}

static int f_malformed_close_capsule(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t payload[8];
    size_t hl = 0;

    SC_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_CLOSE_SESSION, 2,
                                       payload, sizeof(payload), &hl) == 0);
    payload[hl] = 0x00;
    payload[hl + 1] = 0x01;
    uint8_t wire[32];
    size_t wl = wrap_data(payload, hl + 2, wire, sizeof(wire));
    (void)wtq_apipair_deliver(p, 'c', es, wire, wl, false);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_MESSAGE_ERROR);
    return failures;
}

static int f_malformed_drain_capsule(wtq_apipair_t *p)
{
    int failures = 0;
    wtq_estream_t *es = rail_established_client(p, &failures);
    uint8_t payload[8];
    size_t hl = 0;

    SC_CHECK(wtq_capsule_encode_header(WTQ_CAPSULE_DRAIN_SESSION, 1,
                                       payload, sizeof(payload), &hl) == 0);
    payload[hl] = 0x00;
    uint8_t wire[32];
    size_t wl = wrap_data(payload, hl + 1, wire, sizeof(wire));
    (void)wtq_apipair_deliver(p, 'c', es, wire, wl, false);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_MESSAGE_ERROR);
    return failures;
}

static int f_datagram_truncated_qsid(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    uint8_t dg[1] = { 0x40 };
    SC_CHECK(wtq_apipair_inject_datagram(p, 'c', dg, 1) == WTQ_ERR_PROTO);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_DATAGRAM_ERROR);
    return failures;
}

static int f_invalid_session_id_uni(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 1);
    wtq_apipair_inject_stream(p, 'c', 7, false, pre, pl, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_ID_ERROR);
    return failures;
}

static int f_invalid_session_id_bidi(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), true, 2);
    wtq_apipair_inject_stream(p, 'c', 1, true, pre, pl, false, 0);
    SC_CHECK(wtq_conn_is_closed(wtq_apipair_conn(p, 'c')));
    SC_CHECK(wtq_conn_close_code(wtq_apipair_conn(p, 'c')) ==
             WTQ_H3_ID_ERROR);
    return failures;
}

/* --- ordering / race faults ---------------------------------------------- */

static int f_stream_before_session(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_serve(p, false);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream(p, 's', 2, false, st, stl, false, 0);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 0);
    wtq_apipair_inject_stream(p, 's', 6, false, pre, pl, false, 0);
    SC_CHECK(p->s.stream_opened == 0);
    SC_CHECK(!wtq_conn_is_closed(wtq_apipair_conn(p, 's')));
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->s.drv.streams[i].in_use && p->s.drv.streams[i].id == 6)
            ds = &p->s.drv.streams[i];
    SC_CHECK(ds != NULL && ds->stopped);
    if (ds != NULL)
        SC_CHECK(ds->stop_err == WTQ_WT_BUFFERED_STREAM_REJECTED);
    return failures;
}

static int f_datagram_before_session(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_serve(p, false);
    uint8_t st[128];
    size_t stl = build_settings(st, sizeof(st), true);
    wtq_apipair_inject_stream(p, 's', 2, false, st, stl, false, 0);
    uint8_t dg[2] = { 0x00, 'x' };
    SC_CHECK(wtq_apipair_inject_datagram(p, 's', dg, 2) == WTQ_OK);
    SC_CHECK(p->s.dgram_events == 0);
    SC_CHECK(wtq_conn_dgrams_dropped(wtq_apipair_conn(p, 's')) == 1);
    return failures;
}

static int f_stream_after_close(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    SC_CHECK(wtq_session_close(p->c.s, 0, NULL, 0) == WTQ_OK);
    uint8_t pre[8];
    size_t pl = build_preamble(pre, sizeof(pre), false, 0);
    wtq_apipair_inject_stream(p, 'c', 7, false, pre, pl, false, 0);
    struct wtq_dstream *ds = NULL;
    for (size_t i = 0; i < FAKE_MAX_STREAMS; i++)
        if (p->c.drv.streams[i].in_use && p->c.drv.streams[i].id == 7)
            ds = &p->c.drv.streams[i];
    SC_CHECK(ds != NULL && ds->stopped);
    if (ds != NULL)
        SC_CHECK(ds->stop_err == WTQ_WT_SESSION_GONE);
    return failures;
}

static int f_datagram_after_close(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    SC_CHECK(wtq_session_close(p->c.s, 0, NULL, 0) == WTQ_OK);
    uint8_t dg[2] = { 0x00, 'x' };
    SC_CHECK(wtq_apipair_inject_datagram(p, 'c', dg, 2) == WTQ_OK);
    SC_CHECK(p->c.dgram_events == 0);
    SC_CHECK(wtq_conn_dgrams_dropped(wtq_apipair_conn(p, 'c')) == 1);
    return failures;
}

static int f_drain_then_traffic(wtq_apipair_t *p)
{
    int failures = 0;

    failures += rail_establish_pair(p);
    SC_CHECK(wtq_session_drain(p->s.s) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->c.draining == 1);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) == WTQ_OK);
    wtq_span_t dg = { (const uint8_t *)"d", 1 };
    SC_CHECK(wtq_session_send_datagram(p->c.s, &dg, 1) == WTQ_OK);
    wtq_apipair_pump(p);
    SC_CHECK(p->s.dgram_events == 1);
    return failures;
}

static int f_pending_send_conn_close(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"pending", 7 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) == WTQ_OK);
    wtq_apipair_conn_closed(p, 'c', 0);
    SC_CHECK(p->c.closed == 1 && !p->c.closed_clean);
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_apipair_conn(p, 'c')) == 1);
    SC_CHECK(p->c.send_completions == 1 && p->c.send_cancels == 1);
    return failures;
}

static int f_reset_pending_send(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"pending", 7 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) == WTQ_OK);
    SC_CHECK(wtq_stream_reset(st, 5) == WTQ_OK);
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_apipair_conn(p, 'c')) == 1);
    SC_CHECK(p->c.send_completions == 1 && p->c.send_cancels == 1);
    return failures;
}

/* --- capacity / backpressure faults -------------------------------------- */

static int f_fail_open(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    p->c.drv.fail_open = true;
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_ERR_STREAM_LIMIT);
    SC_CHECK(st == NULL);
    return failures;
}

static int f_fail_send(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_uni(p->c.s, &st) == WTQ_OK);
    p->c.drv.fail_send = true;
    int cookie = 0;
    wtq_span_t span = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, &cookie) ==
             WTQ_ERR_WOULD_BLOCK);
    p->c.drv.fail_send = false;
    SC_CHECK(fake_driver_complete_sends(&p->c.drv,
                                        wtq_apipair_conn(p, 'c')) == 0);
    SC_CHECK(p->c.send_completions == 0);
    return failures;
}

static int f_fail_dgram(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    p->c.drv.fail_dgram = true;
    wtq_span_t dg = { (const uint8_t *)"x", 1 };
    SC_CHECK(wtq_session_send_datagram(p->c.s, &dg, 1) ==
             WTQ_ERR_WOULD_BLOCK);
    return failures;
}

static int f_pending_send_queue_exhaustion(wtq_apipair_t *p)
{
    int failures = 0;

    (void)rail_established_client(p, &failures);
    wtq_stream_t *st = NULL;
    SC_CHECK(wtq_session_open_bidi(p->c.s, &st) == WTQ_OK);
    /* fill the fake driver's pending-completion queue without
     * completing any: the next send is refused with WOULD_BLOCK */
    wtq_span_t span = { (const uint8_t *)"q", 1 };
    size_t accepted = 0;
    for (int i = 0; i < FAKE_MAX_PENDING; i++)
        if (wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_OK)
            accepted++;
    SC_CHECK(accepted == FAKE_MAX_PENDING);
    SC_CHECK(wtq_stream_send(st, &span, 1, 0, NULL) == WTQ_ERR_WOULD_BLOCK);
    (void)fake_driver_complete_sends(&p->c.drv, wtq_apipair_conn(p, 'c'));
    return failures;
}

/* --- the table ----------------------------------------------------------- */

static const wtq_scenario_t SCENARIOS[] = {
    { "settings_split", f_settings_split, 0, true, 0 },
    { "response_split", f_response_split, 0, true, 0 },
    { "preamble_split_uni", f_preamble_split_uni, 0, true, 0 },
    { "preamble_split_bidi", f_preamble_split_bidi, 0, true, 0 },
    { "capsule_split", f_capsule_split, 0, true, 0 },
    { "fin_mid_frame_header", f_fin_mid_frame_header, 1, true, 0 },
    { "fin_mid_frame_payload", f_fin_mid_frame_payload, 1, true, 0 },
    { "fin_mid_capsule", f_fin_mid_capsule, 1, true, 0x558c32fc72bc93f8 },
    { "fin_mid_preamble_uni", f_fin_mid_preamble_uni, 0, true, 0 },
    { "fin_mid_preamble_bidi", f_fin_mid_preamble_bidi, 1, true, 0 },
    { "forbidden_control_frame", f_forbidden_control_frame, 1, true, 0 },
    { "duplicate_settings", f_duplicate_settings, 1, true, 0xc928fd7608705556 },
    { "bad_settings_payload", f_bad_settings_payload, 1, true, 0 },
    /* contained to its stream: no connection-level engine error */
    { "malformed_request_qpack", f_malformed_request_qpack, 0, true, 0 },
    { "malformed_response_qpack", f_malformed_response_qpack, 1, true, 0xba06062a17d9a4bd },
    { "malformed_close_capsule", f_malformed_close_capsule, 1, true, 0 },
    { "malformed_drain_capsule", f_malformed_drain_capsule, 1, true, 0 },
    { "datagram_truncated_qsid", f_datagram_truncated_qsid, 1, true, 0xbaa29a9bf2f04696 },
    { "invalid_session_id_uni", f_invalid_session_id_uni, 1, true, 0 },
    { "invalid_session_id_bidi", f_invalid_session_id_bidi, 1, true, 0 },
    { "stream_before_session", f_stream_before_session, 0, true, 0xcbf29ce484222325 },
    { "datagram_before_session", f_datagram_before_session, 0, true, 0 },
    { "stream_after_close", f_stream_after_close, 0, true, 0 },
    { "datagram_after_close", f_datagram_after_close, 0, true, 0 },
    { "drain_then_traffic", f_drain_then_traffic, 0, true, 0 },
    { "pending_send_conn_close", f_pending_send_conn_close, 0, true, 0x77977009b3591809 },
    { "reset_pending_send", f_reset_pending_send, 0, true, 0 },
    { "fail_open", f_fail_open, 0, true, 0 },
    { "fail_send", f_fail_send, 0, true, 0 },
    { "fail_dgram", f_fail_dgram, 0, true, 0 },
    { "pending_send_queue_exhaustion", f_pending_send_queue_exhaustion, 0,
      true, 0 },
};

#define SCENARIO_COUNT (sizeof(SCENARIOS) / sizeof(SCENARIOS[0]))

static const uint64_t SEEDS[] = { 0x51DE, 0xFA117, 0xC0DE, 0x9A9A };
#define SEED_COUNT (sizeof(SEEDS) / sizeof(SEEDS[0]))

int main(int argc, char **argv)
{
    return wtq_scenario_main(SCENARIOS, SCENARIO_COUNT, SEEDS, SEED_COUNT,
                             "fault", argc, argv);
}
