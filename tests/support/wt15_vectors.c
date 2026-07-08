#include "wt15_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proto/capsule.h"
#include "proto/connect.h"
#include "proto/h3_frame.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"
#include "proto/qpack_static.h"
#include "proto/sf_string.h"

#define CHECK_BUILD(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "vector builder failed: %s\n", #expr); \
            abort(); \
        } \
    } while (0)

#define SFV(lit) { lit, sizeof(lit) - 1 }

static void set_bytes(wt15_vector_t *v, const uint8_t *bytes, size_t len)
{
    CHECK_BUILD(len <= WT15_MAX_WIRE);
    memcpy(v->wire, bytes, len);
    v->wire_len = len;
}

size_t wt15_vectors_build(wt15_vector_t *out, size_t max)
{
    size_t n = 0;
    size_t len = 0;

    CHECK_BUILD(max >= WT15_MAX_VECTORS);
    memset(out, 0, max * sizeof(*out));

#define NEXT(nm, ty, dsc) \
    (out[n].name = (nm), out[n].type = (ty), out[n].desc = (dsc), &out[n])

    /* --- SETTINGS ------------------------------------------------------ */
    {
        wt15_vector_t *v = NEXT("settings_default_ecp", WT15_SETTINGS,
                                "wtquic default outgoing SETTINGS payload "
                                "(explicit QPACK zeros, ECP, H3_DATAGRAM, "
                                "WT_ENABLED)");
        wtq_h3_settings_encode_cfg_t cfg = { true, false };
        CHECK_BUILD(wtq_h3_settings_encode_payload(&cfg, v->wire,
                                                   WT15_MAX_WIRE, &len) ==
                    WTQ_H3_SETTINGS_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("settings_minimal_noecp", WT15_SETTINGS,
                                "outgoing SETTINGS without "
                                "ENABLE_CONNECT_PROTOCOL");
        wtq_h3_settings_encode_cfg_t cfg = { false, false };
        CHECK_BUILD(wtq_h3_settings_encode_payload(&cfg, v->wire,
                                                   WT15_MAX_WIRE, &len) ==
                    WTQ_H3_SETTINGS_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("settings_legacy_send", WT15_SETTINGS,
                                "legacy send-compat adds both old "
                                "max-sessions codepoints");
        wtq_h3_settings_encode_cfg_t cfg = { true, true };
        CHECK_BUILD(wtq_h3_settings_encode_payload(&cfg, v->wire,
                                                   WT15_MAX_WIRE, &len) ==
                    WTQ_H3_SETTINGS_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("settings_with_grease", WT15_SETTINGS,
                                "grease id interleaved; decode ignores "
                                "and counts it");
        static const uint8_t wire[] = { 0x40, 0x40, 0x07, 0x33, 0x01,
                                        0xac, 0x7c, 0xf0, 0x00, 0x01 };
        v->decode_only = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }
    {
        wt15_vector_t *v = NEXT("settings_reserved_h2", WT15_SETTINGS,
                                "HTTP/2-reserved id 0x02 rejected");
        static const uint8_t wire[] = { 0x02, 0x00 };
        v->decode_only = true;
        v->expect_error = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }
    {
        wt15_vector_t *v = NEXT("settings_dup_id", WT15_SETTINGS,
                                "duplicate identifier rejected");
        static const uint8_t wire[] = { 0x33, 0x01, 0x33, 0x01 };
        v->decode_only = true;
        v->expect_error = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }

    /* --- H3 frame headers ---------------------------------------------- */
    {
        wt15_vector_t *v = NEXT("frame_data_len0", WT15_FRAME,
                                "DATA frame header, empty payload");
        CHECK_BUILD(wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, 0,
                                               v->wire, WT15_MAX_WIRE,
                                               &len) == WTQ_H3_FRAME_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("frame_headers_len1", WT15_FRAME,
                                "HEADERS frame header, 1-byte payload "
                                "present");
        CHECK_BUILD(wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, 1,
                                               v->wire, WT15_MAX_WIRE,
                                               &len) == WTQ_H3_FRAME_OK);
        v->wire[len] = 0xAA; /* opaque payload byte after the header */
        v->wire_len = len + 1;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("frame_settings_hdr", WT15_FRAME,
                                "SETTINGS frame header for the default "
                                "payload length");
        wtq_h3_settings_encode_cfg_t cfg = { true, false };
        size_t plen = wtq_h3_settings_payload_len(&cfg);
        CHECK_BUILD(wtq_h3_frame_encode_header(WTQ_H3_FRAME_SETTINGS, plen,
                                               v->wire, WT15_MAX_WIRE,
                                               &len) == WTQ_H3_FRAME_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("frame_goaway_len8", WT15_FRAME,
                                "GOAWAY frame header announcing 8 bytes");
        CHECK_BUILD(wtq_h3_frame_encode_header(WTQ_H3_FRAME_GOAWAY, 8,
                                               v->wire, WT15_MAX_WIRE,
                                               &len) == WTQ_H3_FRAME_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("frame_grease_type", WT15_FRAME,
                                "grease frame type 0x21 with payload "
                                "length");
        CHECK_BUILD(wtq_h3_frame_encode_header(0x21, 5, v->wire,
                                               WT15_MAX_WIRE, &len) ==
                    WTQ_H3_FRAME_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("frame_max_header", WT15_FRAME,
                                "maximal 16-byte header (8-byte varints "
                                "for type and length)");
        CHECK_BUILD(wtq_h3_frame_encode_header(WTQ_VARINT_MAX,
                                               WTQ_VARINT_MAX, v->wire,
                                               WT15_MAX_WIRE, &len) ==
                    WTQ_H3_FRAME_OK);
        v->wire_len = len;
        n++;
    }

    /* --- capsules -------------------------------------------------------- */
    {
        wt15_vector_t *v = NEXT("capsule_drain", WT15_CAPSULE,
                                "WT_DRAIN_SESSION, empty payload");
        CHECK_BUILD(wtq_capsule_encode_drain(v->wire, WT15_MAX_WIRE,
                                             &len) == WTQ_CAPSULE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("capsule_close_zero", WT15_CAPSULE,
                                "WT_CLOSE_SESSION, code 0, empty reason");
        CHECK_BUILD(wtq_capsule_encode_close(0, NULL, 0, v->wire,
                                             WT15_MAX_WIRE, &len) ==
                    WTQ_CAPSULE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("capsule_close_code_msg", WT15_CAPSULE,
                                "WT_CLOSE_SESSION, code 0x1234, reason "
                                "'bye'");
        CHECK_BUILD(wtq_capsule_encode_close(0x1234,
                                             (const uint8_t *)"bye", 3,
                                             v->wire, WT15_MAX_WIRE,
                                             &len) == WTQ_CAPSULE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("capsule_close_max_reason", WT15_CAPSULE,
                                "WT_CLOSE_SESSION with the 1024-byte "
                                "reason boundary");
        uint8_t reason[1024];
        memset(reason, 'r', sizeof(reason));
        CHECK_BUILD(wtq_capsule_encode_close(0xffffffffu, reason,
                                             sizeof(reason), v->wire,
                                             WT15_MAX_WIRE, &len) ==
                    WTQ_CAPSULE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("capsule_unknown_skip", WT15_CAPSULE,
                                "unknown capsule type with payload is "
                                "skipped");
        static const uint8_t wire[] = { 0x17, 0x05, 1, 2, 3, 4, 5 };
        v->decode_only = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }
    {
        wt15_vector_t *v = NEXT("capsule_drain_bad_len", WT15_CAPSULE,
                                "DRAIN with nonzero length is malformed");
        static const uint8_t wire[] = { 0x80, 0x00, 0x78, 0xae, 0x01,
                                        0xAA };
        v->decode_only = true;
        v->expect_error = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }

    /* --- preambles ------------------------------------------------------- */
    {
        wt15_vector_t *v = NEXT("preamble_bidi_sid0", WT15_PREAMBLE_BIDI,
                                "bidi stream preamble, session 0");
        CHECK_BUILD(wtq_preamble_encode(WTQ_PREAMBLE_KIND_BIDI, 0, v->wire,
                                        WT15_MAX_WIRE, &len) ==
                    WTQ_PREAMBLE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("preamble_uni_sid0", WT15_PREAMBLE_UNI,
                                "uni stream preamble, session 0");
        CHECK_BUILD(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 0, v->wire,
                                        WT15_MAX_WIRE, &len) ==
                    WTQ_PREAMBLE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("preamble_bidi_64bit_sid",
                                WT15_PREAMBLE_BIDI,
                                "bidi preamble with an 8-byte session id");
        CHECK_BUILD(wtq_preamble_encode(WTQ_PREAMBLE_KIND_BIDI,
                                        UINT64_C(0x100000000), v->wire,
                                        WT15_MAX_WIRE, &len) ==
                    WTQ_PREAMBLE_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("preamble_uni_nonminimal",
                                WT15_PREAMBLE_UNI,
                                "non-minimal type varint accepted with "
                                "wire header_len");
        static const uint8_t wire[] = { 0x80, 0x00, 0x00, 0x54, 0x05 };
        v->decode_only = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }
    {
        wt15_vector_t *v = NEXT("preamble_wrong_direction",
                                WT15_PREAMBLE_BIDI,
                                "uni codepoint on a bidi stream is "
                                "unexpected");
        CHECK_BUILD(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 7, v->wire,
                                        WT15_MAX_WIRE, &len) ==
                    WTQ_PREAMBLE_OK);
        v->wire_len = len;
        v->decode_only = true;
        v->expect_error = true;
        n++;
    }

    /* --- CONNECT sections ------------------------------------------------ */
    {
        wt15_vector_t *v = NEXT("connect_req_basic", WT15_CONNECT_REQ,
                                "minimal extended CONNECT request");
        CHECK_BUILD(wtq_connect_encode_request("example.com", 11, "/wt", 3,
                                               NULL, 0, NULL, 0, v->wire,
                                               WT15_MAX_WIRE, &len) ==
                    WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_req_subprotocols",
                                WT15_CONNECT_REQ,
                                "request offering moqt-18, moqt-16");
        wtq_sf_str_t offer[2] = { SFV("moqt-18"), SFV("moqt-16") };
        CHECK_BUILD(wtq_connect_encode_request("example.com", 11, "/moq",
                                               4, NULL, 0, offer, 2,
                                               v->wire, WT15_MAX_WIRE,
                                               &len) == WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_req_origin", WT15_CONNECT_REQ,
                                "request with an origin header");
        CHECK_BUILD(wtq_connect_encode_request("example.com", 11, "/wt", 3,
                                               "https://o.example", 17,
                                               NULL, 0, v->wire,
                                               WT15_MAX_WIRE, &len) ==
                    WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_req_no_protocol",
                                WT15_CONNECT_REQ,
                                "CONNECT without :protocol is rejected");
        static const uint8_t wire[] = { 0x00, 0x00, 0xcf, 0xd7, 0x50, 0x03,
                                        'w', 't', 'q', 0x51, 0x03, '/',
                                        'w', 't' };
        v->decode_only = true;
        v->expect_error = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_resp_200", WT15_CONNECT_RESP,
                                "200 response, no subprotocol");
        CHECK_BUILD(wtq_connect_encode_response(200, NULL, v->wire,
                                                WT15_MAX_WIRE, &len) ==
                    WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_resp_200_wt_protocol",
                                WT15_CONNECT_RESP,
                                "200 response selecting moqt-18");
        wtq_sf_str_t sel = SFV("moqt-18");
        CHECK_BUILD(wtq_connect_encode_response(200, &sel, v->wire,
                                                WT15_MAX_WIRE, &len) ==
                    WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_resp_404", WT15_CONNECT_RESP,
                                "404 rejection decodes, is not success");
        CHECK_BUILD(wtq_connect_encode_response(404, NULL, v->wire,
                                                WT15_MAX_WIRE, &len) ==
                    WTQ_CONNECT_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("connect_resp_huffman_ignored",
                                WT15_CONNECT_RESP,
                                "Huffman wt-protocol value decodes via "
                                "QPACK but is not a quoted SF string, so "
                                "the field is ignored (RFC 7541 C.6.1 "
                                "'private' bytes)");
        static const uint8_t wire[] = { 0x00, 0x00, 0xd9, 0x27, 0x04, 'w',
                                        't', '-', 'p', 'r', 'o', 't', 'o',
                                        'c', 'o', 'l', 0x85, 0xae, 0xc3,
                                        0x77, 0x1a, 0x4b };
        v->decode_only = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }

    /* --- SF list values --------------------------------------------------- */
    {
        wt15_vector_t *v = NEXT("sf_list_two", WT15_SF_LIST,
                                "canonical WT-Available-Protocols value");
        wtq_sf_str_t members[2] = { SFV("moqt-18"), SFV("moqt-16") };
        CHECK_BUILD(wtq_sf_string_encode_list(members, 2, (char *)v->wire,
                                              WT15_MAX_WIRE, &len) ==
                    WTQ_SF_OK);
        v->wire_len = len;
        n++;
    }
    {
        wt15_vector_t *v = NEXT("sf_list_trailing_comma", WT15_SF_LIST,
                                "trailing comma malforms the field");
        static const uint8_t wire[] = { '"', 'a', '"', ',' };
        v->decode_only = true;
        v->expect_error = true;
        set_bytes(v, wire, sizeof(wire));
        n++;
    }

#undef NEXT
    CHECK_BUILD(n <= max);
    return n;
}

/* ---------------------------------------------------------------------- */
/* Validation                                                             */
/* ---------------------------------------------------------------------- */

#include <stdarg.h>

static int vfail(const wt15_vector_t *v, const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "FAIL[%s]: ", v->name);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 1;
}

static const wtq_connect_opts_t WT15_STRICT = { false, false };

static int validate_settings(const wt15_vector_t *v, const uint8_t *wire,
                             size_t wire_len)
{
    wtq_h3_settings_t s;
    wtq_h3_settings_status_t st = wtq_h3_settings_decode(wire, wire_len,
                                                         &s);

    if (v->expect_error)
        return st == WTQ_H3_SETTINGS_ERR_SETTING
                   ? 0
                   : vfail(v, "expected ERR_SETTING, got %d", st);
    if (st != WTQ_H3_SETTINGS_OK)
        return vfail(v, "decode failed: %d", st);
    if (strcmp(v->name, "settings_with_grease") == 0) {
        if (s.unknown_count != 1)
            return vfail(v, "grease not counted: %zu", s.unknown_count);
        if (!s.has_h3_datagram || s.h3_datagram != 1 ||
            !s.has_wt_enabled || s.wt_enabled != 1)
            return vfail(v, "known settings lost around grease");
    }
    return 0;
}

static int validate_frame(const wt15_vector_t *v, const uint8_t *wire,
                          size_t wire_len)
{
    wtq_h3_frame_t f = { 0, 0, 0 };
    wtq_h3_frame_status_t st = wtq_h3_frame_decode_header(wire, wire_len,
                                                          &f);

    if (st != WTQ_H3_FRAME_OK)
        return vfail(v, "decode failed: %d", st);
    if (f.header_len > wire_len)
        return vfail(v, "header_len overruns wire");
    if (!v->decode_only) {
        uint8_t reenc[16];
        size_t relen = 0;
        if (wtq_h3_frame_encode_header(f.type, f.length, reenc,
                                       sizeof(reenc), &relen) !=
                WTQ_H3_FRAME_OK ||
            relen != f.header_len ||
            memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

static int validate_capsule(const wt15_vector_t *v, const uint8_t *wire,
                            size_t wire_len)
{
    wtq_capsule_dec_t dec;
    wtq_capsule_t c;
    size_t consumed = 0;

    wtq_capsule_dec_init(&dec);
    wtq_capsule_status_t st = wtq_capsule_dec_feed(&dec, wire, wire_len,
                                                   &c, &consumed);
    if (v->expect_error)
        return st == WTQ_CAPSULE_MALFORMED
                   ? 0
                   : vfail(v, "expected MALFORMED, got %d", st);
    if (st != WTQ_CAPSULE_OK)
        return vfail(v, "decode failed: %d", st);
    if (consumed != wire_len)
        return vfail(v, "consumed %zu of %zu", consumed, wire_len);
    if (strcmp(v->name, "capsule_unknown_skip") == 0) {
        if (c.kind != WTQ_CAPSULE_KIND_UNKNOWN || c.type != 0x17 ||
            c.length != 5)
            return vfail(v, "unknown capsule not skipped as advertised");
    }
    if (!v->decode_only) {
        uint8_t reenc[WT15_MAX_WIRE];
        size_t relen = 0;
        wtq_capsule_status_t est;
        if (c.kind == WTQ_CAPSULE_KIND_DRAIN)
            est = wtq_capsule_encode_drain(reenc, sizeof(reenc), &relen);
        else if (c.kind == WTQ_CAPSULE_KIND_CLOSE)
            est = wtq_capsule_encode_close(c.close_code, c.reason,
                                           c.reason_len, reenc,
                                           sizeof(reenc), &relen);
        else
            return 0; /* unknown kinds have no encoder */
        if (est != WTQ_CAPSULE_OK || relen != wire_len ||
            memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

static int validate_preamble(const wt15_vector_t *v, const uint8_t *wire,
                             size_t wire_len)
{
    wtq_preamble_kind_t expect = (v->type == WT15_PREAMBLE_BIDI)
                                     ? WTQ_PREAMBLE_KIND_BIDI
                                     : WTQ_PREAMBLE_KIND_UNI;
    wtq_preamble_t p;
    wtq_preamble_status_t st = wtq_preamble_decode(expect, wire, wire_len,
                                                   &p);

    if (v->expect_error) {
        if (st != WTQ_PREAMBLE_UNEXPECTED)
            return vfail(v, "expected UNEXPECTED, got %d", st);
        if (strcmp(v->name, "preamble_wrong_direction") == 0 &&
            p.wire_type != WTQ_PREAMBLE_UNI)
            return vfail(v, "wire_type not reported: 0x%x",
                         (unsigned)p.wire_type);
        return 0;
    }
    if (st != WTQ_PREAMBLE_OK)
        return vfail(v, "decode failed: %d", st);
    if (strcmp(v->name, "preamble_uni_nonminimal") == 0 &&
        (p.session_id != 5 || p.header_len != wire_len))
        return vfail(v, "non-minimal semantics not preserved");
    if (p.header_len != wire_len)
        return vfail(v, "header_len %zu != wire %zu", p.header_len, wire_len);
    if (!v->decode_only) {
        uint8_t reenc[16];
        size_t relen = 0;
        if (wtq_preamble_encode(p.kind, p.session_id, reenc, sizeof(reenc),
                                &relen) != WTQ_PREAMBLE_OK ||
            relen != wire_len || memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

static int validate_connect_req(const wt15_vector_t *v,
                                const uint8_t *wire, size_t wire_len)
{
    wtq_connect_req_t req;
    wtq_sf_str_t protos[8];
    size_t nproto = 0;
    char scratch[WT15_MAX_WIRE];
    wtq_connect_status_t st = wtq_connect_decode_request(
        wire, wire_len, &WT15_STRICT, &req, protos, 8, &nproto, scratch,
        sizeof(scratch));

    if (v->expect_error)
        return st == WTQ_CONNECT_MALFORMED
                   ? 0
                   : vfail(v, "expected MALFORMED, got %d", st);
    if (st != WTQ_CONNECT_OK)
        return vfail(v, "decode failed: %d", st);
    if (!v->decode_only) {
        uint8_t reenc[WT15_MAX_WIRE];
        size_t relen = 0;
        if (wtq_connect_encode_request(
                req.authority, req.authority_len, req.path, req.path_len,
                req.has_origin ? req.origin : NULL,
                req.has_origin ? req.origin_len : 0, protos, nproto, reenc,
                sizeof(reenc), &relen) != WTQ_CONNECT_OK ||
            relen != wire_len || memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

static int validate_connect_resp(const wt15_vector_t *v,
                                 const uint8_t *wire, size_t wire_len)
{
    wtq_connect_resp_t resp;
    char scratch[WT15_MAX_WIRE];
    wtq_connect_status_t st = wtq_connect_decode_response(
        wire, wire_len, &WT15_STRICT, &resp, scratch, sizeof(scratch));

    if (v->expect_error)
        return st == WTQ_CONNECT_MALFORMED
                   ? 0
                   : vfail(v, "expected MALFORMED, got %d", st);
    if (st != WTQ_CONNECT_OK)
        return vfail(v, "decode failed: %d", st);
    if (strcmp(v->name, "connect_resp_huffman_ignored") == 0) {
        if (resp.status != 200 || resp.has_protocol)
            return vfail(v, "non-SF wt-protocol was not ignored");
    }
    if (!v->decode_only) {
        uint8_t reenc[WT15_MAX_WIRE];
        size_t relen = 0;
        const wtq_sf_str_t *sel = resp.has_protocol ? &resp.protocol
                                                    : NULL;
        if (wtq_connect_encode_response(resp.status, sel, reenc,
                                        sizeof(reenc), &relen) !=
                WTQ_CONNECT_OK ||
            relen != wire_len || memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

static int validate_sf_list(const wt15_vector_t *v, const uint8_t *wire,
                            size_t wire_len)
{
    wtq_sf_str_t members[8];
    size_t n = 0;
    char out_buf[WT15_MAX_WIRE];
    wtq_sf_status_t st = wtq_sf_string_parse_list(
        (const char *)wire, wire_len, false, out_buf, sizeof(out_buf),
        members, 8, &n);

    if (v->expect_error)
        return st == WTQ_SF_MALFORMED
                   ? 0
                   : vfail(v, "expected MALFORMED, got %d", st);
    if (st != WTQ_SF_OK)
        return vfail(v, "parse failed: %d", st);
    if (!v->decode_only) {
        char reenc[WT15_MAX_WIRE];
        size_t relen = 0;
        if (wtq_sf_string_encode_list(members, n, reenc, sizeof(reenc),
                                      &relen) != WTQ_SF_OK ||
            relen != wire_len || memcmp(reenc, wire, relen) != 0)
            return vfail(v, "re-encode not byte-identical");
    }
    return 0;
}

int wt15_vector_validate(const wt15_vector_t *v, const uint8_t *wire,
                         size_t wire_len)
{
    switch (v->type) {
    case WT15_SETTINGS:      return validate_settings(v, wire, wire_len);
    case WT15_FRAME:         return validate_frame(v, wire, wire_len);
    case WT15_CAPSULE:       return validate_capsule(v, wire, wire_len);
    case WT15_PREAMBLE_BIDI:
    case WT15_PREAMBLE_UNI:  return validate_preamble(v, wire, wire_len);
    case WT15_CONNECT_REQ:   return validate_connect_req(v, wire,
                                                         wire_len);
    case WT15_CONNECT_RESP:  return validate_connect_resp(v, wire,
                                                          wire_len);
    case WT15_SF_LIST:       return validate_sf_list(v, wire, wire_len);
    }
    return vfail(v, "unknown vector type %d", (int)v->type);
}

int wt15_vector_feed_hostile(const wt15_vector_t *v, const uint8_t *wire,
                             size_t wire_len, bool is_strict_prefix)
{
    switch (v->type) {
    case WT15_SETTINGS: {
        wtq_h3_settings_t s;
        wtq_h3_settings_status_t st = wtq_h3_settings_decode(wire,
                                                             wire_len, &s);
        if (st != WTQ_H3_SETTINGS_OK && st != WTQ_H3_SETTINGS_NEED_MORE &&
            st != WTQ_H3_SETTINGS_ERR_SETTING)
            return vfail(v, "dirty settings status %d", st);
        return 0;
    }
    case WT15_FRAME: {
        wtq_h3_frame_t f = { 0, 0, 0 };
        wtq_h3_frame_status_t st = wtq_h3_frame_decode_header(wire,
                                                              wire_len,
                                                              &f);
        if (st != WTQ_H3_FRAME_OK && st != WTQ_H3_FRAME_NEED_MORE)
            return vfail(v, "dirty frame status %d", st);
        if (st == WTQ_H3_FRAME_OK && f.header_len > wire_len)
            return vfail(v, "frame overconsumed");
        return 0;
    }
    case WT15_CAPSULE: {
        wtq_capsule_dec_t dec;
        wtq_capsule_t c;
        size_t consumed = 0;
        wtq_capsule_dec_init(&dec);
        wtq_capsule_status_t st = wtq_capsule_dec_feed(&dec, wire,
                                                       wire_len, &c,
                                                       &consumed);
        if (st != WTQ_CAPSULE_OK && st != WTQ_CAPSULE_NEED_MORE &&
            st != WTQ_CAPSULE_MALFORMED)
            return vfail(v, "dirty capsule status %d", st);
        if (consumed > wire_len)
            return vfail(v, "capsule overconsumed");
        /* a strict prefix of one complete positive capsule can never be
         * complete itself */
        if (is_strict_prefix && !v->expect_error &&
            st == WTQ_CAPSULE_OK)
            return vfail(v, "prefix decoded as complete");
        return 0;
    }
    case WT15_PREAMBLE_BIDI:
    case WT15_PREAMBLE_UNI: {
        wtq_preamble_kind_t expect = (v->type == WT15_PREAMBLE_BIDI)
                                         ? WTQ_PREAMBLE_KIND_BIDI
                                         : WTQ_PREAMBLE_KIND_UNI;
        wtq_preamble_t p;
        wtq_preamble_status_t st = wtq_preamble_decode(expect, wire,
                                                       wire_len, &p);
        if (st != WTQ_PREAMBLE_OK && st != WTQ_PREAMBLE_NEED_MORE &&
            st != WTQ_PREAMBLE_UNEXPECTED)
            return vfail(v, "dirty preamble status %d", st);
        if (is_strict_prefix && !v->expect_error &&
            st == WTQ_PREAMBLE_OK)
            return vfail(v, "prefix decoded as complete");
        return 0;
    }
    case WT15_CONNECT_REQ: {
        wtq_connect_req_t req;
        wtq_sf_str_t protos[8];
        size_t nproto = 0;
        char scratch[WT15_MAX_WIRE];
        wtq_connect_status_t st = wtq_connect_decode_request(
            wire, wire_len, &WT15_STRICT, &req, protos, 8, &nproto,
            scratch, sizeof(scratch));
        /* NOT_WEBTRANSPORT is a legal outcome on dirty input: flipping
         * a :protocol or :method byte can yield a well-formed request
         * for something other than WebTransport. */
        if (st != WTQ_CONNECT_OK && st != WTQ_CONNECT_BUFFER &&
            st != WTQ_CONNECT_MALFORMED &&
            st != WTQ_CONNECT_NOT_WEBTRANSPORT)
            return vfail(v, "dirty connect-req status %d", st);
        return 0;
    }
    case WT15_CONNECT_RESP: {
        wtq_connect_resp_t resp;
        char scratch[WT15_MAX_WIRE];
        wtq_connect_status_t st = wtq_connect_decode_response(
            wire, wire_len, &WT15_STRICT, &resp, scratch,
            sizeof(scratch));
        if (st != WTQ_CONNECT_OK && st != WTQ_CONNECT_BUFFER &&
            st != WTQ_CONNECT_MALFORMED)
            return vfail(v, "dirty connect-resp status %d", st);
        return 0;
    }
    case WT15_SF_LIST: {
        wtq_sf_str_t members[8];
        size_t n = 0;
        char out_buf[WT15_MAX_WIRE];
        wtq_sf_status_t st = wtq_sf_string_parse_list(
            (const char *)wire, wire_len, false, out_buf, sizeof(out_buf),
            members, 8, &n);
        if (st != WTQ_SF_OK && st != WTQ_SF_BUFFER &&
            st != WTQ_SF_MALFORMED)
            return vfail(v, "dirty sf status %d", st);
        return 0;
    }
    }
    return vfail(v, "unknown vector type %d", (int)v->type);
}
