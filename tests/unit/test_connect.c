#include <stdio.h>
#include <string.h>

#include "proto/connect.h"
#include "proto/qpack_static.h"

#include "test_support.h"

#define SF(lit) { lit, sizeof(lit) - 1 }

static const wtq_connect_opts_t STRICT = { false, false };
static const wtq_connect_opts_t LENIENT = { true, false };
static const wtq_connect_opts_t LEGACY = { false, true };

static bool span_eq(const char *p, size_t len, const char *lit)
{
    return len == strlen(lit) && (len == 0 || memcmp(p, lit, len) == 0);
}

/* Build a field section from a field list (test helper). */
static size_t build(const wtq_qpack_field_t *fields, size_t count,
                    uint8_t *dst, size_t cap)
{
    size_t out_len = 0;
    if (wtq_qpack_encode_section(fields, count, dst, cap, &out_len) != 0)
        return 0;
    return out_len;
}

static const wtq_qpack_field_t REQ_BASE[] = {
    { ":method", 7, "CONNECT", 7, false },
    { ":scheme", 7, "https", 5, false },
    { ":authority", 10, "example.com", 11, false },
    { ":path", 5, "/wt", 3, false },
    { ":protocol", 9, "webtransport-h3", 15, false },
};

/* byte-exact minimal request encode + decode roundtrip */
static void test_request_roundtrip(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_connect_encode_request("example.com", 11, "/wt", 3,
                                              NULL, 0, NULL, 0, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_CONNECT_OK);
    /* prefix, :method CONNECT idx15, :scheme https idx23,
     * :authority name-ref idx0, :path name-ref idx1,
     * :protocol literal-literal */
    const uint8_t expect[] = { 0x00, 0x00, 0xcf, 0xd7,
                               0x50, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l',
                               'e', '.', 'c', 'o', 'm',
                               0x51, 0x03, '/', 'w', 't',
                               0x27, 0x02, ':', 'p', 'r', 'o', 't', 'o',
                               'c', 'o', 'l', 0x0f, 'w', 'e', 'b', 't',
                               'r', 'a', 'n', 's', 'p', 'o', 'r', 't',
                               '-', 'h', '3' };
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(expect));
    WTQ_TEST_CHECK(memcmp(buf, expect, out_len) == 0);

    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 99;
    char scratch[256];
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, out_len, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(span_eq(req.authority, req.authority_len,
                           "example.com"));
    WTQ_TEST_CHECK(span_eq(req.path, req.path_len, "/wt"));
    WTQ_TEST_CHECK(!req.has_origin);
    WTQ_TEST_CHECK(!req.legacy_protocol);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 0);

    /* with origin + offered protocols */
    wtq_sf_str_t offer[2] = { SF("moqt-18"), SF("moqt-16") };
    WTQ_TEST_CHECK(wtq_connect_encode_request("h.example", 9, "/moq", 4,
                                              "https://o.example", 17,
                                              offer, 2, buf, sizeof(buf),
                                              &out_len) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, out_len, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(req.has_origin);
    WTQ_TEST_CHECK(span_eq(req.origin, req.origin_len,
                           "https://o.example"));
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 2);
    WTQ_TEST_CHECK(span_eq(protos[0].data, protos[0].len, "moqt-18"));
    WTQ_TEST_CHECK(span_eq(protos[1].data, protos[1].len, "moqt-16"));

    *fp += failures;
}

/* byte-exact 200 response + roundtrip incl. wt-protocol */
static void test_response_roundtrip(int *fp)
{
    int failures = 0;
    uint8_t buf[128];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_connect_encode_response(200, NULL, buf, sizeof(buf),
                                               &out_len) ==
                   WTQ_CONNECT_OK);
    const uint8_t expect[] = { 0x00, 0x00, 0xd9 }; /* :status 200 idx 25 */
    WTQ_TEST_CHECK_EQ_SIZE(out_len, sizeof(expect));
    WTQ_TEST_CHECK(memcmp(buf, expect, out_len) == 0);

    wtq_connect_resp_t resp;
    char scratch[128];
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, out_len, &STRICT,
                                               &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_INT(resp.status, 200);
    WTQ_TEST_CHECK(!resp.has_protocol);
    WTQ_TEST_CHECK(wtq_connect_status_is_success(resp.status));

    /* with selected protocol */
    wtq_sf_str_t sel = SF("moqt-18");
    WTQ_TEST_CHECK(wtq_connect_encode_response(200, &sel, buf, sizeof(buf),
                                               &out_len) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, out_len, &STRICT,
                                               &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(resp.has_protocol);
    WTQ_TEST_CHECK(span_eq(resp.protocol.data, resp.protocol.len,
                           "moqt-18"));

    /* a 404 rejection decodes fine but is NOT success */
    WTQ_TEST_CHECK(wtq_connect_encode_response(404, NULL, buf, sizeof(buf),
                                               &out_len) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, out_len, &STRICT,
                                               &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_INT(resp.status, 404);
    WTQ_TEST_CHECK(!wtq_connect_status_is_success(resp.status));

    /* success is draft-wide 2xx by contract ("successful (2xx)
     * response", draft-15; h3zero checks 200-299): 204/206 count,
     * 199/300 do not */
    WTQ_TEST_CHECK(wtq_connect_status_is_success(200));
    WTQ_TEST_CHECK(wtq_connect_status_is_success(204));
    WTQ_TEST_CHECK(wtq_connect_status_is_success(206));
    WTQ_TEST_CHECK(wtq_connect_status_is_success(299));
    WTQ_TEST_CHECK(!wtq_connect_status_is_success(199));
    WTQ_TEST_CHECK(!wtq_connect_status_is_success(300));
    WTQ_TEST_CHECK(!wtq_connect_status_is_success(101));

    *fp += failures;
}

/* the request reject matrix */
static void test_request_rejects(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 0;
    char scratch[256];

    /* each required pseudo missing */
    for (size_t skip = 0; skip < 5; skip++) {
        wtq_qpack_field_t f[5];
        size_t n = 0;
        for (size_t i = 0; i < 5; i++)
            if (i != skip)
                f[n++] = REQ_BASE[i];
        size_t blen = build(f, n, buf, sizeof(buf));
        WTQ_TEST_CHECK(blen > 0);
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }

    /* wrong method */
    {
        wtq_qpack_field_t f[5];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[0].value = "GET";
        f[0].value_len = 3;
        size_t blen = build(f, 5, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* A non-WT :protocol is a well-formed request for another extended
     * CONNECT protocol (NOT_WEBTRANSPORT — see
     * test_not_webtransport_classification); the legacy token is
     * WebTransport only behind the leniency flag. */
    {
        wtq_qpack_field_t f[5];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[4].value = "webtransport";
        f[4].value_len = 12;
        size_t blen = build(f, 5, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &LEGACY, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_OK);
        WTQ_TEST_CHECK(req.legacy_protocol);
    }
    /* duplicate pseudo */
    {
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = REQ_BASE[3]; /* second :path */
        size_t blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* pseudo after regular */
    {
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, 4 * sizeof(REQ_BASE[0]));
        f[4] = (wtq_qpack_field_t){ "origin", 6, "https://x", 9, false };
        f[5] = REQ_BASE[4]; /* :protocol after origin */
        size_t blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* regular field names must be valid lowercase HTTP tokens */
    {
        static const struct {
            const char *name;
            size_t len;
        } bad_names[] = {
            { "bad name", 8 },   /* space */
            { "ba:d", 4 },       /* colon inside a regular name */
            { "bad\x01name", 8 },/* control char */
            { "bad(name)", 9 },  /* separators */
            { "bad\"q", 5 },     /* DQUOTE */
        };
        for (size_t i = 0;
             i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
            wtq_qpack_field_t f[6];
            memcpy(f, REQ_BASE, sizeof(REQ_BASE));
            f[5] = (wtq_qpack_field_t){ bad_names[i].name,
                                        bad_names[i].len, "x", 1, false };
            size_t blen = build(f, 6, buf, sizeof(buf));
            WTQ_TEST_CHECK(blen > 0);
            WTQ_TEST_CHECK(wtq_connect_decode_request(
                               buf, blen, &STRICT, &req, protos, 4,
                               &nproto, scratch, sizeof(scratch)) ==
                           WTQ_CONNECT_MALFORMED);
        }
        /* pseudo name with a non-token tail is also malformed */
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = (wtq_qpack_field_t){ ":me thod", 8, "x", 1, false };
        size_t blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
        /* a valid token-name unknown header is still fine/ignored */
        f[5] = (wtq_qpack_field_t){ "x-custom.h_1", 12, "x", 1, false };
        blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_OK);
    }
    /* uppercase field name */
    {
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = (wtq_qpack_field_t){ "Origin", 6, "https://x", 9, false };
        size_t blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* unknown pseudo header */
    {
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = (wtq_qpack_field_t){ ":wat", 4, "x", 1, false };
        size_t blen = build(f, 6, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* duplicate wt-available-protocols header */
    {
        wtq_qpack_field_t f[7];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                    "\"a\"", 3, false };
        f[6] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                    "\"b\"", 3, false };
        size_t blen = build(f, 7, buf, sizeof(buf));
        WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                                  protos, 4, &nproto,
                                                  scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* qpack-level malformed propagates */
    {
        const uint8_t bad[] = { 0x00, 0x00, 0x81 };
        WTQ_TEST_CHECK(wtq_connect_decode_request(bad, sizeof(bad),
                                                  &STRICT, &req, protos, 4,
                                                  &nproto, scratch,
                                                  sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }

    *fp += failures;
}

/* SF handling: strict vs lenient, empty strings, malformed = ignored */
static void test_sf_handling(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 99;
    char scratch[256];

    wtq_qpack_field_t f[6];
    memcpy(f, REQ_BASE, sizeof(REQ_BASE));

    /* quoted strings accepted (strict) */
    f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                "\"moqt-18\", \"moqt-16\"", 20, false };
    size_t blen = build(f, 6, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 2);

    /* bare tokens rejected strict -> field ignored (count 0),
     * accepted lenient */
    f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                "moqt-18, moqt-16", 16, false };
    blen = build(f, 6, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 0); /* draft: malformed => ignored */
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &LENIENT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 2);

    /* empty protocol string: connect-layer invalid -> field ignored */
    f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                "\"\", \"moqt-18\"", 13, false };
    blen = build(f, 6, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 0);

    /* structurally malformed SF (trailing comma) -> ignored */
    f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                "\"moqt-18\",", 10, false };
    blen = build(f, 6, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_request(buf, blen, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(nproto, 0);

    /* response wt-protocol: quoted ok; bare token ignored strict,
     * accepted lenient; empty ignored; duplicate header MALFORMED */
    wtq_connect_resp_t resp;
    wtq_qpack_field_t r[3] = {
        { ":status", 7, "200", 3, false },
        { "wt-protocol", 11, "\"moqt-18\"", 9, false },
        { "wt-protocol", 11, "\"moqt-16\"", 9, false },
    };
    blen = build(r, 2, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(resp.has_protocol);
    WTQ_TEST_CHECK(span_eq(resp.protocol.data, resp.protocol.len,
                           "moqt-18"));
    blen = build(r, 3, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_MALFORMED);
    r[1].value = "moqt-18";
    r[1].value_len = 7;
    blen = build(r, 2, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(!resp.has_protocol);
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &LENIENT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(resp.has_protocol);
    r[1].value = "\"\"";
    r[1].value_len = 2;
    blen = build(r, 2, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(!resp.has_protocol);

    *fp += failures;
}

/* response pseudo rules + capacities + NULL scratch */
static void test_response_rejects_and_caps(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    wtq_connect_resp_t resp;
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 0;
    char scratch[256];

    /* missing :status */
    wtq_qpack_field_t r1[1] = {
        { "wt-protocol", 11, "\"a\"", 3, false },
    };
    size_t blen = build(r1, 1, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_MALFORMED);
    /* duplicate :status */
    wtq_qpack_field_t r2[2] = {
        { ":status", 7, "200", 3, false },
        { ":status", 7, "204", 3, false },
    };
    blen = build(r2, 2, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_MALFORMED);
    /* non-numeric status */
    wtq_qpack_field_t r3[1] = { { ":status", 7, "2x0", 3, false } };
    blen = build(r3, 1, buf, sizeof(buf));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT, &resp,
                                               scratch, sizeof(scratch)) ==
                   WTQ_CONNECT_MALFORMED);

    /* protocols[] capacity too small -> BUFFER */
    uint8_t rbuf[256];
    wtq_qpack_field_t f[6];
    memcpy(f, REQ_BASE, sizeof(REQ_BASE));
    f[5] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                "\"a\", \"b\", \"c\"", 13, false };
    blen = build(f, 6, rbuf, sizeof(rbuf));
    WTQ_TEST_CHECK(wtq_connect_decode_request(rbuf, blen, &STRICT, &req,
                                              protos, 2, &nproto, scratch,
                                              sizeof(scratch)) ==
                   WTQ_CONNECT_BUFFER);
    /* scratch too small -> BUFFER */
    WTQ_TEST_CHECK(wtq_connect_decode_request(rbuf, blen, &STRICT, &req,
                                              protos, 4, &nproto, scratch,
                                              8) == WTQ_CONNECT_BUFFER);
    /* NULL scratch, zero cap: clean BUFFER, no UB */
    WTQ_TEST_CHECK(wtq_connect_decode_request(rbuf, blen, &STRICT, &req,
                                              protos, 4, &nproto, NULL,
                                              0) == WTQ_CONNECT_BUFFER);
    WTQ_TEST_CHECK(wtq_connect_decode_response(rbuf, blen, &STRICT, &resp,
                                               NULL, 0) !=
                   WTQ_CONNECT_OK);

    /* encode BUFFER untouched */
    for (size_t cap = 0; cap < 8; cap++) {
        uint8_t small[16];
        memset(small, 0xEE, sizeof(small));
        size_t out_len = 0;
        WTQ_TEST_CHECK(wtq_connect_encode_request("a", 1, "/", 1, NULL, 0,
                                                  NULL, 0, small, cap,
                                                  &out_len) ==
                       WTQ_CONNECT_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == 0xEE);
    }

    /* encode rejects invalid protocol values */
    wtq_sf_str_t bad = { "\x01", 1 };
    size_t out_len = 0;
    WTQ_TEST_CHECK(wtq_connect_encode_request("a", 1, "/", 1, NULL, 0,
                                              &bad, 1, buf, sizeof(buf),
                                              &out_len) ==
                   WTQ_CONNECT_MALFORMED);
    wtq_sf_str_t empty = { "", 0 };
    WTQ_TEST_CHECK(wtq_connect_encode_response(200, &empty, buf,
                                               sizeof(buf), &out_len) ==
                   WTQ_CONNECT_MALFORMED);

    *fp += failures;
}

/* selection helper */
static void test_select(int *fp)
{
    int failures = 0;
    wtq_sf_str_t offered[3] = { SF("moqt-18"), SF("moqt-16"), SF("chat") };
    wtq_sf_str_t supported[2] = { SF("moqt-16"), SF("moqt-18") };
    size_t idx = 999;

    WTQ_TEST_CHECK(wtq_connect_select_protocol(offered, 3, supported, 2,
                                               &idx) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK_EQ_SIZE(idx, 0); /* client preference order */

    wtq_sf_str_t other[1] = { SF("h3") };
    WTQ_TEST_CHECK(wtq_connect_select_protocol(offered, 3, other, 1,
                                               &idx) ==
                   WTQ_CONNECT_NO_PROTOCOL);
    WTQ_TEST_CHECK(wtq_connect_select_protocol(offered, 0, supported, 2,
                                               &idx) ==
                   WTQ_CONNECT_NO_PROTOCOL);

    *fp += failures;
}

/* Decode REQ_BASE with field `idx` given a replacement value (or one
 * appended regular field when idx == 5) and return the status. */
static wtq_connect_status_t decode_with(size_t idx, const char *name,
                                        size_t name_len, const char *val,
                                        size_t val_len)
{
    uint8_t buf[512];
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 0;
    char scratch[512];
    wtq_qpack_field_t f[6];
    size_t n = 5;

    memcpy(f, REQ_BASE, sizeof(REQ_BASE));
    if (idx < 5) {
        f[idx].value = val;
        f[idx].value_len = val_len;
    } else {
        f[n++] = (wtq_qpack_field_t){ name, name_len, val, val_len,
                                      false };
    }
    size_t blen = build(f, n, buf, sizeof(buf));
    if (blen == 0)
        return WTQ_CONNECT_BUFFER;
    return wtq_connect_decode_request(buf, blen, &STRICT, &req, protos, 4,
                                      &nproto, scratch, sizeof(scratch));
}

/* Decode an arbitrary field list as a request. */
static wtq_connect_status_t decode_fields(const wtq_qpack_field_t *f,
                                          size_t n,
                                          const wtq_connect_opts_t *opts)
{
    uint8_t buf[512];
    wtq_connect_req_t req;
    wtq_sf_str_t protos[4];
    size_t nproto = 0;
    char scratch[512];
    size_t blen = build(f, n, buf, sizeof(buf));

    if (blen == 0)
        return WTQ_CONNECT_BUFFER;
    return wtq_connect_decode_request(buf, blen, opts, &req, protos, 4,
                                      &nproto, scratch, sizeof(scratch));
}

/* A well-formed non-WebTransport request is NOT malformed: the peer did
 * nothing wrong and the caller must answer, not kill the connection. */
static void test_not_webtransport_classification(int *fp)
{
    int failures = 0;

    /* a plain GET with the normal request pseudo-fields */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "example.com", 11, false },
            { ":path", 5, "/index.html", 11, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* GET carrying Host instead of :authority is a valid request */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":path", 5, "/", 1, false },
            { "host", 4, "example.com", 11, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* a non-http scheme needs no authority at all */
    {
        wtq_qpack_field_t f[3] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "ftp", 3, false },
            { ":path", 5, "/f", 2, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 3, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* generic schemes compare case-insensitively: HTTPS still demands
     * an authority, and having one makes the request valid */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "HTTPS", 5, false },
            { ":authority", 10, "example.com", 11, false },
            { ":path", 5, "/", 1, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* an ordinary CONNECT tunnel: :method + :authority only */
    {
        wtq_qpack_field_t f[2] = {
            { ":method", 7, "CONNECT", 7, false },
            { ":authority", 10, "example.com:443", 15, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 2, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* another extended CONNECT protocol (RFC 8441 shape, not WT) */
    {
        wtq_qpack_field_t f[5];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[4].value = "websocket";
        f[4].value_len = 9;
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
        /* the pre-draft-13 token is "another protocol" under STRICT and
         * WebTransport only when leniency is enabled */
        f[4].value = "webtransport";
        f[4].value_len = 12;
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
        WTQ_TEST_CHECK(decode_fields(f, 5, &LEGACY) == WTQ_CONNECT_OK);
        f[4].value = "masque";
        f[4].value_len = 6;
        WTQ_TEST_CHECK(decode_fields(f, 5, &LEGACY) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }

    /* ...but structural violations stay MALFORMED */
    {
        /* :protocol on a non-CONNECT method (RFC 8441 s4) */
        wtq_qpack_field_t f[5];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[0].value = "GET";
        f[0].value_len = 3;
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    {
        /* GET missing :path */
        wtq_qpack_field_t f[3] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "example.com", 11, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 3, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    {
        /* plain CONNECT must not carry :scheme / :path (RFC 9114 s4.4) */
        wtq_qpack_field_t f[3] = {
            { ":method", 7, "CONNECT", 7, false },
            { ":authority", 10, "example.com:443", 15, false },
            { ":path", 5, "/x", 2, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 3, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    {
        /* extended CONNECT missing :path */
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "CONNECT", 7, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "example.com", 11, false },
            { ":protocol", 9, "websocket", 9, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    {
        /* an empty :protocol is not a token */
        wtq_qpack_field_t f[5];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[4].value = "";
        f[4].value_len = 0;
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* a malformed field value stays malformed even on a non-WT request */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "a\r\nx: 1", 7, false },
            { ":path", 5, "/", 1, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    *fp += failures;
}

/* RFC 9114 s4.3.1: an http/https request must carry a nonempty
 * :authority or Host; a present Host must agree with :authority and
 * must not repeat. */
static void test_host_authority_rules(int *fp)
{
    int failures = 0;

    /* neither :authority nor Host on an https request */
    {
        wtq_qpack_field_t f[3] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":path", 5, "/", 1, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 3, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* empty Host */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":path", 5, "/", 1, false },
            { "host", 4, "", 0, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* empty :authority */
    {
        wtq_qpack_field_t f[4] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "", 0, false },
            { ":path", 5, "/", 1, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* duplicate Host */
    {
        wtq_qpack_field_t f[5] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":path", 5, "/", 1, false },
            { "host", 4, "example.com", 11, false },
            { "host", 4, "example.com", 11, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* Host conflicting with :authority */
    {
        wtq_qpack_field_t f[5] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "example.com", 11, false },
            { ":path", 5, "/", 1, false },
            { "host", 4, "evil.example", 12, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    /* Host agreeing with :authority (host names are case-insensitive) */
    {
        wtq_qpack_field_t f[5] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "https", 5, false },
            { ":authority", 10, "example.com", 11, false },
            { ":path", 5, "/", 1, false },
            { "host", 4, "Example.COM", 11, false },
        };
        WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    /* a WebTransport CONNECT whose Host contradicts :authority */
    {
        wtq_qpack_field_t f[6];
        memcpy(f, REQ_BASE, sizeof(REQ_BASE));
        f[5] = (wtq_qpack_field_t){ "host", 4, "evil.example", 12,
                                    false };
        WTQ_TEST_CHECK(decode_fields(f, 6, &STRICT) ==
                       WTQ_CONNECT_MALFORMED);
    }
    *fp += failures;
}

/* :method and :protocol are HTTP tokens; :scheme obeys RFC 3986. */
static void test_token_and_scheme_syntax(int *fp)
{
    int failures = 0;

    /* method: not a token */
    {
        static const struct { const char *v; size_t n; } bad[] = {
            { "GE T", 4 }, { "", 0 }, { "GET\t", 4 }, { "G/T", 3 },
            { "GE(T", 4 },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wtq_qpack_field_t f[4] = {
                { ":method", 7, bad[i].v, bad[i].n, false },
                { ":scheme", 7, "https", 5, false },
                { ":authority", 10, "example.com", 11, false },
                { ":path", 5, "/", 1, false },
            };
            WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                           WTQ_CONNECT_MALFORMED);
        }
    }
    /* protocol: not a token */
    {
        static const struct { const char *v; size_t n; } bad[] = {
            { "web socket", 10 }, { "", 0 }, { "web/socket", 10 },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wtq_qpack_field_t f[5];
            memcpy(f, REQ_BASE, sizeof(REQ_BASE));
            f[4].value = bad[i].v;
            f[4].value_len = bad[i].n;
            WTQ_TEST_CHECK(decode_fields(f, 5, &STRICT) ==
                           WTQ_CONNECT_MALFORMED);
        }
    }
    /* scheme: RFC 3986 is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
    {
        static const struct { const char *v; size_t n; } bad[] = {
            { "1https", 6 }, { "", 0 }, { "ht tps", 6 }, { "ht_tps", 6 },
            { "+http", 5 },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wtq_qpack_field_t f[4] = {
                { ":method", 7, "GET", 3, false },
                { ":scheme", 7, bad[i].v, bad[i].n, false },
                { ":authority", 10, "example.com", 11, false },
                { ":path", 5, "/", 1, false },
            };
            WTQ_TEST_CHECK(decode_fields(f, 4, &STRICT) ==
                           WTQ_CONNECT_MALFORMED);
        }
        /* a syntactically fine, unusual scheme is merely not-WT */
        wtq_qpack_field_t ok[3] = {
            { ":method", 7, "GET", 3, false },
            { ":scheme", 7, "coap+ws", 7, false },
            { ":path", 5, "/", 1, false },
        };
        WTQ_TEST_CHECK(decode_fields(ok, 3, &STRICT) ==
                       WTQ_CONNECT_NOT_WEBTRANSPORT);
    }
    *fp += failures;
}

/* More fields than the decoder can hold is a local capacity limit, not
 * a peer error: BUFFER, distinct from MALFORMED. */
static void test_field_capacity_buffer(int *fp)
{
    int failures = 0;
    wtq_qpack_field_t f[WTQ_CONNECT_MAX_FIELDS + 1];
    static char names[WTQ_CONNECT_MAX_FIELDS + 1][8];
    size_t n = 0;

    memcpy(f, REQ_BASE, sizeof(REQ_BASE));
    n = 5;
    while (n < WTQ_CONNECT_MAX_FIELDS + 1) {
        snprintf(names[n], sizeof(names[n]), "x-%02zu", n);
        f[n] = (wtq_qpack_field_t){ names[n], strlen(names[n]), "v", 1,
                                    false };
        n++;
    }
    WTQ_TEST_CHECK(decode_fields(f, n, &STRICT) == WTQ_CONNECT_BUFFER);
    *fp += failures;
}

/* :scheme must be exactly lowercase "https" (draft-15 s3.2). */
static void test_scheme_validation(int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "https", 5) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "http", 4) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "HTTPS", 5) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "", 0) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "https2", 6) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(decode_with(1, NULL, 0, "http\rs", 6) ==
                   WTQ_CONNECT_MALFORMED);
    *fp += failures;
}

/* RFC 9110 field-content on EVERY decoded value — the CONNECT subset's
 * ignored fields included (RFC 9114 s10.3: CR/LF/NUL smuggling). */
static void test_field_value_validation(int *fp)
{
    int failures = 0;
    static const struct {
        const char *val;
        size_t len;
        wtq_connect_status_t want;
    } cases[] = {
        { "a\rb", 3, WTQ_CONNECT_MALFORMED },      /* CR */
        { "a\nb", 3, WTQ_CONNECT_MALFORMED },      /* LF */
        { "a\0b", 3, WTQ_CONNECT_MALFORMED },      /* NUL */
        { "a\rn: x", 6, WTQ_CONNECT_MALFORMED },   /* header inject */
        { "a\x01" "b", 3, WTQ_CONNECT_MALFORMED }, /* CTL */
        { "a\x0b" "b", 3, WTQ_CONNECT_MALFORMED }, /* VT */
        { "a\x7f", 2, WTQ_CONNECT_MALFORMED },     /* DEL */
        { " a", 2, WTQ_CONNECT_MALFORMED },        /* leading SP */
        { "a ", 2, WTQ_CONNECT_MALFORMED },        /* trailing SP */
        { "\ta", 2, WTQ_CONNECT_MALFORMED },       /* leading HTAB */
        { "a\t", 2, WTQ_CONNECT_MALFORMED },       /* trailing HTAB */
        { "a b\tc", 5, WTQ_CONNECT_OK },           /* interior SP/HTAB */
        { "caf\xc3\xa9", 5, WTQ_CONNECT_OK },      /* obs-text */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* :authority (2), :path (3), origin and an IGNORED regular
         * field (appended) all enforce the same rule */
        WTQ_TEST_CHECK(decode_with(2, NULL, 0, cases[i].val,
                                   cases[i].len) == cases[i].want);
        WTQ_TEST_CHECK(decode_with(3, NULL, 0, cases[i].val,
                                   cases[i].len) == cases[i].want);
        WTQ_TEST_CHECK(decode_with(5, "origin", 6, cases[i].val,
                                   cases[i].len) == cases[i].want);
        WTQ_TEST_CHECK(decode_with(5, "x-ignored", 9, cases[i].val,
                                   cases[i].len) == cases[i].want);
    }
    /* an empty generic value stays valid */
    WTQ_TEST_CHECK(decode_with(5, "x-ignored", 9, "", 0) ==
                   WTQ_CONNECT_OK);
    *fp += failures;
}

/* The same rule guards response values, ignored fields included; a
 * CR/LF/NUL in wt-protocol is a malformed MESSAGE, never an "ignored
 * structured field". */
static void test_response_value_validation(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    wtq_connect_resp_t resp;
    char scratch[256];
    static const struct {
        const char *name;
        size_t name_len;
        const char *val;
        size_t len;
        wtq_connect_status_t want;
    } cases[] = {
        { "server", 6, "a\rb", 3, WTQ_CONNECT_MALFORMED },
        { "server", 6, "a\nb", 3, WTQ_CONNECT_MALFORMED },
        { "x-ignored", 9, "a\0b", 3, WTQ_CONNECT_MALFORMED },
        { "x-ignored", 9, " a", 2, WTQ_CONNECT_MALFORMED },
        { "wt-protocol", 11, "\"x\"\rz", 5, WTQ_CONNECT_MALFORMED },
        { "wt-protocol", 11, "a\0b", 3, WTQ_CONNECT_MALFORMED },
        { "server", 6, "wtquic 0.1", 10, WTQ_CONNECT_OK },
        { "server", 6, "", 0, WTQ_CONNECT_OK },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wtq_qpack_field_t f[2] = {
            { ":status", 7, "200", 3, false },
            { cases[i].name, cases[i].name_len, cases[i].val,
              cases[i].len, false },
        };
        size_t blen = build(f, 2, buf, sizeof(buf));
        WTQ_TEST_CHECK(blen > 0);
        WTQ_TEST_CHECK(wtq_connect_decode_response(buf, blen, &STRICT,
                                                   &resp, scratch,
                                                   sizeof(scratch)) ==
                       cases[i].want);
    }
    *fp += failures;
}

/* wtquic must never GENERATE an invalid field either. */
static void test_encode_value_validation(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_connect_encode_request("bad\r\nhost", 9, "/wt", 3,
                                              NULL, 0, NULL, 0, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(wtq_connect_encode_request("example.com", 11, "/a\0b",
                                              4, NULL, 0, NULL, 0, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(wtq_connect_encode_request("example.com", 11, "/wt", 3,
                                              "https://e\rvil", 13, NULL,
                                              0, buf, sizeof(buf),
                                              &out_len) ==
                   WTQ_CONNECT_MALFORMED);
    WTQ_TEST_CHECK(wtq_connect_encode_request(" example.com", 12, "/wt",
                                              3, NULL, 0, NULL, 0, buf,
                                              sizeof(buf), &out_len) ==
                   WTQ_CONNECT_MALFORMED);
    /* valid inputs still encode */
    WTQ_TEST_CHECK(wtq_connect_encode_request("example.com", 11, "/wt", 3,
                                              "https://example.com", 19,
                                              NULL, 0, buf, sizeof(buf),
                                              &out_len) == WTQ_CONNECT_OK);
    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_request_roundtrip(&failures);
    test_response_roundtrip(&failures);
    test_request_rejects(&failures);
    test_not_webtransport_classification(&failures);
    test_host_authority_rules(&failures);
    test_token_and_scheme_syntax(&failures);
    test_field_capacity_buffer(&failures);
    test_scheme_validation(&failures);
    test_field_value_validation(&failures);
    test_response_value_validation(&failures);
    test_encode_value_validation(&failures);
    test_sf_handling(&failures);
    test_response_rejects_and_caps(&failures);
    test_select(&failures);

    WTQ_TEST_PASS("test_connect");
    return failures;
}
