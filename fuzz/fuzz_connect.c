/*
 * fuzz_connect — extended CONNECT request/response decoder fuzzing.
 *
 * data[0]: bit0 = request/response, bit1 = strict/lenient SF, bit2 =
 * legacy :protocol acceptance, bits 3-5 = capacity variation. The rest
 * is decoded as a QPACK field-section payload. On OK, every returned
 * span must lie in caller scratch, the QPACK static table, or static ""
 * (bounded uintptr containment — no relational pointer UB), and the
 * semantic fields are re-encoded and re-decoded for agreement.
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/connect.h"
#include "proto/qpack_static.h"

#define MAX_PROTOS 8
#define SCRATCH_CAP 1024

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool span_in(const char *p, size_t len, const char *base,
                    size_t cap)
{
    uintptr_t up = (uintptr_t)p;
    uintptr_t ub = (uintptr_t)base;

    if (len == 0)
        return true; /* zero-length spans point at static "" */
    if (len > cap)
        return false;
    return up >= ub && up - ub <= cap - len;
}

static bool span_is_static(const char *p, size_t len)
{
    for (uint64_t i = 0; i < WTQ_QPACK_STATIC_COUNT; i++) {
        const char *n;
        const char *v;
        size_t nl;
        size_t vl;
        (void)wtq_qpack_static_get(i, &n, &nl, &v, &vl);
        if ((p == n && len == nl) || (p == v && len == vl))
            return true;
    }
    return false;
}

static void check_span(const char *p, size_t len, const char *scratch,
                       size_t cap)
{
    if (!span_in(p, len, scratch, cap) && !span_is_static(p, len))
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    if (size > 4096)
        size = 4096;

    wtq_connect_opts_t opts = {
        (data[0] & 2) != 0, /* lenient_sf_tokens */
        (data[0] & 4) != 0, /* accept_legacy_protocol */
    };
    bool as_response = (data[0] & 1) != 0;
    size_t scratch_cap = ((data[0] >> 3) & 7) * 128 + 16; /* 16..912 */
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    char scratch[SCRATCH_CAP];

    if (as_response) {
        wtq_connect_resp_t resp;
        wtq_connect_status_t st = wtq_connect_decode_response(
            in, len, &opts, &resp, scratch, scratch_cap);
        if (st != WTQ_CONNECT_OK && st != WTQ_CONNECT_BUFFER &&
            st != WTQ_CONNECT_MALFORMED)
            abort();
        if (st != WTQ_CONNECT_OK)
            return 0;
        if (resp.has_protocol) {
            check_span(resp.protocol.data, resp.protocol.len, scratch,
                       scratch_cap);
            if (resp.protocol.len == 0)
                abort(); /* empty protocols must be ignored */
        }

        /* semantic re-encode/decode */
        uint8_t reenc[2048];
        size_t relen = 0;
        const wtq_sf_str_t *sel =
            resp.has_protocol ? &resp.protocol : NULL;
        if (wtq_connect_encode_response(resp.status, sel, reenc,
                                        sizeof(reenc), &relen) !=
            WTQ_CONNECT_OK)
            abort();
        wtq_connect_resp_t r2;
        char scratch2[SCRATCH_CAP];
        if (wtq_connect_decode_response(reenc, relen, &opts, &r2, scratch2,
                                        sizeof(scratch2)) !=
            WTQ_CONNECT_OK)
            abort();
        if (r2.status != resp.status ||
            r2.has_protocol != resp.has_protocol)
            abort();
        if (r2.has_protocol &&
            (r2.protocol.len != resp.protocol.len ||
             memcmp(r2.protocol.data, resp.protocol.data,
                    r2.protocol.len) != 0))
            abort();
        return 0;
    }

    wtq_connect_req_t req;
    wtq_sf_str_t protos[MAX_PROTOS];
    size_t nproto = 0;
    wtq_connect_status_t st = wtq_connect_decode_request(
        in, len, &opts, &req, protos, MAX_PROTOS, &nproto, scratch,
        scratch_cap);
    if (st != WTQ_CONNECT_OK && st != WTQ_CONNECT_BUFFER &&
        st != WTQ_CONNECT_MALFORMED)
        abort();
    if (st != WTQ_CONNECT_OK)
        return 0;

    check_span(req.authority, req.authority_len, scratch, scratch_cap);
    check_span(req.path, req.path_len, scratch, scratch_cap);
    if (req.has_origin)
        check_span(req.origin, req.origin_len, scratch, scratch_cap);
    if (req.authority_len == 0 || req.path_len == 0)
        abort(); /* required non-empty */
    for (size_t i = 0; i < nproto; i++) {
        check_span(protos[i].data, protos[i].len, scratch, scratch_cap);
        if (protos[i].len == 0)
            abort();
    }

    /* semantic re-encode/decode */
    uint8_t reenc[4096];
    size_t relen = 0;
    if (wtq_connect_encode_request(
            req.authority, req.authority_len, req.path, req.path_len,
            req.has_origin ? req.origin : NULL,
            req.has_origin ? req.origin_len : 0, protos, nproto, reenc,
            sizeof(reenc), &relen) != WTQ_CONNECT_OK)
        return 0; /* e.g. protocols with non-SF-encodable bytes */
    wtq_connect_req_t q2;
    wtq_sf_str_t protos2[MAX_PROTOS];
    size_t nproto2 = 0;
    char scratch2[SCRATCH_CAP];
    if (wtq_connect_decode_request(reenc, relen, &opts, &q2, protos2,
                                   MAX_PROTOS, &nproto2, scratch2,
                                   sizeof(scratch2)) != WTQ_CONNECT_OK)
        abort();
    if (q2.authority_len != req.authority_len ||
        memcmp(q2.authority, req.authority, req.authority_len) != 0 ||
        q2.path_len != req.path_len ||
        memcmp(q2.path, req.path, req.path_len) != 0 ||
        q2.has_origin != req.has_origin || nproto2 != nproto)
        abort();
    for (size_t i = 0; i < nproto; i++)
        if (protos2[i].len != protos[i].len ||
            memcmp(protos2[i].data, protos[i].data, protos[i].len) != 0)
            abort();

    return 0;
}
