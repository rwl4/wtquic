/*
 * fuzz_sf_string — Structured Fields string item/list parser fuzzing.
 *
 * data[0] selects the mode (bit0: item vs list; bit1: strict vs
 * lenient-tokens); the remainder is parsed as the field value. Every
 * outcome must be a clean status. If parsing succeeds, every returned
 * span must lie inside out_buf with sane lengths, and canonical
 * re-encode → re-parse must produce identical member values.
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/sf_string.h"

#define MAX_MEMBERS 16
#define OUT_CAP 512

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check_span(wtq_sf_str_t v, const char *out_buf, size_t out_cap)
{
    if (v.len > out_cap)
        abort();
    if (v.len > 0 &&
        (v.data < out_buf || v.data + v.len > out_buf + out_cap))
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    if (size > 1024)
        size = 1024;

    bool as_list = (data[0] & 1) != 0;
    bool lenient = (data[0] & 2) != 0;
    const char *in = (const char *)data + 1;
    size_t in_len = size - 1;

    char out_buf[OUT_CAP];
    char reenc[OUT_CAP * 2 + MAX_MEMBERS * 4];
    char out_buf2[OUT_CAP];

    if (!as_list) {
        wtq_sf_str_t v = { NULL, 0 };
        wtq_sf_status_t st = wtq_sf_string_parse_item(in, in_len, lenient,
                                                      out_buf, OUT_CAP, &v);
        if (st != WTQ_SF_OK && st != WTQ_SF_BUFFER &&
            st != WTQ_SF_MALFORMED)
            abort();
        if (st == WTQ_SF_OK) {
            check_span(v, out_buf, OUT_CAP);
            size_t elen = 0;
            if (wtq_sf_string_encode_item(v.data, v.len, reenc,
                                          sizeof(reenc), &elen) !=
                WTQ_SF_OK)
                abort(); /* parsed values are always encodable */
            wtq_sf_str_t v2 = { NULL, 0 };
            if (wtq_sf_string_parse_item(reenc, elen, false, out_buf2,
                                         OUT_CAP, &v2) != WTQ_SF_OK)
                abort();
            if (v2.len != v.len ||
                (v.len && memcmp(v2.data, v.data, v.len) != 0))
                abort();
        }
        return 0;
    }

    wtq_sf_str_t m[MAX_MEMBERS];
    size_t n = 0;
    wtq_sf_status_t st = wtq_sf_string_parse_list(in, in_len, lenient,
                                                  out_buf, OUT_CAP, m,
                                                  MAX_MEMBERS, &n);
    if (st != WTQ_SF_OK && st != WTQ_SF_BUFFER && st != WTQ_SF_MALFORMED)
        abort();
    if (st == WTQ_SF_OK && n > 0) {
        if (n > MAX_MEMBERS)
            abort();
        for (size_t i = 0; i < n; i++)
            check_span(m[i], out_buf, OUT_CAP);

        size_t elen = 0;
        if (wtq_sf_string_encode_list(m, n, reenc, sizeof(reenc), &elen) !=
            WTQ_SF_OK)
            abort();
        wtq_sf_str_t m2[MAX_MEMBERS];
        size_t n2 = 0;
        if (wtq_sf_string_parse_list(reenc, elen, false, out_buf2, OUT_CAP,
                                     m2, MAX_MEMBERS, &n2) != WTQ_SF_OK)
            abort();
        if (n2 != n)
            abort();
        for (size_t i = 0; i < n; i++)
            if (m2[i].len != m[i].len ||
                (m[i].len &&
                 memcmp(m2[i].data, m[i].data, m[i].len) != 0))
                abort();
    }

    return 0;
}
