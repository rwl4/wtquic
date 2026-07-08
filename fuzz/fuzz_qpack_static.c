/*
 * fuzz_qpack_static — field-section decoder/encoder fuzzing.
 *
 * data[0] selects capacity limits (fields/scratch) and a sub-mode that
 * also exercises the prefixed-integer helpers; the rest is decoded as a
 * field section. Every returned span must lie either inside the caller
 * scratch or inside the static table's own strings. Successful decodes
 * are canonically re-encoded and re-decoded, then compared field by
 * field (names and values byte-equal).
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/qpack_static.h"

#define MAX_FIELDS 24
#define SCRATCH_CAP 1024

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Bounded containment via uintptr_t: relational comparison of pointers
 * into unrelated objects (static-table strings vs stack scratch) is UB,
 * so the check must not use raw pointer ordering. Zero-length spans are
 * always acceptable (they point at static ""). */
static bool span_in(const char *p, size_t len, const char *base,
                    size_t cap)
{
    uintptr_t up = (uintptr_t)p;
    uintptr_t ub = (uintptr_t)base;

    if (len == 0)
        return true;
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

static void fuzz_ints(const uint8_t *data, size_t size)
{
    if (size == 0)
        return;
    unsigned prefix_bits = 3 + (data[0] & 7);
    if (prefix_bits > 8)
        prefix_bits = 8;

    uint64_t v = 0;
    size_t consumed = 0;
    wtq_qpack_status_t st = wtq_qpack_int_decode(data + 1, size - 1,
                                                 prefix_bits, &v,
                                                 &consumed);
    if (st == WTQ_QPACK_OK) {
        if (consumed > size - 1)
            abort();
        uint8_t reenc[16];
        size_t relen = 0;
        if (wtq_qpack_int_encode(v, 0, prefix_bits, reenc, sizeof(reenc),
                                 &relen) != WTQ_QPACK_OK)
            abort(); /* decoded values are always encodable */
        uint64_t v2 = 0;
        size_t c2 = 0;
        if (wtq_qpack_int_decode(reenc, relen, prefix_bits, &v2, &c2) !=
                WTQ_QPACK_OK ||
            v2 != v || c2 != relen)
            abort();
    } else if (st != WTQ_QPACK_NEED_MORE && st != WTQ_QPACK_MALFORMED) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    if (size > 4096)
        size = 4096;

    /* Sub-mode: also drive the integer helpers on the same bytes. */
    if (data[0] & 0x80)
        fuzz_ints(data + 1, size - 1);

    /* Vary capacity limits from the mode byte. */
    size_t max_fields = 1 + (data[0] & 0x0f);          /* 1..16 */
    size_t scratch_cap = ((data[0] >> 4) & 7) * 96 + 8; /* 8..680 */
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    wtq_qpack_field_t fields[MAX_FIELDS];
    size_t count = 0;
    char scratch[SCRATCH_CAP];

    wtq_qpack_status_t st = wtq_qpack_decode_section(in, len, fields,
                                                     max_fields, &count,
                                                     scratch, scratch_cap);
    if (st != WTQ_QPACK_OK && st != WTQ_QPACK_BUFFER &&
        st != WTQ_QPACK_MALFORMED)
        abort();
    if (st != WTQ_QPACK_OK)
        return 0;

    if (count > max_fields)
        abort();
    for (size_t i = 0; i < count; i++) {
        if (!span_in(fields[i].name, fields[i].name_len, scratch,
                     scratch_cap) &&
            !span_is_static(fields[i].name, fields[i].name_len))
            abort();
        if (!span_in(fields[i].value, fields[i].value_len, scratch,
                     scratch_cap) &&
            !span_is_static(fields[i].value, fields[i].value_len))
            abort();
    }

    /* Canonical roundtrip preserves every field's name/value bytes. */
    uint8_t reenc[8192];
    size_t relen = 0;
    if (wtq_qpack_encode_section(fields, count, reenc, sizeof(reenc),
                                 &relen) != WTQ_QPACK_OK)
        abort(); /* decoded fields are always encodable */

    wtq_qpack_field_t fields2[MAX_FIELDS];
    size_t count2 = 0;
    char scratch2[SCRATCH_CAP];
    if (wtq_qpack_decode_section(reenc, relen, fields2, MAX_FIELDS,
                                 &count2, scratch2, sizeof(scratch2)) !=
        WTQ_QPACK_OK)
        abort();
    if (count2 != count)
        abort();
    for (size_t i = 0; i < count; i++) {
        if (fields2[i].name_len != fields[i].name_len ||
            memcmp(fields2[i].name, fields[i].name,
                   fields[i].name_len) != 0)
            abort();
        if (fields2[i].value_len != fields[i].value_len ||
            memcmp(fields2[i].value, fields[i].value,
                   fields[i].value_len) != 0)
            abort();
    }

    return 0;
}
