/*
 * fuzz_preamble — differential + roundtrip fuzzing of the stream
 * association preamble codec.
 *
 * data[0] bit0 selects the expected direction (bidi/uni), bits 1-2 the
 * chunking mode; the rest is decoded atomically and in chunks — every
 * status, field, and total-consumed must agree; consumed never exceeds
 * offered bytes; NEED_MORE consumes everything offered; OK never
 * consumes payload past the preamble. Successful decodes roundtrip
 * through canonical encode/decode. The module returns only values (no
 * spans), and allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>

#include "proto/preamble.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static wtq_preamble_status_t drive(wtq_preamble_kind_t expect,
                                   const uint8_t *in, size_t len,
                                   unsigned mode, wtq_preamble_t *out,
                                   size_t *total)
{
    wtq_preamble_dec_t dec;
    wtq_preamble_status_t st = WTQ_PREAMBLE_NEED_MORE;
    size_t off = 0;

    wtq_preamble_dec_init(&dec);
    *total = 0;
    while (st == WTQ_PREAMBLE_NEED_MORE) {
        size_t n;
        switch (mode) {
        case 1: n = 1; break;
        case 2: n = 3; break;
        case 3: n = (off < len / 2) ? (len / 2 - off) : (len - off); break;
        default: n = len - off; break;
        }
        if (n > len - off)
            n = len - off;
        if (n == 0 && off >= len)
            break;

        size_t consumed = (size_t)-1;
        st = wtq_preamble_dec_feed(&dec, expect, in + off, n, out,
                                   &consumed);
        if (consumed == (size_t)-1 || consumed > n)
            abort();
        off += consumed;
        *total += consumed;
        if (st == WTQ_PREAMBLE_UNEXPECTED)
            break;
        if (st == WTQ_PREAMBLE_NEED_MORE && consumed < n)
            abort(); /* NEED_MORE must consume everything offered */
    }
    return st;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    if (size > 64)
        size = 64; /* max preamble is 16 bytes; keep payload evidence */

    wtq_preamble_kind_t expect = (data[0] & 1) ? WTQ_PREAMBLE_KIND_UNI
                                               : WTQ_PREAMBLE_KIND_BIDI;
    unsigned mode = (data[0] >> 1) & 3;
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    wtq_preamble_t a, b;
    size_t ta = 0, tb = 0;
    wtq_preamble_status_t sa = drive(expect, in, len, 0, &a, &ta);
    wtq_preamble_status_t sb =
        drive(expect, in, len, mode == 0 ? 1 : mode, &b, &tb);

    if (sa != sb || ta != tb)
        abort(); /* chunking changed the outcome */

    if (sa == WTQ_PREAMBLE_OK) {
        if (a.kind != b.kind || a.session_id != b.session_id ||
            a.header_len != b.header_len || a.wire_type != b.wire_type)
            abort();
        if (ta > len)
            abort(); /* payload bytes must remain unconsumed */

        /* canonical roundtrip */
        uint8_t reenc[16];
        size_t elen = 0;
        if (wtq_preamble_encode(a.kind, a.session_id, reenc, sizeof(reenc),
                                &elen) != WTQ_PREAMBLE_OK)
            abort();
        wtq_preamble_t c;
        size_t tc = 0;
        if (drive(a.kind, reenc, elen, 1, &c, &tc) != WTQ_PREAMBLE_OK)
            abort();
        if (c.session_id != a.session_id || c.kind != a.kind ||
            tc != elen)
            abort();
    } else if (sa == WTQ_PREAMBLE_UNEXPECTED) {
        if (a.wire_type != b.wire_type)
            abort();
    }

    return 0;
}
