/*
 * fuzz_capsule — differential + roundtrip fuzzing of the capsule codec.
 *
 * data[0] selects a chunk-split strategy; the rest is fed to the
 * incremental decoder both atomically and in chunks — statuses, kinds,
 * fields, total consumed, AND reason byte contents must agree; spans
 * must stay inside the decoder's reason buffer; consumed must never
 * exceed the input offered. Complete CLOSE/DRAIN capsules are
 * re-encoded and re-decoded for full roundtrip identity including
 * reason bytes.
 *
 * Decoders are owned by the caller so emitted reason spans (which point
 * into decoder state) stay valid for the comparisons — a previous
 * version kept the decoder inside the drive helper and read the span
 * after return (stack-use-after-return, caught with
 * ASAN_OPTIONS=detect_stack_use_after_return=1, now enforced on the
 * fuzz smoke/corpus lane).
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/capsule.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Drive the CALLER's decoder over input with a chunking pattern.
 * mode: 0 whole, 1 byte-wise, 2 three-byte, 3 split at half. The
 * emitted out->reason points into *dec, which the caller keeps alive. */
static wtq_capsule_status_t drive(wtq_capsule_dec_t *dec,
                                  const uint8_t *in, size_t len,
                                  unsigned mode, wtq_capsule_t *out,
                                  size_t *total)
{
    wtq_capsule_status_t st = WTQ_CAPSULE_NEED_MORE;
    size_t off = 0;

    wtq_capsule_dec_init(dec);
    *total = 0;
    while (st == WTQ_CAPSULE_NEED_MORE) {
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
            break; /* input exhausted, still NEED_MORE */

        size_t consumed = (size_t)-1;
        st = wtq_capsule_dec_feed(dec, in + off, n, out, &consumed);
        if (consumed == (size_t)-1 || consumed > n)
            abort(); /* consumed set on every return, never over-consume */
        off += consumed;
        *total += consumed;
        if (st == WTQ_CAPSULE_MALFORMED)
            break;
        if (st == WTQ_CAPSULE_NEED_MORE && consumed < n)
            abort(); /* NEED_MORE must consume everything offered */
    }
    if (st == WTQ_CAPSULE_OK) {
        if (out->reason_len > WTQ_CAPSULE_MAX_REASON)
            abort();
        /* the span must lie inside this decoder's reason buffer */
        if (out->reason_len > 0 &&
            (out->reason < dec->reason ||
             out->reason + out->reason_len >
                 dec->reason + WTQ_CAPSULE_MAX_REASON))
            abort();
    }
    return st;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    if (size > 2048)
        size = 2048;

    unsigned mode = data[0] & 3;
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    /* Caller-owned decoders: emitted reason spans stay valid below. */
    wtq_capsule_dec_t dec_a, dec_b, dec_c;
    wtq_capsule_t a, b;
    size_t ta = 0, tb = 0;
    wtq_capsule_status_t sa = drive(&dec_a, in, len, 0, &a, &ta);
    wtq_capsule_status_t sb = drive(&dec_b, in, len,
                                    mode == 0 ? 1 : mode, &b, &tb);

    if (sa != sb || ta != tb)
        abort(); /* chunking changed the outcome */
    if (sa == WTQ_CAPSULE_OK) {
        if (a.kind != b.kind || a.type != b.type || a.length != b.length ||
            a.header_len != b.header_len)
            abort();
        if (a.kind == WTQ_CAPSULE_KIND_CLOSE) {
            if (a.close_code != b.close_code ||
                a.reason_len != b.reason_len)
                abort();
            if (a.reason_len > 0 &&
                memcmp(a.reason, b.reason, a.reason_len) != 0)
                abort(); /* atomic vs chunked reason contents differ */

            /* roundtrip: canonical re-encode decodes identically,
             * including reason bytes */
            uint8_t reenc[8 + 4 + WTQ_CAPSULE_MAX_REASON];
            size_t elen = 0;
            if (wtq_capsule_encode_close(a.close_code, a.reason,
                                         a.reason_len, reenc,
                                         sizeof(reenc), &elen) !=
                WTQ_CAPSULE_OK)
                abort();
            wtq_capsule_t c;
            size_t tc = 0;
            if (drive(&dec_c, reenc, elen, 1, &c, &tc) != WTQ_CAPSULE_OK)
                abort();
            if (c.kind != WTQ_CAPSULE_KIND_CLOSE ||
                c.close_code != a.close_code ||
                c.reason_len != a.reason_len)
                abort();
            if (c.reason_len > 0 &&
                memcmp(c.reason, a.reason, c.reason_len) != 0)
                abort(); /* re-decode reason contents differ */
        }
        if (a.kind == WTQ_CAPSULE_KIND_DRAIN) {
            uint8_t reenc[8];
            size_t elen = 0;
            if (wtq_capsule_encode_drain(reenc, sizeof(reenc), &elen) !=
                WTQ_CAPSULE_OK)
                abort();
            wtq_capsule_t c;
            size_t tc = 0;
            if (drive(&dec_c, reenc, elen, 1, &c, &tc) != WTQ_CAPSULE_OK ||
                c.kind != WTQ_CAPSULE_KIND_DRAIN)
                abort();
        }
    }

    return 0;
}
