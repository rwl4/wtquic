/*
 * fuzz_varint — differential + roundtrip fuzzing of the varint module.
 *
 * For every input:
 *   1. Decode with the complete decoder.
 *   2. Decode the same bytes byte-by-byte with the incremental decoder.
 *      The two must agree exactly (status, value, consumed) — chunking
 *      must never change the result.
 *   3. If decode succeeded: re-encode canonically, decode again, and
 *      require value identity and canonical length; if the input was
 *      already minimal, the re-encoding must be byte-identical.
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/varint.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 64)
        size = 64; /* a varint needs at most 8 bytes; keep the corpus tight */

    uint64_t value = 0;
    size_t consumed = 0;
    wtq_varint_status_t st = wtq_varint_decode(data, size, &value, &consumed);

    /* Byte-by-byte incremental decode must agree exactly. */
    wtq_varint_dec_t dec;
    wtq_varint_dec_init(&dec);
    uint64_t ivalue = 0;
    size_t itotal = 0;
    wtq_varint_status_t ist = WTQ_VARINT_NEED_MORE;
    for (size_t i = 0; i < size && ist == WTQ_VARINT_NEED_MORE; i++) {
        size_t ic = (size_t)-1;
        ist = wtq_varint_dec_feed(&dec, data + i, 1, &ivalue, &ic);
        /* consumed is set on every return; with 1-byte feeds it is
         * exactly 1 whenever a byte was offered. */
        if (ic != 1)
            abort();
        itotal += ic;
    }

    if (st == WTQ_VARINT_OK) {
        if (ist != WTQ_VARINT_OK || ivalue != value || itotal != consumed)
            abort();

        /* Canonical roundtrip. */
        uint8_t reenc[8];
        size_t relen = 0;
        if (wtq_varint_encode(value, reenc, sizeof(reenc), &relen) !=
            WTQ_VARINT_OK)
            abort();
        if (relen != wtq_varint_len(value))
            abort();

        uint64_t v2 = 0;
        size_t c2 = 0;
        if (wtq_varint_decode(reenc, relen, &v2, &c2) != WTQ_VARINT_OK)
            abort();
        if (v2 != value || c2 != relen)
            abort();

        /* Minimal input must re-encode byte-identically. */
        if (wtq_varint_is_minimal(value, consumed) &&
            (relen != consumed || memcmp(reenc, data, relen) != 0))
            abort();
    } else {
        /* Incomplete input: incremental must agree it is incomplete. */
        if (st != WTQ_VARINT_NEED_MORE || ist == WTQ_VARINT_OK)
            abort();
    }

    return 0;
}
