/*
 * fuzz_h3_frame — differential + roundtrip fuzzing of the H3 frame-header
 * codec.
 *
 * For every input:
 *   1. Decode with the complete decoder.
 *   2. Decode byte-by-byte with the incremental decoder; statuses, fields
 *      and consumed counts must agree exactly, and consumed must be set
 *      on every feed.
 *   3. If decode succeeded: canonically re-encode and decode again; if
 *      the original header used minimal varints for both fields, the
 *      re-encoding must be byte-identical to the original header bytes.
 *
 * Inputs are capped at 40 bytes: a maximal header is 16 bytes, and the
 * surplus keeps trailing-payload bytes in play so "header stops before
 * payload" is continuously exercised. The module allocates nothing; any
 * invariant violation aborts.
 */

#include <stdlib.h>
#include <string.h>

#include "proto/h3_frame.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 40)
        size = 40;

    wtq_h3_frame_t f = { 0, 0, 0 };
    wtq_h3_frame_status_t st = wtq_h3_frame_decode_header(data, size, &f);

    /* Byte-by-byte incremental decode must agree exactly. */
    wtq_h3_frame_dec_t dec;
    wtq_h3_frame_dec_init(&dec);
    wtq_h3_frame_t g = { 0, 0, 0 };
    size_t itotal = 0;
    wtq_h3_frame_status_t ist = WTQ_H3_FRAME_NEED_MORE;
    for (size_t i = 0; i < size && ist == WTQ_H3_FRAME_NEED_MORE; i++) {
        size_t ic = (size_t)-1;
        ist = wtq_h3_frame_dec_feed(&dec, data + i, 1, &g, &ic);
        if (ic != 1) /* consumed set on every feed; 1-byte feeds eat 1 */
            abort();
        itotal += ic;
    }

    if (st == WTQ_H3_FRAME_OK) {
        if (ist != WTQ_H3_FRAME_OK || g.type != f.type ||
            g.length != f.length || g.header_len != f.header_len ||
            itotal != f.header_len)
            abort();

        /* Canonical roundtrip. */
        uint8_t reenc[16];
        size_t relen = 0;
        if (wtq_h3_frame_encode_header(f.type, f.length, reenc,
                                       sizeof(reenc), &relen) !=
            WTQ_H3_FRAME_OK)
            abort();
        if (relen != wtq_h3_frame_header_len(f.type, f.length))
            abort();

        wtq_h3_frame_t h = { 0, 0, 0 };
        if (wtq_h3_frame_decode_header(reenc, relen, &h) != WTQ_H3_FRAME_OK)
            abort();
        if (h.type != f.type || h.length != f.length ||
            h.header_len != relen)
            abort();

        /* Fully-minimal input re-encodes byte-identically. */
        if (relen == f.header_len &&
            memcmp(reenc, data, relen) != 0)
            abort();
    } else {
        /* Incomplete input: incremental must agree. */
        if (st != WTQ_H3_FRAME_NEED_MORE || ist == WTQ_H3_FRAME_OK)
            abort();
        if (itotal != size)
            abort(); /* NEED_MORE consumed everything offered */
    }

    return 0;
}
