#include "preamble.h"

/* Decoder states. */
#define PRE_DEC_TYPE 0
#define PRE_DEC_SESSION 1
#define PRE_DEC_POISONED 2

static uint64_t kind_codepoint(wtq_preamble_kind_t kind)
{
    if (kind == WTQ_PREAMBLE_KIND_BIDI)
        return WTQ_PREAMBLE_BIDI;
    if (kind == WTQ_PREAMBLE_KIND_UNI)
        return WTQ_PREAMBLE_UNI;
    return UINT64_MAX; /* invalid kind sentinel */
}

wtq_preamble_status_t wtq_preamble_encode(wtq_preamble_kind_t kind,
                                          uint64_t session_id,
                                          uint8_t *dst, size_t cap,
                                          size_t *out_len)
{
    uint64_t type = kind_codepoint(kind);

    if (type == UINT64_MAX || session_id > WTQ_VARINT_MAX)
        return WTQ_PREAMBLE_RANGE;

    size_t need = wtq_varint_len(type) + wtq_varint_len(session_id);
    if (cap < need)
        return WTQ_PREAMBLE_BUFFER;

    size_t tl = 0;
    size_t sl = 0;
    /* Capacity checked for the whole preamble; cannot fail from here. */
    (void)wtq_varint_encode(type, dst, cap, &tl);
    (void)wtq_varint_encode(session_id, dst + tl, cap - tl, &sl);

    *out_len = tl + sl;
    return WTQ_PREAMBLE_OK;
}

void wtq_preamble_dec_init(wtq_preamble_dec_t *dec)
{
    wtq_varint_dec_init(&dec->vi);
    dec->state = PRE_DEC_TYPE;
    dec->wire_type = 0;
    dec->hdr_bytes = 0;
}

wtq_preamble_status_t wtq_preamble_dec_feed(wtq_preamble_dec_t *dec,
                                            wtq_preamble_kind_t expect,
                                            const uint8_t *src, size_t len,
                                            wtq_preamble_t *out,
                                            size_t *consumed)
{
    size_t eaten = 0;

    if (dec->state == PRE_DEC_POISONED) {
        out->wire_type = dec->wire_type;
        *consumed = 0;
        return WTQ_PREAMBLE_UNEXPECTED;
    }

    if (dec->state == PRE_DEC_TYPE) {
        uint64_t v = 0;
        size_t c = 0;
        wtq_varint_status_t st = wtq_varint_dec_feed(&dec->vi, src, len,
                                                     &v, &c);
        eaten += c;
        dec->hdr_bytes += c;
        if (st != WTQ_VARINT_OK) {
            *consumed = eaten;
            return st; /* NEED_MORE */
        }
        dec->wire_type = v;
        if (v != kind_codepoint(expect)) {
            dec->state = PRE_DEC_POISONED;
            out->wire_type = v;
            *consumed = eaten;
            return WTQ_PREAMBLE_UNEXPECTED;
        }
        dec->state = PRE_DEC_SESSION;
    }

    uint64_t sid = 0;
    size_t c = 0;
    /* Guard pointer arithmetic on zero-length probes (NULL + 0 is UB;
     * eaten < len implies src is non-NULL). */
    const uint8_t *next = (eaten < len) ? src + eaten : src;
    wtq_varint_status_t st = wtq_varint_dec_feed(&dec->vi, next,
                                                 len - eaten, &sid, &c);
    eaten += c;
    dec->hdr_bytes += c;
    *consumed = eaten;
    if (st != WTQ_VARINT_OK)
        return st; /* NEED_MORE */

    out->kind = expect;
    out->session_id = sid;
    out->header_len = dec->hdr_bytes;
    out->wire_type = dec->wire_type;
    wtq_preamble_dec_init(dec); /* immediately reusable */
    return WTQ_PREAMBLE_OK;
}

wtq_preamble_status_t wtq_preamble_decode(wtq_preamble_kind_t expect,
                                          const uint8_t *src, size_t len,
                                          wtq_preamble_t *out)
{
    wtq_preamble_dec_t dec;
    size_t consumed = 0;

    wtq_preamble_dec_init(&dec);
    return wtq_preamble_dec_feed(&dec, expect, src, len, out, &consumed);
}
