#include "h3_frame.h"

size_t wtq_h3_frame_header_len(uint64_t type, uint64_t length)
{
    size_t tl = wtq_varint_len(type);
    size_t ll = wtq_varint_len(length);

    if (tl == 0 || ll == 0)
        return 0;
    return tl + ll;
}

wtq_h3_frame_status_t wtq_h3_frame_encode_header(uint64_t type,
                                                 uint64_t length,
                                                 uint8_t *dst, size_t cap,
                                                 size_t *out_len)
{
    size_t need = wtq_h3_frame_header_len(type, length);

    if (need == 0)
        return WTQ_H3_FRAME_RANGE;
    if (cap < need)
        return WTQ_H3_FRAME_BUFFER;

    size_t tl = 0;
    size_t ll = 0;
    /* Capacity was checked for the whole header; the varint encodes
     * cannot fail from here. */
    (void)wtq_varint_encode(type, dst, cap, &tl);
    (void)wtq_varint_encode(length, dst + tl, cap - tl, &ll);

    *out_len = tl + ll;
    return WTQ_H3_FRAME_OK;
}

wtq_h3_frame_status_t wtq_h3_frame_decode_header(const uint8_t *src,
                                                 size_t len,
                                                 wtq_h3_frame_t *out)
{
    uint64_t type = 0;
    size_t tl = 0;
    wtq_varint_status_t st = wtq_varint_decode(src, len, &type, &tl);
    if (st != WTQ_VARINT_OK)
        return st;

    uint64_t length = 0;
    size_t ll = 0;
    st = wtq_varint_decode(src + tl, len - tl, &length, &ll);
    if (st != WTQ_VARINT_OK)
        return st;

    out->type = type;
    out->length = length;
    out->header_len = tl + ll;
    return WTQ_H3_FRAME_OK;
}

void wtq_h3_frame_dec_init(wtq_h3_frame_dec_t *dec)
{
    wtq_varint_dec_init(&dec->vi);
    dec->type = 0;
    dec->hdr_bytes = 0;
    dec->state = WTQ_H3_FRAME_DEC_TYPE;
}

wtq_h3_frame_status_t wtq_h3_frame_dec_feed(wtq_h3_frame_dec_t *dec,
                                            const uint8_t *src, size_t len,
                                            wtq_h3_frame_t *out,
                                            size_t *consumed)
{
    size_t eaten = 0;

    if (dec->state == WTQ_H3_FRAME_DEC_TYPE) {
        uint64_t v = 0;
        size_t c = 0;
        wtq_varint_status_t st = wtq_varint_dec_feed(&dec->vi, src, len,
                                                     &v, &c);
        eaten += c;
        dec->hdr_bytes += c;
        if (st != WTQ_VARINT_OK) {
            *consumed = eaten;
            return st;
        }
        dec->type = v;
        dec->state = WTQ_H3_FRAME_DEC_LENGTH;
        /* the varint decoder auto-reset; continue with the Length */
    }

    uint64_t length = 0;
    size_t c = 0;
    /* Guard the pointer arithmetic: src may be NULL on a zero-length
     * probe (NULL + 0 is undefined in C). eaten < len implies src is
     * non-NULL. */
    const uint8_t *next = (eaten < len) ? src + eaten : src;
    wtq_varint_status_t st = wtq_varint_dec_feed(&dec->vi, next,
                                                 len - eaten, &length, &c);
    eaten += c;
    dec->hdr_bytes += c;
    *consumed = eaten;
    if (st != WTQ_VARINT_OK)
        return st;

    out->type = dec->type;
    out->length = length;
    out->header_len = dec->hdr_bytes;
    wtq_h3_frame_dec_init(dec); /* immediately reusable */
    return WTQ_H3_FRAME_OK;
}
