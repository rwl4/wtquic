#include "varint.h"

size_t wtq_varint_len(uint64_t value)
{
    if (value < (UINT64_C(1) << 6))
        return 1;
    if (value < (UINT64_C(1) << 14))
        return 2;
    if (value < (UINT64_C(1) << 30))
        return 4;
    if (value <= WTQ_VARINT_MAX)
        return 8;
    return 0;
}

size_t wtq_varint_len_from_first(uint8_t first_byte)
{
    /* Top two bits: 00=1, 01=2, 10=4, 11=8. */
    return (size_t)1 << (first_byte >> 6);
}

bool wtq_varint_is_minimal(uint64_t value, size_t encoded_len)
{
    return wtq_varint_len(value) == encoded_len;
}

wtq_varint_status_t wtq_varint_encode(uint64_t value, uint8_t *dst,
                                      size_t cap, size_t *out_len)
{
    size_t need = wtq_varint_len(value);

    if (need == 0)
        return WTQ_VARINT_RANGE;
    if (cap < need)
        return WTQ_VARINT_BUFFER;

    /* Big-endian payload; length tag in the top two bits of byte 0.
     * need is a power of two, so need/2 trailing zeros... the tag is
     * log2(need): 1->0, 2->1, 4->2, 8->3. */
    uint8_t tag = (uint8_t)((need == 1) ? 0 : (need == 2) ? 1
                            : (need == 4) ? 2 : 3);
    for (size_t i = 0; i < need; i++)
        dst[i] = (uint8_t)(value >> (8 * (need - 1 - i)));
    dst[0] = (uint8_t)((dst[0] & 0x3f) | (tag << 6));

    *out_len = need;
    return WTQ_VARINT_OK;
}

wtq_varint_status_t wtq_varint_decode(const uint8_t *src, size_t len,
                                      uint64_t *value, size_t *consumed)
{
    if (len == 0)
        return WTQ_VARINT_NEED_MORE;

    size_t need = wtq_varint_len_from_first(src[0]);
    if (len < need)
        return WTQ_VARINT_NEED_MORE;

    uint64_t v = src[0] & 0x3f;
    for (size_t i = 1; i < need; i++)
        v = (v << 8) | src[i];

    *value = v;
    *consumed = need;
    return WTQ_VARINT_OK;
}

void wtq_varint_dec_init(wtq_varint_dec_t *dec)
{
    dec->acc = 0;
    dec->need = 0;
    dec->have = 0;
}

wtq_varint_status_t wtq_varint_dec_feed(wtq_varint_dec_t *dec,
                                        const uint8_t *src, size_t len,
                                        uint64_t *value, size_t *consumed)
{
    size_t eaten = 0;

    if (dec->need == 0) {
        if (len == 0) {
            *consumed = 0;
            return WTQ_VARINT_NEED_MORE;
        }
        dec->need = (uint8_t)wtq_varint_len_from_first(src[0]);
        dec->acc = src[0] & 0x3f;
        dec->have = 1;
        eaten = 1;
    }

    while (dec->have < dec->need && eaten < len) {
        dec->acc = (dec->acc << 8) | src[eaten];
        dec->have++;
        eaten++;
    }

    if (dec->have < dec->need) {
        *consumed = eaten;
        return WTQ_VARINT_NEED_MORE;
    }

    *value = dec->acc;
    *consumed = eaten;
    wtq_varint_dec_init(dec); /* immediately reusable for the next varint */
    return WTQ_VARINT_OK;
}
