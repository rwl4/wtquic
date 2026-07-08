#include "capsule.h"

/* Decoder states. */
#define CAP_DEC_HEADER 0
#define CAP_DEC_PAYLOAD 1
#define CAP_DEC_POISONED 2

wtq_capsule_status_t wtq_capsule_encode_header(uint64_t type,
                                               uint64_t length,
                                               uint8_t *dst, size_t cap,
                                               size_t *out_len)
{
    /* Identical wire shape to an H3 frame header. */
    return wtq_h3_frame_encode_header(type, length, dst, cap, out_len);
}

wtq_capsule_status_t wtq_capsule_decode_header(const uint8_t *src,
                                               size_t len,
                                               wtq_h3_frame_t *out)
{
    return wtq_h3_frame_decode_header(src, len, out);
}

wtq_capsule_status_t wtq_capsule_encode_drain(uint8_t *dst, size_t cap,
                                              size_t *out_len)
{
    return wtq_capsule_encode_header(WTQ_CAPSULE_DRAIN_SESSION, 0, dst,
                                     cap, out_len);
}

wtq_capsule_status_t wtq_capsule_encode_close(uint32_t code,
                                              const uint8_t *reason,
                                              size_t reason_len,
                                              uint8_t *dst, size_t cap,
                                              size_t *out_len)
{
    if (reason_len > WTQ_CAPSULE_MAX_REASON)
        return WTQ_CAPSULE_RANGE;

    uint64_t payload_len = 4 + (uint64_t)reason_len;
    size_t header_len =
        wtq_h3_frame_header_len(WTQ_CAPSULE_CLOSE_SESSION, payload_len);

    if (cap < header_len + payload_len)
        return WTQ_CAPSULE_BUFFER;

    size_t hl = 0;
    /* Capacity checked for the whole capsule; cannot fail from here. */
    (void)wtq_capsule_encode_header(WTQ_CAPSULE_CLOSE_SESSION, payload_len,
                                    dst, cap, &hl);
    dst[hl + 0] = (uint8_t)(code >> 24);
    dst[hl + 1] = (uint8_t)(code >> 16);
    dst[hl + 2] = (uint8_t)(code >> 8);
    dst[hl + 3] = (uint8_t)code;
    for (size_t i = 0; i < reason_len; i++)
        dst[hl + 4 + i] = reason[i];

    *out_len = hl + 4 + reason_len;
    return WTQ_CAPSULE_OK;
}

void wtq_capsule_dec_init(wtq_capsule_dec_t *dec)
{
    wtq_h3_frame_dec_init(&dec->hdr);
    dec->state = CAP_DEC_HEADER;
    dec->kind = 0;
    dec->code_have = 0;
    dec->type = 0;
    dec->payload_len = 0;
    dec->remaining = 0;
    dec->header_len = 0;
    dec->code_acc = 0;
    dec->reason_len = 0;
}

/* Classify a completed header; returns MALFORMED for invalid known
 * shapes, else sets dec->kind. */
static wtq_capsule_status_t classify(wtq_capsule_dec_t *dec)
{
    if (dec->type == WTQ_CAPSULE_CLOSE_SESSION) {
        if (dec->payload_len < 4 ||
            dec->payload_len > 4 + (uint64_t)WTQ_CAPSULE_MAX_REASON)
            return WTQ_CAPSULE_MALFORMED;
        dec->kind = WTQ_CAPSULE_KIND_CLOSE;
    } else if (dec->type == WTQ_CAPSULE_DRAIN_SESSION) {
        if (dec->payload_len != 0)
            return WTQ_CAPSULE_MALFORMED;
        dec->kind = WTQ_CAPSULE_KIND_DRAIN;
    } else {
        dec->kind = WTQ_CAPSULE_KIND_UNKNOWN;
    }
    return WTQ_CAPSULE_OK;
}

static void emit(wtq_capsule_dec_t *dec, wtq_capsule_t *out)
{
    out->kind = (wtq_capsule_kind_t)dec->kind;
    out->type = dec->type;
    out->length = dec->payload_len;
    out->header_len = dec->header_len;
    out->close_code = dec->code_acc;
    out->reason = dec->reason;
    out->reason_len = dec->reason_len;

    /* Ready for the next capsule. out carries VALUE copies of
     * everything except the reason pointer, and the reason BYTES stay
     * untouched until a later feed overwrites them — which is exactly
     * the documented lifetime ("valid until the next feed/_init"). */
    wtq_h3_frame_dec_init(&dec->hdr);
    dec->state = CAP_DEC_HEADER;
    dec->kind = 0;
    dec->code_have = 0;
    dec->type = 0;
    dec->payload_len = 0;
    dec->remaining = 0;
    dec->header_len = 0;
    dec->code_acc = 0;
    dec->reason_len = 0;
}

wtq_capsule_status_t wtq_capsule_dec_feed(wtq_capsule_dec_t *dec,
                                          const uint8_t *src, size_t len,
                                          wtq_capsule_t *out,
                                          size_t *consumed)
{
    size_t eaten = 0;

    if (dec->state == CAP_DEC_POISONED) {
        *consumed = 0;
        return WTQ_CAPSULE_MALFORMED;
    }

    if (dec->state == CAP_DEC_HEADER) {
        wtq_h3_frame_t hdr;
        size_t c = 0;
        /* h3_frame's feed is NULL+0-probe safe (guarded internally). */
        wtq_h3_frame_status_t st =
            wtq_h3_frame_dec_feed(&dec->hdr, src, len, &hdr, &c);
        eaten += c;
        if (st != WTQ_H3_FRAME_OK) {
            *consumed = eaten;
            return st; /* NEED_MORE */
        }

        dec->type = hdr.type;
        dec->payload_len = hdr.length;
        dec->remaining = hdr.length;
        dec->header_len = hdr.header_len;
        dec->code_have = 0;
        dec->code_acc = 0;
        dec->reason_len = 0;

        wtq_capsule_status_t cs = classify(dec);
        if (cs != WTQ_CAPSULE_OK) {
            dec->state = CAP_DEC_POISONED;
            *consumed = eaten;
            return cs;
        }

        if (dec->remaining == 0) {
            emit(dec, out);
            *consumed = eaten;
            return WTQ_CAPSULE_OK;
        }
        dec->state = CAP_DEC_PAYLOAD;
    }

    /* Payload. */
    while (dec->remaining > 0 && eaten < len) {
        size_t avail = len - eaten;
        size_t take = dec->remaining < (uint64_t)avail
                          ? (size_t)dec->remaining
                          : avail;

        if (dec->kind == WTQ_CAPSULE_KIND_CLOSE) {
            size_t i = 0;
            /* 32-bit error code, network byte order. */
            while (dec->code_have < 4 && i < take) {
                dec->code_acc =
                    (dec->code_acc << 8) | src[eaten + i];
                dec->code_have++;
                i++;
            }
            /* Reason bytes. classify() bounded payload_len, so
             * reason_len can never exceed WTQ_CAPSULE_MAX_REASON. */
            while (i < take) {
                dec->reason[dec->reason_len++] = src[eaten + i];
                i++;
            }
        }
        /* UNKNOWN: bytes are discarded. */

        dec->remaining -= take;
        eaten += take;
    }

    *consumed = eaten;
    if (dec->remaining > 0)
        return WTQ_CAPSULE_NEED_MORE;

    emit(dec, out);
    return WTQ_CAPSULE_OK;
}
