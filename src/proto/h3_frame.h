#ifndef WTQ_PROTO_H3_FRAME_H
#define WTQ_PROTO_H3_FRAME_H

/*
 * HTTP/3 generic frame header (RFC 9114 section 7.1):
 *
 *     Frame Type (i), Length (i), Payload (..)
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * This module owns ONLY the generic header: it computes, encodes and
 * decodes the two leading varints and reports the payload length. It
 * never interprets payloads, never skips them, and enforces no
 * stream-specific frame rules (SETTINGS-first, forbidden-on-control,
 * push rejection — all of that belongs to the control-stream semantic
 * layer above).
 *
 * NOT here on purpose: the WebTransport bidi association codepoint 0x41.
 * On a WT stream, 0x41 is followed by a SESSION ID varint, not a Length
 * field — it is not a generic H3 frame, and parsing it with this decoder
 * would mis-read the wire. It lives in the preamble module.
 *
 * Statuses are shared with the varint module (same values, same
 * semantics) so results compose without translation. Non-minimal varint
 * encodings are accepted on decode, with header_len reflecting the
 * actual wire length (see varint.h for the RFC 9000 rationale).
 *
 * This module never allocates.
 */

#include "varint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* H3 frame types used by the WebTransport-relevant subset. Push-related
 * types are listed so upper layers can recognize and reject them. */
#define WTQ_H3_FRAME_DATA         UINT64_C(0x00)
#define WTQ_H3_FRAME_HEADERS      UINT64_C(0x01)
#define WTQ_H3_FRAME_CANCEL_PUSH  UINT64_C(0x03)
#define WTQ_H3_FRAME_SETTINGS     UINT64_C(0x04)
#define WTQ_H3_FRAME_PUSH_PROMISE UINT64_C(0x05)
#define WTQ_H3_FRAME_GOAWAY       UINT64_C(0x07)
#define WTQ_H3_FRAME_MAX_PUSH_ID  UINT64_C(0x0d)

typedef wtq_varint_status_t wtq_h3_frame_status_t;
#define WTQ_H3_FRAME_OK        WTQ_VARINT_OK
#define WTQ_H3_FRAME_NEED_MORE WTQ_VARINT_NEED_MORE
#define WTQ_H3_FRAME_BUFFER    WTQ_VARINT_BUFFER
#define WTQ_H3_FRAME_RANGE     WTQ_VARINT_RANGE

typedef struct wtq_h3_frame {
    uint64_t type;
    uint64_t length;     /* payload length; payload is NOT consumed */
    size_t header_len;   /* wire bytes of the two varints as received */
} wtq_h3_frame_t;

/*
 * Minimal encoded header length for type + payload length.
 * 0 if either value > WTQ_VARINT_MAX.
 */
size_t wtq_h3_frame_header_len(uint64_t type, uint64_t length);

/*
 * Encode a minimal-form frame header into dst[cap]. On WTQ_H3_FRAME_OK,
 * *out_len is the number of bytes written. dst is untouched on error
 * (capacity is checked for the WHOLE header before any write).
 */
wtq_h3_frame_status_t wtq_h3_frame_encode_header(uint64_t type,
                                                 uint64_t length,
                                                 uint8_t *dst, size_t cap,
                                                 size_t *out_len);

/*
 * Decode one frame header from src[len]. Consumes exactly the header:
 * trailing payload bytes in src are never touched.
 *   WTQ_H3_FRAME_OK:        *out fully set; out->header_len bytes consumed.
 *   WTQ_H3_FRAME_NEED_MORE: valid but incomplete prefix (including len 0).
 * Never fails on content: every complete pair of varints decodes.
 */
wtq_h3_frame_status_t wtq_h3_frame_decode_header(const uint8_t *src,
                                                 size_t len,
                                                 wtq_h3_frame_t *out);

/*
 * Incremental frame-header decoder for split input.
 *
 * Zero-initialized state is a valid fresh decoder; wtq_h3_frame_dec_init()
 * resets at any point. After WTQ_H3_FRAME_OK the decoder resets itself and
 * can be fed the next frame header immediately.
 */
typedef enum wtq_h3_frame_dec_state {
    WTQ_H3_FRAME_DEC_TYPE = 0,   /* reading Frame Type varint */
    WTQ_H3_FRAME_DEC_LENGTH = 1, /* reading Length varint */
} wtq_h3_frame_dec_state_t;

typedef struct wtq_h3_frame_dec {
    wtq_varint_dec_t vi;
    uint64_t type;
    size_t hdr_bytes;  /* wire bytes accumulated across calls */
    uint8_t state;     /* wtq_h3_frame_dec_state_t */
} wtq_h3_frame_dec_t;

void wtq_h3_frame_dec_init(wtq_h3_frame_dec_t *dec);

/*
 * Feed bytes. Consumes from src until the header completes or src is
 * exhausted; trailing payload bytes are never consumed. *consumed is set
 * on EVERY return — always the number of bytes eaten FROM THIS CALL.
 *   WTQ_H3_FRAME_OK:        *out fully set (header may span earlier
 *                           calls; out->header_len is the total).
 *   WTQ_H3_FRAME_NEED_MORE: *consumed == len; call again with more.
 * Identical acceptance to wtq_h3_frame_decode_header: chunking never
 * changes the result.
 */
wtq_h3_frame_status_t wtq_h3_frame_dec_feed(wtq_h3_frame_dec_t *dec,
                                            const uint8_t *src, size_t len,
                                            wtq_h3_frame_t *out,
                                            size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_H3_FRAME_H */
