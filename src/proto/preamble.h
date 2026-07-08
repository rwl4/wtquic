#ifndef WTQ_PROTO_PREAMBLE_H
#define WTQ_PROTO_PREAMBLE_H

/*
 * WebTransport stream association preambles
 * (draft-ietf-webtrans-http3-15; codepoints match picoquic's h3zero):
 *
 *   bidi application stream:  varint 0x41 + varint session_id + payload
 *   uni application stream:   varint 0x54 + varint session_id + payload
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * Both codepoints exceed 63, so their minimal varint encodings are TWO
 * bytes ({0x40,0x41} / {0x40,0x54}); a minimal preamble is 3 wire
 * bytes. Non-minimal varints are accepted on decode with header_len
 * reflecting wire bytes.
 *
 * The decoder is DIRECTION-AWARE: it is initialized with the expected
 * kind for the QUIC stream it reads (bidi accepts only 0x41, uni only
 * 0x54). Any other type completes as WTQ_PREAMBLE_UNEXPECTED with the
 * decoded wire type reported — on a uni stream the engine's classifier
 * uses exactly that to route H3 control/QPACK stream types (whose type
 * varint is also consume-and-done) or to drain unknown types; on a bidi
 * stream it is a protocol error. This module only associates streams:
 * no H3 stream dispatch, no datagram quarter-stream-id, no allocation.
 */

#include "varint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_PREAMBLE_BIDI UINT64_C(0x41)
#define WTQ_PREAMBLE_UNI UINT64_C(0x54)

typedef enum wtq_preamble_kind {
    WTQ_PREAMBLE_KIND_BIDI = 1,
    WTQ_PREAMBLE_KIND_UNI = 2,
} wtq_preamble_kind_t;

typedef int wtq_preamble_status_t;
#define WTQ_PREAMBLE_OK        WTQ_VARINT_OK
#define WTQ_PREAMBLE_NEED_MORE WTQ_VARINT_NEED_MORE
#define WTQ_PREAMBLE_BUFFER    WTQ_VARINT_BUFFER
#define WTQ_PREAMBLE_RANGE     WTQ_VARINT_RANGE
/* The type varint completed but is not the expected codepoint for this
 * stream direction. out->wire_type holds the decoded type; the session
 * id is NOT parsed. Latched until _init(). */
#define WTQ_PREAMBLE_UNEXPECTED (-3)

typedef struct wtq_preamble {
    wtq_preamble_kind_t kind;
    uint64_t session_id;
    size_t header_len;  /* wire bytes of type + session_id varints */
    uint64_t wire_type; /* decoded type; the routing value on UNEXPECTED */
} wtq_preamble_t;

/*
 * Encode a minimal preamble (2-byte type varint + minimal session_id
 * varint). RANGE when session_id > WTQ_VARINT_MAX or kind is invalid.
 * dst untouched on error.
 */
wtq_preamble_status_t wtq_preamble_encode(wtq_preamble_kind_t kind,
                                          uint64_t session_id,
                                          uint8_t *dst, size_t cap,
                                          size_t *out_len);

/*
 * Atomic decode from a span. Consumes exactly the preamble; trailing
 * payload bytes are never touched. NEED_MORE on any valid prefix.
 */
wtq_preamble_status_t wtq_preamble_decode(wtq_preamble_kind_t expect,
                                          const uint8_t *src, size_t len,
                                          wtq_preamble_t *out);

/*
 * Incremental decoder for arbitrary chunk boundaries.
 *
 * Zero-initialized state is a valid fresh decoder; the expected stream
 * direction is passed at feed time (a caller must pass the same expect
 * value for the lifetime of one preamble — it is evaluated when the
 * type varint completes). wtq_preamble_dec_init() resets at any point,
 * including mid-parse and after UNEXPECTED latching. After
 * WTQ_PREAMBLE_OK the decoder is ready for the next preamble.
 */
typedef struct wtq_preamble_dec {
    wtq_varint_dec_t vi;
    uint8_t state; /* 0 type, 1 session, 2 poisoned */
    uint64_t wire_type;
    size_t hdr_bytes;
} wtq_preamble_dec_t;

void wtq_preamble_dec_init(wtq_preamble_dec_t *dec);

/*
 * Feed bytes. *consumed is set on EVERY return (bytes eaten from THIS
 * call); NEED_MORE consumes everything offered; OK never consumes
 * payload bytes past the preamble. Chunking never changes the outcome.
 */
wtq_preamble_status_t wtq_preamble_dec_feed(wtq_preamble_dec_t *dec,
                                            wtq_preamble_kind_t expect,
                                            const uint8_t *src, size_t len,
                                            wtq_preamble_t *out,
                                            size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_PREAMBLE_H */
