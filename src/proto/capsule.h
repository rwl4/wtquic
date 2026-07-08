#ifndef WTQ_PROTO_CAPSULE_H
#define WTQ_PROTO_CAPSULE_H

/*
 * WebTransport capsule codec (RFC 9297 capsule framing; capsule types
 * from draft-ietf-webtrans-http3-15):
 *
 *   WT_CLOSE_SESSION (0x2843): Application Error Code (32 bits, network
 *     byte order — NOT a varint) + UTF-8 Application Error Message whose
 *     length MUST NOT exceed 1024 bytes (draft-15 prose, lines 1480-1483;
 *     the figure's "(..8192)" is BITS). Payload length < 4 or
 *     > 4 + 1024 is malformed.
 *   WT_DRAIN_SESSION (0x78ae): payload length MUST be exactly 0.
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * The capsule wire header is varint Type + varint Length — identical
 * shape to an H3 frame header, so the header machinery is shared with
 * h3_frame. Unknown capsule types (including the WT flow-control
 * extension capsules wtquic v1 must ignore) are consumed and reported
 * as UNKNOWN without buffering their payload. Non-minimal varints are
 * accepted with header_len reflecting wire bytes.
 *
 * The incremental decoder owns an inline 1024-byte reason buffer (the
 * only payload it ever retains); it never allocates. UTF-8 validity of
 * the reason is NOT checked here — that is caller policy.
 */

#include "h3_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_CAPSULE_CLOSE_SESSION UINT64_C(0x2843)
#define WTQ_CAPSULE_DRAIN_SESSION UINT64_C(0x78ae)
#define WTQ_CAPSULE_MAX_REASON 1024u

typedef int wtq_capsule_status_t;
#define WTQ_CAPSULE_OK        WTQ_VARINT_OK
#define WTQ_CAPSULE_NEED_MORE WTQ_VARINT_NEED_MORE
#define WTQ_CAPSULE_BUFFER    WTQ_VARINT_BUFFER
#define WTQ_CAPSULE_RANGE     WTQ_VARINT_RANGE
/* Known capsule with invalid payload shape (DRAIN length != 0, CLOSE
 * length < 4 or reason > 1024). The decoder latches this state until
 * _init(); the session layer treats it as a fatal session error. */
#define WTQ_CAPSULE_MALFORMED (-3)

typedef enum wtq_capsule_kind {
    WTQ_CAPSULE_KIND_CLOSE = 1,
    WTQ_CAPSULE_KIND_DRAIN = 2,
    WTQ_CAPSULE_KIND_UNKNOWN = 3, /* complete capsule, payload skipped */
} wtq_capsule_kind_t;

typedef struct wtq_capsule {
    wtq_capsule_kind_t kind;
    uint64_t type;       /* wire type (interesting for UNKNOWN) */
    uint64_t length;     /* payload length */
    size_t header_len;   /* wire bytes of the two header varints */
    /* CLOSE only: */
    uint32_t close_code;
    const uint8_t *reason; /* into the decoder's buffer; valid until the
                              next feed/_init call on that decoder */
    size_t reason_len;
} wtq_capsule_t;

/* Byte-exact encoders (minimal varints). dst untouched on error. */
wtq_capsule_status_t wtq_capsule_encode_drain(uint8_t *dst, size_t cap,
                                              size_t *out_len);
/* RANGE when reason_len > WTQ_CAPSULE_MAX_REASON. */
wtq_capsule_status_t wtq_capsule_encode_close(uint32_t code,
                                              const uint8_t *reason,
                                              size_t reason_len,
                                              uint8_t *dst, size_t cap,
                                              size_t *out_len);

/* Generic header helpers (same wire shape as an H3 frame header). */
wtq_capsule_status_t wtq_capsule_encode_header(uint64_t type,
                                               uint64_t length,
                                               uint8_t *dst, size_t cap,
                                               size_t *out_len);
wtq_capsule_status_t wtq_capsule_decode_header(const uint8_t *src,
                                               size_t len,
                                               wtq_h3_frame_t *out);

/*
 * Incremental capsule decoder for arbitrary chunk boundaries.
 *
 * Zero-initialized state is a valid fresh decoder; wtq_capsule_dec_init()
 * resets at any point (including mid-parse and after MALFORMED). After
 * WTQ_CAPSULE_OK the decoder is immediately ready for the next capsule
 * in the same byte stream (the returned reason span stays valid until
 * the next feed/_init).
 */
typedef struct wtq_capsule_dec {
    wtq_h3_frame_dec_t hdr;    /* shared type+length varint machinery */
    uint8_t state;             /* 0 header, 1 payload, 2 poisoned */
    uint8_t kind;              /* wtq_capsule_kind_t once header done */
    uint8_t code_have;         /* CLOSE: bytes of the 32-bit code seen */
    uint64_t type;
    uint64_t payload_len;
    uint64_t remaining;
    size_t header_len;
    uint32_t code_acc;
    uint16_t reason_len;
    uint8_t reason[WTQ_CAPSULE_MAX_REASON];
} wtq_capsule_dec_t;

void wtq_capsule_dec_init(wtq_capsule_dec_t *dec);

/*
 * Feed bytes. *consumed is set on EVERY return — bytes eaten from THIS
 * call.
 *   WTQ_CAPSULE_OK:        *out describes a complete capsule.
 *   WTQ_CAPSULE_NEED_MORE: *consumed == len; call again with more.
 *   WTQ_CAPSULE_MALFORMED: known capsule with invalid payload shape
 *                          (reported as soon as the header completes);
 *                          latched until _init().
 * Chunking never changes the outcome.
 */
wtq_capsule_status_t wtq_capsule_dec_feed(wtq_capsule_dec_t *dec,
                                          const uint8_t *src, size_t len,
                                          wtq_capsule_t *out,
                                          size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_CAPSULE_H */
