#ifndef WTQ_PROTO_VARINT_H
#define WTQ_PROTO_VARINT_H

/*
 * QUIC variable-length integers (RFC 9000 section 16).
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * Encoding: the top two bits of the first byte select the total length
 * (00=1, 01=2, 10=4, 11=8 bytes); the remaining 6/14/30/62 bits carry the
 * value big-endian. Maximum value is 2^62 - 1.
 *
 * Non-minimal encodings are LEGAL wire format (RFC 9000: values need not
 * use the shortest encoding; both MsQuic and picoquic accept them), so the
 * decoders accept them and report the consumed length. Contexts that
 * require canonical form (e.g. frame types) check wtq_varint_is_minimal().
 *
 * This module never allocates and has no dependencies beyond <stdint.h>.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_VARINT_MAX ((UINT64_C(1) << 62) - 1)

typedef enum wtq_varint_status {
    WTQ_VARINT_OK        = 0,
    WTQ_VARINT_NEED_MORE = 1,  /* valid prefix; feed more bytes (not an error) */
    WTQ_VARINT_BUFFER    = -1, /* encode: destination buffer too small */
    WTQ_VARINT_RANGE     = -2, /* encode: value > WTQ_VARINT_MAX */
} wtq_varint_status_t;

/* Minimal encoded length for value: 1, 2, 4 or 8. 0 if value > MAX. */
size_t wtq_varint_len(uint64_t value);

/* Total encoded length implied by a first byte: 1, 2, 4 or 8. */
size_t wtq_varint_len_from_first(uint8_t first_byte);

/* True when encoded_len is the minimal length for value. */
bool wtq_varint_is_minimal(uint64_t value, size_t encoded_len);

/*
 * Encode value in minimal form into dst[cap]. On WTQ_VARINT_OK, *out_len
 * is the number of bytes written. dst is untouched on error.
 */
wtq_varint_status_t wtq_varint_encode(uint64_t value, uint8_t *dst,
                                      size_t cap, size_t *out_len);

/*
 * Decode one varint from src[len].
 *   WTQ_VARINT_OK:        *value and *consumed set.
 *   WTQ_VARINT_NEED_MORE: src holds a valid but incomplete prefix
 *                         (including len == 0); outputs untouched.
 * Never fails on content: every complete byte sequence decodes.
 */
wtq_varint_status_t wtq_varint_decode(const uint8_t *src, size_t len,
                                      uint64_t *value, size_t *consumed);

/*
 * Incremental decoder for byte-at-a-time / split input.
 *
 * Zero-initialized state is a valid fresh decoder; wtq_varint_dec_init()
 * resets at any point (including mid-parse). After WTQ_VARINT_OK the
 * decoder resets itself and can be fed the next varint immediately.
 */
typedef struct wtq_varint_dec {
    uint64_t acc;  /* accumulated payload bits */
    uint8_t need;  /* total encoded length once first byte seen; 0 = fresh */
    uint8_t have;  /* bytes consumed so far */
} wtq_varint_dec_t;

void wtq_varint_dec_init(wtq_varint_dec_t *dec);

/*
 * Feed bytes. Consumes from src until the varint completes or src is
 * exhausted. *consumed is set on EVERY return — always the number of
 * bytes eaten FROM THIS CALL — so generic callers advance by *consumed
 * without special-casing the status.
 *   WTQ_VARINT_OK:        *value set (the varint may span earlier calls).
 *   WTQ_VARINT_NEED_MORE: *consumed == len; call again with more bytes.
 * Identical acceptance to wtq_varint_decode: chunking never changes the
 * result.
 */
wtq_varint_status_t wtq_varint_dec_feed(wtq_varint_dec_t *dec,
                                        const uint8_t *src, size_t len,
                                        uint64_t *value, size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_VARINT_H */
