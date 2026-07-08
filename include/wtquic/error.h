#ifndef WTQ_ERROR_H
#define WTQ_ERROR_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* wtq_result_t values. 0 is success; all errors are negative. */
enum {
    WTQ_OK                 = 0,

    WTQ_ERR_INVALID_ARG    = -1,  /* bad parameter or config */
    WTQ_ERR_NOMEM          = -2,  /* allocator returned NULL */
    WTQ_ERR_STATE          = -3,  /* operation illegal in current state */
    WTQ_ERR_WOULD_BLOCK    = -4,  /* retry after a writable/unblocked event */
    WTQ_ERR_TOO_LARGE      = -5,  /* datagram over max size, reason over cap */
    WTQ_ERR_STREAM_LIMIT   = -6,  /* peer stream credit exhausted */
    WTQ_ERR_CLOSED         = -7,  /* session/stream already terminal */
    WTQ_ERR_PROTO          = -8,  /* peer protocol violation */
    WTQ_ERR_UNSUPPORTED    = -9,  /* capability absent (e.g. reliable reset) */
    WTQ_ERR_DGRAM_DISABLED = -10, /* datagrams not negotiated */
    WTQ_ERR_NOT_FOUND      = -11, /* unknown path/handle */
    WTQ_ERR_BACKEND        = -12, /* unmapped transport failure */
};

/* Human-readable name for a result code. Never returns NULL. */
WTQ_API const char *wtq_strerror(wtq_result_t rc);

/*
 * WebTransport application error code mapping (draft-15 section 4.4).
 *
 * WebTransport stream error codes are 32-bit application values carried in
 * a reserved HTTP/3 error-code range, skipping the GREASE codepoints
 * (0x1f * N + 0x21).
 */

/* Map a 32-bit WebTransport application error to its H3 wire code. */
WTQ_API uint64_t wtq_app_error_to_h3(uint32_t app_error);

/*
 * Reverse-map an H3 wire code. Returns WTQ_OK and sets *app_error_out when
 * the code lies in the WebTransport range and is not a GREASE gap;
 * WTQ_ERR_NOT_FOUND otherwise.
 */
WTQ_API wtq_result_t wtq_h3_error_to_app(uint64_t h3_error,
                                         uint32_t *app_error_out);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_ERROR_H */
