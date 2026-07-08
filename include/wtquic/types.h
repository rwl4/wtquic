#ifndef WTQ_TYPES_H
#define WTQ_TYPES_H

/*
 * Sentinel for "no native QUIC stream id is available (yet)". Some
 * transports assign stream ids asynchronously; until the id is known,
 * queries report this value. Stream id 0 is a real, valid id (the first
 * client-initiated bidirectional stream on many transports).
 */
#define WTQ_STREAM_ID_UNKNOWN ((uint64_t)-1)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Result type. 0 is success, negative values are errors (see error.h).
 * The universal check is `if (rc < 0)`.
 */
typedef int wtq_result_t;

/*
 * Transport-error record (dual-fidelity, ABI-sized).
 *
 * `kind`/`quic_code` are the NORMALIZED view every backend can produce;
 * `native_domain`/`native_code` carry the backend's full-fidelity status
 * when one exists (domain NONE otherwise). The struct is versioned by
 * `struct_size`: the caller sets it before querying and the library
 * fills only the bytes that fit, so the record can grow without breaking
 * older callers.
 */
typedef enum wtq_error_kind {
    WTQ_ERR_KIND_NONE = 0,
    WTQ_ERR_KIND_QUIC_TRANSPORT = 1,   /* RFC 9000 transport error code   */
    WTQ_ERR_KIND_QUIC_APP = 2,         /* application CONNECTION_CLOSE    */
    WTQ_ERR_KIND_LOCAL = 3,            /* locally generated, no wire code */
} wtq_error_kind_t;

typedef enum wtq_error_domain {
    WTQ_ERRDOM_NONE = 0,
    WTQ_ERRDOM_MSQUIC = 1,
    WTQ_ERRDOM_NW_POSIX = 2,
    WTQ_ERRDOM_NW_DNS = 3,
    WTQ_ERRDOM_NW_TLS = 4,
    /* the EXPLICIT trust evaluator's own rejection (Network backend):
     * the peer's certificate chain failed SecTrustEvaluateWithError.
     * Distinct from NW_TLS (an error NW itself delivered) so consumers
     * can classify certificate/trust failure by PROVENANCE instead of
     * maintaining an OSStatus allowlist; native_code carries the
     * evaluation OSStatus. */
    WTQ_ERRDOM_NW_TRUST = 5,
    WTQ_ERRDOM_BACKEND = 15,
} wtq_error_domain_t;

typedef struct wtq_transport_error {
    uint32_t struct_size;      /* set by caller; library fills what fits */
    uint16_t kind;             /* wtq_error_kind_t, normalized           */
    uint16_t reserved0;
    uint64_t quic_code;
    uint32_t native_domain;    /* wtq_error_domain_t, full-fidelity      */
    uint32_t reserved1;
    int64_t  native_code;
} wtq_transport_error_t;

/*
 * Allocator vtable. Every wtquic allocation goes through one of these;
 * the library never calls libc malloc/free directly.
 *
 * - `alloc` and `free` are required.
 * - `realloc` may be NULL for objects that never grow; APIs that need it
 *   document the requirement.
 * - `free` and `realloc` receive the ORIGINAL allocation size (sized-free
 *   contract, not libc-style).
 * - `ctx` is the first member and is passed as the last argument to every
 *   callback. It must outlive every object created with the allocator.
 * - With a real transport backend the allocator is invoked from both
 *   application threads (environment/listener entry points) and the
 *   transport's worker threads (sessions, streams, send records), so a
 *   custom allocator must tolerate concurrent calls. The default
 *   (libc-backed) allocator does.
 *
 * The vtable is copied by value at object creation.
 */
typedef struct wtq_alloc {
    void *ctx;
    void *(*alloc)(size_t size, void *ctx);
    void *(*realloc)(void *ptr, size_t old_size, size_t new_size, void *ctx);
    void (*free)(void *ptr, size_t size, void *ctx);
} wtq_alloc_t;

/*
 * Default allocator backed by libc malloc/realloc/free. The returned
 * pointer is valid for the program lifetime and never allocates.
 */
WTQ_API const wtq_alloc_t *wtq_alloc_default(void);

/* Non-owning byte span. */
typedef struct wtq_span {
    const uint8_t *data;
    size_t len;
} wtq_span_t;

/* Non-owning string view. NOT guaranteed NUL-terminated. */
typedef struct wtq_str {
    const char *data;
    size_t len;
} wtq_str_t;

/*
 * Transport-initiation role of this endpoint (who dialed the QUIC
 * connection). Values start at 1 so 0 is an invalid sentinel.
 */
typedef enum wtq_perspective {
    WTQ_PERSPECTIVE_CLIENT = 1,
    WTQ_PERSPECTIVE_SERVER = 2,
} wtq_perspective_t;

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TYPES_H */
