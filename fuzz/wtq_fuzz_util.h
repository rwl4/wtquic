#ifndef WTQ_FUZZ_UTIL_H
#define WTQ_FUZZ_UTIL_H

/*
 * Shared helpers for the stateful engine/API fuzzers: a cursor over the
 * fuzzer input and a balance/double-free-checking allocator (the OOM
 * suite's faulting allocator, run with no faults armed). The fuzzers
 * abort() on any invariant violation; libFuzzer treats the abort as a
 * crash.
 */

#include <stdint.h>
#include <stdlib.h>

#include "engine/wt_driver.h"
#include "wtq_fault_alloc.h"

/* --- input cursor -------------------------------------------------------- */

typedef struct fz {
    const uint8_t *d;
    size_t len;
    size_t off;
} fz_t;

static inline void fz_init(fz_t *r, const uint8_t *d, size_t len)
{
    r->d = d;
    r->len = len;
    r->off = 0;
}

static inline int fz_more(const fz_t *r)
{
    return r->off < r->len;
}

static inline uint8_t fz_u8(fz_t *r)
{
    return r->off < r->len ? r->d[r->off++] : 0;
}

/* Take up to `max` bytes (length prefixed by one input byte). *out points
 * into the fuzzer buffer; valid for the lifetime of this input. */
static inline size_t fz_bytes(fz_t *r, const uint8_t **out, size_t max)
{
    size_t want = fz_u8(r);
    if (want > max)
        want = max;
    size_t avail = r->len - r->off;
    if (want > avail)
        want = avail;
    *out = r->d + r->off;
    r->off += want;
    return want;
}

/* --- allocator wrapper --------------------------------------------------- */

/* Init a no-fault balance/double-free-checking allocator. */
static inline const wtq_alloc_t *fz_alloc(wtq_fault_alloc_t *fa)
{
    wtq_fault_alloc_init(fa);
    return wtq_fault_alloc_vtable(fa);
}

/* Abort unless the allocator is balanced and saw no invalid frees. */
static inline void fz_alloc_check(const wtq_fault_alloc_t *fa)
{
    if (fa->live != 0 || fa->errors != 0)
        abort();
}

/* A protocol violation must surface as a non-OK engine-input return —
 * an input that fatally closes the connection while returning WTQ_OK is
 * exactly the swallowed-error class the fault suite found. Pass the
 * closed state captured BEFORE the call and the call's return. */
static inline void fz_check_fatal(const wtq_conn_t *conn, int was_closed,
                                  wtq_result_t rc)
{
    if (conn != NULL && !was_closed && wtq_conn_is_closed(conn) &&
        rc == WTQ_OK)
        abort();
}

#endif /* WTQ_FUZZ_UTIL_H */
