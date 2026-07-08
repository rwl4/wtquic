#ifndef WTQ_TEST_FAULT_ALLOC_H
#define WTQ_TEST_FAULT_ALLOC_H

/*
 * Fail-at-N allocator for OOM sweeps. Counts every allocation attempt,
 * fails exactly attempt fail_at (or every attempt >= fail_at when
 * fail_after is set), and tracks live allocations so a run can assert
 * balance == 0. Freeing a pointer it never handed out, freeing twice,
 * or freeing with the wrong size (a violation of wtquic's sized-free
 * contract) each bump the error counter.
 *
 * A pointer to the embedded vtable is what a session/conn is created
 * with; the wtq_fault_alloc_t is the vtable's ctx.
 */

#include <wtquic/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_FAULT_MAX_LIVE 64

typedef struct wtq_fault_alloc {
    wtq_alloc_t vtable;    /* {ctx = this, alloc, realloc, free} */
    int attempts;          /* alloc + realloc attempts so far */
    int fail_at;           /* fail this attempt number (0 = never) */
    bool fail_after;       /* also fail every attempt after fail_at */
    int live;              /* outstanding allocations (balance) */
    size_t live_bytes;
    int errors;            /* invalid/double free, size mismatch */
    void *ptrs[WTQ_FAULT_MAX_LIVE];
    size_t sizes[WTQ_FAULT_MAX_LIVE];
    int nptrs;
} wtq_fault_alloc_t;

/* Initialize (no faults armed). Sets up the vtable. */
void wtq_fault_alloc_init(wtq_fault_alloc_t *fa);

/* Arm the next run: reset the attempt/error counters and set the fault
 * point. Live tracking is left intact (a balanced prior run leaves it
 * empty); call between runs only after teardown. */
void wtq_fault_alloc_arm(wtq_fault_alloc_t *fa, int fail_at,
                         bool fail_after);

/* The allocator vtable to hand to session/conn creation. */
const wtq_alloc_t *wtq_fault_alloc_vtable(wtq_fault_alloc_t *fa);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_FAULT_ALLOC_H */
