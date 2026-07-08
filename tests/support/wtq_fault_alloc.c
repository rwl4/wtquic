#include "wtq_fault_alloc.h"

#include <stdlib.h>

static bool should_fail(wtq_fault_alloc_t *fa)
{
    if (fa->fail_at == 0)
        return false;
    if (fa->attempts == fa->fail_at)
        return true;
    return fa->fail_after && fa->attempts > fa->fail_at;
}

static void track(wtq_fault_alloc_t *fa, void *p, size_t size)
{
    if (fa->nptrs < WTQ_FAULT_MAX_LIVE) {
        fa->ptrs[fa->nptrs] = p;
        fa->sizes[fa->nptrs] = size;
        fa->nptrs++;
    }
    fa->live++;
    fa->live_bytes += size;
}

static int find(wtq_fault_alloc_t *fa, void *p)
{
    for (int i = 0; i < fa->nptrs; i++)
        if (fa->ptrs[i] == p)
            return i;
    return -1;
}

static void untrack(wtq_fault_alloc_t *fa, int idx)
{
    fa->live--;
    fa->live_bytes -= fa->sizes[idx];
    fa->nptrs--;
    fa->ptrs[idx] = fa->ptrs[fa->nptrs];
    fa->sizes[idx] = fa->sizes[fa->nptrs];
}

static void *fa_alloc(size_t size, void *ctx)
{
    wtq_fault_alloc_t *fa = ctx;

    fa->attempts++;
    if (should_fail(fa))
        return NULL;
    void *p = malloc(size);
    if (p != NULL)
        track(fa, p, size);
    return p;
}

static void fa_free(void *ptr, size_t size, void *ctx)
{
    wtq_fault_alloc_t *fa = ctx;

    if (ptr == NULL)
        return; /* free(NULL) is a no-op */
    int idx = find(fa, ptr);
    if (idx < 0) {
        fa->errors++; /* freeing something we never handed out (or 2x) */
        return;
    }
    if (fa->sizes[idx] != size)
        fa->errors++; /* sized-free contract violation */
    free(ptr);
    untrack(fa, idx);
}

static void *fa_realloc(void *ptr, size_t old_size, size_t new_size,
                        void *ctx)
{
    wtq_fault_alloc_t *fa = ctx;

    fa->attempts++;
    if (should_fail(fa))
        return NULL;
    int idx = ptr != NULL ? find(fa, ptr) : -1;
    if (ptr != NULL) {
        if (idx < 0) {
            fa->errors++;
            return NULL;
        }
        if (fa->sizes[idx] != old_size)
            fa->errors++;
    }
    void *np = realloc(ptr, new_size);
    if (np == NULL)
        return NULL;
    if (idx >= 0)
        untrack(fa, idx);
    track(fa, np, new_size);
    return np;
}

void wtq_fault_alloc_init(wtq_fault_alloc_t *fa)
{
    fa->attempts = 0;
    fa->fail_at = 0;
    fa->fail_after = false;
    fa->live = 0;
    fa->live_bytes = 0;
    fa->errors = 0;
    fa->nptrs = 0;
    fa->vtable.ctx = fa;
    fa->vtable.alloc = fa_alloc;
    fa->vtable.realloc = fa_realloc;
    fa->vtable.free = fa_free;
}

void wtq_fault_alloc_arm(wtq_fault_alloc_t *fa, int fail_at,
                         bool fail_after)
{
    fa->attempts = 0;
    fa->errors = 0;
    fa->fail_at = fail_at;
    fa->fail_after = fail_after;
}

const wtq_alloc_t *wtq_fault_alloc_vtable(wtq_fault_alloc_t *fa)
{
    return &fa->vtable;
}
