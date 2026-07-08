#include <string.h>

#include <wtquic/wtquic.h>

#include "test_support.h"

int main(void)
{
    int failures = 0;

    WTQ_TEST_CHECK(wtq_version() != NULL);
    WTQ_TEST_CHECK(strcmp(wtq_version(), WTQ_VERSION_STRING) == 0);

    /* strerror covers every defined code and never returns NULL. */
    WTQ_TEST_CHECK(strcmp(wtq_strerror(WTQ_OK), "ok") == 0);
    for (int rc = WTQ_ERR_BACKEND; rc <= WTQ_OK; rc++)
        WTQ_TEST_CHECK(wtq_strerror(rc) != NULL);
    WTQ_TEST_CHECK(wtq_strerror(-9999) != NULL);

    /* Default allocator is complete and stable. */
    const wtq_alloc_t *alloc = wtq_alloc_default();
    WTQ_TEST_CHECK(alloc != NULL);
    WTQ_TEST_CHECK(alloc == wtq_alloc_default());
    WTQ_TEST_CHECK(alloc->alloc != NULL);
    WTQ_TEST_CHECK(alloc->realloc != NULL);
    WTQ_TEST_CHECK(alloc->free != NULL);
    void *p = alloc->alloc(64, alloc->ctx);
    WTQ_TEST_CHECK(p != NULL);
    p = alloc->realloc(p, 64, 128, alloc->ctx);
    WTQ_TEST_CHECK(p != NULL);
    alloc->free(p, 128, alloc->ctx);

    WTQ_TEST_PASS("test_version");
    return failures;
}
