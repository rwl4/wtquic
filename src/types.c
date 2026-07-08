#include <stdlib.h>

#include <wtquic/error.h>
#include <wtquic/types.h>
#include <wtquic/version.h>

const char *wtq_version(void)
{
    return WTQ_VERSION_STRING;
}

const char *wtq_strerror(wtq_result_t rc)
{
    switch (rc) {
    case WTQ_OK:                 return "ok";
    case WTQ_ERR_INVALID_ARG:    return "invalid argument";
    case WTQ_ERR_NOMEM:          return "out of memory";
    case WTQ_ERR_STATE:          return "operation illegal in current state";
    case WTQ_ERR_WOULD_BLOCK:    return "would block";
    case WTQ_ERR_TOO_LARGE:      return "too large";
    case WTQ_ERR_STREAM_LIMIT:   return "stream limit reached";
    case WTQ_ERR_CLOSED:         return "closed";
    case WTQ_ERR_PROTO:          return "protocol violation";
    case WTQ_ERR_UNSUPPORTED:    return "unsupported";
    case WTQ_ERR_DGRAM_DISABLED: return "datagrams disabled";
    case WTQ_ERR_NOT_FOUND:      return "not found";
    case WTQ_ERR_BACKEND:        return "backend failure";
    default:                     return "unknown error";
    }
}

static void *default_alloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *default_realloc(void *ptr, size_t old_size, size_t new_size,
                             void *ctx)
{
    (void)old_size;
    (void)ctx;
    return realloc(ptr, new_size);
}

static void default_free(void *ptr, size_t size, void *ctx)
{
    (void)size;
    (void)ctx;
    free(ptr);
}

const wtq_alloc_t *wtq_alloc_default(void)
{
    static const wtq_alloc_t alloc = {
        NULL,
        default_alloc,
        default_realloc,
        default_free,
    };
    return &alloc;
}
