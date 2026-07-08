/*
 * WebTransport application error code <-> HTTP/3 error code mapping.
 * draft-ietf-webtrans-http3-15, section 4.4.
 *
 * The 32-bit WebTransport application error space is carried in a reserved
 * HTTP/3 range starting at WTQ_H3_APP_ERROR_FIRST. Every 0x1e application
 * values, one wire codepoint is skipped so that the mapped range never
 * lands on an HTTP/3 GREASE codepoint (0x1f * N + 0x21).
 */

#include <wtquic/error.h>

#define WTQ_H3_APP_ERROR_FIRST 0x52e4a40fa8dbull
#define WTQ_H3_APP_ERROR_LAST \
    (WTQ_H3_APP_ERROR_FIRST + 0xffffffffull + 0xffffffffull / 0x1e)

uint64_t wtq_app_error_to_h3(uint32_t app_error)
{
    uint64_t n = app_error;
    return WTQ_H3_APP_ERROR_FIRST + n + n / 0x1e;
}

wtq_result_t wtq_h3_error_to_app(uint64_t h3_error, uint32_t *app_error_out)
{
    if (app_error_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (h3_error < WTQ_H3_APP_ERROR_FIRST || h3_error > WTQ_H3_APP_ERROR_LAST)
        return WTQ_ERR_NOT_FOUND;

    uint64_t shifted = h3_error - WTQ_H3_APP_ERROR_FIRST;
    uint64_t n = shifted - shifted / 0x1f;
    if (n > 0xffffffffull ||
        wtq_app_error_to_h3((uint32_t)n) != h3_error)
        return WTQ_ERR_NOT_FOUND; /* GREASE gap */

    *app_error_out = (uint32_t)n;
    return WTQ_OK;
}
