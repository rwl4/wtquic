#ifndef WTQ_WTQUIC_H
#define WTQ_WTQUIC_H

/*
 * wtquic — WebTransport over HTTP/3, purpose-built for performance.
 *
 * Umbrella header for the transport-agnostic core. Backend entry points
 * (MsQuic, picoquic) live in their own headers (<wtquic/wtquic_msquic.h>)
 * and are NOT included here, so this header carries no transport
 * dependencies.
 */

#include <wtquic/export.h>  /* IWYU pragma: export */
#include <wtquic/version.h> /* IWYU pragma: export */
#include <wtquic/types.h>   /* IWYU pragma: export */
#include <wtquic/error.h>   /* IWYU pragma: export */
#include <wtquic/session.h> /* IWYU pragma: export */
#include <wtquic/stream.h>  /* IWYU pragma: export */

#endif /* WTQ_WTQUIC_H */
