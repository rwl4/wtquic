/*
 * EXPERIMENTAL disposal sentinel for the Network.framework probe.
 *
 * The send-retirement experiment must observe completion-block DISPOSAL
 * separately from completion INVOCATION: a backend send record referenced
 * by a completion block is freeable only once the block can no longer run,
 * i.e. when Network.framework has released its copy of the block. Plain-C
 * blocks do not retain their captures, so disposal is invisible from C.
 * This helper (send_sentinel.m, compiled as Objective-C with ARC) creates
 * the completion block in ARC so it strongly captures a sentinel object;
 * the sentinel's -dealloc fires `on_dispose` exactly when the last
 * reference to the block is dropped — invoked or not.
 *
 * Disposal is NEVER inferred from absence of invocation.
 * Public Apple APIs only (Foundation + Network + Blocks).
 */
#ifndef WTQ_NW_SEND_SENTINEL_H
#define WTQ_NW_SEND_SENTINEL_H

#include <stdbool.h>
#include <dispatch/dispatch.h>
#include <Network/Network.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Issue nw_connection_send(content, ..., is_complete) with a completion
 * block that strongly captures a fresh sentinel.
 *   on_complete(ctx, err_domain, err_code) — each invocation (domain -1 =
 *       no error), may legitimately never fire (that is the experiment).
 *   on_dispose(ctx) — exactly once, when NW releases its last reference
 *       to the completion block.
 * `ctx` must stay valid until on_dispose has fired.
 */
void wtq_probe_send_with_sentinel(nw_connection_t c, dispatch_data_t content,
                                  bool is_complete,
                                  void (*on_complete)(void *ctx,
                                                      int err_domain,
                                                      int err_code),
                                  void (*on_dispose)(void *ctx), void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_NW_SEND_SENTINEL_H */
