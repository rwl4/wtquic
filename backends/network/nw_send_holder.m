/*
 * Transport-reference holder for gather sends — the production analogue
 * of the probe's disposal sentinel (send_sentinel.m). Compiled with ARC;
 * the only Objective-C in the backend.
 *
 * The two-phase send record (§3.3 of the stream-identity design) needs
 * TRANSPORT_RETIRED to be directly observed: a record is reusable only
 * once Apple has disposed its copy of the completion block, or a late
 * callback could touch a reused slot (ABA/UAF). Plain-C blocks do not
 * retain their captures, so disposal is invisible from C. Here the
 * completion block strongly captures a holder whose -dealloc reports the
 * disposal — invoked or not. Nothing is ever freed on inferred
 * quiescence.
 */
#import <Foundation/Foundation.h>

#include "nw_internal.h"

@interface WTQNWSendHolder : NSObject {
  @public
    void (*_onRetire)(void *);
    void *_ctx;
    dispatch_queue_t _queue;      /* the connection's domain (retained) */
    dispatch_data_t _content;     /* retained through DISPOSAL: NW may
                                     still read the data object after
                                     the completion fires; releasing it
                                     at send-issue is not proven safe */
}
@end

@implementation WTQNWSendHolder
- (void)dealloc
{
    /*
     * Block disposal runs on WHATEVER thread drops the last reference —
     * thread affinity is NOT guaranteed. Retirement mutates driver/
     * stream/record/allocator state, all queue-confined: marshal it.
     * The marshaling block strongly captures the queue and the content
     * (ARC), keeping both alive until the queued retirement ran.
     */
    void (*retire)(void *) = _onRetire;
    void *ctx = _ctx;
    dispatch_queue_t q = _queue;
    dispatch_data_t content = _content;

    if (retire != NULL && q != NULL) {
        dispatch_async(q, ^{
          (void)content; /* released with the block, after retirement */
          retire(ctx);
        });
    }
}
@end

#ifdef WTQ_NW_TESTING
/*
 * TEST HOOK: exercise the dealloc-marshaling contract from a FOREIGN
 * thread. The completion-shaped block strongly captures a holder (as a
 * real send's would); the copy is created here and released from a
 * global concurrent queue WITHOUT invocation — exactly the "Apple
 * disposed its copy on whatever thread" case. -dealloc must marshal
 * the retirement onto `queue` exactly once.
 */
void wtq_nw_test_holder_foreign_dispose(dispatch_queue_t queue,
                                        void (*on_retire)(void *),
                                        void *ctx)
{
    WTQNWSendHolder *h = [[WTQNWSendHolder alloc] init];
    h->_onRetire = on_retire;
    h->_ctx = ctx;
    h->_queue = queue;
    h->_content = NULL;

    void (^completion)(nw_error_t) = ^(nw_error_t error) {
      (void)h;
      (void)error;
    };
    void (^copy)(nw_error_t) = [completion copy];
    h = nil; /* the block copy holds the ONLY strong reference */
    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
          /* dropped here, uninvoked, on a foreign thread */
          (void)copy;
        });
}

#endif /* WTQ_NW_TESTING */

void wtqi_nw_send_with_holder(nw_connection_t c, dispatch_queue_t queue,
                             dispatch_data_t content, bool is_complete,
                             void (*on_complete)(void *ctx, bool canceled),
                             void (*on_retire)(void *ctx), void *ctx)
{
    WTQNWSendHolder *h = [[WTQNWSendHolder alloc] init];
    h->_onRetire = on_retire;
    h->_ctx = ctx;
    h->_queue = queue;     /* ARC-retained ivars (OS_OBJECT_USE_OBJC) */
    h->_content = content; /* retained through DISPOSAL + retirement */

    /*
     * The block strongly captures `h` (ARC). nw_connection_send copies
     * the block; when Network.framework drops its last reference —
     * after invocation, or without invocation at teardown — ARC
     * releases `h`, and -dealloc marshals TRANSPORT_RETIRED onto the
     * connection's queue. The holder also keeps the dispatch_data
     * alive until that disposal.
     *
     * QUIC streams are STREAM-context sends: is_complete on the
     * default STREAM context is the write-side FIN. (The MESSAGE
     * contexts are for datagram-style protocols; mixing them into a
     * stream loses buffered content — measured.)
     */
    nw_connection_send(c, content, NW_CONNECTION_DEFAULT_STREAM_CONTEXT,
                       is_complete, ^(nw_error_t error) {
                         (void)h;
                         on_complete(ctx, error != NULL);
                       });
}
