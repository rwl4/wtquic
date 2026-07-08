/*
 * EXPERIMENTAL disposal sentinel — see send_sentinel.h.
 * Compiled with ARC; the ONLY Objective-C in the probe. Its sole job is to
 * make completion-block disposal observable from the C experiment code.
 */
#import <Foundation/Foundation.h>

#include "send_sentinel.h"

@interface WTQDisposalSentinel : NSObject {
  @public
    void (*_onDispose)(void *);
    void *_ctx;
}
@end

@implementation WTQDisposalSentinel
- (void)dealloc
{
    if (_onDispose != NULL)
        _onDispose(_ctx);
}
@end

void wtq_probe_send_with_sentinel(nw_connection_t c, dispatch_data_t content,
                                  bool is_complete,
                                  void (*on_complete)(void *ctx,
                                                      int err_domain,
                                                      int err_code),
                                  void (*on_dispose)(void *ctx), void *ctx)
{
    WTQDisposalSentinel *s = [[WTQDisposalSentinel alloc] init];
    s->_onDispose = on_dispose;
    s->_ctx = ctx;

    /*
     * The block strongly captures `s` (ARC). nw_connection_send copies the
     * block; when Network.framework drops its last reference — after
     * invocation, or without invocation at teardown — ARC releases `s`
     * and -dealloc reports the disposal. The (void)s use below forces the
     * capture.
     */
    nw_connection_send(c, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
                       is_complete, ^(nw_error_t error) {
                         (void)s;
                         int d = error != NULL
                                     ? (int)nw_error_get_error_domain(error)
                                     : -1;
                         int e = error != NULL
                                     ? (int)nw_error_get_error_code(error)
                                     : 0;
                         on_complete(ctx, d, e);
                       });
}
