/*
 * MINIMAL Apple-attribution reproducer — raw Network.framework only.
 *
 * No wtquic engine, no backend, no group-metadata-copy API. One serial
 * queue is the serialization domain; the peer is the committed raw
 * MsQuic observer (raw_peer.c, linked unmodified) so no HTTP/3 or
 * WebTransport implementation exists anywhere in this process.
 *
 * Lifecycle discipline (deliberately conservative — every rule Apple
 * documents or the probe measured):
 *   - extracted stream options come from the group's copied parameters,
 *     flags set immediately before each extract (aliased handle);
 *   - one state handler per connection, installed before set_queue/
 *     start; `cancelled` is treated as the ONLY final state (`failed`
 *     converges via cancel);
 *   - after `cancelled`, the handler is removed in a LATER queue turn,
 *     and the connection is released + the record freed in ANOTHER
 *     later turn — never inside a callback frame;
 *   - a record is destroyed only when cancelled AND no send completion
 *     or receive completion is still outstanding; a completion block
 *     Apple disposes without invoking pins its record forever (counted
 *     and leaked, never inferred);
 *   - the group is cancelled last, its terminal awaited, and released
 *     off-domain after a queue barrier.
 *
 * Shape mirrors the settled-abort battery that crashes the full stack:
 * churn rounds of "open stream -> send+FIN -> completion -> cancel ->
 * two-turn teardown" on one connection group, repeated across groups.
 *
 * Exit 0 = survived. A SIGSEGV/SIGBUS here is a crash in a program
 * whose every Network.framework interaction is lifecycle-valid.
 *
 * Build (manual target `nw_apple_repro`, never a registered test):
 *   cmake -DWTQ_BUILD_NETWORK=ON -DWTQ_BUILD_MSQUIC=ON
 * Usage:
 *   nw_apple_repro <cert> <key> [batteries] [rounds] [streams]
 */
#include <dispatch/dispatch.h>
#include <Network/Network.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../backends/network_experimental/raw_peer.h"

#define READY_MS 10000
#define WIRE_MS 10000

static int g_failures;
#define RCHECK(cond)                                                         \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "RCHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                    #cond);                                                  \
            g_failures++;                                                    \
        }                                                                    \
    } while (0)

/* leaked records: a completion block disposed without invocation pins
 * its record (counted, never freed on inference) */
static int g_pinned;

struct rstream {
    nw_connection_t c;
    dispatch_queue_t q;
    struct rstream *next;       /* battery registry (queue-confined) */
    struct rstream **head;
    int cancelled;      /* the final state was observed          */
    int cancel_issued;
    int sends_out;      /* issued sends whose completion has not run */
    int recvs_out;      /* armed receives whose completion has not run */
    int detach_done;    /* turn-1 handler removal ran            */
    int reap_latched;   /* exactly one deferred teardown queued  */
    char payload[64];
    size_t plen;
};

static bool wait_sem(dispatch_semaphore_t s, int ms)
{
    return dispatch_semaphore_wait(
               s, dispatch_time(DISPATCH_TIME_NOW,
                                (int64_t)ms * NSEC_PER_MSEC)) == 0;
}

static bool rs_eligible(struct rstream *rs)
{
    return rs->cancelled && rs->sends_out == 0 && rs->recvs_out == 0;
}

/* Two-turn teardown: turn 1 removes the handler, turn 2 releases the
 * connection and frees the record. Only ever entered from the domain
 * queue, never executed inside a Network.framework callback frame. */
static void rs_maybe_teardown(struct rstream *rs)
{
    if (rs->reap_latched || !rs_eligible(rs))
        return;
    rs->reap_latched = 1;
    struct rstream *cap = rs;
    dispatch_async(rs->q, ^{
      if (!rs_eligible(cap)) {
          cap->reap_latched = 0;
          return;
      }
      nw_connection_set_state_changed_handler(cap->c, NULL);
      cap->detach_done = 1;
      dispatch_async(cap->q, ^{
        if (!rs_eligible(cap) || !cap->detach_done) {
            cap->reap_latched = 0;
            return;
        }
        nw_release(cap->c);
        cap->c = NULL;
        struct rstream **pp = cap->head;
        while (*pp != NULL && *pp != cap)
            pp = &(*pp)->next;
        if (*pp == cap)
            *pp = cap->next;
        free(cap);
      });
    });
}

static void rs_arm_receive(struct rstream *rs)
{
    if (rs->cancelled || rs->cancel_issued || rs->c == NULL)
        return;
    rs->recvs_out++;
    struct rstream *cap = rs;
    nw_connection_receive(
        rs->c, 1, 65535,
        ^(dispatch_data_t content, nw_content_context_t ctx,
          bool is_complete, nw_error_t error) {
          (void)content;
          (void)ctx;
          cap->recvs_out--;
          if (error == NULL && !is_complete)
              rs_arm_receive(cap);
          rs_maybe_teardown(cap);
        });
}

/* Copy the group's parameters, set every stream flag, extract: the one
 * indivisible on-domain operation (the options handle is aliased). */
static nw_connection_t group_extract_stream(nw_connection_group_t g,
                                            bool uni)
{
    nw_parameters_t params = nw_connection_group_copy_parameters(g);
    if (params == NULL)
        return NULL;
    nw_protocol_stack_t stack =
        nw_parameters_copy_default_protocol_stack(params);
    nw_release(params);
    if (stack == NULL)
        return NULL;
    nw_protocol_options_t opts =
        nw_protocol_stack_copy_transport_protocol(stack);
    nw_release(stack);
    if (opts == NULL)
        return NULL;
    nw_quic_set_stream_is_unidirectional(opts, uni);
    nw_quic_set_stream_is_datagram(opts, false);
    nw_connection_t c = nw_connection_group_extract_connection(g, NULL, opts);
    nw_release(opts);
    return c;
}

/*
 * One settled-abort stream: open, send marker+FIN at ready, cancel from
 * the send completion (a later frame than issue), tear down two-turn
 * after cancelled. The whole life happens on `q`.
 */
static void spawn_stream(nw_connection_group_t g, dispatch_queue_t q,
                         int battery, int round, int idx,
                         dispatch_group_t done, struct rstream **head)
{
    struct rstream *rs = calloc(1, sizeof(*rs));
    if (rs == NULL) {
        g_failures++;
        return;
    }
    rs->q = q;
    rs->head = head;
    rs->next = *head;
    *head = rs;
    int n = snprintf(rs->payload, sizeof(rs->payload), "rp-%d-%d-%d%c",
                     battery, round, idx, RAW_PEER_MARKER_TERM);
    rs->plen = (size_t)n;
    rs->c = group_extract_stream(g, false);
    if (rs->c == NULL) {
        *head = rs->next;
        free(rs);
        g_failures++;
        return;
    }
    struct rstream *cap = rs;
    dispatch_group_enter(done);
    nw_connection_set_state_changed_handler(
        rs->c, ^(nw_connection_state_t st, nw_error_t e) {
          (void)e;
          if (st == nw_connection_state_ready) {
              dispatch_data_t d = dispatch_data_create(
                  cap->payload, cap->plen, cap->q,
                  DISPATCH_DATA_DESTRUCTOR_DEFAULT);
              cap->sends_out++;
              nw_connection_send(
                  cap->c, d, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, true,
                  ^(nw_error_t se) {
                    (void)se;
                    cap->sends_out--;
                    /* the settled abort: activity done, now cancel —
                     * from a completion frame, like production */
                    if (!cap->cancel_issued) {
                        cap->cancel_issued = 1;
                        nw_connection_cancel(cap->c);
                    }
                    rs_maybe_teardown(cap);
                  });
              dispatch_release(d);
              rs_arm_receive(cap);
          } else if (st == nw_connection_state_failed) {
              if (!cap->cancel_issued) {
                  cap->cancel_issued = 1;
                  nw_connection_cancel(cap->c);
              }
          } else if (st == nw_connection_state_cancelled) {
              cap->cancelled = 1;
              rs_maybe_teardown(cap);
              dispatch_group_leave(done);
          }
        });
    nw_connection_set_queue(rs->c, q);
    nw_connection_start(rs->c);
}

static int run_battery(const char *cert, const char *key, int battery,
                       int rounds, int streams)
{
    uint16_t port = 0;
    raw_peer_t *rp = raw_peer_start(cert, key, &port, NULL);
    if (rp == NULL) {
        fprintf(stderr, "raw peer failed to start\n");
        return 1;
    }

    dispatch_queue_attr_t qattr =
        dispatch_queue_attr_make_with_autorelease_frequency(
            DISPATCH_QUEUE_SERIAL, DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM);
    dispatch_queue_t q = dispatch_queue_create("nw.repro", qattr);
    dispatch_queue_t vq = dispatch_queue_create("nw.repro.verify", NULL);

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    nw_parameters_t params =
        nw_parameters_create_quic(^(nw_protocol_options_t quic) {
          sec_protocol_options_t sec = nw_quic_copy_sec_protocol_options(quic);
          sec_protocol_options_add_tls_application_protocol(sec, "h3");
          sec_protocol_options_set_verify_block(
              sec,
              ^(sec_protocol_metadata_t md, sec_trust_t t,
                sec_protocol_verify_complete_t vdone) {
                (void)md;
                (void)t;
                vdone(true); /* self-signed loopback peer */
              },
              vq);
          nw_release(sec);
        });
    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_release(ep);
    nw_connection_group_t group = nw_connection_group_create(desc, params);
    nw_release(desc);
    nw_release(params);
    nw_connection_group_set_queue(group, q);
    nw_connection_group_set_receive_handler(
        group, 65535, true,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool fin) {
          (void)content;
          (void)ctx;
          (void)fin;
        });
    nw_connection_group_set_new_connection_handler(
        group, ^(nw_connection_t in) {
          /* the peer opens no streams; NW's own hidden stream may show:
           * adopt-and-kill with owned retain, released in a later turn */
          nw_retain(in);
          nw_connection_set_state_changed_handler(
              in, ^(nw_connection_state_t st, nw_error_t e) {
                (void)st;
                (void)e;
              });
          nw_connection_set_queue(in, q);
          nw_connection_start(in);
          nw_connection_cancel(in);
          dispatch_async(q, ^{
            nw_connection_set_state_changed_handler(in, NULL);
            dispatch_async(q, ^{ nw_release(in); });
          });
        });
    dispatch_semaphore_t gready = dispatch_semaphore_create(0);
    dispatch_semaphore_t ggone = dispatch_semaphore_create(0);
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t e) {
          (void)e;
          if (st == nw_connection_group_state_ready)
              dispatch_semaphore_signal(gready);
          else if (st == nw_connection_group_state_failed ||
                   st == nw_connection_group_state_cancelled)
              dispatch_semaphore_signal(ggone);
        });
    nw_connection_group_start(group);
    if (!wait_sem(gready, READY_MS)) {
        fprintf(stderr, "battery %d: group never ready\n", battery);
        nw_connection_group_cancel(group);
        (void)wait_sem(ggone, WIRE_MS);
        (void)raw_peer_stop(rp);
        return 1;
    }

    static struct rstream *live; /* one battery at a time; queue-confined */
    live = NULL;
    struct rstream **headp = &live;
    for (int r = 0; r < rounds; r++) {
        dispatch_group_t done = dispatch_group_create();
        dispatch_sync(q, ^{
          for (int i = 0; i < streams; i++)
              spawn_stream(group, q, battery, r, i, done, headp);
        });
        /* every stream reached `cancelled` (their two-turn teardowns
         * are queued behind this wait and drain with the barrier) */
        if (dispatch_group_wait(done,
                                dispatch_time(DISPATCH_TIME_NOW,
                                              (int64_t)WIRE_MS *
                                                  NSEC_PER_MSEC)) != 0) {
            fprintf(stderr, "battery %d round %d: streams stuck\n",
                    battery, r);
            g_failures++;
        }
        dispatch_release(done);
        dispatch_sync(q, ^{ /* barrier: teardown turns drained */ });
    }

    /*
     * The flow-failure storm (the production crash shape): spawn a
     * final wave of streams and cancel the GROUP while they are
     * starting/live — every child flow fails at once. Lifecycle stays
     * valid: children are individually cancelled on-domain right after
     * the group cancel (the production group-terminal sweep), each is
     * still awaited to `cancelled`, and teardown stays two-turn.
     */
    dispatch_group_t wave = dispatch_group_create();
    dispatch_sync(q, ^{
      for (int i = 0; i < streams; i++)
          spawn_stream(group, q, battery, rounds, i, wave, headp);
    });
    dispatch_sync(q, ^{
      nw_connection_group_cancel(group);
      for (struct rstream *rs = live; rs != NULL; rs = rs->next)
          if (!rs->cancel_issued && rs->c != NULL) {
              rs->cancel_issued = 1;
              nw_connection_cancel(rs->c);
          }
    });
    if (dispatch_group_wait(wave,
                            dispatch_time(DISPATCH_TIME_NOW,
                                          (int64_t)WIRE_MS *
                                              NSEC_PER_MSEC)) != 0) {
        fprintf(stderr, "battery %d: wave streams stuck\n", battery);
        g_failures++;
    }
    dispatch_release(wave);
    RCHECK(wait_sem(ggone, WIRE_MS));
    dispatch_sync(q, ^{ /* barrier */ });
    __block int pinned = 0;
    dispatch_sync(q, ^{
      for (struct rstream *rs = live; rs != NULL; rs = rs->next)
          pinned++;
    });
    g_pinned += pinned; /* undisposed completions pin records: leaked */
    nw_release(group);
    dispatch_release(q);
    dispatch_release(vq);
    (void)raw_peer_stop(rp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <cert> <key> [batteries] [rounds] [streams]\n",
                argv[0]);
        return 2;
    }
    int batteries = argc > 3 ? atoi(argv[3]) : 10;
    int rounds = argc > 4 ? atoi(argv[4]) : 6;
    int streams = argc > 5 ? atoi(argv[5]) : 8;

    for (int b = 0; b < batteries; b++) {
        if (run_battery(argv[1], argv[2], b, rounds, streams) != 0)
            break;
        fprintf(stderr, "battery %d/%d ok\n", b + 1, batteries);
    }
    if (g_pinned != 0)
        fprintf(stderr, "note: %d records pinned by undisposed blocks\n",
                g_pinned);
    if (g_failures != 0) {
        fprintf(stderr, "FAILURES: %d\n", g_failures);
        return 1;
    }
    fprintf(stderr, "repro survived: %d batteries x %d rounds x %d streams\n",
            batteries, rounds, streams);
    return 0;
}
