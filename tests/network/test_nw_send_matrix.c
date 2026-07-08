/*
 * Network.framework SEND-LOSS ISOLATION MATRIX (production-shaped).
 *
 * Reproduces the cross-backend loopback's traffic shape against the raw
 * MsQuic observer peer (backends/network_experimental/raw_peer.{c,h},
 * linked UNMODIFIED) with exact per-stream-id byte/FIN attribution,
 * then lets dimensions be stripped one at a time to find the minimal
 * losing shape (WTQ_NW_MATRIX_DIMS bitmask, default = all).
 *
 * Dimensions (production ordering preserved):
 *   0x01 CRITICALS  three H3-critical-like local unis, first flights
 *   0x02 CONNECT    a CONNECT-like bidi: first flight + receive armed,
 *                   peer sends response bytes back on it
 *   0x04 DGRAM      a datagram flow on the same group; sends and
 *                   receives overlap the stream first flights
 *   0x08 PARALLEL   WT-like uni+bidi first flights issued with sends
 *                   OUTSTANDING CONCURRENTLY (never wait for one
 *                   marker before issuing the next)
 *   0x10 FIN        WT payloads carry is_complete FIN
 *   0x20 NOCOPY     WT payloads are copied-head + NO-COPY-tail
 *                   composites (the production gather shape)
 *   0x40 INBOUND    the peer opens a server-uni with bytes; the client
 *                   adopts it and reads (inbound receive activity)
 *
 * Issue-context variants alternate per WT stream: INSIDE the ready
 * state-handler frame vs a block QUEUED from that handler and executed
 * after it returns — both proven by queue-specific assertions, never
 * inferred.
 *
 * Sends go through the PRODUCTION holder (wtqi_nw_send_with_holder):
 * content retained through block DISPOSAL, retirement marshaled onto
 * the connection queue (asserted on-domain).
 *
 * Lifecycle rules (probe/production-derived):
 *   - `cancelled` is the ONLY final state; `failed` is followed by a
 *     cancel and a wait for `cancelled` before any release;
 *   - every hidden inbound connection is tracked from registration
 *     through cancel/cancelled/release;
 *   - rundown latches a flag + queue barrier before its snapshot
 *     (the new-connection handler cannot be cleared after start);
 *   - roots are released only after the group and every child reached
 *     terminal; a teardown timeout FAILS the test and retains the
 *     unsafe roots.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dispatch/dispatch.h>
#include <Network/Network.h>

#include "../../backends/network_experimental/raw_peer.h"
#include "nw_internal.h" /* the production send holder */

#define READY_MS 8000
#define WIRE_MS 8000
#define PAYLOAD_LEN 40 /* fits raw_peer MARKER_MAX (48) with headroom */

#define DIM_CRITICALS 0x01u
#define DIM_CONNECT 0x02u
#define DIM_DGRAM 0x04u
#define DIM_PARALLEL 0x08u
#define DIM_FIN 0x10u
#define DIM_NOCOPY 0x20u
#define DIM_INBOUND 0x40u
#define DIM_EMPTYSEED 0x80u /* build the composite EXACTLY like the
                             * production pump: seed with
                             * dispatch_data_empty and fold each part in
                             * with dispatch_data_create_concat */
#define DIM_ALL 0xffu

static char cert_path[512];
static char key_path[512];
static int g_failures;
static void *g_qkey = &g_qkey; /* queue-specific identity key */

#define MCHECK(expr)                                                      \
    do {                                                                  \
        if (!(expr)) {                                                    \
            fprintf(stderr, "MATRIX-FAIL %s:%d: %s\n", __FILE__,          \
                    __LINE__, #expr);                                     \
            g_failures++;                                                 \
        }                                                                 \
    } while (0)

static bool on_domain(void)
{
    return dispatch_get_specific(g_qkey) == g_qkey;
}

static bool wait_sem(dispatch_semaphore_t s, int ms)
{
    return dispatch_semaphore_wait(
               s, dispatch_time(DISPATCH_TIME_NOW,
                                (int64_t)ms * NSEC_PER_MSEC)) == 0;
}

/* --- one matrix stream ---------------------------------------------------- */

struct mstream {
    nw_connection_t c;          /* retained */
    dispatch_semaphore_t done;  /* signaled at CANCELLED (the final state) */
    int ready_seen;
    int failed_seen;
    int cancelled_seen;
    int cancel_issued;
    int completion_ran;         /* production-holder completion count */
    int retire_ran;             /* retirement count (must be on-domain) */
    int retire_on_domain;
    uint8_t rx[256];            /* peer->client bytes (bidi/inbound) */
    size_t rx_len;
    int rx_fin;
};

static struct mstream *ms_new(void)
{
    struct mstream *m = calloc(1, sizeof(*m));

    if (m != NULL)
        m->done = dispatch_semaphore_create(0);
    return m;
}

static void ms_arm_receive(struct mstream *m)
{
    struct mstream *cap = m;

    nw_connection_receive(
        m->c, 1, 4096,
        ^(dispatch_data_t content, nw_content_context_t ctx,
          bool is_complete, nw_error_t error) {
          if (content != NULL) {
              dispatch_data_apply(
                  content, ^bool(dispatch_data_t r, size_t off,
                                 const void *buf, size_t len) {
                    (void)r;
                    (void)off;
                    if (cap->rx_len + len <= sizeof(cap->rx)) {
                        memcpy(cap->rx + cap->rx_len, buf, len);
                        cap->rx_len += len;
                    }
                    return true;
                  });
          }
          if (is_complete && ctx != NULL &&
              nw_content_context_get_is_final(ctx))
              cap->rx_fin = 1;
          if (error == NULL && !cap->rx_fin && !cap->cancel_issued)
              ms_arm_receive(cap);
        });
}

/* Shared state-handler policy: `cancelled` is the ONLY final state. */
static void ms_attach_handler(struct mstream *m,
                              void (^on_ready)(struct mstream *))
{
    struct mstream *cap = m;
    void (^ready_cb)(struct mstream *) = on_ready;

    nw_connection_set_state_changed_handler(
        m->c, ^(nw_connection_state_t st, nw_error_t e) {
          (void)e;
          if (st == nw_connection_state_ready) {
              if (!cap->ready_seen) {
                  cap->ready_seen = 1;
                  if (ready_cb != NULL)
                      ready_cb(cap); /* INSIDE the handler frame */
              }
          } else if (st == nw_connection_state_failed) {
              if (!cap->failed_seen) {
                  cap->failed_seen = 1;
                  if (!cap->cancel_issued) {
                      cap->cancel_issued = 1;
                      nw_connection_cancel(cap->c); /* converge */
                  }
              }
          } else if (st == nw_connection_state_cancelled) {
              cap->cancelled_seen = 1;
              dispatch_semaphore_signal(cap->done);
          }
        });
}

/* Open a stream on the group with the matrix lifecycle. `on_ready`
 * (optional) runs SYNCHRONOUSLY INSIDE the ready state-handler frame. */
static struct mstream *ms_open(nw_connection_group_t g, dispatch_queue_t q,
                               bool uni, bool dgram,
                               void (^on_ready)(struct mstream *))
{
    struct mstream *m = ms_new();

    if (m == NULL)
        return NULL;
    nw_parameters_t params = nw_connection_group_copy_parameters(g);
    nw_protocol_stack_t stack =
        params ? nw_parameters_copy_default_protocol_stack(params) : NULL;
    nw_protocol_options_t o =
        stack ? nw_protocol_stack_copy_transport_protocol(stack) : NULL;
    if (params != NULL)
        nw_release(params);
    if (stack != NULL)
        nw_release(stack);
    if (o == NULL) {
        dispatch_release(m->done);
        free(m);
        return NULL;
    }
    nw_quic_set_stream_is_unidirectional(o, uni);
    nw_quic_set_stream_is_datagram(o, dgram);
    m->c = nw_connection_group_extract_connection(g, NULL, o);
    nw_release(o);
    if (m->c == NULL) {
        dispatch_release(m->done);
        free(m);
        return NULL;
    }
    ms_attach_handler(m, on_ready);
    nw_connection_set_queue(m->c, q);
    nw_connection_start(m->c);
    return m;
}

/* Cancel (if needed) and wait for CANCELLED; false = unsafe to release. */
static bool ms_shutdown(struct mstream *m)
{
    if (m == NULL)
        return true;
    if (!m->cancel_issued) {
        m->cancel_issued = 1;
        nw_connection_cancel(m->c);
    }
    if (!wait_sem(m->done, WIRE_MS) && !m->cancelled_seen)
        return false; /* NOT final: caller must retain the roots */
    nw_release(m->c);
    dispatch_release(m->done);
    free(m);
    return true;
}

/* --- production-holder send accounting ----------------------------------- */

static void send_on_complete(void *ctx, bool canceled)
{
    struct mstream *m = ctx;

    (void)canceled;
    m->completion_ran++;
    MCHECK(on_domain()); /* completion delivered on the connection queue */
}

static void send_on_retire(void *ctx)
{
    struct mstream *m = ctx;

    m->retire_ran++;
    if (on_domain())
        m->retire_on_domain++;
}

/* Build payload content per the composition dimensions. */
static dispatch_data_t build_payload(const char *payload, size_t plen,
                                     bool nocopy, bool emptyseed,
                                     char *tail_store, dispatch_queue_t q)
{
    size_t head = 9;
    dispatch_data_t dh = dispatch_data_create(
        payload, nocopy ? head : plen, q,
        DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    dispatch_data_t dt = NULL;
    if (nocopy) {
        memcpy(tail_store, payload + head, plen - head);
        dt = dispatch_data_create(tail_store, plen - head, q,
                                  ^{ /* no-copy borrow */ });
    }
    dispatch_data_t all;
    if (emptyseed) {
        /* the PRODUCTION pump's exact construction */
        all = dispatch_data_empty;
        dispatch_retain(all);
        dispatch_data_t m1 = dispatch_data_create_concat(all, dh);
        dispatch_release(all);
        all = m1;
        if (dt != NULL) {
            dispatch_data_t m2 = dispatch_data_create_concat(all, dt);
            dispatch_release(all);
            all = m2;
        }
    } else if (dt != NULL) {
        all = dispatch_data_create_concat(dh, dt);
    } else {
        all = dh;
        dispatch_retain(all);
    }
    dispatch_release(dh);
    if (dt != NULL)
        dispatch_release(dt);
    return all;
}

/* Verify size + flattened bytes IMMEDIATELY before the send. */
static bool verify_content(dispatch_data_t d, const char *payload,
                           size_t plen)
{
    if (d == NULL || dispatch_data_get_size(d) != plen)
        return false;
    const void *fb = NULL;
    size_t fl = 0;
    dispatch_data_t map = dispatch_data_create_map(d, &fb, &fl);
    bool ok = map != NULL && fl == plen && memcmp(fb, payload, plen) == 0;
    if (map != NULL)
        dispatch_release(map);
    return ok;
}

/* --- one full-shape block ---------------------------------------------------- */

#define INBOUND_MAX 16
struct inbound_reg {
    struct mstream *conns[INBOUND_MAX];
    int n;
    int overflow;
    int rundown;
};

struct wtcase {
    struct mstream *m;
    char marker[PAYLOAD_LEN + 2];
    char payload[PAYLOAD_LEN + 2];
    char tail_store[PAYLOAD_LEN + 8];
    size_t plen;
    bool fin;
    bool inside_ready;
    int issued_inside;
    int issued_outside;
};

static int run_block(int block, unsigned dims, int *seq_io)
{
    int fail_base = g_failures;
    int seq = *seq_io;
    uint16_t port = 0;
    raw_peer_t *rp = raw_peer_start(cert_path, key_path, &port, NULL);

    if (rp == NULL) {
        fprintf(stderr, "raw peer failed to start\n");
        g_failures++;
        return 1;
    }
    dispatch_queue_t q = dispatch_queue_create("wtq.nw.matrix", NULL);
    dispatch_queue_set_specific(q, g_qkey, g_qkey, NULL);
    dispatch_queue_t vq = dispatch_queue_create("wtq.nw.matrix.v", NULL);

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    nw_parameters_t params =
        nw_parameters_create_quic(^(nw_protocol_options_t quic) {
          nw_quic_set_max_datagram_frame_size(quic, 65535);
          sec_protocol_options_t sec =
              nw_quic_copy_sec_protocol_options(quic);
          sec_protocol_options_add_tls_application_protocol(sec, "h3");
          sec_protocol_options_set_verify_block(
              sec,
              ^(sec_protocol_metadata_t md, sec_trust_t t,
                sec_protocol_verify_complete_t done) {
                (void)md;
                (void)t;
                done(true);
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
        ^(dispatch_data_t content, nw_content_context_t ctx, bool done_) {
          (void)content;
          (void)ctx;
          (void)done_;
        });

    static struct inbound_reg reg; /* one block at a time */
    memset(&reg, 0, sizeof(reg));
    struct inbound_reg *regp = &reg;
    dispatch_queue_t cq0 = q;
    nw_connection_group_set_new_connection_handler(
        group, ^(nw_connection_t in) {
          struct mstream *im = ms_new();
          if (im == NULL)
              return;
          nw_retain(in);
          im->c = in;
          ms_attach_handler(im, ^(struct mstream *mm) {
            ms_arm_receive(mm); /* inbound bytes flow */
          });
          nw_connection_set_queue(in, cq0);
          nw_connection_start(in);
          if (regp->rundown) {
              im->cancel_issued = 1;
              nw_connection_cancel(in); /* adopt-and-kill during rundown */
          }
          if (regp->n < INBOUND_MAX)
              regp->conns[regp->n++] = im;
          else
              regp->overflow = 1; /* hard, visible failure */
        });
    dispatch_semaphore_t gready = dispatch_semaphore_create(0);
    dispatch_semaphore_t ggone = dispatch_semaphore_create(0);
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t e) {
          (void)e;
          if (st == nw_connection_group_state_ready)
              dispatch_semaphore_signal(gready);
          else if (st == nw_connection_group_state_cancelled ||
                   st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(ggone);
        });
    nw_connection_group_start(group);
    if (!wait_sem(gready, READY_MS)) {
        fprintf(stderr, "group never ready (block %d)\n", block);
        g_failures++;
        nw_connection_group_cancel(group);
        (void)wait_sem(ggone, WIRE_MS);
        (void)raw_peer_stop(rp);
        return 1;
    }

    /* ---- production ordering ---- */

    /* 1. three H3-critical-like unis, first flights (no FIN) */
    struct mstream *crit[3] = { NULL, NULL, NULL };
    static char critmark[3][PAYLOAD_LEN + 2];
    static char critpay[3][PAYLOAD_LEN + 2];
    if (dims & DIM_CRITICALS) {
        for (int i = 0; i < 3; i++) {
            int n = snprintf(critmark[i], sizeof(critmark[i]),
                             "mx-%d-crit%d", seq++, i);
            memcpy(critpay[i], critmark[i], (size_t)n);
            critpay[i][n] = RAW_PEER_MARKER_TERM;
            size_t plen = (size_t)n + 1;
            char *pay = critpay[i];
            dispatch_queue_t cq = q;
            crit[i] = ms_open(group, q, true, false,
                              ^(struct mstream *mm) {
                                dispatch_data_t d = dispatch_data_create(
                                    pay, plen, cq,
                                    DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                                wtqi_nw_send_with_holder(
                                    mm->c, cq, d, false, send_on_complete,
                                    send_on_retire, mm);
                                dispatch_release(d);
                              });
            MCHECK(crit[i] != NULL);
        }
    }

    /* 2. CONNECT-like bidi: first flight, receive armed, peer response */
    struct mstream *conn_b = NULL;
    static char connmark[PAYLOAD_LEN + 2];
    static char connpay[PAYLOAD_LEN + 2];
    if (dims & DIM_CONNECT) {
        int n = snprintf(connmark, sizeof(connmark), "mx-%d-connect",
                         seq++);
        memcpy(connpay, connmark, (size_t)n);
        connpay[n] = RAW_PEER_MARKER_TERM;
        size_t plen = (size_t)n + 1;
        dispatch_queue_t cq = q;
        conn_b = ms_open(group, q, false, false, ^(struct mstream *mm) {
          ms_arm_receive(mm);
          dispatch_data_t d = dispatch_data_create(
              connpay, plen, cq, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
          wtqi_nw_send_with_holder(mm->c, cq, d, false, send_on_complete,
                                  send_on_retire, mm);
          dispatch_release(d);
        });
        MCHECK(conn_b != NULL);
    }

    /* 3. datagram flow overlapping the first flights */
    struct mstream *dg = NULL;
    if (dims & DIM_DGRAM) {
        dg = ms_open(group, q, false, true, ^(struct mstream *mm) {
          ms_arm_receive(mm);
          /* overlap: a datagram out during the first flights */
          static const char dmsg[] = "mx-dgram\n";
          dispatch_data_t d = dispatch_data_create(
              dmsg, sizeof(dmsg) - 1, NULL,
              DISPATCH_DATA_DESTRUCTOR_DEFAULT);
          nw_connection_send(mm->c, d,
                             NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                             ^(nw_error_t err) { (void)err; });
          dispatch_release(d);
        });
        MCHECK(dg != NULL);
    }

    /* 4. WT-like first flights: uni+bidi, sends OUTSTANDING
     * CONCURRENTLY when DIM_PARALLEL, alternating issue-inside-ready
     * vs queued-outside-ready (both PROVEN via queue-specific checks) */
    enum { NWT = 4 };
    static struct wtcase wt[NWT];
    memset(wt, 0, sizeof(wt));
    for (int i = 0; i < NWT; i++) {
        struct wtcase *w = &wt[i];
        bool bidi = (i % 2) == 1;
        w->fin = (dims & DIM_FIN) != 0;
        w->inside_ready = (i % 2) == 0;
        int n = snprintf(w->marker, sizeof(w->marker), "mx-%d-wt%d", seq++,
                         i);
        while (n < PAYLOAD_LEN - 1) {
            w->marker[n] = (char)('a' + (n % 26));
            n++;
        }
        w->marker[n] = 0;
        memcpy(w->payload, w->marker, (size_t)n);
        w->payload[n] = RAW_PEER_MARKER_TERM;
        w->plen = (size_t)n + 1;

        struct wtcase *wc = w;
        dispatch_queue_t cq = q;
        bool nocopy = (dims & DIM_NOCOPY) != 0;
        bool eseed = (dims & DIM_EMPTYSEED) != 0;
        void (^issue)(struct mstream *) = ^(struct mstream *mm) {
          dispatch_data_t d = build_payload(wc->payload, wc->plen, nocopy,
                                            eseed, wc->tail_store, cq);
          MCHECK(verify_content(d, wc->payload, wc->plen));
          wtqi_nw_send_with_holder(mm->c, cq, d, wc->fin, send_on_complete,
                                  send_on_retire, mm);
          if (d != NULL)
              dispatch_release(d);
        };
        w->m = ms_open(group, q, !bidi, false, ^(struct mstream *mm) {
          if (bidi)
              ms_arm_receive(mm);
          if (wc->inside_ready) {
              MCHECK(on_domain());
              wc->issued_inside++;
              issue(mm); /* synchronously INSIDE the handler frame */
          } else {
              dispatch_async(cq, ^{
                MCHECK(on_domain());
                wc->issued_outside++;
                issue(mm); /* after the handler frame returned */
              });
          }
        });
        MCHECK(w->m != NULL);
        if (!(dims & DIM_PARALLEL)) {
            uint64_t id = 0;
            MCHECK(raw_peer_wait_marker(rp, w->marker, &id, WIRE_MS));
        }
    }

    /* 5. inbound: the peer opens a server-uni with bytes */
    uint64_t inbound_id = UINT64_MAX;
    if (dims & DIM_INBOUND) {
        MCHECK(raw_peer_open_stream(rp, true, &inbound_id, WIRE_MS));
        if (inbound_id != UINT64_MAX)
            MCHECK(raw_peer_send_on_stream(rp, inbound_id, "sv-in\n", 6,
                                           false));
    }

    /* ---- verification (exact attribution) ---- */

    if (dims & DIM_CRITICALS)
        for (int i = 0; i < 3; i++) {
            uint64_t id = 0;
            if (!raw_peer_wait_marker(rp, critmark[i], &id, WIRE_MS)) {
                fprintf(stderr, "LOSS block=%d dims=0x%02x crit%d\n",
                        block, dims, i);
                g_failures++;
            }
        }
    if (dims & DIM_CONNECT) {
        uint64_t id = 0;
        bool got = raw_peer_wait_marker(rp, connmark, &id, WIRE_MS);
        if (!got) {
            fprintf(stderr, "LOSS block=%d dims=0x%02x connect\n", block,
                    dims);
            g_failures++;
        } else {
            /* the peer's response on the SAME bidi reaches the client */
            MCHECK(raw_peer_send_on_stream(rp, id, "sv-conn-resp", 12,
                                           false));
            for (int spin = 0; spin < WIRE_MS / 10; spin++) {
                if (conn_b->rx_len >= 12)
                    break;
                struct timespec ts = { 0, 10 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            MCHECK(conn_b->rx_len == 12 &&
                   memcmp(conn_b->rx, "sv-conn-resp", 12) == 0);
        }
    }
    for (int i = 0; i < NWT; i++) {
        struct wtcase *w = &wt[i];
        uint64_t id = 0;
        bool got = raw_peer_wait_marker(rp, w->marker, &id, WIRE_MS);
        if (!got) {
            fprintf(stderr,
                    "LOSS block=%d dims=0x%02x wt%d bidi=%d fin=%d "
                    "inside_ready=%d completion=%d\n",
                    block, dims, i, (i % 2), (int)w->fin,
                    (int)w->inside_ready, w->m ? w->m->completion_ran : -1);
            g_failures++;
            continue;
        }
        if (w->fin) {
            /* a BIDI reaches the peer's SHUTDOWN_COMPLETE only once the
             * peer closes its own half too: FIN it back first */
            if ((i % 2) == 1)
                MCHECK(raw_peer_send_on_stream(rp, id, "", 0, true));
            raw_peer_stream_events_t evs;
            bool finok = raw_peer_wait_stream_terminal(rp, id, &evs,
                                                       WIRE_MS) &&
                         evs.saw_fin;
            if (!finok) {
                fprintf(stderr, "FIN-LOSS block=%d wt%d id=%llu\n", block,
                        i, (unsigned long long)id);
                g_failures++;
            }
        }
        /* issue-context proof: exactly one, in the declared context */
        MCHECK((w->inside_ready ? w->issued_inside : w->issued_outside) ==
               1);
    }
    if (dims & DIM_DGRAM)
        MCHECK(raw_peer_wait_datagram(rp, "mx-dgram\n", WIRE_MS));
    if ((dims & DIM_INBOUND) && inbound_id != UINT64_MAX) {
        __block bool got_in = false;
        for (int spin = 0; spin < WIRE_MS / 10 && !got_in; spin++) {
            dispatch_sync(q, ^{
              for (int i = 0; i < regp->n; i++)
                  if (regp->conns[i]->rx_len >= 5 &&
                      memcmp(regp->conns[i]->rx, "sv-in", 5) == 0)
                      got_in = true;
            });
            if (!got_in) {
                struct timespec ts = { 0, 10 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
        }
        MCHECK(got_in);
    }

    /* ---- rundown (lifecycle-valid) ---- */

    /* stop accepting: latch + queue barrier before the snapshot */
    dispatch_sync(q, ^{ regp->rundown = 1; });
    dispatch_sync(q, ^{ /* barrier: scheduled adoptions completed */ });
    MCHECK(!reg.overflow);

    bool teardown_ok = true;
    if (dims & DIM_CRITICALS)
        for (int i = 0; i < 3; i++)
            teardown_ok &= ms_shutdown(crit[i]);
    if (conn_b != NULL)
        teardown_ok &= ms_shutdown(conn_b);
    for (int i = 0; i < NWT; i++)
        teardown_ok &= ms_shutdown(wt[i].m);
    if (dg != NULL)
        teardown_ok &= ms_shutdown(dg);
    for (int i = 0; i < reg.n; i++)
        teardown_ok &= ms_shutdown(reg.conns[i]);

    if (!teardown_ok) {
        /* a child never reached CANCELLED: releasing the roots would be
         * a UAF — fail and deliberately retain everything */
        fprintf(stderr, "TEARDOWN-TIMEOUT block=%d: roots retained\n",
                block);
        g_failures++;
        *seq_io = seq;
        return g_failures - fail_base;
    }

    nw_connection_group_cancel(group);
    if (!wait_sem(ggone, WIRE_MS)) {
        fprintf(stderr, "GROUP-TERMINAL-TIMEOUT block=%d\n", block);
        g_failures++;
        *seq_io = seq;
        return g_failures - fail_base;
    }
    const char *why = NULL;
    if (raw_peer_failed(rp, &why)) {
        fprintf(stderr, "raw peer integrity failure: %s\n", why);
        g_failures++;
    }
    (void)raw_peer_stop(rp);
    dispatch_sync(q, ^{ /* final barrier */ });
    nw_release(group);
    dispatch_release(gready);
    dispatch_release(ggone);
    dispatch_release(q);
    dispatch_release(vq);
    *seq_io = seq;
    return g_failures - fail_base;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : getenv("WTQ_TEST_CERT_DIR");

    if (dir == NULL) {
        fprintf(stderr, "no cert dir\n");
        return 1;
    }
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);

    int blocks = 25;
    const char *b_env = getenv("WTQ_NW_MATRIX_REPS");
    if (b_env != NULL && atoi(b_env) > 0)
        blocks = atoi(b_env);
    unsigned dims = DIM_ALL;
    const char *d_env = getenv("WTQ_NW_MATRIX_DIMS");
    if (d_env != NULL)
        dims = (unsigned)strtoul(d_env, NULL, 0);

    int seq = 0;
    for (int blk = 0; blk < blocks; blk++) {
        run_block(blk, dims, &seq);
        if (g_failures > 0) {
            fprintf(stderr, "stopping at block %d (failures=%d)\n", blk,
                    g_failures);
            break;
        }
    }
    if (g_failures == 0)
        fprintf(stderr,
                "PASS test_nw_send_matrix (dims=0x%02x, %d blocks, zero "
                "loss)\n",
                dims, blocks);
    return g_failures == 0 ? 0 : 1;
}
