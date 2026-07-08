/*
 * Real-transport loopback: a wtquic server and client over MsQuic on
 * localhost, self-signed certs, ephemeral ports.
 *
 * The test follows the backend's confinement contract: all session
 * calls happen inside event callbacks (which run on MsQuic worker
 * threads); the main thread only waits on flags the callbacks set and
 * touches retained handles after wtq_msquic_env_close() has returned
 * (the documented synchronization point).
 *
 * Covered here: CONNECT establishment on both sides with subprotocol
 * negotiation, clean session close with code+reason travelling the
 * capsule, unknown-path refusal (404), exactly-once terminal events,
 * release-from-callback vs release-after-env-close, and sequential
 * connections through one listener.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

#include "test_support.h"

/* Generous: a loaded CI box under sanitizers can stall workers for
 * seconds; the deadline only matters on runs that are already failing. */
#define WAIT_SECS 30

/* One side's observed events, guarded for the main-thread waits. */
struct side {
    pthread_mutex_t mu;
    pthread_cond_t cv;

    int established;
    int refused;
    int failed;
    int closed;
    int stream_opened;

    char sub[64];
    size_t sub_len;
    size_t dgram_max;
    uint16_t refused_status;
    int failed_why;
    uint32_t closed_code;
    bool closed_clean;
    char closed_reason[64];
    size_t closed_reason_len;
    wtq_transport_error_t closed_err; /* record read inside on_closed */

    /* stream-path observations */
    uint8_t data[256];
    size_t data_len;
    size_t data_total;      /* uncapped byte count */
    int data_events;
    int fin_events;
    int stream_closed;
    int stream_reset;
    uint32_t last_reset_code;
    int stream_stop;
    uint32_t last_stop_code;
    int send_completions;
    int send_cancels;
    int would_blocks;
    wtq_result_t overflow_rc;

    /* datagram observations */
    int dgram_events;
    bool dgram_got_echo;    /* the ping payload came back */
    bool dgram_got_empty;   /* the zero-length datagram came back */
    size_t dgram_max_seen;
    wtq_result_t dgram_too_large_rc;
    wtq_result_t dgram_nodata_rc;
    wtq_result_t dgram_disabled_rc;
    int dgram_would_blocks;
    int dgram_accepted;

    /* behavior knobs (what to do from inside callbacks) */
    bool close_in_established;
    uint32_t close_code;
    const char *close_reason;
    bool release_in_closed;
    bool release_in_refused;
    bool ping_in_established;     /* open a bidi stream, send "ping"+FIN
                                     (heap payload freed at completion) */
    bool open_hold_in_established; /* open a bidi stream, small send,
                                      no FIN — keep the send side open */
    bool echo_on_fin;             /* reply "pong"+FIN from on_stream_data */
    bool close_on_fin;            /* close the session on a stream FIN */
    bool greet_on_open;           /* send a short payload on a peer
                                     stream's arrival (no FIN) */
    bool reset_on_data;           /* on stream data: queue a bulk send,
                                     reset the stream, close the session
                                     — the freshly queued send must
                                     cancel */
    uint32_t reset_code;
    bool stop_on_stream_opened;   /* stop the peer's stream on arrival */
    uint32_t stop_code;
    bool reset_on_stop;           /* answer on_stream_stop with a reset,
                                     then close the session */
    bool budget_probe;            /* two 600 KiB sends: second must
                                     block; a 64 KiB send between them
                                     must not */
    bool oversized_probe;         /* one send larger than the whole
                                     in-flight budget, plus FIN */
    wtq_result_t oversized_rc;
    wtq_result_t mid_rc;          /* the budget probe's 64 KiB send */
    int writable_events;          /* on_stream_writable deliveries */
    wtq_stream_t *budget_stream;  /* the probe's stream (live only) */
    wtq_result_t resend_rc;       /* the blocked send, retried on the
                                     writable edge */
    bool resent;
    bool close_after_send;        /* bulk send (no FIN), close session */
    bool dgram_ping_in_established; /* send a ping datagram, an empty
                                       one, and a too-large probe */
    bool dgram_expect_disabled;   /* record the unavailable behavior */
    bool dgram_flood_in_established; /* send past the in-flight cap,
                                        then close with sends pending */
    bool dgram_echo;              /* echo every datagram back */
    bool close_when_dgrams_back;  /* close once echo+empty both seen */
    bool pause_before_ping;       /* pause the bidi stream's receive
                                     side before sending the ping */
    bool resume_on_send_complete; /* resume the paused stream when the
                                     ping's completion arrives */
    bool close_in_send_complete;  /* close the session instead */
    bool echo_big_on_fin;         /* answer a stream FIN with a large
                                     (600 KiB) response */
    wtq_result_t pause_rc;
    wtq_result_t resume_rc;
    size_t data_at_resume;        /* bytes delivered before the resume */
    wtq_stream_t *held;           /* the paused stream (live only) */

    wtq_session_t *session; /* server: seen in callbacks; client: ours */
};

/* Static payloads for the budget probe (static lifetime, so the
 * borrow-until-completion contract is trivially honored): two 600 KiB
 * spans whose sum exceeds the 1 MiB floor, and a 64 KiB span that must
 * ride along un-blocked — media-sized writes must not serialize at one
 * full-ACK cycle each. */
static uint8_t budget_a[600 * 1024];
static uint8_t budget_b[600 * 1024];
static uint8_t budget_c[64 * 1024];
static uint8_t bulk_payload[32 * 1024];
/* several times the in-flight budget floor, for the forward-progress
 * probe */
static uint8_t oversized_payload[3 * 1024 * 1024];

static void side_init(struct side *sd)
{
    memset(sd, 0, sizeof(*sd));
    pthread_mutex_init(&sd->mu, NULL);
    pthread_cond_init(&sd->cv, NULL);
}

static void side_destroy(struct side *sd)
{
    pthread_mutex_destroy(&sd->mu);
    pthread_cond_destroy(&sd->cv);
}

static void side_signal(struct side *sd)
{
    pthread_cond_broadcast(&sd->cv);
}

/* Wait until *flag is nonzero (returns false on timeout). */
static bool side_wait(struct side *sd, const int *flag)
{
    struct timespec deadline;
    bool ok = true;
    bool set;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += WAIT_SECS;
    pthread_mutex_lock(&sd->mu);
    while (*flag == 0 && ok)
        ok = pthread_cond_timedwait(&sd->cv, &sd->mu, &deadline) == 0;
    set = *flag != 0;
    pthread_mutex_unlock(&sd->mu);
    return set;
}

/* --- callbacks (MsQuic worker context) ------------------------------------ */

static void cb_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    struct side *sd = user;

    pthread_mutex_lock(&sd->mu);
    sd->established++;
    sd->session = s;
    sd->sub_len = sub.len < sizeof(sd->sub) ? sub.len : 0;
    if (sd->sub_len > 0)
        memcpy(sd->sub, sub.data, sd->sub_len);
    /* datagram availability is settled by establishment time */
    sd->dgram_max = wtq_session_datagram_max_size(s);
    pthread_mutex_unlock(&sd->mu);

    if (sd->ping_in_established) {
        wtq_stream_t *st = NULL;

        if (wtq_session_open_bidi(s, &st) == WTQ_OK) {
            if (sd->pause_before_ping) {
                /* pausing before the ping even goes out guarantees the
                 * response cannot have been delivered yet */
                pthread_mutex_lock(&sd->mu);
                sd->pause_rc = wtq_stream_pause_receive(st);
                sd->held = st;
                pthread_mutex_unlock(&sd->mu);
            }
            /* heap payload, released in on_send_complete: under ASan
             * this pins that the data is not read after its legal
             * release point */
            char *ping = malloc(4);
            memcpy(ping, "ping", 4);
            wtq_span_t span = { (const uint8_t *)ping, 4 };
            if (wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, ping) !=
                WTQ_OK)
                free(ping);
        }
    }
    if (sd->open_hold_in_established) {
        wtq_stream_t *st = NULL;

        if (wtq_session_open_bidi(s, &st) == WTQ_OK) {
            static const uint8_t hello[5] = { 'h', 'e', 'l', 'l', 'o' };
            wtq_span_t span = { hello, sizeof(hello) };

            (void)wtq_stream_send(st, &span, 1, 0, NULL);
        }
    }
    if (sd->close_after_send) {
        wtq_stream_t *st = NULL;

        if (wtq_session_open_bidi(s, &st) == WTQ_OK) {
            wtq_span_t span = { bulk_payload, sizeof(bulk_payload) };
            (void)wtq_stream_send(st, &span, 1, 0, NULL);
            (void)wtq_session_close(s, 0, NULL, 0);
        }
    }
    if (sd->budget_probe) {
        wtq_stream_t *st = NULL;

        if (wtq_session_open_bidi(s, &st) == WTQ_OK) {
            wtq_span_t a = { budget_a, sizeof(budget_a) };
            wtq_span_t b = { budget_b, sizeof(budget_b) };

            /* a span count beyond the DOCUMENTED cap (stream.h:
             * WTQ_STREAM_MAX_SPANS) is refused before anything reads
             * past the array — the short array is legal exactly
             * because rejection precedes traversal */
            pthread_mutex_lock(&sd->mu);
            sd->overflow_rc = wtq_stream_send(
                st, &a, (size_t)WTQ_STREAM_MAX_SPANS + 1, 0, NULL);
            pthread_mutex_unlock(&sd->mu);

            wtq_span_t mid = { budget_c, sizeof(budget_c) };
            wtq_result_t rc1 = wtq_stream_send(st, &a, 1, 0, NULL);
            /* a small send behind un-ACKed bytes still fits the
             * budget: the floor exists so writes like this pipeline
             * instead of serializing on the first send's full ACK */
            wtq_result_t rcm = wtq_stream_send(st, &mid, 1, 0, NULL);
            wtq_result_t rc2 = wtq_stream_send(st, &b, 1, 0, NULL);

            pthread_mutex_lock(&sd->mu);
            sd->mid_rc = rcm;
            sd->budget_stream = st;
            if (rc2 == WTQ_ERR_WOULD_BLOCK)
                sd->would_blocks++;
            pthread_mutex_unlock(&sd->mu);
            (void)rc1;
            /* the refused send is retried from the writable edge; the
             * FIN follows it there (see cb_stream_writable) */
        }
    }
    if (sd->oversized_probe) {
        wtq_stream_t *st = NULL;

        if (wtq_session_open_bidi(s, &st) == WTQ_OK) {
            wtq_span_t big = { oversized_payload,
                               sizeof(oversized_payload) };

            /* the budget is a queue-depth throttle, not a size cap: an
             * idle stream must admit one legal send of any size — a
             * refused send has no completion, so nothing would ever
             * wake a retry */
            pthread_mutex_lock(&sd->mu);
            sd->oversized_rc =
                wtq_stream_send(st, &big, 1, WTQ_SEND_FIN, NULL);
            pthread_mutex_unlock(&sd->mu);
        }
    }
    if (sd->dgram_ping_in_established) {
        static const uint8_t dping[7] = { 'd', 'g', '-', 'p', 'i',
                                          'n', 'g' };
        wtq_span_t span = { dping, sizeof(dping) };
        size_t max = wtq_session_datagram_max_size(s);

        pthread_mutex_lock(&sd->mu);
        sd->dgram_max_seen = max;
        /* over the current limit by one byte: refused before the
         * transport is involved. The span carries REAL bytes — a
         * nonempty span without data is INVALID_ARG by contract now,
         * checked before any size comparison. */
        uint8_t *big = malloc(max + 1);
        if (big != NULL) {
            memset(big, 'x', max + 1);
            wtq_span_t huge = { big, max + 1 };
            sd->dgram_too_large_rc = wtq_session_send_datagram(s, &huge, 1);
            free(big);
        }
        /* and the contract itself: nonempty span, no data */
        wtq_span_t nodata = { NULL, 1 };
        sd->dgram_nodata_rc = wtq_session_send_datagram(s, &nodata, 1);
        pthread_mutex_unlock(&sd->mu);

        (void)wtq_session_send_datagram(s, &span, 1);
        (void)wtq_session_send_datagram(s, NULL, 0); /* empty datagram */
    }
    if (sd->dgram_expect_disabled) {
        static const uint8_t d[2] = { 'n', 'o' };
        wtq_span_t span = { d, sizeof(d) };

        pthread_mutex_lock(&sd->mu);
        sd->dgram_max_seen = wtq_session_datagram_max_size(s);
        sd->dgram_disabled_rc = wtq_session_send_datagram(s, &span, 1);
        pthread_mutex_unlock(&sd->mu);
        (void)wtq_session_close(s, 0, NULL, 0);
    }
    if (sd->dgram_flood_in_established) {
        static const uint8_t d[8] = { 'f', 'l', 'o', 'o', 'd', '.',
                                      '.', '.' };
        wtq_span_t span = { d, sizeof(d) };

        pthread_mutex_lock(&sd->mu);
        for (int i = 0; i < 65; i++) {
            wtq_result_t rc = wtq_session_send_datagram(s, &span, 1);

            if (rc == WTQ_OK)
                sd->dgram_accepted++;
            else if (rc == WTQ_ERR_WOULD_BLOCK)
                sd->dgram_would_blocks++;
        }
        pthread_mutex_unlock(&sd->mu);
        /* close with datagram sends still pending: their records must
         * finalize (canceled) without leak or double free */
        (void)wtq_session_close(s, 0, NULL, 0);
    }
    if (sd->close_in_established) {
        const char *r = sd->close_reason != NULL ? sd->close_reason : "";
        (void)wtq_session_close(s, sd->close_code, (const uint8_t *)r,
                                strlen(r));
    }
    pthread_mutex_lock(&sd->mu);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_refused(wtq_session_t *s, uint16_t status, void *user)
{
    struct side *sd = user;

    pthread_mutex_lock(&sd->mu);
    sd->refused++;
    sd->refused_status = status;
    pthread_mutex_unlock(&sd->mu);

    if (sd->release_in_refused)
        wtq_session_release(s);

    pthread_mutex_lock(&sd->mu);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->failed++;
    sd->failed_why = (int)why;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t rlen, bool clean,
                      void *user)
{
    struct side *sd = user;

    pthread_mutex_lock(&sd->mu);
    sd->closed++;
    sd->closed_code = code;
    sd->closed_clean = clean;
    memset(&sd->closed_err, 0, sizeof(sd->closed_err));
    sd->closed_err.struct_size = (uint32_t)sizeof(sd->closed_err);
    (void)wtq_session_transport_error(s, &sd->closed_err);
    sd->closed_reason_len = rlen < sizeof(sd->closed_reason) ? rlen : 0;
    if (sd->closed_reason_len > 0)
        memcpy(sd->closed_reason, reason, sd->closed_reason_len);
    pthread_mutex_unlock(&sd->mu);

    if (sd->release_in_closed)
        wtq_session_release(s);

    pthread_mutex_lock(&sd->mu);
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                             bool bidi, void *user)
{
    struct side *sd = user;

    (void)s;
    (void)bidi;
    pthread_mutex_lock(&sd->mu);
    sd->stream_opened++;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (sd->stop_on_stream_opened)
        (void)wtq_stream_stop_sending(st, sd->stop_code);
    if (sd->greet_on_open) {
        static const uint8_t go[2] = { 'g', 'o' };
        wtq_span_t span = { go, sizeof(go) };

        (void)wtq_stream_send(st, &span, 1, 0, NULL);
    }
}

static void cb_stream_data(wtq_session_t *s, wtq_stream_t *st,
                           const uint8_t *data, size_t len, bool fin,
                           void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->data_events++;
    sd->data_total += len;
    if (len > 0 && sd->data_len + len <= sizeof(sd->data)) {
        memcpy(sd->data + sd->data_len, data, len);
        sd->data_len += len;
    }
    if (fin)
        sd->fin_events++;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (fin && sd->echo_big_on_fin && wtq_stream_is_bidi(st)) {
        wtq_span_t span = { budget_a, sizeof(budget_a) };

        (void)wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL);
    }
    if (fin && sd->echo_on_fin && wtq_stream_is_bidi(st)) {
        static const uint8_t pong[4] = { 'p', 'o', 'n', 'g' };
        wtq_span_t span = { pong, sizeof(pong) };

        (void)wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL);
    }
    if (sd->reset_on_data) {
        /* the peer demonstrably knows this stream (it just wrote to
         * it), so the reset is observable there; the bulk send queued
         * in the same batch cannot be acknowledged before the abort
         * processes and must complete canceled */
        wtq_span_t span = { bulk_payload, sizeof(bulk_payload) };

        (void)wtq_stream_send(st, &span, 1, 0, NULL);
        (void)wtq_stream_reset(st, sd->reset_code);
        (void)wtq_session_close(s, 0, NULL, 0);
    }
    if (fin && sd->close_on_fin)
        (void)wtq_session_close(s, sd->close_code, NULL, 0);
}

static void cb_stream_reset(wtq_session_t *s, wtq_stream_t *st,
                            uint32_t code, void *user)
{
    struct side *sd = user;

    (void)s;
    (void)st;
    pthread_mutex_lock(&sd->mu);
    sd->stream_reset++;
    sd->last_reset_code = code;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_stream_stop(wtq_session_t *s, wtq_stream_t *st,
                           uint32_t code, void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->stream_stop++;
    sd->last_stop_code = code;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (sd->reset_on_stop) {
        (void)wtq_stream_reset(st, sd->reset_code);
        (void)wtq_session_close(s, 0, NULL, 0);
    }
}

static void cb_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    struct side *sd = user;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->stream_closed++;
    if (sd->held == st)
        sd->held = NULL; /* the un-retained handle dies with this */
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);
}

static void cb_send_complete(wtq_session_t *s, void *send_ctx,
                             bool canceled, void *user)
{
    struct side *sd = user;
    wtq_stream_t *held;

    pthread_mutex_lock(&sd->mu);
    sd->send_completions++;
    if (canceled)
        sd->send_cancels++;
    sd->data_at_resume = sd->data_total;
    held = sd->held;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (sd->resume_on_send_complete && held != NULL) {
        pthread_mutex_lock(&sd->mu);
        sd->resume_rc = wtq_stream_resume_receive(held);
        pthread_mutex_unlock(&sd->mu);
    }
    if (sd->close_in_send_complete)
        (void)wtq_session_close(s, 0, NULL, 0);

    /* the completion is the legal release point for the send's data */
    free(send_ctx);
}

static void cb_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    struct side *sd = user;
    bool both;

    pthread_mutex_lock(&sd->mu);
    sd->dgram_events++;
    if (len == 7 && memcmp(data, "dg-ping", 7) == 0)
        sd->dgram_got_echo = true;
    if (len == 0)
        sd->dgram_got_empty = true;
    both = sd->dgram_got_echo && sd->dgram_got_empty;
    side_signal(sd);
    pthread_mutex_unlock(&sd->mu);

    if (sd->dgram_echo && len <= 64) {
        wtq_span_t span = { data, len };

        /* borrow-during-call both ways: re-sending the borrowed
         * receive buffer from inside the callback is legal */
        (void)wtq_session_send_datagram(s, &span, len > 0 ? 1 : 0);
    }
    if (sd->close_when_dgrams_back && both)
        (void)wtq_session_close(s, 0, NULL, 0);
}

static void cb_stream_writable(wtq_session_t *s, wtq_stream_t *st,
                               void *user)
{
    struct side *sd = user;
    bool retry = false;

    (void)s;
    pthread_mutex_lock(&sd->mu);
    sd->writable_events++;
    if (st == sd->budget_stream && !sd->resent)
        retry = true;
    pthread_mutex_unlock(&sd->mu);
    if (retry) {
        /* retry from inside the writable callback itself — the edge
         * re-arms if this still does not fit (an early edge can come
         * from ideal-size growth before enough budget freed), and a
         * later edge retries again; on success the stream finishes */
        wtq_span_t b = { budget_b, sizeof(budget_b) };
        wtq_result_t rc = wtq_stream_send(st, &b, 1, 0, NULL);

        pthread_mutex_lock(&sd->mu);
        sd->resend_rc = rc;
        if (rc == WTQ_OK)
            sd->resent = true;
        pthread_mutex_unlock(&sd->mu);
        if (rc == WTQ_OK)
            (void)wtq_stream_send(st, NULL, 0, WTQ_SEND_FIN, NULL);
    }
}

static void events_for(wtq_session_events_t *ev)
{
    wtq_session_events_init(ev);
    ev->on_established = cb_established;
    ev->on_refused = cb_refused;
    ev->on_failed = cb_failed;
    ev->on_closed = cb_closed;
    ev->on_stream_opened = cb_stream_opened;
    ev->on_stream_data = cb_stream_data;
    ev->on_stream_reset = cb_stream_reset;
    ev->on_stream_stop = cb_stream_stop;
    ev->on_stream_closed = cb_stream_closed;
    ev->on_send_complete = cb_send_complete;
    ev->on_datagram = cb_datagram;
    ev->on_stream_writable = cb_stream_writable;
}

/* --- fixtures -------------------------------------------------------------- */

static char cert_path[512];
static char key_path[512];

static int certs_locate(const char *argv1)
{
    const char *dir = argv1;

    if (dir == NULL)
        dir = getenv("WTQ_TEST_CERT_DIR");
    if (dir == NULL) {
        fprintf(stderr,
                "no cert dir: set WTQ_TEST_CERT_DIR or pass it as the "
                "first argument (see scripts/gen_test_certs.sh)\n");
        return -1;
    }
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    FILE *f = fopen(cert_path, "r");
    if (f == NULL) {
        fprintf(stderr, "missing %s\n", cert_path);
        return -1;
    }
    fclose(f);
    return 0;
}

static wtq_result_t listener_up(wtq_msquic_env_t *env, struct side *sd,
                                const char *path,
                                wtq_msquic_listener_t **l_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    wtq_msquic_listener_cfg_t cfg = WTQ_MSQUIC_LISTENER_CFG_INIT;

    events_for(&ev);
    serve.path = path;
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;

    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.cert_file = cert_path;
    cfg.key_file = key_path;
    cfg.paths = &serve;
    cfg.path_count = 1;
    cfg.events = &ev;
    cfg.user = sd;
    return wtq_msquic_listener_start(env, &cfg, l_out);
}

static wtq_result_t client_up(wtq_msquic_env_t *env, struct side *sd,
                              uint16_t port, const char *path,
                              wtq_session_t **s_out)
{
    static const char *const protos[] = { "wtq-test" };
    wtq_session_events_t ev;
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;

    events_for(&ev);
    connect.authority = "localhost";
    connect.path = path;
    connect.subprotocols = protos;
    connect.subprotocol_count = 1;

    cfg.server_name = "127.0.0.1";
    cfg.port = port;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &ev;
    cfg.user = sd;
    return wtq_msquic_client_connect(env, &cfg, s_out);
}

/* --- subtests --------------------------------------------------------------- */

/*
 * Establish on both sides (with subprotocol negotiation), close cleanly
 * from the client callback with a code and reason, observe the capsule
 * on the server, tear down with release-from-callback on both sides.
 */
static int t_handshake_close(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    wtq_msquic_listener_t *listener = NULL;
    struct side sv, cl;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    side_init(&cl);
    cl.close_in_established = true;
    cl.close_code = 7;
    cl.close_reason = "bye";
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(listener_up(env, &sv, "/echo", &listener),
                          WTQ_OK);
    if (env == NULL || listener == NULL)
        goto out;

    uint16_t port = wtq_msquic_listener_port(listener);
    WTQ_TEST_CHECK(port != 0);

    WTQ_TEST_CHECK_EQ_INT(client_up(env, &cl, port, "/echo", &cs),
                          WTQ_OK);
    WTQ_TEST_CHECK(cs != NULL);

    WTQ_TEST_CHECK(side_wait(&cl, &cl.established));
    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));

    wtq_msquic_listener_stop(listener);
    listener = NULL;
    wtq_msquic_env_close(env);
    env = NULL;

    /* exactly-once terminals, on both sides */
    WTQ_TEST_CHECK_EQ_INT(cl.established, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.established, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.closed, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.refused + cl.failed, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.refused + sv.failed, 0);

    /* negotiated subprotocol visible on both sides */
    WTQ_TEST_CHECK_EQ_SIZE(cl.sub_len, strlen("wtq-test"));
    WTQ_TEST_CHECK(memcmp(cl.sub, "wtq-test", cl.sub_len) == 0);
    WTQ_TEST_CHECK_EQ_SIZE(sv.sub_len, strlen("wtq-test"));

    /* datagram capacity is negotiated and visible at establishment */
    WTQ_TEST_CHECK(cl.dgram_max > 0);

    /* clean close with the capsule's code+reason on both sides */
    WTQ_TEST_CHECK(cl.closed_clean);
    WTQ_TEST_CHECK_EQ_U64(cl.closed_code, 7);
    WTQ_TEST_CHECK(sv.closed_clean);
    WTQ_TEST_CHECK_EQ_U64(sv.closed_code, 7);
    /* a CLEAN close has no transport cause: the record was sealed NONE
     * at the terminal, and the connection's routine retirement (cleanup
     * shutdown / peer connection close) must not change it */
    WTQ_TEST_CHECK_EQ_INT((int)cl.closed_err.kind,
                          (int)WTQ_ERR_KIND_NONE);
    WTQ_TEST_CHECK_EQ_INT((int)sv.closed_err.kind,
                          (int)WTQ_ERR_KIND_NONE);
    WTQ_TEST_CHECK_EQ_SIZE(sv.closed_reason_len, 3);
    WTQ_TEST_CHECK(memcmp(sv.closed_reason, "bye", 3) == 0);

out:
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (env != NULL)
        wtq_msquic_env_close(env);
    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: handshake_close\n");
    return failures;
}

/* A CONNECT to a path the server does not serve is refused with 404;
 * the client's terminal is on_refused, the server never establishes. */
static int t_unknown_path_404(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    wtq_msquic_listener_t *listener = NULL;
    struct side sv, cl;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    side_init(&cl);
    cl.release_in_refused = true;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(listener_up(env, &sv, "/echo", &listener),
                          WTQ_OK);
    if (env == NULL || listener == NULL)
        goto out;

    WTQ_TEST_CHECK_EQ_INT(client_up(env, &cl,
                                    wtq_msquic_listener_port(listener),
                                    "/nope", &cs),
                          WTQ_OK);

    WTQ_TEST_CHECK(side_wait(&cl, &cl.refused));

    wtq_msquic_listener_stop(listener);
    listener = NULL;
    wtq_msquic_env_close(env);
    env = NULL;

    WTQ_TEST_CHECK_EQ_INT(cl.refused, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.refused_status, 404);
    WTQ_TEST_CHECK_EQ_INT(cl.established, 0);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.established, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.closed, 0);
    /* the server session never establishes; its terminal is the
     * connection failure when the refused client tears down */
    WTQ_TEST_CHECK_EQ_INT(sv.failed, 1);

out:
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (env != NULL)
        wtq_msquic_env_close(env);
    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: unknown_path_404\n");
    return failures;
}

/*
 * Retain the client session past its terminal: no release from
 * callbacks; after env close the handle is dead-but-valid (queries
 * work, operations report closed) and the final release is legal from
 * the main thread.
 */
static int t_release_after_env_close(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    wtq_msquic_listener_t *listener = NULL;
    struct side sv, cl;
    wtq_session_t *cs = NULL;

    side_init(&sv);
    side_init(&cl);
    cl.close_in_established = true;
    cl.close_code = 0;
    cl.close_reason = NULL;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(listener_up(env, &sv, "/echo", &listener),
                          WTQ_OK);
    if (env == NULL || listener == NULL)
        goto out;

    WTQ_TEST_CHECK_EQ_INT(client_up(env, &cl,
                                    wtq_msquic_listener_port(listener),
                                    "/echo", &cs),
                          WTQ_OK);
    WTQ_TEST_CHECK(cs != NULL);

    WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
    WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));

    wtq_msquic_listener_stop(listener);
    listener = NULL;
    wtq_msquic_env_close(env);
    env = NULL;

    /* dead-but-valid: queries work, operations report closed */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_status(cs),
                          WTQ_SESSION_STATUS_CLOSED);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_close(cs, 1, NULL, 0),
                          WTQ_ERR_CLOSED);
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(cs, &st), WTQ_ERR_CLOSED);
    wtq_session_release(cs);
    cs = NULL;

out:
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (env != NULL)
        wtq_msquic_env_close(env);
    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: release_after_env_close\n");
    return failures;
}

/* Several sequential connections through one listener and one env:
 * shakes teardown ordering (close-once, session release, stream sweep)
 * under repetition. */
static int t_sequential_conns(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    wtq_msquic_listener_t *listener = NULL;
    struct side sv;

    side_init(&sv);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(listener_up(env, &sv, "/echo", &listener),
                          WTQ_OK);
    if (env == NULL || listener == NULL)
        goto out;
    uint16_t port = wtq_msquic_listener_port(listener);

    for (int i = 0; i < 3; i++) {
        struct side cl;
        wtq_session_t *cs = NULL;

        side_init(&cl);
        cl.close_in_established = true;
        cl.close_code = (uint32_t)(100 + i);
        cl.close_reason = "next";
        cl.release_in_closed = true;

        WTQ_TEST_CHECK_EQ_INT(client_up(env, &cl, port, "/echo", &cs),
                              WTQ_OK);
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK_EQ_INT(cl.established, 1);
        WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
        WTQ_TEST_CHECK_EQ_U64(cl.closed_code, 100 + i);
        side_destroy(&cl);
    }

    wtq_msquic_listener_stop(listener);
    listener = NULL;
    wtq_msquic_env_close(env);
    env = NULL;
    WTQ_TEST_CHECK_EQ_INT(sv.established, 3);
    WTQ_TEST_CHECK_EQ_INT(sv.closed, 3);

out:
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (env != NULL)
        wtq_msquic_env_close(env);
    side_destroy(&sv);
    if (failures == 0)
        printf("PASS: sequential_conns\n");
    return failures;
}

/* Shared bring-up for the stream subtests: env, one listener on /echo,
 * one client with the given knobs already set. */
static wtq_result_t pair_up(struct side *sv, struct side *cl,
                            wtq_msquic_env_t **env_out,
                            wtq_msquic_listener_t **l_out,
                            wtq_session_t **cs_out)
{
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_result_t rc;

    *env_out = NULL;
    *l_out = NULL;
    *cs_out = NULL;
    rc = wtq_msquic_env_open(&ecfg, env_out);
    if (rc != WTQ_OK)
        return rc;
    rc = listener_up(*env_out, sv, "/echo", l_out);
    if (rc != WTQ_OK)
        return rc;
    return client_up(*env_out, cl, wtq_msquic_listener_port(*l_out),
                     "/echo", cs_out);
}

static void pair_down(wtq_msquic_env_t *env, wtq_msquic_listener_t *l)
{
    if (l != NULL)
        wtq_msquic_listener_stop(l);
    if (env != NULL)
        wtq_msquic_env_close(env);
}

/*
 * The WebTransport data path end to end: client opens a bidi stream and
 * sends ping+FIN (heap payload, freed at its completion); the server
 * sees the payload with the association preamble already stripped and
 * echoes pong+FIN from inside its data callback; the client closes the
 * session on the pong. Every accepted send completes exactly once,
 * nothing cancels, both sides observe the stream's terminal.
 */
static int t_bidi_pingpong(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.echo_on_fin = true;
    cl.ping_in_established = true;
    cl.close_on_fin = true;
    cl.close_code = 11;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    /* payloads, both directions, preamble stripped */
    WTQ_TEST_CHECK_EQ_SIZE(sv.data_len, 4);
    WTQ_TEST_CHECK(memcmp(sv.data, "ping", 4) == 0);
    WTQ_TEST_CHECK_EQ_INT(sv.fin_events, 1);
    WTQ_TEST_CHECK_EQ_SIZE(cl.data_len, 4);
    WTQ_TEST_CHECK(memcmp(cl.data, "pong", 4) == 0);
    WTQ_TEST_CHECK_EQ_INT(cl.fin_events, 1);

    /* exactly one completion per accepted send, none canceled */
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_cancels, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.send_cancels, 0);

    /* stream terminals on both sides; clean session close after */
    WTQ_TEST_CHECK_EQ_INT(cl.stream_closed, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.stream_closed, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.stream_opened, 1);
    WTQ_TEST_CHECK(cl.closed_clean);
    WTQ_TEST_CHECK_EQ_U64(cl.closed_code, 11);
    WTQ_TEST_CHECK(sv.closed_clean);
    WTQ_TEST_CHECK_EQ_U64(sv.closed_code, 11);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: bidi_pingpong\n");
    return failures;
}

/* The per-stream in-flight budget bounds what wtquic hands MsQuic: a
 * second 600 KiB send while the first is unacknowledged overflows the
 * 1 MiB floor and reports WOULD_BLOCK — never accepted, no completion
 * — while a 64 KiB send in the same window is admitted (the floor
 * throttles depth without serializing media-sized writes). The refused
 * send then progresses WITHOUT any application timer: the completion
 * that releases budget delivers on_stream_writable, the retry from
 * inside that callback succeeds, and the stream finishes. */
static int t_send_budget(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    cl.budget_probe = true;
    cl.close_on_fin = false;
    cl.release_in_closed = true;
    sv.close_on_fin = true; /* server closes once the stream finishes */
    sv.close_code = 0;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK_EQ_INT(cl.would_blocks, 1);
    /* the absurd span count was refused; the 600 KiB send, the 64 KiB
     * rider, the writable-driven retry and the empty FIN completed;
     * the refused sends produced no completion */
    WTQ_TEST_CHECK_EQ_INT(cl.overflow_rc, WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(cl.mid_rc, WTQ_OK);
    /* each refusal (the probe's and every re-blocked retry) arms one
     * edge and each edge is delivered once — ideal-growth edges can
     * arrive before enough budget freed, so the exact count is
     * timing-dependent. What is pinned: the edge fired, and the retry
     * ultimately succeeded with no application timer involved. */
    WTQ_TEST_CHECK(cl.writable_events >= 1);
    WTQ_TEST_CHECK_EQ_INT(cl.resend_rc, WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 4);
    WTQ_TEST_CHECK_EQ_INT(cl.send_cancels, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.fin_events, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: send_budget\n");
    return failures;
}

/*
 * Forward progress for a send larger than the whole in-flight budget:
 * the budget bounds queued depth behind in-flight bytes, it is not a
 * maximum legal write size. One oversized send on an idle stream must
 * be accepted (all-or-nothing, exactly one completion) and delivered
 * in full; a refusal would be a deadlock, since a send that was never
 * accepted has no completion to wake a retry.
 */
static int t_oversized_send(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    cl.oversized_probe = true;
    cl.close_on_fin = false;
    cl.release_in_closed = true;
    sv.close_on_fin = true; /* server closes once the stream finishes */
    sv.close_code = 0;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK_EQ_INT(cl.oversized_rc, WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_cancels, 0);
    WTQ_TEST_CHECK_EQ_INT(sv.fin_events, 1);
    WTQ_TEST_CHECK_EQ_INT((int)sv.data_total,
                          (int)sizeof(oversized_payload));

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: oversized_send\n");
    return failures;
}

/*
 * Reset with a send in flight, on a stream the peer has demonstrably
 * associated (it wrote to it first — a reset racing the association
 * preamble may legally erase the stream unseen; RESET_STREAM_AT is what
 * would fix that, and MsQuic cannot negotiate it). The freshly queued
 * bulk send completes exactly once with canceled=true, and the peer
 * observes the reset with the application code carried through the
 * wire mapping.
 */
static int t_reset_cancels(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.greet_on_open = true;
    cl.open_hold_in_established = true;
    cl.reset_on_data = true;
    cl.reset_code = 42;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&sv, &sv.stream_reset));
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK_EQ_INT(sv.stream_reset, 1);
    WTQ_TEST_CHECK_EQ_U64(sv.last_reset_code, 42);
    /* the hello send (long since acknowledged) and the bulk send (just
     * queued, killed by the reset) each completed exactly once */
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 2);
    WTQ_TEST_CHECK_EQ_INT(cl.send_cancels, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: reset_cancels\n");
    return failures;
}

/* STOP_SENDING mapping: the server stops the client's stream on
 * arrival; the client observes on_stream_stop with the code and answers
 * with a reset, then closes. */
static int t_stop_mapping(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.stop_on_stream_opened = true;
    sv.stop_code = 7;
    cl.open_hold_in_established = true;
    cl.reset_on_stop = true;
    cl.reset_code = 9;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.stream_stop));
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK_EQ_INT(cl.stream_stop, 1);
    WTQ_TEST_CHECK_EQ_U64(cl.last_stop_code, 7);
    /* both sides reach the stream terminal exactly once, and the held
     * send completed exactly once (ACKed or canceled by the race
     * between its ACK and the answering reset) */
    WTQ_TEST_CHECK_EQ_INT(cl.stream_closed, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.stream_closed, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: stop_mapping\n");
    return failures;
}

/* Session close with a send still in flight: the teardown resets the
 * stream, the pending send completes exactly once with canceled=true,
 * and the completion still arrives after the terminal event. */
static int t_close_cancels(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    cl.close_after_send = true;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&cl, &cl.send_completions));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_cancels, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.stream_closed, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: close_cancels\n");
    return failures;
}

/*
 * WebTransport datagrams both directions over real MsQuic: the client
 * sends a ping datagram and an empty one (plus a refused too-large
 * probe); the server echoes each back; the client closes once both
 * echoes arrived. The association prefix travels invisibly.
 */
static int t_datagram_echo(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.dgram_echo = true;
    cl.dgram_ping_in_established = true;
    cl.close_when_dgrams_back = true;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    WTQ_TEST_CHECK(cl.dgram_max_seen > 0);
    WTQ_TEST_CHECK_EQ_INT(cl.dgram_too_large_rc, WTQ_ERR_TOO_LARGE);
    WTQ_TEST_CHECK_EQ_INT(cl.dgram_nodata_rc, WTQ_ERR_INVALID_ARG);
    /* the server saw both datagrams (payload and empty) and echoed
     * them; the client got both back */
    WTQ_TEST_CHECK_EQ_INT(sv.dgram_events, 2);
    WTQ_TEST_CHECK(sv.dgram_got_echo);
    WTQ_TEST_CHECK(sv.dgram_got_empty);
    WTQ_TEST_CHECK(cl.dgram_got_echo);
    WTQ_TEST_CHECK(cl.dgram_got_empty);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: datagram_echo\n");
    return failures;
}

/* Send past the in-flight cap in one callback: the surplus reports
 * WOULD_BLOCK, and closing with sends still pending finalizes every
 * record (canceled) without leak or double free. */
static int t_datagram_flood_close(void)
{
    int failures = 0;
    wtq_msquic_env_t *env;
    wtq_msquic_listener_t *listener;
    wtq_session_t *cs;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    cl.dgram_flood_in_established = true;
    cl.release_in_closed = true;

    WTQ_TEST_CHECK_EQ_INT(pair_up(&sv, &cl, &env, &listener, &cs),
                          WTQ_OK);
    if (cs != NULL) {
        WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
        WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
    }
    pair_down(env, listener);

    /* the cap admits exactly its size in one batch (no state-change
     * event can interleave a running callback) */
    WTQ_TEST_CHECK_EQ_INT(cl.dgram_accepted, 64);
    WTQ_TEST_CHECK_EQ_INT(cl.dgram_would_blocks, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: datagram_flood_close\n");
    return failures;
}

/*
 * A peer that does not accept QUIC datagrams (receive disabled in its
 * transport tuning) leaves our send side unavailable: max size 0 and
 * sends report WTQ_ERR_DGRAM_DISABLED. The session itself still
 * establishes — the engine negotiates on the HTTP/3 SETTINGS layer.
 */
static int t_datagram_unavailable(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t server_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_cfg_t client_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    wtq_msquic_env_t *cenv = NULL;
    wtq_msquic_listener_t *listener = NULL;
    wtq_session_t *cs = NULL;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    cl.dgram_expect_disabled = true;
    cl.release_in_closed = true;

    server_ecfg.tuning.datagram_receive_enabled = false;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&server_ecfg, &senv),
                          WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&client_ecfg, &cenv),
                          WTQ_OK);
    if (senv != NULL && cenv != NULL) {
        WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sv, "/echo", &listener),
                              WTQ_OK);
        if (listener != NULL) {
            WTQ_TEST_CHECK_EQ_INT(
                client_up(cenv, &cl, wtq_msquic_listener_port(listener),
                          "/echo", &cs),
                WTQ_OK);
            if (cs != NULL) {
                WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
                WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
            }
        }
    }
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (senv != NULL)
        wtq_msquic_env_close(senv);
    if (cenv != NULL)
        wtq_msquic_env_close(cenv);

    WTQ_TEST_CHECK_EQ_INT(cl.established, 1);
    WTQ_TEST_CHECK_EQ_SIZE(cl.dgram_max_seen, 0);
    WTQ_TEST_CHECK_EQ_INT(cl.dgram_disabled_rc, WTQ_ERR_DGRAM_DISABLED);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: datagram_unavailable\n");
    return failures;
}

/*
 * Receive backpressure end to end. The client pauses its bidi stream's
 * receive side BEFORE the ping goes out, so not one byte of the large
 * response can be delivered while paused (the pause is queued ahead of
 * the send on the same worker); the client's receive window is shrunk
 * to 16 KiB so the transport demonstrably withholds most of the
 * response at the wire. The ping's own completion is the resume
 * trigger; afterwards the full response and its FIN arrive in order
 * and the session closes cleanly — the server's big send completes
 * un-canceled only because the resume let it finish.
 */
static int t_pause_resume(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t server_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_cfg_t client_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    wtq_msquic_env_t *cenv = NULL;
    wtq_msquic_listener_t *listener = NULL;
    wtq_session_t *cs = NULL;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.echo_big_on_fin = true;
    cl.ping_in_established = true;
    cl.pause_before_ping = true;
    cl.resume_on_send_complete = true;
    cl.close_on_fin = true;
    cl.close_code = 5;
    cl.release_in_closed = true;

    client_ecfg.tuning.stream_recv_window = 16u * 1024u;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&server_ecfg, &senv),
                          WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&client_ecfg, &cenv),
                          WTQ_OK);
    if (senv != NULL && cenv != NULL) {
        WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sv, "/echo", &listener),
                              WTQ_OK);
        if (listener != NULL) {
            WTQ_TEST_CHECK_EQ_INT(
                client_up(cenv, &cl, wtq_msquic_listener_port(listener),
                          "/echo", &cs),
                WTQ_OK);
            if (cs != NULL) {
                WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
                WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
            }
        }
    }
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (senv != NULL)
        wtq_msquic_env_close(senv);
    if (cenv != NULL)
        wtq_msquic_env_close(cenv);

    WTQ_TEST_CHECK_EQ_INT(cl.pause_rc, WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(cl.resume_rc, WTQ_OK);
    /* nothing was delivered while paused… */
    WTQ_TEST_CHECK_EQ_SIZE(cl.data_at_resume, 0);
    /* …and everything (FIN last) after the resume */
    WTQ_TEST_CHECK_EQ_SIZE(cl.data_total, sizeof(budget_a));
    WTQ_TEST_CHECK_EQ_INT(cl.fin_events, 1);
    WTQ_TEST_CHECK_EQ_INT(cl.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.send_cancels, 0);
    WTQ_TEST_CHECK(cl.closed_clean);
    WTQ_TEST_CHECK(sv.closed_clean);
    WTQ_TEST_CHECK_EQ_U64(sv.closed_code, 5);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: pause_resume\n");
    return failures;
}

/*
 * Session close while a paused stream has the peer's large response
 * withheld at the transport: teardown must discard the held-back data
 * and cancel the peer's pinned send (its window can never open again),
 * cleanly on both sides.
 */
static int t_close_while_paused(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t server_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_cfg_t client_ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *senv = NULL;
    wtq_msquic_env_t *cenv = NULL;
    wtq_msquic_listener_t *listener = NULL;
    wtq_session_t *cs = NULL;
    struct side sv, cl;

    side_init(&sv);
    side_init(&cl);
    sv.echo_big_on_fin = true;
    cl.ping_in_established = true;
    cl.pause_before_ping = true;
    cl.close_in_send_complete = true;
    cl.release_in_closed = true;

    client_ecfg.tuning.stream_recv_window = 16u * 1024u;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&server_ecfg, &senv),
                          WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&client_ecfg, &cenv),
                          WTQ_OK);
    if (senv != NULL && cenv != NULL) {
        WTQ_TEST_CHECK_EQ_INT(listener_up(senv, &sv, "/echo", &listener),
                              WTQ_OK);
        if (listener != NULL) {
            WTQ_TEST_CHECK_EQ_INT(
                client_up(cenv, &cl, wtq_msquic_listener_port(listener),
                          "/echo", &cs),
                WTQ_OK);
            if (cs != NULL) {
                WTQ_TEST_CHECK(side_wait(&cl, &cl.closed));
                WTQ_TEST_CHECK(side_wait(&sv, &sv.closed));
            }
        }
    }
    if (listener != NULL)
        wtq_msquic_listener_stop(listener);
    if (senv != NULL)
        wtq_msquic_env_close(senv);
    if (cenv != NULL)
        wtq_msquic_env_close(cenv);

    WTQ_TEST_CHECK_EQ_INT(cl.pause_rc, WTQ_OK);
    /* the response never reached the app */
    WTQ_TEST_CHECK_EQ_SIZE(cl.data_total, 0);
    WTQ_TEST_CHECK_EQ_INT(cl.closed, 1);
    WTQ_TEST_CHECK(cl.closed_clean);
    WTQ_TEST_CHECK_EQ_INT(sv.closed, 1);
    /* the server's pinned send can only end canceled */
    WTQ_TEST_CHECK_EQ_INT(sv.send_completions, 1);
    WTQ_TEST_CHECK_EQ_INT(sv.send_cancels, 1);

    side_destroy(&sv);
    side_destroy(&cl);
    if (failures == 0)
        printf("PASS: close_while_paused\n");
    return failures;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (certs_locate(argc > 1 ? argv[1] : NULL) != 0)
        return 2;

    failures += t_handshake_close();
    failures += t_unknown_path_404();
    failures += t_release_after_env_close();
    failures += t_sequential_conns();
    failures += t_bidi_pingpong();
    failures += t_send_budget();
    failures += t_oversized_send();
    failures += t_reset_cancels();
    failures += t_stop_mapping();
    failures += t_close_cancels();
    failures += t_datagram_echo();
    failures += t_datagram_flood_close();
    failures += t_datagram_unavailable();
    failures += t_pause_resume();
    failures += t_close_while_paused();

    if (failures == 0)
        printf("PASS: loopback_msquic\n");
    else
        fprintf(stderr, "FAIL: loopback_msquic (%d)\n", failures);
    return failures;
}
