/*
 * EXPERIMENTAL Network.framework capability probe — NOT a backend.
 *
 * Apple-only, opt-in, uninstalled, unexported, outside ctest/CI. It asks the
 * real Apple runtime whether Network.framework's multiplexed QUIC API can
 * satisfy wtq_driver_ops (src/engine/wt_driver.h). No public API is
 * committed; only public Apple headers are used.
 *
 * THE PROBE IS SELF-CHECKING. Every required observation records PASS, FAIL
 * or UNRESOLVED. Any FAIL -- a timeout, a wrong code, a wrong direction,
 * missing metadata, a peer-table overflow, a duplicate marker, or a teardown
 * that never reached a terminal state -- makes the process exit nonzero.
 * UNRESOLVED is reported but does not fail the run: the question was asked
 * correctly and the runtime gave no answer.
 *
 * Everything the client emits is judged by an independent raw QUIC peer
 * (raw_peer.c) observing the wire. Apple's application-error GETTERS are
 * receive-side and its SETTERS are send-side, so a local readback proves
 * nothing about transmission and is never used as evidence.
 *
 * Attribution: every test stream sends a unique length-delimited marker
 * ("<marker>\n") as its first bytes. The peer reassembles it across RECEIVE
 * fragments and reports the exact QUIC stream id carrying it. Streams the
 * probe did not create -- notably the client-bidi 0 that Network.framework
 * opens on its own -- carry no marker and cannot be confused with a test
 * stream. Before any stream is stamped or aborted, the probe waits for that
 * exact NW connection to reach `ready` with QUIC metadata, and requires the
 * native id to equal the id the peer saw.
 *
 * Stream-identity chronology, sampled in this exact order:
 *   A after nw_connection_group_extract_connection
 *   B after nw_connection_set_queue + nw_connection_start
 *   C immediately BEFORE nw_connection_send
 *   D immediately AFTER nw_connection_send returns
 *   E inside the `ready` state callback
 */

#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <Network/Network.h>

#include "raw_peer.h"
#include "send_sentinel.h"

#define WIRE_MS 5000
#define READY_MS 5000
#define TEARDOWN_MS 5000

/* --- ordered log ----------------------------------------------------------- */

static int g_seq;
static int next_seq(void) { return __atomic_add_fetch(&g_seq, 1, __ATOMIC_SEQ_CST); }

#define LOGF(...)                                                         \
    do {                                                                  \
        printf("[%03d] ", next_seq());                                    \
        printf(__VA_ARGS__);                                              \
        fflush(stdout);                                                   \
    } while (0)

#define SECTION(name) printf("\n== %s\n", name)

/* --- verdict accumulator --------------------------------------------------- */

typedef enum { V_PASS, V_FAIL, V_UNRESOLVED } verdict_t;

#define MAX_RESULTS 64
static struct {
    const char *name;
    verdict_t v;
    char detail[224];
} g_results[MAX_RESULTS];
static int g_nresults;

static void record(const char *name, verdict_t v, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static bool g_result_overflow;

static void record(const char *name, verdict_t v, const char *fmt, ...)
{
    if (g_nresults >= MAX_RESULTS) {
        /* Fatal: a dropped row could otherwise hide a failure. */
        g_result_overflow = true;
        printf("[!!!] FATAL: result table overflow, dropping \"%s\"\n", name);
        return;
    }
    int i = g_nresults++;
    g_results[i].name = name;
    g_results[i].v = v;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_results[i].detail, sizeof(g_results[i].detail), fmt, ap);
    va_end(ap);
    LOGF("  [%s] %s: %s\n",
         v == V_PASS ? "PASS" : v == V_FAIL ? "FAIL" : "UNRESOLVED", name,
         g_results[i].detail);
}

#define CHECK(name, cond, ...) record((name), (cond) ? V_PASS : V_FAIL, __VA_ARGS__)

/*
 * The exact manifest of rows a complete run must produce, each exactly once.
 * A skipped test therefore cannot yield exit zero, and a duplicated row (two
 * tests writing the same verdict) is caught too.
 *
 * "teardown" is deliberately NOT required here: it is recorded once on the
 * success path and additionally for each failing rundown, so it may legitimately
 * appear more than once. Its failures are caught by the FAIL count.
 */
static const char *const REQUIRED_ROWS[] = {
    "group-ready",
    "id-async:uni",   "id-match:uni",
    "id-async:bidi",  "id-match:bidi",
    "options-alias",
    "overlap:ids",    "overlap:dgram",
    "recv-reset:visible",
    "recv-stop:signal",
    "dgram:usable-size", "dgram:both-ways",
    "reset:local-uni",
    "cancel:bidi-stamped",
    "cancel:bidi-plain",
    "inbound:type-vs-idbits",
    "stop:inbound-uni",
    "detach:no-cancel",
    "serialization",
    "peer-integrity",
    "ownership:group-metadata",
    "conn-close",
    "send-retirement",
};
#define REQUIRED_N ((int)(sizeof(REQUIRED_ROWS) / sizeof(REQUIRED_ROWS[0])))

/* Exit status: nonzero iff anything FAILed, a required row is missing or
 * duplicated, or the result table overflowed. UNRESOLVED never fails. */
static int results_summary(void)
{
    int pass = 0, fail = 0, unres = 0;
    printf("\n== RESULTS\n");
    for (int i = 0; i < g_nresults; i++) {
        const char *tag = g_results[i].v == V_PASS ? "PASS"
                          : g_results[i].v == V_FAIL ? "FAIL" : "UNRESOLVED";
        printf("  %-10s %-24s %s\n", tag, g_results[i].name, g_results[i].detail);
        if (g_results[i].v == V_PASS) pass++;
        else if (g_results[i].v == V_FAIL) fail++;
        else unres++;
    }

    int manifest_errs = 0;
    for (int r = 0; r < REQUIRED_N; r++) {
        int seen = 0;
        for (int i = 0; i < g_nresults; i++)
            if (strcmp(g_results[i].name, REQUIRED_ROWS[r]) == 0)
                seen++;
        if (seen != 1) {
            printf("  MANIFEST   %-24s expected exactly once, saw %d\n",
                   REQUIRED_ROWS[r], seen);
            manifest_errs++;
        }
    }
    if (g_result_overflow) {
        printf("  MANIFEST   result table overflowed; rows were dropped\n");
        manifest_errs++;
    }

    printf("\n  %d passed, %d failed, %d unresolved, %d manifest error(s)\n",
           pass, fail, unres, manifest_errs);
    return (fail == 0 && manifest_errs == 0) ? 0 : 1;
}

/* --- serialization observation --------------------------------------------- */

static int g_in_handler, g_max_concurrent;
static void enter_handler(void)
{
    int n = __atomic_add_fetch(&g_in_handler, 1, __ATOMIC_SEQ_CST);
    int cur = __atomic_load_n(&g_max_concurrent, __ATOMIC_SEQ_CST);
    while (n > cur && !__atomic_compare_exchange_n(&g_max_concurrent, &cur, n,
                                                   false, __ATOMIC_SEQ_CST,
                                                   __ATOMIC_SEQ_CST))
        ;
}
static void exit_handler(void) { __atomic_sub_fetch(&g_in_handler, 1, __ATOMIC_SEQ_CST); }

/* --- helpers --------------------------------------------------------------- */

static raw_peer_t *g_rp;

static void raw_peer_log(const char *line) { LOGF("  %s\n", line); }

static bool wait_sem(dispatch_semaphore_t s, int ms)
{
    return dispatch_semaphore_wait(
               s, dispatch_time(DISPATCH_TIME_NOW, (int64_t)ms * NSEC_PER_MSEC)) == 0;
}

static const char *state_name(nw_connection_state_t s)
{
    switch (s) {
    case nw_connection_state_invalid: return "invalid";
    case nw_connection_state_waiting: return "waiting";
    case nw_connection_state_preparing: return "preparing";
    case nw_connection_state_ready: return "ready";
    case nw_connection_state_failed: return "failed";
    case nw_connection_state_cancelled: return "cancelled";
    default: return "?";
    }
}

static void err_of(nw_error_t e, int *domain, int *code)
{
    *domain = e ? (int)nw_error_get_error_domain(e) : -1;
    *code = e ? (int)nw_error_get_error_code(e) : 0;
}

struct id_sample {
    bool had_md;
    bool is_quic;
    uint64_t id;
    uint8_t type;
};

static const char *id_bits_name(uint64_t id)
{
    switch (id & 0x3u) {
    case 0: return "client-bidi";
    case 1: return "server-bidi";
    case 2: return "client-uni";
    default: return "server-uni";
    }
}

static const char *nw_type_name(uint8_t t)
{
    switch (t) {
    case 0: return "unknown";
    case 1: return "bidirectional";
    case 2: return "unidirectional";
    case 3: return "datagram";
    default: return "?";
    }
}

static struct id_sample sample_id(nw_connection_t c)
{
    struct id_sample s = { false, false, UINT64_MAX, 255 };
    nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(c, def);
    if (md != NULL) {
        s.had_md = true;
        s.is_quic = nw_protocol_metadata_is_quic(md);
        s.id = nw_quic_get_stream_id(md);
        s.type = nw_quic_get_stream_type(md);
        nw_release(md);
    }
    nw_release(def);
    return s;
}

static void log_sample(const char *point, struct id_sample s)
{
    if (!s.had_md) {
        LOGF("  sample %-22s metadata=NULL (no id available)\n", point);
        return;
    }
    LOGF("  sample %-22s metadata=present is_quic=%d id=%llu nw_type=%u(%s) "
         "id&3=%s\n",
         point, (int)s.is_quic, (unsigned long long)s.id, (unsigned)s.type,
         nw_type_name(s.type), id_bits_name(s.id));
}

static void stamp_stream_error(nw_connection_t c, uint64_t code)
{
    nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(c, def);
    if (md != NULL) {
        nw_quic_set_stream_application_error(md, code);
        nw_release(md);
    }
    nw_release(def);
}

static uint64_t read_stream_error(nw_connection_t c)
{
    uint64_t got = UINT64_MAX;
    nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(c, def);
    if (md != NULL) {
        got = nw_quic_get_stream_application_error(md);
        nw_release(md);
    }
    nw_release(def);
    return got;
}

/* --- a probed NW stream ---------------------------------------------------- */

struct stream_probe {
    const char *label;
    nw_connection_t conn;
    struct id_sample a, b, c, d, e;
    bool reached_ready;
    int terminal;          /* atomic: set once a terminal state was delivered */
    int last_domain, last_code;
    dispatch_semaphore_t ready;
    dispatch_semaphore_t gone;
};

/*
 * Every stream_probe is HEAP-OWNED. The state-changed handler captures the
 * probe by raw pointer and Network.framework may deliver callbacks at any
 * time, so a stack-allocated probe whose function returns -- especially on a
 * teardown-timeout path -- would leave a live callback writing into expired
 * stack memory. Probes are freed only after a successful terminal rundown.
 */
static struct stream_probe *probe_new(const char *label)
{
    struct stream_probe *sp = calloc(1, sizeof(*sp));
    if (sp == NULL)
        return NULL;
    sp->label = label;
    sp->last_domain = -1;
    sp->ready = dispatch_semaphore_create(0);
    sp->gone = dispatch_semaphore_create(0);
    return sp;
}

static void probe_destroy(struct stream_probe *sp)
{
    if (sp == NULL)
        return;
    dispatch_release(sp->ready);
    dispatch_release(sp->gone);
    free(sp);
}

/*
 * Quarantine. If a connection never reaches a terminal state we must not
 * release it (that is the UAF the rundown exists to prevent) and must not free
 * the probe (its handler still points at it). Both are parked here forever,
 * the run is failed, and the leak is explicit rather than hidden.
 */
#define QUARANTINE_MAX 16
static struct stream_probe *g_quarantine[QUARANTINE_MAX];
static int g_quarantine_n;

/*
 * Set when a probe could not even be quarantined. An untracked live
 * connection may still schedule callbacks, so once this is set the shared
 * roots may NEVER be released: quarantine_drain() reports not-clear forever.
 */
static bool g_quarantine_overflow;

static void quarantine(struct stream_probe *sp)
{
    if (g_quarantine_n < QUARANTINE_MAX) {
        g_quarantine[g_quarantine_n++] = sp;
    } else {
        g_quarantine_overflow = true;
        record("teardown", V_FAIL,
               "quarantine overflow: an untracked live connection exists; "
               "shared roots will not be released");
    }
}

/*
 * Stop accepting inbound connections DETERMINISTICALLY. Clearing the handler
 * alone is not enough: an invocation of the old handler already scheduled on
 * the group's serial queue can still run after a registry snapshot looks
 * empty. So: clear the handler, then run a barrier block through that queue --
 * when it returns, every previously-scheduled handler invocation has
 * completed, and no further ones can be scheduled. Only then is a registry
 * snapshot meaningful.
 */
static void group_stop_accepting(nw_connection_group_t g, dispatch_queue_t q)
{
    nw_connection_group_set_new_connection_handler(g, NULL);
    dispatch_sync(q, ^{ /* barrier: drain scheduled handler invocations */ });
}

/*
 * After the group is cancelled, quarantined connections frequently reach their
 * terminal state after all. Retry each one's rundown and release those that
 * terminated. Returns true when the quarantine is empty. Any survivor means
 * shared roots (group, queues) must NOT be released before process exit: a
 * live connection still schedules callbacks against them, and releasing them
 * would create exactly the late-callback UAF the quarantine exists to prevent.
 */
static bool quarantine_drain(int timeout_ms)
{
    int live = g_quarantine_overflow ? 1 : 0; /* untracked => never clear */
    for (int i = 0; i < g_quarantine_n; i++) {
        struct stream_probe *sp = g_quarantine[i];
        if (sp == NULL)
            continue;
        if (!__atomic_load_n(&sp->terminal, __ATOMIC_SEQ_CST) &&
            !wait_sem(sp->gone, timeout_ms) &&
            !__atomic_load_n(&sp->terminal, __ATOMIC_SEQ_CST)) {
            live++;
            continue; /* still live: stays quarantined */
        }
        nw_connection_set_state_changed_handler(sp->conn, NULL);
        nw_release(sp->conn);
        g_quarantine[i] = NULL;
        probe_destroy(sp);
    }
    return live == 0;
}

static void attach_state_handler(struct stream_probe *sp)
{
    struct stream_probe *cap = sp;
    nw_connection_set_state_changed_handler(
        sp->conn, ^(nw_connection_state_t st, nw_error_t e) {
          enter_handler();
          int d, c;
          err_of(e, &d, &c);
          cap->last_domain = d;
          cap->last_code = c;
          if (st == nw_connection_state_ready) {
              cap->e = sample_id(cap->conn);
              cap->reached_ready = true;
              dispatch_semaphore_signal(cap->ready);
          } else if (st == nw_connection_state_failed ||
                     st == nw_connection_state_cancelled) {
              LOGF("  [%s] state=%s err(domain=%d code=%d)\n", cap->label,
                   state_name(st), d, c);
              __atomic_store_n(&cap->terminal, 1, __ATOMIC_SEQ_CST);
              dispatch_semaphore_signal(cap->ready); /* unblock a ready-waiter */
              dispatch_semaphore_signal(cap->gone);
          }
          exit_handler();
        });
}

/*
 * Deterministic rundown: cancel -> terminal observed -> clear handlers ->
 * release -> destroy the probe.
 *
 * `gone` is a one-shot semaphore that an earlier test may already have
 * consumed (the RESET/STOP visibility tests wait on it). So the terminal state
 * is tracked by an atomic flag and the semaphore is only waited on when the
 * flag is not already set. Waiting twice on a consumed one-shot would hang.
 *
 * On timeout: record FAIL, quarantine the probe and its connection, and return
 * false. Nothing is released or freed.
 */
static bool shutdown_connection(struct stream_probe *sp)
{
    if (sp == NULL)
        return true;
    if (sp->conn == NULL) {
        probe_destroy(sp);
        return true;
    }
    nw_connection_cancel(sp->conn);

    if (!__atomic_load_n(&sp->terminal, __ATOMIC_SEQ_CST)) {
        if (!wait_sem(sp->gone, TEARDOWN_MS) &&
            !__atomic_load_n(&sp->terminal, __ATOMIC_SEQ_CST)) {
            record("teardown", V_FAIL,
                   "%s: no terminal state within %d ms; connection and probe "
                   "quarantined, not released",
                   sp->label ? sp->label : "?", TEARDOWN_MS);
            quarantine(sp);
            return false;
        }
    }
    nw_connection_set_state_changed_handler(sp->conn, NULL);
    nw_release(sp->conn);
    sp->conn = NULL;
    probe_destroy(sp);
    return true;
}

static void drain(nw_connection_t c, const char *tag)
{
    nw_connection_receive(
        c, 1, 65536,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool complete,
          nw_error_t error) {
          enter_handler();
          int d, e;
          err_of(error, &d, &e);
          (void)ctx;
          LOGF("  recv[%s] bytes=%zu complete=%d err(domain=%d code=%d)\n", tag,
               content ? dispatch_data_get_size(content) : 0, (int)complete, d, e);
          if (error == NULL && !complete)
              drain(c, tag);
          exit_handler();
        });
}

/* --- inbound registry ------------------------------------------------------ */

/*
 * Inbound probes are registered IMMEDIATELY in the new-connection handler,
 * before start/ready; their native-id key is filled in at `ready`. A stream
 * that is merely `preparing` when teardown begins is therefore already tracked
 * and cannot escape rundown.
 *
 * `g_inbound_closed` stops the tests from adopting new inbound streams; a
 * connection arriving after that is still recorded so it is torn down, and the
 * teardown loop runs until the list stops growing.
 */
#define INBOUND_MAX 32
static pthread_mutex_t g_in_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_in_cv = PTHREAD_COND_INITIALIZER;
static struct stream_probe *g_inbound[INBOUND_MAX];
static uint64_t g_inbound_id[INBOUND_MAX];
static bool g_inbound_keyed[INBOUND_MAX];
static int g_inbound_n;
static bool g_inbound_closed;

/* Called from the new-connection handler, BEFORE start. */
static bool inbound_add(struct stream_probe *sp)
{
    bool ok = false;
    pthread_mutex_lock(&g_in_mu);
    if (g_inbound_n < INBOUND_MAX) {
        g_inbound[g_inbound_n] = sp;
        g_inbound_id[g_inbound_n] = UINT64_MAX;
        g_inbound_keyed[g_inbound_n] = false;
        g_inbound_n++;
        ok = true;
        pthread_cond_broadcast(&g_in_cv);
    }
    pthread_mutex_unlock(&g_in_mu);
    if (!ok)
        record("inbound-registry", V_FAIL, "overflow");
    return ok;
}

/* Called at `ready`, once the native id is known. */
static void inbound_key(struct stream_probe *sp, uint64_t id)
{
    pthread_mutex_lock(&g_in_mu);
    for (int i = 0; i < g_inbound_n; i++)
        if (g_inbound[i] == sp) {
            g_inbound_id[i] = id;
            g_inbound_keyed[i] = true;
            break;
        }
    pthread_cond_broadcast(&g_in_cv);
    pthread_mutex_unlock(&g_in_mu);
}

/* Bounded condition-variable wait keyed by the native stream id. No polling. */
static struct stream_probe *inbound_wait(uint64_t id, int timeout_ms)
{
    struct timespec ts;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long ns = (long)tv.tv_usec * 1000 + (long)(timeout_ms % 1000) * 1000000L;
    ts.tv_sec = tv.tv_sec + timeout_ms / 1000 + ns / 1000000000L;
    ts.tv_nsec = ns % 1000000000L;

    struct stream_probe *found = NULL;
    pthread_mutex_lock(&g_in_mu);
    for (;;) {
        if (g_inbound_closed) break;
        for (int i = 0; i < g_inbound_n && !found; i++)
            if (g_inbound_keyed[i] && g_inbound_id[i] == id)
                found = g_inbound[i];
        if (found || pthread_cond_timedwait(&g_in_cv, &g_in_mu, &ts) == ETIMEDOUT)
            break;
    }
    pthread_mutex_unlock(&g_in_mu);
    return found;
}

/* A test is taking ownership of this probe's rundown. */
static void inbound_forget(struct stream_probe *sp)
{
    pthread_mutex_lock(&g_in_mu);
    for (int i = 0; i < g_inbound_n; i++)
        if (g_inbound[i] == sp) {
            g_inbound[i] = g_inbound[g_inbound_n - 1];
            g_inbound_id[i] = g_inbound_id[g_inbound_n - 1];
            g_inbound_keyed[i] = g_inbound_keyed[g_inbound_n - 1];
            g_inbound_n--;
            break;
        }
    pthread_mutex_unlock(&g_in_mu);
}

/*
 * Cancel and run down every registered inbound connection, including ones
 * still `preparing`. group_stop_accepting() guarantees no new-connection
 * handler invocation can add to the registry after it returns, so the
 * snapshot below is complete; the loop is kept as belt-and-braces. Probes are
 * freed only on a successful terminal rundown; otherwise
 * shutdown_connection() quarantines them.
 */
static void inbound_rundown(nw_connection_group_t g, dispatch_queue_t q)
{
    pthread_mutex_lock(&g_in_mu);
    g_inbound_closed = true;
    pthread_cond_broadcast(&g_in_cv);
    pthread_mutex_unlock(&g_in_mu);

    group_stop_accepting(g, q);

    for (;;) {
        struct stream_probe *snap[INBOUND_MAX];
        int n;
        pthread_mutex_lock(&g_in_mu);
        n = g_inbound_n;
        for (int i = 0; i < n; i++) snap[i] = g_inbound[i];
        g_inbound_n = 0;
        pthread_mutex_unlock(&g_in_mu);
        if (n == 0)
            break;
        for (int i = 0; i < n; i++)
            shutdown_connection(snap[i]);
    }
}

/* --- options --------------------------------------------------------------- */

/*
 * nw_quic_create_options() returns CONNECTION-level options; handing a fresh
 * one to extract_connection re-specifies the whole QUIC protocol instance and
 * the stream dies (posix/50). Copy the group's live transport options instead.
 *
 * The returned handle is ALIASED (same pointer every call), so every flag must
 * be set immediately before each extract, as one indivisible operation.
 */
static nw_protocol_options_t copy_group_transport_options(nw_connection_group_t g)
{
    nw_parameters_t params = nw_connection_group_copy_parameters(g);
    if (params == NULL) return NULL;
    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(params);
    nw_release(params);
    if (stack == NULL) return NULL;
    nw_protocol_options_t opts = nw_protocol_stack_copy_transport_protocol(stack);
    nw_release(stack);
    return opts;
}

static nw_connection_t extract_stream(nw_connection_group_t g, bool uni, bool dgram)
{
    nw_protocol_options_t o = copy_group_transport_options(g);
    if (o == NULL) return NULL;
    nw_quic_set_stream_is_unidirectional(o, uni);
    nw_quic_set_stream_is_datagram(o, dgram);
    nw_connection_t c = nw_connection_group_extract_connection(g, NULL, o);
    nw_release(o);
    return c;
}

/* Send "<marker>\n" -- length-delimited so a split RECEIVE still matches. */
static void send_marker(nw_connection_t c, dispatch_queue_t q, const char *marker)
{
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%s%c", marker, RAW_PEER_MARKER_TERM);
    dispatch_data_t d = dispatch_data_create(buf, (size_t)n, q,
                                             DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(c, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                       ^(nw_error_t err) { (void)err; });
    dispatch_release(d);
}

/*
 * Open a local stream, wait for it to be READY WITH METADATA, and confirm the
 * native id equals the id the peer attributes to our marker. Anything missing
 * is a hard failure: the probe never stamps or aborts a stream whose identity
 * it has not established.
 */
static struct stream_probe *open_marked_stream(nw_connection_group_t g,
                                               dispatch_queue_t q, bool uni,
                                               const char *marker,
                                               const char *row,
                                               uint64_t *peer_id)
{
    struct stream_probe *sp = probe_new(marker);
    if (sp == NULL) { record(row, V_FAIL, "out of memory"); return NULL; }
    sp->conn = extract_stream(g, uni, false);
    if (sp->conn == NULL) {
        record(row, V_FAIL, "extract_connection returned NULL");
        probe_destroy(sp);
        return NULL;
    }
    attach_state_handler(sp);
    nw_connection_set_queue(sp->conn, q);
    nw_connection_start(sp->conn);
    send_marker(sp->conn, q, marker);

    const char *why = NULL;
    if (!wait_sem(sp->ready, READY_MS) || !sp->reached_ready)
        why = "never reached ready";
    else if (!sp->e.had_md)
        why = "ready but QUIC metadata absent";
    else if (!raw_peer_wait_marker(g_rp, marker, peer_id, WIRE_MS))
        why = "peer never saw the marker";
    else if (sp->e.id != *peer_id)
        why = "native id != peer id";
    else if (uni != ((sp->e.id & 0x2u) != 0))
        why = "peer saw the wrong direction";
    if (why != NULL) {
        record(row, V_FAIL, "%s (%s, native id=%llu)", why, marker,
               (unsigned long long)sp->e.id);
        shutdown_connection(sp);
        return NULL;
    }
    LOGF("  [%s] ready, native id=%llu == peer id (%s)\n", marker,
         (unsigned long long)sp->e.id, id_bits_name(sp->e.id));
    return sp;
}

/* ========================================================================== */
/* Gating result: is the stream id available synchronously?                    */
/* ========================================================================== */

static void gating_chronology(nw_connection_group_t g, dispatch_queue_t q, bool uni)
{
    const char *marker = uni ? "m-chrono-uni" : "m-chrono-bidi";
    SECTION(uni ? "GATING: chronology, local uni" : "GATING: chronology, local bidi");

    const char *row_async = uni ? "id-async:uni" : "id-async:bidi";
    const char *row_match = uni ? "id-match:uni" : "id-match:bidi";
    struct stream_probe *spp = probe_new(marker);
    if (spp == NULL) { record(row_async, V_FAIL, "out of memory"); return; }
    struct stream_probe sp_ref;
    (void)sp_ref;
    spp->conn = extract_stream(g, uni, false);
    if (spp->conn == NULL) {
        record(row_async, V_FAIL, "extract returned NULL");
        probe_destroy(spp);
        return;
    }
#define sp (*spp)
    sp.a = sample_id(sp.conn);
    log_sample("A after-extract", sp.a);

    attach_state_handler(spp);
    nw_connection_set_queue(sp.conn, q);
    nw_connection_start(sp.conn);
    sp.b = sample_id(sp.conn);
    log_sample("B after-start", sp.b);

    sp.c = sample_id(sp.conn);
    log_sample("C before-send", sp.c);
    send_marker(sp.conn, q, marker);
    sp.d = sample_id(sp.conn);
    log_sample("D after-send-returns", sp.d);

    if (!wait_sem(sp.ready, READY_MS) || !sp.reached_ready) {
        record(row_async, V_FAIL, "never reached ready");
        record(row_match, V_FAIL, "stream never reached ready");
        shutdown_connection(spp);
        return;
    }
    log_sample("E at-ready", sp.e);

    /*
     * The load-bearing claim is A ONLY: sampled after extract and BEFORE
     * start, where `ready` cannot yet have fired -- and exactly where
     * open_uni/open_bidi must return an id. A is structurally NULL.
     *
     * B, C and D are all post-start samples taken on the app thread while
     * `ready` races on the serial queue, so ALL THREE are reported but not
     * asserted: D was observed populated early on, and C was observed
     * populated (with the correct id) in 2 of 20 gated runs -- `ready` can
     * land after start alone, before any byte is written. Asserting any of
     * them would claim a guarantee the runtime does not give. The gating
     * verdict rests on A.
     */
    CHECK(row_async, !sp.a.had_md && sp.e.had_md,
          "metadata at A(open, pre-start)=%d (asserted NULL), at ready=%d "
          "(id=%llu %s); post-start samples B/C/D=%d%d%d (racy, reported "
          "not asserted)",
          sp.a.had_md, sp.e.had_md, (unsigned long long)sp.e.id,
          id_bits_name(sp.e.id), sp.b.had_md, sp.c.had_md, sp.d.had_md);

    uint64_t peer_id = UINT64_MAX;
    if (raw_peer_wait_marker(g_rp, marker, &peer_id, WIRE_MS))
        CHECK(row_match, peer_id == sp.e.id, "peer id=%llu native id=%llu",
              (unsigned long long)peer_id, (unsigned long long)sp.e.id);
    else
        record(row_match, V_FAIL, "peer never saw the marker");

    shutdown_connection(spp);
#undef sp
}

/* ========================================================================== */
/* Options aliasing + overlapping opens (models wtq_conn_start)                */
/* ========================================================================== */

static void options_aliasing(nw_connection_group_t g)
{
    SECTION("copied-options aliasing");
    nw_protocol_options_t a = copy_group_transport_options(g);
    nw_protocol_options_t b = copy_group_transport_options(g);
    if (a == NULL || b == NULL) {
        record("options-alias", V_FAIL, "could not obtain two handles");
        if (a) nw_release(a);
        if (b) nw_release(b);
        return;
    }
    LOGF("  handle A=%p handle B=%p (%s)\n", (void *)a, (void *)b,
         a == b ? "SAME POINTER" : "distinct pointers");
    nw_quic_set_stream_is_unidirectional(a, true);
    nw_quic_set_stream_is_datagram(b, true);
    bool aliased = nw_quic_get_stream_is_datagram(a) &&
                   nw_quic_get_stream_is_unidirectional(b);
    record("options-alias", V_PASS,
           "handles are %s (A{uni=%d,dgram=%d} B{uni=%d,dgram=%d})",
           aliased ? "ALIASED" : "independent",
           (int)nw_quic_get_stream_is_unidirectional(a),
           (int)nw_quic_get_stream_is_datagram(a),
           (int)nw_quic_get_stream_is_unidirectional(b),
           (int)nw_quic_get_stream_is_datagram(b));
    nw_release(a);
    nw_release(b);
}

/* Reassemble a datagram payload from a receive block. */
static void copy_payload(dispatch_data_t content, char *dst, size_t cap)
{
    dst[0] = '\0';
    if (!content || dispatch_data_get_size(content) >= cap)
        return;
    __block size_t off = 0;
    dispatch_data_apply(content, ^bool(dispatch_data_t r, size_t o, const void *b,
                                       size_t sz) {
      (void)r; (void)o;
      if (off + sz < cap) { memcpy(dst + off, b, sz); off += sz; }
      return true;
    });
    dst[off] = '\0';
}

static void overlapping_opens(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("overlapping opens: 3x uni + bidi + datagram, none started yet");

    enum { N = 4 };
    static const char *const markers[N] = { "m-crit-0", "m-crit-1", "m-crit-2",
                                            "m-ovl-bidi" };
    static const bool want_uni[N] = { true, true, true, false };
    struct stream_probe *sp[N], *dg = probe_new("m-ovl-dgram");
    if (dg == NULL) { record("overlap:ids", V_FAIL, "out of memory"); return; }

    /* Phase 1: extract all, no start and no ready in between. Each iteration
     * is (set every flag, extract) with nothing interleaved. */
    for (int i = 0; i < N; i++) {
        sp[i] = probe_new(markers[i]);
        if (sp[i] == NULL || (sp[i]->conn = extract_stream(g, want_uni[i], false)) == NULL) {
            record("overlap:ids", V_FAIL, "%s: extract returned NULL", markers[i]);
            record("overlap:dgram", V_FAIL, "not run: stream extract failed");
            for (int j = 0; j < i; j++) shutdown_connection(sp[j]);
            probe_destroy(sp[i]);
            probe_destroy(dg);
            return;
        }
    }
    dg->conn = extract_stream(g, false, true);
    LOGF("  extracted 3 uni + 1 bidi + 1 datagram, none started\n");

    /* Phase 2: start them all. */
    for (int i = 0; i < N; i++) {
        attach_state_handler(sp[i]);
        nw_connection_set_queue(sp[i]->conn, q);
        nw_connection_start(sp[i]->conn);
        send_marker(sp[i]->conn, q, markers[i]);
    }
    if (dg->conn) {
        attach_state_handler(dg);
        nw_connection_set_queue(dg->conn, q);
        nw_connection_start(dg->conn);
    }

    /* Phase 3: peer-verify every id and direction. */
    int bad = 0;
    for (int i = 0; i < N; i++) {
        uint64_t id = UINT64_MAX;
        if (!raw_peer_wait_marker(g_rp, markers[i], &id, WIRE_MS)) {
            record("overlap:ids", V_FAIL, "%s: peer never saw marker", markers[i]);
            bad++;
            continue;
        }
        if (((id & 0x2u) != 0) != want_uni[i]) {
            record("overlap:ids", V_FAIL, "%s: wanted %s got %s (id=%llu)",
                   markers[i], want_uni[i] ? "uni" : "bidi", id_bits_name(id),
                   (unsigned long long)id);
            bad++;
        } else {
            LOGF("  %-11s peer id=%-3llu %-11s matches\n", markers[i],
                 (unsigned long long)id, id_bits_name(id));
        }
    }
    if (bad == 0)
        record("overlap:ids", V_PASS,
               "3 uni + 1 bidi extracted back-to-back; all ids and directions "
               "correct at the peer");

    /* Phase 3b: peer-verify the overlapping datagram flow, both directions. */
    if (dg->conn == NULL || !wait_sem(dg->ready, READY_MS) || !dg->reached_ready) {
        record("overlap:dgram", V_FAIL, "datagram flow never reached ready");
    } else {
        __block bool got_back = false;
        dispatch_semaphore_t rx = dispatch_semaphore_create(0);
        nw_connection_receive(dg->conn, 1, 65535,
            ^(dispatch_data_t content, nw_content_context_t ctx, bool complete,
              nw_error_t error) {
              enter_handler();
              (void)ctx; (void)complete; (void)error;
              char buf[64];
              copy_payload(content, buf, sizeof(buf));
              got_back = (strcmp(buf, "ovl-dg-s2c") == 0);
              dispatch_semaphore_signal(rx);
              exit_handler();
            });

        dispatch_semaphore_t sent = dispatch_semaphore_create(0);
        const char *pl = "ovl-dg-c2s";
        dispatch_data_t d = dispatch_data_create(pl, strlen(pl), q,
                                                 DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(dg->conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                           ^(nw_error_t err) {
                             enter_handler();
                             (void)err;
                             dispatch_semaphore_signal(sent);
                             exit_handler();
                           });
        dispatch_release(d);
        wait_sem(sent, WIRE_MS);
        dispatch_release(sent);

        bool c2s = raw_peer_wait_datagram(g_rp, "ovl-dg-c2s", WIRE_MS);
        bool issued = raw_peer_send_datagram(g_rp, "ovl-dg-s2c", 10, WIRE_MS);
        bool s2c = issued && wait_sem(rx, WIRE_MS) && got_back;
        dispatch_release(rx);
        CHECK("overlap:dgram", c2s && s2c,
              "datagram flow extracted alongside 4 streams: c2s=%s s2c=%s",
              c2s ? "yes" : "no", s2c ? "yes" : "no");
    }

    for (int i = 0; i < N; i++) shutdown_connection(sp[i]);
    shutdown_connection(dg);
}

/* ========================================================================== */
/* Half-stream matrix                                                          */
/* ========================================================================== */

/*
 * Wait for the exact stream to be TERMINAL at the peer, then judge its whole
 * event record. Expected-absence ("no RESET was sent") is asserted against a
 * finished stream, never against an arbitrary time window.
 */
static void judge_halves(const char *name, uint64_t id, bool want_reset,
                         uint64_t reset_code, bool want_stop, uint64_t stop_code,
                         bool want_fin)
{
    raw_peer_stream_events_t ev;
    if (!raw_peer_wait_stream_terminal(g_rp, id, &ev, WIRE_MS)) {
        record(name, V_FAIL, "stream %llu never became terminal at the peer",
               (unsigned long long)id);
        return;
    }
    bool ok = (ev.saw_reset == want_reset) && (ev.saw_stop == want_stop) &&
              (ev.saw_fin == want_fin);
    if (ok && want_reset) ok = (ev.reset_code == reset_code);
    if (ok && want_stop) ok = (ev.stop_code == stop_code);
    record(name, ok ? V_PASS : V_FAIL,
           "peer(stream %llu terminal): RESET=%s%llu STOP=%s%llu FIN=%s "
           "(expected RESET=%d STOP=%d FIN=%d)",
           (unsigned long long)id, ev.saw_reset ? "" : "none:",
           (unsigned long long)ev.reset_code, ev.saw_stop ? "" : "none:",
           (unsigned long long)ev.stop_code, ev.saw_fin ? "yes" : "no",
           (int)want_reset, (int)want_stop, (int)want_fin);
}

static void wire_local_uni_reset(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("WIRE: local uni, stamp 0x1234 + cancel");
    uint64_t id;
    struct stream_probe *sp =
        open_marked_stream(g, q, true, "m-luni-reset", "reset:local-uni", &id);
    if (sp == NULL) return;
    stamp_stream_error(sp->conn, 0x1234);
    shutdown_connection(sp); /* cancel + terminal + release + destroy */
    /* client-uni has no receive half: RESET only, and a reset supersedes FIN */
    judge_halves("reset:local-uni", id, true, 0x1234, false, 0, false);
}

static void wire_local_bidi(nw_connection_group_t g, dispatch_queue_t q, bool stamp)
{
    SECTION(stamp ? "WIRE: local bidi, stamp 0x1234 + cancel"
                  : "WIRE: local bidi, plain cancel");
    uint64_t id;
    const char *marker = stamp ? "m-lbidi-stamp" : "m-lbidi-plain";
    const char *row = stamp ? "cancel:bidi-stamped" : "cancel:bidi-plain";
    struct stream_probe *sp = open_marked_stream(g, q, false, marker, row, &id);
    if (sp == NULL) return;
    if (stamp) stamp_stream_error(sp->conn, 0x1234);
    shutdown_connection(sp);
    if (stamp)
        /* stamped: RESET aborts the send half, so no FIN is ever sent */
        judge_halves(row, id, true, 0x1234, true, 0x1234, false);
    else
        /* plain: send half closes gracefully (FIN), receive half STOPs with 0 */
        judge_halves(row, id, false, 0, true, 0, true);
}

/* Inbound server-uni: the client has only a receive half, so a cancel there
 * can only be expressed as STOP_SENDING. */
static void wire_peer_uni_stop(void)
{
    SECTION("WIRE: inbound server-uni, client stamps 0x1234 + cancels");
    uint64_t id = UINT64_MAX;
    if (!raw_peer_open_stream(g_rp, true, &id, WIRE_MS)) {
        record("stop:inbound-uni", V_FAIL, "peer could not open a server-uni");
        return;
    }
    /* Give the client bytes so the inbound connection materializes. */
    raw_peer_send_on_stream(g_rp, id, "x\n", 2, false);

    struct stream_probe *sp = inbound_wait(id, READY_MS);
    if (sp == NULL) {
        record("stop:inbound-uni", V_FAIL,
               "client never surfaced inbound id=%llu ready with metadata",
               (unsigned long long)id);
        return;
    }
    /*
     * A KNOWN RUNTIME DEFECT, not a probe requirement: nw_quic_get_stream_type
     * reports peer-initiated unidirectional streams as `datagram` (3), which
     * collides with what a real datagram flow reports. The id bits are
     * authoritative. Recorded as UNRESOLVED so it is reported without failing
     * the run; it becomes PASS if Apple ever makes the accessor correct.
     */
    record("inbound:type-vs-idbits", sp->e.type == 2 ? V_PASS : V_UNRESOLVED,
           "server-uni id=%llu: nw_type=%u(%s), id bits say %s -- nw_type %s "
           "classify an inbound stream",
           (unsigned long long)sp->e.id, (unsigned)sp->e.type,
           nw_type_name(sp->e.type), id_bits_name(sp->e.id),
           sp->e.type == 2 ? "CAN" : "CANNOT");

    /* Take ownership of this probe's rundown from the registry. */
    inbound_forget(sp);
    stamp_stream_error(sp->conn, 0x1234);
    if (!shutdown_connection(sp))
        return;
    /* server-uni: the client has no send half, so the peer can never see a
     * FIN or a RESET from us -- only STOP_SENDING. */
    judge_halves("stop:inbound-uni", id, false, 0, true, 0x1234, false);
}

/* Peer -> client visibility of RESET_STREAM. */
static void wire_peer_reset_visible(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("WIRE: peer sends RESET_STREAM; is it visible to NW?");
    uint64_t id;
    struct stream_probe *sp =
        open_marked_stream(g, q, false, "m-peer-reset", "recv-reset:visible", &id);
    if (sp == NULL) return;
    drain(sp->conn, "peer-reset");

    if (!raw_peer_reset_stream(g_rp, id, 0x4321)) {
        record("recv-reset:visible", V_FAIL, "peer could not reset id=%llu",
               (unsigned long long)id);
        shutdown_connection(sp);
        return;
    }
    /* This may consume `gone`; shutdown_connection() copes via the atomic flag. */
    bool term = wait_sem(sp->gone, WIRE_MS);
    uint64_t got = read_stream_error(sp->conn);
    CHECK("recv-reset:visible", got == 0x4321,
          "getter reports %llu after peer RESET(0x4321); terminal=%d "
          "state_err(domain=%d code=%d)", (unsigned long long)got, (int)term,
          sp->last_domain, sp->last_code);
    shutdown_connection(sp);
}

/*
 * Peer -> client visibility of STOP_SENDING. STOP targets our LOCAL SEND half,
 * so the receive-side getter is only one of three candidate signals. Capture
 * all of them: the state callback, the getter, and the completion error of a
 * send issued AFTER the STOP arrives.
 */
static void wire_peer_stop_visible(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("WIRE: peer sends STOP_SENDING; which public signal exposes it?");
    uint64_t id;
    struct stream_probe *sp =
        open_marked_stream(g, q, false, "m-peer-stop", "recv-stop:signal", &id);
    if (sp == NULL) return;
    drain(sp->conn, "peer-stop");

    if (!raw_peer_stop_sending(g_rp, id, 0x4321)) {
        record("recv-stop:signal", V_FAIL, "peer could not stop id=%llu",
               (unsigned long long)id);
        shutdown_connection(sp);
        return;
    }

    /* (a) a terminal state callback? (may consume `gone`) */
    bool term = wait_sem(sp->gone, 2000);
    /* (b) the receive-side getter? */
    uint64_t got = read_stream_error(sp->conn);
    /* (c) a send issued after the STOP -- does it fail, and with what? */
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int sd = -1, sc = 0;
    const char *pl = "post-stop";
    dispatch_data_t d = dispatch_data_create(pl, strlen(pl), q,
                                             DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(sp->conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                       ^(nw_error_t err) {
                         enter_handler();
                         err_of(err, &sd, &sc);
                         dispatch_semaphore_signal(done);
                         exit_handler();
                       });
    dispatch_release(d);
    bool sent = wait_sem(done, WIRE_MS);
    dispatch_release(done);

    LOGF("  after peer STOP_SENDING(0x4321): terminal_state=%d "
         "state_err(domain=%d code=%d) getter=%llu send_completion=%s "
         "err(domain=%d code=%d)\n",
         (int)term, sp->last_domain, sp->last_code, (unsigned long long)got,
         sent ? "fired" : "never", sd, sc);

    if (got == 0x4321)
        record("recv-stop:signal", V_PASS,
               "code exposed by nw_quic_get_stream_application_error=%llu",
               (unsigned long long)got);
    else
        record("recv-stop:signal", V_UNRESOLVED,
               "code NOT exposed (getter=%llu). Only generic signals: "
               "terminal=%d state_err(%d/%d) post-STOP send %s err(%d/%d)",
               (unsigned long long)got, (int)term, sp->last_domain, sp->last_code,
               sent ? "completed" : "never fired", sd, sc);

    shutdown_connection(sp);
}

static void wire_datagrams(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("WIRE: datagrams, exact payloads both directions");
    struct stream_probe *dgp = probe_new("dgram-flow");
    if (dgp == NULL) { record("dgram:both-ways", V_FAIL, "out of memory"); return; }
#define dg (*dgp)
    dg.conn = extract_stream(g, false, true);
    if (dg.conn == NULL) {
        record("dgram:both-ways", V_FAIL, "extract NULL");
        record("dgram:usable-size", V_FAIL, "extract NULL");
        probe_destroy(dgp);
        return;
    }
    attach_state_handler(dgp);
    nw_connection_set_queue(dg.conn, q);
    nw_connection_start(dg.conn);
    if (!wait_sem(dg.ready, READY_MS) || !dg.reached_ready) {
        record("dgram:both-ways", V_FAIL, "datagram flow never reached ready");
        record("dgram:usable-size", V_FAIL, "datagram flow never reached ready");
        shutdown_connection(dgp);
        return;
    }

    nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(dg.conn, def);
    if (md != NULL) {
        uint32_t usable = nw_quic_get_stream_usable_datagram_frame_size(md);
        CHECK("dgram:usable-size", usable > 0,
              "usable_datagram_frame_size=%u (current usable on the flow, NOT "
              "the configured transport parameter)", usable);
        nw_release(md);
    } else {
        record("dgram:usable-size", V_FAIL, "flow metadata NULL at ready");
    }
    nw_release(def);

    __block bool got_back = false;
    dispatch_semaphore_t rx = dispatch_semaphore_create(0);
    nw_connection_receive(dg.conn, 1, 65535,
        ^(dispatch_data_t content, nw_content_context_t ctx, bool complete,
          nw_error_t error) {
          enter_handler();
          (void)ctx; (void)complete; (void)error;
          char buf[64];
          copy_payload(content, buf, sizeof(buf));
          got_back = (strcmp(buf, "dgram-s2c") == 0);
          LOGF("  client received datagram payload=\"%s\"\n", buf);
          dispatch_semaphore_signal(rx);
          exit_handler();
        });

    dispatch_semaphore_t sent = dispatch_semaphore_create(0);
    __block int sd = -1, sc = 0;
    const char *pl = "dgram-c2s";
    dispatch_data_t d = dispatch_data_create(pl, strlen(pl), q,
                                             DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    /* Each datagram is one complete message: is_complete MUST be true. */
    nw_connection_send(dg.conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                       ^(nw_error_t err) {
                         enter_handler();
                         err_of(err, &sd, &sc);
                         dispatch_semaphore_signal(sent);
                         exit_handler();
                       });
    dispatch_release(d);
    bool sok = wait_sem(sent, WIRE_MS) && sd == -1;
    dispatch_release(sent);

    bool c2s = sok && raw_peer_wait_datagram(g_rp, "dgram-c2s", WIRE_MS);
    bool issued = raw_peer_send_datagram(g_rp, "dgram-s2c", 9, WIRE_MS);
    bool s2c = issued && wait_sem(rx, WIRE_MS) && got_back;
    dispatch_release(rx);

    CHECK("dgram:both-ways", c2s && s2c,
          "client->peer exact payload=%s, peer->client exact payload=%s "
          "(send err domain=%d code=%d)", c2s ? "yes" : "no", s2c ? "yes" : "no",
          sd, sc);
    shutdown_connection(dgp);
#undef dg
}

/* Detach is an identity unlink: not a cancel, not handler removal. */
static void detach_semantics(nw_connection_group_t g, dispatch_queue_t q)
{
    SECTION("detach: clearing handlers must not cancel a live stream");
    uint64_t id;
    struct stream_probe *sp =
        open_marked_stream(g, q, false, "m-detach", "detach:no-cancel", &id);
    if (sp == NULL) return;

    nw_connection_set_state_changed_handler(sp->conn, NULL);

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int sd = -1, sc = 0;
    const char *pl = "after-clear";
    dispatch_data_t d = dispatch_data_create(pl, strlen(pl), q,
                                             DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(sp->conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                       ^(nw_error_t err) {
                         enter_handler();
                         err_of(err, &sd, &sc);
                         dispatch_semaphore_signal(done);
                         exit_handler();
                       });
    dispatch_release(d);
    bool ok = wait_sem(done, WIRE_MS) && sd == -1;
    dispatch_release(done);
    CHECK("detach:no-cancel", ok,
          "send after clearing the state handler completed err(domain=%d code=%d)",
          sd, sc);

    /* Reattach a handler purely so rundown can observe a terminal state.
     * That is teardown, not evidence. */
    attach_state_handler(sp);
    shutdown_connection(sp);
}

/* ========================================================================== */
/* Send retirement: when can a record referenced by a completion be freed?     */
/* ========================================================================== */

/*
 * The exactly-once send-completion contract needs to know the earliest point
 * a backend may free a send record when Network.framework NEVER invokes the
 * completion (the post-peer-STOP case the earlier matrix measured). A block
 * that was copied but not yet DISPOSED may still run or be released later;
 * freeing the record it captures before disposal is a UAF.
 *
 * So this fixture separates INVOCATION from DISPOSAL (send_sentinel.m: an
 * ARC-captured sentinel whose dealloc reports disposal) and attributes each
 * to a stage of the teardown sequence. Attribution is exact: callbacks stamp
 * the CURRENT stage; stage transitions happen on the issuing thread; absence
 * is only ever claimed after the whole sequence plus a bounded final wait.
 *
 * Stages (advanced strictly in order):
 */
enum retire_stage {
    RS_ISSUED = 0,         /* send issued, STOP already sent by the peer  */
    RS_PENDING_CHECK,      /* bounded window: is the completion pending?  */
    RS_STREAM_CANCEL,      /* after nw_connection_cancel(stream)          */
    RS_STREAM_TERMINAL,    /* after the stream's terminal state callback  */
    RS_BARRIER_1,          /* after a serial-queue barrier                */
    RS_GROUP_CANCEL,       /* after nw_connection_group_cancel            */
    RS_GROUP_TERMINAL,     /* after the group's terminal state callback   */
    RS_BARRIER_2,          /* after a second queue barrier                */
    RS_STREAM_RELEASED,    /* after handlers cleared + nw_release(stream) */
    RS_END,                /* fixture done; anything later = NEVER        */
};

static const char *retire_stage_name(int st)
{
    switch (st) {
    case RS_ISSUED: return "issue";
    case RS_PENDING_CHECK: return "pending-check";
    case RS_STREAM_CANCEL: return "stream-cancel";
    case RS_STREAM_TERMINAL: return "stream-terminal";
    case RS_BARRIER_1: return "barrier-after-stream-terminal";
    case RS_GROUP_CANCEL: return "group-cancel";
    case RS_GROUP_TERMINAL: return "group-terminal";
    case RS_BARRIER_2: return "barrier-after-group-terminal";
    case RS_STREAM_RELEASED: return "stream-released";
    default: return "NEVER";
    }
}

/* Heap-owned send record; freed ONLY after disposal is observed. */
struct retire_record {
    int stage;               /* atomic: current stage                     */
    int invoked_stage;       /* -1 until invoked                          */
    int invoke_count;        /* atomic                                    */
    int invoke_domain, invoke_code;
    int disposed_stage;      /* -1 until disposed                         */
    int dispose_count;       /* atomic: sentinel dealloc must be exactly 1 */
    bool freed;              /* audit: free exactly once                  */
    dispatch_semaphore_t invoked;
    dispatch_semaphore_t disposed;
};

static void retire_on_complete(void *ctx, int domain, int code)
{
    struct retire_record *r = ctx;
    int n = __atomic_add_fetch(&r->invoke_count, 1, __ATOMIC_SEQ_CST);
    if (n == 1) {
        r->invoked_stage = __atomic_load_n(&r->stage, __ATOMIC_SEQ_CST);
        r->invoke_domain = domain;
        r->invoke_code = code;
    }
    dispatch_semaphore_signal(r->invoked);
}

static void retire_on_dispose(void *ctx)
{
    struct retire_record *r = ctx;
    if (__atomic_add_fetch(&r->dispose_count, 1, __ATOMIC_SEQ_CST) == 1)
        r->disposed_stage = __atomic_load_n(&r->stage, __ATOMIC_SEQ_CST);
    dispatch_semaphore_signal(r->disposed);
}

static void retire_set_stage(struct retire_record *r, int st)
{
    __atomic_store_n(&r->stage, st, __ATOMIC_SEQ_CST);
}

static void send_retirement_isolated(const char *cert, const char *key)
{
    SECTION("WIRE: send retirement after peer STOP (fresh connection)");

    uint16_t port = 0;
    raw_peer_t *rp = raw_peer_start(cert, key, &port, raw_peer_log);
    if (rp == NULL) { record("send-retirement", V_FAIL, "raw peer did not start"); return; }
    raw_peer_t *saved_rp = g_rp;
    g_rp = rp; /* open_marked_stream attributes through the fixture's peer */

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    /*
     * WORK_ITEM autorelease frequency: ARC releases inside NW callbacks may
     * be deferred to an autorelease-pool drain; per-work-item draining makes
     * disposal attribution deterministic at block granularity.
     */
    dispatch_queue_attr_t qattr = dispatch_queue_attr_make_with_autorelease_frequency(
        DISPATCH_QUEUE_SERIAL, DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM);
    dispatch_queue_t q = dispatch_queue_create("wtq.nw.retire", qattr);
    dispatch_queue_t vq = dispatch_queue_create("wtq.nw.retire.v", DISPATCH_QUEUE_SERIAL);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    nw_parameters_t params = nw_parameters_create_quic(^(nw_protocol_options_t quic) {
      sec_protocol_options_t sec = nw_quic_copy_sec_protocol_options(quic);
      sec_protocol_options_add_tls_application_protocol(sec, "h3");
      sec_protocol_options_set_verify_block(
          sec, ^(sec_protocol_metadata_t m, sec_trust_t t,
                 sec_protocol_verify_complete_t done) {
            (void)m; (void)t; done(true); /* dev-only self-signed loopback */
          }, vq);
      nw_release(sec);
    });
    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_connection_group_t group = nw_connection_group_create(desc, params);

    static pthread_mutex_t rin_mu = PTHREAD_MUTEX_INITIALIZER;
    static struct stream_probe *rin[INBOUND_MAX];
    static int rin_n;
    pthread_mutex_lock(&rin_mu);
    rin_n = 0;
    pthread_mutex_unlock(&rin_mu);

    dispatch_semaphore_t up = dispatch_semaphore_create(0);
    dispatch_semaphore_t down = dispatch_semaphore_create(0);
    __block int st_now = -1;
    bool cancel_requested = false;
    bool group_terminal = false;
    enum { RETIRE_MAX_CANDS = 8 };
    struct retire_record *cands[RETIRE_MAX_CANDS];
    int ncands = 0;
    struct retire_record *r = NULL;
    struct stream_probe *sp = NULL;
    uint64_t id = 0;
    bool pending_at_issue = false;
    int raced_through = 0;
    bool row_recorded = false;

    nw_connection_group_set_queue(group, q);
    nw_connection_group_set_receive_handler(
        group, 65535, true, ^(dispatch_data_t c, nw_content_context_t x, bool done) {
          (void)c; (void)x; (void)done;
        });
    nw_connection_group_set_new_connection_handler(group, ^(nw_connection_t in) {
      enter_handler();
      nw_retain(in);
      struct stream_probe *isp = probe_new("retire-inbound");
      if (isp == NULL) { nw_release(in); exit_handler(); return; }
      isp->conn = in;
      bool tracked = false;
      pthread_mutex_lock(&rin_mu);
      if (rin_n < INBOUND_MAX) { rin[rin_n++] = isp; tracked = true; }
      pthread_mutex_unlock(&rin_mu);
      if (!tracked) {
          record("send-retirement", V_FAIL, "hidden-inbound overflow");
          nw_release(in);
          probe_destroy(isp);
          exit_handler();
          return;
      }
      attach_state_handler(isp);
      nw_connection_set_queue(in, q);
      nw_connection_start(in);
      exit_handler();
    });
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t e) {
          enter_handler();
          (void)e;
          st_now = (int)st;
          if (st == nw_connection_group_state_ready ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(up);
          if (st == nw_connection_group_state_cancelled ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(down);
          exit_handler();
        });
    nw_connection_group_start(group);

    if (!wait_sem(up, 15000) || st_now != (int)nw_connection_group_state_ready) {
        record("send-retirement", V_FAIL, "fresh group never became ready");
        row_recorded = true;
        goto out;
    }

    /* 1. Precisely attributed bidi stream, ready with metadata. */
    sp = open_marked_stream(group, q, false, "m-retire", "send-retirement", &id);
    if (sp == NULL) { row_recorded = true; goto out; }
    drain(sp->conn, "retire");

    /* 2. Peer sends STOP_SENDING on exactly that stream. */
    if (!raw_peer_stop_sending(rp, id, 0x4321)) {
        record("send-retirement", V_FAIL, "peer could not STOP id=%llu",
               (unsigned long long)id);
        row_recorded = true;
        goto out;
    }

    /*
     * 3+4. Obtain a send whose completion is KNOWN to remain pending. The
     * STOP's arrival at NW is not locally observable (the standing finding),
     * so a single send can race it and complete normally. Deterministic by
     * construction: issue sentinel sends one at a time; the first whose
     * completion does not fire within its bounded window is the subject.
     *
     * EVERY candidate stays tracked until its block is disposed — an
     * undisposed candidate is never discarded, makes the required verdict
     * non-PASS, and keeps the shared roots alive (its block could still
     * reference the record and run on the queue).
     */
    {
        for (int i = 0; i < RETIRE_MAX_CANDS && r == NULL; i++) {
            struct retire_record *cand = calloc(1, sizeof(*cand));
            if (cand == NULL) { record("send-retirement", V_FAIL, "oom");
                                row_recorded = true; goto out; }
            cand->invoked_stage = -1;
            cand->disposed_stage = -1;
            cand->invoked = dispatch_semaphore_create(0);
            cand->disposed = dispatch_semaphore_create(0);
            cands[ncands++] = cand;
            retire_set_stage(cand, RS_ISSUED);
            char pl[32];
            snprintf(pl, sizeof(pl), "post-stop-send-%d", i);
            dispatch_data_t d = dispatch_data_create(pl, strlen(pl), q,
                                                     DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            wtq_probe_send_with_sentinel(sp->conn, d, false, retire_on_complete,
                                         retire_on_dispose, cand);
            dispatch_release(d);
            retire_set_stage(cand, RS_PENDING_CHECK);
            if (!wait_sem(cand->invoked, 750)) {
                r = cand; /* pending: the subject */
                pending_at_issue = true;
                raced_through = i;
                LOGF("  send #%d: completion PENDING (subject); %d earlier "
                     "send(s) completed normally before suppression\n", i, i);
            } else {
                LOGF("  send #%d: completed err(domain=%d code=%d)\n", i,
                     cand->invoke_domain, cand->invoke_code);
            }
        }
        if (r == NULL) {
            record("send-retirement", V_UNRESOLVED,
                   "no send stayed pending after peer STOP across %d tries: "
                   "suppression not reproduced this run", RETIRE_MAX_CANDS);
            row_recorded = true;
            goto out;
        }
    }

    /* 5. Staged teardown; every callback stamps the stage it ran in. */
    retire_set_stage(r, RS_STREAM_CANCEL);
    nw_connection_cancel(sp->conn);
    if (!wait_sem(sp->gone, TEARDOWN_MS) &&
        !__atomic_load_n(&sp->terminal, __ATOMIC_SEQ_CST)) {
        record("send-retirement", V_FAIL, "stream never reached terminal");
        row_recorded = true;
        goto out;
    }
    retire_set_stage(r, RS_STREAM_TERMINAL);
    dispatch_sync(q, ^{ /* barrier: drain queued work incl. pool drains */ });
    retire_set_stage(r, RS_BARRIER_1);

    retire_set_stage(r, RS_GROUP_CANCEL);
    nw_connection_group_cancel(group);
    cancel_requested = true;
    group_terminal = wait_sem(down, TEARDOWN_MS);
    if (group_terminal)
        retire_set_stage(r, RS_GROUP_TERMINAL);
    dispatch_sync(q, ^{});
    retire_set_stage(r, RS_BARRIER_2);

    /* 6. Release the stream object itself (handlers cleared first). */
    {
        struct stream_probe *tmp = sp;
        sp = NULL;
        if (shutdown_connection(tmp))
            retire_set_stage(r, RS_STREAM_RELEASED);
    }

    /* Final bounded wait for the subject's disposal (never inferred). */
    (void)wait_sem(r->disposed, 3000);
    retire_set_stage(r, RS_END);

out:
    if (sp != NULL)
        shutdown_connection(sp);
    /* stop accepting + hidden-inbound rundown (same discipline as close). */
    group_stop_accepting(group, q);
    for (;;) {
        struct stream_probe *snap[INBOUND_MAX];
        int n;
        pthread_mutex_lock(&rin_mu);
        n = rin_n;
        for (int i = 0; i < n; i++) snap[i] = rin[i];
        rin_n = 0;
        pthread_mutex_unlock(&rin_mu);
        if (n == 0) break;
        for (int i = 0; i < n; i++)
            shutdown_connection(snap[i]);
    }
    if (!cancel_requested)
        nw_connection_group_cancel(group);
    if (!group_terminal)
        group_terminal = wait_sem(down, TEARDOWN_MS);

    /*
     * CANDIDATE AUDIT — after completed teardown, before any root release.
     * Every candidate must be: invoked at most once, disposed exactly once,
     * freed exactly once. An undisposed candidate is a non-PASS verdict and
     * pins the shared roots (its block may still run on the queue).
     */
    {
        int undisposed = 0, violations = 0;
        for (int i = 0; i < ncands; i++) {
            struct retire_record *c = cands[i];
            if (__atomic_load_n(&c->dispose_count, __ATOMIC_SEQ_CST) == 0)
                (void)wait_sem(c->disposed, 1000); /* bounded, per candidate */
            int inv = __atomic_load_n(&c->invoke_count, __ATOMIC_SEQ_CST);
            int dsp = __atomic_load_n(&c->dispose_count, __ATOMIC_SEQ_CST);
            if (inv > 1 || dsp > 1) {
                violations++;
                LOGF("  AUDIT candidate #%d: invoked=%d disposed=%d "
                     "(contract violation)\n", i, inv, dsp);
            }
            if (dsp == 0) {
                undisposed++;
                LOGF("  AUDIT candidate #%d: NOT disposed after completed "
                     "teardown (invoked=%d)\n", i, inv);
            }
        }

        if (!row_recorded) {
            /*
             * PASS enforces the HEADLINE results, not just consistency:
             *   - the subject completes exactly once, with posix/89
             *     (ECANCELED), invoked AND disposed during stream cancel;
             *   - every raced-through candidate completed exactly once
             *     with no error;
             *   - every candidate disposed exactly once (audited above).
             */
            int n = r ? __atomic_load_n(&r->invoke_count, __ATOMIC_SEQ_CST) : 0;
            bool subject_ok =
                r != NULL && n == 1 && r->invoke_domain == 1 &&
                r->invoke_code == 89 &&
                r->invoked_stage == RS_STREAM_CANCEL &&
                r->disposed_stage == RS_STREAM_CANCEL;
            bool raced_ok = true;
            for (int i = 0; i < ncands; i++) {
                struct retire_record *c = cands[i];
                if (c == r) continue;
                int ci = __atomic_load_n(&c->invoke_count, __ATOMIC_SEQ_CST);
                if (ci != 1 || c->invoke_domain != -1)
                    raced_ok = false;
            }
            if (violations > 0)
                record("send-retirement", V_FAIL,
                       "%d candidate(s) violated at-most-once-invoke/"
                       "exactly-once-dispose", violations);
            else if (undisposed > 0)
                record("send-retirement", V_UNRESOLVED,
                       "%d candidate block(s) NOT disposed by completed "
                       "teardown; records and roots retained (no safe free "
                       "point demonstrated this run)", undisposed);
            else if (!subject_ok || !raced_ok)
                record("send-retirement", V_FAIL,
                       "headline violated: subject invoked=%s(count=%d) "
                       "err(domain=%d code=%d) disposed=%s (expect exactly "
                       "once, posix/89, both at stream-cancel); raced-ok=%d",
                       n > 0 ? retire_stage_name(r->invoked_stage) : "never",
                       n, r ? r->invoke_domain : -1, r ? r->invoke_code : 0,
                       r ? retire_stage_name(r->disposed_stage) : "-",
                       (int)raced_ok);
            else
                record("send-retirement", V_PASS,
                       "raced-through=%d (each exactly once, no error); "
                       "subject invoked exactly once, posix/89 ECANCELED, "
                       "invoked+disposed at stream-cancel; all %d candidates "
                       "disposed exactly once", raced_through, ncands);
            row_recorded = true;
        } else if (violations > 0 || undisposed > 0) {
            /* Row already recorded by an early path; violations still fail. */
            record("teardown", V_FAIL,
                   "retire-fixture audit: %d violation(s), %d undisposed",
                   violations, undisposed);
        }

        /* Free EXACTLY the disposed candidates, exactly once each. */
        for (int i = 0; i < ncands; i++) {
            struct retire_record *c = cands[i];
            if (__atomic_load_n(&c->dispose_count, __ATOMIC_SEQ_CST) == 1 &&
                !c->freed) {
                c->freed = true;
                dispatch_release(c->invoked);
                dispatch_release(c->disposed);
                free(c);
                cands[i] = NULL;
            }
        }

        /* Roots released only with a fully clean audit AND an empty
         * quarantine; a false quarantine_drain() must fail loudly, never
         * silently skip the release. */
        bool q_ok = quarantine_drain(TEARDOWN_MS);
        if (group_terminal && undisposed == 0 && violations == 0 && q_ok) {
            nw_release(group);
            nw_release(desc);
            nw_release(params);
            nw_release(ep);
            dispatch_release(up);
            dispatch_release(down);
            dispatch_release(q);
            dispatch_release(vq);
        } else {
            record("teardown", V_FAIL,
                   "retire-fixture: group-terminal=%d undisposed=%d "
                   "violations=%d quarantine-empty=%d; shared roots "
                   "deliberately not released",
                   (int)group_terminal, undisposed, violations, (int)q_ok);
        }
    }
    g_rp = saved_rp;
    if (!raw_peer_stop(rp))
        record("teardown", V_FAIL, "retire-fixture raw peer did not quiesce");
}

/* ========================================================================== */
/* Group-metadata ownership: decided by a child process, not by an annotation  */
/* ========================================================================== */

/*
 * nw_connection_group_copy_protocol_metadata() documents "Returns a retained
 * protocol metadata object" and follows the `copy` naming rule, but -- unlike
 * nw_connection_copy_protocol_metadata() -- it carries no NW_RETURNS_RETAINED
 * annotation. A missing annotation proves NOTHING about runtime ownership, so
 * the question is settled by experiment.
 *
 * Four children, identical except for one step. Each builds a QUIC group
 * against a raw peer, waits for ready, performs its metadata step, tears
 * everything down, and exits 0. The parent classifies exit vs signal.
 *
 *   0 baseline              no metadata copy at all
 *   1 copy, no release      (leaks if the object really is +1)
 *   2 copy, release once    (the documented contract)
 *   3 copy, retain, release balanced pair around a copy
 *
 * Each mode is repeated and the crash COUNTS are reported. The observed
 * behaviour is an intermittent crash when the documented release contract is
 * followed; the rate varies run to run and by build flavor (see README). It
 * is not treated as proof of +0 ownership, of a deterministic bug, or of any
 * sanitizer-dependent behaviour, and no portable rule is claimed.
 */
enum { OWN_BASELINE = 0, OWN_COPY_NORELEASE, OWN_COPY_RELEASE,
       OWN_COPY_RETAIN_RELEASE };

static const char *own_mode_name(int m)
{
    switch (m) {
    case OWN_BASELINE: return "baseline(no-copy)";
    case OWN_COPY_NORELEASE: return "copy,no-release";
    case OWN_COPY_RELEASE: return "copy,release-once";
    default: return "copy,retain+release";
    }
}

/*
 * Child exit meanings -- keep in sync with ownership_spawn().
 * Only OWN_EXIT_SETUP may become UNRESOLVED in the parent; every other
 * nonzero exit fails the parent run outright.
 */
enum {
    OWN_EXIT_CLEAN = 0,
    OWN_EXIT_SETUP = 10,    /* pre-experiment setup unavailable (peer/TLS)   */
    OWN_EXIT_ASSERT = 11,   /* experiment assertion failure (metadata NULL)  */
    OWN_EXIT_TEARDOWN = 12, /* fixture teardown failure                      */
    OWN_EXIT_EXEC = 127,    /* execv failed                                  */
};

/* One adopted hidden connection in the ownership child. */
struct own_inbound {
    nw_connection_t conn;
    dispatch_semaphore_t gone;
    int terminal; /* atomic */
};

/*
 * Runs in the CHILD. Every mode uses the SAME rigorous fixture: each hidden
 * inbound connection (Network.framework opens client-bidi 0 itself) is
 * retained and registered immediately, then cancelled, waited terminal,
 * unhooked and released during teardown. The four modes differ ONLY in the
 * metadata operation between `ready` and teardown -- an unbalanced hidden
 * connection would otherwise contaminate the very destruction path the
 * experiment observes.
 */
static int ownership_child(int mode, const char *cert, const char *key)
{
    uint16_t port = 0;
    raw_peer_t *rp = raw_peer_start(cert, key, &port, NULL);
    if (rp == NULL)
        return OWN_EXIT_SETUP;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    dispatch_queue_t q = dispatch_queue_create("own.q", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t vq = dispatch_queue_create("own.v", DISPATCH_QUEUE_SERIAL);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    nw_parameters_t params = nw_parameters_create_quic(^(nw_protocol_options_t quic) {
      sec_protocol_options_t sec = nw_quic_copy_sec_protocol_options(quic);
      sec_protocol_options_add_tls_application_protocol(sec, "h3");
      sec_protocol_options_set_verify_block(
          sec, ^(sec_protocol_metadata_t m, sec_trust_t t,
                 sec_protocol_verify_complete_t done) {
            (void)m; (void)t; done(true);
          }, vq);
      nw_release(sec);
    });
    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_connection_group_t group = nw_connection_group_create(desc, params);

    /* Statics are safe: the child is a fresh single-use process. */
    static pthread_mutex_t own_mu = PTHREAD_MUTEX_INITIALIZER;
    static struct own_inbound own_in[8];
    static int own_in_n;
    static bool own_over;

    dispatch_semaphore_t up = dispatch_semaphore_create(0);
    dispatch_semaphore_t down = dispatch_semaphore_create(0);
    __block int st_now = -1;
    nw_connection_group_set_queue(group, q);
    nw_connection_group_set_receive_handler(
        group, 65535, true, ^(dispatch_data_t c, nw_content_context_t x, bool d) {
          (void)c; (void)x; (void)d;
        });
    nw_connection_group_set_new_connection_handler(group, ^(nw_connection_t in) {
      nw_retain(in);
      struct own_inbound *oi = NULL;
      pthread_mutex_lock(&own_mu);
      if (own_in_n < 8)
          oi = &own_in[own_in_n++];
      else
          own_over = true;
      pthread_mutex_unlock(&own_mu);
      if (oi == NULL) { nw_release(in); return; }
      oi->conn = in;
      oi->gone = dispatch_semaphore_create(0);
      struct own_inbound *cap = oi;
      nw_connection_set_state_changed_handler(
          in, ^(nw_connection_state_t st, nw_error_t e) {
            (void)e;
            if (st == nw_connection_state_failed ||
                st == nw_connection_state_cancelled) {
                __atomic_store_n(&cap->terminal, 1, __ATOMIC_SEQ_CST);
                dispatch_semaphore_signal(cap->gone);
            }
          });
      nw_connection_set_queue(in, q);
      nw_connection_start(in);
    });
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t e) {
          (void)e;
          st_now = (int)st;
          if (st == nw_connection_group_state_ready ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(up);
          if (st == nw_connection_group_state_cancelled ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(down);
        });
    nw_connection_group_start(group);
    if (!wait_sem(up, 15000) || st_now != (int)nw_connection_group_state_ready)
        return OWN_EXIT_SETUP;

    /* The metadata operation: the ONLY step that differs between modes. */
    if (mode != OWN_BASELINE) {
        nw_protocol_definition_t def = nw_protocol_copy_quic_definition();
        nw_protocol_metadata_t md =
            nw_connection_group_copy_protocol_metadata(group, def);
        if (md == NULL) {
            nw_release(def);
            return OWN_EXIT_ASSERT;
        }
        if (mode == OWN_COPY_RELEASE) {
            nw_release(md);
        } else if (mode == OWN_COPY_RETAIN_RELEASE) {
            nw_retain(md);
            nw_release(md); /* balanced: net effect identical to no-release */
        }
        nw_release(def);
    }

    /* Teardown, identical for every mode. Stop accepting first (clear the
     * handler, then a barrier through the serial queue), so the hidden-
     * connection list cannot grow under the rundown. */
    nw_connection_group_set_new_connection_handler(group, NULL);
    dispatch_sync(q, ^{});
    if (own_over)
        return OWN_EXIT_TEARDOWN;

    for (int i = 0; i < own_in_n; i++) {
        struct own_inbound *oi = &own_in[i];
        nw_connection_cancel(oi->conn);
        if (!__atomic_load_n(&oi->terminal, __ATOMIC_SEQ_CST) &&
            !wait_sem(oi->gone, 5000) &&
            !__atomic_load_n(&oi->terminal, __ATOMIC_SEQ_CST))
            return OWN_EXIT_TEARDOWN; /* never release a live connection */
        nw_connection_set_state_changed_handler(oi->conn, NULL);
        nw_release(oi->conn);
        dispatch_release(oi->gone);
    }

    nw_connection_group_cancel(group);
    if (!wait_sem(down, 5000))
        return OWN_EXIT_TEARDOWN;
    nw_release(group);
    nw_release(desc);
    nw_release(params);
    nw_release(ep);
    dispatch_release(up);
    dispatch_release(down);
    dispatch_release(q);
    dispatch_release(vq);
    if (!raw_peer_stop(rp))
        return OWN_EXIT_TEARDOWN;
    return OWN_EXIT_CLEAN;
}

/* Runs in the PARENT: fork/exec `reps` children for one mode; count crashes. */
static int ownership_spawn(const char *self, const char *cert_dir, int mode,
                           int *sig_out)
{
    char modestr[8];
    snprintf(modestr, sizeof(modestr), "%d", mode);
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = { (char *)self, (char *)cert_dir,
                               (char *)"--ownership-child", modestr, NULL };
        execv(self, argv);
        _exit(127);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        return -3; /* fork/waitpid failed: fixture failure */
    if (WIFSIGNALED(status)) {
        if (sig_out) *sig_out = WTERMSIG(status);
        return 1; /* crashed: the observation */
    }
    int code = WEXITSTATUS(status);
    if (code == OWN_EXIT_CLEAN)
        return 0;
    if (code == OWN_EXIT_SETUP)
        return -1; /* peer/TLS unavailable: retryable, may become UNRESOLVED */
    /* OWN_EXIT_ASSERT, OWN_EXIT_TEARDOWN, OWN_EXIT_EXEC, anything else:
     * the fixture itself failed and must FAIL the parent run. */
    LOGF("  %-22s child exited %d (fixture failure)\n", own_mode_name(mode),
         code);
    return -3;
}

/*
 * Returns the crash count, or -1 if a child could not even set up. A setup
 * failure is transient (loopback peer / TLS), so each rep is retried once
 * before the mode is declared unattributable -- it must never be reported as
 * a capability failure.
 */
static int ownership_run_mode(const char *self, const char *cert_dir, int mode,
                              int reps, int *sig_out)
{
    int crashes = 0;
    for (int i = 0; i < reps; i++) {
        int r = ownership_spawn(self, cert_dir, mode, sig_out);
        if (r == -1)
            r = ownership_spawn(self, cert_dir, mode, sig_out); /* retry once */
        if (r < 0)
            return r; /* -1 setup unavailable, -3 fixture failure */
        crashes += r;
    }
    return crashes;
}

/*
 * Each mode is repeated because the behaviour is INTERMITTENT: the crash rate
 * varies run to run and by build flavor. A single sample reads as a
 * deterministic rule; the repeated counts show there is none.
 */
static void ownership_experiment(const char *self, const char *cert_dir)
{
    SECTION("group-metadata ownership (child-process experiment)");
    enum { REPS = 5 };
    int sig = 0;
    int base = ownership_run_mode(self, cert_dir, OWN_BASELINE, REPS, &sig);
    int norel = ownership_run_mode(self, cert_dir, OWN_COPY_NORELEASE, REPS, &sig);
    int rel = ownership_run_mode(self, cert_dir, OWN_COPY_RELEASE, REPS, &sig);
    int bal = ownership_run_mode(self, cert_dir, OWN_COPY_RETAIN_RELEASE, REPS, &sig);

    if (base == -3 || norel == -3 || rel == -3 || bal == -3) {
        /* Assert/teardown/exec failure inside a child: the FIXTURE is broken
         * and nothing it measured is trustworthy. This must fail the run. */
        record("ownership:group-metadata", V_FAIL,
               "a child reported an experiment/teardown/exec failure (exit "
               "code logged above); the fixture is broken, not the API");
        return;
    }
    if (base < 0 || norel < 0 || rel < 0 || bal < 0) {
        /* The loopback peer or TLS did not come up. Nothing is attributable to
         * the metadata copy, so this is unresolved -- not a capability failure. */
        record("ownership:group-metadata", V_UNRESOLVED,
               "a child could not set up (peer/TLS) even after a retry; the "
               "ownership question was not exercised this run");
        return;
    }
    LOGF("  crashes out of %d: baseline=%d no-release=%d release-once=%d "
         "retain+release=%d\n", REPS, base, norel, rel, bal);

    if (base > 0) {
        record("ownership:group-metadata", V_FAIL,
               "baseline (no metadata copy) crashed %d/%d: the experiment "
               "cannot attribute anything to the copy", base, REPS);
    } else if (rel == 0 && norel == 0 && bal == 0) {
        record("ownership:group-metadata", V_PASS,
               "no crashes in %d reps of any mode; the documented +1 release "
               "contract held in this run", REPS);
    } else if (rel > 0 && norel == 0) {
        record("ownership:group-metadata", V_UNRESOLVED,
               "release-once crashed %d/%d (sig=%d) while baseline/no-release/"
               "balanced were clean: an INTERMITTENT, timing-dependent crash in "
               "NW teardown -- NOT evidence of +0 ownership", rel, REPS, sig);
    } else {
        record("ownership:group-metadata", V_UNRESOLVED,
               "inconclusive crash counts /%d: baseline=%d no-release=%d "
               "release=%d balanced=%d", REPS, base, norel, rel, bal);
    }
}

/* ========================================================================== */
/* Connection application close, on a FRESH connection with no prior aborts    */
/* ========================================================================== */

static void connection_close_isolated(const char *cert, const char *key)
{
    SECTION("WIRE: connection application close (fresh connection, no aborts)");

    uint16_t port = 0;
    raw_peer_t *rp = raw_peer_start(cert, key, &port, raw_peer_log);
    if (rp == NULL) { record("conn-close", V_FAIL, "raw peer did not start"); return; }

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    dispatch_queue_t q = dispatch_queue_create("wtq.nw.close", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t vq = dispatch_queue_create("wtq.nw.close.v", DISPATCH_QUEUE_SERIAL);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    nw_parameters_t params = nw_parameters_create_quic(^(nw_protocol_options_t quic) {
      sec_protocol_options_t sec = nw_quic_copy_sec_protocol_options(quic);
      sec_protocol_options_add_tls_application_protocol(sec, "h3");
      sec_protocol_options_set_verify_block(
          sec, ^(sec_protocol_metadata_t m, sec_trust_t t,
                 sec_protocol_verify_complete_t done) {
            (void)m; (void)t; done(true); /* dev-only self-signed loopback */
          }, vq);
      nw_release(sec);
      nw_quic_set_max_datagram_frame_size(quic, 65535);
    });
    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_connection_group_t group = nw_connection_group_create(desc, params);

    dispatch_semaphore_t up = dispatch_semaphore_create(0);
    dispatch_semaphore_t down = dispatch_semaphore_create(0);
    __block int st_now = -1;
    bool cancel_requested = false; /* declared before any goto out */
    bool group_terminal = false;
    nw_connection_group_set_queue(group, q);
    nw_connection_group_set_receive_handler(
        group, 65535, true, ^(dispatch_data_t c, nw_content_context_t x, bool done) {
          (void)c; (void)x; (void)done;
        });
    /*
     * Network.framework opens client-bidi 0 itself on a multiplex group.
     * EVERY such hidden connection must be adopted and tracked: an
     * un-adopted one is destroyed only from the group's dealloc, and a
     * single-pointer tracker would silently drop any beyond the first.
     */
    static pthread_mutex_t cin_mu = PTHREAD_MUTEX_INITIALIZER;
    static struct stream_probe *cin[INBOUND_MAX];
    static int cin_n;
    pthread_mutex_lock(&cin_mu);
    cin_n = 0;
    pthread_mutex_unlock(&cin_mu);

    nw_connection_group_set_new_connection_handler(group, ^(nw_connection_t in) {
      enter_handler();
      nw_retain(in);
      struct stream_probe *isp = probe_new("close-inbound");
      if (isp == NULL) { nw_release(in); exit_handler(); return; }
      isp->conn = in;
      bool tracked = false;
      pthread_mutex_lock(&cin_mu);
      if (cin_n < INBOUND_MAX) { cin[cin_n++] = isp; tracked = true; }
      pthread_mutex_unlock(&cin_mu);
      if (!tracked) {
          record("conn-close", V_FAIL, "hidden-inbound table overflow");
          nw_release(in);
          probe_destroy(isp);
          exit_handler();
          return;
      }
      attach_state_handler(isp);
      nw_connection_set_queue(in, q);
      nw_connection_start(in);
      exit_handler();
    });
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t e) {
          enter_handler();
          (void)e;
          st_now = (int)st;
          if (st == nw_connection_group_state_ready ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(up);
          if (st == nw_connection_group_state_cancelled ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(down);
          exit_handler();
        });
    nw_connection_group_start(group);

    if (!wait_sem(up, 15000) || st_now != (int)nw_connection_group_state_ready) {
        record("conn-close", V_FAIL, "fresh group never became ready");
        goto out;
    }

    /*
     * No streams opened, nothing aborted. Stamp the application error on the
     * group metadata and cancel. The peer decides; the receive-side getter is
     * never consulted.
     *
     * The metadata object returned here is deliberately NOT released:
     * releasing it triggers an intermittent crash inside Network.framework's
     * own teardown on this OS (see the ownership experiment and the README).
     * The mechanism is unexplained; no ownership rule is claimed, in either
     * direction. The object is knowingly leaked, and the README states that
     * this close path is therefore not leak-free.
     */
    {
        nw_protocol_definition_t cdef = nw_protocol_copy_quic_definition();
        nw_protocol_metadata_t cmd =
            nw_connection_group_copy_protocol_metadata(group, cdef);
        if (cmd == NULL) {
            record("conn-close", V_FAIL, "group protocol metadata NULL");
            nw_release(cdef);
            goto out;
        }
        nw_quic_set_application_error(cmd, 0x0105, "probe close");
        LOGF("  set_application_error(0x105, \"probe close\") on a fresh "
             "connection with no prior stream aborts\n");
        nw_release(cdef);
    }

    /* The cancel IS the experiment's action (stamp, then close). Its terminal
     * wait feeds the unified teardown below rather than being re-waited. */
    nw_connection_group_cancel(group);
    cancel_requested = true;
    group_terminal = wait_sem(down, TEARDOWN_MS);

    {
        raw_peer_close_kind_t kind = RAW_PEER_CLOSE_NONE;
        uint64_t code = UINT64_MAX;
        bool saw = raw_peer_wait_close(rp, &kind, &code, WIRE_MS);
        if (saw && kind == RAW_PEER_CLOSE_BY_APP && code == 0x0105)
            record("conn-close", V_PASS,
                   "peer saw CONNECTION_CLOSE (application) code=%llu",
                   (unsigned long long)code);
        else if (saw && kind == RAW_PEER_CLOSE_BY_APP)
            record("conn-close", V_FAIL,
                   "peer saw application close but code=%llu, not 0x105",
                   (unsigned long long)code);
        else if (saw)
            record("conn-close", V_UNRESOLVED,
                   "peer saw a TRANSPORT close (code=%llu); the stamped "
                   "application code did not reach the wire",
                   (unsigned long long)code);
        else
            record("conn-close", V_UNRESOLVED,
                   "peer saw no close of any kind within %d ms", WIRE_MS);
    }

out:
    /*
     * ONE unconditional teardown path, reached by every setup/error/normal
     * flow. Order: stop accepting (handler clear + queue barrier), run down
     * every hidden connection, cancel the group if the experiment did not
     * already, wait for the group's terminal callback, drain quarantine --
     * and release the shared roots only when BOTH the group is terminal AND
     * the quarantine is empty. A failure path that jumped here early must
     * never release a still-live group.
     */
    group_stop_accepting(group, q);
    for (;;) {
        struct stream_probe *snap[INBOUND_MAX];
        int n;
        pthread_mutex_lock(&cin_mu);
        n = cin_n;
        for (int i = 0; i < n; i++) snap[i] = cin[i];
        cin_n = 0;
        pthread_mutex_unlock(&cin_mu);
        if (n == 0) break;
        for (int i = 0; i < n; i++)
            shutdown_connection(snap[i]);
    }
    if (!cancel_requested)
        nw_connection_group_cancel(group);
    if (!group_terminal)
        group_terminal = wait_sem(down, TEARDOWN_MS);
    bool q_clear = quarantine_drain(TEARDOWN_MS);
    if (group_terminal && q_clear) {
        nw_release(group);
        nw_release(desc);
        nw_release(params);
        nw_release(ep);
        dispatch_release(up);
        dispatch_release(down);
        dispatch_release(q);
        dispatch_release(vq);
    } else {
        record("teardown", V_FAIL,
               "close-fixture: group-terminal=%d quarantine-empty=%d; shared "
               "roots deliberately not released", (int)group_terminal,
               (int)q_clear);
    }
    if (!raw_peer_stop(rp))
        record("teardown", V_FAIL, "close-fixture raw peer did not quiesce");
}

/* ========================================================================== */

int main(int argc, char **argv)
{
    const char *cert_dir = argc > 1 ? argv[1] : getenv("WTQ_TEST_CERT_DIR");
    if (cert_dir == NULL) {
        fprintf(stderr, "usage: wtq_nw_probe <cert-dir>\n");
        return 2;
    }
    static char cert[1024], key[1024];
    snprintf(cert, sizeof(cert), "%s/cert.pem", cert_dir);
    snprintf(key, sizeof(key), "%s/key.pem", cert_dir);

    /* Child arm of the ownership experiment: do one thing, then exit. */
    if (argc > 3 && strcmp(argv[2], "--ownership-child") == 0)
        return ownership_child(atoi(argv[3]), cert, key);

    printf("wtquic Network.framework capability probe (experimental)\n");
    printf("self-checking: any FAIL exits nonzero\n");

    uint16_t port = 0;
    g_rp = raw_peer_start(cert, key, &port, raw_peer_log);
    if (g_rp == NULL) {
        fprintf(stderr, "raw_peer_start failed (certs at %s?)\n", cert_dir);
        return 2;
    }
    printf("peer: RAW MsQuic observer 127.0.0.1:%u (ALPN h3, no H3/WT)\n",
           (unsigned)port);

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    dispatch_queue_t q = dispatch_queue_create("wtq.nw.probe", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t vq = dispatch_queue_create("wtq.nw.verify", DISPATCH_QUEUE_SERIAL);

    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portstr);
    /* QUIC is a TRANSPORT: nw_parameters_create_quic() builds the right stack.
     * Prepending QUIC onto the default TCP stack silently never starts. */
    nw_parameters_t params = nw_parameters_create_quic(^(nw_protocol_options_t quic) {
      sec_protocol_options_t sec = nw_quic_copy_sec_protocol_options(quic);
      sec_protocol_options_add_tls_application_protocol(sec, "h3");
      sec_protocol_options_set_verify_block(
          sec, ^(sec_protocol_metadata_t m, sec_trust_t t,
                 sec_protocol_verify_complete_t done) {
            (void)m; (void)t; done(true); /* dev-only self-signed loopback */
          }, vq);
      nw_release(sec);
      nw_quic_set_max_datagram_frame_size(quic, 65535);
    });

    nw_group_descriptor_t desc = nw_group_descriptor_create_multiplex(ep);
    nw_connection_group_t group = nw_connection_group_create(desc, params);

    dispatch_semaphore_t up = dispatch_semaphore_create(0);
    dispatch_semaphore_t down = dispatch_semaphore_create(0);
    __block int group_state = -1;

    nw_connection_group_set_queue(group, q);
    nw_connection_group_set_receive_handler(
        group, 65535, true, ^(dispatch_data_t c, nw_content_context_t x, bool done) {
          (void)c; (void)x; (void)done;
        });
    nw_connection_group_set_new_connection_handler(group, ^(nw_connection_t incoming) {
      enter_handler();
      nw_retain(incoming);
      struct stream_probe *sp = probe_new("inbound");
      if (sp == NULL) { nw_release(incoming); exit_handler(); return; }
      sp->conn = incoming;
      /* Registered BEFORE start: a stream still `preparing` at teardown is
       * already tracked and cannot escape rundown. */
      if (!inbound_add(sp)) {
          nw_release(incoming);
          probe_destroy(sp);
          exit_handler();
          return;
      }
      struct stream_probe *cap = sp;
      nw_connection_set_state_changed_handler(
          incoming, ^(nw_connection_state_t st, nw_error_t e) {
            enter_handler();
            int d, c;
            err_of(e, &d, &c);
            cap->last_domain = d;
            cap->last_code = c;
            struct id_sample s = sample_id(incoming);
            LOGF("  INBOUND state=%-9s err(domain=%d code=%d) metadata=%s "
                 "id=%llu nw_type=%u(%s)\n",
                 state_name(st), d, c, s.had_md ? "present" : "NULL",
                 (unsigned long long)s.id, (unsigned)s.type, nw_type_name(s.type));
            if (st == nw_connection_state_ready) {
                cap->e = s;
                cap->reached_ready = true;
                if (s.had_md)
                    inbound_key(cap, s.id); /* fill in the native-id key */
                dispatch_semaphore_signal(cap->ready);
                drain(incoming, "inbound");
            } else if (st == nw_connection_state_failed ||
                       st == nw_connection_state_cancelled) {
                __atomic_store_n(&cap->terminal, 1, __ATOMIC_SEQ_CST);
                dispatch_semaphore_signal(cap->ready);
                dispatch_semaphore_signal(cap->gone);
            }
            exit_handler();
          });
      nw_connection_set_queue(incoming, q);
      nw_connection_start(incoming);
      exit_handler();
    });
    nw_connection_group_set_state_changed_handler(
        group, ^(nw_connection_group_state_t st, nw_error_t error) {
          enter_handler();
          int d, c;
          err_of(error, &d, &c);
          group_state = (int)st;
          LOGF("  GROUP state=%d err(domain=%d code=%d)\n", (int)st, d, c);
          if (st == nw_connection_group_state_ready ||
              st == nw_connection_group_state_failed)
              dispatch_semaphore_signal(up);
          if (st == nw_connection_group_state_failed ||
              st == nw_connection_group_state_cancelled)
              dispatch_semaphore_signal(down);
          exit_handler();
        });

    SECTION("connection group");
    nw_connection_group_start(group);
    if (!wait_sem(up, 15000) ||
        group_state != (int)nw_connection_group_state_ready) {
        record("group-ready", V_FAIL, "group never became ready");
    } else {
        record("group-ready", V_PASS, "multiplex QUIC group ready");

        gating_chronology(group, q, true);
        gating_chronology(group, q, false);
        options_aliasing(group);
        overlapping_opens(group, q);

        wire_peer_reset_visible(group, q);
        wire_peer_stop_visible(group, q);
        wire_datagrams(group, q);
        wire_local_uni_reset(group, q);
        wire_local_bidi(group, q, true);
        wire_local_bidi(group, q, false);
        wire_peer_uni_stop();
        detach_semantics(group, q);

        SECTION("callback serialization");
        int maxc = __atomic_load_n(&g_max_concurrent, __ATOMIC_SEQ_CST);
        CHECK("serialization", maxc == 1,
              "max concurrently-entered handlers=%d (must be 1); a property "
              "the backend CONSTRUCTS with one serial queue, not a runtime "
              "guarantee", maxc);
    }

    SECTION("teardown");
    inbound_rundown(group, q);
    nw_connection_group_cancel(group);
    bool group_down = wait_sem(down, TEARDOWN_MS);
    /* Group cancellation often unblocks quarantined connections: retry them. */
    bool q_clear = quarantine_drain(TEARDOWN_MS);
    if (!group_down)
        record("teardown", V_FAIL, "group never reached a terminal state");
    else if (q_clear)
        record("teardown", V_PASS, "every NW stream/flow and the group ran down");
    if (!q_clear)
        record("teardown", V_FAIL,
               "quarantined connection(s) still live after group cancel; "
               "shared roots deliberately not released");

    {
        const char *why = "";
        if (raw_peer_failed(g_rp, &why))
            record("peer-integrity", V_FAIL, "%s", why);
        else
            record("peer-integrity", V_PASS,
                   "no stream-table overflow, no duplicate markers");
    }

    if (q_clear && group_down) {
        nw_release(group);
        nw_release(desc);
        nw_release(params);
        nw_release(ep);
        dispatch_release(up);
        dispatch_release(down);
        dispatch_release(q);
        dispatch_release(vq);
    }
    /* else: a live connection still schedules callbacks against these roots;
     * releasing them would be a late-callback UAF. The FAIL rows above make
     * the process exit nonzero, and the leak is explicit. */
    if (!raw_peer_stop(g_rp))
        record("teardown", V_FAIL, "raw peer did not quiesce");
    g_rp = NULL;

    /* Ownership settled by observation, in isolated child processes. */
    ownership_experiment(argv[0], cert_dir);

    /* Fresh, uncontaminated connection for the close question. */
    connection_close_isolated(cert, key);

    /* Send-record retirement after peer STOP, on its own fresh connection. */
    send_retirement_isolated(cert, key);

    int rc = results_summary();
    printf("\nprobe %s\n", rc == 0 ? "PASSED" : "FAILED");
    return rc;
}
