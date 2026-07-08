#ifndef WTQ_TEST_APIPAIR_H
#define WTQ_TEST_APIPAIR_H

/*
 * Deterministic conformance rail: two PUBLIC-API sessions (client and
 * server) talking through fake transports, with a seeded delivery pump
 * that the scenarios drive entirely through wtq_session_* /
 * wtq_stream_*. The engine appears only inside the pump (the fake
 * backend) — never in scenario logic.
 *
 * Two hashes:
 *   trace_hash    — every line, including per-delivery chunk sizes;
 *                   same seed -> byte-identical, so it pins delivery
 *                   reproducibility.
 *   semantic_hash — app events + actions + engine errors only, no
 *                   chunk/timing lines; equal ACROSS seeds for a
 *                   deterministic scenario, so it pins the outcome
 *                   independent of how bytes were chopped.
 *
 * engine_errors counts every non-OK engine-input return the pump sees
 * (bytes / datagrams / resets). Protocol-violation scenarios assert
 * their expected count; happy scenarios assert 0. Nothing is swallowed.
 */

#include <wtquic/session.h>
#include <wtquic/stream.h>

#include "fake_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_APIPAIR_TRACE_CAP (48 * 1024)

typedef struct wtq_apipair wtq_apipair_t;

typedef struct wtq_apipair_side {
    struct wtq_driver drv;
    wtq_session_t *s;
    wtq_apipair_t *pair;
    char label; /* 'c' or 's' */

    /* captured session events */
    int established;
    int refused;
    uint16_t refused_status;
    int failed;
    int failed_reason;
    int draining;
    int closed;
    uint32_t closed_code;
    uint8_t closed_reason[128];
    size_t closed_reason_len;
    bool closed_clean;
    char sub[64];
    size_t sub_len;

    /* captured stream events */
    int stream_opened;
    wtq_stream_t *last_stream;
    bool last_stream_bidi;
    int stream_closed;
    int stream_reset;
    uint32_t last_reset_code;
    int stream_stop;
    uint32_t last_stop_code;
    uint8_t data[512];
    size_t data_len;
    int data_events;
    int fin_events;

    /* datagrams + completions */
    int dgram_events;
    uint8_t dgram[256];
    size_t dgram_len;
    int send_completions;
    int send_cancels;

    /* behavior flags a scenario sets before the pump runs */
    bool echo_bidi;        /* on_stream_data(fin,bidi) -> "pong" + FIN */
    bool close_in_data;    /* on_stream_data -> wtq_session_close */
    bool stop_in_data;     /* on_stream_data -> wtq_stream_stop_sending */
    uint32_t behavior_code;/* app code used by the flags above */
    bool retain_streams;   /* add_ref every opened stream */

    bool fatal_traced;     /* the H3 close code was already recorded */
    /* per-slot engine ctx mirror, for the pump's linkage */
    wtq_estream_t *es_for_slot[FAKE_MAX_STREAMS];
    /* retained handles (for retain_streams teardown) */
    wtq_stream_t *retained[FAKE_MAX_STREAMS];
    size_t retained_count;
} wtq_apipair_side_t;

struct wtq_apipair {
    uint64_t seed;
    size_t step;
    uint64_t now_us;
    wtq_apipair_side_t c;
    wtq_apipair_side_t s;
    int engine_errors;
    /* both sessions allocate through this counting allocator, so a
     * scenario can snapshot steady-state allocation growth */
    int allocs;
    int frees;
    wtq_alloc_t alloc;

    char trace[WTQ_APIPAIR_TRACE_CAP];
    size_t trace_len;
    char sem[WTQ_APIPAIR_TRACE_CAP];
    size_t sem_len;
    bool overflow;
};

/* Bring both public sessions up (control planes started). */
int wtq_apipair_create(wtq_apipair_t *p, uint64_t seed);
/* Same, but the sessions allocate through `alloc` (an OOM sweep's
 * faulting allocator) instead of the pair's built-in counting one.
 * Partial construction (server fails after client succeeds) tears the
 * client back down; a failed create leaves both session pointers NULL
 * and is safe to destroy. */
int wtq_apipair_create_alloc(wtq_apipair_t *p, uint64_t seed,
                             const wtq_alloc_t *alloc);
void wtq_apipair_destroy(wtq_apipair_t *p);

/* Deliver all matured wire (both directions) to quiescence, tracing
 * deliveries and counting engine-input errors. */
size_t wtq_apipair_pump(wtq_apipair_t *p);

uint64_t wtq_apipair_trace_hash(const wtq_apipair_t *p);
uint64_t wtq_apipair_semantic_hash(const wtq_apipair_t *p);

/* A semantic trace line (recorded in BOTH hashes). Scenarios call this
 * to mark app actions so timelines are legible and hashable. */
void wtq_apipair_mark(wtq_apipair_t *p, const char *fmt, ...);

/* Inject raw bytes as a peer-opened stream on the given side's engine
 * (for malformed / split-boundary scenarios that can't be expressed
 * through the public API). is_bidi picks the stream kind; the bytes
 * are delivered in one shot unless chunk > 0. */
void wtq_apipair_inject_stream(wtq_apipair_t *p, char side, uint64_t id,
                               bool is_bidi, const uint8_t *bytes,
                               size_t len, bool fin, size_t chunk);

/* Inject a raw datagram into a side's engine. */
wtq_result_t wtq_apipair_inject_datagram(wtq_apipair_t *p, char side,
                                         const uint8_t *bytes, size_t len);

/*
 * Counted raw engine inputs on an already-opened peer/local stream —
 * for scenarios that must feed the engine directly (a bare FIN on the
 * CONNECT stream, a peer RESET/STOP, a transport close). EVERY one is
 * wrapped in the backend enter/leave bracket, counts non-OK returns
 * into engine_errors, records the H3 close code semantically on a
 * fatal, and honors leave()'s destroy signal. es must be a live engine
 * context obtained from injection or the fake driver.
 */
wtq_result_t wtq_apipair_deliver(wtq_apipair_t *p, char side,
                                 wtq_estream_t *es, const uint8_t *data,
                                 size_t len, bool fin);

/*
 * Seeded-chunk variants of the injection/delivery paths: the payload is
 * split into 1..8-byte chunks at boundaries derived from the pair's
 * seed, so each seed exercises different split points reproducibly.
 * nonce distinguishes independent split streams within one scenario.
 * Same accounting as the plain helpers (count/trace/note-fatal/leave).
 * A len > 0 with a NULL pointer is rejected without touching the engine.
 */
void wtq_apipair_inject_stream_seeded(wtq_apipair_t *p, char side,
                                      uint64_t id, bool is_bidi,
                                      const uint8_t *bytes, size_t len,
                                      bool fin, uint64_t nonce);
wtq_result_t wtq_apipair_deliver_seeded(wtq_apipair_t *p, char side,
                                        wtq_estream_t *es,
                                        const uint8_t *data, size_t len,
                                        bool fin, uint64_t nonce);
wtq_result_t wtq_apipair_reset(wtq_apipair_t *p, char side,
                               wtq_estream_t *es, uint64_t quic_err);
wtq_result_t wtq_apipair_stop(wtq_apipair_t *p, char side,
                              wtq_estream_t *es, uint64_t quic_err);
void wtq_apipair_conn_closed(wtq_apipair_t *p, char side, uint64_t err);

/* The engine connection for a side (harness/pump use only). */
wtq_conn_t *wtq_apipair_conn(wtq_apipair_t *p, char side);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_APIPAIR_H */
