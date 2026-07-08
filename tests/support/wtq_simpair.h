#ifndef WTQ_TEST_SIMPAIR_H
#define WTQ_TEST_SIMPAIR_H

/*
 * Deterministic engine pair.
 *
 * Two engines over recording fake drivers; the pair owns the "wire":
 * driver ops append into the fake stream logs, and step() delivers the
 * undelivered bytes into the peer engine in seeded chunks (per-stream
 * order always preserved; chunk boundaries vary by seed). Virtual time
 * advances with each step; no clock is ever read.
 *
 * Every delivery and every semantic engine event appends a line to the
 * trace buffer; wtq_simpair_trace_hash() FNV-1a-hashes it. Same seed →
 * identical trace, byte for byte. This is the seam the seeded
 * trace-hash runners grow from.
 */

#include "fake_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_SIMPAIR_TRACE_CAP (32 * 1024)

typedef struct wtq_simpair wtq_simpair_t;

typedef struct wtq_simpair_side {
    struct wtq_driver drv;
    wtq_conn_t *conn;
    wtq_simpair_t *sp;
    char label; /* 'c' or 's' */
    int settings_events;
    bool wt_supported;
    int error_events;
    uint64_t last_error;
    int established_events;
    char selected[64];
    size_t selected_len;
    int rejected_events;
    uint16_t rejected_status;
    int failed_events;
    int failed_reason;
    /* session runtime */
    int closed_events;
    uint32_t closed_code;
    char closed_reason[128];
    size_t closed_reason_len;
    bool closed_clean;
    int draining_events;
    /* WT streams: opened/received oracle */
    int wt_opened_events;
    wtq_estream_t *wt_last_es;
    bool wt_last_bidi;
    int wt_data_events;
    uint8_t wt_data[512]; /* concatenation of all received payload */
    size_t wt_data_len;
    int wt_fin_events;
    int wt_reset_events;
    int wt_stop_events;
    int send_completions;
    int send_cancels;
    int dgram_events;
    uint8_t dgram_data[256]; /* concatenation of received payloads */
    size_t dgram_data_len;
    /* engine stream ctx for each peer-side fake stream slot */
    wtq_estream_t *es_for_slot[FAKE_MAX_STREAMS];
} wtq_simpair_side_t;

struct wtq_simpair {
    uint64_t seed;
    uint64_t now_us;
    size_t step;
    wtq_simpair_side_t c;
    wtq_simpair_side_t s;
    char trace[WTQ_SIMPAIR_TRACE_CAP];
    size_t trace_len;
    bool trace_overflow;
    /* Non-OK engine-input returns observed during delivery. Expected
     * to be 0 in happy-path scenarios; protocol-close scenarios assert
     * their expected counts so failures can never vanish silently. */
    int engine_errors;
};

/* Create both engines and start them (control/QPACK streams open). */
int wtq_simpair_create(wtq_simpair_t *sp, uint64_t seed);
/* As wtq_simpair_create, but each side latches an explicit WebTransport wire
 * profile (wtq_h3_wt_profile_t: 0 = current draft-16, 1 = D13/14 compat). The
 * caller must pass the client's profile again in wtq_simpair_client_connect so
 * the CONNECT token matches the SETTINGS the client emitted at start. */
int wtq_simpair_create_profiles(wtq_simpair_t *sp, uint64_t seed,
                                int client_profile, int server_profile);
void wtq_simpair_destroy(wtq_simpair_t *sp);

/* Deliver matured wire bytes both directions once. Returns the number
 * of bytes+events delivered (0 = quiescent). */
size_t wtq_simpair_step(wtq_simpair_t *sp);

/* Step until quiescent; returns total steps taken (caps at max_steps). */
size_t wtq_simpair_run_until_quiescent(wtq_simpair_t *sp,
                                       size_t max_steps);

uint64_t wtq_simpair_trace_hash(const wtq_simpair_t *sp);

/* Convenience wrappers so scenarios read naturally. side is 'c'/'s'.
 * Each traces the app action so scenario timelines stay hashable. */
wtq_result_t wtq_simpair_client_connect(wtq_simpair_t *sp,
                                        const wtq_client_connect_cfg_t *c);
wtq_result_t wtq_simpair_server_paths(wtq_simpair_t *sp,
                                      const wtq_server_path_cfg_t *paths,
                                      size_t count);
wtq_result_t wtq_simpair_session_close(wtq_simpair_t *sp, char side,
                                       uint32_t code, const char *reason);
wtq_result_t wtq_simpair_session_drain(wtq_simpair_t *sp, char side);
wtq_result_t wtq_simpair_wt_open(wtq_simpair_t *sp, char side, bool bidi,
                                 wtq_estream_t **es_out);
/* The send cookie is the estream itself (completion identity only). */
wtq_result_t wtq_simpair_wt_send(wtq_simpair_t *sp, char side,
                                 wtq_estream_t *es, const void *data,
                                 size_t len, bool fin);
wtq_result_t wtq_simpair_dgram_send(wtq_simpair_t *sp, char side,
                                    const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_SIMPAIR_H */
