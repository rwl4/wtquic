#ifndef WTQ_TEST_WT15_VECTORS_H
#define WTQ_TEST_WT15_VECTORS_H

/*
 * Shared draft-15 wire-vector table for the fixture tests.
 *
 * Each vector carries its committed wire bytes (built by the module
 * encoders where one exists, inline bytes for decode-only and negative
 * cases) plus a type tag that selects the validating codec. The same
 * table drives:
 *   - test_vectors_wt15: byte-identity with committed .bin files,
 *     decode + field assertions, re-encode byte-identity, --generate
 *   - test_truncation: exhaustive prefix + single-bit mutation sweeps
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt15_vec_type {
    WT15_SETTINGS = 1,    /* h3_settings payload */
    WT15_FRAME,           /* h3_frame header (+ opaque payload bytes) */
    WT15_CAPSULE,         /* capsule stream bytes */
    WT15_PREAMBLE_BIDI,   /* stream preamble, bidi expectation */
    WT15_PREAMBLE_UNI,    /* stream preamble, uni expectation */
    WT15_CONNECT_REQ,     /* QPACK field section, CONNECT request */
    WT15_CONNECT_RESP,    /* QPACK field section, CONNECT response */
    WT15_SF_LIST,         /* WT-Available-Protocols field value */
} wt15_vec_type_t;

#define WT15_MAX_WIRE 1200

typedef struct wt15_vector {
    const char *name;      /* fixture basename without .bin */
    wt15_vec_type_t type;
    const char *desc;
    bool expect_error;     /* negative vector: decode must fail cleanly */
    bool decode_only;      /* wire is not encoder output (non-minimal
                              varints, foreign encodings): skip encoder
                              byte-identity and re-encode identity */
    uint8_t wire[WT15_MAX_WIRE];
    size_t wire_len;
} wt15_vector_t;

/* Build the table (fills wire bytes via the module encoders where
 * applicable). Returns the vector count. Aborts on internal builder
 * failure — the table must always be constructible. */
size_t wt15_vectors_build(wt15_vector_t *out, size_t max);

#define WT15_MAX_VECTORS 40

/*
 * Validate one vector's wire bytes with its module codec:
 * decode + field assertions (+ re-encode byte-identity for encoder-
 * backed vectors). Returns the number of failures (0 = pass); appends
 * diagnostics to stderr.
 */
int wt15_vector_validate(const wt15_vector_t *v, const uint8_t *wire,
                         size_t wire_len);

/*
 * Feed a (possibly truncated or mutated) byte string to the vector's
 * codec and require a clean outcome: any documented status, no crash.
 * Returns the number of failures. For single-object incremental types
 * (capsule/preamble) a strict prefix must report NEED_MORE; frame
 * vectors may carry trailing payload bytes, so completing early is
 * legal for them.
 */
int wt15_vector_feed_hostile(const wt15_vector_t *v, const uint8_t *wire,
                             size_t wire_len, bool is_strict_prefix);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_TEST_WT15_VECTORS_H */
