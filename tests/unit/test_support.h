#ifndef WTQ_TEST_SUPPORT_H
#define WTQ_TEST_SUPPORT_H

/*
 * Minimal unit-test assertion macros. Each macro assumes a local
 * `int failures;` in scope and increments it on failure — tests keep
 * running and report every failure, never early-return.
 */

#include <inttypes.h>
#include <stdio.h>

#define WTQ_TEST_CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        failures++; \
    } \
} while (0)

#define WTQ_TEST_CHECK_EQ_INT(actual, expected) do { \
    int wtq_a_ = (int)(actual); \
    int wtq_e_ = (int)(expected); \
    if (wtq_a_ != wtq_e_) { \
        fprintf(stderr, "FAIL: %s:%d: %s == %d, expected %d\n", \
                __FILE__, __LINE__, #actual, wtq_a_, wtq_e_); \
        failures++; \
    } \
} while (0)

#define WTQ_TEST_CHECK_EQ_U64(actual, expected) do { \
    uint64_t wtq_a_ = (uint64_t)(actual); \
    uint64_t wtq_e_ = (uint64_t)(expected); \
    if (wtq_a_ != wtq_e_) { \
        fprintf(stderr, "FAIL: %s:%d: %s == %" PRIu64 ", expected %" PRIu64 \
                "\n", __FILE__, __LINE__, #actual, wtq_a_, wtq_e_); \
        failures++; \
    } \
} while (0)

#define WTQ_TEST_CHECK_EQ_HEX(actual, expected) do { \
    uint64_t wtq_a_ = (uint64_t)(actual); \
    uint64_t wtq_e_ = (uint64_t)(expected); \
    if (wtq_a_ != wtq_e_) { \
        fprintf(stderr, "FAIL: %s:%d: %s == 0x%" PRIx64 ", expected 0x%" \
                PRIx64 "\n", __FILE__, __LINE__, #actual, wtq_a_, wtq_e_); \
        failures++; \
    } \
} while (0)

#define WTQ_TEST_CHECK_EQ_SIZE(actual, expected) do { \
    size_t wtq_a_ = (size_t)(actual); \
    size_t wtq_e_ = (size_t)(expected); \
    if (wtq_a_ != wtq_e_) { \
        fprintf(stderr, "FAIL: %s:%d: %s == %zu, expected %zu\n", \
                __FILE__, __LINE__, #actual, wtq_a_, wtq_e_); \
        failures++; \
    } \
} while (0)

#define WTQ_TEST_PASS(name) do { \
    if (failures == 0) \
        printf("PASS: %s\n", (name)); \
} while (0)

#endif /* WTQ_TEST_SUPPORT_H */
