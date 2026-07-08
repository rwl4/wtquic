#include <wtquic/wtquic.h>

#include "test_support.h"

#define FIRST 0x52e4a40fa8dbull
#define LAST (FIRST + 0xffffffffull + 0xffffffffull / 0x1e)

/* errmap_formula_known_points: spot values against the draft-15 formula
 * h3 = FIRST + n + n/0x1e. */
static void test_known_points(int *fp)
{
    int failures = 0;

    WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(0), FIRST);
    WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(1), FIRST + 1);
    WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(0x1d), FIRST + 0x1d);
    /* n = 0x1e crosses the first GREASE gap: h3 skips FIRST + 0x1e. */
    WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(0x1e), FIRST + 0x1f);
    WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(0xffffffffu), LAST);

    /* Every mapped value must avoid H3 GREASE codepoints (0x1f*N + 0x21). */
    for (uint32_t n = 0; n < 4096; n++) {
        uint64_t h3 = wtq_app_error_to_h3(n);
        WTQ_TEST_CHECK((h3 - 0x21) % 0x1f != 0);
    }

    *fp += failures;
}

/* errmap_roundtrip_exhaustive_low: all app errors < 2^16 roundtrip. */
static void test_roundtrip_low(int *fp)
{
    int failures = 0;

    for (uint32_t n = 0; n < 0x10000; n++) {
        uint32_t back = 0;
        WTQ_TEST_CHECK(wtq_h3_error_to_app(wtq_app_error_to_h3(n),
                                           &back) == WTQ_OK);
        if (back != n) {
            WTQ_TEST_CHECK_EQ_U64(back, n);
            break; /* one detailed failure is enough */
        }
    }

    *fp += failures;
}

/* errmap_roundtrip_sampled_high: strided + boundary samples over u32. */
static void test_roundtrip_high(int *fp)
{
    int failures = 0;
    const uint32_t samples[] = {
        0x10000, 0xffff0000u, 0xfffffffeu, 0xffffffffu,
        0x7fffffffu, 0x80000000u,
    };

    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        uint32_t back = 0;
        WTQ_TEST_CHECK(wtq_h3_error_to_app(wtq_app_error_to_h3(samples[i]),
                                           &back) == WTQ_OK);
        WTQ_TEST_CHECK_EQ_U64(back, samples[i]);
    }
    for (uint64_t n = 0; n <= 0xffffffffull; n += 0x10001) {
        uint32_t back = 0;
        uint64_t h3 = wtq_app_error_to_h3((uint32_t)n);
        WTQ_TEST_CHECK(wtq_h3_error_to_app(h3, &back) == WTQ_OK);
        if (back != (uint32_t)n) {
            WTQ_TEST_CHECK_EQ_U64(back, n);
            break;
        }
    }

    *fp += failures;
}

/* errmap_grease_gaps_unmappable: skipped wire codepoints reverse to
 * NOT_FOUND. */
static void test_grease_gaps(int *fp)
{
    int failures = 0;
    uint32_t back = 0;

    /* FIRST + 0x1e is the first skipped codepoint (see known-points). */
    WTQ_TEST_CHECK(wtq_h3_error_to_app(FIRST + 0x1e, &back) ==
                   WTQ_ERR_NOT_FOUND);

    /* Exhaustively: within the first 64 blocks every in-range h3 value is
     * either a clean roundtrip or NOT_FOUND on a GREASE codepoint. */
    for (uint64_t h3 = FIRST; h3 < FIRST + 64 * 0x1f; h3++) {
        wtq_result_t rc = wtq_h3_error_to_app(h3, &back);
        if (rc == WTQ_OK)
            WTQ_TEST_CHECK_EQ_HEX(wtq_app_error_to_h3(back), h3);
        else
            WTQ_TEST_CHECK((h3 - 0x21) % 0x1f == 0);
    }

    *fp += failures;
}

/* errmap_out_of_range: h3 codes outside the window are not app errors. */
static void test_out_of_range(int *fp)
{
    int failures = 0;
    uint32_t back = 0;

    WTQ_TEST_CHECK(wtq_h3_error_to_app(0, &back) == WTQ_ERR_NOT_FOUND);
    WTQ_TEST_CHECK(wtq_h3_error_to_app(FIRST - 1, &back) ==
                   WTQ_ERR_NOT_FOUND);
    WTQ_TEST_CHECK(wtq_h3_error_to_app(LAST + 1, &back) == WTQ_ERR_NOT_FOUND);
    WTQ_TEST_CHECK(wtq_h3_error_to_app(UINT64_MAX, &back) ==
                   WTQ_ERR_NOT_FOUND);
    WTQ_TEST_CHECK(wtq_h3_error_to_app(FIRST, NULL) == WTQ_ERR_INVALID_ARG);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_known_points(&failures);
    test_roundtrip_low(&failures);
    test_roundtrip_high(&failures);
    test_grease_gaps(&failures);
    test_out_of_range(&failures);

    WTQ_TEST_PASS("test_errcode_map");
    return failures;
}
