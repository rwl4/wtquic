#include <string.h>

#include "proto/sf_string.h"

#include "test_support.h"

#define SF(lit) { lit, sizeof(lit) - 1 }

static bool span_eq(wtq_sf_str_t s, const char *lit)
{
    return s.len == strlen(lit) &&
           (s.len == 0 || memcmp(s.data, lit, s.len) == 0);
}

/* item parse: WT-Protocol style values */
static void test_item_parse(int *fp)
{
    int failures = 0;
    char buf[64];
    wtq_sf_str_t v;

    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"moqt-18\"", 9, false, buf,
                                            sizeof(buf), &v) == WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "moqt-18"));

    /* leading/trailing SP tolerated per RFC 8941 */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("  \"a\"  ", 7, false, buf,
                                            sizeof(buf), &v) == WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "a"));

    /* escapes unescaped */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"a\\\"b\\\\c\"", 9, false,
                                            buf, sizeof(buf), &v) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "a\"b\\c"));

    /* parameters ignored (draft-15 MUST ignore) */
    const char with_params[] = "\"chat\";q=1;pref=\"x\";t=tok;b=?1;s=:YQ==:";
    WTQ_TEST_CHECK(wtq_sf_string_parse_item(with_params,
                                            sizeof(with_params) - 1, false,
                                            buf, sizeof(buf), &v) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "chat"));

    /* empty string is a valid sf-string (caller policy decides) */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"\"", 2, false, buf,
                                            sizeof(buf), &v) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(v.len, 0);

    /* trailing junk rejected */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"a\" x", 5, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);

    /* unterminated / bad escape / control char */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"abc", 4, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("\"a\\x\"", 5, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    const char ctrl[] = { '"', 'a', 0x01, '"' };
    WTQ_TEST_CHECK(wtq_sf_string_parse_item(ctrl, sizeof(ctrl), false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);

    /* wrong types are MALFORMED (ignore-the-field rule): token, integer,
     * boolean, byte sequence, inner list */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("moqt-18", 7, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("42", 2, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("?1", 2, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(wtq_sf_string_parse_item(":YQ==:", 6, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("(\"a\")", 5, false, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);

    /* lenient interop mode: bare token accepted as a string value */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("moqt-18", 7, true, buf,
                                            sizeof(buf), &v) == WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "moqt-18"));
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("webtransport-h3", 15, true,
                                            buf, sizeof(buf), &v) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK(span_eq(v, "webtransport-h3"));
    /* lenient still rejects things that are not tokens either */
    WTQ_TEST_CHECK(wtq_sf_string_parse_item("42", 2, true, buf,
                                            sizeof(buf), &v) ==
                   WTQ_SF_MALFORMED);

    *fp += failures;
}

/* list parse: WT-Available-Protocols style values */
static void test_list_parse(int *fp)
{
    int failures = 0;
    char buf[128];
    wtq_sf_str_t m[8];
    size_t n = 0;

    const char two[] = "\"moqt-18\", \"moqt-16\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(two, sizeof(two) - 1, false,
                                            buf, sizeof(buf), m, 8, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);
    WTQ_TEST_CHECK(span_eq(m[0], "moqt-18")); /* preference order kept */
    WTQ_TEST_CHECK(span_eq(m[1], "moqt-16"));

    /* no spaces / extra spaces both fine */
    const char tight[] = "\"a\",\"b\",\"c\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(tight, sizeof(tight) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 3);
    const char spaced[] = "  \"a\"  ,   \"b\" ";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(spaced, sizeof(spaced) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);

    /* member params ignored */
    const char params[] = "\"a\";x=1, \"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(params, sizeof(params) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);

    /* duplicates accepted at the parse layer */
    const char dup[] = "\"a\", \"a\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(dup, sizeof(dup) - 1, false,
                                            buf, sizeof(buf), m, 8, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);

    /* empty input => empty list, count 0 */
    WTQ_TEST_CHECK(wtq_sf_string_parse_list("", 0, false, buf, sizeof(buf),
                                            m, 8, &n) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 0);
    WTQ_TEST_CHECK(wtq_sf_string_parse_list("   ", 3, false, buf,
                                            sizeof(buf), m, 8, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 0);

    /* missing member and trailing comma are malformed */
    const char misses[] = "\"a\",,\"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(misses, sizeof(misses) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_MALFORMED);
    const char trail[] = "\"a\",";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(trail, sizeof(trail) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_MALFORMED);
    const char trail_sp[] = "\"a\", ";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(trail_sp, sizeof(trail_sp) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_MALFORMED);

    /* any non-String member poisons the whole field (strict) */
    const char mixed[] = "\"a\", tok, \"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(mixed, sizeof(mixed) - 1,
                                            false, buf, sizeof(buf), m, 8,
                                            &n) == WTQ_SF_MALFORMED);
    /* ...but lenient mode accepts the picowt-style bare-token list */
    const char bare[] = "moqt-18, moqt-16";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(bare, sizeof(bare) - 1, true,
                                            buf, sizeof(buf), m, 8, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);
    WTQ_TEST_CHECK(span_eq(m[0], "moqt-18"));

    /* capacity: member array too small */
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(tight, sizeof(tight) - 1,
                                            false, buf, sizeof(buf), m, 2,
                                            &n) == WTQ_SF_BUFFER);
    /* capacity: out_buf too small */
    char tiny[2];
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(two, sizeof(two) - 1, false,
                                            tiny, sizeof(tiny), m, 8,
                                            &n) == WTQ_SF_BUFFER);

    *fp += failures;
}

/* encoding: canonical bytes, escaping, bounds */
static void test_encode(int *fp)
{
    int failures = 0;
    char buf[128];
    size_t out_len = 0;

    WTQ_TEST_CHECK(wtq_sf_string_encode_item("moqt-18", 7, buf, sizeof(buf),
                                             &out_len) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 9);
    WTQ_TEST_CHECK(memcmp(buf, "\"moqt-18\"", 9) == 0);

    /* escaping */
    WTQ_TEST_CHECK(wtq_sf_string_encode_item("a\"b\\c", 5, buf, sizeof(buf),
                                             &out_len) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 9);
    WTQ_TEST_CHECK(memcmp(buf, "\"a\\\"b\\\\c\"", 9) == 0);

    /* canonical list serialization: ", " separator */
    wtq_sf_str_t members[2] = { SF("moqt-18"), SF("moqt-16") };
    WTQ_TEST_CHECK(wtq_sf_string_encode_list(members, 2, buf, sizeof(buf),
                                             &out_len) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 20);
    WTQ_TEST_CHECK(memcmp(buf, "\"moqt-18\", \"moqt-16\"", 20) == 0);

    /* roundtrip through the parser */
    wtq_sf_str_t m[4];
    size_t n = 0;
    char pbuf[64];
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(buf, out_len, false, pbuf,
                                            sizeof(pbuf), m, 4, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);
    WTQ_TEST_CHECK(span_eq(m[0], "moqt-18"));
    WTQ_TEST_CHECK(span_eq(m[1], "moqt-16"));

    /* invalid bytes rejected */
    WTQ_TEST_CHECK(wtq_sf_string_encode_item("a\x01", 2, buf, sizeof(buf),
                                             &out_len) == WTQ_SF_MALFORMED);
    WTQ_TEST_CHECK(!wtq_sf_string_valid("\xc3\xa9", 2)); /* non-ASCII */
    WTQ_TEST_CHECK(wtq_sf_string_valid("moqt-18", 7));
    WTQ_TEST_CHECK(wtq_sf_string_valid("a\"b\\c", 5)); /* escapable */

    /* empty list must be omitted, not encoded */
    WTQ_TEST_CHECK(wtq_sf_string_encode_list(members, 0, buf, sizeof(buf),
                                             &out_len) == WTQ_SF_MALFORMED);

    /* buffer-too-small leaves output untouched (item and list) */
    for (size_t cap = 0; cap < 9; cap++) {
        char small[16];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_sf_string_encode_item("moqt-18", 7, small, cap,
                                                 &out_len) ==
                       WTQ_SF_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == (char)0xEE);
    }
    {
        char small[8];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_sf_string_encode_list(members, 2, small,
                                                 sizeof(small), &out_len) ==
                       WTQ_SF_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == (char)0xEE);
    }

    *fp += failures;
}

/* selection: first client-offered token the server supports */
static void test_select(int *fp)
{
    int failures = 0;
    wtq_sf_str_t offered[3] = { SF("moqt-18"), SF("moqt-16"), SF("chat") };
    wtq_sf_str_t supported[2] = { SF("moqt-16"), SF("moqt-18") };
    size_t idx = 999;

    /* client preference order wins: moqt-18 is offered first */
    WTQ_TEST_CHECK(wtq_sf_string_select(offered, 3, supported, 2, &idx));
    WTQ_TEST_CHECK_EQ_SIZE(idx, 0);

    /* server supporting only the second offer */
    wtq_sf_str_t only16[1] = { SF("moqt-16") };
    WTQ_TEST_CHECK(wtq_sf_string_select(offered, 3, only16, 1, &idx));
    WTQ_TEST_CHECK_EQ_SIZE(idx, 1);

    /* no overlap */
    wtq_sf_str_t other[1] = { SF("h3-dgram") };
    WTQ_TEST_CHECK(!wtq_sf_string_select(offered, 3, other, 1, &idx));

    /* case-sensitive */
    wtq_sf_str_t upper[1] = { SF("MOQT-18") };
    WTQ_TEST_CHECK(!wtq_sf_string_select(offered, 3, upper, 1, &idx));

    /* empty offer list */
    WTQ_TEST_CHECK(!wtq_sf_string_select(offered, 0, supported, 2, &idx));

    *fp += failures;
}

/* parameters must PARSE per RFC 8941 strict grammar before being
 * ignored: malformed param values poison the field */
static void test_param_strictness(int *fp)
{
    int failures = 0;
    char buf[64];
    wtq_sf_str_t v;
    wtq_sf_str_t m[4];
    size_t n = 0;

    /* invalid: bare minus, trailing dot, double dot, oversized integer
     * (>15 digits), >3 fraction digits, >12 integer digits in a decimal,
     * garbage byte sequence, unterminated byte sequence */
    static const char *const bad_items[] = {
        "\"moqt-18\";p=-",
        "\"a\";p=1.",
        "\"a\";p=1.2.3",
        "\"a\";p=1234567890123456",      /* 16 digits */
        "\"a\";p=1.2345",                /* 4 frac digits */
        "\"a\";p=1234567890123.1",       /* 13 int digits in decimal */
        "\"a\";p=:@@@:",
        "\"a\";p=:YQ==",
    };
    for (size_t i = 0; i < sizeof(bad_items) / sizeof(bad_items[0]); i++)
        WTQ_TEST_CHECK(wtq_sf_string_parse_item(bad_items[i],
                                                strlen(bad_items[i]), false,
                                                buf, sizeof(buf), &v) ==
                       WTQ_SF_MALFORMED);

    /* the same poison propagates through the list path */
    const char bad_list[] = "\"a\";p=-, \"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(bad_list, sizeof(bad_list) - 1,
                                            false, buf, sizeof(buf), m, 4,
                                            &n) == WTQ_SF_MALFORMED);

    /* valid params of every type still parse and are ignored */
    static const char *const good_items[] = {
        "\"a\";p=-5",
        "\"a\";p=1.25",
        "\"a\";p=123456789012345",       /* 15 digits */
        "\"a\";p=123456789012.345",      /* 12 int + 3 frac */
        "\"a\";p=:YQ==:",
        "\"a\";p=:aGVsbG8+/w==:",
        "\"a\";p",                       /* bare key, no value */
    };
    for (size_t i = 0; i < sizeof(good_items) / sizeof(good_items[0]); i++) {
        WTQ_TEST_CHECK(wtq_sf_string_parse_item(good_items[i],
                                                strlen(good_items[i]),
                                                false, buf, sizeof(buf),
                                                &v) == WTQ_SF_OK);
        WTQ_TEST_CHECK(span_eq(v, "a") || span_eq(v, "moqt-18"));
    }

    *fp += failures;
}

/* RFC 8941 s4.2.1: OWS (SP / HTAB) is legal around list commas; leading
 * field whitespace remains SP-only per s4.2 */
static void test_list_ows(int *fp)
{
    int failures = 0;
    char buf[64];
    wtq_sf_str_t m[4];
    size_t n = 0;

    const char htab[] = "\"a\"\t,\t\"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(htab, sizeof(htab) - 1, false,
                                            buf, sizeof(buf), m, 4, &n) ==
                   WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);
    WTQ_TEST_CHECK(span_eq(m[0], "a"));
    WTQ_TEST_CHECK(span_eq(m[1], "b"));

    const char mixed_ws[] = "\"a\" \t, \t \"b\"";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(mixed_ws, sizeof(mixed_ws) - 1,
                                            false, buf, sizeof(buf), m, 4,
                                            &n) == WTQ_SF_OK);
    WTQ_TEST_CHECK_EQ_SIZE(n, 2);

    /* trailing comma followed by HTAB is still a trailing comma */
    const char trail_tab[] = "\"a\",\t";
    WTQ_TEST_CHECK(wtq_sf_string_parse_list(trail_tab,
                                            sizeof(trail_tab) - 1, false,
                                            buf, sizeof(buf), m, 4, &n) ==
                   WTQ_SF_MALFORMED);

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_item_parse(&failures);
    test_list_parse(&failures);
    test_encode(&failures);
    test_select(&failures);
    test_param_strictness(&failures);
    test_list_ows(&failures);

    WTQ_TEST_PASS("test_sf_string");
    return failures;
}
