#include <string.h>

#include "proto/qpack_static.h"

#include "test_support.h"

static bool field_is(const wtq_qpack_field_t *f, const char *name,
                     const char *value)
{
    return f->name_len == strlen(name) &&
           memcmp(f->name, name, f->name_len) == 0 &&
           f->value_len == strlen(value) &&
           memcmp(f->value, value, f->value_len) == 0;
}

/* prefixed integers: boundaries, continuation, truncation, overflow */
static void test_integers(int *fp)
{
    int failures = 0;
    uint8_t buf[16];
    size_t out_len = 0;
    uint64_t v = 0;
    size_t consumed = 0;

    /* single byte below prefix max (7-bit prefix: max 126 fits) */
    WTQ_TEST_CHECK(wtq_qpack_int_encode(10, 0x80, 7, buf, sizeof(buf),
                                        &out_len) == WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 1);
    WTQ_TEST_CHECK(buf[0] == 0x8a);
    WTQ_TEST_CHECK(wtq_qpack_int_decode(buf, 1, 7, &v, &consumed) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_U64(v, 10);

    /* exactly prefix max starts continuation (RFC 7541 C.1.2: 1337 with
     * 5-bit prefix = 1f 9a 0a) */
    WTQ_TEST_CHECK(wtq_qpack_int_encode(1337, 0x00, 5, buf, sizeof(buf),
                                        &out_len) == WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 3);
    WTQ_TEST_CHECK(buf[0] == 0x1f && buf[1] == 0x9a && buf[2] == 0x0a);
    WTQ_TEST_CHECK(wtq_qpack_int_decode(buf, 3, 5, &v, &consumed) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_U64(v, 1337);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 3);

    /* value exactly prefix max - 1 stays single byte; prefix max needs
     * a zero continuation byte */
    WTQ_TEST_CHECK(wtq_qpack_int_encode(30, 0x00, 5, buf, sizeof(buf),
                                        &out_len) == WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 1);
    WTQ_TEST_CHECK(wtq_qpack_int_encode(31, 0x00, 5, buf, sizeof(buf),
                                        &out_len) == WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(out_len, 2);
    WTQ_TEST_CHECK(buf[0] == 0x1f && buf[1] == 0x00);

    /* truncation at every byte of the 1337 encoding */
    const uint8_t enc1337[] = { 0x1f, 0x9a, 0x0a };
    for (size_t plen = 0; plen < sizeof(enc1337); plen++)
        WTQ_TEST_CHECK(wtq_qpack_int_decode(enc1337, plen, 5, &v,
                                            &consumed) ==
                       WTQ_QPACK_NEED_MORE);

    /* overflow: 62-bit cap exceeded via long continuation */
    const uint8_t huge[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0x7f };
    WTQ_TEST_CHECK(wtq_qpack_int_decode(huge, sizeof(huge), 5, &v,
                                        &consumed) == WTQ_QPACK_MALFORMED);

    /* max legal value roundtrips */
    WTQ_TEST_CHECK(wtq_qpack_int_encode((UINT64_C(1) << 62) - 1, 0x00, 5,
                                        buf, sizeof(buf), &out_len) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(wtq_qpack_int_decode(buf, out_len, 5, &v, &consumed) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_U64(v, (UINT64_C(1) << 62) - 1);
    WTQ_TEST_CHECK(wtq_qpack_int_encode(UINT64_C(1) << 62, 0x00, 5, buf,
                                        sizeof(buf), &out_len) ==
                   WTQ_QPACK_RANGE);

    /* encode untouched-on-BUFFER */
    for (size_t cap = 0; cap < 3; cap++) {
        uint8_t small[8];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_qpack_int_encode(1337, 0x00, 5, small, cap,
                                            &out_len) == WTQ_QPACK_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == 0xEE);
    }

    *fp += failures;
}

/* static table: count, spot values, roundtrips, exact lookups */
static void test_static_table(int *fp)
{
    int failures = 0;
    const char *name;
    const char *value;
    size_t nlen;
    size_t vlen;

    /* spot RFC 9204 Appendix A values */
    WTQ_TEST_CHECK(wtq_qpack_static_get(0, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 10 && memcmp(name, ":authority", 10) == 0);
    WTQ_TEST_CHECK_EQ_SIZE(vlen, 0);
    WTQ_TEST_CHECK(wtq_qpack_static_get(1, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 5 && memcmp(name, ":path", 5) == 0);
    WTQ_TEST_CHECK(vlen == 1 && value[0] == '/');
    WTQ_TEST_CHECK(wtq_qpack_static_get(15, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 7 && memcmp(name, ":method", 7) == 0);
    WTQ_TEST_CHECK(vlen == 7 && memcmp(value, "CONNECT", 7) == 0);
    WTQ_TEST_CHECK(wtq_qpack_static_get(23, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 7 && memcmp(name, ":scheme", 7) == 0);
    WTQ_TEST_CHECK(vlen == 5 && memcmp(value, "https", 5) == 0);
    WTQ_TEST_CHECK(wtq_qpack_static_get(25, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 7 && memcmp(name, ":status", 7) == 0);
    WTQ_TEST_CHECK(vlen == 3 && memcmp(value, "200", 3) == 0);
    WTQ_TEST_CHECK(wtq_qpack_static_get(90, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(nlen == 6 && memcmp(name, "origin", 6) == 0);

    /* out of range */
    WTQ_TEST_CHECK(!wtq_qpack_static_get(99, &name, &nlen, &value, &vlen));
    WTQ_TEST_CHECK(!wtq_qpack_static_get(UINT64_MAX, &name, &nlen, &value,
                                         &vlen));

    /* every index roundtrips through exact lookup (first match may be a
     * lower duplicate name+value — assert the found index maps back to
     * identical bytes) */
    for (uint64_t i = 0; i < WTQ_QPACK_STATIC_COUNT; i++) {
        WTQ_TEST_CHECK(wtq_qpack_static_get(i, &name, &nlen, &value,
                                            &vlen));
        int found = wtq_qpack_static_find(name, nlen, value, vlen);
        WTQ_TEST_CHECK(found >= 0);
        const char *n2;
        const char *v2;
        size_t nl2;
        size_t vl2;
        WTQ_TEST_CHECK(wtq_qpack_static_get((uint64_t)found, &n2, &nl2,
                                            &v2, &vl2));
        WTQ_TEST_CHECK(nl2 == nlen && memcmp(n2, name, nlen) == 0);
        WTQ_TEST_CHECK(vl2 == vlen && memcmp(v2, value, vlen) == 0);
    }

    /* exact lookups for the connect set */
    WTQ_TEST_CHECK_EQ_INT(wtq_qpack_static_find(":method", 7, "CONNECT", 7),
                          15);
    WTQ_TEST_CHECK_EQ_INT(wtq_qpack_static_find(":scheme", 7, "https", 5),
                          23);
    WTQ_TEST_CHECK_EQ_INT(wtq_qpack_static_find(":status", 7, "200", 3),
                          25);
    WTQ_TEST_CHECK_EQ_INT(wtq_qpack_static_find(":path", 5, "/", 1), 1);
    WTQ_TEST_CHECK_EQ_INT(wtq_qpack_static_find(":method", 7, "PATCH", 5),
                          -1);
    WTQ_TEST_CHECK(wtq_qpack_static_find_name(":path", 5) == 1);
    WTQ_TEST_CHECK(wtq_qpack_static_find_name(":protocol", 9) == -1);
    WTQ_TEST_CHECK(wtq_qpack_static_find_name(":authority", 10) == 0);

    *fp += failures;
}

/* the field-section prefix contract */
static void test_prefix(int *fp)
{
    int failures = 0;
    wtq_qpack_field_t fields[4];
    size_t count = 99;
    char scratch[64];

    const uint8_t empty[] = { 0x00, 0x00 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(empty, sizeof(empty), fields,
                                            4, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(count, 0);

    const uint8_t bad_ric[] = { 0x01, 0x00 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(bad_ric, 2, fields, 4, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    const uint8_t bad_sign[] = { 0x00, 0x80 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(bad_sign, 2, fields, 4, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    const uint8_t bad_base[] = { 0x00, 0x01 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(bad_base, 2, fields, 4, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    const uint8_t trunc1[] = { 0x00 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(trunc1, 1, fields, 4, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    WTQ_TEST_CHECK(wtq_qpack_decode_section(NULL, 0, fields, 4, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);

    *fp += failures;
}

/* decode: indexed, name-ref literal, literal-literal, Huffman, mixed */
static void test_decode(int *fp)
{
    int failures = 0;
    wtq_qpack_field_t fields[8];
    size_t count = 0;
    char scratch[256];

    /* indexed static :method CONNECT (0xc0 | 15) and :status 200 */
    const uint8_t idx_connect[] = { 0x00, 0x00, 0xcf };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(idx_connect, 3, fields, 8,
                                            &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(count, 1);
    WTQ_TEST_CHECK(field_is(&fields[0], ":method", "CONNECT"));

    const uint8_t idx_status[] = { 0x00, 0x00, 0xd9 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(idx_status, 3, fields, 8,
                                            &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":status", "200"));

    /* literal with static name ref: :path = /moq (name idx 1) */
    const uint8_t lit_path[] = { 0x00, 0x00, 0x51, 0x04, '/', 'm', 'o',
                                 'q' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(lit_path, sizeof(lit_path),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":path", "/moq"));

    /* literal with literal name: :protocol = webtransport
     * (3-bit prefix: namelen 9 = 7 + cont 2) */
    const uint8_t lit_proto[] = { 0x00, 0x00, 0x27, 0x02, ':', 'p', 'r',
                                  'o', 't', 'o', 'c', 'o', 'l', 0x0c,
                                  'w', 'e', 'b', 't', 'r', 'a', 'n', 's',
                                  'p', 'o', 'r', 't' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(lit_proto, sizeof(lit_proto),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":protocol", "webtransport"));
    WTQ_TEST_CHECK(!fields[0].never_index);

    /* never-index bit recorded on literal-literal (N = 0x10) */
    const uint8_t lit_ni[] = { 0x00, 0x00, 0x31, 'x', 0x01, 'y' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(lit_ni, sizeof(lit_ni), fields,
                                            8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], "x", "y"));
    WTQ_TEST_CHECK(fields[0].never_index);

    /* WT headers as raw value bytes (quoted sf-strings inside) */
    const char wtap_name[] = "wt-available-protocols";
    const char wtap_value[] = "\"moqt-18\", \"moqt-17\"";
    uint8_t wtap[64];
    size_t off = 0;
    wtap[off++] = 0x00;
    wtap[off++] = 0x00;
    wtap[off++] = 0x27; /* literal-literal, namelen 7+ */
    wtap[off++] = (uint8_t)(strlen(wtap_name) - 7);
    memcpy(wtap + off, wtap_name, strlen(wtap_name));
    off += strlen(wtap_name);
    wtap[off++] = (uint8_t)strlen(wtap_value);
    memcpy(wtap + off, wtap_value, strlen(wtap_value));
    off += strlen(wtap_value);
    WTQ_TEST_CHECK(wtq_qpack_decode_section(wtap, off, fields, 8, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], wtap_name, wtap_value));

    /* Huffman value via static name ref: :path = "private"
     * (RFC 7541 C.6.1: ae c3 77 1a 4b) */
    const uint8_t huff_val[] = { 0x00, 0x00, 0x51, 0x85, 0xae, 0xc3, 0x77,
                                 0x1a, 0x4b };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(huff_val, sizeof(huff_val),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":path", "private"));

    /* Huffman literal name (H bit 0x08): "www.example.com" as a name
     * (RFC 7541 C.4.1: f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff, 12 bytes) */
    const uint8_t huff_name[] = { 0x00, 0x00, 0x2f, 0x05, 0xf1, 0xe3, 0xc2,
                                  0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
                                  0xf4, 0xff, 0x01, 'z' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(huff_name, sizeof(huff_name),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], "www.example.com", "z"));

    /* mixed CONNECT-ish block decodes in order */
    const uint8_t mixed[] = { 0x00, 0x00,
                              0xcf,                        /* :method CONNECT */
                              0xd7,                        /* :scheme https */
                              0x50, 0x03, 'w', 't', 'q',   /* :authority wtq */
                              0x51, 0x04, '/', 'm', 'o', 'q',
                              0x27, 0x02, ':', 'p', 'r', 'o', 't', 'o',
                              'c', 'o', 'l', 0x0c, 'w', 'e', 'b', 't',
                              'r', 'a', 'n', 's', 'p', 'o', 'r', 't' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(mixed, sizeof(mixed), fields,
                                            8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(count, 5);
    WTQ_TEST_CHECK(field_is(&fields[0], ":method", "CONNECT"));
    WTQ_TEST_CHECK(field_is(&fields[1], ":scheme", "https"));
    WTQ_TEST_CHECK(field_is(&fields[2], ":authority", "wtq"));
    WTQ_TEST_CHECK(field_is(&fields[3], ":path", "/moq"));
    WTQ_TEST_CHECK(field_is(&fields[4], ":protocol", "webtransport"));

    *fp += failures;
}

/* rejections: dynamic, post-base, OOB index, truncation, capacities,
 * bad Huffman */
static void test_reject(int *fp)
{
    int failures = 0;
    wtq_qpack_field_t fields[8];
    size_t count = 0;
    char scratch[256];

    /* dynamic indexed (S bit clear): 0x81 */
    const uint8_t dyn_idx[] = { 0x00, 0x00, 0x81 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(dyn_idx, 3, fields, 8, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* dynamic name ref (T bit clear): 0x41 + value */
    const uint8_t dyn_ref[] = { 0x00, 0x00, 0x41, 0x01, 'x' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(dyn_ref, sizeof(dyn_ref),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* post-base name ref (0001....): 0x10 */
    const uint8_t pb_ref[] = { 0x00, 0x00, 0x10, 0x01, 'x' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(pb_ref, sizeof(pb_ref), fields,
                                            8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* post-base indexed (0000....): 0x01 */
    const uint8_t pb_idx[] = { 0x00, 0x00, 0x01 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(pb_idx, 3, fields, 8, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* static index 99 (0xff continuation 0x24) */
    const uint8_t oob[] = { 0x00, 0x00, 0xff, 0x24 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(oob, 4, fields, 8, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* literal value length beyond input */
    const uint8_t overrun[] = { 0x00, 0x00, 0x51, 0x7e, 'x' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(overrun, sizeof(overrun),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* truncated mid field line */
    const uint8_t mid[] = { 0x00, 0x00, 0x51 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(mid, 3, fields, 8, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);

    /* field count overflow -> BUFFER */
    const uint8_t two[] = { 0x00, 0x00, 0xcf, 0xd7 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(two, 4, fields, 1, &count,
                                            scratch, sizeof(scratch)) ==
                   WTQ_QPACK_BUFFER);
    /* scratch overflow -> BUFFER */
    const uint8_t lit[] = { 0x00, 0x00, 0x51, 0x04, '/', 'm', 'o', 'q' };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(lit, sizeof(lit), fields, 8,
                                            &count, scratch, 3) ==
                   WTQ_QPACK_BUFFER);
    /* scratch == NULL with scratch_cap == 0: clean BUFFER, no pointer
     * arithmetic on NULL (UBSan-visible) */
    WTQ_TEST_CHECK(wtq_qpack_decode_section(lit, sizeof(lit), fields, 8,
                                            &count, NULL, 0) ==
                   WTQ_QPACK_BUFFER);
    /* ...same for the Huffman path */
    const uint8_t hlit[] = { 0x00, 0x00, 0x51, 0x85, 0xae, 0xc3, 0x77,
                             0x1a, 0x4b };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(hlit, sizeof(hlit), fields, 8,
                                            &count, NULL, 0) ==
                   WTQ_QPACK_BUFFER);
    /* zero-length literal value needs no scratch and must succeed */
    const uint8_t empty_val[] = { 0x00, 0x00, 0x51, 0x00 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(empty_val, sizeof(empty_val),
                                            fields, 8, &count, NULL, 0) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":path", ""));

    /* bad Huffman: EOS in data (30 one-bits fit in 4 bytes) */
    const uint8_t eos[] = { 0x00, 0x00, 0x51, 0x84, 0xff, 0xff, 0xff,
                            0xff };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(eos, sizeof(eos), fields, 8,
                                            &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* bad Huffman: zero padding ('0' = 00000 then 000) */
    const uint8_t zeropad[] = { 0x00, 0x00, 0x51, 0x81, 0x00 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(zeropad, sizeof(zeropad),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* bad Huffman: 8 bits of pure padding (more than 7) */
    const uint8_t longpad[] = { 0x00, 0x00, 0x51, 0x81, 0xff };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(longpad, sizeof(longpad),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_MALFORMED);
    /* good Huffman single char for contrast: '0' + 111 padding = 0x07 */
    const uint8_t okpad[] = { 0x00, 0x00, 0x51, 0x81, 0x07 };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(okpad, sizeof(okpad), fields,
                                            8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK(field_is(&fields[0], ":path", "0"));

    *fp += failures;
}

/* encode: byte-exact forms + roundtrips */
static void test_encode(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    size_t out_len = 0;

    const wtq_qpack_field_t connect_req[] = {
        { ":method", 7, "CONNECT", 7, false },
        { ":scheme", 7, "https", 5, false },
        { ":authority", 10, "wtq", 3, false },
        { ":path", 5, "/moq", 4, false },
        { ":protocol", 9, "webtransport", 12, false },
    };

    WTQ_TEST_CHECK(wtq_qpack_encode_section(connect_req, 5, buf,
                                            sizeof(buf), &out_len) ==
                   WTQ_QPACK_OK);
    /* prefix {00 00}; :method CONNECT -> indexed 15 (0xcf); :scheme
     * https -> indexed 23 (0xd7); :authority -> name-ref idx 0 (0x50);
     * :path /moq -> name-ref idx 1 (0x51); :protocol -> literal-literal
     * (0x27 0x02 ...) */
    WTQ_TEST_CHECK(buf[0] == 0x00 && buf[1] == 0x00);
    WTQ_TEST_CHECK(buf[2] == 0xcf);
    WTQ_TEST_CHECK(buf[3] == 0xd7);
    WTQ_TEST_CHECK(buf[4] == 0x50 && buf[5] == 0x03);
    WTQ_TEST_CHECK(buf[9] == 0x51 && buf[10] == 0x04);
    WTQ_TEST_CHECK(buf[15] == 0x27 && buf[16] == 0x02);

    /* roundtrip */
    wtq_qpack_field_t fields[8];
    size_t count = 0;
    char scratch[256];
    WTQ_TEST_CHECK(wtq_qpack_decode_section(buf, out_len, fields, 8,
                                            &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(count, 5);
    for (size_t i = 0; i < 5; i++) {
        WTQ_TEST_CHECK(fields[i].name_len == connect_req[i].name_len &&
                       memcmp(fields[i].name, connect_req[i].name,
                              fields[i].name_len) == 0);
        WTQ_TEST_CHECK(fields[i].value_len == connect_req[i].value_len &&
                       memcmp(fields[i].value, connect_req[i].value,
                              fields[i].value_len) == 0);
    }

    /* decode(Huffman) -> canonical encode -> decode preserves values */
    const uint8_t huff_val[] = { 0x00, 0x00, 0x51, 0x85, 0xae, 0xc3, 0x77,
                                 0x1a, 0x4b };
    WTQ_TEST_CHECK(wtq_qpack_decode_section(huff_val, sizeof(huff_val),
                                            fields, 8, &count, scratch,
                                            sizeof(scratch)) ==
                   WTQ_QPACK_OK);
    uint8_t reenc[64];
    size_t relen = 0;
    WTQ_TEST_CHECK(wtq_qpack_encode_section(fields, count, reenc,
                                            sizeof(reenc), &relen) ==
                   WTQ_QPACK_OK);
    wtq_qpack_field_t fields2[8];
    size_t count2 = 0;
    char scratch2[256];
    WTQ_TEST_CHECK(wtq_qpack_decode_section(reenc, relen, fields2, 8,
                                            &count2, scratch2,
                                            sizeof(scratch2)) ==
                   WTQ_QPACK_OK);
    WTQ_TEST_CHECK_EQ_SIZE(count2, count);
    WTQ_TEST_CHECK(field_is(&fields2[0], ":path", "private"));

    /* untouched-on-BUFFER at several short caps */
    for (size_t cap = 0; cap < 8; cap++) {
        uint8_t small[16];
        memset(small, 0xEE, sizeof(small));
        WTQ_TEST_CHECK(wtq_qpack_encode_section(connect_req, 5, small, cap,
                                                &out_len) ==
                       WTQ_QPACK_BUFFER);
        for (size_t i = 0; i < sizeof(small); i++)
            WTQ_TEST_CHECK(small[i] == 0xEE);
    }

    *fp += failures;
}

/* exhaustive truncation: every strict prefix of valid sections is
 * MALFORMED or BUFFER, never OK, never a crash */
static void test_truncation(int *fp)
{
    int failures = 0;
    const uint8_t mixed[] = { 0x00, 0x00, 0xcf, 0xd7, 0x50, 0x03, 'w',
                              't', 'q', 0x51, 0x04, '/', 'm', 'o', 'q' };

    for (size_t plen = 0; plen < sizeof(mixed); plen++) {
        wtq_qpack_field_t fields[8];
        size_t count = 0;
        char scratch[64];
        wtq_qpack_status_t st =
            wtq_qpack_decode_section(mixed, plen, fields, 8, &count,
                                     scratch, sizeof(scratch));
        /* prefixes ending exactly after the section prefix or after a
         * complete field line are themselves valid sections */
        if (plen == 2 || plen == 3 || plen == 4 || plen == 9)
            WTQ_TEST_CHECK(st == WTQ_QPACK_OK);
        else
            WTQ_TEST_CHECK(st == WTQ_QPACK_MALFORMED);
    }

    *fp += failures;
}

int main(void)
{
    int failures = 0;

    test_integers(&failures);
    test_static_table(&failures);
    test_prefix(&failures);
    test_decode(&failures);
    test_reject(&failures);
    test_encode(&failures);
    test_truncation(&failures);

    WTQ_TEST_PASS("test_qpack_static");
    return failures;
}
