#include "qpack_static.h"

#include <string.h>

typedef struct wtq_qpack_static_entry {
    const char *name;
    uint16_t name_len;
    const char *value;
    uint16_t value_len;
} wtq_qpack_static_entry_t;

#include "qpack_tables.inc"

#define WTQ_QPACK_MAX_INT ((UINT64_C(1) << 62) - 1)
#define WTQ_HUFF_N_LENGTHS \
    (sizeof(wtq_huff_lengths) / sizeof(wtq_huff_lengths[0]))

/* --- prefixed integers (RFC 7541 s5.1) -------------------------------- */

static size_t int_encoded_len(uint64_t value, unsigned prefix_bits)
{
    uint64_t max_prefix = (UINT64_C(1) << prefix_bits) - 1;
    size_t n = 1;

    if (value < max_prefix)
        return 1;
    value -= max_prefix;
    do {
        n++;
        value >>= 7;
    } while (value > 0);
    return n;
}

wtq_qpack_status_t wtq_qpack_int_encode(uint64_t value,
                                        uint8_t first_byte_flags,
                                        unsigned prefix_bits, uint8_t *dst,
                                        size_t cap, size_t *out_len)
{
    if (prefix_bits < 3 || prefix_bits > 8 || value > WTQ_QPACK_MAX_INT)
        return WTQ_QPACK_RANGE;

    uint64_t max_prefix = (UINT64_C(1) << prefix_bits) - 1;
    size_t need = int_encoded_len(value, prefix_bits);
    if (cap < need)
        return WTQ_QPACK_BUFFER;

    size_t o = 0;
    if (value < max_prefix) {
        dst[o++] = (uint8_t)(first_byte_flags | value);
    } else {
        dst[o++] = (uint8_t)(first_byte_flags | max_prefix);
        value -= max_prefix;
        while (value >= 0x80) {
            dst[o++] = (uint8_t)(0x80 | (value & 0x7f));
            value >>= 7;
        }
        dst[o++] = (uint8_t)value;
    }

    *out_len = o;
    return WTQ_QPACK_OK;
}

wtq_qpack_status_t wtq_qpack_int_decode(const uint8_t *src, size_t len,
                                        unsigned prefix_bits,
                                        uint64_t *value, size_t *consumed)
{
    if (prefix_bits < 3 || prefix_bits > 8)
        return WTQ_QPACK_MALFORMED;
    if (len == 0)
        return WTQ_QPACK_NEED_MORE;

    uint64_t max_prefix = (UINT64_C(1) << prefix_bits) - 1;
    uint64_t v = src[0] & max_prefix;
    size_t i = 1;

    if (v == max_prefix) {
        unsigned shift = 0;
        for (;;) {
            if (i >= len)
                return WTQ_QPACK_NEED_MORE;
            uint8_t b = src[i++];
            uint64_t chunk = b & 0x7f;
            if (shift > 62 || (shift > 0 && chunk > (WTQ_QPACK_MAX_INT >>
                                                     shift)))
                return WTQ_QPACK_MALFORMED; /* beyond 62-bit range */
            v += chunk << shift;
            if (v > WTQ_QPACK_MAX_INT)
                return WTQ_QPACK_MALFORMED;
            if (!(b & 0x80))
                break;
            shift += 7;
        }
    }

    *value = v;
    *consumed = i;
    return WTQ_QPACK_OK;
}

/* --- static table ------------------------------------------------------ */

bool wtq_qpack_static_get(uint64_t index, const char **name,
                          size_t *name_len, const char **value,
                          size_t *value_len)
{
    if (index >= WTQ_QPACK_STATIC_COUNT)
        return false;
    *name = wtq_qpack_static_table[index].name;
    *name_len = wtq_qpack_static_table[index].name_len;
    *value = wtq_qpack_static_table[index].value;
    *value_len = wtq_qpack_static_table[index].value_len;
    return true;
}

int wtq_qpack_static_find(const char *name, size_t name_len,
                          const char *value, size_t value_len)
{
    for (unsigned i = 0; i < WTQ_QPACK_STATIC_COUNT; i++) {
        const wtq_qpack_static_entry_t *e = &wtq_qpack_static_table[i];
        if (e->name_len == name_len && e->value_len == value_len &&
            memcmp(e->name, name, name_len) == 0 &&
            (value_len == 0 || memcmp(e->value, value, value_len) == 0))
            return (int)i;
    }
    return -1;
}

int wtq_qpack_static_find_name(const char *name, size_t name_len)
{
    for (unsigned i = 0; i < WTQ_QPACK_STATIC_COUNT; i++) {
        const wtq_qpack_static_entry_t *e = &wtq_qpack_static_table[i];
        if (e->name_len == name_len &&
            memcmp(e->name, name, name_len) == 0)
            return (int)i;
    }
    return -1;
}

/* --- Huffman decode (canonical, RFC 7541 Appendix B) ------------------- */

static wtq_qpack_status_t huffman_decode(const uint8_t *src, size_t len,
                                         char *dst, size_t cap,
                                         size_t *out_len)
{
    uint32_t code = 0;
    unsigned nbits = 0;
    size_t o = 0;
    size_t row = 0;

    for (size_t i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            code = (code << 1) | ((src[i] >> bit) & 1);
            nbits++;
            while (row < WTQ_HUFF_N_LENGTHS &&
                   wtq_huff_lengths[row].bits < nbits)
                row++;
            if (row < WTQ_HUFF_N_LENGTHS &&
                wtq_huff_lengths[row].bits == nbits &&
                code < wtq_huff_lengths[row].first_code +
                           wtq_huff_lengths[row].count) {
                /* canonical hit (codes below first_code of a length are
                 * impossible by construction) */
                if (o >= cap)
                    return WTQ_QPACK_BUFFER;
                dst[o++] = (char)wtq_huff_symbols
                    [wtq_huff_lengths[row].first_index +
                     (code - wtq_huff_lengths[row].first_code)];
                code = 0;
                nbits = 0;
                row = 0;
            } else if (nbits >= WTQ_HUFF_EOS_BITS) {
                /* EOS symbol in data, or an impossible code */
                return WTQ_QPACK_MALFORMED;
            }
        }
    }

    /* Terminal padding: at most 7 bits, all ones (EOS prefix). */
    if (nbits > 7)
        return WTQ_QPACK_MALFORMED;
    if (nbits > 0 && code != (UINT32_C(1) << nbits) - 1)
        return WTQ_QPACK_MALFORMED;

    *out_len = o;
    return WTQ_QPACK_OK;
}

/* --- string literal decode --------------------------------------------- */
/*
 * Decodes one string literal at src[*off]: H bit at (1 << prefix_bits),
 * length in a prefix_bits-prefix int, then the bytes. The result is
 * always copied (plain) or Huffman-decoded into scratch.
 */
static wtq_qpack_status_t decode_string(const uint8_t *src, size_t len,
                                        size_t *off, unsigned prefix_bits,
                                        char *scratch, size_t scratch_cap,
                                        size_t *scratch_off,
                                        const char **out, size_t *out_len)
{
    if (*off >= len)
        return WTQ_QPACK_MALFORMED;

    bool huffman = (src[*off] & (1u << prefix_bits)) != 0;
    uint64_t slen = 0;
    size_t c = 0;
    wtq_qpack_status_t st = wtq_qpack_int_decode(src + *off, len - *off,
                                                 prefix_bits, &slen, &c);
    if (st != WTQ_QPACK_OK)
        return WTQ_QPACK_MALFORMED; /* complete-span contract */
    *off += c;

    if (slen > len - *off)
        return WTQ_QPACK_MALFORMED; /* announced length beyond input */

    /* Guard the pointer arithmetic: scratch may be NULL when
     * scratch_cap is 0 (NULL + 0 is UB — same class as the h3_frame
     * zero-length-probe fix). */
    char *dst = (scratch != NULL) ? scratch + *scratch_off : NULL;
    size_t dcap = scratch_cap - *scratch_off;
    size_t dlen = 0;

    if (huffman) {
        st = huffman_decode(src + *off, (size_t)slen, dst, dcap, &dlen);
        if (st != WTQ_QPACK_OK)
            return st;
    } else {
        if (slen > dcap)
            return WTQ_QPACK_BUFFER;
        if (slen > 0)
            memcpy(dst, src + *off, (size_t)slen);
        dlen = (size_t)slen;
    }

    *off += (size_t)slen;
    *scratch_off += dlen;
    /* Zero-length results point at static "" so callers never receive a
     * NULL span base (memcmp with NULL is UB even for length 0). */
    *out = (dlen > 0) ? dst : "";
    *out_len = dlen;
    return WTQ_QPACK_OK;
}

/* --- field-section decode ---------------------------------------------- */

wtq_qpack_status_t wtq_qpack_decode_section(const uint8_t *src, size_t len,
                                            wtq_qpack_field_t *fields,
                                            size_t max_fields,
                                            size_t *out_count,
                                            char *scratch,
                                            size_t scratch_cap)
{
    size_t off = 0;
    size_t scratch_off = 0;
    size_t count = 0;

    /* Prefix: Required Insert Count (8-bit prefix int) must be 0; base
     * byte must have the sign bit clear and Delta Base 0. Static-only
     * by contract. */
    uint64_t ric = 0;
    size_t c = 0;
    if (wtq_qpack_int_decode(src, len, 8, &ric, &c) != WTQ_QPACK_OK ||
        ric != 0)
        return WTQ_QPACK_MALFORMED;
    off += c;
    if (off >= len)
        return WTQ_QPACK_MALFORMED;
    if (src[off] & 0x80)
        return WTQ_QPACK_MALFORMED; /* sign bit: dynamic reference */
    uint64_t base = 0;
    if (wtq_qpack_int_decode(src + off, len - off, 7, &base, &c) !=
            WTQ_QPACK_OK ||
        base != 0)
        return WTQ_QPACK_MALFORMED;
    off += c;

    while (off < len) {
        uint8_t b = src[off];
        wtq_qpack_field_t f;
        memset(&f, 0, sizeof(f));

        if (b & 0x80) {
            /* Indexed Field Line: 1 T index(6+). T=1 (static) only. */
            if (!(b & 0x40))
                return WTQ_QPACK_MALFORMED; /* dynamic table */
            uint64_t idx = 0;
            if (wtq_qpack_int_decode(src + off, len - off, 6, &idx, &c) !=
                WTQ_QPACK_OK)
                return WTQ_QPACK_MALFORMED;
            off += c;
            if (!wtq_qpack_static_get(idx, &f.name, &f.name_len, &f.value,
                                      &f.value_len))
                return WTQ_QPACK_MALFORMED; /* static index OOB */
        } else if (b & 0x40) {
            /* Literal With Name Reference: 01 N T name_index(4+). */
            f.never_index = (b & 0x20) != 0;
            if (!(b & 0x10))
                return WTQ_QPACK_MALFORMED; /* dynamic name reference */
            uint64_t idx = 0;
            if (wtq_qpack_int_decode(src + off, len - off, 4, &idx, &c) !=
                WTQ_QPACK_OK)
                return WTQ_QPACK_MALFORMED;
            off += c;
            const char *sv;
            size_t svl;
            if (!wtq_qpack_static_get(idx, &f.name, &f.name_len, &sv,
                                      &svl))
                return WTQ_QPACK_MALFORMED;
            wtq_qpack_status_t st = decode_string(src, len, &off, 7,
                                                  scratch, scratch_cap,
                                                  &scratch_off, &f.value,
                                                  &f.value_len);
            if (st != WTQ_QPACK_OK)
                return st;
        } else if (b & 0x20) {
            /* Literal With Literal Name: 001 N H name_len(3+). */
            f.never_index = (b & 0x10) != 0;
            wtq_qpack_status_t st = decode_string(src, len, &off, 3,
                                                  scratch, scratch_cap,
                                                  &scratch_off, &f.name,
                                                  &f.name_len);
            if (st != WTQ_QPACK_OK)
                return st;
            st = decode_string(src, len, &off, 7, scratch, scratch_cap,
                               &scratch_off, &f.value, &f.value_len);
            if (st != WTQ_QPACK_OK)
                return st;
        } else {
            /* 0001 (post-base name ref) and 0000 (post-base indexed)
             * are dynamic-only forms. */
            return WTQ_QPACK_MALFORMED;
        }

        if (count >= max_fields)
            return WTQ_QPACK_BUFFER;
        fields[count++] = f;
    }

    *out_count = count;
    return WTQ_QPACK_OK;
}

/* --- field-section encode ---------------------------------------------- */

static size_t field_encoded_len(const wtq_qpack_field_t *f)
{
    int idx = wtq_qpack_static_find(f->name, f->name_len, f->value,
                                    f->value_len);
    if (idx >= 0)
        return int_encoded_len((uint64_t)idx, 6);

    int nidx = wtq_qpack_static_find_name(f->name, f->name_len);
    if (nidx >= 0)
        return int_encoded_len((uint64_t)nidx, 4) +
               int_encoded_len(f->value_len, 7) + f->value_len;

    return int_encoded_len(f->name_len, 3) + f->name_len +
           int_encoded_len(f->value_len, 7) + f->value_len;
}

wtq_qpack_status_t wtq_qpack_encode_section(const wtq_qpack_field_t *fields,
                                            size_t count, uint8_t *dst,
                                            size_t cap, size_t *out_len)
{
    size_t need = 2; /* prefix {0x00, 0x00} */

    for (size_t i = 0; i < count; i++) {
        if (fields[i].name_len > WTQ_QPACK_MAX_INT ||
            fields[i].value_len > WTQ_QPACK_MAX_INT)
            return WTQ_QPACK_RANGE;
        need += field_encoded_len(&fields[i]);
    }
    if (cap < need)
        return WTQ_QPACK_BUFFER;

    size_t o = 0;
    dst[o++] = 0x00;
    dst[o++] = 0x00;

    for (size_t i = 0; i < count; i++) {
        const wtq_qpack_field_t *f = &fields[i];
        size_t c = 0;
        /* Capacity verified above; the int encodes cannot fail. */
        int idx = wtq_qpack_static_find(f->name, f->name_len, f->value,
                                        f->value_len);
        if (idx >= 0) {
            /* Indexed Field Line, static: 1 T=1 index(6+). */
            (void)wtq_qpack_int_encode((uint64_t)idx, 0xc0, 6, dst + o,
                                       cap - o, &c);
            o += c;
            continue;
        }
        int nidx = wtq_qpack_static_find_name(f->name, f->name_len);
        if (nidx >= 0) {
            /* Literal With Name Reference: 01 N T=1 idx(4+), then plain
             * value string (H=0). */
            uint8_t flags = (uint8_t)(0x40 | (f->never_index ? 0x20 : 0) |
                                      0x10);
            (void)wtq_qpack_int_encode((uint64_t)nidx, flags, 4, dst + o,
                                       cap - o, &c);
            o += c;
            (void)wtq_qpack_int_encode(f->value_len, 0x00, 7, dst + o,
                                       cap - o, &c);
            o += c;
            memcpy(dst + o, f->value, f->value_len);
            o += f->value_len;
            continue;
        }
        /* Literal With Literal Name: 001 N H=0 name_len(3+). */
        uint8_t flags = (uint8_t)(0x20 | (f->never_index ? 0x10 : 0));
        (void)wtq_qpack_int_encode(f->name_len, flags, 3, dst + o, cap - o,
                                   &c);
        o += c;
        memcpy(dst + o, f->name, f->name_len);
        o += f->name_len;
        (void)wtq_qpack_int_encode(f->value_len, 0x00, 7, dst + o, cap - o,
                                   &c);
        o += c;
        memcpy(dst + o, f->value, f->value_len);
        o += f->value_len;
    }

    *out_len = o;
    return WTQ_QPACK_OK;
}
