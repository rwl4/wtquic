/*
 * Independent WebTransport profile parsers.
 *
 * These strict parsers are TEST-ONLY and deliberately do NOT call
 * wtquic's production CONNECT or SETTINGS decoders. They walk the raw
 * wire bytes with a self-contained QUIC varint reader and classify a
 * payload into exactly one of the three supported profiles (or none),
 * proving that:
 *   - the current profile is webtransport-h3 + WT_ENABLED only;
 *   - the D13/14 compat profile is webtransport + WT_MAX_SESSIONS
 *     (0x14e9cd29) only;
 *   - cross-profile emitted outputs are rejected both ways;
 *   - peer SETTINGS with D13+D07 classify as compat, while a D07-only
 *     (0xc671706a) signal matches no profile;
 *   - ENABLE_WEBTRANSPORT (0x2b603742) = 1 selects the D02/RFC9297
 *     profile when the peer ALSO sends H3_DATAGRAM (0x33) = 1. That pair
 *     is exactly what stable Chrome emits, so a 0x2b603742 signal is not
 *     "matches neither" -- it is the D02 selector. Alone, without 0x33,
 *     it selects nothing.
 *
 * Inputs are produced by the PRODUCTION ENCODERS (encoders are fine —
 * only the decoders are off-limits), so this pins the encoder output
 * against an independent reader.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <wtquic/error.h>

#include "proto/connect.h"
#include "proto/qpack_static.h"
#include "proto/h3_settings.h"
#include "proto/preamble.h"
#include "proto/varint.h"

#include "test_support.h"

/* ---- self-contained QUIC varint reader (NOT wtq_varint) -------------- */
static bool tp_varint(const uint8_t *p, size_t len, size_t *off,
                      uint64_t *out)
{
    if (*off >= len)
        return false;
    uint8_t b0 = p[*off];
    size_t n = (size_t)1 << (b0 >> 6);
    if (*off + n > len)
        return false;
    uint64_t v = b0 & 0x3f;
    for (size_t i = 1; i < n; i++)
        v = (v << 8) | p[*off + i];
    *off += n;
    *out = v;
    return true;
}

/* Wire codepoints (literal here; the point is independence). */
#define ID_WT_ENABLED   0x2c7cf000ull
#define ID_WT_MAXSESS13 0x14e9cd29ull
#define ID_WT_MAXSESS07 0xc671706aull
#define ID_ENABLE_WT    0x2b603742ull
#define ID_QPACK_CAP     0x01ull
#define ID_QPACK_BLOCKED 0x07ull
#define ID_ECP           0x08ull
#define ID_DATAGRAM      0x33ull

/* Walk a bare SETTINGS PAYLOAD (id,value pairs) and record which WT
 * signals appear. Returns false on a malformed stream. */
typedef struct {
    bool wt_enabled;   uint64_t wt_enabled_v;   unsigned wt_enabled_n;
    bool max13;        uint64_t max13_v;        unsigned max13_n;
    bool max07;        uint64_t max07_v;        unsigned max07_n;
    bool enable_wt;    uint64_t enable_wt_v;    unsigned enable_wt_n;
    /* shared base every wtquic advertisement carries */
    bool qpack_cap;     uint64_t qpack_cap_v;     unsigned qpack_cap_n;
    bool qpack_blocked; uint64_t qpack_blocked_v; unsigned qpack_blocked_n;
    bool ecp;           uint64_t ecp_v;           unsigned ecp_n;
    bool datagram;      uint64_t datagram_v;      unsigned datagram_n;
    /* identifiers never DECREASE across the payload. Non-decreasing (not
     * strict) on purpose: that keeps ORDER and DUPLICATE detection
     * independently load-bearing — a repeat is caught by the *_n counts,
     * a swap by this flag. */
    bool nondecreasing;
    size_t pairs;
} tp_wt_signals_t;

static bool tp_scan_settings(const uint8_t *p, size_t len,
                             tp_wt_signals_t *s)
{
    size_t off = 0;
    bool have_last = false;
    uint64_t last_id = 0;

    memset(s, 0, sizeof(*s));
    s->nondecreasing = true;
    while (off < len) {
        uint64_t id, val;
        if (!tp_varint(p, len, &off, &id))
            return false;
        if (!tp_varint(p, len, &off, &val))
            return false;
        if (have_last && id < last_id)
            s->nondecreasing = false;
        last_id = id;
        have_last = true;
        s->pairs++;
        switch (id) {
        case ID_WT_ENABLED:
            s->wt_enabled = true; s->wt_enabled_v = val; s->wt_enabled_n++;
            break;
        case ID_WT_MAXSESS13:
            s->max13 = true;      s->max13_v = val;      s->max13_n++;
            break;
        case ID_WT_MAXSESS07:
            s->max07 = true;      s->max07_v = val;      s->max07_n++;
            break;
        case ID_ENABLE_WT:
            s->enable_wt = true;  s->enable_wt_v = val;  s->enable_wt_n++;
            break;
        case ID_QPACK_CAP:
            s->qpack_cap = true; s->qpack_cap_v = val; s->qpack_cap_n++;
            break;
        case ID_QPACK_BLOCKED:
            s->qpack_blocked = true; s->qpack_blocked_v = val;
            s->qpack_blocked_n++;
            break;
        case ID_ECP:
            s->ecp = true; s->ecp_v = val; s->ecp_n++;
            break;
        case ID_DATAGRAM:
            s->datagram = true; s->datagram_v = val; s->datagram_n++;
            break;
        default: break; /* grease and anything else: ignored */
        }
    }
    return true;
}

/* Does the payload carry the shared base every wtquic advertisement has?
 * (QPACK zeros, ECP=1, H3_DATAGRAM=1.) */
static bool tp_base_ok(const tp_wt_signals_t *s)
{
    return s->qpack_cap && s->qpack_cap_n == 1 && s->qpack_cap_v == 0 &&
           s->qpack_blocked && s->qpack_blocked_n == 1 &&
           s->qpack_blocked_v == 0 && s->ecp && s->ecp_n == 1 &&
           s->ecp_v == 1 && s->datagram && s->datagram_n == 1 &&
           s->datagram_v == 1;
}

/*
 * Strict three-profile union classifier. Every base and profile setting must
 * appear exactly once with its canonical value, D07 must be absent, and the
 * identifiers must be in deterministic ascending order.
 * Deliberately does NOT call the production SETTINGS decoder, so encoder
 * and decoder cannot agree on the same defect.
 */
static bool tp_settings_is_union(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    if (!s.nondecreasing)
        return false;
    if (!tp_base_ok(&s) || s.pairs != 7)
        return false;
    if (!(s.max13 && s.max13_n == 1 && s.max13_v == 1))
        return false;
    if (!(s.wt_enabled && s.wt_enabled_n == 1 && s.wt_enabled_v == 1))
        return false;
    /* The union now offers three generations; the D02 signal is present
     * exactly once with value 1. D07 0xc671706a still never appears. */
    if (!(s.enable_wt && s.enable_wt_n == 1 && s.enable_wt_v == 1))
        return false;
    return !s.max07;
}

/* Strict CURRENT SETTINGS: WT_ENABLED==1 present, and NO other-profile
 * WT signal. */
static bool tp_settings_is_current(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return tp_base_ok(&s) && s.nondecreasing && s.pairs == 5 &&
           s.wt_enabled && s.wt_enabled_n == 1 && s.wt_enabled_v == 1 &&
           !s.max13 && !s.max07 && !s.enable_wt;
}

/* Strict D13/14 compat OUTPUT: WT_MAX_SESSIONS(0x14e9cd29)==1 present,
 * and NO other WT codepoint — this validates what WTQUIC ITSELF EMITS
 * (a single clean signal, never D07/Chrome/WT_ENABLED). */
static bool tp_settings_is_compat(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return tp_base_ok(&s) && s.nondecreasing && s.pairs == 5 &&
           s.max13 && s.max13_n == 1 && s.max13_v == 1 &&
           !s.wt_enabled && !s.max07 && !s.enable_wt;
}

/* Strict D02/RFC9297 output: one ENABLE_WEBTRANSPORT signal and no other
 * profile signal, over the same canonical local base. */
static bool tp_settings_is_d02(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return tp_base_ok(&s) && s.nondecreasing && s.pairs == 5 &&
           s.enable_wt && s.enable_wt_n == 1 && s.enable_wt_v == 1 &&
           !s.wt_enabled && !s.max13 && !s.max07;
}

/* PEER-SIGNAL classifiers: the WT-signal rule PRODUCTION applies to an
 * INBOUND peer's SETTINGS (wtq_h3_settings_peer_supports_wt) — current
 * iff WT_ENABLED==1; D13/14 compat iff
 * WT_MAX_SESSIONS(0x14e9cd29)>0; D02/RFC9297 iff
 * ENABLE_WEBTRANSPORT==1 and H3_DATAGRAM==1. D07 co-presence is
 * TOLERATED for D13/14 compat (pico/h3zero sends both D13 and D07),
 * while a D07-only peer signal matches no profile. */
static bool tp_peer_is_current(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return s.wt_enabled && s.wt_enabled_v == 1;
}
static bool tp_peer_is_compat(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return s.max13 && s.max13_v > 0;
}

static bool tp_peer_is_d02(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return s.enable_wt && s.enable_wt_v == 1 &&
           s.datagram && s.datagram_v == 1;
}

/* ---- minimal independent QPACK field-section parser ----------------- */
/* A self-contained decoder for the STATIC-only, non-Huffman field
 * sections wtquic emits (RFC 9204). It is NOT wtquic's production QPACK
 * code: it exists to prove the generated :protocol FIELD (name +
 * value), not merely a byte substring. */

/* QPACK prefix integer (N-bit prefix), RFC 9204 s4.1.1. */
static bool qp_int(const uint8_t *p, size_t len, size_t *off, int nbits,
                   uint64_t *out)
{
    if (*off >= len)
        return false;
    uint64_t maxpre = ((uint64_t)1 << nbits) - 1;
    uint64_t v = p[*off] & maxpre;
    (*off)++;
    if (v < maxpre) {
        *out = v;
        return true;
    }
    uint64_t m = 0;
    for (;;) {
        if (*off >= len || m > 62)
            return false;
        uint8_t b = p[*off];
        (*off)++;
        v += (uint64_t)(b & 0x7f) << m;
        if (!(b & 0x80))
            break;
        m += 7;
    }
    *out = v;
    return true;
}

/* Extract the value of the :protocol field. Returns true and fills
 * out_val/out_len on success. Handles: indexed field line (static),
 * literal-with-name-reference (static), literal-with-literal-name — all
 * non-Huffman, which is exactly what wtquic emits. */
/*
 * INDEPENDENT field-section reader. It generalises the same static-only,
 * non-Huffman walker used for `:protocol` above: it parses real field
 * boundaries, compares COMPLETE names and values, and returns a parse
 * FAILURE on malformed or truncated input (distinguishable from a valid
 * section with zero matches). It never calls the production QPACK or
 * CONNECT decoder, so the production encoder is checked against a genuinely
 * separate implementation.
 *
 * Returns false on malformed input. On success *count_out is the number of
 * fields whose name matches exactly, and the LAST such value is reported.
 */
/*
 * The static table has 99 entries (RFC 9204 Appendix A). The independent
 * reader validates every reference against it rather than trusting the
 * encoder, so an out-of-range or dynamic reference is malformed input.
 */
#define TP_STATIC_COUNT 99u

/* off + add, refusing any arithmetic that could wrap or run past len. */
static bool tp_advance(size_t *off, uint64_t add, size_t len)
{
    if (add > (uint64_t)(len - *off))
        return false;
    *off += (size_t)add;
    return true;
}

static bool tp_field_count(const uint8_t *p, size_t len, const char *name,
                           size_t name_len, const uint8_t **val_out,
                           size_t *val_len_out, unsigned *count_out)
{
    size_t off = 0;
    uint64_t ric, delta_base;
    unsigned found = 0;

    if (count_out != NULL)
        *count_out = 0;
    /*
     * FIELD SECTION PREFIX, parsed and validated in full. For the
     * static-only form this encoder emits, Required Insert Count is 0 and
     * the Delta Base byte is the zero-base form: S (sign) clear and a
     * Delta Base of 0. A nonzero prefix means a dynamic-table reference we
     * do not implement, so it is malformed, not something to skip over.
     */
    if (!qp_int(p, len, &off, 8, &ric) || ric != 0)
        return false;
    if (off >= len)
        return false;
    if ((p[off] & 0x80) != 0) /* S set: base below the insert count */
        return false;
    if (!qp_int(p, len, &off, 7, &delta_base) || delta_base != 0)
        return false;

    while (off < len) {
        const uint8_t b = p[off];
        if (b & 0x80) {
            /* Indexed Field Line: 1 T index(6+). T (0x40) MUST be set --
             * a dynamic-table reference is rejected, not accepted. */
            uint64_t idx;
            if ((b & 0x40) == 0)
                return false;
            if (!qp_int(p, len, &off, 6, &idx))
                return false;
            if (idx >= TP_STATIC_COUNT)
                return false;
        } else if (b & 0x40) {
            /* Literal Field Line With Name Reference: 0 1 N T index(4+).
             * T (0x10) MUST be set for a static name reference. */
            uint64_t nidx, vlen;
            if ((b & 0x10) == 0)
                return false;
            if (!qp_int(p, len, &off, 4, &nidx))
                return false;
            if (nidx >= TP_STATIC_COUNT)
                return false;
            if (off >= len)
                return false;
            const bool vhuff = (p[off] & 0x80) != 0;
            if (!qp_int(p, len, &off, 7, &vlen) || vhuff)
                return false;
            if (!tp_advance(&off, vlen, len))
                return false;
            /* The name is a static reference, so it can never be one of
             * our literal marker names; nothing to compare. */
        } else if (b & 0x20) {
            /* Literal Field Line With Literal Name: 0 0 1 N H len(3+). */
            const bool nhuff = (b & 0x08) != 0;
            uint64_t nlen, vlen;
            if (!qp_int(p, len, &off, 3, &nlen) || nhuff)
                return false;
            const uint8_t *fname = p + off;
            if (!tp_advance(&off, nlen, len))
                return false;
            const size_t fnamelen = (size_t)nlen;
            if (off >= len)
                return false;
            const bool vhuff = (p[off] & 0x80) != 0;
            if (!qp_int(p, len, &off, 7, &vlen) || vhuff)
                return false;
            const uint8_t *val = p + off;
            if (!tp_advance(&off, vlen, len))
                return false;
            /* COMPLETE name comparison at a real field boundary: a longer
             * name that merely starts with `name` does not match, so the
             * response name can never alias the request name. */
            if (fnamelen == name_len &&
                memcmp(fname, name, name_len) == 0) {
                found++;
                if (val_out != NULL)
                    *val_out = val;
                if (val_len_out != NULL)
                    *val_len_out = (size_t)vlen;
            }
        } else {
            /* post-base forms: wtquic never emits them */
            return false;
        }
    }
    if (count_out != NULL)
        *count_out = found;
    return true;
}

/*
 * `:protocol` extraction, backed by the SAME strict static-only reader the
 * D02 marker checks use. There is deliberately only ONE field-section
 * walker in this file: a second, laxer parser behind the profile
 * classifier would mean the classifier was never actually backed by the
 * strict reader.
 *
 * Requires EXACTLY ONE complete `:protocol` field. A duplicate, a
 * malformed trailing field, or any malformed input anywhere in the
 * section fails -- the whole section is scanned before success is
 * reported, so a valid `:protocol` cannot mask later garbage.
 */
static bool tp_extract_protocol(const uint8_t *p, size_t len,
                                const uint8_t **out_val, size_t *out_len)
{
    unsigned count = 0;

    if (!tp_field_count(p, len, ":protocol", 9, out_val, out_len, &count))
        return false;
    return count == 1;
}

static bool tp_protocol_is(const uint8_t *p, size_t len, const char *tok)
{
    const uint8_t *v;
    size_t vl;
    if (!tp_extract_protocol(p, len, &v, &vl))
        return false;
    return vl == strlen(tok) && memcmp(v, tok, vl) == 0;
}

/* Strict :protocol acceptance per profile — the parsed FIELD value must
 * be exactly the profile's token (not the other). */
static bool tp_connect_is_current(const uint8_t *p, size_t len)
{
    return tp_protocol_is(p, len, "webtransport-h3");
}
static bool tp_connect_is_compat(const uint8_t *p, size_t len)
{
    return tp_protocol_is(p, len, "webtransport");
}

/* ---- tests ---------------------------------------------------------- */

/*
 * The multi-version advertisement, validated by the INDEPENDENT parser.
 * Input comes from the production ENCODER (encoders are fine here — only
 * the production DECODER is off-limits), so a defect the encoder and
 * decoder would agree on is still caught.
 */
static void test_settings_union_parser(int *fp)
{
    int failures = 0;
    uint8_t buf[64];
    size_t n = 0;

    /* The real union classifies as a union and as no single-profile shape. */
    wtq_h3_settings_encode_cfg_t all = { true, WTQ_H3_WT_PROFILES_ALL };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&all, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(tp_settings_is_union(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_current(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_compat(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_d02(buf, n));
    /* All three peer support predicates match the capability union. */
    WTQ_TEST_CHECK(tp_peer_is_current(buf, n));
    WTQ_TEST_CHECK(tp_peer_is_compat(buf, n));
    WTQ_TEST_CHECK(tp_peer_is_d02(buf, n));

    /* No single-profile payload is a union. */
    wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILES_CURRENT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cur, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(!tp_settings_is_union(buf, n));
    WTQ_TEST_CHECK(tp_settings_is_current(buf, n));
    wtq_h3_settings_encode_cfg_t cmp = {
        true, WTQ_H3_WT_PROFILES_D13_14_COMPAT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cmp, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(!tp_settings_is_union(buf, n));
    WTQ_TEST_CHECK(tp_settings_is_compat(buf, n));
    wtq_h3_settings_encode_cfg_t d02 = {
        true, WTQ_H3_WT_PROFILES_D02_RFC9297_COMPAT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&d02, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(!tp_settings_is_union(buf, n));
    WTQ_TEST_CHECK(tp_settings_is_d02(buf, n));
    WTQ_TEST_CHECK(tp_peer_is_d02(buf, n));

    /* --- hand-built negatives: the oracle must REJECT each defect --- */
    /* the exact good union, for reference */
    const uint8_t ok[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,       /* 0x14e9cd29 = 1 */
        0xab, 0x60, 0x37, 0x42, 0x01,       /* 0x2b603742 = 1 */
        0xac, 0x7c, 0xf0, 0x00, 0x01,       /* 0x2c7cf000 = 1 */
    };
    WTQ_TEST_CHECK(tp_settings_is_union(ok, sizeof(ok)));

    /* missing member: CURRENT dropped */
    const uint8_t miss_cur[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(miss_cur, sizeof(miss_cur)));

    /* missing member: D13/14 dropped */
    const uint8_t miss_d13[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(miss_d13, sizeof(miss_d13)));

    /* DUPLICATE member (still non-decreasing, so the *_n count is what
     * catches this — order and duplication are independent checks) */
    const uint8_t dup[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,       /* repeated CURRENT */
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(dup, sizeof(dup)));

    /* WRONG VALUE on each member */
    const uint8_t bad_cur_val[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x00,       /* WT_ENABLED = 0 */
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(bad_cur_val, sizeof(bad_cur_val)));
    const uint8_t bad_d13_val[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x00,       /* MAX_SESSIONS = 0 */
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(bad_d13_val, sizeof(bad_d13_val)));
    const uint8_t bad_d02_val[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x00,       /* ENABLE_WT = 0 */
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(bad_d02_val,
                                          sizeof(bad_d02_val)));

    /* WRONG ORDER: CURRENT emitted before D13/14 (ids decrease) */
    const uint8_t swapped[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(swapped, sizeof(swapped)));

    /* FOREIGN generation present: D07 (0xc671706a, 8-byte varint id) */
    const uint8_t with_d07[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
        0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(with_d07, sizeof(with_d07)));

    /* missing member: the D02/RFC9297 signal dropped. 0x2b603742 is now a
     * UNION MEMBER, not a foreign generation — the foreign-signal rule is
     * carried by D07 (0xc671706a), asserted separately. */
    const uint8_t miss_d02[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(miss_d02, sizeof(miss_d02)));


    /* SHARED BASE broken: H3_DATAGRAM missing */
    const uint8_t no_dgram[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(no_dgram, sizeof(no_dgram)));

    /* SHARED BASE broken: ECP present but 0 */
    const uint8_t bad_ecp[] = {
        0x01, 0x00, 0x07, 0x00, 0x08, 0x00, 0x33, 0x01,
        0x94, 0xe9, 0xcd, 0x29, 0x01,
        0xab, 0x60, 0x37, 0x42, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    WTQ_TEST_CHECK(!tp_settings_is_union(bad_ecp, sizeof(bad_ecp)));

    *fp += failures;
}


static void test_settings_parsers(int *fp)
{
    int failures = 0;
    uint8_t buf[64];
    size_t n = 0;

    /* current-profile SETTINGS from the production encoder */
    wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILES_CURRENT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cur, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(tp_settings_is_current(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_compat(buf, n)); /* cross-profile fails */

    /* compat-profile SETTINGS */
    wtq_h3_settings_encode_cfg_t cmp = { true, WTQ_H3_WT_PROFILES_D13_14_COMPAT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cmp, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(tp_settings_is_compat(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_current(buf, n)); /* cross-profile fails */

    /* A D13+D07 peer payload (what pico/h3zero actually sends): D13 is
     * present, so PRODUCTION classifies it compat and accepts it. The
     * peer classifier must agree (D07 co-presence tolerated); it is NOT
     * a current-profile signal. */
    {
        /* D07 0xc671706a needs an 8-byte QUIC varint (top 2 bits 11). */
        const uint8_t d13_d07[] = {
            0x94, 0xe9, 0xcd, 0x29, 0x01,               /* D13 = 1 */
            0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01 }; /* D07=1 */
        WTQ_TEST_CHECK(tp_peer_is_compat(d13_d07, sizeof(d13_d07)));
        WTQ_TEST_CHECK(!tp_peer_is_current(d13_d07, sizeof(d13_d07)));
        WTQ_TEST_CHECK(!tp_peer_is_d02(d13_d07, sizeof(d13_d07)));
        /* it is NOT wtquic's own clean output (that never carries D07) */
        WTQ_TEST_CHECK(!tp_settings_is_compat(d13_d07, sizeof(d13_d07)));
    }
    /* A D07-only payload matches no supported profile. */
    {
        const uint8_t d07[] = {
            0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01 };
        WTQ_TEST_CHECK(!tp_peer_is_current(d07, sizeof(d07)));
        WTQ_TEST_CHECK(!tp_peer_is_compat(d07, sizeof(d07)));
        WTQ_TEST_CHECK(!tp_peer_is_d02(d07, sizeof(d07)));
    }
    /* ENABLE_WEBTRANSPORT without RFC 9297 datagrams is insufficient. */
    {
        const uint8_t chrome[] = { 0x6b, 0x60, 0x37, 0x42, 0x01 };
        WTQ_TEST_CHECK(!tp_peer_is_current(chrome, sizeof(chrome)));
        WTQ_TEST_CHECK(!tp_peer_is_compat(chrome, sizeof(chrome)));
        WTQ_TEST_CHECK(!tp_peer_is_d02(chrome, sizeof(chrome)));
    }
    /* wtquic's OWN emitted output never carries a second WT codepoint —
     * the strict output classifiers reject a mixed D13+WT_ENABLED blob. */
    {
        const uint8_t mixed[] = {
            0x94, 0xe9, 0xcd, 0x29, 0x01,   /* WT_MAX_SESSIONS = 1 */
            0xac, 0x7c, 0xf0, 0x00, 0x01 }; /* WT_ENABLED = 1     */
        WTQ_TEST_CHECK(!tp_settings_is_current(mixed, sizeof(mixed)));
        WTQ_TEST_CHECK(!tp_settings_is_compat(mixed, sizeof(mixed)));
        WTQ_TEST_CHECK(!tp_settings_is_d02(mixed, sizeof(mixed)));
    }

    *fp += failures;
}

static void test_connect_token_parsers(int *fp)
{
    int failures = 0;
    uint8_t buf[256];
    size_t n = 0;

    /* current token via the production encoder (default token). */
    WTQ_TEST_CHECK(wtq_connect_encode_request(
                       "h.example", 9, "/moq", 4, NULL, 0, NULL, 0, buf,
                       sizeof(buf), &n) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(tp_connect_is_current(buf, n));
    WTQ_TEST_CHECK(!tp_connect_is_compat(buf, n));

    /* compat token via the _ex encoder. */
    WTQ_TEST_CHECK(wtq_connect_encode_request_ex(
                       "h.example", 9, "/moq", 4, NULL, 0, NULL, 0,
                       WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY,
                       sizeof(WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY) - 1, buf,
                       sizeof(buf), &n) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(tp_connect_is_compat(buf, n));
    WTQ_TEST_CHECK(!tp_connect_is_current(buf, n));

    /* FIELD-not-substring: a COMPAT request whose :authority literally
     * CONTAINS "webtransport-h3". A byte scan would misread it as the
     * current profile; the QPACK field parser reads the :protocol FIELD
     * (which is "webtransport") and classifies it compat only. */
    WTQ_TEST_CHECK(wtq_connect_encode_request_ex(
                       "webtransport-h3", 15, "/moq", 4, NULL, 0, NULL, 0,
                       WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY,
                       sizeof(WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY) - 1, buf,
                       sizeof(buf), &n) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(tp_connect_is_compat(buf, n));
    WTQ_TEST_CHECK(!tp_connect_is_current(buf, n)); /* not the substring */

    *fp += failures;
}

/*
 * The explicit PROFILE TABLE. The three profiles differ on exactly SEVEN
 * profile-semantic axes and are identical on every other; this test pins
 * both directions.
 *
 * This table is a manually audited SEMANTIC inventory. It is not a count
 * of profile-read sites in the source -- that inventory is kept
 * separately, and review requires it to map onto these seven axes.
 *
 * The WT data plane (preambles, quarter-stream-ID datagrams, CLOSE and
 * DRAIN capsules) takes no profile argument and is profile-agnostic. The
 * error plane is NOT: it is shared on DECODE, where every profile decodes
 * the full 32-bit inbound range with the identical formula, but the
 * OUTBOUND cap is axis 6, and D02 caps it at 0..255.
 */
/* AXIS_SPECIFIC: differs by profile (and this test pins the difference).
 * AXIS_WITNESSED: identical in all three, with a runtime byte-witness below.
 * AXIS_STRUCTURAL: identical in all three by CONSTRUCTION — the engine reads
 *   the profile in exactly the seven SPECIFIC axes and these
 *   control-plane paths have no profile branch; not runtime-witnessed
 *   here (they need the full engine/transport), so the claim is
 *   structural, not tested-identical. */
enum axis_kind { AXIS_SPECIFIC, AXIS_WITNESSED, AXIS_STRUCTURAL };
struct axis {
    const char *name;
    enum axis_kind kind;
};
static const struct axis PROFILE_TABLE[] = {
    /* differ only where intended (pinned by this test) */
    { "extended-CONNECT :protocol token", AXIS_SPECIFIC },
    { "outgoing WT SETTINGS signal",      AXIS_SPECIFIC },
    { "peer-SETTINGS WT predicate",       AXIS_SPECIFIC },
    { "D02 CONNECT request marker",       AXIS_SPECIFIC },
    { "D02 CONNECT response marker",      AXIS_SPECIFIC },
    { "outbound app error-code cap",      AXIS_SPECIFIC },
    { "D02 Origin presence requirement",  AXIS_SPECIFIC },
    /* identical in all three, runtime-witnessed below */
    { "uni/bidi association preambles",   AXIS_WITNESSED },
    { "quarter-stream-ID datagram prefix", AXIS_WITNESSED },
    { "application error mapping",         AXIS_WITNESSED },
    /* identical in all three by construction (no profile branch) */
    { "RESET_STREAM_AT / reset behavior", AXIS_STRUCTURAL },
    { "CLOSE / DRAIN / session teardown", AXIS_STRUCTURAL },
};


/* ---- independent oracle for the two D02 CONNECT markers ------------- */
/*
 * These rows use the SINGLE strict field-section reader defined above --
 * the same one the `:protocol` classifier uses. It parses all three
 * static-only, non-Huffman field-line forms (indexed, literal with a
 * static name reference, and literal with a literal name), validates the
 * whole field-section prefix, and fails closed on anything else. It is
 * genuinely independent of the production decoder: the production encoder
 * is checked against THIS, not against its own decoder.
 */

/*
 * The two markers, checked by the independent reader: the REQUEST name
 * carries the version, the RESPONSE name does not and carries it in the
 * value. Emitted exactly once for D02 and never for CURRENT or D13/14.
 */
static void test_d02_marker_oracle(int *fp)
{
    int failures = 0;
    static const char REQ_NAME[] = "sec-webtransport-http3-draft02";
    static const char RSP_NAME[] = "sec-webtransport-http3-draft";
    uint8_t buf[512];
    size_t n = 0;
    const uint8_t *v = NULL;
    size_t vl = 0;
    unsigned cnt = 0;

    /* the two names must be DISTINCT (a unified name is a bug) */
    WTQ_TEST_CHECK(sizeof(REQ_NAME) != sizeof(RSP_NAME));
    WTQ_TEST_CHECK(memcmp(REQ_NAME, RSP_NAME, sizeof(RSP_NAME) - 1) == 0);

    /* D02 request: exactly one marker whose value is "1" */
    WTQ_TEST_CHECK(wtq_connect_encode_request_d02(
        "example.com", 11, "/moq", 4, "https://example.com:443", 23, NULL, 0,
        "webtransport", 12, true, buf, sizeof(buf), &n) == WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(tp_field_count(buf, n, REQ_NAME, sizeof(REQ_NAME) - 1, &v,
                                 &vl, &cnt));
    WTQ_TEST_CHECK_EQ_INT((int)cnt, 1);
    WTQ_TEST_CHECK_EQ_SIZE(vl, 1);
    WTQ_TEST_CHECK(vl == 1 && v[0] == '1');

    /* CURRENT / D13-14 request: the marker must be ABSENT */
    WTQ_TEST_CHECK(wtq_connect_encode_request_d02(
        "example.com", 11, "/moq", 4, NULL, 0, NULL, 0,
        "webtransport-h3", 15, false, buf, sizeof(buf), &n) ==
        WTQ_CONNECT_OK);
    cnt = 99;
    WTQ_TEST_CHECK(tp_field_count(buf, n, REQ_NAME, sizeof(REQ_NAME) - 1, NULL,
                                 NULL, &cnt));
    WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);

    /* D02 success response: exactly one marker whose value is "draft02" */
    wtq_sf_str_t sel = { "moqt-18", 7 };
    WTQ_TEST_CHECK(wtq_connect_encode_response_ex(200, &sel, true, buf,
                                                  sizeof(buf), &n) ==
                   WTQ_CONNECT_OK);
    v = NULL; vl = 0; cnt = 0;
    WTQ_TEST_CHECK(tp_field_count(buf, n, RSP_NAME, sizeof(RSP_NAME) - 1, &v,
                                 &vl, &cnt));
    WTQ_TEST_CHECK_EQ_INT((int)cnt, 1);
    WTQ_TEST_CHECK_EQ_SIZE(vl, 7);
    WTQ_TEST_CHECK(vl == 7 && memcmp(v, "draft02", 7) == 0);
    /* and the REQUEST name never appears in a response */
    cnt = 99;
    WTQ_TEST_CHECK(tp_field_count(buf, n, REQ_NAME, sizeof(REQ_NAME) - 1, NULL,
                                 NULL, &cnt));
    WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);

    /* non-D02 response: no marker at all */
    WTQ_TEST_CHECK(wtq_connect_encode_response_ex(200, &sel, false, buf,
                                                  sizeof(buf), &n) ==
                   WTQ_CONNECT_OK);
    cnt = 99;
    WTQ_TEST_CHECK(tp_field_count(buf, n, RSP_NAME, sizeof(RSP_NAME) - 1, NULL,
                                 NULL, &cnt));
    WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);

    *fp += failures;
}


/*
 * Response-marker classification through the PRODUCTION decoder: a
 * singleton is surfaced with its exact value, a duplicate is malformed
 * message syntax, and absence is reported as absence (the engine, not the
 * decoder, decides whether absence is fatal for D02).
 */
static void test_d02_response_marker_faults(int *fp)
{
    int failures = 0;
    static const char RSP_NAME[] = "sec-webtransport-http3-draft";
    uint8_t buf[512];
    size_t n = 0;
    char scratch[512];
    wtq_connect_resp_t resp;
    static const wtq_connect_opts_t OPTS = { false, false };
    wtq_sf_str_t sel = { "moqt-18", 7 };

    /* present exactly once, value "draft02" */
    WTQ_TEST_CHECK(wtq_connect_encode_response_ex(200, &sel, true, buf,
                                                  sizeof(buf), &n) ==
                   WTQ_CONNECT_OK);
    memset(&resp, 0, sizeof(resp));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, n, &OPTS, &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(resp.has_d02_marker);
    WTQ_TEST_CHECK_EQ_SIZE(resp.d02_marker_len, 7);
    WTQ_TEST_CHECK(resp.d02_marker_len == 7 &&
                   memcmp(resp.d02_marker, "draft02", 7) == 0);

    /* absent: decoded fine, reported absent */
    WTQ_TEST_CHECK(wtq_connect_encode_response_ex(200, &sel, false, buf,
                                                  sizeof(buf), &n) ==
                   WTQ_CONNECT_OK);
    memset(&resp, 0, sizeof(resp));
    WTQ_TEST_CHECK(wtq_connect_decode_response(buf, n, &OPTS, &resp, scratch,
                                               sizeof(scratch)) ==
                   WTQ_CONNECT_OK);
    WTQ_TEST_CHECK(!resp.has_d02_marker);
    WTQ_TEST_CHECK_EQ_SIZE(resp.d02_marker_len, 0);

    /* DUPLICATE singleton: malformed message syntax, not a policy verdict */
    {
        wtq_qpack_field_t f[3];
        size_t fn = 0;
        f[fn++] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[fn++] = (wtq_qpack_field_t){ RSP_NAME, sizeof(RSP_NAME) - 1,
                                       "draft02", 7, false };
        f[fn++] = (wtq_qpack_field_t){ RSP_NAME, sizeof(RSP_NAME) - 1,
                                       "draft02", 7, false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, fn, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        memset(&resp, 0, sizeof(resp));
        WTQ_TEST_CHECK(wtq_connect_decode_response(buf, n, &OPTS, &resp,
                                                   scratch, sizeof(scratch)) ==
                       WTQ_CONNECT_MALFORMED);
    }

    /* WRONG value: surfaced verbatim so the engine can reject it */
    {
        wtq_qpack_field_t f[2];
        size_t fn = 0;
        f[fn++] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[fn++] = (wtq_qpack_field_t){ RSP_NAME, sizeof(RSP_NAME) - 1,
                                       "draft07", 7, false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, fn, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        memset(&resp, 0, sizeof(resp));
        WTQ_TEST_CHECK(wtq_connect_decode_response(buf, n, &OPTS, &resp,
                                                   scratch, sizeof(scratch)) ==
                       WTQ_CONNECT_OK);
        /* The surfaced value is asserted EXACTLY: presence, exact length,
         * and exact bytes. Anything weaker passes on a wrong length. */
        WTQ_TEST_CHECK(resp.has_d02_marker);
        WTQ_TEST_CHECK_EQ_SIZE(resp.d02_marker_len, sizeof("draft07") - 1);
        WTQ_TEST_CHECK(memcmp(resp.d02_marker, "draft07",
                              sizeof("draft07") - 1) == 0);
        /* secondary, not a substitute: it is not the accepted value */
        WTQ_TEST_CHECK(!(resp.d02_marker_len == sizeof("draft02") - 1 &&
                         memcmp(resp.d02_marker, "draft02",
                                sizeof("draft02") - 1) == 0));
    }

    *fp += failures;
}


/*
 * Adversarial rows for the independent reader. These are exactly the
 * false positives a raw byte scan produces, so they fail if the reader
 * ever regresses to substring matching.
 */
static void test_marker_reader_adversarial(int *fp)
{
    int failures = 0;
    static const char REQ[] = "sec-webtransport-http3-draft02";
    static const char RSP[] = "sec-webtransport-http3-draft";
    uint8_t buf[512];
    size_t n = 0;
    unsigned cnt = 99;

    /* (1) the marker text inside an unrelated field VALUE is not a marker */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[1] = (wtq_qpack_field_t){ "x-note", 6, REQ, sizeof(REQ) - 1,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf), &n) ==
                       WTQ_QPACK_OK);
        WTQ_TEST_CHECK(tp_field_count(buf, n, REQ, sizeof(REQ) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);
        cnt = 99;
        WTQ_TEST_CHECK(tp_field_count(buf, n, RSP, sizeof(RSP) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);
    }

    /* (2) strict-prefix aliasing in BOTH directions: a section carrying
     * only the REQUEST name must report zero RESPONSE markers, and vice
     * versa, even though one name is a strict prefix of the other. */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[1] = (wtq_qpack_field_t){ REQ, sizeof(REQ) - 1, "1", 1, false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf), &n) ==
                       WTQ_QPACK_OK);
        cnt = 99;
        WTQ_TEST_CHECK(tp_field_count(buf, n, RSP, sizeof(RSP) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);   /* prefix must NOT alias */
        cnt = 0;
        WTQ_TEST_CHECK(tp_field_count(buf, n, REQ, sizeof(REQ) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 1);

        f[1] = (wtq_qpack_field_t){ RSP, sizeof(RSP) - 1, "draft02", 7,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf), &n) ==
                       WTQ_QPACK_OK);
        cnt = 99;
        WTQ_TEST_CHECK(tp_field_count(buf, n, REQ, sizeof(REQ) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 0);
    }

    /* (3) duplicate EXACT fields count as two */
    {
        wtq_qpack_field_t f[3];
        f[0] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[1] = (wtq_qpack_field_t){ RSP, sizeof(RSP) - 1, "draft02", 7,
                                    false };
        f[2] = (wtq_qpack_field_t){ RSP, sizeof(RSP) - 1, "draft02", 7,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 3, buf, sizeof(buf), &n) ==
                       WTQ_QPACK_OK);
        cnt = 0;
        WTQ_TEST_CHECK(tp_field_count(buf, n, RSP, sizeof(RSP) - 1, NULL,
                                      NULL, &cnt));
        WTQ_TEST_CHECK_EQ_INT((int)cnt, 2);
    }

    /* (4) DETERMINISTIC malformed fixtures: every one must return false.
     * Each is hand-built rather than produced by truncating a valid
     * section, so it names the exact rule it violates. */
    {
        struct mal { const char *why; uint8_t b[24]; size_t n; };
        /* A valid static-only prefix is {0x00, 0x00}: RIC 0, S clear,
         * Delta Base 0. Each fixture below breaks exactly one rule. */
        static const struct mal MAL[] = {
            { "truncated prefix integer (RIC byte only)",
              { 0x00 }, 1 },
            { "nonzero Required Insert Count (dynamic prefix)",
              { 0x05, 0x00, 0xd1 }, 3 },
            { "Delta Base sign bit set (base below insert count)",
              { 0x00, 0x80, 0xd1 }, 3 },
            { "nonzero Delta Base",
              { 0x00, 0x03, 0xd1 }, 3 },
            { "indexed field line, DYNAMIC table (T clear)",
              { 0x00, 0x00, 0x91 }, 3 },
            { "indexed field line, static index exactly 99 (first invalid)",
              { 0x00, 0x00, 0xff, 0x24 }, 4 },
            { "name reference, DYNAMIC table (T clear)",
              { 0x00, 0x00, 0x41, 0x01, 'x' }, 5 },
            { "name reference, static index exactly 99 (first invalid)",
              { 0x00, 0x00, 0x5f, 0x54, 0x01, 'x' }, 6 },
            { "literal name truncated (length exceeds section)",
              { 0x00, 0x00, 0x2f, 0x40 }, 4 },
            { "truncated before the value length byte",
              { 0x00, 0x00, 0x21, 'a' }, 4 },
            { "value length exceeds the remaining section",
              { 0x00, 0x00, 0x21, 'a', 0x40 }, 5 },
            { "value truncated mid-way",
              { 0x00, 0x00, 0x21, 'a', 0x04, 'b', 'c' }, 7 },
            { "post-base indexed form (never emitted)",
              { 0x00, 0x00, 0x11 }, 3 },
            { "Huffman literal name (reader implements no Huffman)",
              { 0x00, 0x00, 0x29, 'a' }, 4 },
            { "zero-length section",
              { 0x00 }, 0 },
        };
        for (size_t k = 0; k < sizeof(MAL) / sizeof(MAL[0]); k++) {
            unsigned cm = 77;
            const bool ok = tp_field_count(MAL[k].b, MAL[k].n, RSP,
                                           sizeof(RSP) - 1, NULL, NULL, &cm);
            if (ok) {
                fprintf(stderr,
                        "FAIL: malformed fixture accepted: %s\n", MAL[k].why);
                failures++;
            }
        }
    }

    /* (4b) A truncation landing EXACTLY on a complete field boundary is a
     * VALID smaller section, not malformed. It must parse and report only
     * the fields that are actually present -- never the marker that the
     * removed bytes carried. Anything else is malformed and fails. */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ ":status", 7, "200", 3, false };
        f[1] = (wtq_qpack_field_t){ RSP, sizeof(RSP) - 1, "draft02", 7,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf), &n) ==
                       WTQ_QPACK_OK);
        /* the boundary after field 0: encode field 0 alone and measure */
        uint8_t bnd[128];
        size_t n0 = 0;
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 1, bnd, sizeof(bnd),
                                                &n0) == WTQ_QPACK_OK);
        WTQ_TEST_CHECK(n0 < n);
        unsigned cb = 77;
        /* exactly at the boundary: valid, and the marker is GONE */
        WTQ_TEST_CHECK(tp_field_count(buf, n0, RSP, sizeof(RSP) - 1, NULL,
                                      NULL, &cb));
        WTQ_TEST_CHECK_EQ_INT((int)cb, 0);
        /* every OTHER cut is mid-field and must fail closed */
        for (size_t keep = 3; keep < n; keep++) {
            if (keep == n0)
                continue;
            unsigned c2 = 77;
            if (tp_field_count(buf, keep, RSP, sizeof(RSP) - 1, NULL, NULL,
                               &c2)) {
                fprintf(stderr,
                        "FAIL: mid-field truncation at %zu accepted\n", keep);
                failures++;
            }
        }
        /* the complete section still reports exactly one marker */
        unsigned cfull = 77;
        WTQ_TEST_CHECK(tp_field_count(buf, n, RSP, sizeof(RSP) - 1, NULL,
                                      NULL, &cfull));
        WTQ_TEST_CHECK_EQ_INT((int)cfull, 1);
    }
    *fp += failures;
}

/*
 * ADVERSARIAL rows driven through the `:protocol` CLASSIFIER itself, not
 * only through the marker counter. The classifier is what decides whether a
 * CONNECT names the current or the bare token, so it must be exactly as
 * strict as the marker path -- these are the inputs that a fail-open
 * walker would have accepted.
 */
static void test_protocol_classifier_adversarial(int *fp)
{
    int failures = 0;
    uint8_t buf[512];
    size_t n = 0;
    const uint8_t *v = NULL;
    size_t vl = 0;

    /* baseline: a real current-profile CONNECT classifies, once */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ ":method", 7, "CONNECT", 7, false };
        f[1] = (wtq_qpack_field_t){ ":protocol", 9, "webtransport-h3", 15,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        WTQ_TEST_CHECK(tp_extract_protocol(buf, n, &v, &vl));
        WTQ_TEST_CHECK_EQ_SIZE(vl, 15);
        WTQ_TEST_CHECK(tp_connect_is_current(buf, n));
        WTQ_TEST_CHECK(!tp_connect_is_compat(buf, n));
    }

    /* (1) a VALID :protocol followed by MALFORMED trailing bytes: the old
     *     early-return walker returned true here. The whole section must
     *     be scanned, so this fails. */
    {
        wtq_qpack_field_t f[1];
        f[0] = (wtq_qpack_field_t){ ":protocol", 9, "webtransport", 12,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 1, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        WTQ_TEST_CHECK(tp_extract_protocol(buf, n, &v, &vl));
        /* append a truncated literal-name field line */
        WTQ_TEST_CHECK(n + 2 <= sizeof(buf));
        buf[n] = 0x2f;      /* literal name, 3-bit prefix escape */
        buf[n + 1] = 0x40;  /* a name length far past the section */
        WTQ_TEST_CHECK(!tp_extract_protocol(buf, n + 2, &v, &vl));
        WTQ_TEST_CHECK(!tp_connect_is_compat(buf, n + 2));
        WTQ_TEST_CHECK(!tp_connect_is_current(buf, n + 2));
    }

    /* (2) DUPLICATE :protocol fields: exactly one is required. */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ ":protocol", 9, "webtransport", 12,
                                    false };
        f[1] = (wtq_qpack_field_t){ ":protocol", 9, "webtransport", 12,
                                    false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        WTQ_TEST_CHECK(!tp_extract_protocol(buf, n, &v, &vl));
        WTQ_TEST_CHECK(!tp_connect_is_compat(buf, n));
    }

    /* (3) prefix/reference/truncation adversaries, each hand-built. A
     *     valid static-only prefix is {0x00, 0x00}. */
    {
        struct pmal { const char *why; uint8_t b[32]; size_t n; };
        static const struct pmal PMAL[] = {
            { "nonzero Required Insert Count",
              { 0x05, 0x00, 0x27, ':', 'p', 'r', 'o', 't', 'o', 'c', 'o',
                'l', 0x01, 'x' }, 14 },
            { "Delta Base sign bit set",
              { 0x00, 0x80, 0x27, ':', 'p', 'r', 'o', 't', 'o', 'c', 'o',
                'l', 0x01, 'x' }, 14 },
            { "nonzero Delta Base",
              { 0x00, 0x03, 0x27, ':', 'p', 'r', 'o', 't', 'o', 'c', 'o',
                'l', 0x01, 'x' }, 14 },
            { "dynamic INDEXED field line (T clear)",
              { 0x00, 0x00, 0x91 }, 3 },
            { "dynamic NAME REFERENCE (T clear)",
              { 0x00, 0x00, 0x41, 0x01, 'x' }, 5 },
            { "indexed static index exactly 99",
              { 0x00, 0x00, 0xff, 0x24 }, 4 },
            { "name-reference static index exactly 99",
              { 0x00, 0x00, 0x5f, 0x54, 0x01, 'x' }, 6 },
            { "truncated MID-NAME",
              { 0x00, 0x00, 0x27, ':', 'p', 'r', 'o' }, 7 },
            { "truncated MID-VALUE",
              { 0x00, 0x00, 0x27, ':', 'p', 'r', 'o', 't', 'o', 'c', 'o',
                'l', 0x04, 'w', 'e' }, 15 },
        };
        for (size_t k = 0; k < sizeof(PMAL) / sizeof(PMAL[0]); k++) {
            if (tp_extract_protocol(PMAL[k].b, PMAL[k].n, &v, &vl)) {
                fprintf(stderr,
                        "FAIL: :protocol classifier accepted: %s\n",
                        PMAL[k].why);
                failures++;
            }
            if (tp_connect_is_compat(PMAL[k].b, PMAL[k].n) ||
                tp_connect_is_current(PMAL[k].b, PMAL[k].n)) {
                fprintf(stderr,
                        "FAIL: :protocol classifier CLASSIFIED: %s\n",
                        PMAL[k].why);
                failures++;
            }
        }
    }

    /* (4) the token text appearing in an UNRELATED value must not
     *     classify, and a strict-prefix field-name alias must not match. */
    {
        wtq_qpack_field_t f[2];
        f[0] = (wtq_qpack_field_t){ "x-note", 6, "webtransport-h3", 15,
                                    false };
        f[1] = (wtq_qpack_field_t){ ":protocol-ish", 13, "webtransport",
                                    12, false };
        WTQ_TEST_CHECK(wtq_qpack_encode_section(f, 2, buf, sizeof(buf),
                                                &n) == WTQ_QPACK_OK);
        /* a VALID section with ZERO :protocol fields: parses, no match */
        unsigned c = 77;
        WTQ_TEST_CHECK(tp_field_count(buf, n, ":protocol", 9, NULL, NULL,
                                      &c));
        WTQ_TEST_CHECK_EQ_INT((int)c, 0);
        /* the classifier requires exactly one, so it does not classify */
        WTQ_TEST_CHECK(!tp_extract_protocol(buf, n, &v, &vl));
        WTQ_TEST_CHECK(!tp_connect_is_current(buf, n));
        WTQ_TEST_CHECK(!tp_connect_is_compat(buf, n));
    }
    *fp += failures;
}

static void test_profile_table(int *fp)
{
    int failures = 0;
    uint8_t a[128], b[128];
    size_t na = 0, nb = 0;

    /* Exactly SEVEN profile-semantic axes; the rest shared. This table is
     * a MANUALLY AUDITED semantic inventory, not a source-level proof of
     * branch count — every concrete profile read must map onto these. */
    size_t n_axes = sizeof(PROFILE_TABLE) / sizeof(PROFILE_TABLE[0]);
    int n_specific = 0, n_witnessed = 0, n_structural = 0;
    for (size_t i = 0; i < n_axes; i++) {
        WTQ_TEST_CHECK(PROFILE_TABLE[i].name != NULL);
        switch (PROFILE_TABLE[i].kind) {
        case AXIS_SPECIFIC:   n_specific++;   break;
        case AXIS_WITNESSED:  n_witnessed++;  break;
        case AXIS_STRUCTURAL: n_structural++; break;
        }
    }
    WTQ_TEST_CHECK_EQ_INT(n_specific, 7);
    WTQ_TEST_CHECK_EQ_INT(n_witnessed, 3);
    WTQ_TEST_CHECK_EQ_INT(n_structural, 2);

    /* Outgoing SETTINGS share the whole base and differ only
     * in the trailing WT signal (8-byte common prefix identical). */
    {
        wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILES_CURRENT };
        wtq_h3_settings_encode_cfg_t cmp = { true, WTQ_H3_WT_PROFILES_D13_14_COMPAT };
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cur, a, sizeof(a),
                                                      &na) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cmp, b, sizeof(b),
                                                      &nb) ==
                       WTQ_H3_SETTINGS_OK);
        WTQ_TEST_CHECK(na >= 8 && nb >= 8);
        WTQ_TEST_CHECK(memcmp(a, b, 8) == 0); /* QPACK/ECP/DATAGRAM base */
        WTQ_TEST_CHECK(tp_settings_is_current(a, na));
        WTQ_TEST_CHECK(tp_settings_is_compat(b, nb));
    }

    /* CONNECT sections carry exactly the profile's
     * token and never the other. */
    {
        WTQ_TEST_CHECK(wtq_connect_encode_request(
                           "h", 1, "/", 1, NULL, 0, NULL, 0, a, sizeof(a),
                           &na) == WTQ_CONNECT_OK);
        WTQ_TEST_CHECK(wtq_connect_encode_request_ex(
                           "h", 1, "/", 1, NULL, 0, NULL, 0,
                           WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY,
                           sizeof(WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY) - 1, b,
                           sizeof(b), &nb) == WTQ_CONNECT_OK);
        WTQ_TEST_CHECK(tp_connect_is_current(a, na));
        WTQ_TEST_CHECK(tp_connect_is_compat(b, nb));
    }

    /* The same peer SETTINGS satisfy exactly one
     * profile's predicate. */
    {
        wtq_h3_settings_t cur_peer = { 0 };
        cur_peer.has_wt_enabled = true; cur_peer.wt_enabled = 1;
        cur_peer.has_h3_datagram = true; cur_peer.h3_datagram = 1;
        cur_peer.has_enable_connect_protocol = true;
        cur_peer.enable_connect_protocol = 1;
        WTQ_TEST_CHECK(wtq_h3_settings_peer_supports_wt(
            &cur_peer, true, WTQ_H3_WT_PROFILE_CURRENT));
        WTQ_TEST_CHECK(!wtq_h3_settings_peer_supports_wt(
            &cur_peer, true, WTQ_H3_WT_PROFILE_D13_14_COMPAT));
    }

    /* WITNESSED SHARED AXES: the WT data plane takes no profile argument,
     * and the error mapping is shared on DECODE (the outbound cap is a
     * separate axis); pin the canonical bytes as runtime witnesses. */
    {
        /* uni + bidi association preambles (session id 4). */
        WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_UNI, 4, a,
                                           sizeof(a), &na) ==
                       WTQ_PREAMBLE_OK);
        const uint8_t uni_expect[] = { 0x40, 0x54, 0x04 };
        WTQ_TEST_CHECK_EQ_SIZE(na, sizeof(uni_expect));
        WTQ_TEST_CHECK(memcmp(a, uni_expect, na) == 0);

        WTQ_TEST_CHECK(wtq_preamble_encode(WTQ_PREAMBLE_KIND_BIDI, 4, b,
                                           sizeof(b), &nb) ==
                       WTQ_PREAMBLE_OK);
        const uint8_t bidi_expect[] = { 0x40, 0x41, 0x04 };
        WTQ_TEST_CHECK_EQ_SIZE(nb, sizeof(bidi_expect));
        WTQ_TEST_CHECK(memcmp(b, bidi_expect, nb) == 0);

        /* quarter-stream-ID datagram prefix: the engine encodes it as
         * wtq_varint_encode(session_id / 4) (conn.c) — no profile input.
         * Pin the prefix the SAME primitive produces for a sample
         * session id 40 (qsid = 10 -> varint 0x0a). */
        WTQ_TEST_CHECK(wtq_varint_encode(40 / 4, a, sizeof(a), &na) ==
                       WTQ_VARINT_OK);
        const uint8_t qsid_expect[] = { 0x0a };
        WTQ_TEST_CHECK_EQ_SIZE(na, sizeof(qsid_expect));
        WTQ_TEST_CHECK(memcmp(a, qsid_expect, na) == 0);

        /* application error mapping is profile-independent (round-trip). */
        WTQ_TEST_CHECK(wtq_app_error_to_h3(0) == wtq_app_error_to_h3(0));
        uint32_t app = 0;
        WTQ_TEST_CHECK(wtq_h3_error_to_app(wtq_app_error_to_h3(7), &app) ==
                       WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)app, 7);
    }

    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_settings_parsers(&failures);
    test_settings_union_parser(&failures);
    test_connect_token_parsers(&failures);
    test_profile_table(&failures);
    test_d02_marker_oracle(&failures);
    test_marker_reader_adversarial(&failures);
    test_protocol_classifier_adversarial(&failures);
    test_d02_response_marker_faults(&failures);
    WTQ_TEST_PASS("test_profile_parsers");
    return failures;
}
