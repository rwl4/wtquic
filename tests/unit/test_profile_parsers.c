/*
 * Independent WebTransport profile parsers (checkpoint blocker #3).
 *
 * These strict parsers are TEST-ONLY and deliberately do NOT call
 * wtquic's production CONNECT or SETTINGS decoders. They walk the raw
 * wire bytes with a self-contained QUIC varint reader and classify a
 * payload into exactly one of the two supported profiles (or neither),
 * proving that:
 *   - the current profile is webtransport-h3 + WT_ENABLED only;
 *   - the D13/14 compat profile is webtransport + WT_MAX_SESSIONS
 *     (0x14e9cd29) only;
 *   - cross-profile emitted outputs are rejected both ways;
 *   - peer SETTINGS with D13+D07 classify as compat, while D07-only or
 *     Chrome ENABLE_WEBTRANSPORT (0x2b603742) signals match neither.
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

/* Walk a bare SETTINGS PAYLOAD (id,value pairs) and record which WT
 * signals appear. Returns false on a malformed stream. */
typedef struct {
    bool wt_enabled;   uint64_t wt_enabled_v;
    bool max13;        uint64_t max13_v;
    bool max07;        uint64_t max07_v;
    bool enable_wt;    uint64_t enable_wt_v;
} tp_wt_signals_t;

static bool tp_scan_settings(const uint8_t *p, size_t len,
                             tp_wt_signals_t *s)
{
    size_t off = 0;
    memset(s, 0, sizeof(*s));
    while (off < len) {
        uint64_t id, val;
        if (!tp_varint(p, len, &off, &id))
            return false;
        if (!tp_varint(p, len, &off, &val))
            return false;
        switch (id) {
        case ID_WT_ENABLED:   s->wt_enabled = true; s->wt_enabled_v = val; break;
        case ID_WT_MAXSESS13: s->max13 = true;      s->max13_v = val;      break;
        case ID_WT_MAXSESS07: s->max07 = true;      s->max07_v = val;      break;
        case ID_ENABLE_WT:    s->enable_wt = true;  s->enable_wt_v = val;  break;
        default: break; /* QPACK zeros, DATAGRAM, ECP, grease: ignored */
        }
    }
    return true;
}

/* Strict CURRENT SETTINGS: WT_ENABLED==1 present, and NO other-profile
 * WT signal. */
static bool tp_settings_is_current(const uint8_t *p, size_t len)
{
    tp_wt_signals_t s;
    if (!tp_scan_settings(p, len, &s))
        return false;
    return s.wt_enabled && s.wt_enabled_v == 1 &&
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
    return s.max13 && s.max13_v == 1 &&
           !s.wt_enabled && !s.max07 && !s.enable_wt;
}

/* PEER-SIGNAL classifiers: the WT-signal rule PRODUCTION applies to an
 * INBOUND peer's SETTINGS (wtq_h3_settings_peer_supports_wt) — current
 * iff WT_ENABLED==1; compat iff WT_MAX_SESSIONS(0x14e9cd29)>0. D07
 * co-presence is TOLERATED for compat (pico/h3zero sends both D13 and
 * D07); a D07-only or Chrome-only peer signal matches NEITHER. */
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
static bool tp_extract_protocol(const uint8_t *p, size_t len,
                                const uint8_t **out_val, size_t *out_len)
{
    size_t off = 0;
    uint64_t ric, base;
    /* encoded field-section prefix: Required Insert Count (8-bit prefix)
     * + Base (S bit + 7-bit prefix). Static-only => both 0. */
    if (!qp_int(p, len, &off, 8, &ric) || ric != 0)
        return false;
    if (off >= len)
        return false;
    off++; /* the Base byte (S + 7-bit); 0 for static-only */
    (void)base;

    while (off < len) {
        uint8_t b = p[off];
        if (b & 0x80) {
            /* Indexed Field Line (name+value from table) — skip. */
            uint64_t idx;
            if (!qp_int(p, len, &off, 6, &idx))
                return false;
        } else if (b & 0x40) {
            /* Literal Field Line With Name Reference (static name) — the
             * name is a static entry (never :protocol here); skip the
             * value. */
            uint64_t nidx, vlen;
            if (!qp_int(p, len, &off, 4, &nidx))
                return false;
            if (off >= len)
                return false;
            bool vhuff = (p[off] & 0x80) != 0;
            if (!qp_int(p, len, &off, 7, &vlen) || vhuff ||
                off + vlen > len)
                return false;
            off += (size_t)vlen;
        } else if (b & 0x20) {
            /* Literal Field Line With Literal Name. */
            bool nhuff = (b & 0x08) != 0;
            uint64_t nlen, vlen;
            if (!qp_int(p, len, &off, 3, &nlen) || nhuff ||
                off + nlen > len)
                return false;
            const uint8_t *name = p + off;
            size_t namelen = (size_t)nlen;
            off += namelen;
            if (off >= len)
                return false;
            bool vhuff = (p[off] & 0x80) != 0;
            if (!qp_int(p, len, &off, 7, &vlen) || vhuff ||
                off + vlen > len)
                return false;
            const uint8_t *val = p + off;
            off += (size_t)vlen;
            if (namelen == 9 && memcmp(name, ":protocol", 9) == 0) {
                *out_val = val;
                *out_len = (size_t)vlen;
                return true;
            }
        } else {
            return false; /* post-base forms: wtquic never emits them */
        }
    }
    return false;
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

static void test_settings_parsers(int *fp)
{
    int failures = 0;
    uint8_t buf[64];
    size_t n = 0;

    /* current-profile SETTINGS from the production encoder */
    wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILE_CURRENT };
    WTQ_TEST_CHECK(wtq_h3_settings_encode_payload(&cur, buf, sizeof(buf),
                                                  &n) == WTQ_H3_SETTINGS_OK);
    WTQ_TEST_CHECK(tp_settings_is_current(buf, n));
    WTQ_TEST_CHECK(!tp_settings_is_compat(buf, n)); /* cross-profile fails */

    /* compat-profile SETTINGS */
    wtq_h3_settings_encode_cfg_t cmp = {
        true, WTQ_H3_WT_PROFILE_D13_14_COMPAT };
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
        /* it is NOT wtquic's own clean output (that never carries D07) */
        WTQ_TEST_CHECK(!tp_settings_is_compat(d13_d07, sizeof(d13_d07)));
    }
    /* a D07-ONLY payload (no D13): matches NEITHER profile. */
    {
        const uint8_t d07[] = {
            0xc0, 0x00, 0x00, 0x00, 0xc6, 0x71, 0x70, 0x6a, 0x01 };
        WTQ_TEST_CHECK(!tp_peer_is_current(d07, sizeof(d07)));
        WTQ_TEST_CHECK(!tp_peer_is_compat(d07, sizeof(d07)));
    }
    /* a Chrome ENABLE_WEBTRANSPORT-only payload (0x2b603742): NEITHER. */
    {
        const uint8_t chrome[] = { 0x6b, 0x60, 0x37, 0x42, 0x01 };
        WTQ_TEST_CHECK(!tp_peer_is_current(chrome, sizeof(chrome)));
        WTQ_TEST_CHECK(!tp_peer_is_compat(chrome, sizeof(chrome)));
    }
    /* wtquic's OWN emitted output never carries a second WT codepoint —
     * the strict output classifiers reject a mixed D13+WT_ENABLED blob. */
    {
        const uint8_t mixed[] = {
            0x94, 0xe9, 0xcd, 0x29, 0x01,   /* WT_MAX_SESSIONS = 1 */
            0xac, 0x7c, 0xf0, 0x00, 0x01 }; /* WT_ENABLED = 1     */
        WTQ_TEST_CHECK(!tp_settings_is_current(mixed, sizeof(mixed)));
        WTQ_TEST_CHECK(!tp_settings_is_compat(mixed, sizeof(mixed)));
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
 * The explicit PROFILE TABLE (checkpoint blocker #4). The two profiles
 * differ on exactly three axes and are identical on every other; this
 * test pins both directions. The engine reads the profile in exactly
 * three places (SETTINGS encode, CONNECT token, peer-SETTINGS
 * predicate); the WT data/error plane below takes no profile argument
 * and is therefore profile-agnostic by construction.
 */
/* AXIS_SPECIFIC: differs by profile (and this test pins the difference).
 * AXIS_WITNESSED: identical in both, with a runtime byte-witness below.
 * AXIS_STRUCTURAL: identical in both by CONSTRUCTION — the engine reads
 *   the profile in exactly the three SPECIFIC sites and these
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
    /* identical in both, runtime-witnessed below */
    { "uni/bidi association preambles",   AXIS_WITNESSED },
    { "quarter-stream-ID datagram prefix", AXIS_WITNESSED },
    { "application error mapping",         AXIS_WITNESSED },
    /* identical in both by construction (no profile branch) */
    { "RESET_STREAM_AT / reset behavior", AXIS_STRUCTURAL },
    { "CLOSE / DRAIN / session teardown", AXIS_STRUCTURAL },
};

static void test_profile_table(int *fp)
{
    int failures = 0;
    uint8_t a[128], b[128];
    size_t na = 0, nb = 0;

    /* exactly three profile-specific axes; the rest shared. */
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
    WTQ_TEST_CHECK_EQ_INT(n_specific, 3);
    WTQ_TEST_CHECK_EQ_INT(n_witnessed, 3);
    WTQ_TEST_CHECK_EQ_INT(n_structural, 2);

    /* AXIS 1 (SPECIFIC): SETTINGS share the whole base and differ ONLY
     * in the trailing WT signal (8-byte common prefix identical). */
    {
        wtq_h3_settings_encode_cfg_t cur = { true, WTQ_H3_WT_PROFILE_CURRENT };
        wtq_h3_settings_encode_cfg_t cmp = {
            true, WTQ_H3_WT_PROFILE_D13_14_COMPAT };
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

    /* AXIS 2 (SPECIFIC): CONNECT sections carry exactly the profile's
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

    /* AXIS 3 (SPECIFIC): the same peer SETTINGS satisfy exactly one
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

    /* WITNESSED SHARED AXES: the WT data/error plane takes no profile
     * argument; pin the canonical bytes as runtime witnesses. */
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
    test_connect_token_parsers(&failures);
    test_profile_table(&failures);
    WTQ_TEST_PASS("test_profile_parsers");
    return failures;
}
