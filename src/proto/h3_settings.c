#include "h3_settings.h"

#include "h3_frame.h"

static bool setting_is_h2_reserved(uint64_t id)
{
    return id >= 0x02 && id <= 0x05;
}

/* Scan the already-decoded prefix for a previous occurrence of id.
 * Zero-allocation duplicate detection: SETTINGS is cold path, O(n^2)
 * over the payload is fine. The prefix is known well-formed (we just
 * decoded it), so the varint decodes here cannot fail. */
static bool setting_seen_before(const uint8_t *payload, size_t prefix_len,
                                uint64_t id)
{
    size_t off = 0;

    while (off < prefix_len) {
        uint64_t prev_id = 0;
        uint64_t prev_value = 0;
        size_t c = 0;
        (void)wtq_varint_decode(payload + off, prefix_len - off, &prev_id,
                                &c);
        off += c;
        (void)wtq_varint_decode(payload + off, prefix_len - off,
                                &prev_value, &c);
        off += c;
        if (prev_id == id)
            return true;
    }
    return false;
}

wtq_h3_settings_status_t wtq_h3_settings_decode(const uint8_t *payload,
                                                size_t len,
                                                wtq_h3_settings_t *out)
{
    wtq_h3_settings_t s;
    size_t off = 0;

    /* Zero-init without memset dependency on struct layout. */
    s = (wtq_h3_settings_t){ 0 };

    while (off < len) {
        uint64_t id = 0;
        uint64_t value = 0;
        size_t c = 0;

        wtq_varint_status_t st =
            wtq_varint_decode(payload + off, len - off, &id, &c);
        if (st != WTQ_VARINT_OK)
            return WTQ_H3_SETTINGS_NEED_MORE;
        size_t id_off = off;
        off += c;

        st = wtq_varint_decode(payload + off, len - off, &value, &c);
        if (st != WTQ_VARINT_OK)
            return WTQ_H3_SETTINGS_NEED_MORE;
        off += c;

        if (setting_is_h2_reserved(id))
            return WTQ_H3_SETTINGS_ERR_SETTING;
        if (setting_seen_before(payload, id_off, id))
            return WTQ_H3_SETTINGS_ERR_SETTING;

        switch (id) {
        case WTQ_H3_SET_QPACK_MAX_TABLE_CAPACITY:
            s.has_qpack_max_table_capacity = true;
            s.qpack_max_table_capacity = value;
            break;
        case WTQ_H3_SET_MAX_FIELD_SECTION_SIZE:
            s.has_max_field_section_size = true;
            s.max_field_section_size = value;
            break;
        case WTQ_H3_SET_QPACK_BLOCKED_STREAMS:
            s.has_qpack_blocked_streams = true;
            s.qpack_blocked_streams = value;
            break;
        /* The two BOOLEAN settings: any value but 0 or 1 is a SETTINGS
         * error, not merely "unsupported" (RFC 8441 s3, RFC 9297
         * s2.1.1). The check is on the DECODED value, so a non-minimal
         * varint cannot smuggle a 2 past it. */
        case WTQ_H3_SET_ENABLE_CONNECT_PROTOCOL:
            if (value > 1)
                return WTQ_H3_SETTINGS_ERR_SETTING;
            s.has_enable_connect_protocol = true;
            s.enable_connect_protocol = value;
            break;
        case WTQ_H3_SET_H3_DATAGRAM:
            if (value > 1)
                return WTQ_H3_SETTINGS_ERR_SETTING;
            s.has_h3_datagram = true;
            s.h3_datagram = value;
            break;
        case WTQ_H3_SET_WT_ENABLED:
            /* draft-16 WT_ENABLED is a 0/1 boolean; > 1 is malformed. */
            if (value > 1)
                return WTQ_H3_SETTINGS_ERR_SETTING;
            s.has_wt_enabled = true;
            s.wt_enabled = value;
            break;
        case WTQ_H3_SET_WT_MAX_SESSIONS_D13:
            s.has_wt_max_sessions_d13 = true;
            s.wt_max_sessions_d13 = value;
            break;
        case WTQ_H3_SET_WT_MAX_SESSIONS_D07:
            s.has_wt_max_sessions_d07 = true;
            s.wt_max_sessions_d07 = value;
            break;
        case WTQ_H3_SET_ENABLE_WEBTRANSPORT_LEG:
            s.has_enable_webtransport_leg = true;
            s.enable_webtransport_leg = value;
            break;
        default:
            s.unknown_count++;
            break;
        }
    }

    *out = s;
    return WTQ_H3_SETTINGS_OK;
}

/* The v1 outgoing settings in ascending identifier order. */
typedef struct out_setting {
    uint64_t id;
    uint64_t value;
} out_setting_t;

/* Worst case: 2 QPACK zeros + ECP + DATAGRAM + one WT setting per known
 * profile (a full multi-version advertisement). */
#define MAX_OUT_SETTINGS (4 + WTQ_H3_WT_PROFILE_COUNT)

static size_t build_out_settings(const wtq_h3_settings_encode_cfg_t *cfg,
                                 out_setting_t *out)
{
    size_t n = 0;

    out[n].id = WTQ_H3_SET_QPACK_MAX_TABLE_CAPACITY;
    out[n++].value = 0;
    out[n].id = WTQ_H3_SET_QPACK_BLOCKED_STREAMS;
    out[n++].value = 0;
    if (cfg->enable_connect_protocol) {
        out[n].id = WTQ_H3_SET_ENABLE_CONNECT_PROTOCOL;
        out[n++].value = 1;
    }
    out[n].id = WTQ_H3_SET_H3_DATAGRAM;
    out[n++].value = 1;
    /*
     * One WT setting per set member, in ASCENDING identifier order so the
     * payload stays byte-exact testable (0x14e9cd29 < 0x2c7cf000). This is
     * a capability advertisement, not a selection: several members is a
     * legitimate multi-version offer. The D07 codepoint (0xc671706a) is
     * never emitted — it stays receive-only.
     *
     * TOTALITY: mask to the profiles this build knows FIRST, then fall back
     * to CURRENT-only when nothing known remains. Masking before the test is
     * what makes the fallback true: a non-zero set carrying only UNKNOWN bits
     * would otherwise slip past a bare `== 0` check and emit an
     * advertisement with no WT capability signal at all. Rejecting unknown
     * caller bits stays the engine/public boundary's job; this is defence in
     * depth, not public acceptance.
     */
    wtq_h3_wt_profile_set_t profiles =
        cfg->wt_profiles & WTQ_H3_WT_PROFILES_ALL;
    if (profiles == 0)
        profiles = WTQ_H3_WT_PROFILES_CURRENT;
    if (profiles & WTQ_H3_WT_PROFILES_D13_14_COMPAT) {
        out[n].id = WTQ_H3_SET_WT_MAX_SESSIONS_D13;
        out[n++].value = 1;
    }
    if (profiles & WTQ_H3_WT_PROFILES_CURRENT) {
        /* draft-16 s3.1: the value MUST be exactly 1. Always send 1 —
         * drafts 15 and 16 share this codepoint but draft-16 treats > 1 as
         * H3_SETTINGS_ERROR, so 1 is the only value both accept. */
        out[n].id = WTQ_H3_SET_WT_ENABLED;
        out[n++].value = 1;
    }
    return n;
}

size_t wtq_h3_settings_payload_len(const wtq_h3_settings_encode_cfg_t *cfg)
{
    out_setting_t set[MAX_OUT_SETTINGS];
    size_t n = build_out_settings(cfg, set);
    size_t total = 0;

    for (size_t i = 0; i < n; i++)
        total += wtq_varint_len(set[i].id) + wtq_varint_len(set[i].value);
    return total;
}

wtq_h3_settings_status_t wtq_h3_settings_encode_payload(
    const wtq_h3_settings_encode_cfg_t *cfg, uint8_t *dst, size_t cap,
    size_t *out_len)
{
    out_setting_t set[MAX_OUT_SETTINGS];
    size_t n = build_out_settings(cfg, set);
    size_t need = wtq_h3_settings_payload_len(cfg);

    if (cap < need)
        return WTQ_H3_SETTINGS_BUFFER;

    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        size_t c = 0;
        /* Capacity checked up front; these cannot fail. */
        (void)wtq_varint_encode(set[i].id, dst + off, cap - off, &c);
        off += c;
        (void)wtq_varint_encode(set[i].value, dst + off, cap - off, &c);
        off += c;
    }

    *out_len = off;
    return WTQ_H3_SETTINGS_OK;
}

wtq_h3_settings_status_t wtq_h3_settings_encode_frame(
    const wtq_h3_settings_encode_cfg_t *cfg, uint8_t *dst, size_t cap,
    size_t *out_len)
{
    size_t payload_len = wtq_h3_settings_payload_len(cfg);
    size_t header_len =
        wtq_h3_frame_header_len(WTQ_H3_FRAME_SETTINGS, payload_len);

    if (cap < header_len + payload_len)
        return WTQ_H3_SETTINGS_BUFFER;

    size_t hl = 0;
    (void)wtq_h3_frame_encode_header(WTQ_H3_FRAME_SETTINGS, payload_len,
                                     dst, cap, &hl);
    size_t pl = 0;
    (void)wtq_h3_settings_encode_payload(cfg, dst + hl, cap - hl, &pl);

    *out_len = hl + pl;
    return WTQ_H3_SETTINGS_OK;
}

/*
 * Profile precedence, NEWEST DRAFT FIRST. This ordering is the negotiation
 * policy ("the highest version supported by both endpoints is selected",
 * draft-16 s7.1) and is deliberately explicit rather than derived from the
 * enum's numeric values, so introducing a profile cannot silently reorder
 * preference.
 */
static const wtq_h3_wt_profile_t WT_PRECEDENCE[] = {
    WTQ_H3_WT_PROFILE_CURRENT,        /* drafts 15-16 */
    WTQ_H3_WT_PROFILE_D13_14_COMPAT,  /* drafts 13-14 */
};

_Static_assert(sizeof(WT_PRECEDENCE) / sizeof(WT_PRECEDENCE[0]) ==
                   WTQ_H3_WT_PROFILE_COUNT,
               "every known profile must appear exactly once in the "
               "precedence table");

/* Does the peer advertise THIS profile's WT signal? */
static bool peer_advertises(const wtq_h3_settings_t *peer,
                            wtq_h3_wt_profile_t profile)
{
    switch (profile) {
    case WTQ_H3_WT_PROFILE_CURRENT:
        /* draft-16: a 0/1 boolean; the decoder already rejects > 1. */
        return peer->has_wt_enabled && peer->wt_enabled == 1;
    case WTQ_H3_WT_PROFILE_D13_14_COMPAT:
        return peer->has_wt_max_sessions_d13 &&
               peer->wt_max_sessions_d13 > 0;
    }
    return false;
}

bool wtq_h3_settings_select_profile(const wtq_h3_settings_t *peer,
                                    bool peer_is_server,
                                    wtq_h3_wt_profile_set_t set,
                                    wtq_h3_wt_profile_t *out)
{
    if (peer == NULL || out == NULL)
        return false;

    /* Profile-independent requirements first: they gate every profile
     * equally, so a peer failing them has no mutual profile at all. */
    if (!(peer->has_h3_datagram && peer->h3_datagram == 1))
        return false;
    if (peer_is_server &&
        !(peer->has_enable_connect_protocol &&
          peer->enable_connect_protocol == 1))
        return false;

    /* The intersection, walked newest-first: the first hit is the highest
     * mutually supported profile. A signal for a profile outside `set` is
     * ignored — it can never select anything on its own. */
    for (size_t i = 0; i < WTQ_H3_WT_PROFILE_COUNT; i++) {
        wtq_h3_wt_profile_t p = WT_PRECEDENCE[i];

        if ((set & wtq_h3_wt_profile_bit(p)) == 0)
            continue;
        if (!peer_advertises(peer, p))
            continue;
        *out = p;
        return true;
    }
    return false;
}

bool wtq_h3_settings_peer_supports_wt(const wtq_h3_settings_t *peer,
                                      bool peer_is_server,
                                      wtq_h3_wt_profile_t profile)
{
    wtq_h3_wt_profile_t sel;

    /* One implementation of the policy: ask for exactly this profile. */
    return wtq_h3_settings_select_profile(peer, peer_is_server,
                                          wtq_h3_wt_profile_bit(profile),
                                          &sel);
}
