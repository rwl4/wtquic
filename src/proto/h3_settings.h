#ifndef WTQ_PROTO_H3_SETTINGS_H
#define WTQ_PROTO_H3_SETTINGS_H

/*
 * HTTP/3 SETTINGS payload codec (RFC 9114 section 7.2.4) with the
 * WebTransport-relevant setting identifiers.
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * This module owns SETTINGS payload encode/decode and SETTINGS-local
 * validation only: duplicate identifiers, the HTTP/2-reserved
 * identifiers 0x02-0x05, and invalid VALUES for known settings are
 * errors here (RFC 9114 sections 7.2.4.1 and 11.2.2; h3zero rejects the
 * same identifier set). Control-stream ORDERING rules ("SETTINGS must
 * be first", "no second SETTINGS frame") belong to the control-stream
 * semantic layer, not here.
 *
 * Value validity: ENABLE_CONNECT_PROTOCOL (RFC 8441 s3) and H3_DATAGRAM
 * (RFC 9297 s2.1.1) are BOOLEAN — only 0 and 1 are legal, and a peer
 * sending anything else must be terminated with H3_SETTINGS_ERROR
 * rather than treated as "feature not supported". WT_ENABLED and the
 * legacy max-sessions codepoints are NOT boolean (any value > 0 is the
 * WT signal / a session count), and unknown identifiers carry arbitrary
 * values.
 *
 * Codepoints verified against the local draft-ietf-webtrans-http3-16
 * and picoquic/picohttp/h3zero.h:
 *   - SETTINGS_WT_ENABLED 0x2c7cf000 (draft-16 current profile; a 0/1
 *     boolean — value > 1 is a settings error; both sides send 1)
 *   - SETTINGS_H3_DATAGRAM 0x33 (RFC 9297; both sides send value 1)
 *   - SETTINGS_ENABLE_CONNECT_PROTOCOL 0x8 (RFC 9220)
 *   - legacy receive-compat: WT_MAX_SESSIONS 0x14e9cd29 (drafts 13-14),
 *     0xc671706a (drafts 7-12), Chrome ENABLE_WEBTRANSPORT 0x2b603742
 *   - QPACK_MAX_TABLE_CAPACITY 0x1, QPACK_BLOCKED_STREAMS 0x7 (RFC 9204),
 *     MAX_FIELD_SECTION_SIZE 0x6 (RFC 9114 — a VALID id, not reserved)
 *
 * This module never allocates. Duplicate detection re-scans the already
 * parsed payload prefix instead of storing seen identifiers — O(n^2)
 * over a cold-path frame, zero state.
 */

#include "varint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Setting identifiers. */
#define WTQ_H3_SET_QPACK_MAX_TABLE_CAPACITY UINT64_C(0x01)
#define WTQ_H3_SET_MAX_FIELD_SECTION_SIZE   UINT64_C(0x06)
#define WTQ_H3_SET_QPACK_BLOCKED_STREAMS    UINT64_C(0x07)
#define WTQ_H3_SET_ENABLE_CONNECT_PROTOCOL  UINT64_C(0x08)
#define WTQ_H3_SET_H3_DATAGRAM              UINT64_C(0x33)
#define WTQ_H3_SET_WT_ENABLED               UINT64_C(0x2c7cf000)
#define WTQ_H3_SET_WT_MAX_SESSIONS_D13      UINT64_C(0x14e9cd29)
#define WTQ_H3_SET_WT_MAX_SESSIONS_D07      UINT64_C(0xc671706a)
#define WTQ_H3_SET_ENABLE_WEBTRANSPORT_LEG  UINT64_C(0x2b603742)

typedef int wtq_h3_settings_status_t;
#define WTQ_H3_SETTINGS_OK          WTQ_VARINT_OK
#define WTQ_H3_SETTINGS_NEED_MORE   WTQ_VARINT_NEED_MORE
#define WTQ_H3_SETTINGS_BUFFER      WTQ_VARINT_BUFFER
#define WTQ_H3_SETTINGS_RANGE       WTQ_VARINT_RANGE
/* Duplicate identifier (known or unknown), HTTP/2-reserved identifier
 * 0x02-0x05, or an invalid value for a known setting (the boolean
 * settings ENABLE_CONNECT_PROTOCOL and H3_DATAGRAM accept only 0/1).
 * Maps to H3_SETTINGS_ERROR (0x109) at the connection layer. */
#define WTQ_H3_SETTINGS_ERR_SETTING (-3)

/* Decoded view. has_* flags distinguish "absent" from "present with
 * value 0" — required: a peer sending WT_ENABLED=0 or H3_DATAGRAM=0 has
 * explicitly NOT enabled the feature. */
typedef struct wtq_h3_settings {
    bool has_qpack_max_table_capacity;
    bool has_max_field_section_size;
    bool has_qpack_blocked_streams;
    bool has_enable_connect_protocol;
    bool has_h3_datagram;
    bool has_wt_enabled;
    bool has_wt_max_sessions_d13;
    bool has_wt_max_sessions_d07;
    bool has_enable_webtransport_leg;
    uint64_t qpack_max_table_capacity;
    uint64_t max_field_section_size;
    uint64_t qpack_blocked_streams;
    uint64_t enable_connect_protocol;
    uint64_t h3_datagram;
    uint64_t wt_enabled;
    uint64_t wt_max_sessions_d13;
    uint64_t wt_max_sessions_d07;
    uint64_t enable_webtransport_leg;
    size_t unknown_count; /* unknown, non-reserved ids (incl. grease) */
} wtq_h3_settings_t;

/*
 * Decode a SETTINGS frame payload from a complete or growing span.
 *   OK:          *out fully populated; the whole span was consumed.
 *   NEED_MORE:   span ends mid identifier or mid value — caller keeps
 *                accumulating payload bytes and calls again with more.
 *   ERR_SETTING: duplicate identifier, reserved 0x02-0x05, or an
 *                invalid value for a known setting (a boolean setting
 *                carrying a value > 1).
 * An empty payload (len == 0) is valid and decodes to all-absent.
 * Non-minimal varints are accepted (see varint.h) — value validity is
 * judged on the DECODED value, so the encoding cannot smuggle one past.
 * ATOMIC: *out is written only on OK; any error leaves it untouched.
 */
wtq_h3_settings_status_t wtq_h3_settings_decode(const uint8_t *payload,
                                                size_t len,
                                                wtq_h3_settings_t *out);

/* The WebTransport-over-HTTP/3 wire profile that selects which WT SETTINGS
 * we emit (proto-layer mirror of the public wtq_webtransport_profile_t;
 * the engine maps one to the other). Each profile contributes exactly ONE
 * WT setting to the advertisement. */
typedef enum wtq_h3_wt_profile {
    /* draft-16: SETTINGS_WT_ENABLED (0x2c7cf000) = 1. */
    WTQ_H3_WT_PROFILE_CURRENT = 0,
    /* drafts 13/14 compat: SETTINGS_WT_MAX_SESSIONS (0x14e9cd29) = 1.
     * NOT the D07 codepoint (0xc671706a), NOT WT_ENABLED, no flow control. */
    WTQ_H3_WT_PROFILE_D13_14_COMPAT = 1
} wtq_h3_wt_profile_t;

/*
 * A SET of the profiles above — the proto-layer mirror of the public
 * wtq_webtransport_profile_set_t. This header is internal and never
 * includes a public API header, so the set type is mirrored here exactly
 * as wtq_h3_wt_profile_t mirrors the public profile enum; the API/backend
 * boundary converts between them and static-asserts the masks match.
 *
 * Membership is spelled with explicit constants rather than a shift macro:
 * a generic 1u << p is undefined behaviour for an out-of-range profile.
 */
typedef uint64_t wtq_h3_wt_profile_set_t;

#define WTQ_H3_WT_PROFILES_CURRENT       UINT64_C(0x1)
#define WTQ_H3_WT_PROFILES_D13_14_COMPAT UINT64_C(0x2)

/* Every profile this build knows — the validity mask for a caller's set. */
#define WTQ_H3_WT_PROFILES_ALL \
    (WTQ_H3_WT_PROFILES_CURRENT | WTQ_H3_WT_PROFILES_D13_14_COMPAT)

/* How many profiles this build knows: the upper bound on WT settings in
 * one advertisement. The precedence table's length is static-asserted
 * against it, so the two cannot drift. */
#define WTQ_H3_WT_PROFILE_COUNT 2

/* The one-bit set for a single profile, or 0 for an unknown value. Total
 * by construction — no shift, so no undefined behaviour. */
static inline wtq_h3_wt_profile_set_t
wtq_h3_wt_profile_bit(wtq_h3_wt_profile_t profile)
{
    switch (profile) {
    case WTQ_H3_WT_PROFILE_CURRENT:
        return WTQ_H3_WT_PROFILES_CURRENT;
    case WTQ_H3_WT_PROFILE_D13_14_COMPAT:
        return WTQ_H3_WT_PROFILES_D13_14_COMPAT;
    }
    return 0;
}

/*
 * wtquic's outgoing SETTINGS:
 *   always: QPACK_MAX_TABLE_CAPACITY=0, QPACK_BLOCKED_STREAMS=0 (explicit
 *           zeros: unambiguous "no dynamic table" signal, matches h3zero),
 *           H3_DATAGRAM=1
 *   profiles: one WT setting per member of wt_profiles, in ascending
 *           identifier order — WT_MAX_SESSIONS 0x14e9cd29=1 (D13/14 compat)
 *           and/or WT_ENABLED 0x2c7cf000=1 (current). Never the D07
 *           0xc671706a codepoint, which stays receive-only.
 *   config: ENABLE_CONNECT_PROTOCOL (servers MUST send it; harmless from
 *           clients).
 *
 * SETTINGS advertise CAPABILITIES, not an already-selected dialect: a set
 * with several members is a legitimate multi-version advertisement (see
 * draft-16 s7.1, "sends a SETTINGS_WT_ENABLED value for each supported
 * version"). Selecting one from the peer's reply is
 * wtq_h3_settings_select_profile's job.
 *
 * The set is masked to WTQ_H3_WT_PROFILES_ALL first; if nothing KNOWN
 * remains — an empty set, or a non-zero set carrying only unknown bits —
 * it encodes as CURRENT-only. This codec is deliberately TOTAL: it has no
 * way to report an error, and emitting zero WT settings ("no
 * WebTransport") is not a configuration wtquic ever wants. Rejecting an
 * empty or out-of-range set belongs to the layer that accepts it from a
 * caller (the engine at conn-create), so a mistake fails loudly there;
 * this fallback is defence in depth, never public acceptance of unknown
 * bits.
 */
typedef struct wtq_h3_settings_encode_cfg {
    bool enable_connect_protocol;
    wtq_h3_wt_profile_set_t wt_profiles;
} wtq_h3_settings_encode_cfg_t;

/* Encoded payload length for the configuration. Never 0. */
size_t wtq_h3_settings_payload_len(const wtq_h3_settings_encode_cfg_t *cfg);

/*
 * Encode the SETTINGS payload into dst[cap]. Settings are emitted in
 * ascending identifier order (deterministic, byte-exact testable). On
 * OK, *out_len is the number of bytes written. dst untouched on error.
 */
wtq_h3_settings_status_t wtq_h3_settings_encode_payload(
    const wtq_h3_settings_encode_cfg_t *cfg, uint8_t *dst, size_t cap,
    size_t *out_len);

/*
 * Convenience: encode the complete SETTINGS frame (type 0x04 + length +
 * payload) for the control-stream preface. Same semantics as
 * encode_payload. (A frame-decode twin is deliberately absent: the
 * control-stream layer parses frame headers with wtq_h3_frame_dec_t and
 * hands the accumulated payload span to wtq_h3_settings_decode.)
 */
wtq_h3_settings_status_t wtq_h3_settings_encode_frame(
    const wtq_h3_settings_encode_cfg_t *cfg, uint8_t *dst, size_t cap,
    size_t *out_len);

/*
 * Choose the wire profile to speak with this peer: the HIGHEST-precedence
 * member of (our `set` INTERSECT the profiles the peer advertised) that
 * also meets the profile-independent requirements. Pure function, no
 * connection state.
 *
 * Returns true and writes *out on success; returns false and leaves *out
 * UNTOUCHED when there is no mutual profile. There is deliberately no
 * "none" enum member — the boolean carries that, so no caller can mistake
 * a sentinel for the zero-valued CURRENT profile.
 *
 * PRECEDENCE is newest-draft-first and explicit (see the table in the .c),
 * NOT the enum's numeric order, so adding a profile cannot silently
 * reorder preference.
 *
 * Per-profile WT signal (a signal from a profile outside `set` never
 * counts, and never selects a profile on its own):
 *   WTQ_H3_WT_PROFILE_CURRENT:        WT_ENABLED == 1.
 *   WTQ_H3_WT_PROFILE_D13_14_COMPAT:  WT_MAX_SESSIONS (0x14e9cd29) > 0.
 *
 * Profile-independent requirements:
 *   peer_is_server true (we are the client evaluating a server):
 *     H3_DATAGRAM == 1 AND ENABLE_CONNECT_PROTOCOL == 1.
 *   peer_is_server false (we are the server evaluating a client):
 *     H3_DATAGRAM == 1.
 *
 * Present-with-value-0 settings count as NOT enabled.
 */
bool wtq_h3_settings_select_profile(const wtq_h3_settings_t *peer,
                                    bool peer_is_server,
                                    wtq_h3_wt_profile_set_t set,
                                    wtq_h3_wt_profile_t *out);

/*
 * Does a peer's SETTINGS indicate enough WebTransport support for exactly
 * ONE profile? A thin convenience over wtq_h3_settings_select_profile with
 * a single-member set — one implementation, no duplicated policy.
 */
bool wtq_h3_settings_peer_supports_wt(const wtq_h3_settings_t *peer,
                                      bool peer_is_server,
                                      wtq_h3_wt_profile_t profile);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_H3_SETTINGS_H */
