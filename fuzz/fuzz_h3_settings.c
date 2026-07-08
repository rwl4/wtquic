/*
 * fuzz_h3_settings — SETTINGS payload parser fuzzing.
 *
 * For every input:
 *   1. Decode as a SETTINGS payload. Any outcome must be a clean status
 *      (OK / NEED_MORE / ERR_SETTING) — never a crash, never a hang.
 *   2. If OK: encode wtquic's canonical outgoing payload for a config
 *      derived from the decoded settings, then decode THAT and require a
 *      stable second decode (encoder output must always parse cleanly,
 *      whatever config the fuzzer reaches).
 *
 * The module allocates nothing; any invariant violation aborts.
 */

#include <stdlib.h>

#include "proto/h3_settings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 512)
        size = 512; /* SETTINGS payloads are small; bound the O(n^2)
                       duplicate scan */

    wtq_h3_settings_t s;
    wtq_h3_settings_status_t st = wtq_h3_settings_decode(data, size, &s);

    if (st != WTQ_H3_SETTINGS_OK && st != WTQ_H3_SETTINGS_NEED_MORE &&
        st != WTQ_H3_SETTINGS_ERR_SETTING)
        abort();

    if (st == WTQ_H3_SETTINGS_OK) {
        /* Steer the encoder config from decoded bits so the fuzzer
         * exercises all encode shapes. */
        wtq_h3_settings_encode_cfg_t cfg = {
            s.has_enable_connect_protocol,
            (s.has_wt_max_sessions_d13 || s.has_wt_max_sessions_d07)
                ? WTQ_H3_WT_PROFILE_D13_14_COMPAT
                : WTQ_H3_WT_PROFILE_CURRENT,
        };
        uint8_t buf[64];
        size_t out_len = 0;

        if (wtq_h3_settings_encode_payload(&cfg, buf, sizeof(buf),
                                           &out_len) != WTQ_H3_SETTINGS_OK)
            abort();
        if (out_len != wtq_h3_settings_payload_len(&cfg))
            abort();

        wtq_h3_settings_t s2;
        if (wtq_h3_settings_decode(buf, out_len, &s2) !=
            WTQ_H3_SETTINGS_OK)
            abort();
        if (!s2.has_h3_datagram || s2.h3_datagram != 1)
            abort();
        /* Profile-aware: exactly one WT signal, matching cfg.wt_profile.
         * Compat emits WT_MAX_SESSIONS (never WT_ENABLED); current emits
         * WT_ENABLED (never a max-sessions codepoint). */
        if (cfg.wt_profile == WTQ_H3_WT_PROFILE_D13_14_COMPAT) {
            if (!s2.has_wt_max_sessions_d13 || s2.wt_max_sessions_d13 != 1 ||
                s2.has_wt_enabled || s2.has_wt_max_sessions_d07)
                abort();
        } else {
            if (!s2.has_wt_enabled || s2.wt_enabled != 1 ||
                s2.has_wt_max_sessions_d13 || s2.has_wt_max_sessions_d07)
                abort();
        }
        if (s2.has_enable_connect_protocol != cfg.enable_connect_protocol)
            abort();
        /* Our own encode always satisfies the server-support predicate
         * for its own profile when ECP is on. */
        if (cfg.enable_connect_protocol &&
            !wtq_h3_settings_peer_supports_wt(&s2, true, cfg.wt_profile))
            abort();

        /* Full-frame helper agrees with payload helper. */
        uint8_t frame[80];
        size_t frame_len = 0;
        if (wtq_h3_settings_encode_frame(&cfg, frame, sizeof(frame),
                                         &frame_len) != WTQ_H3_SETTINGS_OK)
            abort();
        if (frame_len <= out_len)
            abort(); /* header adds bytes */
    }

    return 0;
}
