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
         * exercises all encode shapes. Each supported profile is steered
         * ONLY by its own codepoint.
         * D07 (0xc671706a) is a DISTINCT unsupported generation, never
         * evidence of D13/14 — mapping it here would both contradict the
         * architecture and weaken this oracle by turning a D07-only input
         * into a D13 output shape. D07 receive DECODING is unchanged; it
         * simply steers nothing. */
        wtq_h3_wt_profile_set_t set = 0;
        if (s.has_wt_max_sessions_d13)
            set |= WTQ_H3_WT_PROFILES_D13_14_COMPAT;
        if (s.has_wt_enabled)
            set |= WTQ_H3_WT_PROFILES_CURRENT;
        /* Load-bearing: a D07-only (or Chrome/D02-only) decode must leave
         * the supported set empty, so it can never select or advertise a
         * supported profile. */
        if (!s.has_wt_max_sessions_d13 && !s.has_wt_enabled && set != 0)
            abort();
        if (s.has_wt_max_sessions_d07 &&
            (set & WTQ_H3_WT_PROFILES_D13_14_COMPAT) &&
            !s.has_wt_max_sessions_d13)
            abort();
        wtq_h3_settings_encode_cfg_t cfg = {
            s.has_enable_connect_protocol,
            set,
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
        /* Set-aware round trip: exactly the requested profiles' signals
         * appear, one each, and nothing else. An empty set encodes as
         * CURRENT-only (the codec is total), so normalise before checking.
         * The D07 codepoint is receive-only and must NEVER be emitted. */
        wtq_h3_wt_profile_set_t want = set ? set : WTQ_H3_WT_PROFILES_CURRENT;
        bool want_d13 = (want & WTQ_H3_WT_PROFILES_D13_14_COMPAT) != 0;
        bool want_cur = (want & WTQ_H3_WT_PROFILES_CURRENT) != 0;
        if (s2.has_wt_max_sessions_d13 != want_d13)
            abort();
        if (want_d13 && s2.wt_max_sessions_d13 != 1)
            abort();
        if (s2.has_wt_enabled != want_cur)
            abort();
        if (want_cur && s2.wt_enabled != 1)
            abort();
        if (s2.has_wt_max_sessions_d07)
            abort();
        if (s2.has_enable_connect_protocol != cfg.enable_connect_protocol)
            abort();
        /* Our own advertisement always selects back: with ECP on, every
         * profile we advertised is mutually supported, and the winner is
         * the highest-precedence member of what we sent. */
        if (cfg.enable_connect_protocol) {
            wtq_h3_wt_profile_t sel;
            if (!wtq_h3_settings_select_profile(&s2, true, want, &sel))
                abort();
            if (wtq_h3_wt_profile_bit(sel) == 0 ||
                (wtq_h3_wt_profile_bit(sel) & want) == 0)
                abort();
            /* CURRENT outranks D13/14 whenever both were advertised. */
            if (want_cur && sel != WTQ_H3_WT_PROFILE_CURRENT)
                abort();
        }

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
