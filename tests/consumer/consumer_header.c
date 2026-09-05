/*
 * Consumer smoke: the public umbrella header compiles standalone under
 * pedantic C11 and links against the library.
 */

#include <wtquic/wtquic.h>

int main(void)
{
    wtq_session_t *session = 0; /* opaque handles are declarable */
    wtq_stream_t *stream = 0;
    (void)session;
    (void)stream;

    wtq_span_t span = { 0, 0 };
    wtq_str_t str = { 0, 0 };
    (void)span;
    (void)str;

    /* config discipline compiles and initializes */
    wtq_session_events_t events = WTQ_SESSION_EVENTS_INIT;
    wtq_connect_config_t connect_cfg = WTQ_CONNECT_CONFIG_INIT;
    wtq_serve_config_t serve_cfg = WTQ_SERVE_CONFIG_INIT;
    if (events.struct_size != sizeof(events))
        return 1;
    if (connect_cfg.struct_size != sizeof(connect_cfg))
        return 1;
    if (serve_cfg.struct_size != sizeof(serve_cfg))
        return 1;
    wtq_session_events_init(&events);
    wtq_connect_config_init(&connect_cfg);
    wtq_serve_config_init(&serve_cfg);
    if (events.on_established != 0)
        return 1;

    /* the WebTransport profile field + both init entry points */
    connect_cfg.webtransport_profile =
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;
    if (connect_cfg.webtransport_profile ==
        WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    wtq_connect_config_init(0);              /* NULL init: compiling no-op */
    wtq_connect_config_init_ex(0, 999);      /* NULL _ex: compiling no-op */
    wtq_connect_config_init_ex(&connect_cfg, sizeof(connect_cfg));
    if (connect_cfg.webtransport_profile !=
        WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT) /* init resets the profile */
        return 1;
    /* &wtq_connect_config_init selects the FROZEN v1 symbol; a separate
     * function pointer reaches the sized entry. */
    {
        void (*bare)(wtq_connect_config_t *) = &wtq_connect_config_init;
        void (*ex)(wtq_connect_config_t *, size_t) =
            &wtq_connect_config_init_ex;
        bare(&connect_cfg);
        ex(&connect_cfg, sizeof(connect_cfg));
    }

    /* Origin-policy tail and both serve initializer entry points. */
    {
        const char *origins[] = { "https://example.com" };
        serve_cfg.origin_policy = WTQ_ORIGIN_POLICY_ALLOWLIST;
        serve_cfg.allowed_origins = origins;
        serve_cfg.allowed_origin_count = 1;
        if (serve_cfg.origin_policy == WTQ_ORIGIN_POLICY_UNSET)
            return 1;
        (void)WTQ_ORIGIN_POLICY_ALLOW_ANY_NON_OPAQUE;
        (void)WTQ_ORIGIN_POLICY_ALLOW_ANY_INCLUDING_NULL;
        wtq_serve_config_init(0);
        wtq_serve_config_init_ex(0, 999);
        void (*bare)(wtq_serve_config_t *) = &wtq_serve_config_init;
        void (*ex)(wtq_serve_config_t *, size_t) =
            &wtq_serve_config_init_ex;
        bare(&serve_cfg);
        ex(&serve_cfg, sizeof(serve_cfg));
        if (serve_cfg.origin_policy != WTQ_ORIGIN_POLICY_UNSET)
            return 1;
    }

    /* NULL-tolerant handle helpers link and behave */
    wtq_stream_set_user(stream, 0);
    if (wtq_stream_get_user(stream) != 0)
        return 1;
    (void)WTQ_SEND_FIN;

    /* receive-pause mode query + enumerators link; NULL is UNSUPPORTED */
    if (wtq_stream_receive_pause_mode(stream) != WTQ_RECEIVE_PAUSE_UNSUPPORTED)
        return 1;
    {
        wtq_receive_pause_mode_t m = WTQ_RECEIVE_PAUSE_DELIVERY_ONLY;
        (void)m;
        (void)WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;
    }

    /* public capability-set constants + negotiated-profile query */
    {
        wtq_webtransport_profile_set_t set =
            WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT |
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_13_14_COMPAT |
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT;
        wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;
        if (set != WTQ_WEBTRANSPORT_PROFILES_ALL)
            return 1;
        if (WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT ==
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_13_14_COMPAT)
            return 1;
        /* Name, assign and distinguish the exact D02 enum and mask, not
         * merely reach them through PROFILES_ALL. */
        {
            wtq_webtransport_profile_t d02_named =
                WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT;
            wtq_webtransport_profile_set_t d02_mask =
                WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT;
            if (d02_named == WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
                return 1;
            if (d02_named == WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT)
                return 1;
            if (d02_mask == WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT)
                return 1;
            if (d02_mask == WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_13_14_COMPAT)
                return 1;
            if ((WTQ_WEBTRANSPORT_PROFILES_ALL & d02_mask) != d02_mask)
                return 1;
        }
        if (wtq_session_webtransport_profile(NULL, &prof) !=
            WTQ_ERR_INVALID_ARG)
            return 1;
        /* failure leaves the output untouched */
        if (prof != (wtq_webtransport_profile_t)0x7f)
            return 1;
    }

    if (!wtq_version())
        return 1;
    if (wtq_app_error_to_h3(0) == 0)
        return 1;
    return wtq_strerror(WTQ_OK) ? 0 : 1;
}
