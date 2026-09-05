/*
 * Consumer smoke: the public umbrella header compiles as C++17 (extern "C"
 * guards + no compound-literal leakage) and links.
 */

#include <wtquic/wtquic.h>

int main()
{
    wtq_session_t *session = nullptr;
    wtq_stream_t *stream = nullptr;
    (void)session;
    (void)stream;

    uint32_t app = 0;
    if (wtq_h3_error_to_app(wtq_app_error_to_h3(42), &app) != WTQ_OK)
        return 1;
    if (app != 42)
        return 1;

    /* the config macros must be valid C++ initializers too */
    wtq_session_events_t events = WTQ_SESSION_EVENTS_INIT;
    wtq_connect_config_t connect_cfg = WTQ_CONNECT_CONFIG_INIT;
    wtq_serve_config_t serve_cfg = WTQ_SERVE_CONFIG_INIT;
    if (events.struct_size != sizeof(events))
        return 1;
    wtq_session_events_init(&events);
    wtq_connect_config_init(&connect_cfg);
    wtq_serve_config_init(&serve_cfg);
    if (events.on_closed != nullptr)
        return 1;

    /* the WebTransport profile field + both init entry points (C++17) */
    connect_cfg.webtransport_profile =
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;
    wtq_connect_config_init(nullptr);         /* nullptr init: no-op */
    wtq_connect_config_init_ex(nullptr, 999); /* nullptr _ex: no-op  */
    wtq_connect_config_init_ex(&connect_cfg, sizeof(connect_cfg));
    if (connect_cfg.webtransport_profile !=
        WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    void (*bare)(wtq_connect_config_t *) = &wtq_connect_config_init;
    void (*ex)(wtq_connect_config_t *, size_t) =
        &wtq_connect_config_init_ex;
    bare(&connect_cfg);
    ex(&connect_cfg, sizeof(connect_cfg));
    if (connect_cfg.authority != nullptr || serve_cfg.path != nullptr)
        return 1;

    const char *origins[] = { "https://example.com" };
    serve_cfg.origin_policy = WTQ_ORIGIN_POLICY_ALLOWLIST;
    serve_cfg.allowed_origins = origins;
    serve_cfg.allowed_origin_count = 1;
    (void)WTQ_ORIGIN_POLICY_ALLOW_ANY_NON_OPAQUE;
    (void)WTQ_ORIGIN_POLICY_ALLOW_ANY_INCLUDING_NULL;
    wtq_serve_config_init(nullptr);
    wtq_serve_config_init_ex(nullptr, 999);
    void (*serve_bare)(wtq_serve_config_t *) = &wtq_serve_config_init;
    void (*serve_ex)(wtq_serve_config_t *, size_t) =
        &wtq_serve_config_init_ex;
    serve_bare(&serve_cfg);
    serve_ex(&serve_cfg, sizeof(serve_cfg));
    if (serve_cfg.origin_policy != WTQ_ORIGIN_POLICY_UNSET)
        return 1;
    (void)WTQ_SEND_FIN;
    wtq_stream_set_user(stream, nullptr);

    /* receive-pause mode query + enumerators are usable from C++17 */
    if (wtq_stream_receive_pause_mode(stream) != WTQ_RECEIVE_PAUSE_UNSUPPORTED)
        return 1;
    (void)WTQ_RECEIVE_PAUSE_DELIVERY_ONLY;
    (void)WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;

    {
        wtq_webtransport_profile_set_t set =
            WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT |
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_13_14_COMPAT |
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT;
        wtq_webtransport_profile_t prof =
            static_cast<wtq_webtransport_profile_t>(0x7f);
        static_assert(
            WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT !=
                WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT,
            "D02 profile must differ from current");
        static_assert(
            WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT !=
                WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT,
            "D02 profile must differ from D13/14");
        static_assert(
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT !=
                WTQ_WEBTRANSPORT_PROFILES_H3_CURRENT,
            "D02 mask must differ from current");
        static_assert(
            (WTQ_WEBTRANSPORT_PROFILES_ALL &
             WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT) ==
                WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT,
            "D02 mask must be in the complete set");
        if (set != WTQ_WEBTRANSPORT_PROFILES_ALL)
            return 1;
        if (wtq_session_webtransport_profile(nullptr, &prof) !=
            WTQ_ERR_INVALID_ARG)
            return 1;
        if (prof != static_cast<wtq_webtransport_profile_t>(0x7f))
            return 1;
    }

    return wtq_version() ? 0 : 1;
}
