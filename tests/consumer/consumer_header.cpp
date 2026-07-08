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
    if (connect_cfg.authority != nullptr || serve_cfg.path != nullptr)
        return 1;
    (void)WTQ_SEND_FIN;
    wtq_stream_set_user(stream, nullptr);

    return wtq_version() ? 0 : 1;
}
