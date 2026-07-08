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

    /* NULL-tolerant handle helpers link and behave */
    wtq_stream_set_user(stream, 0);
    if (wtq_stream_get_user(stream) != 0)
        return 1;
    (void)WTQ_SEND_FIN;

    if (!wtq_version())
        return 1;
    if (wtq_app_error_to_h3(0) == 0)
        return 1;
    return wtq_strerror(WTQ_OK) ? 0 : 1;
}
