/* Actual backend registration, queried after the public quiescence barrier. */
#include <wtquic/wtquic_msquic.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    bool legacy = argc == 2 && strcmp(argv[1], "legacy") == 0;
    if (argc != 1 && !legacy) return 2;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;
    if (wtq_msquic_env_open(&ecfg, &env) != WTQ_OK) return 3;
    wtq_session_events_t events;
    wtq_session_events_init(&events);
    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost";
    connect.path = "/qualification";
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = 9;
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect;
    cfg.events = &events;
    wtq_session_t *session = NULL;
    wtq_result_t rc = wtq_msquic_client_connect(env, &cfg, &session);
    wtq_msquic_env_close(env);
    if (rc != WTQ_OK || !session) return 4;
    size_t quantum = 99;
    wtq_receive_pause_mode_t mode = WTQ_RECEIVE_PAUSE_UNSUPPORTED;
    rc = wtq_session_receive_contract(session, &quantum, &mode);
    printf("legacy=%d rc=%d quantum=%zu mode=%d\n", legacy, rc, quantum, mode);
    bool ok = legacy ? rc == WTQ_ERR_UNSUPPORTED && quantum == 0 &&
                       mode == WTQ_RECEIVE_PAUSE_UNSUPPORTED :
                       rc == WTQ_OK && quantum == 65535 &&
                       mode == WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;
    wtq_session_release(session);
    return ok ? 0 : 1;
}
