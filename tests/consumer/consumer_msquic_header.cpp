/*
 * The MsQuic backend header is includable and linkable from C++17. The
 * extern "C" guards keep the entry points C-linkable across the boundary.
 */

#include <wtquic/wtquic_msquic.h>

int main()
{
    wtq_msquic_tuning_t tuning = WTQ_MSQUIC_TUNING_INIT;
    wtq_msquic_env_cfg_t cfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_client_cfg_t ccfg;
    wtq_msquic_listener_cfg_t lcfg;
    wtq_result_t (*open_fn)(const wtq_msquic_env_cfg_t *,
                            wtq_msquic_env_t **) = wtq_msquic_env_open;
    void (*close_fn)(wtq_msquic_env_t *) = wtq_msquic_env_close;

    void (*cinit)(wtq_msquic_client_cfg_t *) = wtq_msquic_client_cfg_init;
    void (*cinit_ex)(wtq_msquic_client_cfg_t *, size_t) =
        wtq_msquic_client_cfg_init_ex;
    void (*linit)(wtq_msquic_listener_cfg_t *) = wtq_msquic_listener_cfg_init;
    void (*linit_ex)(wtq_msquic_listener_cfg_t *, size_t) =
        wtq_msquic_listener_cfg_init_ex;

    wtq_msquic_tuning_init(&tuning);
    wtq_msquic_env_cfg_init(&cfg);
    /* The init macro must expand cleanly under C++17, including cfg_init(NULL). */
    wtq_msquic_client_cfg_init(&ccfg);
    wtq_msquic_listener_cfg_init(&lcfg);
    wtq_msquic_client_cfg_init(nullptr);
    wtq_msquic_listener_cfg_init(nullptr);

    /* the listener-wide WebTransport profile field defaults to current. */
    if (lcfg.webtransport_profile != WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    lcfg.webtransport_profile = WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;

    (void)open_fn;
    (void)close_fn;
    (void)cinit; (void)cinit_ex; (void)linit; (void)linit_ex;
    return (cfg.struct_size == sizeof(cfg) &&
            tuning.struct_size == sizeof(tuning) &&
            ccfg.struct_size == sizeof(ccfg) &&
            lcfg.struct_size == sizeof(lcfg)) ? 0 : 1;
}
