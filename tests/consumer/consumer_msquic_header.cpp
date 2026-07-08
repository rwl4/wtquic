/*
 * The MsQuic backend header is includable and linkable from C++17. The
 * extern "C" guards keep the entry points C-linkable across the boundary.
 */

#include <wtquic/wtquic_msquic.h>

int main()
{
    wtq_msquic_tuning_t tuning = WTQ_MSQUIC_TUNING_INIT;
    wtq_msquic_env_cfg_t cfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_result_t (*open_fn)(const wtq_msquic_env_cfg_t *,
                            wtq_msquic_env_t **) = wtq_msquic_env_open;
    void (*close_fn)(wtq_msquic_env_t *) = wtq_msquic_env_close;

    wtq_msquic_tuning_init(&tuning);
    wtq_msquic_env_cfg_init(&cfg);

    (void)open_fn;
    (void)close_fn;
    return (cfg.struct_size == sizeof(cfg) &&
            tuning.struct_size == sizeof(tuning)) ? 0 : 1;
}
