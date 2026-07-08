/*
 * The MsQuic backend header compiles standalone under pedantic C11 and
 * links against the backend library. Referencing the entry points through
 * correctly-typed function pointers forces link resolution without needing
 * a running MsQuic.
 */

#include <wtquic/wtquic_msquic.h>

int main(void)
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
    if (cfg.struct_size != sizeof(cfg))
        return 1;
    if (tuning.struct_size != sizeof(tuning))
        return 1;
    return 0;
}
