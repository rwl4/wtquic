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
    wtq_msquic_client_cfg_t ccfg;
    wtq_msquic_listener_cfg_t lcfg;
    wtq_result_t (*open_fn)(const wtq_msquic_env_cfg_t *,
                            wtq_msquic_env_t **) = wtq_msquic_env_open;
    void (*close_fn)(wtq_msquic_env_t *) = wtq_msquic_env_close;

    /* The bare symbol (taken by address) is the frozen v1 initialiser; _ex is
     * the current-size one. Both must be linkable and correctly typed. */
    void (*cinit)(wtq_msquic_client_cfg_t *) = wtq_msquic_client_cfg_init;
    void (*cinit_ex)(wtq_msquic_client_cfg_t *, size_t) =
        wtq_msquic_client_cfg_init_ex;
    void (*linit)(wtq_msquic_listener_cfg_t *) = wtq_msquic_listener_cfg_init;
    void (*linit_ex)(wtq_msquic_listener_cfg_t *, size_t) =
        wtq_msquic_listener_cfg_init_ex;

    wtq_msquic_tuning_init(&tuning);
    wtq_msquic_env_cfg_init(&cfg);
    /* The init macro uses the concrete type size, so a source caller always
     * gets a config sized for its compiled version AND cfg_init(NULL) is a
     * compiling no-op under pedantic C. */
    wtq_msquic_client_cfg_init(&ccfg);
    wtq_msquic_listener_cfg_init(&lcfg);
    wtq_msquic_client_cfg_init(NULL);
    wtq_msquic_listener_cfg_init(NULL);

    /* the listener-wide WebTransport profile field is present and defaults to
     * current after init; both profile enumerators are usable. */
    if (lcfg.webtransport_profile != WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    lcfg.webtransport_profile = WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;
    (void)lcfg.webtransport_profile;

    (void)open_fn;
    (void)close_fn;
    (void)cinit; (void)cinit_ex; (void)linit; (void)linit_ex;
    if (cfg.struct_size != sizeof(cfg))
        return 1;
    if (tuning.struct_size != sizeof(tuning))
        return 1;
    if (ccfg.struct_size != sizeof(ccfg))
        return 1;
    if (lcfg.struct_size != sizeof(lcfg))
        return 1;
    return 0;
}
