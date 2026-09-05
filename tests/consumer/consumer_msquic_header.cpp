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
    lcfg.path_stride = sizeof(wtq_serve_config_t);
    wtq_msquic_client_cfg_init(nullptr);
    wtq_msquic_listener_cfg_init(nullptr);

    /* the listener-wide WebTransport profile field defaults to current. */
    if (lcfg.webtransport_profile != WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    lcfg.webtransport_profile = WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;
    lcfg.webtransport_profile =
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT;
    static_assert(
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT !=
            WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT,
        "D02 profile must differ from current");
    static_assert(
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT !=
            WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT,
        "D02 profile must differ from D13/14");
    static_assert(
        (WTQ_WEBTRANSPORT_PROFILES_ALL &
         WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT) ==
            WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT,
        "D02 mask must be in the complete set");

    (void)open_fn;
    (void)close_fn;
    (void)cinit; (void)cinit_ex; (void)linit; (void)linit_ex;
    lcfg.webtransport_profiles = WTQ_WEBTRANSPORT_PROFILES_ALL;
    if (lcfg.webtransport_profiles != WTQ_WEBTRANSPORT_PROFILES_ALL)
        return 1;
    lcfg.webtransport_profiles =
        WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT;
    if (lcfg.webtransport_profiles == 0)
        return 1;
    return (cfg.struct_size == sizeof(cfg) &&
            tuning.struct_size == sizeof(tuning) &&
            ccfg.struct_size == sizeof(ccfg) &&
            lcfg.struct_size == sizeof(lcfg)) ? 0 : 1;
}
