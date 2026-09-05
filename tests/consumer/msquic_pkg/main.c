/*
 * Installed-consumer smoke: find_package(wtquic COMPONENTS msquic) must
 * resolve wtq::msquic AND its transitive msquic::msquic dependency. If the
 * config package fails to re-establish that target, this project fails to
 * configure/build.
 */

#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

int main(void)
{
    wtq_msquic_tuning_t tuning = WTQ_MSQUIC_TUNING_INIT;

    wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;
    wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
    lcfg.path_stride = sizeof(wtq_serve_config_t);

    wtq_msquic_tuning_init(&tuning);
    /* link (not merely compile) the installed negotiated-profile query, and
     * touch the v4 listener capability set */
    if (wtq_session_webtransport_profile(NULL, &prof) != WTQ_ERR_INVALID_ARG)
        return 1;
    lcfg.webtransport_profiles = WTQ_WEBTRANSPORT_PROFILES_ALL;
    if (lcfg.webtransport_profiles == 0)
        return 1;
    lcfg.webtransport_profiles =
        WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_02_RFC9297_COMPAT;
    if (lcfg.webtransport_profiles == 0 ||
        (WTQ_WEBTRANSPORT_PROFILES_ALL & lcfg.webtransport_profiles) !=
            lcfg.webtransport_profiles)
        return 1;
    lcfg.webtransport_profile =
        WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT;
    if (lcfg.webtransport_profile == WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT)
        return 1;
    return tuning.struct_size != 0 ? 0 : 1;
}
