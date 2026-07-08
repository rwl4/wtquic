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

    wtq_msquic_tuning_init(&tuning);
    return tuning.struct_size != 0 ? 0 : 1;
}
