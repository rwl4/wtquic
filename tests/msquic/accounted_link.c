/* Link/load the actual production backend and both generations of core SPI. */
#include <wtquic/wtquic_msquic.h>
#include "engine/wt_driver.h"
#include "api/api_internal.h"
#ifdef WTQ_LINK_NETWORK
#include <wtquic/wtquic_network.h>
#endif

int main(void)
{
    wtq_session_t *session = NULL;
    if (wtq_api_session_create_accounted(NULL, &session) != WTQ_ERR_INVALID_ARG)
        return 1;
    size_t quantum = 99;
    wtq_receive_pause_mode_t mode = WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;
    if (wtq_session_receive_contract(NULL, &quantum, &mode) != WTQ_ERR_INVALID_ARG ||
        quantum != 0 || mode != WTQ_RECEIVE_PAUSE_UNSUPPORTED) return 1;
    wtq_msquic_tuning_t tuning;
    wtq_msquic_tuning_init(&tuning);
#ifdef WTQ_LINK_NETWORK
    wtq_nw_conn_cfg_t cfg;
    wtq_nw_conn_cfg_init(&cfg);
#endif
    size_t consumed = 99;
    if (wtq_conn_on_stream_bytes_accounted(NULL, NULL, NULL, 0, true, 0,
                                          &consumed) != WTQ_ERR_INVALID_ARG ||
        consumed != 0)
        return 1;
    return wtq_conn_on_stream_bytes(NULL, NULL, NULL, 0, false, 0) ==
                   WTQ_ERR_INVALID_ARG ? 0 : 2;
}
