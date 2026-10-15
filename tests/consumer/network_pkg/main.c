/* Installed-package consumer: strict C99 over the shipped header. */
#include <wtquic/wtquic_network.h>

#include <stdio.h>

int main(void)
{
    if (wtq_session_local_flush(NULL) != WTQ_ERR_INVALID_ARG ||
        wtq_session_local_flush_mode(NULL) != WTQ_LOCAL_FLUSH_UNSUPPORTED)
        return 1;
    wtq_connect_request_metadata_t metadata = WTQ_CONNECT_REQUEST_METADATA_INIT;
    if (wtq_session_connect_request_metadata(NULL, &metadata) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_cfg_t cfg;

    wtq_nw_conn_cfg_init(&cfg);
    if (cfg.struct_size != (uint32_t)sizeof(cfg))
        return 1;
    if (wtq_nw_conn_is_on_domain(NULL))
        return 1;
    if (wtq_nw_conn_session(NULL) != NULL)
        return 1;
    if (wtq_nw_conn_doorbell_ring_after(NULL, 1000) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_doorbell_cancel_after(NULL);
    wtq_nw_conn_release(NULL);
    printf("PASS: network_pkg consumer (C99)\n");
    return 0;
}
