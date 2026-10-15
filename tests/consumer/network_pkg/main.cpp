// Installed-package consumer: strict C++17 over the shipped header.
#include <wtquic/wtquic_network.h>

#include <cstdio>

int main()
{
    if (wtq_session_local_flush(nullptr) != WTQ_ERR_INVALID_ARG ||
        wtq_session_local_flush_mode(nullptr) != WTQ_LOCAL_FLUSH_UNSUPPORTED)
        return 1;
    wtq_connect_request_metadata_t metadata = WTQ_CONNECT_REQUEST_METADATA_INIT;
    if (wtq_session_connect_request_metadata(nullptr, &metadata) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    if (cfg.struct_size != static_cast<uint32_t>(sizeof(cfg)))
        return 1;
    if (wtq_nw_conn_doorbell_ring_after(nullptr, 1000) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_doorbell_cancel_after(nullptr);
    wtq_nw_conn_release(nullptr);
    std::printf("PASS: network_pkg consumer (C++17)\n");
    return 0;
}
