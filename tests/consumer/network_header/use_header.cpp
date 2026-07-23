// The same header as a strict C++17 translation unit.
#include <wtquic/wtquic_network.h>

#include <cstdio>

int main()
{
    wtq_nw_conn_cfg_t cfg = WTQ_NW_CONN_CFG_INIT;
    if (cfg.struct_size != static_cast<uint32_t>(sizeof(cfg)))
        return 1;
    if (wtq_nw_conn_is_on_domain(nullptr))
        return 1;
    if (wtq_nw_conn_doorbell_ring_after(nullptr, 1000) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_doorbell_cancel_after(nullptr);
    wtq_nw_conn_release(nullptr);
    std::printf("PASS: consumer_network_header_cxx\n");
    return 0;
}
