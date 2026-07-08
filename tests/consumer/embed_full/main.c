#include <wtquic/wtquic_network.h>

int main(void)
{
    wtq_nw_conn_cfg_t cfg;

    wtq_nw_conn_cfg_init(&cfg);
    return cfg.struct_size == (uint32_t)sizeof(cfg) ? 0 : 1;
}
