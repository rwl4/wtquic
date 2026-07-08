/* Installed-package consumer: strict C99 over the shipped header. */
#include <wtquic/wtquic_network.h>

#include <stdio.h>

int main(void)
{
    wtq_nw_conn_cfg_t cfg;

    wtq_nw_conn_cfg_init(&cfg);
    if (cfg.struct_size != (uint32_t)sizeof(cfg))
        return 1;
    if (wtq_nw_conn_is_on_domain(NULL))
        return 1;
    if (wtq_nw_conn_session(NULL) != NULL)
        return 1;
    wtq_nw_conn_release(NULL);
    printf("PASS: network_pkg consumer (C99)\n");
    return 0;
}
