/* The public Network.framework backend header consumed as a strict
 * C99 translation unit — no backend internals, no Apple types. */
#include <wtquic/wtquic_network.h>

#include <stdio.h>

int main(void)
{
    wtq_nw_conn_cfg_t cfg;

    wtq_nw_conn_cfg_init(&cfg);
    if (cfg.struct_size != (uint32_t)sizeof(cfg))
        return 1;
    /* NULL-safety of the query surface */
    if (wtq_nw_conn_is_on_domain(NULL))
        return 1;
    if (wtq_nw_conn_session(NULL) != NULL)
        return 1;
    if (wtq_nw_conn_doorbell_ring_after(NULL, 1000) != WTQ_ERR_INVALID_ARG)
        return 1;
    wtq_nw_conn_doorbell_cancel_after(NULL);
    wtq_nw_conn_release(NULL);
    printf("PASS: consumer_network_header_c99\n");
    return 0;
}
