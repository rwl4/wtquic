/*
 * Tuning to QUIC_SETTINGS translation. MsQuic applies a settings field
 * only when its IsSet bit is on, so every mapped field sets both.
 */

#include <string.h>

#include "msq_internal.h"

void wtq_msq_settings_init(QUIC_SETTINGS *qs,
                           const wtq_msquic_tuning_t *tuning)
{
    wtq_msquic_tuning_t t = *tuning;

    if (t.struct_size == 0)
        wtq_msquic_tuning_init(&t);

    memset(qs, 0, sizeof(*qs));
    qs->SendBufferingEnabled = t.send_buffering ? TRUE : FALSE;
    qs->IsSet.SendBufferingEnabled = TRUE;
    qs->PeerUnidiStreamCount = t.peer_unidi_stream_count;
    qs->IsSet.PeerUnidiStreamCount = TRUE;
    qs->PeerBidiStreamCount = t.peer_bidi_stream_count;
    qs->IsSet.PeerBidiStreamCount = TRUE;
    qs->StreamRecvWindowDefault = t.stream_recv_window;
    qs->IsSet.StreamRecvWindowDefault = TRUE;
    qs->ConnFlowControlWindow = t.conn_flow_control_window;
    qs->IsSet.ConnFlowControlWindow = TRUE;
    qs->DatagramReceiveEnabled = t.datagram_receive_enabled ? TRUE : FALSE;
    qs->IsSet.DatagramReceiveEnabled = TRUE;
    qs->IdleTimeoutMs = t.idle_timeout_ms;
    qs->IsSet.IdleTimeoutMs = TRUE;
}
