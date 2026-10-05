#include <wtquic/session.h>
#include <string.h>
#include <wtquic/stream.h>
#include "api/api_internal.h"
#include "fake_driver.h"
#include "test_support.h"

static unsigned passes;
static wtq_result_t service(wtq_driver_t *drv)
{
    (void)drv; passes++; return WTQ_OK;
}
static void lease(wtq_driver_t *drv, wtq_dstream_t *ds, bool held)
{
    (void)drv; (void)ds; (void)held;
}

int main(void)
{
    int failures = 0;
    size_t quantum = 99;
    wtq_receive_pause_mode_t mode = WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(NULL, &quantum, &mode),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(quantum == 0 && mode == WTQ_RECEIVE_PAUSE_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(NULL), WTQ_ERR_INVALID_ARG);
    for (int registered = 0; registered < 2; registered++) {
        for (int flow = 0; flow < 3; flow++) {
            struct wtq_driver drv;
            fake_driver_init(&drv, true);
            wtq_driver_ops_t ops = *fake_driver_ops();
            if (flow == 1) ops.caps |= WTQ_DCAP_RECV_FLOW_CONTROLLED;
            if (flow == 2) ops.recv_enable = NULL;
            wtq_session_events_t ev;
            wtq_session_events_init(&ev);
            wtq_api_session_cfg_t cfg = {
                .alloc = wtq_alloc_default(), .perspective = WTQ_PERSPECTIVE_CLIENT,
                .events = &ev, .drv = &drv, .ops = &ops,
            };
            wtq_session_t *s = NULL;
            wtq_result_t rc = registered ? wtq_api_session_create_accounted(&cfg, &s)
                                        : wtq_api_session_create(&cfg, &s);
            WTQ_TEST_CHECK_EQ_INT(rc, WTQ_OK);
            if (!s) continue;
            WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(s), WTQ_ERR_UNSUPPORTED);
            for (int terminal = 0; terminal < 2; terminal++) {
                quantum = 99; mode = WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED;
                rc = wtq_session_receive_contract(s, &quantum, &mode);
                /* Accounted delivery alone does not certify bounded admission. */
                WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_UNSUPPORTED);
                WTQ_TEST_CHECK(quantum == 0);
                WTQ_TEST_CHECK_EQ_INT(mode, WTQ_RECEIVE_PAUSE_UNSUPPORTED);
                WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(s, NULL, &mode), WTQ_ERR_INVALID_ARG);
                WTQ_TEST_CHECK_EQ_INT(mode, WTQ_RECEIVE_PAUSE_UNSUPPORTED);
                WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(s, &quantum, NULL), WTQ_ERR_INVALID_ARG);
                WTQ_TEST_CHECK(quantum == 0);
                if (!terminal) {
                    wtq_api_session_enter(s);
                    wtq_conn_on_conn_closed(wtq_api_session_conn(s), 0, true, 0);
                    (void)wtq_api_session_leave(s);
                    /* The query must not read the driver after terminal. */
                    memset(&drv, 0xa5, sizeof(drv));
                }
            }
            wtq_session_release(s);
        }
    }
    struct wtq_driver drv;
    fake_driver_init(&drv, true);
    wtq_driver_ops_t driver_ops = *fake_driver_ops();
    driver_ops.caps |= WTQ_DCAP_RECV_FLOW_CONTROLLED;
    wtq_session_events_t events;
    wtq_session_events_init(&events);
    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(), .perspective = WTQ_PERSPECTIVE_CLIENT,
        .drv = &drv, .ops = &driver_ops, .events = &events,
    };
    wtq_api_admission_ops_t ops = { .peer_uni = 8, .peer_bidi = 7,
        .service = service, .lease = lease };
    wtq_session_t *s = NULL;
    for (unsigned count = 6; count < 10; ++count) {
        if (count == 8) continue;
        ops.peer_uni = count;
        WTQ_TEST_CHECK_EQ_INT(wtq_api_session_create_admission(&cfg, &ops, &s), WTQ_ERR_UNSUPPORTED);
        WTQ_TEST_CHECK(s == NULL);
    }
    ops.peer_uni = 8;
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_create_admission(&cfg, &ops, &s), WTQ_OK);
    if (s) {
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(s), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(passes, 1);
        wtq_api_session_enter(s);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(s), WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT(passes, 1);
        (void)wtq_api_session_leave(s);
        WTQ_TEST_CHECK_EQ_INT(passes, 1); /* no arbitrary exit publication */
        wtq_api_session_enter(s);
        wtq_conn_on_conn_closed(wtq_api_session_conn(s), 0, true, 0);
        (void)wtq_api_session_leave(s);
        wtq_api_session_admission_detach(s);
        memset(&drv, 0xa5, sizeof(drv));
        WTQ_TEST_CHECK_EQ_INT(wtq_session_receive_contract(s, &quantum, &mode), WTQ_OK);
        WTQ_TEST_CHECK(quantum == 65535 && mode == WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED);
        WTQ_TEST_CHECK_EQ_INT(wtq_session_service_stream_admission(s), WTQ_ERR_CLOSED);
        WTQ_TEST_CHECK_EQ_INT(passes, 1);
        wtq_session_release(s);
    }
    WTQ_TEST_PASS("receive_contract");
    return failures;
}
