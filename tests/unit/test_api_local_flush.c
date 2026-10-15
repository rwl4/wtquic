#define main legacy_session_tests
#include "test_api_session.c"
#undef main

struct flush_probe {
    wtq_result_t result;
    unsigned calls;
};

static wtq_result_t passive_probe(const void *ctx)
{
    struct flush_probe *p = (struct flush_probe *)ctx;
    p->calls++;
    return p->result;
}

static wtq_result_t callback_flush;
static wtq_local_flush_mode_t callback_mode;
static wtq_result_t terminal_flush;
static wtq_session_t *terminal_session;
static unsigned terminal_closed_calls, terminal_failed_calls;

static void flush_on_established(wtq_session_t *s, wtq_str_t protocol, void *user)
{
    on_established(s, protocol, user);
    callback_flush = wtq_session_local_flush(s);
    callback_mode = wtq_session_local_flush_mode(s);
}

static void flush_on_closed(wtq_session_t *s, uint32_t code,
    const uint8_t *reason, size_t len, bool clean, void *user)
{
    on_closed(s, code, reason, len, clean, user);
    terminal_session = s;
    terminal_closed_calls++;
    terminal_flush = wtq_session_local_flush(s);
}

static void flush_on_failed(wtq_session_t *s, wtq_connect_failure_t why, void *user)
{
    on_failed(s, why, user);
    terminal_session = s;
    terminal_failed_calls++;
    terminal_flush = wtq_session_local_flush(s);
}

static void flush_rig_up(rig_t *r, int *fp)
{
    int failures = 0;
    memset(r, 0, sizeof(*r));
    r->alloc = (wtq_alloc_t){ &r->ca, count_alloc, NULL, count_free };
    fake_driver_init(&r->drv, true);
    wtq_session_events_t ev;
    base_events(&ev);
    ev.on_established = flush_on_established;
    ev.on_closed = flush_on_closed;
    ev.on_failed = flush_on_failed;
    wtq_api_session_cfg_t cfg = {
        .alloc = &r->alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = &ev,
        .user = &r->lg,
        .drv = &r->drv,
        .ops = fake_driver_ops(),
    };
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_create(&cfg, &r->s), WTQ_OK);
    WTQ_TEST_CHECK(r->s != NULL);
    r->lg.session = r->s;
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(NULL), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(NULL),
        WTQ_LOCAL_FLUSH_UNSUPPORTED);
    rig_t r, other, unseen;
    struct flush_probe *p = malloc(sizeof(*p));
    WTQ_TEST_CHECK(p != NULL);
    if (p == NULL) return failures;
    *p = (struct flush_probe){ WTQ_ERR_WOULD_BLOCK, 0 };
    flush_rig_up(&r, &failures);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(NULL,
        WTQ_LOCAL_FLUSH_ACKNOWLEDGED, passive_probe, p), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_UNSUPPORTED, passive_probe, p), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        (wtq_local_flush_mode_t)99, passive_probe, p), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_ACKNOWLEDGED, NULL, p), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_ACKNOWLEDGED, passive_probe, NULL), WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.s),
        WTQ_LOCAL_FLUSH_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_ACKNOWLEDGED, passive_probe, p), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(p->calls, 0);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_ACKNOWLEDGED, passive_probe, p), WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_start(r.s, 1), WTQ_OK);
    do_connect(&r, &failures);
    deliver_peer_settings(&r, &failures);
    uint8_t response[128];
    size_t len = build_response(response, sizeof(response), 200, "moqt-18");
    r.sess_ds = find_local_bidi(&r);
    WTQ_TEST_CHECK(r.sess_ds != NULL);
    if (r.sess_ds != NULL) {
        WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes(wtq_api_session_conn(r.s),
            r.sess_ds->ectx, response, len, false, 2), WTQ_OK);
    }
    WTQ_TEST_CHECK_EQ_INT(wtq_session_status(r.s), WTQ_SESSION_STATUS_ESTABLISHED);
    WTQ_TEST_CHECK_EQ_INT(callback_flush, WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(callback_mode, WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
    WTQ_TEST_CHECK_EQ_INT(p->calls, 1);
    establish_client(&other, &failures);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(other.s), WTQ_ERR_UNSUPPORTED);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(other.s,
        WTQ_LOCAL_FLUSH_TRANSPORT, passive_probe, p), WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.s), WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
    struct wtq_driver before = r.drv;
    int allocations = r.ca.allocs, events = r.lg.count;
    for (unsigned i = 0; i < 1000; ++i)
        WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_ERR_WOULD_BLOCK);
    WTQ_TEST_CHECK_EQ_INT(r.ca.allocs, allocations);
    WTQ_TEST_CHECK_EQ_INT(r.lg.count, events);
    WTQ_TEST_CHECK(memcmp(&before, &r.drv, sizeof(before)) == 0);
    p->result = WTQ_OK;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_OK);
    p->result = WTQ_ERR_BACKEND;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_ERR_BACKEND);
    wtq_api_session_local_flush_failed(r.s);
    p->result = WTQ_OK; /* Provider zero cannot erase the event-side loss. */
    terminal_flush = WTQ_ERR_STATE;
    terminal_session = NULL;
    wtq_conn_on_conn_closed(wtq_api_session_conn(r.s), 1, false, 3);
    WTQ_TEST_CHECK_EQ_INT(terminal_flush, WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(terminal_session == r.s);
    WTQ_TEST_CHECK_EQ_INT(terminal_closed_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(terminal_failed_calls, 0);
    unsigned calls = p->calls;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK_EQ_INT(p->calls, calls);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(r.s,
        WTQ_LOCAL_FLUSH_TRANSPORT, passive_probe, p), WTQ_ERR_STATE);

    /* No query ever samples the loss before this session becomes terminal. */
    flush_rig_up(&unseen, &failures);
    WTQ_TEST_CHECK_EQ_INT(wtq_api_session_set_local_flush(unseen.s,
        WTQ_LOCAL_FLUSH_TRANSPORT, passive_probe, p), WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(unseen.s),
        WTQ_LOCAL_FLUSH_TRANSPORT);
    wtq_api_session_local_flush_failed(unseen.s);
    terminal_flush = WTQ_ERR_STATE;
    terminal_session = NULL;
    wtq_conn_on_conn_closed(wtq_api_session_conn(unseen.s), 1, false, 4);
    WTQ_TEST_CHECK_EQ_INT(terminal_flush, WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(terminal_session == unseen.s);
    WTQ_TEST_CHECK_EQ_INT(terminal_closed_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(terminal_failed_calls, 1);
    WTQ_TEST_CHECK_EQ_INT(p->calls, calls);
    free(p);
    /* The retained terminal handle must not touch the retired provider. */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(r.s), WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(unseen.s), WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush_mode(r.s), WTQ_LOCAL_FLUSH_ACKNOWLEDGED);
    wtq_api_session_local_flush_failed(NULL);
    wtq_api_session_local_flush_failed(other.s); /* Unqualified stays so. */
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(other.s), WTQ_ERR_UNSUPPORTED);
    wtq_conn_on_conn_closed(wtq_api_session_conn(other.s), 1, false, 5);
    WTQ_TEST_CHECK_EQ_INT(wtq_session_local_flush(other.s), WTQ_ERR_CLOSED);
    rig_down(&r, &failures);
    rig_down(&other, &failures);
    rig_down(&unseen, &failures);
    WTQ_TEST_PASS("api_local_flush");
    return failures;
}
