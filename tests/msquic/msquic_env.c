/*
 * MsQuic environment: open/close, ownership of borrowed vs owned handles,
 * argument validation, and an allocation fail-at-N sweep that pins every
 * failure path to a clean allocator balance.
 *
 * These link and run against a real libmsquic (they open the API table
 * and a Registration), so they are gated behind the backend build.
 */

#include <string.h>

#include <wtquic/wtquic_msquic.h>

#include "test_support.h"
#include "wtq_fault_alloc.h"

/* Default tuning is the documented performance posture. */
static int test_tuning_defaults(void)
{
    int failures = 0;
    wtq_msquic_tuning_t t;
    wtq_msquic_tuning_t macro_init = WTQ_MSQUIC_TUNING_INIT;

    memset(&t, 0xAB, sizeof(t));
    wtq_msquic_tuning_init(&t);

    WTQ_TEST_CHECK_EQ_SIZE(t.struct_size, sizeof(t));
    WTQ_TEST_CHECK(t.send_buffering == false);
    /* bounded by the engine's fixed 16-slot peer pool */
    WTQ_TEST_CHECK_EQ_INT(t.peer_unidi_stream_count, 8);
    WTQ_TEST_CHECK_EQ_INT(t.peer_bidi_stream_count, 7);
    WTQ_TEST_CHECK_EQ_U64(t.stream_recv_window, 16u * 1024u * 1024u);
    WTQ_TEST_CHECK_EQ_U64(t.conn_flow_control_window, 32u * 1024u * 1024u);
    WTQ_TEST_CHECK(t.datagram_receive_enabled == true);
    WTQ_TEST_CHECK_EQ_U64(t.idle_timeout_ms, 30000);

    /* The macro and the helper produce identical defaults. */
    WTQ_TEST_CHECK(memcmp(&t, &macro_init, sizeof(t)) == 0);

    /* NULL-tolerant. */
    wtq_msquic_tuning_init(NULL);
    return failures;
}

/* cfg_init zeroes optionals and installs default tuning. */
static int test_cfg_defaults(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t c;

    memset(&c, 0xCD, sizeof(c));
    wtq_msquic_env_cfg_init(&c);

    WTQ_TEST_CHECK_EQ_SIZE(c.struct_size, sizeof(c));
    WTQ_TEST_CHECK(c.alloc == NULL);
    WTQ_TEST_CHECK(c.existing_api == NULL);
    WTQ_TEST_CHECK(c.existing_registration == NULL);
    WTQ_TEST_CHECK(c.app_name == NULL);
    WTQ_TEST_CHECK_EQ_SIZE(c.tuning.struct_size, sizeof(c.tuning));

    wtq_msquic_env_cfg_init(NULL);
    return failures;
}

/* Open and close an environment that owns its API table and Registration. */
static int test_open_close_owned(void)
{
    int failures = 0;
    wtq_msquic_env_cfg_t cfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;

    cfg.app_name = "wtq-owned";
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, &env), WTQ_OK);
    WTQ_TEST_CHECK(env != NULL);
    wtq_msquic_env_close(env);

    /* No app name: still opens (owned Registration, no copied label). */
    cfg = (wtq_msquic_env_cfg_t)WTQ_MSQUIC_ENV_CFG_INIT;
    env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, &env), WTQ_OK);
    WTQ_TEST_CHECK(env != NULL);
    wtq_msquic_env_close(env);

    /* NULL is accepted. */
    wtq_msquic_env_close(NULL);
    return failures;
}

/* Bad arguments are rejected before any MsQuic call and never leave a
 * dangling out-pointer. */
static int test_invalid_args(void)
{
    int failures = 0;
    int marker;
    void *nonnull = &marker;   /* a non-NULL sentinel for the out-param */
    wtq_msquic_env_t *env;
    wtq_msquic_env_cfg_t cfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_cfg_t zero;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, NULL),
                          WTQ_ERR_INVALID_ARG);

    env = nonnull;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(NULL, &env),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(env == NULL);

    memset(&zero, 0, sizeof(zero));   /* struct_size 0 → invalid */
    env = nonnull;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&zero, &env),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(env == NULL);
    return failures;
}

/* A borrowed API table / Registration is used but never closed by the
 * environment; the caller's later close of them is the double-free canary
 * (loud under ASan). Also covers borrow-registration-without-api. */
static int test_borrow_existing(void)
{
    int failures = 0;
    const QUIC_API_TABLE *api = NULL;
    HQUIC reg = NULL;
    HQUIC probe = NULL;
    QUIC_REGISTRATION_CONFIG rc;
    wtq_msquic_env_cfg_t cfg;
    wtq_msquic_env_t *env;
    int marker;
    void *nonnull = &marker;

    if (QUIC_FAILED(MsQuicOpen2(&api))) {
        WTQ_TEST_CHECK(0 && "MsQuicOpen2");
        return failures;
    }
    memset(&rc, 0, sizeof(rc));
    rc.AppName = "wtq-outer";
    rc.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
    if (QUIC_FAILED(api->RegistrationOpen(&rc, &reg))) {
        WTQ_TEST_CHECK(0 && "RegistrationOpen");
        MsQuicClose(api);
        return failures;
    }

    /* Borrowing a Registration requires the table that owns it. */
    cfg = (wtq_msquic_env_cfg_t)WTQ_MSQUIC_ENV_CFG_INIT;
    cfg.existing_registration = reg;
    cfg.existing_api = NULL;
    env = nonnull;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, &env),
                          WTQ_ERR_INVALID_ARG);
    WTQ_TEST_CHECK(env == NULL);

    /* Borrow both. */
    cfg = (wtq_msquic_env_cfg_t)WTQ_MSQUIC_ENV_CFG_INIT;
    cfg.existing_api = api;
    cfg.existing_registration = reg;
    env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, &env), WTQ_OK);
    WTQ_TEST_CHECK(env != NULL);
    wtq_msquic_env_close(env);

    /* Borrow the table only; the environment owns a fresh Registration. */
    cfg = (wtq_msquic_env_cfg_t)WTQ_MSQUIC_ENV_CFG_INIT;
    cfg.existing_api = api;
    cfg.app_name = "wtq-inner";
    env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&cfg, &env), WTQ_OK);
    WTQ_TEST_CHECK(env != NULL);
    wtq_msquic_env_close(env);

    /* The borrowed table still works after both closes. */
    WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->RegistrationOpen(&rc, &probe)));
    if (probe != NULL)
        api->RegistrationClose(probe);

    /* Caller closes its own — a double free here would fire under ASan. */
    api->RegistrationClose(reg);
    MsQuicClose(api);
    return failures;
}

/* Fail each allocation in turn: every failing open returns NOMEM, nulls
 * the out-pointer, and leaves the allocator perfectly balanced. */
static int test_alloc_fault(void)
{
    int failures = 0;
    wtq_fault_alloc_t fa;
    int n;

    wtq_fault_alloc_init(&fa);
    for (n = 1; n <= 4; n++) {
        wtq_msquic_env_cfg_t cfg = WTQ_MSQUIC_ENV_CFG_INIT;
        wtq_msquic_env_t *env = NULL;
        wtq_result_t rc;

        wtq_fault_alloc_arm(&fa, n, false);
        cfg.alloc = wtq_fault_alloc_vtable(&fa);
        cfg.app_name = "wtq-fault";   /* forces the second alloc site */

        rc = wtq_msquic_env_open(&cfg, &env);
        if (rc == WTQ_OK) {
            WTQ_TEST_CHECK(env != NULL);
            wtq_msquic_env_close(env);
        } else {
            WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_NOMEM);
            WTQ_TEST_CHECK(env == NULL);
        }
        WTQ_TEST_CHECK_EQ_INT(fa.live, 0);     /* no leak on any path */
        WTQ_TEST_CHECK_EQ_INT(fa.errors, 0);   /* no sized-free violation */
    }
    return failures;
}


/* An impossible accept policy must be rejected by listener_start ITSELF,
 * before any listener/configuration resource is created — never accepted
 * and then discovered on the first connection. Classification matters:
 * malformed content is INVALID_ARG, codec capacity is TOO_LARGE. */
static void test_listener_policy_validation(int *fp)
{
    int failures = 0;
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    wtq_msquic_env_t *env = NULL;

    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (env == NULL) {
        *fp += failures + 1;
        return;
    }

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);

    /* All-backslash: every byte doubles when escaped. 200 raw bytes fit
     * MsQuic's own copy buffer (so the old length-only check passed it)
     * but blow the codec once escaped — exactly the gap this closes. */
    static char escape_heavy[201];
    memset(escape_heavy, '\\', sizeof(escape_heavy) - 1);
    escape_heavy[sizeof(escape_heavy) - 1] = '\0';
    /* the same, all-quote */
    static char quote_heavy[201];
    memset(quote_heavy, '"', sizeof(quote_heavy) - 1);
    quote_heavy[sizeof(quote_heavy) - 1] = '\0';

    static const struct {
        const char *proto;
        wtq_result_t want;
    } cases[] = {
        { "moqt\r18", WTQ_ERR_INVALID_ARG },   /* CR: malformed */
        { "moqt\n18", WTQ_ERR_INVALID_ARG },   /* LF: malformed */
        { escape_heavy, WTQ_ERR_TOO_LARGE },   /* valid, oversized */
        { quote_heavy, WTQ_ERR_TOO_LARGE },    /* valid, oversized */
        { "moqt-18", WTQ_OK },                 /* control */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *const protos[] = { cases[i].proto };
        wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
        wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
        wtq_msquic_listener_t *l = NULL;

        serve.path = "/moq";
        serve.subprotocols = protos;
        serve.subprotocol_count = 1;

        lcfg.bind_address = "127.0.0.1";
        lcfg.port = 0;
        /* deliberately bogus credentials: the policy must be rejected
         * BEFORE any Configuration or Listener is opened, so these are
         * never touched on the failing cases */
        lcfg.cert_file = "/nonexistent/cert.pem";
        lcfg.key_file = "/nonexistent/key.pem";
        lcfg.paths = &serve;
        lcfg.path_count = 1;
        lcfg.events = &ev;

        wtq_result_t rc = wtq_msquic_listener_start(env, &lcfg, &l);
        if (cases[i].want == WTQ_OK) {
            /* a valid policy gets past validation and only then fails on
             * the missing certificate — proving order, not luck */
            WTQ_TEST_CHECK_EQ_INT(rc, WTQ_ERR_BACKEND);
        } else {
            WTQ_TEST_CHECK_EQ_INT(rc, cases[i].want);
        }
        WTQ_TEST_CHECK(l == NULL); /* nothing left behind */
    }

    wtq_msquic_env_close(env);
    *fp += failures;
}

int main(void)
{
    int failures = 0;
    test_listener_policy_validation(&failures);

    failures += test_tuning_defaults();
    failures += test_cfg_defaults();
    failures += test_open_close_owned();
    failures += test_invalid_args();
    failures += test_borrow_existing();
    failures += test_alloc_fault();

    WTQ_TEST_PASS("msquic_env");
    return failures;
}
