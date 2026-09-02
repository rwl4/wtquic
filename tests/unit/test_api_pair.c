#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "fake_driver.h"

#include "test_support.h"

/*
 * Two PUBLIC sessions talking through the fake transports: everything
 * the applications do goes through wtq_session_* / wtq_stream_* — the
 * engine appears only inside the wire-delivery pump. Deterministic:
 * seeded chunking, same seed -> same event sequence.
 */

typedef struct side side_t;

/* splitmix64 (the simpair's chunking recipe) */
static uint64_t mix64(uint64_t x)
{
    x += UINT64_C(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94D049BB133111EB);
    return x ^ (x >> 31);
}

struct side {
    struct wtq_driver drv;
    wtq_session_t *s;
    char label;
    /* app state */
    int established;
    int failed;
    int draining;
    int closed;
    uint32_t closed_code;
    bool closed_clean;
    int stream_opened;
    wtq_stream_t *last_stream;
    int stream_closed;
    uint8_t data[256];
    size_t data_len;
    int fin_events;
    int dgram_events;
    uint8_t dgram[64];
    size_t dgram_len;
    int completions;
    bool echo; /* respond to bidi data with an echo + FIN */
    /* the negotiated-profile query sampled INSIDE on_established, which is
     * what proves the value is published BEFORE the callback rather than
     * merely by the time the pump finishes */
    int cb_query_rc;
    int cb_profile;
    int cb_status_after_query;
    wtq_estream_t *es_for_slot[FAKE_MAX_STREAMS];
};

static void on_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    side_t *sd = user;
    wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;

    (void)sub;
    sd->established++;
    sd->cb_query_rc = (int)wtq_session_webtransport_profile(s, &prof);
    sd->cb_profile = (int)prof;
    /* a following status query from the same callback still behaves
     * normally — this records that STATUS, not callback depth */
    sd->cb_status_after_query = (int)wtq_session_status(s);
}

static void on_failed(wtq_session_t *s, wtq_connect_failure_t why,
                      void *user)
{
    (void)s;
    (void)why;
    ((side_t *)user)->failed++;
}

static void on_draining(wtq_session_t *s, void *user)
{
    (void)s;
    ((side_t *)user)->draining++;
}

static void on_closed(wtq_session_t *s, uint32_t code,
                      const uint8_t *reason, size_t rlen, bool clean,
                      void *user)
{
    side_t *sd = user;

    (void)s;
    (void)reason;
    (void)rlen;
    sd->closed++;
    sd->closed_code = code;
    sd->closed_clean = clean;
}

static void on_stream_opened(wtq_session_t *s, wtq_stream_t *st,
                             bool bidi, void *user)
{
    side_t *sd = user;

    (void)s;
    (void)bidi;
    sd->stream_opened++;
    sd->last_stream = st;
}

static void on_stream_data(wtq_session_t *s, wtq_stream_t *st,
                           const uint8_t *data, size_t len, bool fin,
                           void *user)
{
    side_t *sd = user;

    (void)s;
    if (len > 0 && sd->data_len + len <= sizeof(sd->data)) {
        memcpy(sd->data + sd->data_len, data, len);
        sd->data_len += len;
    }
    if (fin)
        sd->fin_events++;
    if (sd->echo && fin && wtq_stream_is_bidi(st)) {
        wtq_span_t span = { (const uint8_t *)"pong", 4 };
        (void)wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL);
    }
}

static void on_stream_closed(wtq_session_t *s, wtq_stream_t *st,
                             void *user)
{
    (void)s;
    (void)st;
    ((side_t *)user)->stream_closed++;
}

static void on_send_complete(wtq_session_t *s, void *ctx, bool canceled,
                             void *user)
{
    (void)s;
    (void)ctx;
    (void)canceled;
    ((side_t *)user)->completions++;
}

static void on_datagram(wtq_session_t *s, const uint8_t *data, size_t len,
                        void *user)
{
    side_t *sd = user;

    (void)s;
    sd->dgram_events++;
    sd->dgram_len = len < sizeof(sd->dgram) ? len : 0;
    if (sd->dgram_len > 0)
        memcpy(sd->dgram, data, sd->dgram_len);
}

static int side_up_profiles(side_t *sd, char label, bool client,
                            int singular, uint64_t set, int *fp);

static int side_up(side_t *sd, char label, bool client, int *fp)
{
    return side_up_profiles(sd, label, client, 0, 0, fp);
}

static int side_up_profiles(side_t *sd, char label, bool client,
                            int singular, uint64_t set, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(sd, 0, sizeof(*sd));
    sd->label = label;
    fake_driver_init(&sd->drv, client);
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
    ev.on_failed = on_failed;
    ev.on_draining = on_draining;
    ev.on_closed = on_closed;
    ev.on_stream_opened = on_stream_opened;
    ev.on_stream_data = on_stream_data;
    ev.on_stream_closed = on_stream_closed;
    ev.on_send_complete = on_send_complete;
    ev.on_datagram = on_datagram;

    wtq_api_session_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = client ? WTQ_PERSPECTIVE_CLIENT
                              : WTQ_PERSPECTIVE_SERVER,
        .events = &ev,
        .user = sd,
        .drv = &sd->drv,
        .ops = fake_driver_ops(),
        .webtransport_profile = singular,
        .webtransport_profiles = set,
    };
    WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &sd->s) == WTQ_OK);
    if (sd->s == NULL) {
        *fp += failures + 1;
        return -1;
    }
    WTQ_TEST_CHECK(wtq_api_session_start(sd->s, 1000) == WTQ_OK);
    *fp += failures;
    return 0;
}

/* Deliver one side's pending wire to the other (seeded chunking). */
static size_t pump_dir(uint64_t seed, size_t step, side_t *from,
                       side_t *to)
{
    size_t delivered = 0;
    wtq_conn_t *conn = wtq_api_session_conn(to->s);

    if (conn == NULL)
        return 0;
    wtq_api_session_enter(to->s); /* the backend delivery bracket */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++) {
        struct wtq_dstream *src = &from->drv.streams[slot];
        if (!src->in_use || !src->is_local)
            continue;
        if (to->es_for_slot[slot] == NULL && src->len > 0) {
            struct wtq_dstream *pds =
                fake_driver_add_peer_stream(&to->drv, src->id);
            if (pds == NULL)
                continue;
            pds->is_bidi = src->is_bidi;
            pds->linked = src;
            src->linked = pds;
            wtq_estream_t *es = NULL;
            (void)(src->is_bidi
                       ? wtq_conn_on_peer_bidi_opened(conn, pds, src->id,
                                                      &es)
                       : wtq_conn_on_peer_uni_opened(conn, pds, src->id,
                                                     &es));
            to->es_for_slot[slot] = es;
            delivered++;
        }
        wtq_estream_t *es = to->es_for_slot[slot];
        if (es == NULL)
            continue;
        while (src->delivered < src->len) {
            size_t rem = src->len - src->delivered;
            size_t chunk =
                1 + (size_t)(mix64(seed ^ (step * 31 + slot * 7 +
                                           src->delivered)) %
                             7);
            if (chunk > rem)
                chunk = rem;
            bool fin = src->fin && (src->delivered + chunk == src->len);
            (void)wtq_conn_on_stream_bytes(conn, es,
                                           src->bytes + src->delivered,
                                           chunk, fin, 2000);
            if (fin)
                src->fin_delivered = true;
            src->delivered += chunk;
            delivered += chunk;
        }
        if (src->fin && !src->fin_delivered &&
            src->delivered == src->len) {
            (void)wtq_conn_on_stream_bytes(conn, es, NULL, 0, true,
                                           2000);
            src->fin_delivered = true;
            delivered++;
        }
    }
    /* reverse direction of bidi streams the peer opened on us */
    for (size_t slot = 0; slot < FAKE_MAX_STREAMS; slot++) {
        struct wtq_dstream *src = &from->drv.streams[slot];
        if (!src->in_use || src->is_local || !src->is_bidi ||
            src->linked == NULL || src->linked->ectx == NULL)
            continue;
        wtq_conn_t *oconn = wtq_api_session_conn(to->s);
        while (src->delivered < src->len) {
            size_t rem = src->len - src->delivered;
            size_t chunk =
                1 + (size_t)(mix64(seed ^ (step * 131 + slot * 17 +
                                           src->delivered)) %
                             7);
            if (chunk > rem)
                chunk = rem;
            bool fin = src->fin && (src->delivered + chunk == src->len);
            (void)wtq_conn_on_stream_bytes(oconn, src->linked->ectx,
                                           src->bytes + src->delivered,
                                           chunk, fin, 2000);
            if (fin)
                src->fin_delivered = true;
            src->delivered += chunk;
            delivered += chunk;
        }
    }
    /* datagrams */
    while (from->drv.dgram_delivered < from->drv.dgram_count) {
        size_t i = from->drv.dgram_delivered++;
        (void)wtq_conn_on_datagram(conn, from->drv.dgrams[i].bytes,
                                   from->drv.dgrams[i].len, 2000);
        delivered++;
    }
    (void)wtq_api_session_leave(to->s);
    return delivered;
}

static size_t pump(uint64_t seed, side_t *c, side_t *s)
{
    size_t step = 0;
    size_t moved;

    do {
        step++;
        moved = pump_dir(seed, step, c, s) + pump_dir(seed, step, s, c);
        moved += fake_driver_complete_sends(&c->drv,
                                            wtq_api_session_conn(c->s));
        moved += fake_driver_complete_sends(&s->drv,
                                            wtq_api_session_conn(s->s));
    } while (moved > 0 && step < 64);
    return step;
}

static const char *const OFFER[] = { "moqt-18" };

/* One whole public-API session: connect, drain, bidi ping/pong echo
 * (the echo issued from inside the data callback), datagrams both
 * ways, clean close with code+reason on the far side. */
static int scenario_api_pair(uint64_t seed, int *fp)
{
    int failures = 0;
    static side_t c;
    static side_t s;

    if (side_up(&c, 'c', true, fp) != 0 ||
        side_up(&s, 's', false, fp) != 0)
        return 1;
    s.echo = true;

    wtq_serve_config_t path;
    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = OFFER;
    path.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_serve(s.s, &path, 1) == WTQ_OK);

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(c.s, &cc) == WTQ_OK);
    pump(seed, &c, &s);
    WTQ_TEST_CHECK(c.established == 1);
    WTQ_TEST_CHECK(s.established == 1);

    /* server drains; client sees it and traffic continues */
    WTQ_TEST_CHECK(wtq_session_drain(s.s) == WTQ_OK);
    pump(seed, &c, &s);
    WTQ_TEST_CHECK(c.draining == 1);
    WTQ_TEST_CHECK(wtq_session_status(c.s) ==
                   WTQ_SESSION_STATUS_DRAINING);

    /* client bidi ping; the server echoes FROM ITS DATA CALLBACK */
    wtq_stream_t *st = NULL;
    WTQ_TEST_CHECK(wtq_session_open_bidi(c.s, &st) == WTQ_OK);
    wtq_span_t span = { (const uint8_t *)"ping", 4 };
    WTQ_TEST_CHECK(wtq_stream_send(st, &span, 1, WTQ_SEND_FIN, NULL) ==
                   WTQ_OK);
    pump(seed, &c, &s);
    WTQ_TEST_CHECK(s.stream_opened == 1);
    WTQ_TEST_CHECK_EQ_SIZE(s.data_len, 4);
    WTQ_TEST_CHECK(memcmp(s.data, "ping", 4) == 0);
    WTQ_TEST_CHECK_EQ_SIZE(c.data_len, 4);
    WTQ_TEST_CHECK(memcmp(c.data, "pong", 4) == 0);
    WTQ_TEST_CHECK(c.fin_events == 1);
    /* both stream terminals fired (both directions finished) */
    WTQ_TEST_CHECK(c.stream_closed == 1);
    WTQ_TEST_CHECK(s.stream_closed == 1);
    WTQ_TEST_CHECK(c.completions >= 1);
    WTQ_TEST_CHECK(s.completions >= 1);

    /* datagrams both ways */
    wtq_span_t dg = { (const uint8_t *)"dg-c", 4 };
    WTQ_TEST_CHECK(wtq_session_send_datagram(c.s, &dg, 1) == WTQ_OK);
    wtq_span_t dg2 = { (const uint8_t *)"dg-s", 4 };
    WTQ_TEST_CHECK(wtq_session_send_datagram(s.s, &dg2, 1) == WTQ_OK);
    pump(seed, &c, &s);
    WTQ_TEST_CHECK(s.dgram_events == 1);
    WTQ_TEST_CHECK(memcmp(s.dgram, "dg-c", 4) == 0);
    WTQ_TEST_CHECK(c.dgram_events == 1);
    WTQ_TEST_CHECK(memcmp(c.dgram, "dg-s", 4) == 0);

    /* client closes; server sees code + clean */
    WTQ_TEST_CHECK(wtq_session_close(c.s, 7, (const uint8_t *)"done",
                                     4) == WTQ_OK);
    WTQ_TEST_CHECK(c.closed == 1);
    WTQ_TEST_CHECK(c.closed_clean);
    pump(seed, &c, &s);
    WTQ_TEST_CHECK(s.closed == 1);
    WTQ_TEST_CHECK(s.closed_code == 7);
    WTQ_TEST_CHECK(s.closed_clean);

    wtq_session_release(c.s);
    wtq_session_release(s.s);
    *fp += failures;
    return failures;
}

/*
 * The public negotiated-profile query. One MULTI-PROFILE server is driven
 * against a CURRENT client and a D13/14 client on separate connections, and
 * each side is asked what IT selected — never merely what it was configured
 * with.
 */
static int scenario_profile_query(uint64_t seed, int client_profile,
                                  int expect, int *fp)
{
    int failures = 0;
    static side_t c;
    static side_t s;
    const uint64_t BOTH = WTQ_WEBTRANSPORT_PROFILES_ALL;

    if (side_up_profiles(&c, 'c', true, client_profile, 0, fp) != 0 ||
        side_up_profiles(&s, 's', false, 0, BOTH, fp) != 0)
        return 1;

    /* before establishment: no selection exists, and the output is left
     * untouched so it can never be read as the zero-valued current profile */
    {
        wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(c.s, &prof),
            (int)WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f);
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(s.s, &prof),
            (int)WTQ_ERR_STATE);
        WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f);
        /* NULL arguments, output still untouched */
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(NULL, &prof),
            (int)WTQ_ERR_INVALID_ARG);
        WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f);
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(c.s, NULL),
            (int)WTQ_ERR_INVALID_ARG);
    }

    wtq_serve_config_t path;
    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = OFFER;
    path.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_serve(s.s, &path, 1) == WTQ_OK);

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    cc.webtransport_profile = (uint32_t)client_profile;
    WTQ_TEST_CHECK(wtq_api_session_connect(c.s, &cc) == WTQ_OK);
    pump(seed, &c, &s);

    WTQ_TEST_CHECK_EQ_INT(c.established, 1);
    WTQ_TEST_CHECK_EQ_INT(s.established, 1);

    /* INSIDE on_established the query already answered, with the profile
     * this connection selected — the multi-profile server reports the
     * client's generation, not its own configured set or a default */
    WTQ_TEST_CHECK_EQ_INT(s.cb_query_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(s.cb_profile, expect);
    WTQ_TEST_CHECK_EQ_INT(c.cb_query_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(c.cb_profile, expect);
    /* The query is legal from inside the callback and the session is still
     * usable there. This pins callback-time LEGALITY only: it does NOT
     * observe callback depth. That the query mutates no session state is
     * enforced by its implementation — a const session, no
     * session_enter/exit bracket, no counter touched — verified by
     * inspection, not by this assertion. */
    WTQ_TEST_CHECK_EQ_INT(s.cb_status_after_query,
                          (int)WTQ_SESSION_STATUS_ESTABLISHED);

    /* and afterwards, from outside any callback */
    {
        wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(s.s, &prof), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)prof, expect);
    }

    /* stable on a RETAINED handle past the session terminal */
    wtq_session_add_ref(s.s);
    WTQ_TEST_CHECK(wtq_session_close(s.s, 0, NULL, 0) == WTQ_OK);
    pump(seed, &c, &s);
    /* CAUSAL: prove the handle really is POST-TERMINAL before querying it.
     * Without this the close could have failed to complete and the query
     * would still answer from the live session, passing without ever
     * exercising the dead-but-valid state this case exists to cover. */
    WTQ_TEST_CHECK_EQ_INT(s.closed, 1);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_session_status(s.s),
                          (int)WTQ_SESSION_STATUS_CLOSED);
    {
        wtq_webtransport_profile_t prof = (wtq_webtransport_profile_t)0x7f;
        WTQ_TEST_CHECK_EQ_INT(
            (int)wtq_session_webtransport_profile(s.s, &prof), (int)WTQ_OK);
        WTQ_TEST_CHECK_EQ_INT((int)prof, expect);
    }
    wtq_session_release(s.s);

    wtq_session_release(c.s);
    wtq_session_release(s.s);
    *fp += failures;
    return 0;
}

/*
 * The public lifecycle states in which no selection exists yet. Each is
 * pinned separately even though profile_available is the single authority,
 * because these are distinct states an application can actually be in.
 */
static int scenario_profile_query_states(uint64_t seed, int *fp)
{
    int failures = 0;
    static side_t c;
    static side_t s;
    wtq_webtransport_profile_t prof;

    /* (a) CREATED but not started */
    {
        side_t only;
        wtq_session_events_t ev;

        memset(&only, 0, sizeof(only));
        only.label = 'x';
        fake_driver_init(&only.drv, true);
        wtq_session_events_init(&ev);
        wtq_api_session_cfg_t cfg = {
            .alloc = wtq_alloc_default(),
            .perspective = WTQ_PERSPECTIVE_CLIENT,
            .events = &ev,
            .user = &only,
            .drv = &only.drv,
            .ops = fake_driver_ops(),
        };
        WTQ_TEST_CHECK(wtq_api_session_create(&cfg, &only.s) == WTQ_OK);
        if (only.s != NULL) {
            prof = (wtq_webtransport_profile_t)0x7f;
            WTQ_TEST_CHECK_EQ_INT(
                (int)wtq_session_webtransport_profile(only.s, &prof),
                (int)WTQ_ERR_STATE);
            WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f); /* untouched */
            wtq_session_release(only.s);
        }
    }

    /* (b) reached a TERMINAL FAILURE without ever establishing: a
     * deterministic no-mutual-profile pairing (CURRENT client vs a
     * D13/14-only server) fails at settings validation. A RETAINED handle
     * must still report no selection, with the output untouched. */
    if (side_up_profiles(&c, 'c', true,
                         (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT, 0,
                         fp) != 0 ||
        side_up_profiles(&s, 's', false, 0,
                         WTQ_WEBTRANSPORT_PROFILES_H3_DRAFT_13_14_COMPAT,
                         fp) != 0)
        return 1;

    wtq_serve_config_t path;
    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = OFFER;
    path.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_serve(s.s, &path, 1) == WTQ_OK);

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_connect(c.s, &cc) == WTQ_OK);
    pump(seed, &c, &s);

    /* CAUSAL: prove this really reached a TERMINAL FAILURE and did not
     * merely stall in CONNECTING — `established == 0` alone cannot tell
     * those apart. */
    WTQ_TEST_CHECK_EQ_INT(c.established, 0);
    WTQ_TEST_CHECK_EQ_INT(s.established, 0);
    WTQ_TEST_CHECK_EQ_INT(c.failed, 1);
    WTQ_TEST_CHECK_EQ_INT((int)wtq_session_status(c.s),
                          (int)WTQ_SESSION_STATUS_FAILED);
    prof = (wtq_webtransport_profile_t)0x7f;
    WTQ_TEST_CHECK_EQ_INT(
        (int)wtq_session_webtransport_profile(c.s, &prof),
        (int)WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f);
    WTQ_TEST_CHECK_EQ_INT(
        (int)wtq_session_webtransport_profile(s.s, &prof),
        (int)WTQ_ERR_STATE);
    WTQ_TEST_CHECK_EQ_INT((int)prof, 0x7f);

    wtq_session_release(c.s);
    wtq_session_release(s.s);
    *fp += failures;
    return 0;
}

/*
 * The AUTHORITATIVE-SET rule, end to end. A server configured with a valid
 * non-zero set AND an out-of-range singular profile must build, negotiate
 * and establish normally: once the set is given the singular input has no
 * role, so validating it would make the documented backend rule
 * unreachable. A test that stopped at listener normalisation would not
 * catch the engine rejecting it.
 */
static int scenario_authoritative_set_ignores_singular(uint64_t seed, int *fp)
{
    int failures = 0;
    static side_t c;
    static side_t s;

    /* 99 is deliberately out of range; the set is what counts */
    if (side_up_profiles(&c, 'c', true,
                         (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT,
                         0, fp) != 0 ||
        side_up_profiles(&s, 's', false, 99,
                         WTQ_WEBTRANSPORT_PROFILES_ALL, fp) != 0)
        return 1;

    wtq_serve_config_t path;
    wtq_serve_config_init(&path);
    path.path = "/app";
    path.subprotocols = OFFER;
    path.subprotocol_count = 1;
    WTQ_TEST_CHECK(wtq_api_session_serve(s.s, &path, 1) == WTQ_OK);

    wtq_connect_config_t cc;
    wtq_connect_config_init(&cc);
    cc.authority = "example.com";
    cc.path = "/app";
    cc.subprotocols = OFFER;
    cc.subprotocol_count = 1;
    cc.webtransport_profile =
        (uint32_t)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT;
    WTQ_TEST_CHECK(wtq_api_session_connect(c.s, &cc) == WTQ_OK);
    pump(seed, &c, &s);

    /* it negotiated normally, and selected from the SET */
    WTQ_TEST_CHECK_EQ_INT(s.established, 1);
    WTQ_TEST_CHECK_EQ_INT(c.established, 1);
    WTQ_TEST_CHECK_EQ_INT(s.cb_query_rc, (int)WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(
        s.cb_profile, (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT);

    wtq_session_release(c.s);
    wtq_session_release(s.s);
    *fp += failures;
    return 0;
}

int main(void)
{
    int failures = 0;

    (void)scenario_api_pair(0xAB1E, &failures);
    (void)scenario_api_pair(0x5EED, &failures); /* other chunking */
    (void)scenario_profile_query(0xC0FFEE,
                                 (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT,
                                 (int)WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT,
                                 &failures);
    (void)scenario_profile_query(
        0xDECAF, (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT,
        (int)WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT, &failures);
    (void)scenario_authoritative_set_ignores_singular(0xBADF00D, &failures);
    (void)scenario_profile_query_states(0x5747E5, &failures);

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_api_pair (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_api_pair\n");
    return 0;
}
