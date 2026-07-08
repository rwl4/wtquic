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
    wtq_estream_t *es_for_slot[FAKE_MAX_STREAMS];
};

static void on_established(wtq_session_t *s, wtq_str_t sub, void *user)
{
    side_t *sd = user;

    (void)s;
    (void)sub;
    sd->established++;
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

static int side_up(side_t *sd, char label, bool client, int *fp)
{
    int failures = 0;
    wtq_session_events_t ev;

    memset(sd, 0, sizeof(*sd));
    sd->label = label;
    fake_driver_init(&sd->drv, client);
    wtq_session_events_init(&ev);
    ev.on_established = on_established;
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

int main(void)
{
    int failures = 0;

    (void)scenario_api_pair(0xAB1E, &failures);
    (void)scenario_api_pair(0x5EED, &failures); /* other chunking */

    if (failures > 0) {
        fprintf(stderr, "FAILED: test_api_pair (%d)\n", failures);
        return 1;
    }
    printf("PASS: test_api_pair\n");
    return 0;
}
