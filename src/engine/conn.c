#include "wt_driver.h"

#include <string.h>

#include <wtquic/stream.h> /* WTQ_STREAM_MAX_SPANS: the public span-
                              count contract is enforced HERE, centrally
                              for every backend */

#include "../proto/capsule.h"
#include "../proto/connect.h"
#include "../proto/h3_err.h"
#include "../proto/h3_frame.h"
#include "../proto/preamble.h"
#include "../proto/varint.h"

/*
 * The wtquic engine: H3 control plane, extended-CONNECT session
 * establishment, capsule-driven session lifecycle, and WT stream
 * demux/passthrough. One allocation (the wtq_conn, including its
 * inline stream pool) at create; the receive path allocates nothing.
 */

#define WTQ_CONN_MAX_PEER_UNI 16
#define WTQ_CONN_SETTINGS_CAP 512

/* Peer stream classification states. */
enum {
    ES_FREE = 0,
    ES_TYPE,     /* uni: reading the stream-type varint / WT preamble */
    ES_BTYPE,    /* bidi: WT preamble vs H3 request classification */
    ES_CONTROL,  /* the peer's H3 control stream */
    ES_QPACK,    /* peer QPACK encoder/decoder stream: bytes ignored */
    ES_DRAIN,    /* unknown type or rejected WT stream: bytes discarded */
    ES_CONNECT,  /* client: our CONNECT stream (reads the response) */
    ES_REQUEST,  /* server: a peer request stream */
    ES_WT,       /* an associated WebTransport stream (either side) */
};

/* Control-frame payload handling classes. */
enum {
    CF_SETTINGS = 0,   /* accumulate + h3_settings decode */
    CF_ONE_VARINT,     /* GOAWAY / CANCEL_PUSH / MAX_PUSH_ID: payload is
                          exactly one varint (RFC 9114 s7.2.3/6/7) */
    CF_SKIP,           /* unknown/grease extension frame: opaque skip */
    CF_CAPSULE,        /* session-stream DATA: capsule protocol bytes */
};

struct wtq_estream {
    uint8_t kind;
    uint8_t qpack_type;         /* 0x02 or 0x03 for ES_QPACK */
    /* stream classification: uni routes H3 stream types out of the
     * UNEXPECTED result; bidi buffers the type varint for replay into
     * the request walk when the stream is not WT */
    wtq_preamble_dec_t pre;
    uint8_t btype_buf[8];       /* a type varint is at most 8 bytes */
    uint8_t btype_fill;
    /* control/request-stream frame state */
    wtq_h3_frame_dec_t frame_dec;
    bool frame_active;
    uint8_t frame_kind; /* CF_* */
    uint64_t frame_type;
    uint64_t frame_remaining;
    uint16_t set_fill;
    uint8_t set_buf[WTQ_CONN_SETTINGS_CAP];
    bool headers_done;  /* request/CONNECT streams: HEADERS consumed */
    bool trailers_done; /* the one permitted trailing HEADERS consumed */
    bool request_dead; /* server: rejected/second-CONNECT stream */
    bool is_session_stream; /* the established session's CONNECT stream */
    bool wt_bidi;      /* ES_WT: has both directions */
    bool wt_local;     /* ES_WT: we opened it */
    bool wt_send_open; /* ES_WT: our send side still usable */
    bool wt_recv_open; /* ES_WT: peer's send side still open */
    bool wt_recv_drain; /* ES_WT: locally stopped — absorb late bytes
                           quietly until the peer's FIN/RESET lands */
    void *user;        /* app per-stream context */
    wtq_dstream_t *ds;
    uint64_t id;             /* native QUIC id; WTQ_STREAM_ID_UNKNOWN until
                                assigned (locally-opened, async transports) */
    bool native_id_pending;  /* open_* returned UNKNOWN; a report is due */
};

/* Session states: the wtq_session_state_t values from the SPI header,
 * under the short names the code grew up with. */
#define SS_IDLE WTQ_SESSION_IDLE
#define SS_PENDING WTQ_SESSION_PENDING
#define SS_SENT WTQ_SESSION_SENT
#define SS_ESTABLISHED WTQ_SESSION_ESTABLISHED
#define SS_DRAINING WTQ_SESSION_DRAINING
#define SS_CLOSED WTQ_SESSION_CLOSED
#define SS_REJECTED WTQ_SESSION_REJECTED
#define SS_FAILED WTQ_SESSION_FAILED

struct wtq_conn {
    wtq_alloc_t alloc;
    wtq_perspective_t persp;
    wtq_driver_t *drv;
    wtq_driver_ops_t ops;
    wtq_conn_callbacks_t cb;
    bool ecp;
    /* The connection-latched WebTransport wire profile. Committed before
     * the control-stream SETTINGS are emitted; selects both the emitted
     * WT SETTINGS and the extended-CONNECT :protocol token. Defaults to
     * current (draft-16); a client latches it at wtq_conn_client_connect. */
    wtq_h3_wt_profile_t wt_profile;

    bool started;            /* start ATTEMPTED (one-shot latch) */
    bool locals_attempted;   /* the ONE-SHOT local-bootstrap attempt is
                                consumed (control/QPACK opens tried —
                                NOT necessarily succeeded). Clients
                                consume it at start; servers defer it
                                to the first inbound event, and a
                                failed attempt is connection-fatal
                                (H3_INTERNAL_ERROR), never retried. */
    bool peer_control_seen;
    bool qpack_enc_seen;
    bool qpack_dec_seen;
    bool settings_received;
    bool wt_supported;
    bool max_push_id_seen;      /* server: MAX_PUSH_ID monotonicity */
    uint64_t max_push_id;
    wtq_h3_settings_t peer_settings;

    bool closed;
    uint64_t close_code;
    /* First-causal transport-error record (write-once; §6 of the stream-
     * identity design). Latched by conn_fatal (engine origin) or
     * wtq_conn_set_transport_error (backend origin), whichever is FIRST;
     * synthesized from the terminal input when neither ran. */
    bool transport_error_set;
    wtq_transport_error_t transport_error;

    wtq_dstream_t *local_ctrl;
    wtq_dstream_t *local_qpk_enc;
    wtq_dstream_t *local_qpk_dec;

    /* client CONNECT (encoded eagerly; sending deferred to SETTINGS) */
    uint8_t sess_state;
    uint8_t connect_section[1024];
    size_t connect_section_len;
    char offered_buf[512];
    wtq_sf_str_t offered[WTQ_CONN_MAX_OFFERED];
    size_t offered_count;
    bool require_protocol;
    wtq_dstream_t *connect_ds;
    /* client establishment latches: a successful response may arrive
     * before the CONNECT stream's native id (async-id transports). The
     * selection is parked as an index into offered[] — persistent bytes,
     * never a pointer into decode scratch. */
    bool client_response_ok;
    int16_t client_selected_offer;  /* -1 = no subprotocol selected */

    /* server accept policy + accepted-request record */
    struct {
        char path[128];
        size_t path_len;
        char proto_buf[256];
        wtq_sf_str_t protos[WTQ_CONN_MAX_OFFERED];
        size_t proto_count;
        bool require;
    } paths[WTQ_CONN_MAX_PATHS];
    size_t path_count;
    char req_path[256];
    size_t req_path_len;
    char req_auth[256];
    size_t req_auth_len;

    /* server: one completed CONNECT parked until the client's SETTINGS
     * arrive (draft-15 s3.1: the server must not process WT requests
     * before then). The encoded request is COPIED out of the estream's
     * set_buf, which later frames (trailers, grease) reuse. One parked
     * request per connection, so one buffer. */
    struct wtq_estream *parked_es;
    uint8_t parked_buf[WTQ_CONN_SETTINGS_CAP];
    uint16_t parked_fill;
    bool parked_fin; /* peer FIN arrived while parked */

    bool session_established;
    /* The negotiated subprotocol, verbatim. Always a copy of one of OUR
     * configured values, and every configured value was round-tripped
     * through this engine's codec at configuration time — so whatever
     * reaches here came out of a decoder bounded by the same capacity
     * and always fits. */
    char selected[WTQ_CONN_PROTOCOL_STORAGE];
    size_t selected_len;

    /* the established session's runtime state */
    uint64_t session_id;              /* == the CONNECT stream's id */
    struct wtq_estream *session_es;   /* NULL once that stream ends */
    wtq_capsule_dec_t caps_dec;       /* capsule walk over DATA payload */
    bool close_capsule_rx;
    bool drain_rx;
    /* datagram association: the minimal varint encoding of the
     * quarter stream id (session_id / 4), precomputed so the receive
     * fast path is one memcmp */
    uint8_t qsid_prefix[8];
    uint8_t qsid_prefix_len;
    uint64_t dgrams_dropped;

    struct wtq_estream peer[WTQ_CONN_MAX_PEER_UNI];
};

static const wtq_connect_opts_t CONN_STRICT_OPTS = { false, false };
/* Server inbound-request decode for the D13/14 compat profile: accept the
 * bare "webtransport" :protocol token. The current profile decodes with
 * CONN_STRICT_OPTS (webtransport-h3 only). Either profile still rejects the
 * OTHER profile's token — see the symmetry gate in server_request_done. */
static const wtq_connect_opts_t CONN_SERVER_COMPAT_OPTS = { false, true };

/*
 * Can this engine carry `p` as a negotiated subprotocol at all? Decided
 * by DOING it: encode a successful response around the value and decode
 * that response back through the same bounded scratch this engine uses
 * on receive, then require the bytes to survive intact.
 *
 * This is what makes escaping honest. draft-15 s3.3 permits '"' and '\\'
 * in a Structured Fields String, and each costs two bytes escaped, so a
 * value's raw length says nothing about whether it fits.
 *
 * The status distinguishes the two failure kinds the caller must report
 * differently: content the grammar forbids (INVALID_ARG) versus content
 * that is fine but does not fit (TOO_LARGE).
 */
static wtq_result_t protocol_check(const char *p, size_t len)
{
    uint8_t section[WTQ_CONN_SETTINGS_CAP];
    char scratch[WTQ_CONN_SETTINGS_CAP];
    wtq_sf_str_t sel = { p, len };
    wtq_connect_resp_t resp;
    size_t slen = 0;

    if (len == 0 || !wtq_sf_string_valid(p, len))
        return WTQ_ERR_INVALID_ARG; /* not a Structured Fields String */

    wtq_connect_status_t st = wtq_connect_encode_response(
        200, &sel, section, sizeof(section), &slen);
    if (st == WTQ_CONNECT_BUFFER)
        return WTQ_ERR_TOO_LARGE;
    if (st != WTQ_CONNECT_OK)
        return WTQ_ERR_INVALID_ARG;

    st = wtq_connect_decode_response(section, slen, &CONN_STRICT_OPTS,
                                     &resp, scratch, sizeof(scratch));
    if (st == WTQ_CONNECT_BUFFER)
        return WTQ_ERR_TOO_LARGE;
    if (st != WTQ_CONNECT_OK)
        return WTQ_ERR_INVALID_ARG;

    /* survived, but only if the bytes came back whole */
    if (!resp.has_protocol || resp.protocol.len != len ||
        memcmp(resp.protocol.data, p, len) != 0)
        return WTQ_ERR_TOO_LARGE;
    return WTQ_OK;
}

wtq_result_t wtq_conn_validate_protocols(const char *const *protocols,
                                         size_t count)
{
    size_t buf_off = 0;

    if (count > WTQ_CONN_MAX_OFFERED)
        return WTQ_ERR_TOO_LARGE;
    if (count > 0 && protocols == NULL)
        return WTQ_ERR_INVALID_ARG;

    for (size_t i = 0; i < count; i++) {
        if (protocols[i] == NULL)
            return WTQ_ERR_INVALID_ARG;
        size_t len = strlen(protocols[i]);
        wtq_result_t rc = protocol_check(protocols[i], len);
        if (rc != WTQ_OK)
            return rc;
        if (buf_off + len > WTQ_CONN_PATH_PROTO_STORAGE)
            return WTQ_ERR_TOO_LARGE;
        buf_off += len;
    }
    return WTQ_OK;
}

static void conn_fatal(wtq_conn_t *conn, uint64_t h3_err);
static void estream_release(wtq_conn_t *conn, struct wtq_estream *es);
static void wt_release_if_done(wtq_conn_t *conn, struct wtq_estream *es);

/*
 * Raw, ds-level whole-stream abort for paths with no (or a dying)
 * estream: pool rejection, demotion, refusal, teardown. ONE transaction;
 * WTQ_ERR_CLOSED from the backend is benign (transport already dead),
 * any other failure is a runtime defect and fails the connection —
 * never a pretended rollback.
 */
static void shutdown_raw(wtq_conn_t *conn, wtq_dstream_t *ds,
                         bool abort_send, bool abort_recv, uint64_t code)
{
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_WHOLE_STREAM,
                           .abort_send = abort_send,
                           .abort_recv = abort_recv,
                           .send_err = code,
                           .recv_err = code };
    wtq_result_t rc = conn->ops.shutdown_stream(conn->drv, ds, &req);
    if (rc != WTQ_OK && rc != WTQ_ERR_CLOSED)
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
}

static void session_failed(wtq_conn_t *conn,
                           wtq_session_fail_reason_t reason)
{
    conn->sess_state = SS_FAILED;
    if (conn->cb.on_session_failed != NULL)
        conn->cb.on_session_failed(conn, reason, conn->cb.ctx);
}

static void session_established(wtq_conn_t *conn, struct wtq_estream *es,
                                const char *sel, size_t sel_len)
{
    /* Unreachable: selection only ever yields one of our own configured
     * protocols, and those are bounded at configuration time. Never
     * silently downgrade a real selection to "absent". */
    if (sel_len > sizeof(conn->selected)) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    if (sel_len > 0)
        memcpy(conn->selected, sel, sel_len);
    conn->selected_len = sel_len;
    /* The session id IS the CONNECT stream's native id; establishment is
     * gated on knowing it (client_maybe_establish; servers adopt it from
     * the peer-open event), so UNKNOWN here is an engine logic error. */
    if (es->id == WTQ_STREAM_ID_UNKNOWN) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    conn->session_established = true;
    conn->sess_state = SS_ESTABLISHED;
    conn->session_id = es->id;
    conn->session_es = es;
    es->is_session_stream = true;
    wtq_capsule_dec_init(&conn->caps_dec);
    size_t qlen = 0;
    (void)wtq_varint_encode(conn->session_id / 4, conn->qsid_prefix,
                            sizeof(conn->qsid_prefix), &qlen);
    conn->qsid_prefix_len = (uint8_t)qlen;
    if (conn->cb.on_session_established != NULL)
        conn->cb.on_session_established(conn, conn->selected,
                                        conn->selected_len, conn->cb.ctx);
}

/*
 * THE terminal transition: ESTABLISHED/DRAINING -> CLOSED, exactly
 * once, whatever ends the session. Tears down every associated WT
 * stream first (draft-15 s6: reset send sides / abort reading with
 * WT_SESSION_GONE) — skipped when the whole connection is already
 * closed, since driver ops are meaningless then.
 */
static void session_closed(wtq_conn_t *conn, uint32_t code,
                           const uint8_t *reason, size_t reason_len,
                           bool clean)
{
    if (conn->sess_state != SS_ESTABLISHED &&
        conn->sess_state != SS_DRAINING)
        return;
    conn->sess_state = SS_CLOSED;

    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++) {
        struct wtq_estream *es = &conn->peer[i];
        if (es->kind != ES_WT)
            continue;
        if (!conn->closed && (es->wt_send_open || es->wt_recv_open))
            shutdown_raw(conn, es->ds, es->wt_send_open,
                         es->wt_recv_open, WTQ_WT_SESSION_GONE);
        /* Never force-free: the backend may still deliver in-flight
         * bytes against this ectx, and the slot must not be reused
         * while it can. Close both directions and leave receive
         * sides draining until the peer's FIN/RESET lands (the same
         * discipline as wt_stop). */
        es->wt_send_open = false;
        if (es->wt_recv_open) {
            es->wt_recv_open = false;
            es->wt_recv_drain = true;
        }
        wt_release_if_done(conn, es);
    }

    if (conn->cb.on_session_closed != NULL)
        conn->cb.on_session_closed(conn, code,
                                   reason != NULL ? reason
                                                  : (const uint8_t *)"",
                                   reason != NULL ? reason_len : 0,
                                   clean, conn->cb.ctx);
}

/* Send the (already encoded) CONNECT request on a fresh bidi stream. */
static void client_send_connect(wtq_conn_t *conn)
{
    struct wtq_estream *es = NULL;

    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++)
        if (conn->peer[i].kind == ES_FREE) {
            es = &conn->peer[i];
            break;
        }
    if (es == NULL) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    memset(es, 0, sizeof(*es));
    es->kind = ES_CONNECT;
    es->id = WTQ_STREAM_ID_UNKNOWN; /* explicit: 0 is a real stream id */
    wtq_h3_frame_dec_init(&es->frame_dec);

    uint64_t id = WTQ_STREAM_ID_UNKNOWN;
    if (conn->ops.open_bidi == NULL ||
        conn->ops.open_bidi(conn->drv, es, &conn->connect_ds, &id) !=
            WTQ_OK) {
        estream_release(conn, es);
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    es->ds = conn->connect_ds;
    es->id = id;
    es->native_id_pending = (id == WTQ_STREAM_ID_UNKNOWN);

    uint8_t hdr[16];
    size_t hl = 0;
    (void)wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS,
                                     conn->connect_section_len, hdr,
                                     sizeof(hdr), &hl);
    if (conn->ops.send(conn->drv, conn->connect_ds, hdr, hl, false) !=
            WTQ_OK ||
        conn->ops.send(conn->drv, conn->connect_ds,
                       conn->connect_section, conn->connect_section_len,
                       false) != WTQ_OK) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    conn->sess_state = SS_SENT;
}

static void request_stream_bytes(wtq_conn_t *conn,
                                 struct wtq_estream *es,
                                 const uint8_t *data, size_t len);
static void request_stream_fin(wtq_conn_t *conn, struct wtq_estream *es);
static void server_request_done(wtq_conn_t *conn, struct wtq_estream *es);
static void request_stream_refuse(wtq_conn_t *conn,
                                  struct wtq_estream *es);
static void parked_request_cancel(wtq_conn_t *conn);
static void session_stream_poisoned(wtq_conn_t *conn,
                                    struct wtq_estream *es);

/* Close the connection with an H3 error exactly once. An established
 * session dies with it: the terminal session callback fires (unclean)
 * before the connection-error callback. */
/*
 * The connection died. Give the session EXACTLY ONE outcome, chosen by
 * its state, before the connection error is reported:
 *   ESTABLISHED / DRAINING -> unclean on_session_closed
 *   IDLE / PENDING / SENT  -> on_session_failed(CONNECTION)
 *   CLOSED / REJECTED / FAILED -> already terminal; nothing fires, and
 *       an existing specific reason stays authoritative.
 */
static void session_conn_lost(wtq_conn_t *conn)
{
    switch (conn->sess_state) {
    case SS_ESTABLISHED:
    case SS_DRAINING:
        session_closed(conn, 0, NULL, 0, false);
        break;
    case SS_IDLE:
    case SS_PENDING:
    case SS_SENT:
        session_failed(conn, WTQ_SESSION_FAIL_CONNECTION);
        break;
    default:
        break; /* terminal already */
    }
}

/* Write-once: the first causal error wins across BOTH origins. */
static void conn_latch_error(wtq_conn_t *conn, uint16_t kind,
                             uint64_t quic_code, uint32_t native_domain,
                             int64_t native_code)
{
    if (conn->transport_error_set)
        return;
    conn->transport_error_set = true;
    memset(&conn->transport_error, 0, sizeof(conn->transport_error));
    conn->transport_error.struct_size =
        (uint32_t)sizeof(conn->transport_error);
    conn->transport_error.kind = kind;
    conn->transport_error.quic_code = quic_code;
    conn->transport_error.native_domain = native_domain;
    conn->transport_error.native_code = native_code;
}

static void conn_fatal(wtq_conn_t *conn, uint64_t h3_err)
{
    if (conn->closed)
        return;
    /* Latch BEFORE the backend shutdown and BEFORE any callback: the
     * engine's error is the first cause; whatever status the transport
     * reports while executing this teardown must not overwrite it. */
    conn_latch_error(conn, WTQ_ERR_KIND_QUIC_APP, h3_err,
                     WTQ_ERRDOM_NONE, 0);
    conn->closed = true;
    conn->close_code = h3_err;
    (void)conn->ops.conn_close(conn->drv, h3_err);
    session_conn_lost(conn);
    if (conn->cb.on_conn_error != NULL)
        conn->cb.on_conn_error(conn, h3_err, conn->cb.ctx);
}

wtq_result_t wtq_conn_create(const wtq_conn_cfg_t *cfg, wtq_driver_t *drv,
                             const wtq_driver_ops_t *ops, wtq_conn_t **out)
{
    if (cfg == NULL || cfg->alloc == NULL || drv == NULL || ops == NULL ||
        ops->open_uni == NULL || ops->open_bidi == NULL ||
        ops->send == NULL || ops->shutdown_stream == NULL ||
        ops->conn_close == NULL ||
        ops->detach == NULL || out == NULL)
        return WTQ_ERR_INVALID_ARG; /* send_gather alone is optional */
    if (cfg->perspective != WTQ_PERSPECTIVE_CLIENT &&
        cfg->perspective != WTQ_PERSPECTIVE_SERVER)
        return WTQ_ERR_INVALID_ARG;
    if (cfg->webtransport_profile != WTQ_H3_WT_PROFILE_CURRENT &&
        cfg->webtransport_profile != WTQ_H3_WT_PROFILE_D13_14_COMPAT)
        return WTQ_ERR_INVALID_ARG;

    wtq_conn_t *conn = cfg->alloc->alloc(sizeof(*conn), cfg->alloc->ctx);
    if (conn == NULL)
        return WTQ_ERR_NOMEM;
    memset(conn, 0, sizeof(*conn));

    conn->alloc = *cfg->alloc;
    conn->persp = cfg->perspective;
    conn->drv = drv;
    conn->ops = *ops;
    conn->cb = cfg->callbacks;
    conn->ecp = cfg->enable_connect_protocol;
    /* Latched here for the SERVER (fixes its SETTINGS dialect + the inbound
     * CONNECT token it accepts, before any stream opens). A CLIENT is created
     * with current (0) and re-latches its real profile in
     * wtq_conn_client_connect, before start emits SETTINGS. */
    conn->wt_profile = (wtq_h3_wt_profile_t)cfg->webtransport_profile;

    *out = conn;
    return WTQ_OK;
}

void wtq_conn_destroy(wtq_conn_t *conn)
{
    if (conn == NULL)
        return;
    wtq_alloc_t alloc = conn->alloc;
    alloc.free(conn, sizeof(*conn), alloc.ctx);
}

/*
 * Open OUR control + QPACK streams and send the SETTINGS/prefaces.
 * One-shot: the attempt is consumed before the first driver op. A
 * failure part-way leaves an opened stream (and possibly a transmitted
 * SETTINGS frame) on the wire, and neither can be un-sent — so no
 * retry is possible and no rollback is attempted.
 */
static wtq_result_t conn_open_locals(wtq_conn_t *conn)
{
    /* Control stream: type 0x00 + our SETTINGS frame. */
    uint8_t buf[1 + 8 + 64];
    wtq_h3_settings_encode_cfg_t scfg = { conn->ecp, conn->wt_profile };
    size_t flen = 0;

    buf[0] = 0x00;
    if (wtq_h3_settings_encode_frame(&scfg, buf + 1, sizeof(buf) - 1,
                                     &flen) != WTQ_H3_SETTINGS_OK)
        return WTQ_ERR_BACKEND; /* unreachable: buf sized for the
                                   largest settings frame we emit */
    conn->locals_attempted = true;

    uint64_t id = 0;
    wtq_result_t rc = conn->ops.open_uni(conn->drv, NULL,
                                         &conn->local_ctrl, &id);
    if (rc != WTQ_OK)
        return rc;
    rc = conn->ops.send(conn->drv, conn->local_ctrl, buf, 1 + flen,
                        false);
    if (rc != WTQ_OK)
        return rc;

    /* QPACK encoder/decoder streams: one-byte prefaces, nothing ever
     * follows (static-only QPACK). */
    static const uint8_t enc_type = 0x02;
    static const uint8_t dec_type = 0x03;
    rc = conn->ops.open_uni(conn->drv, NULL, &conn->local_qpk_enc, &id);
    if (rc != WTQ_OK)
        return rc;
    rc = conn->ops.send(conn->drv, conn->local_qpk_enc, &enc_type, 1,
                        false);
    if (rc != WTQ_OK)
        return rc;
    rc = conn->ops.open_uni(conn->drv, NULL, &conn->local_qpk_dec, &id);
    if (rc != WTQ_OK)
        return rc;
    rc = conn->ops.send(conn->drv, conn->local_qpk_dec, &dec_type, 1,
                        false);
    if (rc != WTQ_OK)
        return rc;

    return WTQ_OK;
}

wtq_result_t wtq_conn_start(wtq_conn_t *conn, uint64_t now_us)
{
    (void)now_us;
    if (conn->started || conn->closed)
        return WTQ_ERR_STATE;
    conn->started = true;

    /*
     * SERVER DEFERRAL (measured platform loss, see the runtime-proof
     * attribution): a server that opens its uni streams at
     * handshake-complete races the CLIENT transport's own readiness —
     * Network.framework's QUIC intermittently drops server-initiated
     * streams that arrive inside its ready transition
     * ("quic_stream_add_new_flow ... failed", never retransmitted once
     * acked), wedging the H3 handshake. Deferring OUR streams until
     * the peer's first inbound event guarantees they depart only after
     * the client demonstrably finished its transition (the client only
     * sends after ready). Ordering stays RFC 9220-clean: the client's
     * extended CONNECT still waits for our SETTINGS, which now follow
     * its control stream by one flight. Clients never defer (their
     * streams depart after their own readiness by construction).
     */
    if (conn->persp == WTQ_PERSPECTIVE_SERVER)
        return WTQ_OK;
    return conn_open_locals(conn);
}

/* First inbound engine input on a deferred server: open our locals
 * BEFORE processing the peer's event. The attempt is one-shot (the
 * latch is consumed before the first driver op), so a failure can
 * never be retried — it is CONNECTION-FATAL, exactly once, with
 * H3_INTERNAL_ERROR as the first-causal error, and the triggering
 * peer event is NOT processed (the caller sees the closed
 * connection). */
static wtq_result_t conn_open_locals_if_deferred(wtq_conn_t *conn)
{
    if (conn->locals_attempted || !conn->started || conn->closed)
        return WTQ_OK;
    if (conn_open_locals(conn) != WTQ_OK) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return WTQ_ERR_CLOSED;
    }
    return WTQ_OK;
}

wtq_result_t wtq_conn_on_peer_uni_opened(wtq_conn_t *conn,
                                         wtq_dstream_t *ds, uint64_t id,
                                         wtq_estream_t **ectx_out)
{
    *ectx_out = NULL;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    wtq_result_t lrc = conn_open_locals_if_deferred(conn);
    if (lrc != WTQ_OK)
        return lrc;

    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++) {
        struct wtq_estream *es = &conn->peer[i];
        if (es->kind == ES_FREE) {
            memset(es, 0, sizeof(*es));
            es->kind = ES_TYPE;
            es->ds = ds;
            es->id = id;
            *ectx_out = es;
            return WTQ_OK;
        }
    }
    /* The pool is full. Reject the stream ACTIVELY (draft-15 s4.6) so
     * the peer learns immediately — never a silent sink. A uni stream
     * only has a receive side to abort. */
    shutdown_raw(conn, ds, false, true, WTQ_WT_BUFFERED_STREAM_REJECTED);
    return WTQ_ERR_STREAM_LIMIT;
}

/* Classify a completed stream-type varint. Returns false when the
 * connection died. */
static bool classify_uni(wtq_conn_t *conn, struct wtq_estream *es,
                         uint64_t type)
{
    if (type == 0x00) {
        if (conn->peer_control_seen) {
            conn_fatal(conn, WTQ_H3_STREAM_CREATION_ERROR);
            return false;
        }
        conn->peer_control_seen = true;
        es->kind = ES_CONTROL;
        wtq_h3_frame_dec_init(&es->frame_dec);
        return true;
    }
    if (type == 0x02 || type == 0x03) {
        bool *seen = (type == 0x02) ? &conn->qpack_enc_seen
                                    : &conn->qpack_dec_seen;
        if (*seen) {
            conn_fatal(conn, WTQ_H3_STREAM_CREATION_ERROR);
            return false;
        }
        *seen = true;
        es->kind = ES_QPACK;
        es->qpack_type = (uint8_t)type;
        return true;
    }
    if (type == 0x01) {
        /* Push stream: a known type with required error behavior
         * (RFC 9114 s4.6, s6.2.2). Servers must reject client pushes
         * outright; a client that never sent MAX_PUSH_ID (wtquic never
         * does) must treat any push id as exceeding the limit. */
        conn_fatal(conn, conn->persp == WTQ_PERSPECTIVE_SERVER
                             ? WTQ_H3_STREAM_CREATION_ERROR
                             : WTQ_H3_ID_ERROR);
        return false;
    }
    /* Unknown/grease types: drained (RFC 9114 s6.2.2 allows
     * STOP_SENDING with H3_STREAM_CREATION_ERROR; discarding keeps v0
     * minimal). */
    es->kind = ES_DRAIN;
    return true;
}

/* Control-stream frame legality after SETTINGS (RFC 9114 Table 1 +
 * s7.2.8): GOAWAY, CANCEL_PUSH and MAX_PUSH_ID are KNOWN frames whose
 * one-varint payloads are validated (see CF_ONE_VARINT handling);
 * unknown extension frames are opaque-skipped; DATA, HEADERS,
 * PUSH_PROMISE and the reserved types 0x02/0x06/0x08/0x09 are
 * connection errors. */
static bool control_frame_forbidden(uint64_t type)
{
    switch (type) {
    case 0x00: /* DATA */
    case 0x01: /* HEADERS */
    case 0x05: /* PUSH_PROMISE */
    case 0x02: /* reserved (H2 PRIORITY) */
    case 0x06: /* reserved (H2 PING) */
    case 0x08: /* reserved (H2 WINDOW_UPDATE) */
    case 0x09: /* reserved (H2 CONTINUATION) */
        return true;
    default:
        return false;
    }
}

/* Feed control-stream bytes through the frame layer. */
static void control_bytes(wtq_conn_t *conn, struct wtq_estream *es,
                          const uint8_t *data, size_t len)
{
    size_t off = 0;

    while (off < len && !conn->closed) {
        if (!es->frame_active) {
            wtq_h3_frame_t hdr;
            size_t c = 0;
            wtq_h3_frame_status_t st = wtq_h3_frame_dec_feed(
                &es->frame_dec, data + off, len - off, &hdr, &c);
            off += c;
            if (st == WTQ_H3_FRAME_NEED_MORE)
                return;

            bool is_settings = (hdr.type == WTQ_H3_FRAME_SETTINGS);
            es->frame_type = hdr.type;
            es->frame_remaining = hdr.length;
            es->frame_active = true;
            es->set_fill = 0;

            if (!conn->settings_received && !is_settings) {
                conn_fatal(conn, WTQ_H3_MISSING_SETTINGS);
                return;
            }
            if (conn->settings_received && is_settings) {
                /* RFC 9114 s7.2.4: a second SETTINGS frame is
                 * FRAME_UNEXPECTED (h3zero agrees). */
                conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                return;
            }
            if (!is_settings && control_frame_forbidden(hdr.type)) {
                conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                return;
            }
            if (is_settings) {
                if (hdr.length > WTQ_CONN_SETTINGS_CAP) {
                    conn_fatal(conn, WTQ_H3_EXCESSIVE_LOAD);
                    return;
                }
                es->frame_kind = CF_SETTINGS;
            } else if (hdr.type == WTQ_H3_FRAME_GOAWAY ||
                       hdr.type == WTQ_H3_FRAME_CANCEL_PUSH ||
                       hdr.type == WTQ_H3_FRAME_MAX_PUSH_ID) {
                /* Known one-varint frames: validate layout, never
                 * grease-skip. A client must never receive
                 * MAX_PUSH_ID at all (s7.2.7). */
                if (hdr.type == WTQ_H3_FRAME_MAX_PUSH_ID &&
                    conn->persp == WTQ_PERSPECTIVE_CLIENT) {
                    conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                    return;
                }
                if (hdr.length == 0 || hdr.length > 8) {
                    conn_fatal(conn, WTQ_H3_FRAME_ERROR);
                    return;
                }
                es->frame_kind = CF_ONE_VARINT;
            } else {
                es->frame_kind = CF_SKIP;
            }
        }

        /* Frame payload. */
        size_t avail = len - off;
        size_t take = es->frame_remaining < (uint64_t)avail
                          ? (size_t)es->frame_remaining
                          : avail;
        if (es->frame_kind != CF_SKIP && take > 0) {
            memcpy(es->set_buf + es->set_fill, data + off, take);
            es->set_fill = (uint16_t)(es->set_fill + take);
        }
        /* grease/extension frames: payload skipped opaquely */
        off += take;
        es->frame_remaining -= take;

        if (es->frame_remaining == 0) {
            es->frame_active = false;
            if (es->frame_kind == CF_ONE_VARINT) {
                /* payload must be exactly one varint */
                uint64_t v = 0;
                size_t c = 0;
                if (wtq_varint_decode(es->set_buf, es->set_fill, &v,
                                      &c) != WTQ_VARINT_OK ||
                    c != es->set_fill) {
                    conn_fatal(conn, WTQ_H3_FRAME_ERROR);
                    return;
                }
                if (es->frame_type == WTQ_H3_FRAME_CANCEL_PUSH) {
                    /* wtquic never promises or accepts pushes: any
                     * push id is unknown (RFC 9114 s7.2.3). */
                    conn_fatal(conn, WTQ_H3_ID_ERROR);
                    return;
                }
                if (es->frame_type == WTQ_H3_FRAME_MAX_PUSH_ID) {
                    /* Server side (clients rejected at header time).
                     * RFC 9114 s7.2.7: the maximum cannot shrink. We
                     * never push, but the invariant still gates. */
                    if (conn->max_push_id_seen &&
                        v < conn->max_push_id) {
                        conn_fatal(conn, WTQ_H3_ID_ERROR);
                        return;
                    }
                    conn->max_push_id_seen = true;
                    conn->max_push_id = v;
                }
                /* GOAWAY: layout validated; semantics deferred to the
                 * session layer. */
            } else if (es->frame_kind == CF_SETTINGS) {
                wtq_h3_settings_t s;
                wtq_h3_settings_status_t st = wtq_h3_settings_decode(
                    es->set_buf, es->set_fill, &s);
                if (st == WTQ_H3_SETTINGS_ERR_SETTING) {
                    conn_fatal(conn, WTQ_H3_SETTINGS_ERROR);
                    return;
                }
                if (st != WTQ_H3_SETTINGS_OK) {
                    /* the frame ended mid-pair: layout violation */
                    conn_fatal(conn, WTQ_H3_FRAME_ERROR);
                    return;
                }
                conn->peer_settings = s;
                conn->settings_received = true;
                conn->wt_supported = wtq_h3_settings_peer_supports_wt(
                    &s, conn->persp == WTQ_PERSPECTIVE_CLIENT,
                    conn->wt_profile);
                if (conn->cb.on_peer_settings != NULL)
                    conn->cb.on_peer_settings(conn, conn->wt_supported,
                                              conn->cb.ctx);
                if (conn->persp == WTQ_PERSPECTIVE_CLIENT &&
                    conn->sess_state == SS_PENDING) {
                    if (!conn->wt_supported)
                        session_failed(conn,
                                       WTQ_SESSION_FAIL_NO_WT_SUPPORT);
                    else
                        client_send_connect(conn);
                }
                if (conn->persp == WTQ_PERSPECTIVE_SERVER &&
                    conn->parked_es != NULL) {
                    /* Release the deferred CONNECT: decide it now,
                     * then apply a FIN that arrived while parked with
                     * its normal post-decision meaning (mirrors the
                     * fin path in wtq_conn_on_stream_bytes). */
                    struct wtq_estream *req = conn->parked_es;
                    bool deferred_fin = conn->parked_fin;
                    uint16_t fill = conn->parked_fill;
                    uint8_t buf[WTQ_CONN_SETTINGS_CAP];

                    memcpy(buf, conn->parked_buf, fill);
                    parked_request_cancel(conn);
                    /* restore the request the trailers may have
                     * overwritten in set_buf */
                    memcpy(req->set_buf, buf, fill);
                    req->set_fill = fill;
                    server_request_done(conn, req);
                    if (deferred_fin && !conn->closed &&
                        req->kind != ES_FREE) {
                        request_stream_fin(conn, req);
                        if (conn->session_es == req)
                            conn->session_es = NULL;
                        estream_release(conn, req);
                    }
                }
            }
        }
    }
}

/*
 * Associate a stream that presented a complete WT preamble. Streams
 * for an unknown session are rejected deterministically — wtquic
 * buffers ZERO pre-establishment streams (draft-15 s4.6 requires only
 * a limit; the SHOULD-buffer is declined for now) — and streams for
 * the terminated session get WT_SESSION_GONE. Rejected streams become
 * drain tombstones so late in-flight bytes stay harmless.
 */
static bool wt_associate(wtq_conn_t *conn, struct wtq_estream *es,
                         uint64_t sid, bool bidi)
{
    /* draft-15 s4: session ids MUST correspond to a client-initiated
     * bidirectional stream id; anything else MUST close the
     * connection with H3_ID_ERROR. (Closed sessions are NOT invalid
     * for this check — they take the SESSION_GONE path below.) */
    if (sid % 4 != 0) {
        conn_fatal(conn, WTQ_H3_ID_ERROR);
        return false;
    }

    bool active = conn->session_established &&
                  (conn->sess_state == SS_ESTABLISHED ||
                   conn->sess_state == SS_DRAINING);

    if (active && sid == conn->session_id) {
        es->kind = ES_WT;
        es->wt_bidi = bidi;
        es->wt_local = false;
        es->wt_recv_open = true;
        es->wt_send_open = bidi;
        if (conn->cb.on_wt_stream_opened != NULL)
            conn->cb.on_wt_stream_opened(conn, es, bidi, es->id,
                                         conn->cb.ctx);
        return true;
    }

    uint64_t code = (conn->session_established &&
                     sid == conn->session_id)
                        ? WTQ_WT_SESSION_GONE
                        : WTQ_WT_BUFFERED_STREAM_REJECTED;
    shutdown_raw(conn, es->ds, bidi, true, code);
    es->kind = ES_DRAIN;
    return false;
}

/* The single gate to slot reuse: sever the backend's stream→engine
 * linkage FIRST, so a late transport event on the old stream can never
 * reach the slot's next occupant. The detach is identity-checked in
 * the backend, so releasing a slot whose ds pointer is stale (open
 * failure paths) is harmless. Drain tombstones are NOT released here —
 * they come through only once their terminal condition is met. */
static void estream_release(wtq_conn_t *conn, struct wtq_estream *es)
{
    if (es->ds != NULL)
        conn->ops.detach(conn->drv, es->ds, es);
    es->kind = ES_FREE;
    /* a released slot never has a report due: a buggy backend passing a
     * cached pointer must hit the fatal path, not mutate the free slot */
    es->native_id_pending = false;
}

/* A WT stream lives until BOTH directions are done (FIN/reset closes
 * receive; send(fin)/reset closes send; single-direction streams have
 * the missing side born closed). A locally-stopped receive side keeps
 * the estream alive as a quiet absorber until the peer's FIN/RESET
 * arrives — QUIC delivers in-flight bytes until STOP_SENDING is
 * answered. */
static void wt_release_if_done(wtq_conn_t *conn, struct wtq_estream *es)
{
    if (es->kind == ES_WT && !es->wt_send_open && !es->wt_recv_open &&
        !es->wt_recv_drain)
        estream_release(conn, es);
}

/* Payload passthrough for an associated WT stream: the engine hands
 * the transport's bytes through untouched (no copy, no buffering). */
static void wt_deliver(wtq_conn_t *conn, struct wtq_estream *es,
                       const uint8_t *data, size_t len, bool fin)
{
    if (es->wt_recv_drain) {
        /* locally stopped: bytes are absorbed, never delivered */
        if (fin) {
            es->wt_recv_drain = false;
            wt_release_if_done(conn, es);
        }
        return;
    }
    if (conn->cb.on_wt_stream_data != NULL && (len > 0 || fin))
        conn->cb.on_wt_stream_data(conn, es, data, len, fin,
                                   conn->cb.ctx);
    if (fin) {
        es->wt_recv_open = false;
        /* a drain requested from INSIDE that callback (wt_stop or
         * session_close during a fin=true delivery) is satisfied by
         * this very FIN — nothing later can answer it */
        es->wt_recv_drain = false;
        wt_release_if_done(conn, es);
    }
}

/* Bidi classification: WT preamble (0x41 + session id) or, on the
 * server, an H3 request stream whose buffered type bytes are replayed
 * into the frame walk. Returns false when the connection died. */
static bool bidi_classify_bytes(wtq_conn_t *conn, struct wtq_estream *es,
                                const uint8_t *data, size_t len,
                                size_t *off)
{
    while (*off < len && es->kind == ES_BTYPE && !conn->closed) {
        wtq_preamble_t pre;
        size_t c = 0;
        wtq_preamble_status_t st = wtq_preamble_dec_feed(
            &es->pre, WTQ_PREAMBLE_KIND_BIDI, data + *off, len - *off,
            &pre, &c);
        /* Buffer the consumed bytes: they are the frame-type varint if
         * this turns out to be a request stream (a type varint is at
         * most 8 bytes, so the buffer cannot overflow before the
         * decoder decides; session-id bytes past 8 are only consumed
         * on the OK path, where the buffer is discarded). */
        for (size_t i = 0; i < c && es->btype_fill < sizeof(es->btype_buf);
             i++)
            es->btype_buf[es->btype_fill++] = data[*off + i];
        *off += c;

        if (st == WTQ_PREAMBLE_NEED_MORE)
            return true;
        if (st == WTQ_PREAMBLE_OK) {
            es->btype_fill = 0;
            (void)wt_associate(conn, es, pre.session_id, true);
            /* association may have fataled (e.g. a session id that is
             * not a client-initiated bidi id -> H3_ID_ERROR); surface
             * that as a protocol error the same way the uni and request
             * paths do, so the input's non-OK return is never lost. */
            return !conn->closed;
        }
        /* UNEXPECTED: the first varint is an H3 frame type */
        if (conn->persp == WTQ_PERSPECTIVE_CLIENT) {
            /* RFC 9114 s6.1: H3 never negotiates server-initiated
             * bidi; only a WT preamble could have made this legal. */
            conn_fatal(conn, WTQ_H3_STREAM_CREATION_ERROR);
            return false;
        }
        es->kind = ES_REQUEST;
        wtq_h3_frame_dec_init(&es->frame_dec);
        uint8_t replay[sizeof(es->btype_buf)];
        uint8_t rlen = es->btype_fill;
        memcpy(replay, es->btype_buf, rlen);
        es->btype_fill = 0;
        request_stream_bytes(conn, es, replay, rlen);
        return !conn->closed;
    }
    return !conn->closed;
}

wtq_result_t wtq_conn_on_stream_bytes(wtq_conn_t *conn, wtq_estream_t *es,
                                      const uint8_t *data, size_t len,
                                      bool fin, uint64_t now_us)
{
    (void)now_us;
    if (conn->closed || es == NULL || es->kind == ES_FREE)
        return conn->closed ? WTQ_ERR_CLOSED : WTQ_ERR_INVALID_ARG;

    size_t off = 0;

    if (es->kind == ES_BTYPE) {
        if (!bidi_classify_bytes(conn, es, data, len, &off))
            return WTQ_ERR_PROTO;
        if (es->kind == ES_BTYPE) {
            /* still classifying */
            if (fin) {
                if (es->pre.state == 1) {
                    /* 0x41 seen, session id truncated */
                    conn_fatal(conn, WTQ_H3_FRAME_ERROR);
                } else if (conn->persp == WTQ_PERSPECTIVE_SERVER) {
                    /* a request stream with no complete message */
                    conn_fatal(conn, WTQ_H3_REQUEST_INCOMPLETE);
                } else {
                    conn_fatal(conn, WTQ_H3_STREAM_CREATION_ERROR);
                }
                return WTQ_ERR_PROTO;
            }
            return WTQ_OK;
        }
        /* classified: the rest of this delivery flows below */
    }

    if (es->kind == ES_CONNECT || es->kind == ES_REQUEST) {
        if (es->is_session_stream && conn->close_capsule_rx &&
            len - off > 0) {
            session_stream_poisoned(conn, es);
            return WTQ_OK;
        }
        if (len - off > 0)
            request_stream_bytes(conn, es, data + off, len - off);
        if (conn->closed)
            return WTQ_ERR_PROTO;
        if (es->kind == ES_FREE) /* poisoned mid-walk */
            return WTQ_OK;
        if (fin) {
            if (conn->parked_es == es) {
                /* A stream-layout violation is diagnosed now (same
                 * expression as request_stream_fin's truncation
                 * check); a clean FIN is held with the parked request
                 * — the deferred response still needs this stream, so
                 * the slot must survive until SETTINGS release it. */
                if (es->frame_active || es->frame_dec.hdr_bytes > 0) {
                    conn_fatal(conn, WTQ_H3_FRAME_ERROR);
                    return WTQ_ERR_PROTO;
                }
                conn->parked_fin = true;
                return WTQ_OK;
            }
            request_stream_fin(conn, es);
            if (conn->session_es == es)
                conn->session_es = NULL;
            estream_release(conn, es);
            if (conn->closed)
                return WTQ_ERR_PROTO;
        }
        return WTQ_OK;
    }

    if (es->kind == ES_TYPE && off < len) {
        /* Uni classification rides the preamble decoder: OK is a WT
         * stream; UNEXPECTED reports the wire type for H3 stream-type
         * routing (control/QPACK/push/unknown). */
        wtq_preamble_t pre;
        size_t c = 0;
        wtq_preamble_status_t st = wtq_preamble_dec_feed(
            &es->pre, WTQ_PREAMBLE_KIND_UNI, data + off, len - off, &pre,
            &c);
        off += c;
        if (st == WTQ_PREAMBLE_OK) {
            (void)wt_associate(conn, es, pre.session_id, false);
        } else if (st == WTQ_PREAMBLE_UNEXPECTED) {
            if (!classify_uni(conn, es, pre.wire_type))
                return WTQ_ERR_PROTO;
        }
        /* NEED_MORE: wait for the rest */
    }

    if (es->kind == ES_WT) {
        /* off == len on a bare FIN, where data may be NULL (never
         * compute NULL + 0) */
        wt_deliver(conn, es, off < len ? data + off : NULL, len - off,
                   fin);
        return WTQ_OK;
    }

    if (!conn->closed && es->kind == ES_CONTROL && off < len)
        control_bytes(conn, es, data + off, len - off);
    /* ES_QPACK / ES_DRAIN / still-ES_TYPE: bytes consumed and ignored */

    if (conn->closed)
        return WTQ_ERR_PROTO;

    if (fin) {
        if (es->kind == ES_CONTROL || es->kind == ES_QPACK) {
            /* Completed critical streams must never terminate. */
            conn_fatal(conn, WTQ_H3_CLOSED_CRITICAL_STREAM);
            return WTQ_ERR_PROTO;
        }
        /* ES_TYPE (incl. a FIN before or mid preamble — the session-id
         * varint counts as stream header here) and ES_DRAIN: RFC 9114
         * s6.2 — receivers MUST tolerate uni streams ending before the
         * stream header completes. A drain tombstone reaches its
         * terminal condition here. */
        estream_release(conn, es);
    }
    return WTQ_OK;
}

/*
 * Transport certainty that a stream ceased to exist WHOLE: no bytes,
 * FIN, or RESET can ever be delivered for it again (e.g. a transport
 * whose stream terminal is final with no further callback possible).
 * Absorber tombstones — a receive drain, an ES_DRAIN byte sink, a
 * dead request absorber — release immediately (their awaited peer
 * answer can never arrive). Still-LIVE WT halves close now: no
 * RESET_STREAM or STOP_SENDING code exists to report, so nothing is
 * fabricated — on_wt_stream_terminal fires instead, and ONLY when an
 * app-visible live stream still needed terminalization (halves that
 * all closed through normal events see no callback). Critical
 * streams, the CONNECT stream, and live HTTP request semantics are
 * untouched.
 */
wtq_result_t wtq_conn_on_stream_terminal(wtq_conn_t *conn,
                                         wtq_estream_t *es)
{
    if (conn == NULL || es == NULL || es->kind == ES_FREE)
        return WTQ_ERR_INVALID_ARG; /* stale input: same contract as
                                       the reset input */
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (es->kind == ES_DRAIN) {
        /* a byte sink whose bytes can never arrive again: release */
        estream_release(conn, es);
        return WTQ_OK;
    }
    if (es->kind == ES_REQUEST && es->request_dead) {
        /* dead request absorber: our refusal went out; the peer's
         * answer can never be delivered — release */
        if (conn->parked_es == es)
            parked_request_cancel(conn);
        estream_release(conn, es);
        return WTQ_OK;
    }
    if (es->kind == ES_WT) {
        /* WHOLE terminal: any still-open halves close now — no
         * RESET_STREAM or STOP_SENDING code exists to report, so the
         * app-visible outcome is exactly one terminal notification
         * (never a forged reset/stop). A stream whose halves all
         * closed through normal events (a local abort, delivered
         * FIN/reset) sees no callback: only the drain resolves. */
        bool live = es->wt_send_open || es->wt_recv_open;
        es->wt_recv_drain = false;
        es->wt_send_open = false;
        es->wt_recv_open = false;
        if (live && conn->cb.on_wt_stream_terminal != NULL)
            conn->cb.on_wt_stream_terminal(conn, es, conn->cb.ctx);
        estream_release(conn, es); /* exactly once (kind -> ES_FREE) */
        return WTQ_OK;
    }
    /* criticals, the CONNECT stream, live requests: their closing
     * events (or the connection terminal) own the app-facing
     * semantics — untouched */
    return WTQ_OK;
}

wtq_result_t wtq_conn_on_stream_reset(wtq_conn_t *conn, wtq_estream_t *es,
                                      uint64_t quic_err, uint64_t now_us)
{
    (void)quic_err;
    (void)now_us;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (es == NULL || es->kind == ES_FREE)
        return WTQ_ERR_INVALID_ARG;

    if (es->kind == ES_CONTROL || es->kind == ES_QPACK) {
        conn_fatal(conn, WTQ_H3_CLOSED_CRITICAL_STREAM);
        return WTQ_OK;
    }
    if (es->is_session_stream) {
        /* abrupt CONNECT-stream close: the session terminates (s6) */
        if (conn->session_es == es)
            conn->session_es = NULL;
        estream_release(conn, es);
        session_closed(conn, 0, NULL, 0, false);
        return WTQ_OK;
    }
    if (es->kind == ES_WT) {
        if (es->wt_recv_drain) {
            /* the RESET answering our STOP_SENDING: the receive side
             * already closed once — absorb without a callback */
            es->wt_recv_drain = false;
            wt_release_if_done(conn, es);
            return WTQ_OK;
        }
        /* s4.4: in-range codes map to the app error; anything else is
         * delivered as a reset with no application error code (0).
         * A reset is a receive-side event: a bidi stream's send side
         * stays usable, and the estream survives at least until the
         * callback returns. */
        uint32_t app = 0;
        (void)wtq_h3_error_to_app(quic_err, &app);
        es->wt_recv_open = false;
        if (conn->cb.on_wt_stream_reset != NULL)
            conn->cb.on_wt_stream_reset(conn, es, app, conn->cb.ctx);
        wt_release_if_done(conn, es);
        return WTQ_OK;
    }
    if (es->kind == ES_CONNECT && conn->sess_state == SS_SENT &&
        !conn->session_established)
        session_failed(conn, WTQ_SESSION_FAIL_BAD_RESPONSE);
    /* ES_REQUEST resets pre-establishment leave no session state;
     * ES_BTYPE / mid-preamble resets release silently */
    if (conn->parked_es == es) {
        /* the deferred request died with its stream */
        parked_request_cancel(conn);
    }
    estream_release(conn, es);
    return WTQ_OK;
}

void wtq_conn_on_conn_closed(wtq_conn_t *conn, uint64_t err, bool remote,
                             uint64_t now_us)
{
    (void)now_us;
    if (conn->closed)
        return;
    /* Synthesized fallback: the backend never supplied detail, so the
     * normalized view comes from the terminal input itself. Latched
     * before any callback so the record is readable inside them. */
    conn_latch_error(conn,
                     remote ? WTQ_ERR_KIND_QUIC_APP : WTQ_ERR_KIND_LOCAL,
                     err, WTQ_ERRDOM_NONE, 0);
    conn->closed = true;
    conn->close_code = err;
    session_conn_lost(conn);
    if (conn->cb.on_conn_error != NULL)
        conn->cb.on_conn_error(conn, err, conn->cb.ctx);
}

void wtq_conn_set_transport_error(wtq_conn_t *conn,
                                  const wtq_transport_error_t *e)
{
    if (conn == NULL || e == NULL ||
        e->struct_size < offsetof(wtq_transport_error_t, kind) +
                             sizeof(e->kind))
        return;
    if (conn->transport_error_set)
        return; /* write-once: the first causal error already won */
    /* Read only the fields the caller declared; missing ones are zero. */
    wtq_transport_error_t rec;
    memset(&rec, 0, sizeof(rec));
    size_t n = e->struct_size < sizeof(rec) ? e->struct_size : sizeof(rec);
    memcpy(&rec, e, n);
    /* A non-error record is ignored: it must never consume the latch
     * and suppress later synthesis while reporting no error. */
    if (rec.kind != WTQ_ERR_KIND_QUIC_TRANSPORT &&
        rec.kind != WTQ_ERR_KIND_QUIC_APP &&
        rec.kind != WTQ_ERR_KIND_LOCAL)
        return;
    conn_latch_error(conn, rec.kind, rec.quic_code, rec.native_domain,
                     rec.native_code);
}

const wtq_transport_error_t *wtq_conn_transport_error(const wtq_conn_t *conn)
{
    return conn->transport_error_set ? &conn->transport_error : NULL;
}

void wtq_conn_seal_transport_error(wtq_conn_t *conn)
{
    /* Explicit NONE: the session ended without a transport-level cause.
     * Write-once makes every later engine/backend write a no-op, so the
     * value observed in the terminal callback can never change. */
    conn_latch_error(conn, WTQ_ERR_KIND_NONE, 0, WTQ_ERRDOM_NONE, 0);
}

bool wtq_conn_peer_settings_received(const wtq_conn_t *conn)
{
    return conn->settings_received;
}

bool wtq_conn_peer_supports_wt(const wtq_conn_t *conn)
{
    return conn->settings_received && conn->wt_supported;
}

const wtq_h3_settings_t *wtq_conn_peer_settings(const wtq_conn_t *conn)
{
    return conn->settings_received ? &conn->peer_settings : NULL;
}

bool wtq_conn_is_closed(const wtq_conn_t *conn)
{
    return conn->closed;
}

uint64_t wtq_conn_close_code(const wtq_conn_t *conn)
{
    return conn->close_code;
}

/* --- request/CONNECT stream frame handling ----------------------------- */

/* Frame types that are control-stream-only: never legal on a request
 * stream (RFC 9114 Table 1; sequence violations are FRAME_UNEXPECTED
 * per s4.1). */
static bool request_frame_forbidden(uint64_t type)
{
    switch (type) {
    case 0x00: /* DATA before HEADERS handled by caller ordering */
        return false;
    case 0x03: /* CANCEL_PUSH */
    case 0x04: /* SETTINGS */
    case 0x05: /* PUSH_PROMISE (client-bound only, and we never push) */
    case 0x07: /* GOAWAY */
    case 0x0d: /* MAX_PUSH_ID */
    case 0x02:
    case 0x06:
    case 0x08:
    case 0x09: /* reserved */
        return true;
    default:
        return false;
    }
}

static void server_send_response(wtq_conn_t *conn, wtq_dstream_t *ds,
                                 uint16_t status,
                                 const wtq_sf_str_t *selected)
{
    /* Every configured subprotocol was round-tripped through exactly
     * this buffer size at configuration time (protocol_check), so
     * the encode below cannot fail on capacity. */
    uint8_t section[WTQ_CONN_SETTINGS_CAP];
    size_t slen = 0;

    if (wtq_connect_encode_response(status, selected, section,
                                    sizeof(section), &slen) !=
        WTQ_CONNECT_OK) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return;
    }
    uint8_t hdr[16];
    size_t hl = 0;
    (void)wtq_h3_frame_encode_header(WTQ_H3_FRAME_HEADERS, slen, hdr,
                                     sizeof(hdr), &hl);
    if (conn->ops.send(conn->drv, ds, hdr, hl, false) != WTQ_OK ||
        conn->ops.send(conn->drv, ds, section, slen, false) != WTQ_OK)
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
}

/*
 * ESTABLISHED requires BOTH latches, in either arrival order: a parked
 * successful response AND the CONNECT stream's native id (the session id
 * and the RFC 9297 datagram association derive from it). Called from the
 * response path and from wtq_conn_on_stream_native_id; fires exactly once
 * because session_established leaves SS_SENT.
 */
static void client_maybe_establish(wtq_conn_t *conn, struct wtq_estream *es)
{
    if (conn->sess_state != SS_SENT || !conn->client_response_ok ||
        es->native_id_pending)
        return;
    const char *sel = "";
    size_t sel_len = 0;
    if (conn->client_selected_offer >= 0) {
        sel = conn->offered[conn->client_selected_offer].data;
        sel_len = conn->offered[conn->client_selected_offer].len;
    }
    session_established(conn, es, sel, sel_len);
}

/* A complete response HEADERS payload arrived on the CONNECT stream. */
static void client_response_done(wtq_conn_t *conn, struct wtq_estream *es)
{
    wtq_connect_resp_t resp;
    char scratch[512];
    wtq_connect_status_t st = wtq_connect_decode_response(
        es->set_buf, es->set_fill, &CONN_STRICT_OPTS, &resp, scratch,
        sizeof(scratch));

    if (st != WTQ_CONNECT_OK) {
        session_failed(conn, WTQ_SESSION_FAIL_BAD_RESPONSE);
        conn_fatal(conn, WTQ_H3_MESSAGE_ERROR);
        return;
    }

    if (!wtq_connect_status_is_success(resp.status)) {
        conn->sess_state = SS_REJECTED;
        if (conn->cb.on_session_rejected != NULL)
            conn->cb.on_session_rejected(conn, resp.status, conn->cb.ctx);
        return;
    }

    /* Subprotocol validation against our recorded offer. The selection is
     * PARKED as an index into offered[] — resp.protocol points into the
     * stack scratch above and dies with this frame, while offered_buf
     * persists and holds the byte-identical value the match required. */
    int16_t selected = -1;
    if (resp.has_protocol) {
        if (conn->offered_count == 0) {
            /* a selection we never offered (draft: client error) */
            session_failed(conn, WTQ_SESSION_FAIL_NO_PROTOCOL);
            return;
        }
        for (size_t i = 0; i < conn->offered_count; i++)
            if (conn->offered[i].len == resp.protocol.len &&
                memcmp(conn->offered[i].data, resp.protocol.data,
                       resp.protocol.len) == 0) {
                selected = (int16_t)i;
                break;
            }
        if (selected < 0) {
            session_failed(conn, WTQ_SESSION_FAIL_NO_PROTOCOL);
            return;
        }
    }
    if (conn->require_protocol && selected < 0) {
        session_failed(conn, WTQ_SESSION_FAIL_NO_PROTOCOL);
        return;
    }

    conn->client_response_ok = true;
    conn->client_selected_offer = selected;
    client_maybe_establish(conn, es);
}

/* Refuse a request stream without an HTTP response: reset the response
 * direction (also the RESET_STREAM that answers a peer STOP_SENDING),
 * stop reading the request, and leave the estream as a dead absorber —
 * late bytes drain harmlessly and the peer's eventual FIN/RESET frees
 * the slot (through detachment). Never a connection error. */
static void request_stream_refuse_err(wtq_conn_t *conn,
                                      struct wtq_estream *es,
                                      uint64_t h3_err)
{
    shutdown_raw(conn, es->ds, true, true, h3_err);
    es->request_dead = true;
}

static void request_stream_refuse(wtq_conn_t *conn,
                                  struct wtq_estream *es)
{
    request_stream_refuse_err(conn, es, WTQ_H3_REQUEST_REJECTED);
}

/*
 * Kill a request/CONNECT stream with a stream error, never a connection
 * error. A parked request dies with it. When the stream carries the
 * established session, the session terminates uncleanly: the estream is
 * released through detachment FIRST so no late transport event can
 * reach it, then the single on_session_closed fires (session_closed's
 * state guard makes it exactly once).
 */
static void request_stream_fail(wtq_conn_t *conn, struct wtq_estream *es,
                                uint64_t h3_err)
{
    request_stream_refuse_err(conn, es, h3_err);
    if (conn->parked_es == es)
        parked_request_cancel(conn);
    if (es->is_session_stream) {
        if (conn->session_es == es)
            conn->session_es = NULL;
        estream_release(conn, es);
        session_closed(conn, 0, NULL, 0, false);
    }
}

/* The single place parked-request state is dropped. */
static void parked_request_cancel(wtq_conn_t *conn)
{
    conn->parked_es = NULL;
    conn->parked_fill = 0;
    conn->parked_fin = false;
}

/* A complete request HEADERS payload arrived on a server stream. */
static void server_request_done(wtq_conn_t *conn, struct wtq_estream *es)
{
    wtq_connect_req_t req;
    wtq_sf_str_t offered[WTQ_CONN_MAX_OFFERED];
    size_t offered_count = 0;
    char scratch[512];
    /* Decode under OUR profile: the compat server tolerates the bare
     * "webtransport" token; the current server (STRICT) rejects it as
     * NOT_WEBTRANSPORT. The cross-profile token is rejected below. */
    const bool compat = conn->wt_profile == WTQ_H3_WT_PROFILE_D13_14_COMPAT;
    const wtq_connect_opts_t *opts =
        compat ? &CONN_SERVER_COMPAT_OPTS : &CONN_STRICT_OPTS;
    wtq_connect_status_t st = wtq_connect_decode_request(
        es->set_buf, es->set_fill, opts, &req, offered,
        WTQ_CONN_MAX_OFFERED, &offered_count, scratch, sizeof(scratch));

    if (st == WTQ_CONNECT_NOT_WEBTRANSPORT) {
        /* A valid request that simply is not WebTransport (a GET, a
         * plain CONNECT, another extended protocol). The peer did
         * nothing wrong: answer with one generic 400 and let the
         * connection live. Sent before any path lookup or subprotocol
         * selection, so it reveals nothing about what this server
         * serves. */
        server_send_response(conn, es->ds, 400, NULL);
        es->request_dead = true;
        return;
    }
    if (st == WTQ_CONNECT_BUFFER) {
        /* Not the peer's fault: the request outgrew a LOCAL decode
         * limit (field count or scratch). Same stream-local treatment
         * as an oversized HEADERS frame. */
        request_stream_refuse_err(conn, es, WTQ_H3_EXCESSIVE_LOAD);
        return;
    }
    if (st != WTQ_CONNECT_OK) {
        /* RFC 9114 s4.1.2: a malformed message is a STREAM error, not a
         * connection error. */
        request_stream_refuse_err(conn, es, WTQ_H3_MESSAGE_ERROR);
        return;
    }

    /* Profile symmetry: honour ONLY our profile's extended-CONNECT
     * :protocol token — a compat server accepts the bare "webtransport"
     * token, a current server accepts "webtransport-h3". req.legacy_protocol
     * records which token matched; a mismatch is answered like any other
     * non-WebTransport request (a generic 400, connection lives), so the
     * server never emits one profile's SETTINGS while honouring the other's
     * CONNECT token. (STRICT already rejects the bare token before here, so
     * for the current profile legacy_protocol is always false and this never
     * false-rejects.) */
    if (req.legacy_protocol != compat) {
        server_send_response(conn, es->ds, 400, NULL);
        es->request_dead = true;
        return;
    }

    /* One WT session per connection: reset extras, never respond. */
    if (conn->session_established) {
        request_stream_refuse(conn, es);
        return;
    }

    /* A server must not process WT requests until the client's SETTINGS
     * arrive (draft-15 s3.1) — and must not reveal path or subprotocol
     * policy before then, so this gate precedes lookup. Exactly one
     * completed request is parked (one WT session per connection);
     * extras are refused generically. */
    if (!conn->settings_received) {
        if (conn->parked_es != NULL) {
            /* over the one-request bound: a generic stream refusal —
             * an HTTP response would itself be processing the request
             * before SETTINGS */
            request_stream_refuse(conn, es);
            return;
        }
        conn->parked_es = es;
        conn->parked_fill = es->set_fill;
        memcpy(conn->parked_buf, es->set_buf, es->set_fill);
        return;
    }
    if (!conn->wt_supported) {
        server_send_response(conn, es->ds, 400, NULL);
        es->request_dead = true;
        return;
    }

    /* Path lookup (exact match). */
    size_t p = conn->path_count;
    for (size_t i = 0; i < conn->path_count; i++)
        if (conn->paths[i].path_len == req.path_len &&
            memcmp(conn->paths[i].path, req.path, req.path_len) == 0) {
            p = i;
            break;
        }
    if (p == conn->path_count) {
        server_send_response(conn, es->ds, 404, NULL);
        es->request_dead = true;
        return;
    }

    /* Subprotocol selection: first client-offered supported one. */
    const wtq_sf_str_t *selected = NULL;
    size_t idx = 0;
    if (offered_count > 0 &&
        wtq_connect_select_protocol(offered, offered_count,
                                    conn->paths[p].protos,
                                    conn->paths[p].proto_count, &idx) ==
            WTQ_CONNECT_OK)
        selected = &offered[idx];
    if (conn->paths[p].require && selected == NULL) {
        server_send_response(conn, es->ds, 400, NULL);
        es->request_dead = true;
        return;
    }

    /* Accept. */
    if (req.path_len <= sizeof(conn->req_path)) {
        memcpy(conn->req_path, req.path, req.path_len);
        conn->req_path_len = req.path_len;
    }
    if (req.authority_len <= sizeof(conn->req_auth)) {
        memcpy(conn->req_auth, req.authority, req.authority_len);
        conn->req_auth_len = req.authority_len;
    }
    server_send_response(conn, es->ds, 200, selected);
    if (!conn->closed)
        session_established(conn, es, selected ? selected->data : "",
                            selected ? selected->len : 0);
}

/* Kill the session stream after post-CLOSE data (draft-15 s6: "the
 * stream MUST be reset with code H3_MESSAGE_ERROR"). Not a connection
 * error; the session is already terminated. */
static void session_stream_poisoned(wtq_conn_t *conn,
                                    struct wtq_estream *es)
{
    shutdown_raw(conn, es->ds, true, true, WTQ_H3_MESSAGE_ERROR);
    if (conn->session_es == es)
        conn->session_es = NULL;
    /* release THROUGH detachment: post-CLOSE in-flight bytes may still
     * be delivered against this stream, and must reach nobody */
    estream_release(conn, es);
}

/* Capsule protocol over the session stream's DATA payload bytes (the
 * concatenation across DATA frames — capsules may span frames). */
static void session_capsule_bytes(wtq_conn_t *conn,
                                  struct wtq_estream *es,
                                  const uint8_t *data, size_t len)
{
    if (conn->close_capsule_rx) {
        session_stream_poisoned(conn, es);
        return;
    }

    size_t off = 0;
    while (off < len && !conn->closed) {
        /*
         * Re-read the terminal gate on EVERY capsule: the session may
         * have been closed locally between deliveries (so a capsule
         * that started before the close completes after it), or by a
         * callback fired for an earlier capsule in this very frame.
         * SS_CLOSED is the gate — close_capsule_rx means something
         * else entirely (the PEER's CLOSE arrived).
         */
        bool terminal = (conn->sess_state == SS_CLOSED);
        wtq_capsule_t cap;
        size_t c = 0;
        wtq_capsule_status_t st = wtq_capsule_dec_feed(
            &conn->caps_dec, data + off, len - off, &cap, &c);
        off += c;
        if (st == WTQ_CAPSULE_NEED_MORE)
            return;
        if (st != WTQ_CAPSULE_OK) {
            /* MALFORMED (bad CLOSE/DRAIN shape) or decoder failure. */
            if (terminal) {
                /* the session is already gone: contain it to the
                 * stream (RFC 9114 s4.1.2) — no connection error */
                request_stream_fail(conn, es, WTQ_H3_MESSAGE_ERROR);
                return;
            }
            /* a content violation on a live CONNECT stream */
            conn_fatal(conn, WTQ_H3_MESSAGE_ERROR);
            return;
        }
        if (terminal) {
            /*
             * Post-terminal capsules are consumed silently: no
             * callbacks, no state changes, no connection error. A
             * peer CLOSE is still RECORDED so its trailing bytes are
             * poisoned and its FIN is accepted quietly.
             */
            if (cap.kind == WTQ_CAPSULE_KIND_CLOSE) {
                conn->close_capsule_rx = true;
                if (off < len) {
                    session_stream_poisoned(conn, es);
                    return;
                }
            }
            continue;
        }
        switch (cap.kind) {
        case WTQ_CAPSULE_KIND_CLOSE:
            conn->close_capsule_rx = true;
            session_closed(conn, cap.close_code, cap.reason,
                           cap.reason_len, true);
            if (off < len) {
                /* bytes after the CLOSE capsule in this delivery */
                session_stream_poisoned(conn, es);
                return;
            }
            break;
        case WTQ_CAPSULE_KIND_DRAIN:
            if (!conn->drain_rx) {
                conn->drain_rx = true;
                if (conn->sess_state == SS_ESTABLISHED)
                    conn->sess_state = SS_DRAINING;
                if (conn->cb.on_session_draining != NULL)
                    conn->cb.on_session_draining(conn, conn->cb.ctx);
            }
            break;
        default:
            break; /* unknown capsules: payload already skipped */
        }
    }
}

/* Frame walk for CONNECT/request streams. */
static void request_stream_bytes(wtq_conn_t *conn, struct wtq_estream *es,
                                 const uint8_t *data, size_t len)
{
    size_t off = 0;

    /* A refused request stream is over: everything the peer keeps
     * sending on it — this delivery's tail and every later one — is
     * discarded WITHOUT frame-sequence rules. Anything queued behind a
     * rejection (a forbidden frame, trailers) was written before the
     * peer could see the refusal, so it must not become an error. The
     * slot is released by the FIN/RESET path, through detachment. */
    if (es->request_dead)
        return;

    while (off < len && !conn->closed) {
        if (!es->frame_active) {
            wtq_h3_frame_t hdr;
            size_t c = 0;
            wtq_h3_frame_status_t st = wtq_h3_frame_dec_feed(
                &es->frame_dec, data + off, len - off, &hdr, &c);
            off += c;
            if (st == WTQ_H3_FRAME_NEED_MORE)
                return;

            es->frame_type = hdr.type;
            es->frame_remaining = hdr.length;
            es->frame_active = true;
            es->set_fill = 0;

            if (request_frame_forbidden(hdr.type)) {
                conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                return;
            }
            if (hdr.type == WTQ_H3_FRAME_HEADERS) {
                /* RFC 9114 s4.1: at most one trailing field section
                 * after the initial one. A third HEADERS is a frame
                 * SEQUENCE violation — a connection error. */
                if (es->trailers_done) {
                    conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                    return;
                }
                if (hdr.length > WTQ_CONN_SETTINGS_CAP) {
                    /* Too large to decode. Contained on a server
                     * request stream and on any TRAILER section (a
                     * local limit, so H3_EXCESSIVE_LOAD, and no
                     * response can be produced from an unparsed
                     * section). An oversized initial response on the
                     * client's CONNECT stream stays fatal. */
                    if (es->kind == ES_REQUEST || es->headers_done) {
                        request_stream_fail(conn, es,
                                            WTQ_H3_EXCESSIVE_LOAD);
                        return;
                    }
                    conn_fatal(conn, WTQ_H3_EXCESSIVE_LOAD);
                    return;
                }
                es->frame_kind = CF_SETTINGS; /* accumulate */
            } else if (hdr.type == WTQ_H3_FRAME_DATA) {
                if (!es->headers_done || es->trailers_done) {
                    /* a request/response starts with HEADERS and no
                     * DATA may follow the trailers (RFC 9114 s4.1:
                     * invalid frame sequence) */
                    conn_fatal(conn, WTQ_H3_FRAME_UNEXPECTED);
                    return;
                }
                if (conn->parked_es == es) {
                    /* Capsule bytes for a request the engine may not
                     * process yet (draft-15 s3.1): refuse the stream
                     * outright rather than buffer or silently drop
                     * them. Not a connection error, and no policy is
                     * revealed. */
                    request_stream_refuse(conn, es);
                    parked_request_cancel(conn);
                    return;
                }
                /* session stream: DATA carries the capsule protocol;
                 * other request streams (rejected responses' bodies)
                 * are skipped */
                es->frame_kind = es->is_session_stream ? CF_CAPSULE
                                                       : CF_SKIP;
            } else {
                es->frame_kind = CF_SKIP; /* unknown/grease */
            }
        }

        size_t avail = len - off;
        size_t take = es->frame_remaining < (uint64_t)avail
                          ? (size_t)es->frame_remaining
                          : avail;
        if (es->frame_kind == CF_SETTINGS && take > 0) {
            memcpy(es->set_buf + es->set_fill, data + off, take);
            es->set_fill = (uint16_t)(es->set_fill + take);
        } else if (es->frame_kind == CF_CAPSULE && take > 0) {
            session_capsule_bytes(conn, es, data + off, take);
            if (conn->closed || es->kind == ES_FREE)
                return;
        }
        off += take;
        es->frame_remaining -= take;

        if (es->frame_remaining == 0 && es->frame_active) {
            es->frame_active = false;
            if (es->frame_type == WTQ_H3_FRAME_HEADERS) {
                if (!es->headers_done) {
                    es->headers_done = true;
                    if (es->kind == ES_CONNECT)
                        client_response_done(conn, es);
                    else
                        server_request_done(conn, es);
                } else {
                    /* The one permitted trailing field section. It is
                     * validated (no pseudo-headers, RFC 9114 s4.3) and
                     * then discarded: wtquic exposes no trailer API. A
                     * PARKED request's bytes live in conn->parked_buf,
                     * so reusing set_buf here is safe. */
                    char scratch[WTQ_CONN_SETTINGS_CAP];

                    es->trailers_done = true;
                    wtq_connect_status_t tst =
                        wtq_connect_validate_trailers(es->set_buf,
                                                      es->set_fill,
                                                      scratch,
                                                      sizeof(scratch));
                    es->set_fill = 0;
                    if (tst == WTQ_CONNECT_BUFFER) {
                        request_stream_fail(conn, es,
                                            WTQ_H3_EXCESSIVE_LOAD);
                        return;
                    }
                    if (tst != WTQ_CONNECT_OK) {
                        request_stream_fail(conn, es,
                                            WTQ_H3_MESSAGE_ERROR);
                        return;
                    }
                }
                /* A refusal ends the walk: the rest of this delivery is
                 * not ours to interpret. (A PARKED request keeps
                 * walking — that is how DATA behind it is caught and
                 * the stream refused.) */
                if (conn->closed || es->kind == ES_FREE ||
                    es->request_dead)
                    return;
            }
        }
    }
}

/* FIN completion for CONNECT/request streams. A FIN is only clean when
 * no frame header is mid-parse and no frame payload is outstanding
 * (RFC 9114 s7.1: a truncated last frame is H3_FRAME_ERROR) and, on a
 * server request stream, a complete HEADERS arrived (s4.1: a request
 * ending without a complete message is H3_REQUEST_INCOMPLETE). Streams
 * we already rejected (request_dead) are exempt: we sent reset/stop, so
 * however the peer's half ends carries no protocol meaning. */
static void request_stream_fin(wtq_conn_t *conn, struct wtq_estream *es)
{
    if (es->request_dead)
        return;

    /* frame_dec resets itself after each completed header, so nonzero
     * hdr_bytes means a header is mid-parse; frame_active at rest means
     * declared payload is still outstanding (zero-length frames close
     * within the delivery that completes their header). */
    bool truncated = es->frame_active || es->frame_dec.hdr_bytes > 0;

    if (es->is_session_stream) {
        if (conn->session_es == es)
            conn->session_es = NULL;
        if (truncated) {
            /* conn_fatal delivers the unclean terminal callback */
            conn_fatal(conn, WTQ_H3_FRAME_ERROR);
            return;
        }
        if (conn->close_capsule_rx)
            return; /* the FIN the CLOSE capsule promised */
        if (conn->caps_dec.state == 1 ||
            conn->caps_dec.hdr.hdr_bytes > 0) {
            /* every DATA frame completed, but the capsule inside is
             * truncated: a content violation */
            if (conn->sess_state == SS_CLOSED) {
                /* the session already ended (locally): contain the
                 * violation to the stream, exactly as the post-close
                 * capsule path does. Only REFUSE here — our caller
                 * runs estream_release() right after, so releasing
                 * again would detach the slot twice. */
                request_stream_refuse_err(conn, es,
                                          WTQ_H3_MESSAGE_ERROR);
                return;
            }
            conn_fatal(conn, WTQ_H3_MESSAGE_ERROR);
            return;
        }
        /* draft-15 s6: clean FIN without a capsule == CLOSE(0, "") */
        session_closed(conn, 0, NULL, 0, true);
        return;
    }

    bool connect_pending = es->kind == ES_CONNECT &&
                           !conn->session_established &&
                           conn->sess_state == SS_SENT;

    if (truncated) {
        if (connect_pending)
            session_failed(conn, WTQ_SESSION_FAIL_BAD_RESPONSE);
        conn_fatal(conn, WTQ_H3_FRAME_ERROR);
        return;
    }
    if (es->kind == ES_REQUEST && !es->headers_done) {
        conn_fatal(conn, WTQ_H3_REQUEST_INCOMPLETE);
        return;
    }
    if (connect_pending) {
        /* clean FIN, but the response never arrived */
        session_failed(conn, WTQ_SESSION_FAIL_BAD_RESPONSE);
    }
}

/* --- public CONNECT surface -------------------------------------------- */

wtq_result_t wtq_conn_client_connect(wtq_conn_t *conn,
                                     const wtq_client_connect_cfg_t *cfg)
{
    if (conn == NULL || cfg == NULL || cfg->authority == NULL ||
        cfg->path == NULL || cfg->protocol_count > WTQ_CONN_MAX_OFFERED ||
        (cfg->protocol_count > 0 && cfg->protocols == NULL))
        return WTQ_ERR_INVALID_ARG;
    for (size_t i = 0; i < cfg->protocol_count; i++)
        if (cfg->protocols[i] == NULL)
            return WTQ_ERR_INVALID_ARG;
    if (conn->persp != WTQ_PERSPECTIVE_CLIENT)
        return WTQ_ERR_STATE;
    if (conn->closed || conn->sess_state != SS_IDLE)
        return WTQ_ERR_STATE;
    if (cfg->webtransport_profile != WTQ_H3_WT_PROFILE_CURRENT &&
        cfg->webtransport_profile != WTQ_H3_WT_PROFILE_D13_14_COMPAT)
        return WTQ_ERR_INVALID_ARG;
    /*
     * The requested profile stays LOCAL through preflight — it is
     * committed to conn->wt_profile only in the committed block below,
     * after every fallible check has passed, so a connect that fails in
     * preflight (INVALID_ARG / TOO_LARGE) has ZERO effect and cannot
     * poison a later start/connect into emitting compat SETTINGS.
     *
     * A non-default (compat) profile requested after the client already
     * started — SETTINGS are already on the wire under the committed
     * profile — cannot be honoured: reject with WTQ_ERR_STATE (this
     * check reads but never writes conn state). A current-profile
     * request after start stays valid (it matches what was sent).
     */
    wtq_h3_wt_profile_t req_profile =
        (wtq_h3_wt_profile_t)cfg->webtransport_profile;
    if (conn->started && req_profile != conn->wt_profile)
        return WTQ_ERR_STATE;

    /*
     * PREFLIGHT, before a single byte of connection state changes.
     *
     * Every offer must survive a response round-trip (the server will
     * echo one back and we must be able to report it), and the COMPLETE
     * generated CONNECT — authority, path, origin, every offer, all
     * escaping — must decode through this engine's own bounded scratch.
     * A capacity failure is WTQ_ERR_TOO_LARGE, never INVALID_ARG.
     *
     * The 512-byte bound is this engine's receive capacity, not a
     * protocol conformance limit; another implementation might accept a
     * larger section. We refuse to emit what we could not ourselves
     * read back.
     */
    size_t buf_off = 0;
    wtq_sf_str_t offer_spans[WTQ_CONN_MAX_OFFERED];
    for (size_t i = 0; i < cfg->protocol_count; i++) {
        size_t plen = strlen(cfg->protocols[i]);
        /* malformed content and capacity exhaustion are different
         * failures and must not be conflated */
        wtq_result_t prc = protocol_check(cfg->protocols[i], plen);
        if (prc != WTQ_OK)
            return prc;
        if (buf_off + plen > sizeof(conn->offered_buf))
            return WTQ_ERR_TOO_LARGE;
        offer_spans[i].data = cfg->protocols[i];
        offer_spans[i].len = plen;
        buf_off += plen;
    }

    /* The REQUESTED profile (still local — not yet committed) selects
     * the extended-CONNECT :protocol token and the readback options. */
    const bool compat = req_profile == WTQ_H3_WT_PROFILE_D13_14_COMPAT;
    const char *proto_tok = compat ? WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY
                                   : WTQ_CONNECT_PROTOCOL_TOKEN;
    const size_t proto_tok_len =
        compat ? sizeof(WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY) - 1
               : sizeof(WTQ_CONNECT_PROTOCOL_TOKEN) - 1;

    uint8_t section[sizeof(conn->connect_section)];
    size_t slen = 0;
    wtq_connect_status_t st = wtq_connect_encode_request_ex(
        cfg->authority, strlen(cfg->authority), cfg->path,
        strlen(cfg->path), cfg->origin,
        cfg->origin != NULL ? strlen(cfg->origin) : 0, offer_spans,
        cfg->protocol_count, proto_tok, proto_tok_len, section,
        sizeof(section), &slen);
    if (st == WTQ_CONNECT_BUFFER)
        return WTQ_ERR_TOO_LARGE;
    if (st != WTQ_CONNECT_OK)
        return WTQ_ERR_INVALID_ARG;
    if (slen > WTQ_CONN_SETTINGS_CAP)
        return WTQ_ERR_TOO_LARGE;

    /* Decode the request we just built to prove it survives THIS engine's
     * bounded scratch. For the compat profile the readback must accept
     * the bare "webtransport" token — this is a LOCAL capacity/readback
     * check of our own bytes, NOT server acceptance policy (inbound
     * requests are still decoded strictly at the server path). */
    {
        static const wtq_connect_opts_t CONN_READBACK_LEGACY_OPTS = {
            false, true };
        const wtq_connect_opts_t *rb_opts =
            compat ? &CONN_READBACK_LEGACY_OPTS : &CONN_STRICT_OPTS;
        wtq_connect_req_t rq;
        wtq_sf_str_t got[WTQ_CONN_MAX_OFFERED];
        size_t got_count = 0;
        char scratch[WTQ_CONN_SETTINGS_CAP];
        wtq_connect_status_t dst = wtq_connect_decode_request(
            section, slen, rb_opts, &rq, got,
            WTQ_CONN_MAX_OFFERED, &got_count, scratch, sizeof(scratch));

        if (dst == WTQ_CONNECT_BUFFER)
            return WTQ_ERR_TOO_LARGE;
        if (dst != WTQ_CONNECT_OK)
            return WTQ_ERR_INVALID_ARG;
        /* the offer list must come back whole and byte-exact */
        if (got_count != cfg->protocol_count)
            return WTQ_ERR_TOO_LARGE;
        for (size_t i = 0; i < got_count; i++)
            if (got[i].len != offer_spans[i].len ||
                memcmp(got[i].data, offer_spans[i].data,
                       got[i].len) != 0)
                return WTQ_ERR_TOO_LARGE;
    }

    /* Committed: every fallible check passed. Commit the profile HERE —
     * before the CONNECT section is stored/sent and before start can
     * emit SETTINGS — so a failed preflight above left it untouched. */
    conn->wt_profile = req_profile;

    /* Copy the offer into connection-owned storage (needed later to
     * validate the server's WT-Protocol pick). */
    buf_off = 0;
    for (size_t i = 0; i < cfg->protocol_count; i++) {
        size_t plen = offer_spans[i].len;
        memcpy(conn->offered_buf + buf_off, cfg->protocols[i], plen);
        conn->offered[i].data = conn->offered_buf + buf_off;
        conn->offered[i].len = plen;
        buf_off += plen;
    }
    conn->offered_count = cfg->protocol_count;
    conn->require_protocol = cfg->require_protocol;
    memcpy(conn->connect_section, section, slen);
    conn->connect_section_len = slen;

    conn->client_response_ok = false;
    conn->client_selected_offer = -1;
    conn->sess_state = SS_PENDING;
    if (conn->settings_received) {
        if (!conn->wt_supported)
            session_failed(conn, WTQ_SESSION_FAIL_NO_WT_SUPPORT);
        else
            client_send_connect(conn);
    }
    return WTQ_OK;
}

wtq_result_t wtq_conn_server_set_paths(wtq_conn_t *conn,
                                       const wtq_server_path_cfg_t *paths,
                                       size_t count)
{
    if (conn == NULL || (count > 0 && paths == NULL) ||
        count > WTQ_CONN_MAX_PATHS)
        return WTQ_ERR_INVALID_ARG;
    if (conn->persp != WTQ_PERSPECTIVE_SERVER)
        return WTQ_ERR_STATE;

    /* Validate the whole table before copying anything: conn->paths is
     * written in-place, and a reject halfway through must not leave a
     * half-updated table behind. The protocol_count bound must be
     * checked here, before any protocols[j] access — an oversized count
     * would otherwise walk past the caller's array. */
    for (size_t i = 0; i < count; i++) {
        if (paths[i].path == NULL ||
            (paths[i].protocol_count > 0 && paths[i].protocols == NULL))
            return WTQ_ERR_INVALID_ARG;
        size_t plen = strlen(paths[i].path);
        if (plen == 0 || plen > sizeof(conn->paths[i].path) ||
            paths[i].protocol_count > WTQ_CONN_MAX_OFFERED)
            return WTQ_ERR_TOO_LARGE;
        /* A policy this engine could not honour must be refused HERE,
         * never accepted and then failed after a 200 went out. Exactly
         * the rules a backend applies at listener configuration. */
        wtq_result_t prc =
            wtq_conn_validate_protocols(paths[i].protocols,
                                        paths[i].protocol_count);
        if (prc != WTQ_OK)
            return prc;
    }

    for (size_t i = 0; i < count; i++) {
        size_t plen = strlen(paths[i].path);
        memcpy(conn->paths[i].path, paths[i].path, plen);
        conn->paths[i].path_len = plen;
        conn->paths[i].require = paths[i].require_protocol;
        size_t buf_off = 0;
        for (size_t j = 0; j < paths[i].protocol_count; j++) {
            size_t sl = strlen(paths[i].protocols[j]);
            memcpy(conn->paths[i].proto_buf + buf_off,
                   paths[i].protocols[j], sl);
            conn->paths[i].protos[j].data =
                conn->paths[i].proto_buf + buf_off;
            conn->paths[i].protos[j].len = sl;
            buf_off += sl;
        }
        conn->paths[i].proto_count = paths[i].protocol_count;
    }
    conn->path_count = count;
    return WTQ_OK;
}

wtq_result_t wtq_conn_on_peer_bidi_opened(wtq_conn_t *conn,
                                          wtq_dstream_t *ds, uint64_t id,
                                          wtq_estream_t **ectx_out)
{
    *ectx_out = NULL;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    wtq_result_t lrc = conn_open_locals_if_deferred(conn);
    if (lrc != WTQ_OK)
        return lrc;

    /* Classification is deferred to the first bytes: a 0x41 WT
     * preamble joins the session on either perspective; anything else
     * is a request stream (server) or a protocol error (client). */
    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++) {
        struct wtq_estream *es = &conn->peer[i];
        if (es->kind == ES_FREE) {
            memset(es, 0, sizeof(*es));
            es->kind = ES_BTYPE;
            es->ds = ds;
            es->id = id;
            *ectx_out = es;
            return WTQ_OK;
        }
    }
    /* The pool is full: reject both directions in one transaction. */
    shutdown_raw(conn, ds, true, true, WTQ_WT_BUFFERED_STREAM_REJECTED);
    return WTQ_ERR_STREAM_LIMIT;
}

/* --- session runtime + WT data path ------------------------------------ */

/* Is the session in a state where runtime operations are legal? */
static bool session_active(const wtq_conn_t *conn)
{
    return conn->sess_state == SS_ESTABLISHED ||
           conn->sess_state == SS_DRAINING;
}

/* Send one capsule inside a DATA frame on the session stream. */
static wtq_result_t session_send_capsule(wtq_conn_t *conn,
                                         const uint8_t *cap, size_t clen,
                                         bool fin)
{
    uint8_t hdr[16];
    size_t hl = 0;

    if (wtq_h3_frame_encode_header(WTQ_H3_FRAME_DATA, clen, hdr,
                                   sizeof(hdr), &hl) != 0)
        return WTQ_ERR_BACKEND;
    wtq_dstream_t *ds = conn->session_es->ds;
    if (conn->ops.send(conn->drv, ds, hdr, hl, false) != WTQ_OK ||
        conn->ops.send(conn->drv, ds, cap, clen, fin) != WTQ_OK) {
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return WTQ_ERR_BACKEND;
    }
    return WTQ_OK;
}

wtq_result_t wtq_conn_session_close(wtq_conn_t *conn, uint32_t code,
                                    const uint8_t *reason,
                                    size_t reason_len)
{
    if (conn == NULL || (reason == NULL && reason_len > 0))
        return WTQ_ERR_INVALID_ARG;
    if (reason_len > WTQ_CAPSULE_MAX_REASON)
        return WTQ_ERR_TOO_LARGE;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (!session_active(conn) || conn->session_es == NULL)
        return WTQ_ERR_STATE;

    uint8_t cap[16 + WTQ_CAPSULE_MAX_REASON];
    size_t clen = 0;
    if (wtq_capsule_encode_close(code, reason, reason_len, cap,
                                 sizeof(cap), &clen) != 0)
        return WTQ_ERR_INVALID_ARG;
    /* draft-15 s6: CLOSE capsule, then immediately FIN */
    wtq_result_t rc = session_send_capsule(conn, cap, clen, true);
    if (rc != WTQ_OK)
        return rc;
    session_closed(conn, code, reason, reason_len, true);
    return WTQ_OK;
}

wtq_result_t wtq_conn_session_drain(wtq_conn_t *conn)
{
    if (conn == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (!session_active(conn) || conn->session_es == NULL)
        return WTQ_ERR_STATE;

    uint8_t cap[8];
    size_t clen = 0;
    if (wtq_capsule_encode_drain(cap, sizeof(cap), &clen) != 0)
        return WTQ_ERR_BACKEND;
    /* advisory: local state does not change (draft-15 s4.7) */
    return session_send_capsule(conn, cap, clen, false);
}

static wtq_result_t wt_open(wtq_conn_t *conn, bool bidi,
                            wtq_estream_t **es_out)
{
    if (conn == NULL || es_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *es_out = NULL;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (!session_active(conn))
        return WTQ_ERR_STATE;

    struct wtq_estream *es = NULL;
    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++)
        if (conn->peer[i].kind == ES_FREE) {
            es = &conn->peer[i];
            break;
        }
    if (es == NULL)
        return WTQ_ERR_STREAM_LIMIT;
    memset(es, 0, sizeof(*es));
    es->id = WTQ_STREAM_ID_UNKNOWN; /* explicit: 0 is a real stream id */

    uint64_t id = WTQ_STREAM_ID_UNKNOWN;
    wtq_result_t rc =
        bidi ? conn->ops.open_bidi(conn->drv, es, &es->ds, &id)
             : conn->ops.open_uni(conn->drv, es, &es->ds, &id);
    if (rc != WTQ_OK)
        return rc;
    es->id = id;
    es->native_id_pending = (id == WTQ_STREAM_ID_UNKNOWN);
    es->kind = ES_WT;
    es->wt_bidi = bidi;
    es->wt_local = true;
    es->wt_send_open = true;
    es->wt_recv_open = bidi;

    uint8_t pre[16];
    size_t plen = 0;
    if (wtq_preamble_encode(bidi ? WTQ_PREAMBLE_KIND_BIDI
                                 : WTQ_PREAMBLE_KIND_UNI,
                            conn->session_id, pre, sizeof(pre),
                            &plen) != 0 ||
        conn->ops.send(conn->drv, es->ds, pre, plen, false) != WTQ_OK) {
        estream_release(conn, es);
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return WTQ_ERR_BACKEND;
    }
    *es_out = es;
    return WTQ_OK;
}

wtq_result_t wtq_conn_wt_open_uni(wtq_conn_t *conn, wtq_estream_t **es_out)
{
    return wt_open(conn, false, es_out);
}

wtq_result_t wtq_conn_wt_open_bidi(wtq_conn_t *conn,
                                   wtq_estream_t **es_out)
{
    return wt_open(conn, true, es_out);
}

wtq_result_t wtq_conn_wt_send(wtq_conn_t *conn, wtq_estream_t *es,
                              const wtq_span_t *spans, size_t count,
                              bool fin, void *cookie)
{
    if (conn == NULL || es == NULL || (spans == NULL && count > 0))
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed || conn->sess_state == SS_CLOSED)
        return WTQ_ERR_CLOSED;
    if (es->kind != ES_WT || !es->wt_send_open)
        return WTQ_ERR_STATE; /* receive-only, already FIN/reset, dead */
    if (conn->ops.send_gather == NULL)
        return WTQ_ERR_STATE;
    /* Span validation, centrally for every backend: the documented
     * count cap rejects BEFORE the array is read (a corrupt count can
     * never drive a wild traversal); each nonempty span must carry
     * data; the aggregate length is summed without wrapping. */
    if (count > WTQ_STREAM_MAX_SPANS)
        return WTQ_ERR_INVALID_ARG;
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > 0 && spans[i].data == NULL)
            return WTQ_ERR_INVALID_ARG;
        if (spans[i].len > SIZE_MAX - total)
            return WTQ_ERR_TOO_LARGE;
        total += spans[i].len;
    }
    wtq_result_t rc = conn->ops.send_gather(conn->drv, es->ds, spans,
                                            count, fin, cookie);
    if (rc == WTQ_OK && fin) {
        es->wt_send_open = false;
        wt_release_if_done(conn, es);
    }
    return rc;
}

wtq_result_t wtq_conn_wt_shutdown(wtq_conn_t *conn, wtq_estream_t *es,
                                  const wtq_shutdown_t *req)
{
    if (conn == NULL || es == NULL || req == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (es->kind != ES_WT)
        return WTQ_ERR_STATE;
    if (req->mode != WTQ_SHUTDOWN_WHOLE_STREAM &&
        req->mode != WTQ_SHUTDOWN_EXACT_HALVES)
        return WTQ_ERR_INVALID_ARG; /* before any backend call or flip */

    wtq_shutdown_t eff = *req;
    if (req->mode == WTQ_SHUTDOWN_WHOLE_STREAM) {
        if (req->send_err != req->recv_err)
            return WTQ_ERR_INVALID_ARG; /* whole means ONE code */
        eff.abort_send = es->wt_send_open;
        eff.abort_recv = es->wt_recv_open;
        if (!eff.abort_send && !eff.abort_recv)
            return WTQ_ERR_STATE; /* nothing open to abort */
    } else {
        if (!req->abort_send && !req->abort_recv)
            return WTQ_ERR_INVALID_ARG;
        if (req->abort_send && !es->wt_send_open)
            return WTQ_ERR_STATE;
        if (req->abort_recv && !es->wt_recv_open)
            return WTQ_ERR_STATE;

        /*
         * SUPPORT IS DECIDED HERE, BEFORE ANY EFFECT — an unsupported
         * request returns with zero state change. Only fully-open-bidi
         * single halves and split codes are capability-gated; a half
         * that is the stream's only remaining open half is the whole
         * stream, normalized to the baseline mode below.
         */
        if (es->wt_bidi) {
            bool fully_open = es->wt_send_open && es->wt_recv_open;
            if (eff.abort_send && eff.abort_recv) {
                if (eff.send_err != eff.recv_err &&
                    (conn->ops.caps & WTQ_DCAP_SHUT_SPLIT_CODES) == 0)
                    return WTQ_ERR_UNSUPPORTED;
                if (eff.send_err == eff.recv_err)
                    eff.mode = WTQ_SHUTDOWN_WHOLE_STREAM;
            } else if (fully_open) {
                uint32_t need = eff.abort_send ? WTQ_DCAP_SHUT_BIDI_SEND
                                               : WTQ_DCAP_SHUT_BIDI_RECV;
                if ((conn->ops.caps & need) == 0)
                    return WTQ_ERR_UNSUPPORTED;
            } else {
                /* single half == only remaining half: baseline */
                eff.mode = WTQ_SHUTDOWN_WHOLE_STREAM;
                eff.recv_err = eff.abort_send ? eff.send_err
                                              : eff.recv_err;
                eff.send_err = eff.recv_err;
            }
        } else {
            /* a uni stream's only half: baseline */
            eff.mode = WTQ_SHUTDOWN_WHOLE_STREAM;
            eff.recv_err = eff.abort_send ? eff.send_err : eff.recv_err;
            eff.send_err = eff.recv_err;
        }
    }

    wtq_result_t rc = conn->ops.shutdown_stream(conn->drv, es->ds, &eff);
    if (rc == WTQ_ERR_CLOSED)
        return rc; /* transport already dead; no state change (as before) */
    if (rc != WTQ_OK) {
        /* Runtime failure, possibly after PARTIAL application. No
         * rollback pretense: the connection dies. */
        conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
        return WTQ_ERR_BACKEND;
    }
    if (eff.abort_send)
        es->wt_send_open = false;
    if (eff.abort_recv) {
        /* the receive side closes exactly once; the estream survives
         * (in drain) to absorb in-flight bytes until the peer's
         * FIN/RESET answers the STOP */
        es->wt_recv_open = false;
        es->wt_recv_drain = true;
    }
    wt_release_if_done(conn, es);
    return WTQ_OK;
}

wtq_result_t wtq_conn_wt_reset(wtq_conn_t *conn, wtq_estream_t *es,
                               uint32_t app_code)
{
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_EXACT_HALVES,
                           .abort_send = true,
                           .send_err = wtq_app_error_to_h3(app_code) };
    return wtq_conn_wt_shutdown(conn, es, &req);
}

wtq_result_t wtq_conn_wt_stop(wtq_conn_t *conn, wtq_estream_t *es,
                              uint32_t app_code)
{
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_EXACT_HALVES,
                           .abort_recv = true,
                           .recv_err = wtq_app_error_to_h3(app_code) };
    return wtq_conn_wt_shutdown(conn, es, &req);
}

wtq_result_t wtq_conn_wt_abort(wtq_conn_t *conn, wtq_estream_t *es,
                               uint32_t app_code)
{
    uint64_t code = wtq_app_error_to_h3(app_code);
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_WHOLE_STREAM,
                           .send_err = code,
                           .recv_err = code };
    return wtq_conn_wt_shutdown(conn, es, &req);
}

void wtq_conn_wt_reject(wtq_conn_t *conn, wtq_estream_t *es)
{
    if (conn == NULL || es == NULL || conn->closed || es->kind != ES_WT)
        return;
    /* The exact WebTransport wire code — NOT an application error run
     * through wtq_app_error_to_h3(): a stream the layer above cannot
     * hold was never the application's to name. ONE whole-stream
     * transaction; the receive side (if any) becomes a drain tombstone
     * until the peer's FIN/RESET answers the STOP. */
    wtq_shutdown_t req = { .mode = WTQ_SHUTDOWN_WHOLE_STREAM,
                           .send_err = WTQ_WT_BUFFERED_STREAM_REJECTED,
                           .recv_err = WTQ_WT_BUFFERED_STREAM_REJECTED };
    es->user = NULL;
    (void)wtq_conn_wt_shutdown(conn, es, &req);
}

wtq_result_t wtq_conn_wt_recv_enable(wtq_conn_t *conn, wtq_estream_t *es,
                                     bool enabled)
{
    if (conn == NULL || es == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (es->kind != ES_WT || !es->wt_recv_open)
        return WTQ_ERR_STATE; /* send-only, already FIN/reset, dead */
    if (conn->ops.recv_enable == NULL)
        return WTQ_ERR_UNSUPPORTED; /* the backend cannot pause reads */
    return conn->ops.recv_enable(conn->drv, es->ds, enabled);
}

void wtq_estream_set_user(wtq_estream_t *es, void *user)
{
    if (es != NULL)
        es->user = user;
}

void *wtq_estream_get_user(const wtq_estream_t *es)
{
    return es != NULL ? es->user : NULL;
}

uint64_t wtq_estream_id(const wtq_estream_t *es)
{
    return es != NULL ? es->id : UINT64_MAX;
}

/*
 * Reject a native-id report as a backend defect. A wrong id would
 * silently poison session_id and every datagram, so the failure is loud
 * and connection-fatal, never a quiet ignore.
 */
static void native_id_report_invalid(wtq_conn_t *conn)
{
    conn_fatal(conn, WTQ_H3_INTERNAL_ERROR);
}

void wtq_conn_on_stream_native_id(wtq_conn_t *conn, wtq_estream_t *es,
                                  uint64_t native_id)
{
    if (conn == NULL || es == NULL)
        return;
    if (conn->closed)
        return; /* post-mortem report: driver state is gone, drop it */

    /* Only locally-opened CONNECT/WT streams can ever owe a report; any
     * other kind — ES_FREE (released slot), peer streams, criticals — is
     * a defect regardless of flag state. */
    if (es->kind != ES_CONNECT && !(es->kind == ES_WT && es->wt_local)) {
        native_id_report_invalid(conn);
        return;
    }
    /* A report the stream never asked for (sync-id open, duplicate) is a
     * defect too. */
    if (!es->native_id_pending) {
        native_id_report_invalid(conn);
        return;
    }
    /* 62-bit varint range (RFC 9000 s2.1). */
    if (native_id >= (1ull << 62)) {
        native_id_report_invalid(conn);
        return;
    }
    /* Locally-opened: the initiator bit must be ours... */
    uint64_t our_init = conn->persp == WTQ_PERSPECTIVE_CLIENT ? 0 : 1;
    if ((native_id & 1) != our_init) {
        native_id_report_invalid(conn);
        return;
    }
    /* ...and the direction bit must match the stream we opened. */
    bool bidi = es->kind == ES_CONNECT || (es->kind == ES_WT && es->wt_bidi);
    if (((native_id & 2) != 0) == bidi) {
        native_id_report_invalid(conn);
        return;
    }
    /* Uniqueness — against KNOWN ids only (id 0 is a real, valid id and
     * an UNKNOWN peer must never be compared). */
    if (conn->session_established && native_id == conn->session_id) {
        native_id_report_invalid(conn);
        return;
    }
    for (size_t i = 0; i < WTQ_CONN_MAX_PEER_UNI; i++) {
        const struct wtq_estream *o = &conn->peer[i];
        if (o != es && o->kind != ES_FREE &&
            o->id != WTQ_STREAM_ID_UNKNOWN && o->id == native_id) {
            native_id_report_invalid(conn);
            return;
        }
    }

    es->id = native_id;
    es->native_id_pending = false;

    /* The CONNECT stream's id is one of the two establishment latches. */
    if (es->kind == ES_CONNECT && conn->persp == WTQ_PERSPECTIVE_CLIENT)
        client_maybe_establish(conn, es);
}

void wtq_conn_on_send_complete(wtq_conn_t *conn, void *cookie,
                               bool canceled)
{
    /* Always forwarded — even after connection teardown, the app must
     * get its buffers back. */
    if (conn != NULL && conn->cb.on_wt_send_complete != NULL)
        conn->cb.on_wt_send_complete(conn, cookie, canceled,
                                     conn->cb.ctx);
}

void wtq_conn_on_stream_writable(wtq_conn_t *conn, wtq_estream_t *es)
{
    /* Only WT data streams gather-send against a budget; anything
     * else (or a closed connection) has nothing to retry. */
    if (conn == NULL || conn->closed || es == NULL || es->kind != ES_WT)
        return;
    if (conn->cb.on_wt_stream_writable != NULL)
        conn->cb.on_wt_stream_writable(conn, es, conn->cb.ctx);
}

wtq_result_t wtq_conn_on_stop_sending(wtq_conn_t *conn, wtq_estream_t *es,
                                      uint64_t quic_err, uint64_t now_us)
{
    (void)now_us;
    if (conn == NULL || es == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (conn->parked_es == es) {
        /* The peer aborted the response direction: the deferred
         * request can never be answered. Cancel it — the refusal's
         * RESET_STREAM is also the required answer to STOP_SENDING.
         * With the FIN already consumed no later event can free an
         * absorber, so release the slot outright; otherwise leave the
         * estream absorbing until the peer's FIN/RESET lands. */
        bool fin_seen = conn->parked_fin;

        request_stream_refuse(conn, es);
        parked_request_cancel(conn);
        if (fin_seen)
            estream_release(conn, es);
        return WTQ_OK;
    }
    if (es->kind == ES_WT) {
        uint32_t app = 0;
        (void)wtq_h3_error_to_app(quic_err, &app);
        /* the stream stays usable until FIN/reset */
        if (conn->cb.on_wt_stream_stop != NULL)
            conn->cb.on_wt_stream_stop(conn, es, app, conn->cb.ctx);
    }
    /* non-WT streams: nothing to surface in this layer yet */
    return WTQ_OK;
}

wtq_result_t wtq_conn_dgram_send(wtq_conn_t *conn, const wtq_span_t *spans,
                                 size_t count)
{
    if (conn == NULL || (spans == NULL && count > 0) ||
        count > WTQ_DGRAM_MAX_SPANS)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed || conn->sess_state == SS_CLOSED)
        return WTQ_ERR_CLOSED; /* s6: MUST NOT send after termination */
    if (!session_active(conn))
        return WTQ_ERR_STATE;
    if (conn->ops.dgram_send == NULL || conn->ops.dgram_max_size == NULL)
        return WTQ_ERR_DGRAM_DISABLED;

    size_t tmax = conn->ops.dgram_max_size(conn->drv);
    /* tmax == prefix still allows the empty WT datagram (receive
     * accepts them; the sendable payload is just 0 bytes) */
    if (tmax < conn->qsid_prefix_len)
        return WTQ_ERR_DGRAM_DISABLED;
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (spans[i].len > 0 && spans[i].data == NULL)
            return WTQ_ERR_INVALID_ARG; /* nonempty spans carry data */
        if (spans[i].len > SIZE_MAX - total)
            return WTQ_ERR_TOO_LARGE; /* hostile lengths must not wrap */
        total += spans[i].len;
    }
    if (total > tmax - conn->qsid_prefix_len)
        return WTQ_ERR_TOO_LARGE;

    wtq_span_t out[1 + WTQ_DGRAM_MAX_SPANS];
    out[0].data = conn->qsid_prefix;
    out[0].len = conn->qsid_prefix_len;
    for (size_t i = 0; i < count; i++)
        out[1 + i] = spans[i];
    return conn->ops.dgram_send(conn->drv, out, 1 + count);
}

size_t wtq_conn_dgram_max_size(const wtq_conn_t *conn)
{
    if (conn == NULL || conn->closed || !session_active(conn) ||
        conn->ops.dgram_send == NULL || conn->ops.dgram_max_size == NULL)
        return 0;
    size_t tmax = conn->ops.dgram_max_size(conn->drv);
    return tmax > conn->qsid_prefix_len ? tmax - conn->qsid_prefix_len
                                        : 0;
}

uint64_t wtq_conn_dgrams_dropped(const wtq_conn_t *conn)
{
    return conn->dgrams_dropped;
}

wtq_result_t wtq_conn_on_datagram(wtq_conn_t *conn, const uint8_t *data,
                                  size_t len, uint64_t now_us)
{
    (void)now_us;
    if (conn == NULL)
        return WTQ_ERR_INVALID_ARG;
    if (conn->closed)
        return WTQ_ERR_CLOSED;
    if (conn_open_locals_if_deferred(conn) != WTQ_OK)
        return WTQ_ERR_CLOSED; /* bootstrap failed: fatal, datagram dropped */

    /* Fast path: the session's own minimal-varint prefix. */
    if (session_active(conn) && len >= conn->qsid_prefix_len &&
        memcmp(data, conn->qsid_prefix, conn->qsid_prefix_len) == 0) {
        if (conn->cb.on_wt_datagram != NULL)
            conn->cb.on_wt_datagram(
                conn,
                len > conn->qsid_prefix_len ? data + conn->qsid_prefix_len
                                            : NULL,
                len - conn->qsid_prefix_len, conn->cb.ctx);
        return WTQ_OK;
    }

    /* Slow path: decode the varint (non-minimal encodings of our qsid
     * are still ours; RFC 9000 varints don't require minimal form). A
     * payload too short to carry the quarter-stream-id varint is a
     * connection error (RFC 9297 s2.1). Note any decoded qsid maps to
     * qsid*4 — always a client-initiated bidi id, so the s4 session-id
     * validity rule cannot trip on datagrams. */
    uint64_t qsid = 0;
    size_t c = 0;
    if (len == 0 ||
        wtq_varint_decode(data, len, &qsid, &c) != WTQ_VARINT_OK) {
        conn_fatal(conn, WTQ_H3_DATAGRAM_ERROR);
        return WTQ_ERR_PROTO;
    }
    if (session_active(conn) && qsid == conn->session_id / 4) {
        if (conn->cb.on_wt_datagram != NULL)
            conn->cb.on_wt_datagram(conn,
                                    len > c ? data + c : NULL, len - c,
                                    conn->cb.ctx);
        return WTQ_OK;
    }
    /* unknown / not-yet-established / terminated session: dropped
     * (s4.6 buffering limit is zero; s6 discards closed-session data) */
    conn->dgrams_dropped++;
    return WTQ_OK;
}

wtq_session_state_t wtq_conn_session_state(const wtq_conn_t *conn)
{
    return (wtq_session_state_t)conn->sess_state;
}

uint64_t wtq_conn_session_id(const wtq_conn_t *conn)
{
    /* established, not the value: stream id 0 is a real id, and the SPI
     * documents the id as available once established. */
    return conn->session_established ? conn->session_id : UINT64_MAX;
}

bool wtq_conn_session_established(const wtq_conn_t *conn)
{
    return conn->session_established;
}

const char *wtq_conn_selected_protocol(const wtq_conn_t *conn,
                                       size_t *len_out)
{
    *len_out = conn->selected_len;
    return conn->selected_len > 0 ? conn->selected : "";
}

const char *wtq_conn_request_path(const wtq_conn_t *conn, size_t *len_out)
{
    *len_out = conn->req_path_len;
    return conn->req_path_len > 0 ? conn->req_path : "";
}

const char *wtq_conn_request_authority(const wtq_conn_t *conn,
                                       size_t *len_out)
{
    *len_out = conn->req_auth_len;
    return conn->req_auth_len > 0 ? conn->req_auth : "";
}
