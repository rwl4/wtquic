#ifndef WTQ_PROTO_CONNECT_H
#define WTQ_PROTO_CONNECT_H

/*
 * WebTransport extended CONNECT request/response codec
 * (draft-ietf-webtrans-http3-15 section 3; RFC 9220; RFC 9114 header
 * validation rules), over the static-only QPACK codec and the
 * Structured Fields string helpers.
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * This module owns WebTransport CONNECT semantics ONLY: inputs and
 * outputs are QPACK field-section payloads (H3 HEADERS frame headers
 * stay in h3_frame / the control-stream layer), and it is not a
 * generic HTTP/3 header layer.
 *
 * SPEC NOTE: draft-15 requires ":protocol = webtransport-h3" (line
 * 472); the bare "webtransport" token is pre-draft-13 legacy, accepted
 * on receive only behind accept_legacy_protocol. Requests must carry
 * :method=CONNECT, :protocol, and exactly one :scheme / :authority /
 * :path; pseudo-headers precede regular fields, appear at most once,
 * and field names must be lowercase (RFC 9114 s4.3/s4.1.1 rules as they
 * apply here). wt-available-protocols / wt-protocol are RFC 8941
 * Strings (sf_string module); EMPTY protocol strings are invalid at
 * this layer even though sf_string parses them; bare-token members are
 * rejected unless lenient_sf_tokens (pico/Chrome interop experiments).
 *
 * No allocation. Decoded spans point into the caller's scratch, the
 * QPACK static table, or static "" — valid until the caller reuses the
 * scratch. Internal field capacity is WTQ_CONNECT_MAX_FIELDS; sections
 * with more fields return BUFFER.
 */

#include "sf_string.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WTQ_CONNECT_PROTOCOL_TOKEN "webtransport-h3"
#define WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY "webtransport"
#define WTQ_CONNECT_MAX_FIELDS 32u

typedef int wtq_connect_status_t;
#define WTQ_CONNECT_OK          0
#define WTQ_CONNECT_BUFFER      (-1) /* scratch/array capacity too small */
#define WTQ_CONNECT_MALFORMED   (-2) /* bad QPACK, bad SF, or bad header
                                        semantics */
#define WTQ_CONNECT_NO_PROTOCOL (-3) /* protocol negotiation: no overlap */
/* A well-formed HTTP request that simply is not a WebTransport extended
 * CONNECT: an ordinary method (GET, ...), a plain CONNECT tunnel, or an
 * extended CONNECT for some other :protocol. The peer did nothing wrong
 * — the caller answers with a response, never a protocol error. */
#define WTQ_CONNECT_NOT_WEBTRANSPORT (-4)

typedef struct wtq_connect_opts {
    bool lenient_sf_tokens;      /* accept bare-token SF members */
    bool accept_legacy_protocol; /* accept ":protocol = webtransport" */
} wtq_connect_opts_t;

/* Decoded extended CONNECT request. Spans point into caller scratch /
 * static storage; offered protocols are written to the caller's
 * protocols[] in wire (client preference) order. */
typedef struct wtq_connect_req {
    const char *authority;
    size_t authority_len;
    const char *path;
    size_t path_len;
    const char *origin; /* optional; has_origin distinguishes "" */
    size_t origin_len;
    bool has_origin;
    bool legacy_protocol; /* matched via the legacy token */
} wtq_connect_req_t;

/* Decoded CONNECT response. 2xx means the session was accepted
 * (draft-15); anything else is a rejection the caller reports — never
 * treat it as established. */
typedef struct wtq_connect_resp {
    uint16_t status;
    bool has_protocol; /* wt-protocol header present */
    wtq_sf_str_t protocol;
} wtq_connect_resp_t;

/* CONTRACT: success is draft-wide 2xx — draft-15 defines acceptance via
 * a "successful (2xx) response" and h3zero checks 200-299 the same way.
 * wtquic servers only ever SEND 200; on receive, narrowing to ==200
 * would reject spec-legal servers. */
static inline bool wtq_connect_status_is_success(uint16_t status)
{
    return status >= 200 && status <= 299;
}

/*
 * Decode a request field section, classifying it three ways:
 *
 *   OK               - a WebTransport extended CONNECT; *out is filled.
 *   NOT_WEBTRANSPORT - a well-formed request that is not one: an
 *                      ordinary method, a plain CONNECT tunnel, or an
 *                      extended CONNECT for another :protocol. *out is
 *                      NOT filled; answer with an HTTP response.
 *   MALFORMED        - an HTTP/3 message-syntax violation (bad QPACK,
 *                      bad field name/value, missing or misplaced
 *                      pseudo-headers, a non-token :method / :protocol,
 *                      a :scheme violating RFC 3986, a missing/empty/
 *                      duplicate/conflicting authority source on an
 *                      http(s) request, a WebTransport CONNECT whose
 *                      :scheme is not exactly "https"). RFC 9114
 *                      s4.1.2: the caller answers with a STREAM error.
 *   BUFFER           - a LOCAL capacity limit (field count or scratch),
 *                      not a peer error; answer with a stream-local
 *                      H3_EXCESSIVE_LOAD, never H3_MESSAGE_ERROR.
 *
 * Generic URI schemes are compared case-insensitively (RFC 3986 s3.1)
 * when deciding whether a request is http(s); WebTransport's own
 * :scheme check is exact lowercase "https" per draft-15 s3.2.
 *
 * protocols[] receives the wt-available-protocols members (count 0 when
 * the header is absent — or present-but-malformed SF, which the draft
 * says to treat as an ignored/absent field; header-level violations
 * like duplicates are MALFORMED).
 */
wtq_connect_status_t wtq_connect_decode_request(
    const uint8_t *section, size_t len, const wtq_connect_opts_t *opts,
    wtq_connect_req_t *out, wtq_sf_str_t *protocols, size_t max_protocols,
    size_t *protocol_count, char *scratch, size_t scratch_cap);

/*
 * Validate a TRAILING field section (RFC 9114 s4.1/s4.3): the same
 * QPACK decode and universal name/value rules as a header section, plus
 * "no pseudo-headers". Regular fields are accepted and intentionally
 * not reported — wtquic exposes no trailer API. OK / MALFORMED /
 * BUFFER carry the same meanings as wtq_connect_decode_request.
 */
wtq_connect_status_t wtq_connect_validate_trailers(const uint8_t *section,
                                                   size_t len,
                                                   char *scratch,
                                                   size_t scratch_cap);

/*
 * Decode a response field section. A missing/malformed wt-protocol is
 * reported via has_protocol == false (the draft ignores the field);
 * duplicate wt-protocol headers are MALFORMED.
 */
wtq_connect_status_t wtq_connect_decode_response(
    const uint8_t *section, size_t len, const wtq_connect_opts_t *opts,
    wtq_connect_resp_t *out, char *scratch, size_t scratch_cap);

/*
 * Encode a request field section: :method CONNECT, :scheme https,
 * :authority, :path, :protocol webtransport-h3, optional origin,
 * optional wt-available-protocols (canonical SF list; each protocol
 * must be a valid non-empty sf-string value). The SF serialization
 * uses an internal 1024-byte staging buffer: longer protocol lists
 * return BUFFER.
 */
wtq_connect_status_t wtq_connect_encode_request(
    const char *authority, size_t authority_len, const char *path,
    size_t path_len, const char *origin, size_t origin_len,
    const wtq_sf_str_t *protocols, size_t protocol_count, uint8_t *dst,
    size_t cap, size_t *out_len);

/*
 * Encode a response field section: :status, plus wt-protocol when
 * selected != NULL (must be a valid non-empty sf-string value).
 */
wtq_connect_status_t wtq_connect_encode_response(
    uint16_t status, const wtq_sf_str_t *selected, uint8_t *dst,
    size_t cap, size_t *out_len);

/*
 * Server-side selection: first client-offered protocol (preference
 * order) present in supported[]. Case-sensitive. OK + *out_index, or
 * NO_PROTOCOL.
 */
wtq_connect_status_t wtq_connect_select_protocol(
    const wtq_sf_str_t *offered, size_t offered_count,
    const wtq_sf_str_t *supported, size_t supported_count,
    size_t *out_index);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_CONNECT_H */
