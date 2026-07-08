#include "connect.h"

#include <string.h>

#include "qpack_static.h"

#define CONNECT_SF_STAGING 1024

static bool name_is(const wtq_qpack_field_t *f, const char *lit)
{
    size_t n = strlen(lit);

    return f->name_len == n && memcmp(f->name, lit, n) == 0;
}

static bool value_is(const wtq_qpack_field_t *f, const char *lit)
{
    size_t n = strlen(lit);

    return f->value_len == n && memcmp(f->value, lit, n) == 0;
}

/* RFC 9110 tchar, full alphabet (methods and :protocol are tokens and
 * may carry uppercase). */
static bool is_token_char(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return true;
    return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static bool is_tchar(char c)
{
    /* Same set minus uppercase: H3 field names must be lowercase. */
    return !(c >= 'A' && c <= 'Z') && is_token_char(c);
}

/* RFC 9110 token: 1*tchar. */
static bool value_is_token(const char *v, size_t len)
{
    if (len == 0)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!is_token_char(v[i]))
            return false;
    return true;
}

/* RFC 3986 s3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
static bool scheme_is_valid(const char *v, size_t len)
{
    if (len == 0)
        return false;
    if (!((v[0] >= 'a' && v[0] <= 'z') || (v[0] >= 'A' && v[0] <= 'Z')))
        return false;
    for (size_t i = 1; i < len; i++) {
        char c = v[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')
            continue;
        return false;
    }
    return true;
}

static char ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/* ASCII case-insensitive span compare (URI schemes and host names are
 * case-insensitive; WebTransport's own :scheme check stays exact). */
static bool span_ieq(const char *a, size_t alen, const char *b,
                     size_t blen)
{
    if (alen != blen)
        return false;
    for (size_t i = 0; i < alen; i++)
        if (ascii_lower(a[i]) != ascii_lower(b[i]))
            return false;
    return true;
}

static bool scheme_ieq(const wtq_qpack_field_t *f, const char *lit)
{
    return span_ieq(f->value, f->value_len, lit, strlen(lit));
}

/* Field-value syntax (RFC 9110 field-content): empty is valid; a
 * nonempty value begins and ends with VCHAR (0x21-0x7E) or obs-text
 * (0x80-0xFF), with SP/HTAB additionally allowed between. CTLs — CR,
 * LF and NUL included — and DEL are forbidden everywhere: those are
 * the intermediary-injection bytes RFC 9114 s10.3 calls out, so a
 * value carrying one makes the whole message malformed. */
static bool value_is_valid(const char *v, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c == ' ' || c == '\t') {
            if (i == 0 || i + 1 == len)
                return false;
            continue;
        }
        if (c < 0x21 || c == 0x7F)
            return false;
    }
    return true;
}

/* Field-name syntax: pseudo names are ':' + 1*tchar; regular names are
 * 1*tchar. Rejects uppercase, spaces, controls, separators, DQUOTE and
 * stray ':' in regular names. */
static bool name_is_valid(const wtq_qpack_field_t *f)
{
    size_t start = 0;

    if (f->name_len == 0)
        return false;
    if (f->name[0] == ':') {
        if (f->name_len == 1)
            return false;
        start = 1;
    }
    for (size_t i = start; i < f->name_len; i++)
        if (!is_tchar(f->name[i]))
            return false;
    return true;
}

/* Highest scratch offset used by the decoded qpack literals, so SF
 * unescaping can append after them. Bounded uintptr_t containment (see
 * the fuzz harness rationale: relational comparison of unrelated
 * pointers is UB). */
static size_t scratch_high_water(const wtq_qpack_field_t *fields,
                                 size_t count, const char *scratch,
                                 size_t scratch_cap)
{
    uintptr_t base = (uintptr_t)scratch;
    size_t high = 0;

    if (scratch == NULL)
        return 0;
    for (size_t i = 0; i < count; i++) {
        const char *spans[2] = { fields[i].name, fields[i].value };
        size_t lens[2] = { fields[i].name_len, fields[i].value_len };
        for (int s = 0; s < 2; s++) {
            uintptr_t p = (uintptr_t)spans[s];
            if (lens[s] == 0 || lens[s] > scratch_cap)
                continue;
            if (p >= base && p - base <= scratch_cap - lens[s]) {
                size_t end = (size_t)(p - base) + lens[s];
                if (end > high)
                    high = end;
            }
        }
    }
    return high;
}

/* Shared header-walk state. */
typedef struct walk {
    wtq_qpack_field_t fields[WTQ_CONNECT_MAX_FIELDS];
    size_t count;
    size_t sf_off; /* scratch offset where SF output may begin */
} walk_t;

static wtq_connect_status_t walk_init(walk_t *w, const uint8_t *section,
                                      size_t len, char *scratch,
                                      size_t scratch_cap)
{
    size_t count = 0;
    wtq_qpack_status_t st =
        wtq_qpack_decode_section(section, len, w->fields,
                                 WTQ_CONNECT_MAX_FIELDS, &count, scratch,
                                 scratch_cap);

    if (st == WTQ_QPACK_BUFFER)
        return WTQ_CONNECT_BUFFER;
    if (st != WTQ_QPACK_OK)
        return WTQ_CONNECT_MALFORMED;

    w->count = count;
    w->sf_off = scratch_high_water(w->fields, count, scratch, scratch_cap);

    /* Universal field rules: valid lowercase token names; RFC 9110
     * field-content values — enforced on EVERY field, the ones this
     * CONNECT subset otherwise ignores included, so an invalid value
     * cannot hide in an unexamined field; pseudo-headers first. */
    bool seen_regular = false;
    for (size_t i = 0; i < count; i++) {
        if (!name_is_valid(&w->fields[i]))
            return WTQ_CONNECT_MALFORMED;
        if (!value_is_valid(w->fields[i].value, w->fields[i].value_len))
            return WTQ_CONNECT_MALFORMED;
        if (w->fields[i].name[0] == ':') {
            if (seen_regular)
                return WTQ_CONNECT_MALFORMED;
        } else {
            seen_regular = true;
        }
    }
    return WTQ_CONNECT_OK;
}

/* Parse one SF-string protocol list/item with the draft's ignore rule:
 * SF malformed or an empty member => treat the field as absent
 * (returns OK with *out_count = 0); capacity problems stay BUFFER. */
static wtq_connect_status_t parse_protocol_list(
    const wtq_qpack_field_t *f, const wtq_connect_opts_t *opts,
    wtq_sf_str_t *protocols, size_t max_protocols, size_t *out_count,
    char *scratch, size_t sf_off, size_t scratch_cap)
{
    char *out_buf = (scratch != NULL) ? scratch + sf_off : NULL;
    size_t out_cap = scratch_cap - sf_off;
    size_t n = 0;

    wtq_sf_status_t st = wtq_sf_string_parse_list(
        f->value, f->value_len, opts->lenient_sf_tokens, out_buf, out_cap,
        protocols, max_protocols, &n);
    if (st == WTQ_SF_BUFFER)
        return WTQ_CONNECT_BUFFER;
    if (st != WTQ_SF_OK) {
        *out_count = 0; /* draft: malformed field is ignored */
        return WTQ_CONNECT_OK;
    }
    for (size_t i = 0; i < n; i++) {
        if (protocols[i].len == 0) {
            *out_count = 0; /* empty protocol: connect-layer invalid */
            return WTQ_CONNECT_OK;
        }
    }
    *out_count = n;
    return WTQ_CONNECT_OK;
}

wtq_connect_status_t wtq_connect_decode_request(
    const uint8_t *section, size_t len, const wtq_connect_opts_t *opts,
    wtq_connect_req_t *out, wtq_sf_str_t *protocols, size_t max_protocols,
    size_t *protocol_count, char *scratch, size_t scratch_cap)
{
    walk_t w;
    wtq_connect_status_t st = walk_init(&w, section, len, scratch,
                                        scratch_cap);
    if (st != WTQ_CONNECT_OK)
        return st;

    const wtq_qpack_field_t *method = NULL;
    const wtq_qpack_field_t *scheme = NULL;
    const wtq_qpack_field_t *authority = NULL;
    const wtq_qpack_field_t *path = NULL;
    const wtq_qpack_field_t *protocol = NULL;
    const wtq_qpack_field_t *origin = NULL;
    const wtq_qpack_field_t *wtap = NULL;
    const wtq_qpack_field_t *host = NULL;

    for (size_t i = 0; i < w.count; i++) {
        const wtq_qpack_field_t *f = &w.fields[i];
        if (f->name[0] == ':') {
            const wtq_qpack_field_t **slot;
            if (name_is(f, ":method"))
                slot = &method;
            else if (name_is(f, ":scheme"))
                slot = &scheme;
            else if (name_is(f, ":authority"))
                slot = &authority;
            else if (name_is(f, ":path"))
                slot = &path;
            else if (name_is(f, ":protocol"))
                slot = &protocol;
            else
                return WTQ_CONNECT_MALFORMED; /* unknown pseudo */
            if (*slot != NULL)
                return WTQ_CONNECT_MALFORMED; /* duplicate pseudo */
            *slot = f;
        } else if (name_is(f, "origin")) {
            if (origin != NULL)
                return WTQ_CONNECT_MALFORMED;
            origin = f;
        } else if (name_is(f, "wt-available-protocols")) {
            if (wtap != NULL)
                return WTQ_CONNECT_MALFORMED;
            wtap = f;
        } else if (name_is(f, "host")) {
            /* RFC 9110 s7.2: at most one Host */
            if (host != NULL)
                return WTQ_CONNECT_MALFORMED;
            host = f;
        }
        /* other regular headers are ignored */
    }

    /*
     * Classify before judging. Three outcomes, and only the middle one
     * is the peer's fault:
     *   MALFORMED        - the request violates HTTP/3 message syntax
     *   NOT_WEBTRANSPORT - a valid request for something else
     *   OK               - a WebTransport extended CONNECT
     */
    if (method == NULL)
        return WTQ_CONNECT_MALFORMED; /* every request carries :method */

    /* Syntax of the pseudo-headers we route on, before any of them can
     * steer a request toward "valid, just not WebTransport". */
    if (!value_is_token(method->value, method->value_len))
        return WTQ_CONNECT_MALFORMED;
    if (protocol != NULL &&
        !value_is_token(protocol->value, protocol->value_len))
        return WTQ_CONNECT_MALFORMED;
    if (scheme != NULL && !scheme_is_valid(scheme->value,
                                           scheme->value_len))
        return WTQ_CONNECT_MALFORMED;

    /* RFC 9110 s7.2 / RFC 9114 s4.3.1: a Host must be nonempty and,
     * when :authority is also present, must agree with it (host names
     * are ASCII case-insensitive). */
    if (host != NULL) {
        if (host->value_len == 0)
            return WTQ_CONNECT_MALFORMED;
        if (authority != NULL &&
            !span_ieq(host->value, host->value_len, authority->value,
                      authority->value_len))
            return WTQ_CONNECT_MALFORMED;
    }

    if (!value_is(method, "CONNECT")) {
        /* RFC 9114 s4.3.1: non-CONNECT requests carry :scheme and
         * :path; RFC 8441 s4: :protocol is CONNECT-only. */
        if (scheme == NULL || path == NULL || protocol != NULL)
            return WTQ_CONNECT_MALFORMED;
        if (path->value_len == 0)
            return WTQ_CONNECT_MALFORMED;
        /* For http/https, one nonempty authority source is mandatory —
         * :authority, or Host in its absence. Other schemes carry
         * their authority (if any) elsewhere. */
        if (scheme_ieq(scheme, "https") || scheme_ieq(scheme, "http")) {
            if (authority != NULL && authority->value_len == 0)
                return WTQ_CONNECT_MALFORMED;
            if (authority == NULL && host == NULL)
                return WTQ_CONNECT_MALFORMED;
        }
        return WTQ_CONNECT_NOT_WEBTRANSPORT; /* GET, POST, ... */
    }

    if (protocol == NULL) {
        /* RFC 9114 s4.4: an ordinary CONNECT tunnel carries :authority
         * and MUST omit :scheme and :path. */
        if (authority == NULL || scheme != NULL || path != NULL)
            return WTQ_CONNECT_MALFORMED;
        if (authority->value_len == 0)
            return WTQ_CONNECT_MALFORMED;
        return WTQ_CONNECT_NOT_WEBTRANSPORT;
    }

    /* Extended CONNECT (RFC 8441 s4 / RFC 9220): :scheme, :authority
     * and :path are all required, whatever the :protocol turns out to
     * be. (:protocol's token syntax was checked above.) */
    if (scheme == NULL || authority == NULL || path == NULL)
        return WTQ_CONNECT_MALFORMED;

    bool legacy = false;
    if (!value_is(protocol, WTQ_CONNECT_PROTOCOL_TOKEN)) {
        if (opts->accept_legacy_protocol &&
            value_is(protocol, WTQ_CONNECT_PROTOCOL_TOKEN_LEGACY))
            legacy = true;
        else
            return WTQ_CONNECT_NOT_WEBTRANSPORT; /* websocket, ... */
    }

    /* It IS a WebTransport CONNECT: now the WebTransport rules bite. */
    /* draft-15 s3.2: the :scheme MUST be https — exactly (pseudo-header
     * values are case-sensitive; https is the lowercase URI scheme) */
    if (!value_is(scheme, "https"))
        return WTQ_CONNECT_MALFORMED;
    if (authority->value_len == 0 || path->value_len == 0)
        return WTQ_CONNECT_MALFORMED;

    *protocol_count = 0;
    if (wtap != NULL) {
        wtq_connect_status_t pst = parse_protocol_list(
            wtap, opts, protocols, max_protocols, protocol_count, scratch,
            w.sf_off, scratch_cap);
        if (pst != WTQ_CONNECT_OK)
            return pst;
    }

    out->authority = authority->value;
    out->authority_len = authority->value_len;
    out->path = path->value;
    out->path_len = path->value_len;
    out->has_origin = origin != NULL;
    out->origin = (origin != NULL) ? origin->value : "";
    out->origin_len = (origin != NULL) ? origin->value_len : 0;
    out->legacy_protocol = legacy;
    return WTQ_CONNECT_OK;
}

wtq_connect_status_t wtq_connect_validate_trailers(const uint8_t *section,
                                                   size_t len,
                                                   char *scratch,
                                                   size_t scratch_cap)
{
    walk_t w;
    /* The universal rules (QPACK decode, lowercase token names, RFC
     * 9110 field-content values) come free with the walk. */
    wtq_connect_status_t st = walk_init(&w, section, len, scratch,
                                        scratch_cap);

    if (st != WTQ_CONNECT_OK)
        return st;
    /* RFC 9114 s4.3: a trailer section carries no pseudo-headers. */
    for (size_t i = 0; i < w.count; i++)
        if (w.fields[i].name[0] == ':')
            return WTQ_CONNECT_MALFORMED;
    /* Regular fields are accepted and deliberately not surfaced. */
    return WTQ_CONNECT_OK;
}

wtq_connect_status_t wtq_connect_decode_response(
    const uint8_t *section, size_t len, const wtq_connect_opts_t *opts,
    wtq_connect_resp_t *out, char *scratch, size_t scratch_cap)
{
    walk_t w;
    wtq_connect_status_t st = walk_init(&w, section, len, scratch,
                                        scratch_cap);
    if (st != WTQ_CONNECT_OK)
        return st;

    const wtq_qpack_field_t *status = NULL;
    const wtq_qpack_field_t *wtp = NULL;

    for (size_t i = 0; i < w.count; i++) {
        const wtq_qpack_field_t *f = &w.fields[i];
        if (f->name[0] == ':') {
            if (!name_is(f, ":status"))
                return WTQ_CONNECT_MALFORMED; /* unknown pseudo */
            if (status != NULL)
                return WTQ_CONNECT_MALFORMED;
            status = f;
        } else if (name_is(f, "wt-protocol")) {
            if (wtp != NULL)
                return WTQ_CONNECT_MALFORMED;
            wtp = f;
        }
    }

    if (status == NULL || status->value_len != 3)
        return WTQ_CONNECT_MALFORMED;
    uint16_t code = 0;
    for (size_t i = 0; i < 3; i++) {
        char c = status->value[i];
        if (c < '0' || c > '9')
            return WTQ_CONNECT_MALFORMED;
        code = (uint16_t)(code * 10 + (uint16_t)(c - '0'));
    }
    if (code < 100)
        return WTQ_CONNECT_MALFORMED;

    out->status = code;
    out->has_protocol = false;
    out->protocol.data = "";
    out->protocol.len = 0;

    if (wtp != NULL) {
        char *out_buf = (scratch != NULL) ? scratch + w.sf_off : NULL;
        size_t out_cap = scratch_cap - w.sf_off;
        wtq_sf_str_t v = { "", 0 };
        wtq_sf_status_t sst = wtq_sf_string_parse_item(
            wtp->value, wtp->value_len, opts->lenient_sf_tokens, out_buf,
            out_cap, &v);
        if (sst == WTQ_SF_BUFFER)
            return WTQ_CONNECT_BUFFER;
        if (sst == WTQ_SF_OK && v.len > 0) {
            out->has_protocol = true;
            out->protocol = v;
        }
        /* malformed or empty: field ignored (draft rule) */
    }

    return WTQ_CONNECT_OK;
}

wtq_connect_status_t wtq_connect_encode_request(
    const char *authority, size_t authority_len, const char *path,
    size_t path_len, const char *origin, size_t origin_len,
    const wtq_sf_str_t *protocols, size_t protocol_count, uint8_t *dst,
    size_t cap, size_t *out_len)
{
    if (authority == NULL || authority_len == 0 || path == NULL ||
        path_len == 0)
        return WTQ_CONNECT_MALFORMED;
    /* never generate what the decoder would reject */
    if (!value_is_valid(authority, authority_len) ||
        !value_is_valid(path, path_len) ||
        (origin != NULL && !value_is_valid(origin, origin_len)))
        return WTQ_CONNECT_MALFORMED;

    char sf_staging[CONNECT_SF_STAGING];
    size_t sf_len = 0;
    if (protocol_count > 0) {
        for (size_t i = 0; i < protocol_count; i++)
            if (protocols[i].len == 0 ||
                !wtq_sf_string_valid(protocols[i].data, protocols[i].len))
                return WTQ_CONNECT_MALFORMED;
        wtq_sf_status_t sst = wtq_sf_string_encode_list(
            protocols, protocol_count, sf_staging, sizeof(sf_staging),
            &sf_len);
        if (sst == WTQ_SF_BUFFER)
            return WTQ_CONNECT_BUFFER;
        if (sst != WTQ_SF_OK)
            return WTQ_CONNECT_MALFORMED;
    }

    wtq_qpack_field_t fields[8];
    size_t n = 0;
    fields[n++] = (wtq_qpack_field_t){ ":method", 7, "CONNECT", 7, false };
    fields[n++] = (wtq_qpack_field_t){ ":scheme", 7, "https", 5, false };
    fields[n++] = (wtq_qpack_field_t){ ":authority", 10, authority,
                                       authority_len, false };
    fields[n++] = (wtq_qpack_field_t){ ":path", 5, path, path_len, false };
    fields[n++] = (wtq_qpack_field_t){ ":protocol", 9,
                                       WTQ_CONNECT_PROTOCOL_TOKEN,
                                       sizeof(WTQ_CONNECT_PROTOCOL_TOKEN) -
                                           1,
                                       false };
    if (origin != NULL && origin_len > 0)
        fields[n++] = (wtq_qpack_field_t){ "origin", 6, origin, origin_len,
                                           false };
    if (protocol_count > 0)
        fields[n++] = (wtq_qpack_field_t){ "wt-available-protocols", 22,
                                           sf_staging, sf_len, false };

    wtq_qpack_status_t st = wtq_qpack_encode_section(fields, n, dst, cap,
                                                     out_len);
    if (st == WTQ_QPACK_BUFFER)
        return WTQ_CONNECT_BUFFER;
    return (st == WTQ_QPACK_OK) ? WTQ_CONNECT_OK : WTQ_CONNECT_MALFORMED;
}

wtq_connect_status_t wtq_connect_encode_response(
    uint16_t status, const wtq_sf_str_t *selected, uint8_t *dst,
    size_t cap, size_t *out_len)
{
    if (status < 100 || status > 999)
        return WTQ_CONNECT_MALFORMED;

    char code[4];
    code[0] = (char)('0' + status / 100);
    code[1] = (char)('0' + (status / 10) % 10);
    code[2] = (char)('0' + status % 10);
    code[3] = '\0';

    char sf_staging[CONNECT_SF_STAGING];
    size_t sf_len = 0;
    if (selected != NULL) {
        if (selected->len == 0 ||
            !wtq_sf_string_valid(selected->data, selected->len))
            return WTQ_CONNECT_MALFORMED;
        wtq_sf_status_t sst = wtq_sf_string_encode_item(
            selected->data, selected->len, sf_staging,
            sizeof(sf_staging), &sf_len);
        if (sst == WTQ_SF_BUFFER)
            return WTQ_CONNECT_BUFFER;
        if (sst != WTQ_SF_OK)
            return WTQ_CONNECT_MALFORMED;
    }

    wtq_qpack_field_t fields[2];
    size_t n = 0;
    fields[n++] = (wtq_qpack_field_t){ ":status", 7, code, 3, false };
    if (selected != NULL)
        fields[n++] = (wtq_qpack_field_t){ "wt-protocol", 11, sf_staging,
                                           sf_len, false };

    wtq_qpack_status_t st = wtq_qpack_encode_section(fields, n, dst, cap,
                                                     out_len);
    if (st == WTQ_QPACK_BUFFER)
        return WTQ_CONNECT_BUFFER;
    return (st == WTQ_QPACK_OK) ? WTQ_CONNECT_OK : WTQ_CONNECT_MALFORMED;
}

wtq_connect_status_t wtq_connect_select_protocol(
    const wtq_sf_str_t *offered, size_t offered_count,
    const wtq_sf_str_t *supported, size_t supported_count,
    size_t *out_index)
{
    if (wtq_sf_string_select(offered, offered_count, supported,
                             supported_count, out_index))
        return WTQ_CONNECT_OK;
    return WTQ_CONNECT_NO_PROTOCOL;
}
