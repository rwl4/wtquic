#include "sf_string.h"

#include <string.h>

/* RFC 8941 grammar helpers. */

static bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_tchar(char c)
{
    /* RFC 7230 tchar. */
    if (is_alpha(c) || is_digit(c))
        return true;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL && c != '\0';
}

static bool is_token_char(char c)
{
    /* sf-token tail: tchar / ":" / "/" */
    return is_tchar(c) || c == ':' || c == '/';
}

static bool is_lcalpha(char c)
{
    return c >= 'a' && c <= 'z';
}

static void skip_sp(const char *in, size_t len, size_t *off)
{
    while (*off < len && in[*off] == ' ')
        (*off)++;
}

/* RFC 8941 s4.2.1 uses OWS (SP / HTAB) around list separators; the
 * top-level parse (s4.2) discards leading SP only. */
static void skip_ows(const char *in, size_t len, size_t *off)
{
    while (*off < len && (in[*off] == ' ' || in[*off] == '\t'))
        (*off)++;
}

static bool is_base64_char(char c)
{
    return is_alpha(c) || is_digit(c) || c == '+' || c == '/' || c == '=';
}

bool wtq_sf_string_valid(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

/* --- parsing ---------------------------------------------------------- */

/* Parse an sf-string at in[*off], unescaping into out_buf[*out_off].
 * Advances both offsets. */
static wtq_sf_status_t parse_string(const char *in, size_t len, size_t *off,
                                    char *out_buf, size_t out_cap,
                                    size_t *out_off, wtq_sf_str_t *out)
{
    size_t i = *off;
    size_t start = *out_off;

    if (i >= len || in[i] != '"')
        return WTQ_SF_MALFORMED;
    i++;

    while (i < len) {
        char c = in[i];
        if (c == '"') {
            i++;
            out->data = out_buf + start;
            out->len = *out_off - start;
            *off = i;
            return WTQ_SF_OK;
        }
        if (c == '\\') {
            if (i + 1 >= len)
                return WTQ_SF_MALFORMED;
            char e = in[i + 1];
            if (e != '"' && e != '\\')
                return WTQ_SF_MALFORMED;
            c = e;
            i += 2;
        } else {
            unsigned char u = (unsigned char)c;
            /* unescaped = %x20-21 / %x23-5B / %x5D-7E */
            if (u < 0x20 || u > 0x7e)
                return WTQ_SF_MALFORMED;
            i++;
        }
        if (*out_off >= out_cap)
            return WTQ_SF_BUFFER;
        out_buf[(*out_off)++] = c;
    }
    return WTQ_SF_MALFORMED; /* unterminated */
}

/* Lenient interop mode: accept an sf-token member as if it were a
 * string (picowt and other SF-naive peers send bare tokens). */
static wtq_sf_status_t parse_token_lenient(const char *in, size_t len,
                                           size_t *off, char *out_buf,
                                           size_t out_cap, size_t *out_off,
                                           wtq_sf_str_t *out)
{
    size_t i = *off;
    size_t start = *out_off;

    if (i >= len || !(is_alpha(in[i]) || in[i] == '*'))
        return WTQ_SF_MALFORMED;

    while (i < len && is_token_char(in[i])) {
        if (*out_off >= out_cap)
            return WTQ_SF_BUFFER;
        out_buf[(*out_off)++] = in[i];
        i++;
    }

    out->data = out_buf + start;
    out->len = *out_off - start;
    *off = i;
    return WTQ_SF_OK;
}

/* Skip a bare item (any RFC 8941 type) for parameter values. We never
 * surface these values; we only need to consume them correctly. */
static wtq_sf_status_t skip_bare_item(const char *in, size_t len,
                                      size_t *off)
{
    size_t i = *off;

    if (i >= len)
        return WTQ_SF_MALFORMED;

    char c = in[i];
    if (c == '"') {
        /* string: scan to unescaped closing quote */
        i++;
        while (i < len) {
            if (in[i] == '\\') {
                if (i + 1 >= len ||
                    (in[i + 1] != '"' && in[i + 1] != '\\'))
                    return WTQ_SF_MALFORMED;
                i += 2;
            } else if (in[i] == '"') {
                *off = i + 1;
                return WTQ_SF_OK;
            } else {
                unsigned char u = (unsigned char)in[i];
                if (u < 0x20 || u > 0x7e)
                    return WTQ_SF_MALFORMED;
                i++;
            }
        }
        return WTQ_SF_MALFORMED;
    }
    if (c == ':') {
        /* byte sequence: ':' *base64 ':' — RFC 8941 s3.3.5 restricts the
         * content to the base64 alphabet */
        i++;
        while (i < len && is_base64_char(in[i]))
            i++;
        if (i >= len || in[i] != ':')
            return WTQ_SF_MALFORMED;
        *off = i + 1;
        return WTQ_SF_OK;
    }
    if (c == '?') {
        /* boolean: ?0 / ?1 */
        if (i + 1 >= len || (in[i + 1] != '0' && in[i + 1] != '1'))
            return WTQ_SF_MALFORMED;
        *off = i + 2;
        return WTQ_SF_OK;
    }
    if (c == '-' || is_digit(c)) {
        /* sf-integer: ["-"] 1*15DIGIT
         * sf-decimal: ["-"] 1*12DIGIT "." 1*3DIGIT  (RFC 8941 s3.3.1/2) */
        if (c == '-')
            i++;
        size_t int_start = i;
        while (i < len && is_digit(in[i]))
            i++;
        size_t int_digits = i - int_start;
        if (int_digits == 0)
            return WTQ_SF_MALFORMED; /* bare "-" */
        if (i < len && in[i] == '.') {
            if (int_digits > 12)
                return WTQ_SF_MALFORMED;
            i++;
            size_t frac_start = i;
            while (i < len && is_digit(in[i]))
                i++;
            size_t frac_digits = i - frac_start;
            if (frac_digits == 0 || frac_digits > 3)
                return WTQ_SF_MALFORMED; /* "1." or too precise */
        } else if (int_digits > 15) {
            return WTQ_SF_MALFORMED;
        }
        *off = i;
        return WTQ_SF_OK;
    }
    if (is_alpha(c) || c == '*') {
        /* token */
        i++;
        while (i < len && is_token_char(in[i]))
            i++;
        *off = i;
        return WTQ_SF_OK;
    }
    return WTQ_SF_MALFORMED;
}

/* Skip parameters: *( ";" *SP key [ "=" bare-item ] ). draft-15:
 * parameters carry no semantics and MUST be ignored — but they must
 * still PARSE, else the field is malformed. */
static wtq_sf_status_t skip_params(const char *in, size_t len, size_t *off)
{
    size_t i = *off;

    while (i < len && in[i] == ';') {
        i++;
        while (i < len && in[i] == ' ')
            i++;
        /* key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" /
         *         "." / "*" ) */
        if (i >= len || !(is_lcalpha(in[i]) || in[i] == '*'))
            return WTQ_SF_MALFORMED;
        i++;
        while (i < len &&
               (is_lcalpha(in[i]) || is_digit(in[i]) || in[i] == '_' ||
                in[i] == '-' || in[i] == '.' || in[i] == '*'))
            i++;
        if (i < len && in[i] == '=') {
            i++;
            wtq_sf_status_t st = skip_bare_item(in, len, &i);
            if (st != WTQ_SF_OK)
                return st;
        }
    }
    *off = i;
    return WTQ_SF_OK;
}

/* Parse one list member that must be a String (plus ignored params). */
static wtq_sf_status_t parse_member(const char *in, size_t len, size_t *off,
                                    bool lenient_tokens, char *out_buf,
                                    size_t out_cap, size_t *out_off,
                                    wtq_sf_str_t *out)
{
    wtq_sf_status_t st;

    if (*off < len && in[*off] == '(')
        return WTQ_SF_MALFORMED; /* inner list: wrong type */

    if (*off < len && in[*off] == '"')
        st = parse_string(in, len, off, out_buf, out_cap, out_off, out);
    else if (lenient_tokens)
        st = parse_token_lenient(in, len, off, out_buf, out_cap, out_off,
                                 out);
    else
        return WTQ_SF_MALFORMED; /* non-String type */

    if (st != WTQ_SF_OK)
        return st;
    return skip_params(in, len, off);
}

wtq_sf_status_t wtq_sf_string_parse_item(const char *in, size_t len,
                                         bool lenient_tokens,
                                         char *out_buf, size_t out_cap,
                                         wtq_sf_str_t *out)
{
    size_t off = 0;
    size_t out_off = 0;
    wtq_sf_str_t v = { NULL, 0 };

    skip_sp(in, len, &off);
    wtq_sf_status_t st = parse_member(in, len, &off, lenient_tokens,
                                      out_buf, out_cap, &out_off, &v);
    if (st != WTQ_SF_OK)
        return st;
    skip_sp(in, len, &off);
    if (off != len)
        return WTQ_SF_MALFORMED; /* trailing junk */

    *out = v;
    return WTQ_SF_OK;
}

wtq_sf_status_t wtq_sf_string_parse_list(const char *in, size_t len,
                                         bool lenient_tokens,
                                         char *out_buf, size_t out_cap,
                                         wtq_sf_str_t *members,
                                         size_t max_members,
                                         size_t *out_count)
{
    size_t off = 0;
    size_t out_off = 0;
    size_t count = 0;

    skip_sp(in, len, &off);
    while (off < len) {
        wtq_sf_str_t v = { NULL, 0 };
        wtq_sf_status_t st = parse_member(in, len, &off, lenient_tokens,
                                          out_buf, out_cap, &out_off, &v);
        if (st != WTQ_SF_OK)
            return st;
        if (count >= max_members)
            return WTQ_SF_BUFFER;
        members[count++] = v;

        skip_ows(in, len, &off);
        if (off == len)
            break;
        if (in[off] != ',')
            return WTQ_SF_MALFORMED;
        off++;
        skip_ows(in, len, &off);
        if (off == len)
            return WTQ_SF_MALFORMED; /* trailing comma */
    }

    *out_count = count;
    return WTQ_SF_OK;
}

/* --- encoding --------------------------------------------------------- */

static size_t encoded_item_len(const char *s, size_t len)
{
    size_t n = 2; /* quotes */

    for (size_t i = 0; i < len; i++)
        n += (s[i] == '"' || s[i] == '\\') ? 2 : 1;
    return n;
}

wtq_sf_status_t wtq_sf_string_encode_item(const char *s, size_t len,
                                          char *dst, size_t cap,
                                          size_t *out_len)
{
    if (!wtq_sf_string_valid(s, len))
        return WTQ_SF_MALFORMED;

    size_t need = encoded_item_len(s, len);
    if (cap < need)
        return WTQ_SF_BUFFER;

    size_t o = 0;
    dst[o++] = '"';
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '"' || s[i] == '\\')
            dst[o++] = '\\';
        dst[o++] = s[i];
    }
    dst[o++] = '"';

    *out_len = o;
    return WTQ_SF_OK;
}

wtq_sf_status_t wtq_sf_string_encode_list(const wtq_sf_str_t *members,
                                          size_t count, char *dst,
                                          size_t cap, size_t *out_len)
{
    if (count == 0)
        return WTQ_SF_MALFORMED; /* empty list = omit the field */

    size_t need = 0;
    for (size_t i = 0; i < count; i++) {
        if (!wtq_sf_string_valid(members[i].data, members[i].len))
            return WTQ_SF_MALFORMED;
        need += encoded_item_len(members[i].data, members[i].len);
        if (i + 1 < count)
            need += 2; /* ", " */
    }
    if (cap < need)
        return WTQ_SF_BUFFER;

    size_t o = 0;
    for (size_t i = 0; i < count; i++) {
        size_t n = 0;
        (void)wtq_sf_string_encode_item(members[i].data, members[i].len,
                                        dst + o, cap - o, &n);
        o += n;
        if (i + 1 < count) {
            dst[o++] = ',';
            dst[o++] = ' ';
        }
    }

    *out_len = o;
    return WTQ_SF_OK;
}

bool wtq_sf_string_select(const wtq_sf_str_t *offered, size_t offered_count,
                          const wtq_sf_str_t *supported,
                          size_t supported_count,
                          size_t *out_offered_index)
{
    for (size_t i = 0; i < offered_count; i++) {
        for (size_t j = 0; j < supported_count; j++) {
            if (offered[i].len == supported[j].len &&
                (offered[i].len == 0 ||
                 memcmp(offered[i].data, supported[j].data,
                        offered[i].len) == 0)) {
                *out_offered_index = i;
                return true;
            }
        }
    }
    return false;
}
