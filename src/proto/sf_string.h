#ifndef WTQ_PROTO_SF_STRING_H
#define WTQ_PROTO_SF_STRING_H

/*
 * RFC 8941 Structured Fields helpers for WebTransport subprotocol
 * negotiation (draft-ietf-webtrans-http3-15 section 3.3):
 *
 *   WT-Available-Protocols  sf-list, members MUST be Strings
 *   WT-Protocol             sf-item, MUST be a String
 *
 * INTERNAL header — not installed, never included from public headers.
 *
 * SPEC NOTE (verified against the local draft, lines 547-553): the only
 * valid value type is a STRING — not a token. "Any value type other
 * than String MUST be treated as an error that causes the entire field
 * to be ignored"; parameters carry no semantics and "MUST be ignored"
 * (parsed and skipped, not rejected). WTQ_SF_MALFORMED therefore means
 * "the caller must behave as if the field were absent".
 *
 * INTEROP NOTE: picoquic's picowt is SF-naive — it emits and tokenizes
 * bare comma-separated values, so deployed peers may send tokens where
 * the spec requires quoted strings. The lenient_tokens flag (default
 * off; an explicit interop escape hatch) additionally accepts sf-token
 * members as if they were strings.
 *
 * Parsing writes unescaped member bytes into a caller-provided buffer
 * and returns spans into it (sf-strings may contain \" and \\ escapes,
 * so input slices alone cannot represent every value). This module
 * never allocates.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int wtq_sf_status_t;
#define WTQ_SF_OK        0
#define WTQ_SF_BUFFER    (-1) /* out_buf or member array too small */
#define WTQ_SF_MALFORMED (-2) /* malformed or non-String type: ignore the
                                 ENTIRE field (draft-15 rule) */

typedef struct wtq_sf_str {
    const char *data; /* into the caller's out_buf; NOT NUL-terminated */
    size_t len;
} wtq_sf_str_t;

/* True when s[len] is encodable as an sf-string: every byte in
 * %x20-7E (DQUOTE and backslash are legal — they get escaped). */
bool wtq_sf_string_valid(const char *s, size_t len);

/*
 * Encode one sf-string item: DQUOTE-delimited with minimal escaping.
 * On OK, *out_len bytes were written. dst untouched on error.
 * MALFORMED if the value contains bytes outside %x20-7E.
 */
wtq_sf_status_t wtq_sf_string_encode_item(const char *s, size_t len,
                                          char *dst, size_t cap,
                                          size_t *out_len);

/*
 * Encode an sf-list of strings, canonical RFC 8941 serialization:
 * members joined by ", ". count == 0 is MALFORMED (an empty list is
 * expressed by omitting the field entirely).
 */
wtq_sf_status_t wtq_sf_string_encode_list(const wtq_sf_str_t *members,
                                          size_t count, char *dst,
                                          size_t cap, size_t *out_len);

/*
 * Parse an sf-item that must be a String (WT-Protocol). Unescapes into
 * out_buf; *out points into out_buf. Item parameters are skipped.
 * Trailing non-SP input is MALFORMED.
 */
wtq_sf_status_t wtq_sf_string_parse_item(const char *in, size_t len,
                                         bool lenient_tokens,
                                         char *out_buf, size_t out_cap,
                                         wtq_sf_str_t *out);

/*
 * Parse an sf-list whose members must all be Strings
 * (WT-Available-Protocols). Members are unescaped into out_buf
 * back-to-back; members[i] point into out_buf, in wire order (client
 * preference order, most preferred first). Member parameters are
 * skipped. Empty input yields OK with *out_count == 0 (RFC 8941: an
 * empty field value parses to an empty list; the caller treats zero
 * offers as no negotiation). A missing member (",," or trailing comma)
 * or any non-String member is MALFORMED.
 * BUFFER when out_cap or max_members is insufficient.
 */
wtq_sf_status_t wtq_sf_string_parse_list(const char *in, size_t len,
                                         bool lenient_tokens,
                                         char *out_buf, size_t out_cap,
                                         wtq_sf_str_t *members,
                                         size_t max_members,
                                         size_t *out_count);

/*
 * Subprotocol selection: the first member of offered[] (client
 * preference order) that appears in supported[]. Case-sensitive
 * byte equality. Returns true and sets *out_offered_index on a match.
 */
bool wtq_sf_string_select(const wtq_sf_str_t *offered, size_t offered_count,
                          const wtq_sf_str_t *supported,
                          size_t supported_count,
                          size_t *out_offered_index);

#ifdef __cplusplus
}
#endif

#endif /* WTQ_PROTO_SF_STRING_H */
