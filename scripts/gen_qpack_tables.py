#!/usr/bin/env python3
"""Generate src/proto/qpack_tables.inc — QPACK static table + RFC 7541
Huffman decode tables for wtquic.

Data provenance (extracted mechanically from the checked-out sources, never
transcribed from memory):

  QPACK_STATIC — RFC 9204 Appendix A (QPACK static table, 99 entries),
      extracted from Google QUICHE:
      QUIC/quiche/quiche/quic/core/qpack/qpack_static_table.cc

  HUFF — RFC 7541 Appendix B (HPACK Huffman code, 257 codes: 256 symbols
      + EOS), extracted from Google QUICHE:
      QUIC/quiche/quiche/http2/hpack/huffman/huffman_spec_tables.cc
      (kCodeLengths / kRightCodes; kLeftCodes was verified consistent with
      these at extraction time: left == right << (32 - length))

  H3ZERO_STATIC / H3ZERO_HUFF_BIT / H3ZERO_HUFF_VAL — independent
      cross-check source, extracted from picoquic h3zero:
      picoquic/picohttp/h3zero.c (qpack_static[],
      h3zero_qpack_huffman_bit[64], h3zero_qpack_huffman_val[512]).
      h3zero encodes static-table names as http_header_* enums; the
      enum-name -> header-name mapping is mechanical (strip prefix,
      '_' -> '-', pseudo-headers get a ':' prefix) and is applied in
      h3zero_header_name() below.

Every run re-verifies the embedded data:
  * QPACK static table: 99 entries, spot checks, and a full 99/99
    cross-check against the h3zero table (hard error on any mismatch).
  * Huffman: 257 codes, full canonical-code-space check (within a length
    codes are consecutive; across lengths next_first ==
    (prev_last + 1) << (next_bits - prev_bits); code space is exactly
    covered ending at the all-ones 30-bit EOS), spot checks, and a full
    256/256 cross-check by walking every code through the embedded h3zero
    decode tree (plus a check that EOS escapes the tree, i.e. h3zero also
    treats EOS as non-decodable).

Output is deterministic: rerunning reproduces the committed
src/proto/qpack_tables.inc byte-identically.

Usage:
    python3 scripts/gen_qpack_tables.py            # write to stdout
    python3 scripts/gen_qpack_tables.py -o FILE    # write to FILE
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# Embedded data (see provenance above)
# ---------------------------------------------------------------------------

QPACK_STATIC = [
    (':authority', ''),
    (':path', '/'),
    ('age', '0'),
    ('content-disposition', ''),
    ('content-length', '0'),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('referer', ''),
    ('set-cookie', ''),
    (':method', 'CONNECT'),
    (':method', 'DELETE'),
    (':method', 'GET'),
    (':method', 'HEAD'),
    (':method', 'OPTIONS'),
    (':method', 'POST'),
    (':method', 'PUT'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '103'),
    (':status', '200'),
    (':status', '304'),
    (':status', '404'),
    (':status', '503'),
    ('accept', '*/*'),
    ('accept', 'application/dns-message'),
    ('accept-encoding', 'gzip, deflate, br'),
    ('accept-ranges', 'bytes'),
    ('access-control-allow-headers', 'cache-control'),
    ('access-control-allow-headers', 'content-type'),
    ('access-control-allow-origin', '*'),
    ('cache-control', 'max-age=0'),
    ('cache-control', 'max-age=2592000'),
    ('cache-control', 'max-age=604800'),
    ('cache-control', 'no-cache'),
    ('cache-control', 'no-store'),
    ('cache-control', 'public, max-age=31536000'),
    ('content-encoding', 'br'),
    ('content-encoding', 'gzip'),
    ('content-type', 'application/dns-message'),
    ('content-type', 'application/javascript'),
    ('content-type', 'application/json'),
    ('content-type', 'application/x-www-form-urlencoded'),
    ('content-type', 'image/gif'),
    ('content-type', 'image/jpeg'),
    ('content-type', 'image/png'),
    ('content-type', 'text/css'),
    ('content-type', 'text/html; charset=utf-8'),
    ('content-type', 'text/plain'),
    ('content-type', 'text/plain;charset=utf-8'),
    ('range', 'bytes=0-'),
    ('strict-transport-security', 'max-age=31536000'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains; preload'),
    ('vary', 'accept-encoding'),
    ('vary', 'origin'),
    ('x-content-type-options', 'nosniff'),
    ('x-xss-protection', '1; mode=block'),
    (':status', '100'),
    (':status', '204'),
    (':status', '206'),
    (':status', '302'),
    (':status', '400'),
    (':status', '403'),
    (':status', '421'),
    (':status', '425'),
    (':status', '500'),
    ('accept-language', ''),
    ('access-control-allow-credentials', 'FALSE'),
    ('access-control-allow-credentials', 'TRUE'),
    ('access-control-allow-headers', '*'),
    ('access-control-allow-methods', 'get'),
    ('access-control-allow-methods', 'get, post, options'),
    ('access-control-allow-methods', 'options'),
    ('access-control-expose-headers', 'content-length'),
    ('access-control-request-headers', 'content-type'),
    ('access-control-request-method', 'get'),
    ('access-control-request-method', 'post'),
    ('alt-svc', 'clear'),
    ('authorization', ''),
    ('content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ('early-data', '1'),
    ('expect-ct', ''),
    ('forwarded', ''),
    ('if-range', ''),
    ('origin', ''),
    ('purpose', 'prefetch'),
    ('server', ''),
    ('timing-allow-origin', '*'),
    ('upgrade-insecure-requests', '1'),
    ('user-agent', ''),
    ('x-forwarded-for', ''),
    ('x-frame-options', 'deny'),
    ('x-frame-options', 'sameorigin'),
]

HUFF = [  # (length_bits, code) per symbol 0..256 (256 = EOS)
    (13, 0x00001ff8),
    (23, 0x007fffd8),
    (28, 0x0fffffe2),
    (28, 0x0fffffe3),
    (28, 0x0fffffe4),
    (28, 0x0fffffe5),
    (28, 0x0fffffe6),
    (28, 0x0fffffe7),
    (28, 0x0fffffe8),
    (24, 0x00ffffea),
    (30, 0x3ffffffc),
    (28, 0x0fffffe9),
    (28, 0x0fffffea),
    (30, 0x3ffffffd),
    (28, 0x0fffffeb),
    (28, 0x0fffffec),
    (28, 0x0fffffed),
    (28, 0x0fffffee),
    (28, 0x0fffffef),
    (28, 0x0ffffff0),
    (28, 0x0ffffff1),
    (28, 0x0ffffff2),
    (30, 0x3ffffffe),
    (28, 0x0ffffff3),
    (28, 0x0ffffff4),
    (28, 0x0ffffff5),
    (28, 0x0ffffff6),
    (28, 0x0ffffff7),
    (28, 0x0ffffff8),
    (28, 0x0ffffff9),
    (28, 0x0ffffffa),
    (28, 0x0ffffffb),
    (6, 0x00000014),
    (10, 0x000003f8),
    (10, 0x000003f9),
    (12, 0x00000ffa),
    (13, 0x00001ff9),
    (6, 0x00000015),
    (8, 0x000000f8),
    (11, 0x000007fa),
    (10, 0x000003fa),
    (10, 0x000003fb),
    (8, 0x000000f9),
    (11, 0x000007fb),
    (8, 0x000000fa),
    (6, 0x00000016),
    (6, 0x00000017),
    (6, 0x00000018),
    (5, 0x00000000),
    (5, 0x00000001),
    (5, 0x00000002),
    (6, 0x00000019),
    (6, 0x0000001a),
    (6, 0x0000001b),
    (6, 0x0000001c),
    (6, 0x0000001d),
    (6, 0x0000001e),
    (6, 0x0000001f),
    (7, 0x0000005c),
    (8, 0x000000fb),
    (15, 0x00007ffc),
    (6, 0x00000020),
    (12, 0x00000ffb),
    (10, 0x000003fc),
    (13, 0x00001ffa),
    (6, 0x00000021),
    (7, 0x0000005d),
    (7, 0x0000005e),
    (7, 0x0000005f),
    (7, 0x00000060),
    (7, 0x00000061),
    (7, 0x00000062),
    (7, 0x00000063),
    (7, 0x00000064),
    (7, 0x00000065),
    (7, 0x00000066),
    (7, 0x00000067),
    (7, 0x00000068),
    (7, 0x00000069),
    (7, 0x0000006a),
    (7, 0x0000006b),
    (7, 0x0000006c),
    (7, 0x0000006d),
    (7, 0x0000006e),
    (7, 0x0000006f),
    (7, 0x00000070),
    (7, 0x00000071),
    (7, 0x00000072),
    (8, 0x000000fc),
    (7, 0x00000073),
    (8, 0x000000fd),
    (13, 0x00001ffb),
    (19, 0x0007fff0),
    (13, 0x00001ffc),
    (14, 0x00003ffc),
    (6, 0x00000022),
    (15, 0x00007ffd),
    (5, 0x00000003),
    (6, 0x00000023),
    (5, 0x00000004),
    (6, 0x00000024),
    (5, 0x00000005),
    (6, 0x00000025),
    (6, 0x00000026),
    (6, 0x00000027),
    (5, 0x00000006),
    (7, 0x00000074),
    (7, 0x00000075),
    (6, 0x00000028),
    (6, 0x00000029),
    (6, 0x0000002a),
    (5, 0x00000007),
    (6, 0x0000002b),
    (7, 0x00000076),
    (6, 0x0000002c),
    (5, 0x00000008),
    (5, 0x00000009),
    (6, 0x0000002d),
    (7, 0x00000077),
    (7, 0x00000078),
    (7, 0x00000079),
    (7, 0x0000007a),
    (7, 0x0000007b),
    (15, 0x00007ffe),
    (11, 0x000007fc),
    (14, 0x00003ffd),
    (13, 0x00001ffd),
    (28, 0x0ffffffc),
    (20, 0x000fffe6),
    (22, 0x003fffd2),
    (20, 0x000fffe7),
    (20, 0x000fffe8),
    (22, 0x003fffd3),
    (22, 0x003fffd4),
    (22, 0x003fffd5),
    (23, 0x007fffd9),
    (22, 0x003fffd6),
    (23, 0x007fffda),
    (23, 0x007fffdb),
    (23, 0x007fffdc),
    (23, 0x007fffdd),
    (23, 0x007fffde),
    (24, 0x00ffffeb),
    (23, 0x007fffdf),
    (24, 0x00ffffec),
    (24, 0x00ffffed),
    (22, 0x003fffd7),
    (23, 0x007fffe0),
    (24, 0x00ffffee),
    (23, 0x007fffe1),
    (23, 0x007fffe2),
    (23, 0x007fffe3),
    (23, 0x007fffe4),
    (21, 0x001fffdc),
    (22, 0x003fffd8),
    (23, 0x007fffe5),
    (22, 0x003fffd9),
    (23, 0x007fffe6),
    (23, 0x007fffe7),
    (24, 0x00ffffef),
    (22, 0x003fffda),
    (21, 0x001fffdd),
    (20, 0x000fffe9),
    (22, 0x003fffdb),
    (22, 0x003fffdc),
    (23, 0x007fffe8),
    (23, 0x007fffe9),
    (21, 0x001fffde),
    (23, 0x007fffea),
    (22, 0x003fffdd),
    (22, 0x003fffde),
    (24, 0x00fffff0),
    (21, 0x001fffdf),
    (22, 0x003fffdf),
    (23, 0x007fffeb),
    (23, 0x007fffec),
    (21, 0x001fffe0),
    (21, 0x001fffe1),
    (22, 0x003fffe0),
    (21, 0x001fffe2),
    (23, 0x007fffed),
    (22, 0x003fffe1),
    (23, 0x007fffee),
    (23, 0x007fffef),
    (20, 0x000fffea),
    (22, 0x003fffe2),
    (22, 0x003fffe3),
    (22, 0x003fffe4),
    (23, 0x007ffff0),
    (22, 0x003fffe5),
    (22, 0x003fffe6),
    (23, 0x007ffff1),
    (26, 0x03ffffe0),
    (26, 0x03ffffe1),
    (20, 0x000fffeb),
    (19, 0x0007fff1),
    (22, 0x003fffe7),
    (23, 0x007ffff2),
    (22, 0x003fffe8),
    (25, 0x01ffffec),
    (26, 0x03ffffe2),
    (26, 0x03ffffe3),
    (26, 0x03ffffe4),
    (27, 0x07ffffde),
    (27, 0x07ffffdf),
    (26, 0x03ffffe5),
    (24, 0x00fffff1),
    (25, 0x01ffffed),
    (19, 0x0007fff2),
    (21, 0x001fffe3),
    (26, 0x03ffffe6),
    (27, 0x07ffffe0),
    (27, 0x07ffffe1),
    (26, 0x03ffffe7),
    (27, 0x07ffffe2),
    (24, 0x00fffff2),
    (21, 0x001fffe4),
    (21, 0x001fffe5),
    (26, 0x03ffffe8),
    (26, 0x03ffffe9),
    (28, 0x0ffffffd),
    (27, 0x07ffffe3),
    (27, 0x07ffffe4),
    (27, 0x07ffffe5),
    (20, 0x000fffec),
    (24, 0x00fffff3),
    (20, 0x000fffed),
    (21, 0x001fffe6),
    (22, 0x003fffe9),
    (21, 0x001fffe7),
    (21, 0x001fffe8),
    (23, 0x007ffff3),
    (22, 0x003fffea),
    (22, 0x003fffeb),
    (25, 0x01ffffee),
    (25, 0x01ffffef),
    (24, 0x00fffff4),
    (24, 0x00fffff5),
    (26, 0x03ffffea),
    (23, 0x007ffff4),
    (26, 0x03ffffeb),
    (27, 0x07ffffe6),
    (26, 0x03ffffec),
    (26, 0x03ffffed),
    (27, 0x07ffffe7),
    (27, 0x07ffffe8),
    (27, 0x07ffffe9),
    (27, 0x07ffffea),
    (27, 0x07ffffeb),
    (28, 0x0ffffffe),
    (27, 0x07ffffec),
    (27, 0x07ffffed),
    (27, 0x07ffffee),
    (27, 0x07ffffef),
    (27, 0x07fffff0),
    (26, 0x03ffffee),
    (30, 0x3fffffff),
]

H3ZERO_STATIC = [  # (index, name_enum, value or None)
    (0, 'http_pseudo_header_authority', None),
    (1, 'http_pseudo_header_path', '/'),
    (2, 'http_header_age', '0'),
    (3, 'http_header_content_disposition', None),
    (4, 'http_header_content_length', '0'),
    (5, 'http_header_cookie', None),
    (6, 'http_header_date', None),
    (7, 'http_header_etag', None),
    (8, 'http_header_if_modified_since', None),
    (9, 'http_header_if_none_match', None),
    (10, 'http_header_last_modified', None),
    (11, 'http_header_link', None),
    (12, 'http_header_location', None),
    (13, 'http_header_referer', None),
    (14, 'http_header_set_cookie', None),
    (15, 'http_pseudo_header_method', 'CONNECT'),
    (16, 'http_pseudo_header_method', 'DELETE'),
    (17, 'http_pseudo_header_method', 'GET'),
    (18, 'http_pseudo_header_method', 'HEAD'),
    (19, 'http_pseudo_header_method', 'OPTIONS'),
    (20, 'http_pseudo_header_method', 'POST'),
    (21, 'http_pseudo_header_method', 'PUT'),
    (22, 'http_pseudo_header_scheme', 'http'),
    (23, 'http_pseudo_header_scheme', 'https'),
    (24, 'http_pseudo_header_status', '103'),
    (25, 'http_pseudo_header_status', '200'),
    (26, 'http_pseudo_header_status', '304'),
    (27, 'http_pseudo_header_status', '404'),
    (28, 'http_pseudo_header_status', '503'),
    (29, 'http_header_accept', '*/*'),
    (30, 'http_header_accept', 'application/dns-message'),
    (31, 'http_header_accept_encoding', 'gzip, deflate, br'),
    (32, 'http_header_accept_ranges', 'bytes'),
    (33, 'http_header_access_control_allow_headers', 'cache-control'),
    (34, 'http_header_access_control_allow_headers', 'content-type'),
    (35, 'http_header_access_control_allow_origin', '*'),
    (36, 'http_header_cache_control', 'max-age=0'),
    (37, 'http_header_cache_control', 'max-age=2592000'),
    (38, 'http_header_cache_control', 'max-age=604800'),
    (39, 'http_header_cache_control', 'no-cache'),
    (40, 'http_header_cache_control', 'no-store'),
    (41, 'http_header_cache_control', 'public, max-age=31536000'),
    (42, 'http_header_content_encoding', 'br'),
    (43, 'http_header_content_encoding', 'gzip'),
    (44, 'http_header_content_type', 'application/dns-message'),
    (45, 'http_header_content_type', 'application/javascript'),
    (46, 'http_header_content_type', 'application/json'),
    (47, 'http_header_content_type', 'application/x-www-form-urlencoded'),
    (48, 'http_header_content_type', 'image/gif'),
    (49, 'http_header_content_type', 'image/jpeg'),
    (50, 'http_header_content_type', 'image/png'),
    (51, 'http_header_content_type', 'text/css'),
    (52, 'http_header_content_type', 'text/html; charset=utf-8'),
    (53, 'http_header_content_type', 'text/plain'),
    (54, 'http_header_content_type', 'text/plain;charset=utf-8'),
    (55, 'http_header_range', 'bytes=0-'),
    (56, 'http_header_strict_transport_security', 'max-age=31536000'),
    (57, 'http_header_strict_transport_security', 'max-age=31536000; includesubdomains'),
    (58, 'http_header_strict_transport_security', 'max-age=31536000; includesubdomains; preload'),
    (59, 'http_header_vary', 'accept-encoding'),
    (60, 'http_header_vary', 'origin'),
    (61, 'http_header_x_content_type_options', 'nosniff'),
    (62, 'http_header_x_xss_protection', '1; mode=block'),
    (63, 'http_pseudo_header_status', '100'),
    (64, 'http_pseudo_header_status', '204'),
    (65, 'http_pseudo_header_status', '206'),
    (66, 'http_pseudo_header_status', '302'),
    (67, 'http_pseudo_header_status', '400'),
    (68, 'http_pseudo_header_status', '403'),
    (69, 'http_pseudo_header_status', '421'),
    (70, 'http_pseudo_header_status', '425'),
    (71, 'http_pseudo_header_status', '500'),
    (72, 'http_header_accept_language', None),
    (73, 'http_header_access_control_allow_credentials', 'FALSE'),
    (74, 'http_header_access_control_allow_credentials', 'TRUE'),
    (75, 'http_header_access_control_allow_headers', '*'),
    (76, 'http_header_access_control_allow_methods', 'get'),
    (77, 'http_header_access_control_allow_methods', 'get, post, options'),
    (78, 'http_header_access_control_allow_methods', 'options'),
    (79, 'http_header_access_control_expose_headers', 'content-length'),
    (80, 'http_header_access_control_request_headers', 'content-type'),
    (81, 'http_header_access_control_request_method', 'get'),
    (82, 'http_header_access_control_request_method', 'post'),
    (83, 'http_header_alt_svc', 'clear'),
    (84, 'http_header_authorization', None),
    (85, 'http_header_content_security_policy', "script-src 'none'; object-src 'none'; base-uri 'none'"),
    (86, 'http_header_early_data', '1'),
    (87, 'http_header_expect_ct', None),
    (88, 'http_header_forwarded', None),
    (89, 'http_header_if_range', None),
    (90, 'http_header_origin', None),
    (91, 'http_header_purpose', 'prefetch'),
    (92, 'http_header_server', None),
    (93, 'http_header_timing_allow_origin', '*'),
    (94, 'http_header_upgrade_insecure_requests', '1'),
    (95, 'http_header_user_agent', None),
    (96, 'http_header_x_forwarded_for', None),
    (97, 'http_header_x_frame_options', 'deny'),
    (98, 'http_header_x_frame_options', 'sameorigin'),
]

H3ZERO_HUFF_BIT = [
    249, 50, 115, 39, 38, 79, 147, 39, 38, 100, 249, 50, 114, 100, 242, 100,
    228, 228, 206, 77, 52, 228, 204, 203, 202, 114, 102, 79, 147, 39, 76, 156,
    153, 62, 76, 156, 156, 153, 62, 76, 156, 153, 60, 154, 100, 242, 102, 79,
    147, 39, 38, 83, 228, 201, 201, 147, 211, 39, 38, 79, 38, 78, 76, 178,
]

H3ZERO_HUFF_VAL = [
    44, 16, 8, 4, 2, 48, 49, 2, 50, 97, 4, 2, 99, 101, 2, 105,
    111, 12, 4, 2, 115, 116, 4, 2, 32, 37, 2, 45, 46, 8, 4, 2,
    47, 51, 2, 52, 53, 4, 2, 54, 55, 2, 56, 57, 36, 16, 8, 4,
    2, 61, 65, 2, 95, 98, 4, 2, 100, 102, 2, 103, 104, 8, 4, 2,
    108, 109, 2, 110, 112, 4, 2, 114, 117, 4, 2, 58, 66, 2, 67, 68,
    32, 16, 8, 4, 2, 69, 70, 2, 71, 72, 4, 2, 73, 74, 2, 75,
    76, 8, 4, 2, 77, 78, 2, 79, 80, 4, 2, 81, 82, 2, 83, 84,
    16, 8, 4, 2, 85, 86, 2, 87, 89, 4, 2, 106, 107, 2, 113, 118,
    8, 4, 2, 119, 120, 2, 121, 122, 8, 4, 2, 38, 42, 2, 44, 59,
    4, 2, 88, 90, 8, 4, 2, 33, 34, 2, 40, 41, 6, 2, 63, 2,
    39, 43, 6, 2, 124, 2, 35, 62, 8, 4, 2, 0, 36, 2, 64, 91,
    4, 2, 93, 126, 4, 2, 94, 125, 4, 2, 60, 96, 2, 123, 30, 10,
    4, 2, 92, 195, 2, 208, 2, 128, 130, 8, 4, 2, 131, 162, 2, 184,
    194, 4, 2, 224, 226, 4, 2, 153, 161, 2, 167, 172, 46, 16, 8, 4,
    2, 176, 177, 2, 179, 209, 4, 2, 216, 217, 2, 227, 229, 14, 6, 2,
    230, 2, 129, 132, 4, 2, 133, 134, 2, 136, 146, 8, 4, 2, 154, 156,
    2, 160, 163, 4, 2, 164, 169, 2, 170, 173, 40, 16, 8, 4, 2, 178,
    181, 2, 185, 186, 4, 2, 187, 189, 2, 190, 196, 8, 4, 2, 198, 228,
    2, 232, 233, 8, 4, 2, 1, 135, 2, 137, 138, 4, 2, 139, 140, 2,
    141, 143, 32, 16, 8, 4, 2, 147, 149, 2, 150, 151, 4, 2, 152, 155,
    2, 157, 158, 8, 4, 2, 165, 166, 2, 168, 174, 4, 2, 175, 180, 2,
    182, 183, 22, 8, 4, 2, 188, 191, 2, 197, 231, 6, 2, 239, 2, 9,
    142, 4, 2, 144, 145, 2, 148, 159, 20, 8, 4, 2, 171, 206, 2, 215,
    225, 4, 2, 236, 237, 4, 2, 199, 207, 2, 234, 235, 34, 16, 8, 4,
    2, 192, 193, 2, 200, 201, 4, 2, 202, 205, 2, 210, 213, 8, 4, 2,
    218, 219, 2, 238, 240, 4, 2, 242, 243, 2, 255, 2, 203, 204, 32, 16,
    8, 4, 2, 211, 212, 2, 214, 221, 4, 2, 222, 223, 2, 241, 244, 8,
    4, 2, 245, 246, 2, 247, 248, 4, 2, 250, 251, 2, 252, 253, 30, 14,
    6, 2, 254, 2, 2, 3, 4, 2, 4, 5, 2, 6, 7, 8, 4, 2,
    8, 11, 2, 12, 14, 4, 2, 15, 16, 2, 17, 18, 16, 8, 4, 2,
    19, 20, 2, 21, 23, 4, 2, 24, 25, 2, 26, 27, 8, 4, 2, 28,
    29, 2, 30, 31, 4, 2, 127, 220, 2, 249, 4, 2, 10, 13, 2, 22,
]

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def fail(msg):
    sys.stderr.write("FATAL: %s\n" % msg)
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def h3zero_header_name(enum_name):
    """Mechanical h3zero http_header_* enum -> header-name string."""
    if enum_name.startswith("http_pseudo_header_"):
        return ":" + enum_name[len("http_pseudo_header_"):].replace("_", "-")
    check(enum_name.startswith("http_header_"),
          "unrecognized h3zero enum %r" % enum_name)
    return enum_name[len("http_header_"):].replace("_", "-")


def verify_static(report):
    check(len(QPACK_STATIC) == 99,
          "static table has %d entries, want 99" % len(QPACK_STATIC))

    spots = {
        0: (":authority", ""),
        1: (":path", "/"),
        15: (":method", "CONNECT"),
        17: (":method", "GET"),
        23: (":scheme", "https"),
        25: (":status", "200"),
        90: ("origin", ""),
    }
    for idx, want in sorted(spots.items()):
        got = QPACK_STATIC[idx]
        check(got == want,
              "static[%d] = %r, want %r" % (idx, got, want))
        report.append("static[%d] = (%r, %r)  OK" % (idx, got[0], got[1]))
    report.append("static[98] (last) = (%r, %r)"
                  % (QPACK_STATIC[98][0], QPACK_STATIC[98][1]))

    for i, (n, v) in enumerate(QPACK_STATIC):
        check(len(n) > 0, "static[%d] has empty name" % i)
        for s in (n, v):
            check(all(0x20 <= ord(c) <= 0x7E for c in s),
                  "static[%d] contains non-printable/non-ASCII byte" % i)
            check('"' not in s and "\\" not in s,
                  "static[%d] contains quote/backslash" % i)

    # Full cross-check against picoquic h3zero (independent source).
    check(len(H3ZERO_STATIC) == 99,
          "h3zero table has %d entries, want 99" % len(H3ZERO_STATIC))
    for i, (idx, enum_name, val) in enumerate(H3ZERO_STATIC):
        check(idx == i, "h3zero table not positional at %d" % i)
        name = h3zero_header_name(enum_name)
        value = "" if val is None else val
        got = QPACK_STATIC[i]
        check(got == (name, value),
              "CROSS-CHECK MISMATCH static[%d]: quiche=%r h3zero=%r"
              % (i, got, (name, value)))
    report.append("static cross-check vs h3zero: 99/99 entries match")


def h3zero_decode_one(length, code):
    """Walk one (length, code) through the h3zero decode tree.

    Returns the decoded symbol, or None if the walk escapes the table
    (h3zero's end-of-string / EOS path). Mirrors
    hzero_qpack_huffman_decode() in picoquic/picohttp/h3zero.c.
    """
    idx = 0
    for bitpos in range(length - 1, -1, -1):
        check((H3ZERO_HUFF_BIT[idx >> 3] >> (7 - (idx & 7))) & 1 == 1,
              "h3zero walk hit a terminal mid-code (code 0x%x/%d)"
              % (code, length))
        if (code >> bitpos) & 1:
            idx += H3ZERO_HUFF_VAL[idx]
        else:
            idx += 1
        if idx >= 512:
            return None
    check((H3ZERO_HUFF_BIT[idx >> 3] >> (7 - (idx & 7))) & 1 == 0,
          "h3zero walk not terminal after full code (code 0x%x/%d)"
          % (code, length))
    return H3ZERO_HUFF_VAL[idx]


def verify_huffman(report):
    check(len(HUFF) == 257, "huffman table has %d codes, want 257" % len(HUFF))
    for sym, (length, code) in enumerate(HUFF):
        check(5 <= length <= 30, "symbol %d has length %d" % (sym, length))
        check(0 <= code < (1 << length),
              "symbol %d code 0x%x does not fit %d bits" % (sym, code, length))

    spots = [
        (0x30, "'0'", 5, 0b00000),
        (0x61, "'a'", 5, 0b00011),
        (0x20, "' '", 6, 0b010100),
        (256, "EOS", 30, 0x3FFFFFFF),
    ]
    for sym, label, wlen, wcode in spots:
        length, code = HUFF[sym]
        check((length, code) == (wlen, wcode),
              "huffman %s = 0x%x/%d, want 0x%x/%d"
              % (label, code, length, wcode, wlen))
        report.append("huffman %s = 0x%x / %d bits  OK" % (label, code, length))

    # Canonicity over the full 257-code set (EOS included): within a
    # length codes are consecutive; across lengths the code space is
    # exactly covered; the last code is all-ones.
    order = sorted(range(257), key=lambda s: (HUFF[s][0], HUFF[s][1]))
    check(HUFF[order[0]][1] == 0, "first canonical code is not 0")
    prev_len, prev_code = HUFF[order[0]]
    for sym in order[1:]:
        length, code = HUFF[sym]
        if length == prev_len:
            check(code == prev_code + 1,
                  "codes not consecutive at length %d (0x%x after 0x%x)"
                  % (length, code, prev_code))
        else:
            check(length > prev_len, "length ordering broken")
            check(code == (prev_code + 1) << (length - prev_len),
                  "code space gap: length %d first 0x%x, want 0x%x"
                  % (length, code, (prev_code + 1) << (length - prev_len)))
        prev_len, prev_code = length, code
    check(prev_code == (1 << prev_len) - 1,
          "canonical code space does not end all-ones")
    check(order[-1] == 256, "EOS is not the last canonical code")
    report.append("huffman canonicity: 257 codes exactly cover the code "
                  "space, EOS last")

    # Full cross-check against the h3zero decode tree.
    for sym in range(256):
        length, code = HUFF[sym]
        got = h3zero_decode_one(length, code)
        check(got == sym,
              "CROSS-CHECK MISMATCH huffman symbol %d: h3zero decodes %r"
              % (sym, got))
    check(h3zero_decode_one(*HUFF[256]) is None,
          "h3zero unexpectedly decodes EOS to a symbol")
    report.append("huffman cross-check vs h3zero decode tree: "
                  "256/256 symbols match")
    report.append("huffman EOS escapes the h3zero tree (non-decodable)")


# ---------------------------------------------------------------------------
# Table construction
# ---------------------------------------------------------------------------


def build_decode_tables():
    """Return (symbols, length_rows) for the canonical decode tables.

    symbols: the 256 non-EOS symbols ordered by (length, code).
    length_rows: (bits, first_code, first_index, count) per bit length
    that has at least one non-EOS code, ascending by bits.
    """
    order = sorted(range(256), key=lambda s: (HUFF[s][0], HUFF[s][1]))
    rows = []
    i = 0
    while i < len(order):
        bits = HUFF[order[i]][0]
        j = i
        while j < len(order) and HUFF[order[j]][0] == bits:
            j += 1
        first_code = HUFF[order[i]][1]
        count = j - i
        for k in range(i, j):
            check(HUFF[order[k]][1] == first_code + (k - i),
                  "non-EOS codes not consecutive at length %d" % bits)
        rows.append((bits, first_code, i, count))
        i = j
    check(sum(r[3] for r in rows) == 256, "length rows do not cover 256")
    return order, rows


# ---------------------------------------------------------------------------
# C emission
# ---------------------------------------------------------------------------


def c_string(s):
    out = []
    for c in s:
        if c in ('"', "\\"):
            out.append("\\" + c)
        else:
            check(0x20 <= ord(c) <= 0x7E, "non-printable byte in %r" % s)
            out.append(c)
    return '"' + "".join(out) + '"'


def emit(report):
    symbols, length_rows = build_decode_tables()
    out = []
    w = out.append

    w("/* GENERATED by scripts/gen_qpack_tables.py -- DO NOT EDIT.")
    w(" *")
    w(" * QPACK static table (RFC 9204 Appendix A) and RFC 7541 Appendix B")
    w(" * canonical Huffman decode tables.")
    w(" *")
    w(" * Provenance (data extracted from local checkouts, cross-checked):")
    w(" *   QUIC/quiche/quiche/quic/core/qpack/qpack_static_table.cc")
    w(" *   QUIC/quiche/quiche/http2/hpack/huffman/huffman_spec_tables.cc")
    w(" *   picoquic/picohttp/h3zero.c (independent cross-check source)")
    w(" *")
    w(" * Cross-check summary (re-verified on every generator run):")
    for line in report:
        w(" *   " + line)
    w(" */")
    w("")
    w("/* The includer must define, before including this file:")
    w(" *")
    w(" *   typedef struct {")
    w(" *       const char *name;")
    w(" *       uint16_t    name_len;")
    w(" *       const char *value;")
    w(" *       uint16_t    value_len;")
    w(" *   } wtq_qpack_static_entry_t;")
    w(" *")
    w(" * and include <stdint.h>. This file defines only the data tables")
    w(" * below. Static-table index == array position (0..98). Empty values")
    w(" * are \"\" with length 0, never NULL.")
    w(" */")
    w("")
    w("static const wtq_qpack_static_entry_t wtq_qpack_static_table[99] = {")
    for i, (n, v) in enumerate(QPACK_STATIC):
        one = "    { %s, %d, %s, %d },  /* %d */" % (
            c_string(n), len(n), c_string(v), len(v), i)
        if len(one) <= 80:
            w(one)
        else:
            w("    /* %d */" % i)
            w("    { %s, %d," % (c_string(n), len(n)))
            val = "      %s, %d }," % (c_string(v), len(v))
            if len(val) <= 80:
                w(val)
            else:
                w("      %s," % c_string(v))
                w("      %d }," % len(v))
    w("};")
    w("")
    w("/* RFC 7541 Appendix B Huffman code, decode form. The code is")
    w(" * canonical: within a bit length, codes are consecutive and symbols")
    w(" * appear in code order. wtq_huff_symbols lists the 256 real symbols")
    w(" * ordered by (bit length, code); the 30-bit all-ones EOS code is")
    w(" * excluded (decoding it is an error per RFC 7541 Section 5.2)")
    w(" * and is handled via WTQ_HUFF_EOS_CODE/BITS below.")
    w(" */")
    w("static const uint8_t wtq_huff_symbols[256] = {")
    for i in range(0, 256, 12):
        row = symbols[i:i + 12]
        w("    " + " ".join("0x%02x," % s for s in row))
    w("};")
    w("")
    w("/* Per-bit-length decode rows, ascending by bits; only lengths with")
    w(" * at least one non-EOS code appear. first_code is the smallest")
    w(" * non-EOS code of that length; first_index indexes")
    w(" * wtq_huff_symbols; count excludes EOS.")
    w(" */")
    w("static const struct {")
    w("    uint8_t  bits;")
    w("    uint32_t first_code;")
    w("    uint16_t first_index;")
    w("    uint16_t count;")
    w("} wtq_huff_lengths[%d] = {" % len(length_rows))
    for bits, first_code, first_index, count in length_rows:
        w("    { %2d, 0x%08x, %3d, %2d }," % (bits, first_code, first_index,
                                              count))
    w("};")
    w("")
    w("#define WTQ_HUFF_EOS_CODE 0x3fffffff")
    w("#define WTQ_HUFF_EOS_BITS 30")
    return "\n".join(out) + "\n", length_rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--output", help="output file (default: stdout)")
    args = ap.parse_args()

    report = []
    verify_static(report)
    verify_huffman(report)
    text, length_rows = emit(report)

    for line in report:
        sys.stderr.write("verified: %s\n" % line)
    sys.stderr.write("per-length huffman summary (bits -> non-EOS count): %s\n"
                     % ", ".join("%d->%d" % (r[0], r[3])
                                 for r in length_rows))

    if args.output:
        with open(args.output, "w", encoding="ascii", newline="\n") as f:
            f.write(text)
        sys.stderr.write("wrote %s (%d bytes)\n"
                         % (args.output, len(text.encode("ascii"))))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
