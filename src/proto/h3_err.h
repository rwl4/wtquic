#ifndef WTQ_PROTO_H3_ERR_H
#define WTQ_PROTO_H3_ERR_H

/*
 * HTTP/3 connection error codes (RFC 9114 section 8.1; values verified
 * against picoquic h3zero.h lines 31-46) plus the RFC 9297 datagram
 * error.
 *
 * INTERNAL header — not installed.
 */

#define WTQ_H3_NO_ERROR                UINT64_C(0x0100)
#define WTQ_H3_GENERAL_PROTOCOL_ERROR  UINT64_C(0x0101)
#define WTQ_H3_INTERNAL_ERROR          UINT64_C(0x0102)
#define WTQ_H3_STREAM_CREATION_ERROR   UINT64_C(0x0103)
#define WTQ_H3_CLOSED_CRITICAL_STREAM  UINT64_C(0x0104)
#define WTQ_H3_FRAME_UNEXPECTED        UINT64_C(0x0105)
#define WTQ_H3_FRAME_ERROR             UINT64_C(0x0106)
#define WTQ_H3_EXCESSIVE_LOAD          UINT64_C(0x0107)
#define WTQ_H3_ID_ERROR                UINT64_C(0x0108)
#define WTQ_H3_SETTINGS_ERROR          UINT64_C(0x0109)
#define WTQ_H3_MISSING_SETTINGS        UINT64_C(0x010a)
#define WTQ_H3_REQUEST_REJECTED        UINT64_C(0x010b)
#define WTQ_H3_REQUEST_INCOMPLETE      UINT64_C(0x010d)
#define WTQ_H3_MESSAGE_ERROR           UINT64_C(0x010e)
#define WTQ_H3_DATAGRAM_ERROR          UINT64_C(0x33)

#endif /* WTQ_PROTO_H3_ERR_H */
