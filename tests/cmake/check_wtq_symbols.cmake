# Symbol policy: the shared library exports EXACTLY the pinned allowlist.
# A missing symbol is a visibility regression; an extra one is an
# unreviewed ABI addition. Grows only via reviewed edits to this file.
#
# Usage: cmake -DDYLIB=<path> -P check_wtq_symbols.cmake

if(POLICY CMP0057)
    cmake_policy(SET CMP0057 NEW)
endif()

if(NOT DEFINED DYLIB)
    message(FATAL_ERROR "pass -DDYLIB=<path to libwtquic>")
endif()

set(ALLOWED_SYMBOLS
    wtq_alloc_default
    wtq_app_error_to_h3
    wtq_h3_error_to_app
    wtq_strerror
    wtq_version
    # session/stream public API
    wtq_session_events_init
    wtq_connect_config_init
    wtq_connect_config_init_ex
    wtq_serve_config_init
    wtq_session_add_ref
    wtq_session_release
    wtq_session_close
    wtq_session_drain
    wtq_session_open_uni
    wtq_session_open_bidi
    wtq_session_send_datagram
    wtq_session_datagram_max_size
    wtq_session_status
    wtq_session_transport_error
    wtq_session_subprotocol
    wtq_session_set_user
    wtq_session_get_user
    wtq_stream_add_ref
    wtq_stream_release
    wtq_stream_send
    wtq_stream_reset
    wtq_stream_abort
    wtq_stream_stop_sending
    wtq_stream_pause_receive
    wtq_stream_resume_receive
    wtq_stream_id
    wtq_stream_is_bidi
    wtq_stream_is_local
    wtq_stream_session
    wtq_stream_set_user
    wtq_stream_get_user
    # backend seam (WTQ_SPI): exported for the backend libraries, which
    # link against the core across the shared-library boundary. NOT
    # public API — the declaring headers are never installed.
    wtq_api_session_create
    wtq_api_session_start
    wtq_api_session_connect
    wtq_api_session_serve
    wtq_api_session_conn
    wtq_api_session_enter
    wtq_api_session_leave
    wtq_session_events_copy
    wtq_conn_on_peer_uni_opened
    wtq_conn_on_peer_bidi_opened
    wtq_conn_on_stream_bytes
    wtq_conn_on_stream_reset
    wtq_conn_on_stream_terminal
    wtq_conn_on_stop_sending
    wtq_conn_on_stream_writable
    wtq_conn_on_stream_native_id
    wtq_conn_on_conn_closed
    wtq_conn_set_transport_error
    wtq_conn_on_datagram
    wtq_conn_on_send_complete
    wtq_conn_session_state
    wtq_conn_validate_protocols
    wtq_conn_is_closed
    wtq_conn_close_code
)

if(WIN32)
    message(STATUS "symbol_policy: skipped on Windows")
    return()
endif()

if(APPLE)
    execute_process(COMMAND nm -gU ${DYLIB}
        OUTPUT_VARIABLE NM_OUT RESULT_VARIABLE NM_RC)
else()
    execute_process(COMMAND nm -D --defined-only ${DYLIB}
        OUTPUT_VARIABLE NM_OUT RESULT_VARIABLE NM_RC)
endif()
if(NOT NM_RC EQUAL 0)
    message(FATAL_ERROR "nm failed on ${DYLIB}")
endif()

string(REPLACE "\n" ";" NM_LINES "${NM_OUT}")
set(EXPORTED "")
foreach(line IN LISTS NM_LINES)
    # "<addr> T _wtq_foo" (Darwin) / "<addr> T wtq_foo" (ELF)
    if(line MATCHES "[ ]+[TDBS][ ]+_?([A-Za-z_][A-Za-z0-9_]*)$")
        list(APPEND EXPORTED "${CMAKE_MATCH_1}")
    endif()
endforeach()

set(FAILURES 0)
foreach(sym IN LISTS ALLOWED_SYMBOLS)
    if(NOT "${sym}" IN_LIST EXPORTED)
        message(SEND_ERROR "MISSING export: ${sym} (visibility regression?)")
        math(EXPR FAILURES "${FAILURES}+1")
    endif()
endforeach()
foreach(sym IN LISTS EXPORTED)
    if(NOT "${sym}" IN_LIST ALLOWED_SYMBOLS)
        message(SEND_ERROR
            "UNEXPECTED export: ${sym} (add to allowlist via review)")
        math(EXPR FAILURES "${FAILURES}+1")
    endif()
endforeach()

if(FAILURES GREATER 0)
    message(FATAL_ERROR "symbol_policy: ${FAILURES} violation(s)")
endif()
message(STATUS "symbol_policy: OK (${ALLOWED_SYMBOLS})")
