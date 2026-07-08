# Symbol policy for the MsQuic backend shared library: it exports EXACTLY
# the pinned wtq_msquic_* allowlist and nothing else. A missing symbol is a
# visibility regression; an extra one is an unreviewed ABI addition. Core
# wtq_* symbols live in the core library and are resolved as imports here,
# not re-exported. Grows only via reviewed edits to this file.
#
# Usage: cmake -DDYLIB=<path to libwtquic-msquic> -P check_wtq_msquic_symbols.cmake

if(POLICY CMP0057)
    cmake_policy(SET CMP0057 NEW)
endif()

if(NOT DEFINED DYLIB)
    message(FATAL_ERROR "pass -DDYLIB=<path to libwtquic-msquic>")
endif()

set(ALLOWED_SYMBOLS
    wtq_msquic_tuning_init
    wtq_msquic_env_cfg_init
    wtq_msquic_env_open
    wtq_msquic_env_close
    wtq_msquic_listener_cfg_init
    wtq_msquic_listener_cfg_init_ex
    wtq_msquic_listener_start
    wtq_msquic_listener_stop
    wtq_msquic_listener_port
    wtq_msquic_client_cfg_init
    wtq_msquic_client_cfg_init_ex
    wtq_msquic_client_connect
)

if(WIN32)
    message(STATUS "msquic_symbol_policy: skipped on Windows")
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
    message(FATAL_ERROR "msquic_symbol_policy: ${FAILURES} violation(s)")
endif()
message(STATUS "msquic_symbol_policy: OK (${ALLOWED_SYMBOLS})")
