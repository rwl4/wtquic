# Symbol policy: the LEAN shared Network.framework backend exports
# EXACTLY the pinned public allowlist — no test SPI, no diagnostics,
# no internal helpers.
if(NOT DEFINED DYLIB)
    message(FATAL_ERROR "pass -DDYLIB=<path>")
endif()

set(ALLOWED_SYMBOLS
    wtq_nw_conn_cfg_init
    wtq_nw_conn_create
    wtq_nw_conn_retain
    wtq_nw_conn_release
    wtq_nw_conn_post
    wtq_nw_conn_is_on_domain
    wtq_nw_conn_session
    wtq_nw_conn_stop_begin
    wtq_nw_conn_join
)

execute_process(COMMAND nm -gU ${DYLIB}
                OUTPUT_VARIABLE NM_OUT RESULT_VARIABLE NM_RC)
if(NOT NM_RC EQUAL 0)
    message(FATAL_ERROR "nm failed on ${DYLIB}")
endif()

string(REPLACE "\n" ";" NM_LINES "${NM_OUT}")
set(EXPORTED "")
foreach(line IN LISTS NM_LINES)
    if(line MATCHES " (T|D|S) _(wtq_[a-z0-9_]+)$")
        list(APPEND EXPORTED "${CMAKE_MATCH_2}")
    elseif(line MATCHES " (T|D|S) _([a-zA-Z0-9_]+)$")
        # any non-wtq export from OUR objects is a policy violation;
        # the statically linked core's own wtq_* surface is checked by
        # the core policy lane
        set(sym "${CMAKE_MATCH_2}")
        if(NOT sym MATCHES "^wtq_")
            message(FATAL_ERROR "UNEXPECTED non-wtq export: ${sym}")
        endif()
    endif()
endforeach()

set(violations 0)
foreach(sym IN LISTS EXPORTED)
    if(sym MATCHES "^wtq_nw_")
        if(NOT "${sym}" IN_LIST ALLOWED_SYMBOLS)
            message(SEND_ERROR
                "UNEXPECTED export: ${sym} (add to allowlist via review)")
            math(EXPR violations "${violations}+1")
        endif()
    endif()
endforeach()
foreach(sym IN LISTS ALLOWED_SYMBOLS)
    if(NOT "${sym}" IN_LIST EXPORTED)
        message(SEND_ERROR "MISSING export: ${sym}")
        math(EXPR violations "${violations}+1")
    endif()
endforeach()
if(violations GREATER 0)
    message(FATAL_ERROR "network_symbol_policy: ${violations} violation(s)")
endif()
message(STATUS "network_symbol_policy: OK (${ALLOWED_SYMBOLS})")
