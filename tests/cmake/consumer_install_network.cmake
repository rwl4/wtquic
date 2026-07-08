# Install the built project to a scratch prefix, then prove the network
# component's whole packaging story:
#   1. find_package(wtquic REQUIRED COMPONENTS network) + wtq::network
#      builds and runs C99 and C++17 consumers;
#   2. the SAME install keeps working after the prefix is RELOCATED;
#   3. a static pkg-config consumer links via wtquic-network.pc;
#   4. deleting the component's targets file makes REQUIRED COMPONENTS
#      network fail with the config's missing-component message;
#   5. the install tree ships no probe/test/internal files, and the
#      installed archive exports exactly the nine public functions and
#      zero test seams/diagnostics.
#
# Args (all -D): BUILD (wtquic build dir), SRC (consumer source dir),
# WORK (scratch dir), plus optional C_FLAGS/LINK_FLAGS forwarded so
# sanitizer lanes link consistently.

foreach(_v BUILD SRC WORK)
    if(NOT DEFINED ${_v})
        message(FATAL_ERROR "pass -D${_v}=<path>")
    endif()
endforeach()

set(_prefix "${WORK}/prefix")
set(_moved "${WORK}/prefix-moved")
set(_cbuild "${WORK}/consumer-build")
set(_cbuild2 "${WORK}/consumer-build-moved")
set(_cbuild3 "${WORK}/consumer-build-missing")
file(REMOVE_RECURSE "${_prefix}" "${_moved}" "${_cbuild}" "${_cbuild2}"
     "${_cbuild3}")

execute_process(
    COMMAND ${CMAKE_COMMAND} --install "${BUILD}" --prefix "${_prefix}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "install failed:\n${_out}")
endif()

set(_hints "")
if(DEFINED C_FLAGS AND NOT C_FLAGS STREQUAL "")
    list(APPEND _hints "-DCMAKE_C_FLAGS=${C_FLAGS}")
    list(APPEND _hints "-DCMAKE_CXX_FLAGS=${C_FLAGS}")
endif()
if(DEFINED LINK_FLAGS AND NOT LINK_FLAGS STREQUAL "")
    list(APPEND _hints "-DCMAKE_EXE_LINKER_FLAGS=${LINK_FLAGS}")
endif()

# --- 5: install-tree hygiene BEFORE anything consumes it --------------------

file(GLOB_RECURSE _shipped RELATIVE "${_prefix}" "${_prefix}/*")
foreach(_f IN LISTS _shipped)
    if(_f MATCHES "nw_internal|network_experimental|nw_probe|test_|_test|raw_peer")
        message(FATAL_ERROR "install tree ships an internal file: ${_f}")
    endif()
endforeach()
if(NOT EXISTS "${_prefix}/include/wtquic/wtquic_network.h")
    message(FATAL_ERROR "public header not installed")
endif()

file(GLOB _libs "${_prefix}/lib/libwtquic-network.*")
if(_libs STREQUAL "")
    message(FATAL_ERROR "installed network library not found")
endif()
list(GET _libs 0 _lib)
execute_process(COMMAND nm ${_lib} OUTPUT_VARIABLE _nm RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "nm failed on ${_lib}")
endif()
if(_nm MATCHES "wtq_nw_test")
    message(FATAL_ERROR "installed archive ships test seams/diagnostics")
endif()
set(_api wtq_nw_conn_cfg_init wtq_nw_conn_create wtq_nw_conn_retain
         wtq_nw_conn_release wtq_nw_conn_post wtq_nw_conn_is_on_domain
         wtq_nw_conn_session wtq_nw_conn_stop_begin wtq_nw_conn_join
         wtq_nw_conn_doorbell_ring)
foreach(_sym IN LISTS _api)
    if(NOT _nm MATCHES "T _${_sym}\n")
        message(FATAL_ERROR "installed archive missing public: ${_sym}")
    endif()
endforeach()
string(REGEX MATCHALL "T _wtq_nw_[a-z0-9_]+" _nw_defs "${_nm}")
list(REMOVE_DUPLICATES _nw_defs)
list(LENGTH _nw_defs _nw_count)
if(NOT _nw_count EQUAL 10)
    message(FATAL_ERROR
        "installed wtq_nw_* surface is ${_nw_count}, expected exactly 10: "
        "${_nw_defs}")
endif()

# --- 1: installed find_package consumers -------------------------------------

execute_process(
    COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${_cbuild}"
        -Dwtquic_DIR=${_prefix}/lib/cmake/wtquic ${_hints}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "consumer configure failed:\n${_out}")
endif()
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${_cbuild}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "consumer build failed:\n${_out}")
endif()
foreach(_exe consumer consumer_cxx)
    execute_process(COMMAND "${_cbuild}/${_exe}"
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "${_exe} run failed:\n${_out}")
    endif()
endforeach()

# --- 2: relocated prefix ------------------------------------------------------

file(RENAME "${_prefix}" "${_moved}")
execute_process(
    COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${_cbuild2}"
        -Dwtquic_DIR=${_moved}/lib/cmake/wtquic ${_hints}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "relocated consumer configure failed:\n${_out}")
endif()
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${_cbuild2}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "relocated consumer build failed:\n${_out}")
endif()
execute_process(COMMAND "${_cbuild2}/consumer"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "relocated consumer run failed:\n${_out}")
endif()

# --- 3: static pkg-config consumer against the RELOCATED prefix ---------------

find_program(_pkgconf NAMES pkg-config)
find_program(_cc NAMES cc clang)
if(_pkgconf AND _cc)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env
            "PKG_CONFIG_PATH=${_moved}/lib/pkgconfig"
            ${_pkgconf} --static --cflags --libs wtquic-network
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _flags ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "pkg-config wtquic-network failed:\n${_err}")
    endif()
    string(STRIP "${_flags}" _flags)
    separate_arguments(_flags_list UNIX_COMMAND "${_flags}")
    separate_arguments(_cflags_extra UNIX_COMMAND "${C_FLAGS}")
    separate_arguments(_lflags_extra UNIX_COMMAND "${LINK_FLAGS}")
    execute_process(
        COMMAND ${_cc} -std=c99 "${SRC}/main.c" -o "${WORK}/pc_consumer"
            ${_cflags_extra} ${_flags_list} ${_lflags_extra}
            "-Wl,-rpath,${_moved}/lib"
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "pkg-config consumer link failed:\n${_out}")
    endif()
    execute_process(COMMAND "${WORK}/pc_consumer"
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "pkg-config consumer run failed:\n${_out}")
    endif()
else()
    message(STATUS "pkg-config or cc unavailable: static pc lane skipped")
endif()

# --- 4: missing component fails loudly ----------------------------------------

file(REMOVE "${_moved}/lib/cmake/wtquic/wtquic-networkTargets.cmake")
execute_process(
    COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${_cbuild3}"
        -Dwtquic_DIR=${_moved}/lib/cmake/wtquic ${_hints}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(_rc EQUAL 0)
    message(FATAL_ERROR
        "REQUIRED COMPONENTS network succeeded without the component")
endif()
if(NOT _out MATCHES "network")
    message(FATAL_ERROR
        "missing-component failure lacks a component message:\n${_out}")
endif()

message(STATUS "consumer_install_network: OK")
