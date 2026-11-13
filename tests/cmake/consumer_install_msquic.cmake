# Install the built project to a scratch prefix, then configure and build a
# standalone consumer that does find_package(wtquic COMPONENTS msquic) and
# links wtq::msquic. This pins that the installed config re-establishes the
# backend's transitive msquic::msquic dependency.
#
# Args (all -D): BUILD (wtquic build dir), SRC (consumer source dir),
# WORK (scratch dir), and optional MSQUIC_DIR / MSQUIC_ROOT discovery hints
# forwarded so the consumer finds MsQuic exactly as the build tree did.

foreach(_v BUILD SRC WORK)
    if(NOT DEFINED ${_v})
        message(FATAL_ERROR "pass -D${_v}=<path>")
    endif()
endforeach()

set(_prefix "${WORK}/prefix")
set(_cbuild "${WORK}/consumer-build")
file(REMOVE_RECURSE "${_prefix}" "${_cbuild}")

# Run one step. Its exit status and complete output are printed whether or
# not it succeeds, and kept in WORK/<name>.log, so the test log carries every
# install, configure, compiler and linker diagnostic of a passing run too.
function(_consumer_step name)
    execute_process(COMMAND ${ARGN}
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
    file(WRITE "${WORK}/${name}.log" "${_out}")
    message(STATUS "consumer_install_msquic: ${name} exit ${_rc}; "
                   "complete output follows (also ${WORK}/${name}.log)")
    if(NOT _out STREQUAL "")
        message(NOTICE "${_out}")
    endif()
    message(STATUS "consumer_install_msquic: end of ${name} output")
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "consumer_install_msquic: ${name} failed")
    endif()
endfunction()

_consumer_step(install
    ${CMAKE_COMMAND} --install "${BUILD}" --prefix "${_prefix}")

set(_hints "")
if(DEFINED MSQUIC_DIR AND NOT MSQUIC_DIR STREQUAL "")
    list(APPEND _hints "-Dmsquic_DIR=${MSQUIC_DIR}")
endif()
if(DEFINED MSQUIC_ROOT AND NOT MSQUIC_ROOT STREQUAL "")
    list(APPEND _hints "-DWTQ_MSQUIC_ROOT=${MSQUIC_ROOT}")
endif()
# Sanitizer lanes instrument the installed libraries; the consumer must
# build with the same flags or its link fails on the sanitizer runtime.
if(DEFINED C_FLAGS AND NOT C_FLAGS STREQUAL "")
    list(APPEND _hints "-DCMAKE_C_FLAGS=${C_FLAGS}")
endif()
if(DEFINED LINK_FLAGS AND NOT LINK_FLAGS STREQUAL "")
    list(APPEND _hints "-DCMAKE_EXE_LINKER_FLAGS=${LINK_FLAGS}")
endif()

_consumer_step(configure
    ${CMAKE_COMMAND} -S "${SRC}" -B "${_cbuild}"
        "-DCMAKE_PREFIX_PATH=${_prefix}" ${_hints})

# One job, whatever the nested generator or environment would choose.
_consumer_step(build
    ${CMAKE_COMMAND} --build "${_cbuild}" --parallel 1)

message(STATUS "consumer_install_msquic: OK")
