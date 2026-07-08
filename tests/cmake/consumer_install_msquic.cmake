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

execute_process(
    COMMAND ${CMAKE_COMMAND} --install "${BUILD}" --prefix "${_prefix}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "install failed:\n${_out}")
endif()

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

execute_process(
    COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${_cbuild}"
        "-DCMAKE_PREFIX_PATH=${_prefix}" ${_hints}
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

message(STATUS "consumer_install_msquic: OK")
