# Embedded add_subdirectory(wtquic) as a subproject — configure, build,
# AND install (the install proves packaging files were generated inside
# wtquic's own directories; the historical failure mode was
# CMAKE_SOURCE_DIR/CMAKE_BINARY_DIR leaking the SUPERPROJECT's paths).
# MsQuic is included when discovery hints are available.
foreach(_v SRC WTQ WORK)
    if(NOT DEFINED ${_v})
        message(FATAL_ERROR "pass -D${_v}=<path>")
    endif()
endforeach()

set(_build "${WORK}/build")
set(_prefix "${WORK}/prefix")
file(REMOVE_RECURSE "${_build}" "${_prefix}")

set(_args
    -DWTQ_SOURCE_DIR=${WTQ}
    -DWTQ_BUILD_NETWORK=ON
    -DWTQ_BUILD_TESTS=OFF)
if(DEFINED MSQUIC_DIR AND NOT MSQUIC_DIR STREQUAL "")
    list(APPEND _args "-Dmsquic_DIR=${MSQUIC_DIR}" -DWTQ_BUILD_MSQUIC=ON)
elseif(DEFINED MSQUIC_ROOT AND NOT MSQUIC_ROOT STREQUAL "")
    list(APPEND _args "-DWTQ_MSQUIC_ROOT=${MSQUIC_ROOT}"
         -DWTQ_BUILD_MSQUIC=ON)
else()
    list(APPEND _args -DWTQ_BUILD_MSQUIC=OFF)
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${_build}" ${_args}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "embedded configure failed:\n${_out}")
endif()
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${_build}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "embedded build failed:\n${_out}")
endif()
execute_process(COMMAND "${_build}/embed_consumer"
    RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "embedded consumer run failed")
endif()
# the packaging artifacts must exist inside WTQUIC'S build dir
foreach(_f wtquic.pc wtquic-network.pc)
    if(NOT EXISTS "${_build}/wtquic/${_f}")
        message(FATAL_ERROR
            "embedded build did not generate ${_f} in wtquic's build dir")
    endif()
endforeach()
execute_process(
    COMMAND ${CMAKE_COMMAND} --install "${_build}" --prefix "${_prefix}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _out)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "embedded install failed:\n${_out}")
endif()
if(NOT EXISTS "${_prefix}/lib/pkgconfig/wtquic-network.pc")
    message(FATAL_ERROR "embedded install missing wtquic-network.pc")
endif()
message(STATUS "consumer_embed_network: OK")
