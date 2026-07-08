# FindMsQuic
# ----------
# Locates MsQuic and defines the imported target msquic::msquic.
#
# Search order:
#   1. An installed msquic CMake config package.
#   2. WTQ_MSQUIC_ROOT (cache var), defaulting to ../msquic next to this
#      checkout: header at src/inc/msquic.h, library under build/bin/.
#
# Result variables: MsQuic_FOUND

set(WTQ_MSQUIC_MIN_VERSION 2.5.9)

function(_wtq_msquic_target_location target out)
    get_target_property(_loc ${target} IMPORTED_LOCATION)
    if(_loc)
        set(${out} "${_loc}" PARENT_SCOPE)
        return()
    endif()

    get_target_property(_configs ${target} IMPORTED_CONFIGURATIONS)
    foreach(_cfg IN LISTS _configs)
        string(TOUPPER "${_cfg}" _ucfg)
        get_target_property(_loc ${target} IMPORTED_LOCATION_${_ucfg})
        if(_loc)
            set(${out} "${_loc}" PARENT_SCOPE)
            return()
        endif()
    endforeach()

    foreach(_cfg RELEASE RELWITHDEBINFO MINSIZEREL DEBUG)
        get_target_property(_loc ${target} IMPORTED_LOCATION_${_cfg})
        if(_loc)
            set(${out} "${_loc}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
endfunction()

function(_wtq_msquic_version_from_path path out)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" _ver "${path}")
    set(${out} "${_ver}" PARENT_SCOPE)
endfunction()

function(_wtq_msquic_version_from_source root out)
    set(_ver "")
    if(EXISTS "${root}/CMakeLists.txt")
        file(STRINGS "${root}/CMakeLists.txt" _lines
            REGEX "^[ \t]*set\\(QUIC_FULL_VERSION[ \t]+[0-9]+\\.[0-9]+\\.[0-9]+\\)")
        if(_lines)
            list(GET _lines 0 _line)
            string(REGEX REPLACE
                ".*QUIC_FULL_VERSION[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+).*"
                "\\1" _ver "${_line}")
        endif()
    endif()
    set(${out} "${_ver}" PARENT_SCOPE)
endfunction()

function(_wtq_msquic_detect_version out)
    set(_ver "")
    foreach(_var msquic_VERSION MSQUIC_VERSION MsQuic_VERSION)
        if(DEFINED ${_var} AND NOT "${${_var}}" STREQUAL "")
            set(_ver "${${_var}}")
            break()
        endif()
    endforeach()

    if(_ver STREQUAL "" AND TARGET msquic::msquic)
        _wtq_msquic_target_location(msquic::msquic _loc)
        if(_loc)
            _wtq_msquic_version_from_path("${_loc}" _ver)
        endif()
    endif()
    if(_ver STREQUAL "" AND DEFINED WTQ_MSQUIC_LIBRARY)
        _wtq_msquic_version_from_path("${WTQ_MSQUIC_LIBRARY}" _ver)
    endif()
    if(_ver STREQUAL "" AND DEFINED WTQ_MSQUIC_ROOT)
        _wtq_msquic_version_from_source("${WTQ_MSQUIC_ROOT}" _ver)
    endif()

    set(${out} "${_ver}" PARENT_SCOPE)
endfunction()

function(_wtq_msquic_check_min_version out)
    _wtq_msquic_detect_version(_ver)
    set(MsQuic_VERSION "${_ver}" PARENT_SCOPE)
    if(_ver STREQUAL "")
        message(STATUS
            "MsQuic found, but its version could not be determined; "
            "wtquic requires MsQuic >= ${WTQ_MSQUIC_MIN_VERSION}")
        set(${out} FALSE PARENT_SCOPE)
        return()
    endif()
    if(_ver VERSION_LESS WTQ_MSQUIC_MIN_VERSION)
        message(STATUS
            "MsQuic ${_ver} found, but wtquic requires MsQuic >= "
            "${WTQ_MSQUIC_MIN_VERSION}")
        set(${out} FALSE PARENT_SCOPE)
        return()
    endif()
    set(${out} TRUE PARENT_SCOPE)
endfunction()

if(TARGET msquic::msquic)
    _wtq_msquic_check_min_version(_wtq_msquic_version_ok)
    set(MsQuic_FOUND ${_wtq_msquic_version_ok})
    return()
endif()

find_package(msquic CONFIG QUIET)
if(msquic_FOUND)
    if(TARGET msquic AND NOT TARGET msquic::msquic)
        add_library(msquic::msquic ALIAS msquic)
    endif()
    _wtq_msquic_check_min_version(_wtq_msquic_version_ok)
    set(MsQuic_FOUND ${_wtq_msquic_version_ok})
    return()
endif()

set(WTQ_MSQUIC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../msquic" CACHE PATH
    "Path to an MsQuic checkout (header at src/inc/msquic.h)")

find_path(WTQ_MSQUIC_INCLUDE_DIR msquic.h
    PATHS "${WTQ_MSQUIC_ROOT}/src/inc"
    NO_DEFAULT_PATH
)
find_library(WTQ_MSQUIC_LIBRARY
    NAMES msquic
    PATHS
        "${WTQ_MSQUIC_ROOT}/build/bin/Release"
        "${WTQ_MSQUIC_ROOT}/build/bin/Debug"
        "${WTQ_MSQUIC_ROOT}/build/bin"
    NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MsQuic
    REQUIRED_VARS WTQ_MSQUIC_INCLUDE_DIR WTQ_MSQUIC_LIBRARY
    VERSION_VAR MsQuic_VERSION
)

if(MsQuic_FOUND AND NOT TARGET msquic::msquic)
    add_library(msquic::msquic UNKNOWN IMPORTED)
    set_target_properties(msquic::msquic PROPERTIES
        IMPORTED_LOCATION "${WTQ_MSQUIC_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${WTQ_MSQUIC_INCLUDE_DIR}"
    )
endif()

if(MsQuic_FOUND)
    _wtq_msquic_check_min_version(_wtq_msquic_version_ok)
    set(MsQuic_FOUND ${_wtq_msquic_version_ok})
endif()
