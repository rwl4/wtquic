# Network.framework client backend (wtq::network). Apple-only,
# opt-in (WTQ_BUILD_NETWORK). Installed and exported as the optional
# `network` component of the wtquic package.
#
# The INSTALLED target is always LEAN: no test seams, diagnostics, or
# counters compile into it whatever the tree's test configuration. The
# in-tree tests link a SEPARATE testing variant (wtq::network-testing)
# that adds WTQ_NW_TESTING; that variant is never installed.

if(NOT APPLE)
    message(FATAL_ERROR "WTQ_BUILD_NETWORK requires an Apple platform")
endif()

# The backend uses QUIC multiplex connection groups with deliberately
# NO runtime availability guards, so the deployment target must carry
# the platform floor (macOS 13 / iOS 16). Unset targets inherit the
# SDK default, which is always new enough.
if(CMAKE_OSX_DEPLOYMENT_TARGET)
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(_wtq_nw_floor 16.0)
    else()
        set(_wtq_nw_floor 13.0)
    endif()
    if(CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS _wtq_nw_floor)
        message(FATAL_ERROR
            "WTQ_BUILD_NETWORK needs CMAKE_OSX_DEPLOYMENT_TARGET >= "
            "${_wtq_nw_floor} on ${CMAKE_SYSTEM_NAME} (QUIC multiplex "
            "connection groups); got ${CMAKE_OSX_DEPLOYMENT_TARGET}")
    endif()
endif()

set(WTQ_NW_SOURCES
    nw_conn.c
    nw_send_holder.m
)

add_library(wtquic-network STATIC ${WTQ_NW_SOURCES})
add_library(wtq::network ALIAS wtquic-network)

# Frameworks are PUBLIC: this is a static archive, so consumers carry
# the Network/Security/Foundation link themselves.
target_link_libraries(wtquic-network
    PUBLIC wtq::wtquic
           "-framework Network" "-framework Security"
           "-framework Foundation"
)
target_include_directories(wtquic-network PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
# The backend builds against the engine/API internals (never installed).
target_include_directories(wtquic-network PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)
set_source_files_properties(nw_send_holder.m PROPERTIES
    COMPILE_OPTIONS "-fobjc-arc")
# Blocks are a clang extension on Darwin; the framework headers use
# nullability annotations the strict-prototype lanes would reject.
target_compile_options(wtquic-network PRIVATE
    ${WTQ_WARN_FLAGS} -Wno-nullability-extension
    -Wno-nullability-completeness)
set_target_properties(wtquic-network PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME wtquic-network
    EXPORT_NAME network
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MINOR}
)
target_compile_definitions(wtquic-network PRIVATE WTQ_BUILDING)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(wtquic-network PUBLIC WTQ_STATIC)
endif()

# The testing variant: identical sources plus the diagnostic seams and
# counters. In-tree tests link THIS; it is never installed or exported.
if(WTQ_BUILD_TESTS)
    add_library(wtquic-network-testing STATIC ${WTQ_NW_SOURCES})
    add_library(wtq::network-testing ALIAS wtquic-network-testing)
    target_link_libraries(wtquic-network-testing
        PUBLIC wtq::wtquic
               "-framework Network" "-framework Security"
               "-framework Foundation"
    )
    target_include_directories(wtquic-network-testing PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    )
    target_include_directories(wtquic-network-testing PRIVATE
        ${PROJECT_SOURCE_DIR}/src
    )
    target_compile_options(wtquic-network-testing PRIVATE
        ${WTQ_WARN_FLAGS} -Wno-nullability-extension
        -Wno-nullability-completeness)
    set_target_properties(wtquic-network-testing PROPERTIES
        C_VISIBILITY_PRESET hidden
        POSITION_INDEPENDENT_CODE ON
    )
    target_compile_definitions(wtquic-network-testing
        PUBLIC WTQ_NW_TESTING=1
        PRIVATE WTQ_BUILDING)
    if(NOT BUILD_SHARED_LIBS)
        target_compile_definitions(wtquic-network-testing PUBLIC WTQ_STATIC)
    endif()
endif()

# --- Install / packaging (component: network) --------------------------------

include(GNUInstallDirs)

install(TARGETS wtquic-network EXPORT wtquic-networkTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(EXPORT wtquic-networkTargets
    NAMESPACE wtq::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic
)

configure_file(${PROJECT_SOURCE_DIR}/cmake/wtquic-network.pc.in
    ${PROJECT_BINARY_DIR}/wtquic-network.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/wtquic-network.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
