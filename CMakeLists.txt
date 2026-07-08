cmake_minimum_required(VERSION 3.24)
project(wtquic VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Are we the top-level project?
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(WTQ_TOPLEVEL ON)
else()
    set(WTQ_TOPLEVEL OFF)
endif()

# --- Options ----------------------------------------------------------------

# AUTO: build the MsQuic backend only when top-level AND MsQuic is found.
set(WTQ_BUILD_MSQUIC "AUTO" CACHE STRING
    "Build the MsQuic backend (ON/OFF/AUTO)")
option(WTQ_REQUIRE_MSQUIC "Fail configure if MsQuic backend cannot build" OFF)
option(WTQ_BUILD_PICOQUIC "Build the picoquic backend" OFF)
option(WTQ_BUILD_TESTS "Build tests" ${WTQ_TOPLEVEL})
option(WTQ_BUILD_SIM "Build the deterministic simulator" ${WTQ_TOPLEVEL})
option(WTQ_BUILD_FUZZ "Build libFuzzer targets" OFF)
option(WTQ_REQUIRE_FUZZ "Fail if fuzz targets cannot be built" OFF)
option(WTQ_BUILD_BENCHMARKS "Build benchmarks" ${WTQ_TOPLEVEL})
option(WTQ_BUILD_EXAMPLES "Build examples" ${WTQ_TOPLEVEL})
option(WTQ_MSQUIC_PREVIEW
    "Enable MsQuic preview features (legacy reliable reset)" OFF)
option(WTQ_WARNINGS_AS_ERRORS "Treat warnings as errors" ${WTQ_TOPLEVEL})

set(WTQ_WARN_FLAGS "")
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    list(APPEND WTQ_WARN_FLAGS -Wall -Wextra -Wpedantic
        -Wmissing-field-initializers -Wshadow)
    if(WTQ_WARNINGS_AS_ERRORS)
        list(APPEND WTQ_WARN_FLAGS -Werror)
    endif()
endif()

# --- Generated version header ----------------------------------------------

configure_file(include/wtquic/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/wtquic/version.h @ONLY)

# --- wtq_proto: sans-I/O codecs (OBJECT lib; no engine/backend symbols) -----

add_library(wtq_proto OBJECT
    src/proto/capsule.c
    src/proto/connect.c
    src/proto/errmap.c
    src/proto/h3_frame.c
    src/proto/h3_settings.c
    src/proto/preamble.c
    src/proto/qpack_static.c
    src/proto/sf_string.c
    src/proto/varint.c
)
target_include_directories(wtq_proto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_compile_options(wtq_proto PRIVATE ${WTQ_WARN_FLAGS})
set_target_properties(wtq_proto PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
target_compile_definitions(wtq_proto PRIVATE WTQ_BUILDING)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(wtq_proto PUBLIC WTQ_STATIC)
endif()

# --- wtquic: core library (proto + engine) ----------------------------------

add_library(wtquic
    src/types.c
    src/engine/conn.c
    src/api/session.c
    $<TARGET_OBJECTS:wtq_proto>
)
add_library(wtq::wtquic ALIAS wtquic)
target_include_directories(wtquic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_options(wtquic PRIVATE ${WTQ_WARN_FLAGS})
set_target_properties(wtquic PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME wtquic
    EXPORT_NAME wtquic
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MINOR}
)
target_compile_definitions(wtquic PRIVATE WTQ_BUILDING)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(wtquic PUBLIC WTQ_STATIC)
endif()

# --- MsQuic backend (AUTO/ON/OFF) --------------------------------------------

set(WTQ_MSQUIC_ENABLED OFF)
if(NOT WTQ_BUILD_MSQUIC STREQUAL "OFF")
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
    find_package(MsQuic QUIET)
    if(MsQuic_FOUND)
        set(WTQ_MSQUIC_ENABLED ON)
    elseif(WTQ_BUILD_MSQUIC STREQUAL "ON" OR WTQ_REQUIRE_MSQUIC)
        message(FATAL_ERROR
            "MsQuic >= 2.5.9 not found (set WTQ_MSQUIC_ROOT or install a "
            "current config package); required by WTQ_BUILD_MSQUIC=ON / "
            "WTQ_REQUIRE_MSQUIC")
    else()
        message(STATUS "wtquic: MsQuic not found — backend disabled (AUTO)")
    endif()
endif()
if(WTQ_MSQUIC_ENABLED)
    include(GNUInstallDirs)
    include(cmake/WtqPcPrefix.cmake)
    add_subdirectory(backends/msquic)
endif()

if(WTQ_BUILD_PICOQUIC)
    add_subdirectory(backends/picoquic)
endif()

# --- Network.framework client backend (opt-in, Apple-only) -------------------
# Managed-lifecycle backend, installed and exported as the optional
# `network` component (wtq::network, wtquic-network.pc). The in-tree
# tests use a separate never-installed testing variant.
option(WTQ_BUILD_NETWORK
    "Build the Network.framework client backend (Apple only)" OFF)
if(WTQ_BUILD_NETWORK)
    add_subdirectory(backends/network)
endif()

# --- EXPERIMENTAL Network.framework capability probe (opt-in, Apple-only) ----
# Not a backend: no library, no install, no export, no ctest. Default OFF and
# excluded from every package config and CI lane.
option(WTQ_BUILD_NW_EXPERIMENTAL
    "Build the experimental Network.framework capability probe (Apple only)"
    OFF)
if(WTQ_BUILD_NW_EXPERIMENTAL)
    add_subdirectory(backends/network_experimental)
endif()

# --- Tests -------------------------------------------------------------------

if(WTQ_BUILD_TESTS OR WTQ_BUILD_FUZZ)
    enable_testing()
endif()

if(WTQ_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(WTQ_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

if(WTQ_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# Examples are wired in once the public API lands; directory holds stubs.

# --- Install / packaging -----------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(cmake/WtqPcPrefix.cmake)

install(TARGETS wtquic EXPORT wtquicTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/wtquic
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "version.h.in" EXCLUDE
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/wtquic/version.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wtquic
)
install(EXPORT wtquicTargets
    NAMESPACE wtq::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic
)

configure_package_config_file(cmake/wtquicConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/wtquicConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/wtquicConfigVersion.cmake
    COMPATIBILITY SameMinorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/wtquicConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/wtquicConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic
)

# When a backend is built, its exported target carries a transport
# dependency the installed config must resolve; ship the find-module it
# uses so installed consumers discover MsQuic as the build tree does.
if(WTQ_MSQUIC_ENABLED)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindMsQuic.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic)
endif()

configure_file(cmake/wtquic.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wtquic.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wtquic.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
