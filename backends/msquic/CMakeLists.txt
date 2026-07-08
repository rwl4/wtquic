# MsQuic backend library (wtq::msquic). Built when MsQuic is found; see
# the top-level AUTO/REQUIRE logic that decides whether to add it.

add_library(wtquic-msquic
    msq_client.c
    msq_conn.c
    msq_env.c
    msq_listener.c
    msq_settings.c
    msq_stream.c
)
add_library(wtq::msquic ALIAS wtquic-msquic)

# msquic is PUBLIC: the installed header <wtquic/wtquic_msquic.h> includes
# <msquic.h>, so consumers need MsQuic's include path (and link).
# Threads is PRIVATE: the blocking env_close contract uses a mutex and
# condition variable internally.
find_package(Threads REQUIRED)
target_link_libraries(wtquic-msquic
    PUBLIC wtq::wtquic msquic::msquic
    PRIVATE Threads::Threads
)
target_include_directories(wtquic-msquic PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
# The backend builds against the engine/API internals (never installed).
target_include_directories(wtquic-msquic PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)
target_compile_options(wtquic-msquic PRIVATE ${WTQ_WARN_FLAGS})
set_target_properties(wtquic-msquic PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME wtquic-msquic
    EXPORT_NAME msquic
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MINOR}
)
target_compile_definitions(wtquic-msquic PRIVATE WTQ_BUILDING)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(wtquic-msquic PUBLIC WTQ_STATIC)
endif()

# Preview features change the MsQuic ABI (API-table layout, extra enum
# values), so the macro must be set identically here and in the linked
# libmsquic. Kept off by default.
if(WTQ_MSQUIC_PREVIEW)
    target_compile_definitions(wtquic-msquic PRIVATE
        QUIC_API_ENABLE_PREVIEW_FEATURES)
endif()

# --- Install / packaging (component: msquic) --------------------------------

include(GNUInstallDirs)

install(TARGETS wtquic-msquic EXPORT wtquic-msquicTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(EXPORT wtquic-msquicTargets
    NAMESPACE wtq::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wtquic
)

# Record the directory MsQuic was found in so the .pc's Libs.private -lmsquic
# resolves for pkg-config --static consumers: MsQuic is CMake-discovered, so a
# non-default install path (e.g. Homebrew) is not on the linker's default
# search path and must be recorded by the package that owns the dependency.
set(WTQ_MSQUIC_PC_LIBDIR "")
set(_wtq_msq_loc "")
if(DEFINED WTQ_MSQUIC_LIBRARY AND WTQ_MSQUIC_LIBRARY)
    set(_wtq_msq_loc "${WTQ_MSQUIC_LIBRARY}")
elseif(TARGET msquic::msquic)
    get_target_property(_wtq_msq_real msquic::msquic ALIASED_TARGET)
    if(NOT _wtq_msq_real)
        set(_wtq_msq_real msquic::msquic)
    endif()
    foreach(_p IMPORTED_LOCATION IMPORTED_LOCATION_RELEASE
               IMPORTED_LOCATION_NOCONFIG IMPORTED_LOCATION_DEBUG
               IMPORTED_LOCATION_RELWITHDEBINFO)
        get_target_property(_l ${_wtq_msq_real} ${_p})
        if(_l)
            set(_wtq_msq_loc "${_l}")
            break()
        endif()
    endforeach()
endif()
if(_wtq_msq_loc)
    get_filename_component(_wtq_msq_dir "${_wtq_msq_loc}" DIRECTORY)
    set(WTQ_MSQUIC_PC_LIBDIR "-L${_wtq_msq_dir} ")
endif()

# PROJECT_ paths: an embedded add_subdirectory(wtquic) build must
# generate packaging files inside WTQUIC's own directories, never the
# superproject's.
configure_file(${PROJECT_SOURCE_DIR}/cmake/wtquic-msquic.pc.in
    ${PROJECT_BINARY_DIR}/wtquic-msquic.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/wtquic-msquic.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
