# Test conventions (mirrors libmoq):
#   - executable test_<name> registers as CTest `<name>` (prefix dropped)
#   - unit tests are bare names; seeded runners are scenario_*;
#     conformance registers once per rail (conformance_<rail>)
#   - black-box tests link wtq::wtquic only; white-box engine tests
#     compile the engine sources directly (see wtq_add_engine_test)

include(CheckLanguage)

function(wtq_add_unit_test name)
    add_executable(test_${name} unit/test_${name}.c)
    target_link_libraries(test_${name} PRIVATE wtq::wtquic)
    target_compile_options(test_${name} PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME ${name} COMMAND test_${name})
endfunction()

# White-box proto tests compile the module sources directly (internal
# symbols are hidden in shared builds, so linking the library would fail)
# and see the internal src/ headers. <proto/*.h> is never installed.
function(wtq_add_proto_test name)
    add_executable(test_${name} unit/test_${name}.c ${ARGN})
    target_include_directories(test_${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include)
    target_compile_options(test_${name} PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME ${name} COMMAND test_${name})
endfunction()

wtq_add_unit_test(version)
wtq_add_unit_test(errcode_map)
wtq_add_proto_test(varint ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c)
wtq_add_proto_test(h3_frame
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c)
wtq_add_proto_test(h3_settings
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_settings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c)
wtq_add_proto_test(sf_string
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/sf_string.c)
wtq_add_proto_test(capsule
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/capsule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c)
wtq_add_proto_test(preamble
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/preamble.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c)
wtq_add_proto_test(qpack_static
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/qpack_static.c)
wtq_add_proto_test(connect
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/qpack_static.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/sf_string.c)
wtq_add_proto_test(profile_parsers
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/qpack_static.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/sf_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_settings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/h3_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/varint.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/preamble.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/proto/errmap.c)

# --- committed wire fixtures + hostile sweeps (whole proto plane) ------

add_executable(test_vectors_wt15
    unit/test_vectors_wt15.c
    support/wt15_vectors.c
    $<TARGET_OBJECTS:wtq_proto>
)
add_executable(test_truncation
    unit/test_truncation.c
    support/wt15_vectors.c
    $<TARGET_OBJECTS:wtq_proto>
)
foreach(t test_vectors_wt15 test_truncation)
    target_include_directories(${t} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/support
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_options(${t} PRIVATE ${WTQ_WARN_FLAGS})
endforeach()
target_compile_definitions(test_vectors_wt15 PRIVATE
    WT15_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors/wt15")
add_test(NAME vectors_wt15 COMMAND test_vectors_wt15)
add_test(NAME truncation COMMAND test_truncation)

# --- engine (white-box: compiles engine + proto sources directly) ------

function(wtq_add_engine_test name)
    add_executable(test_${name}
        unit/test_${name}.c
        support/fake_driver.c
        ${ARGN}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
        $<TARGET_OBJECTS:wtq_proto>
    )
    target_include_directories(test_${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/support
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_options(test_${name} PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME ${name} COMMAND test_${name})
endfunction()

wtq_add_engine_test(engine_bootstrap)
wtq_add_engine_test(engine_connect)
wtq_add_engine_test(engine_session)
wtq_add_engine_test(engine_wtstream)
wtq_add_engine_test(engine_dgram)
wtq_add_engine_test(engine_async_id)
wtq_add_engine_test(engine_shutdown)
wtq_add_engine_test(api_session)
wtq_add_engine_test(api_async_id)
wtq_add_engine_test(api_abort)
wtq_add_engine_test(api_transport_error)
wtq_add_engine_test(api_stream)
wtq_add_engine_test(api_pair)
wtq_add_engine_test(api_pause)
wtq_add_engine_test(simpair_bootstrap support/wtq_simpair.c)
wtq_add_engine_test(engine_profile support/wtq_simpair.c)

# --- scenario suites over the public API rail (shared runner) ----------

function(wtq_add_scenario_suite name src)
    add_executable(${name}
        ${src}
        support/fake_driver.c
        support/wtq_apipair.c
        support/wtq_scenario.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
        $<TARGET_OBJECTS:wtq_proto>
    )
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/support
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_options(${name} PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

wtq_add_scenario_suite(conformance_apipair conformance/wtq_scenarios.c)
wtq_add_scenario_suite(fault_apipair fault/wtq_fault_scenarios.c)

# --- OOM fail-at-N sweeps (own faulting allocator; own runner) ---------

add_executable(oom_apipair
    oom/wtq_oom_scenarios.c
    support/fake_driver.c
    support/wtq_apipair.c
    support/wtq_fault_alloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
    $<TARGET_OBJECTS:wtq_proto>
)
target_include_directories(oom_apipair PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/support
    ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_compile_options(oom_apipair PRIVATE ${WTQ_WARN_FLAGS})
add_test(NAME oom_apipair COMMAND oom_apipair)

# --- Consumer: public headers compile standalone under pedantic C11/C++17 ---

add_executable(consumer_header_c99 consumer/consumer_header.c)
target_link_libraries(consumer_header_c99 PRIVATE wtq::wtquic)
target_compile_options(consumer_header_c99 PRIVATE ${WTQ_WARN_FLAGS})
add_test(NAME consumer_header_c99 COMMAND consumer_header_c99)

check_language(CXX)
if(CMAKE_CXX_COMPILER)
    enable_language(CXX)
    add_executable(consumer_header_cxx17 consumer/consumer_header.cpp)
    target_link_libraries(consumer_header_cxx17 PRIVATE wtq::wtquic)
    set_target_properties(consumer_header_cxx17 PROPERTIES
        CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(consumer_header_cxx17 PRIVATE
            -Wall -Wextra -Wpedantic)
        if(WTQ_WARNINGS_AS_ERRORS)
            target_compile_options(consumer_header_cxx17 PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME consumer_header_cxx17 COMMAND consumer_header_cxx17)
endif()

# --- Boundary + symbol policy ------------------------------------------------

find_program(WTQ_BASH bash)
if(WTQ_BASH)
    add_test(NAME api_boundary
        COMMAND ${WTQ_BASH}
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_api_boundary.sh
            ${CMAKE_CURRENT_SOURCE_DIR}/..)
endif()

if(BUILD_SHARED_LIBS)
    add_test(NAME symbol_policy
        COMMAND ${CMAKE_COMMAND}
            -DDYLIB=$<TARGET_FILE:wtquic>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_wtq_symbols.cmake)
endif()

# Core public headers never expose a transport backend (HQUIC/QUIC_* or a
# transport include). Runs regardless of whether the backend is built.
if(WTQ_BASH)
    add_test(NAME consumer_no_backend_leak
        COMMAND ${WTQ_BASH}
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_no_backend_leak.sh
            ${CMAKE_CURRENT_SOURCE_DIR}/..)
endif()

# --- MsQuic backend tests (only when the backend is built) -------------------
# Gated on WTQ_MSQUIC_ENABLED (set by the top-level AUTO/REQUIRE logic) and
# labelled `msquic` so a lane can select or exclude them.
if(WTQ_MSQUIC_ENABLED)
    add_executable(test_msquic_env
        msquic/msquic_env.c
        support/wtq_fault_alloc.c)
    target_link_libraries(test_msquic_env PRIVATE wtq::msquic)
    target_include_directories(test_msquic_env PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unit
        ${CMAKE_CURRENT_SOURCE_DIR}/support)
    target_compile_options(test_msquic_env PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME msquic_env COMMAND test_msquic_env)
    set_tests_properties(msquic_env PROPERTIES LABELS msquic)

    # White-box driver-op edge cases (compiles the backend sources
    # directly — the ops are not part of any library's public surface).
    add_executable(test_msquic_ops
        msquic/msquic_ops.c
        ../backends/msquic/msq_client.c
        ../backends/msquic/msq_conn.c
        ../backends/msquic/msq_env.c
        ../backends/msquic/msq_listener.c
        ../backends/msquic/msq_settings.c
        ../backends/msquic/msq_stream.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
        $<TARGET_OBJECTS:wtq_proto>)
    target_include_directories(test_msquic_ops PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/msquic
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_link_libraries(test_msquic_ops PRIVATE msquic::msquic)
    target_compile_options(test_msquic_ops PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME msquic_ops COMMAND test_msquic_ops)
    set_tests_properties(msquic_ops PROPERTIES LABELS msquic)

    # White-box managed-domain contract (guard bracket, quiescence hook,
    # client-publication race) — same compile shape as msquic_ops.
    add_executable(test_msquic_managed
        msquic/msquic_managed.c
        ../backends/msquic/msq_client.c
        ../backends/msquic/msq_conn.c
        ../backends/msquic/msq_env.c
        ../backends/msquic/msq_listener.c
        ../backends/msquic/msq_settings.c
        ../backends/msquic/msq_stream.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
        $<TARGET_OBJECTS:wtq_proto>)
    target_include_directories(test_msquic_managed PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/msquic
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_link_libraries(test_msquic_managed PRIVATE
        msquic::msquic Threads::Threads)
    target_compile_options(test_msquic_managed PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME msquic_managed COMMAND test_msquic_managed)
    set_tests_properties(msquic_managed PROPERTIES LABELS msquic)

    # Backend header compiles + links, C and C++.
    add_executable(consumer_msquic_header_c consumer/consumer_msquic_header.c)
    target_link_libraries(consumer_msquic_header_c PRIVATE wtq::msquic)
    target_compile_options(consumer_msquic_header_c PRIVATE ${WTQ_WARN_FLAGS})
    add_test(NAME consumer_msquic_header_c COMMAND consumer_msquic_header_c)
    set_tests_properties(consumer_msquic_header_c PROPERTIES LABELS msquic)

    if(CMAKE_CXX_COMPILER)
        add_executable(consumer_msquic_header_cxx
            consumer/consumer_msquic_header.cpp)
        target_link_libraries(consumer_msquic_header_cxx PRIVATE wtq::msquic)
        set_target_properties(consumer_msquic_header_cxx PROPERTIES
            CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(consumer_msquic_header_cxx PRIVATE
                -Wall -Wextra -Wpedantic)
            if(WTQ_WARNINGS_AS_ERRORS)
                target_compile_options(consumer_msquic_header_cxx PRIVATE
                    -Werror)
            endif()
        endif()
        add_test(NAME consumer_msquic_header_cxx
            COMMAND consumer_msquic_header_cxx)
        set_tests_properties(consumer_msquic_header_cxx PROPERTIES
            LABELS msquic)
    endif()

    # Backend dylib exports exactly the pinned wtq_msquic_* allowlist.
    if(BUILD_SHARED_LIBS)
        add_test(NAME msquic_symbol_policy
            COMMAND ${CMAKE_COMMAND}
                -DDYLIB=$<TARGET_FILE:wtquic-msquic>
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_wtq_msquic_symbols.cmake)
        set_tests_properties(msquic_symbol_policy PROPERTIES LABELS msquic)
    endif()

    # Installed find_package(wtquic COMPONENTS msquic) resolves wtq::msquic
    # and its transitive msquic::msquic dependency. MsQuic discovery hints
    # are forwarded so the consumer finds MsQuic as this build did.
    add_test(NAME consumer_install_msquic
        COMMAND ${CMAKE_COMMAND}
            -DBUILD=${CMAKE_BINARY_DIR}
            -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/consumer/msquic_pkg
            -DWORK=${CMAKE_CURRENT_BINARY_DIR}/consumer_install_msquic
            -DMSQUIC_DIR=${msquic_DIR}
            -DMSQUIC_ROOT=${WTQ_MSQUIC_ROOT}
            "-DC_FLAGS=${CMAKE_C_FLAGS}"
            "-DLINK_FLAGS=${CMAKE_EXE_LINKER_FLAGS}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/consumer_install_msquic.cmake)
    set_tests_properties(consumer_install_msquic PROPERTIES LABELS msquic)

    # Accept-registration contract, white-box (compiles the backend
    # sources with WTQ_MSQ_TESTING for the accept-path fault seam and
    # environment internals): closing-refusal, atomic publication,
    # configuration-failure unwind, and env_close/accept churn over
    # real loopback connections.
    add_executable(test_msquic_accept
        msquic/msquic_accept.c
        ../backends/msquic/msq_client.c
        ../backends/msquic/msq_conn.c
        ../backends/msquic/msq_env.c
        ../backends/msquic/msq_listener.c
        ../backends/msquic/msq_settings.c
        ../backends/msquic/msq_stream.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/engine/conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api/session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/types.c
        $<TARGET_OBJECTS:wtq_proto>)
    target_include_directories(test_msquic_accept PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/msquic
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_definitions(test_msquic_accept PRIVATE WTQ_MSQ_TESTING)
    target_link_libraries(test_msquic_accept PRIVATE msquic::msquic)
    target_compile_options(test_msquic_accept PRIVATE ${WTQ_WARN_FLAGS})

    # Real-transport loopback: self-signed certs generated into the build
    # dir by the fixture, ephemeral ports, real MsQuic on localhost.
    find_package(Threads REQUIRED)
    add_executable(loopback_msquic loopback/loopback_msquic.c)
    target_link_libraries(loopback_msquic PRIVATE wtq::msquic
        Threads::Threads)
    target_include_directories(loopback_msquic PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_options(loopback_msquic PRIVATE ${WTQ_WARN_FLAGS})

    if(WTQ_BASH)
        add_test(NAME gen_certs
            COMMAND ${WTQ_BASH}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/gen_test_certs.sh
                ${CMAKE_CURRENT_BINARY_DIR}/certs)
        set_tests_properties(gen_certs PROPERTIES
            FIXTURES_SETUP certs
            LABELS "msquic;loopback")
        add_test(NAME loopback_msquic COMMAND loopback_msquic)
        set_tests_properties(loopback_msquic PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "msquic;loopback"
            TIMEOUT 120)
        add_test(NAME msquic_accept COMMAND test_msquic_accept)
        set_tests_properties(msquic_accept PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "msquic;loopback"
            TIMEOUT 180)
    endif()

    # Network.framework client <-> MsQuic server cross-backend loopback
    # (slice 5). Two registrations: the regular single pass, and the
    # probe-pattern 20-consecutive-run gate.
    if(WTQ_BUILD_NETWORK AND WTQ_BASH)
        add_executable(test_nw_loopback network/test_nw_loopback.c)
        target_link_libraries(test_nw_loopback PRIVATE
            wtq::network-testing wtq::msquic Threads::Threads)
        target_include_directories(test_nw_loopback PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/unit
            ${PROJECT_SOURCE_DIR}/backends/network
            ${PROJECT_SOURCE_DIR}/src)
        target_compile_options(test_nw_loopback PRIVATE ${WTQ_WARN_FLAGS}
            -Wno-nullability-extension -Wno-nullability-completeness)
        add_test(NAME nw_loopback COMMAND test_nw_loopback)
        set_tests_properties(nw_loopback PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "network;loopback"
            TIMEOUT 180)
        # Send-loss isolation matrix: standalone NW client against the
        # raw MsQuic observer peer from Network test support. Exact
        # per-stream attribution; any missing byte or FIN fails.
        add_executable(test_nw_send_matrix
            network/test_nw_send_matrix.c
            network/support/raw_peer.c)
        target_include_directories(test_nw_send_matrix PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/network/support)
        target_link_libraries(test_nw_send_matrix PRIVATE
            wtq::network-testing msquic::msquic Threads::Threads
            "-framework Network" "-framework Security")
        target_include_directories(test_nw_send_matrix PRIVATE
            ${PROJECT_SOURCE_DIR}/backends/network
            ${PROJECT_SOURCE_DIR}/src)
        target_compile_options(test_nw_send_matrix PRIVATE ${WTQ_WARN_FLAGS}
            -Wno-nullability-extension -Wno-nullability-completeness)
        add_test(NAME nw_send_matrix COMMAND test_nw_send_matrix)
        set_tests_properties(nw_send_matrix PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "network;loopback"
            TIMEOUT 600)

        # Managed-lifecycle contract tests (slice 6): the public
        # wtq_nw_conn_t surface — post/stop/join/ownership split.
        add_executable(test_nw_lifecycle network/test_nw_lifecycle.c)
        target_link_libraries(test_nw_lifecycle PRIVATE
            wtq::network-testing wtq::msquic Threads::Threads)
        target_include_directories(test_nw_lifecycle PRIVATE
            ${PROJECT_SOURCE_DIR}/backends/network
            ${PROJECT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/support
            ${CMAKE_CURRENT_SOURCE_DIR}/unit)
        target_compile_options(test_nw_lifecycle PRIVATE ${WTQ_WARN_FLAGS}
            -Wno-nullability-extension -Wno-nullability-completeness)
        add_test(NAME nw_lifecycle COMMAND test_nw_lifecycle)
        set_tests_properties(nw_lifecycle PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "network;loopback"
            TIMEOUT 300)

        # Dedicated caller-thread establishment battery (own fresh server).
        add_executable(test_nw_create_thread network/test_nw_create_thread.c)
        target_link_libraries(test_nw_create_thread PRIVATE
            wtq::network-testing wtq::msquic Threads::Threads)
        target_include_directories(test_nw_create_thread PRIVATE
            ${PROJECT_SOURCE_DIR}/backends/network
            ${PROJECT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/support
            ${CMAKE_CURRENT_SOURCE_DIR}/unit)
        target_compile_options(test_nw_create_thread PRIVATE ${WTQ_WARN_FLAGS}
            -Wno-nullability-extension -Wno-nullability-completeness)
        add_test(NAME nw_create_thread COMMAND test_nw_create_thread)
        set_tests_properties(nw_create_thread PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "network;loopback"
            TIMEOUT 600)

        # The public header consumed exactly as shipped: strict C99 and
        # C++17 translation units with no backend-internal includes.
        add_executable(consumer_network_header_c99
            consumer/network_header/use_header.c)
        target_link_libraries(consumer_network_header_c99 PRIVATE
            wtq::network)
        set_target_properties(consumer_network_header_c99 PROPERTIES
            C_STANDARD 99 C_STANDARD_REQUIRED ON)
        add_test(NAME consumer_network_header_c99
            COMMAND consumer_network_header_c99)
        set_tests_properties(consumer_network_header_c99 PROPERTIES
            LABELS network)
        add_executable(consumer_network_header_cxx
            consumer/network_header/use_header.cpp)
        target_link_libraries(consumer_network_header_cxx PRIVATE
            wtq::network)
        set_target_properties(consumer_network_header_cxx PROPERTIES
            CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
        add_test(NAME consumer_network_header_cxx
            COMMAND consumer_network_header_cxx)
        set_tests_properties(consumer_network_header_cxx PROPERTIES
            LABELS network)

        # Backend export surface: a LEAN shared build (no WTQ_NW_TESTING)
        # must export exactly the pinned wtq_nw_* allowlist. Only
        # meaningful where the core builds PIC/shared.
        if(BUILD_SHARED_LIBS)
            add_library(wtquic-network-shared SHARED
                ${PROJECT_SOURCE_DIR}/backends/network/nw_conn.c
                ${PROJECT_SOURCE_DIR}/backends/network/nw_send_holder.m)
            target_link_libraries(wtquic-network-shared
                PUBLIC wtq::wtquic
                PRIVATE "-framework Network" "-framework Security"
                        "-framework Foundation")
            target_include_directories(wtquic-network-shared PRIVATE
                ${PROJECT_SOURCE_DIR}/include
                ${PROJECT_BINARY_DIR}/include
                ${PROJECT_SOURCE_DIR}/src)
            set_source_files_properties(
                ${PROJECT_SOURCE_DIR}/backends/network/nw_send_holder.m
                PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
            target_compile_options(wtquic-network-shared PRIVATE
                ${WTQ_WARN_FLAGS} -Wno-nullability-extension
                -Wno-nullability-completeness)
            set_target_properties(wtquic-network-shared PROPERTIES
                C_VISIBILITY_PRESET hidden)
            add_test(NAME network_symbol_policy
                COMMAND ${CMAKE_COMMAND}
                    -DDYLIB=$<TARGET_FILE:wtquic-network-shared>
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_wtq_network_symbols.cmake)
            set_tests_properties(network_symbol_policy PROPERTIES
                LABELS network)
        endif()

        # Installed-package story: find_package COMPONENTS network,
        # relocated prefix, static pkg-config, missing-component
        # failure, install-tree hygiene, exact installed symbol surface.
        add_test(NAME consumer_install_network
            COMMAND ${CMAKE_COMMAND}
                -DBUILD=${CMAKE_BINARY_DIR}
                -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/consumer/network_pkg
                -DWORK=${CMAKE_CURRENT_BINARY_DIR}/consumer_install_network
                "-DC_FLAGS=${CMAKE_C_FLAGS}"
                "-DLINK_FLAGS=${CMAKE_EXE_LINKER_FLAGS}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/consumer_install_network.cmake)
        set_tests_properties(consumer_install_network PROPERTIES
            LABELS network TIMEOUT 300)

        # Embedded add_subdirectory(wtquic): configure/build/install with
        # packaging files generated inside wtquic's own directories.
        add_test(NAME consumer_embed_network
            COMMAND ${CMAKE_COMMAND}
                -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/consumer/embed_full
                -DWTQ=${PROJECT_SOURCE_DIR}
                -DWORK=${CMAKE_CURRENT_BINARY_DIR}/consumer_embed_network
                -DMSQUIC_DIR=${msquic_DIR}
                -DMSQUIC_ROOT=${WTQ_MSQUIC_ROOT}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/consumer_embed_network.cmake)
        set_tests_properties(consumer_embed_network PROPERTIES
            LABELS network TIMEOUT 600)

        # Minimal raw-NW lifecycle diagnostic: no wtquic engine or backend,
        # only Network.framework against the raw MsQuic observer. It retains
        # the settled-abort teardown shape as a control if a future backend
        # lifetime regression needs framework attribution. MANUAL target,
        # deliberately not a registered test.
        add_executable(nw_apple_repro EXCLUDE_FROM_ALL
            network/repro_nw_stream_teardown.c
            network/support/raw_peer.c)
        target_include_directories(nw_apple_repro PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/network/support)
        target_link_libraries(nw_apple_repro PRIVATE
            msquic::msquic Threads::Threads
            "-framework Network" "-framework Security")
        target_compile_options(nw_apple_repro PRIVATE ${WTQ_WARN_FLAGS}
            -Wno-nullability-extension -Wno-nullability-completeness)

        add_test(NAME nw_loopback_gate20 COMMAND test_nw_loopback)
        set_tests_properties(nw_loopback_gate20 PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT
            "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs;WTQ_NW_LOOPBACK_RUNS=20"
            LABELS "network;loopback;gate"
            TIMEOUT 900)
    endif()

    # env_close contract: active child teardown, bounded by construction —
    # the TIMEOUT is the backstop that makes a passive-close regression
    # (which would wait on an idle timeout that never comes) fail loudly.
    add_executable(loopback_env_close loopback/loopback_env_close.c)
    target_link_libraries(loopback_env_close PRIVATE wtq::msquic
        Threads::Threads)
    target_include_directories(loopback_env_close PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unit)
    target_compile_options(loopback_env_close PRIVATE ${WTQ_WARN_FLAGS})
    if(WTQ_BASH)
        add_test(NAME loopback_env_close COMMAND loopback_env_close)
        set_tests_properties(loopback_env_close PROPERTIES
            FIXTURES_REQUIRED certs
            ENVIRONMENT "WTQ_TEST_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/certs"
            LABELS "msquic;loopback"
            TIMEOUT 120)
    endif()
endif()
