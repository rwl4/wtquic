# libFuzzer targets. Requires Clang with the fuzzer runtime (Apple clang
# ships without it — use Homebrew LLVM clang locally). Fuzz targets compile
# the proto sources DIRECTLY so the parsers themselves are
# coverage-instrumented, not just the harness.
#
# WTQ_REQUIRE_FUZZ=ON turns a missing runtime into a configure error (CI).

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    if(WTQ_REQUIRE_FUZZ)
        message(FATAL_ERROR "WTQ_REQUIRE_FUZZ: fuzz targets need Clang")
    endif()
    message(STATUS "wtquic: fuzz targets skipped (compiler is not Clang)")
    return()
endif()

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_c_source_compiles("
int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s);
int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s)
{ (void)d; (void)s; return 0; }
" WTQ_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)

if(NOT WTQ_HAVE_LIBFUZZER)
    if(WTQ_REQUIRE_FUZZ)
        message(FATAL_ERROR
            "WTQ_REQUIRE_FUZZ: libFuzzer runtime not available "
            "(Apple clang lacks it; use LLVM clang)")
    endif()
    message(STATUS "wtquic: fuzz targets skipped (no libFuzzer runtime)")
    return()
endif()

set(WTQ_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer)

function(wtq_add_fuzz_target name)
    # ARGN: proto sources compiled into the target for instrumentation.
    add_executable(fuzz_${name} fuzz_${name}.c ${ARGN})
    target_include_directories(fuzz_${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
    )
    target_compile_options(fuzz_${name} PRIVATE ${WTQ_FUZZ_FLAGS})
    target_link_options(fuzz_${name} PRIVATE ${WTQ_FUZZ_FLAGS})

    # Smoke: startup only. Corpus: replay committed seeds (-runs=0).
    # detect_stack_use_after_return: harness-lifetime bugs (a capsule
    # fuzzer once returned spans into a dead stack frame) must fail here.
    add_test(NAME fuzz_${name}_smoke COMMAND fuzz_${name} -runs=1)
    set_tests_properties(fuzz_${name}_smoke PROPERTIES
        ENVIRONMENT "ASAN_OPTIONS=detect_stack_use_after_return=1")
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
        add_test(NAME fuzz_${name}_corpus
            COMMAND fuzz_${name} ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}
                    -runs=0)
        set_tests_properties(fuzz_${name}_corpus PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=detect_stack_use_after_return=1")
    endif()
endfunction()

wtq_add_fuzz_target(varint ${CMAKE_SOURCE_DIR}/src/proto/varint.c)
wtq_add_fuzz_target(h3_frame
    ${CMAKE_SOURCE_DIR}/src/proto/h3_frame.c
    ${CMAKE_SOURCE_DIR}/src/proto/varint.c)
wtq_add_fuzz_target(h3_settings
    ${CMAKE_SOURCE_DIR}/src/proto/h3_settings.c
    ${CMAKE_SOURCE_DIR}/src/proto/h3_frame.c
    ${CMAKE_SOURCE_DIR}/src/proto/varint.c)
wtq_add_fuzz_target(sf_string ${CMAKE_SOURCE_DIR}/src/proto/sf_string.c)
wtq_add_fuzz_target(capsule
    ${CMAKE_SOURCE_DIR}/src/proto/capsule.c
    ${CMAKE_SOURCE_DIR}/src/proto/h3_frame.c
    ${CMAKE_SOURCE_DIR}/src/proto/varint.c)
wtq_add_fuzz_target(preamble
    ${CMAKE_SOURCE_DIR}/src/proto/preamble.c
    ${CMAKE_SOURCE_DIR}/src/proto/varint.c)
wtq_add_fuzz_target(qpack_static
    ${CMAKE_SOURCE_DIR}/src/proto/qpack_static.c)
wtq_add_fuzz_target(connect
    ${CMAKE_SOURCE_DIR}/src/proto/connect.c
    ${CMAKE_SOURCE_DIR}/src/proto/qpack_static.c
    ${CMAKE_SOURCE_DIR}/src/proto/sf_string.c)

# --- stateful engine/API fuzzers ---------------------------------------------
# These drive the engine (and, for the soup fuzzer, the public API) to a
# state and then feed hostile byte/event sequences. They compile the
# engine + api + fake driver + a balance-checking allocator alongside the
# proto sources so all of it is coverage-instrumented. The fuzzers abort
# on any invariant violation (crash, UB, leak, steady-state allocation).

set(WTQ_ENGINE_SRCS
    ${CMAKE_SOURCE_DIR}/src/engine/conn.c
    ${CMAKE_SOURCE_DIR}/src/types.c
    ${CMAKE_SOURCE_DIR}/src/proto/capsule.c
    ${CMAKE_SOURCE_DIR}/src/proto/connect.c
    ${CMAKE_SOURCE_DIR}/src/proto/errmap.c
    ${CMAKE_SOURCE_DIR}/src/proto/h3_frame.c
    ${CMAKE_SOURCE_DIR}/src/proto/h3_settings.c
    ${CMAKE_SOURCE_DIR}/src/proto/preamble.c
    ${CMAKE_SOURCE_DIR}/src/proto/qpack_static.c
    ${CMAKE_SOURCE_DIR}/src/proto/sf_string.c
    ${CMAKE_SOURCE_DIR}/src/proto/varint.c
    ${CMAKE_SOURCE_DIR}/tests/support/fake_driver.c
    ${CMAKE_SOURCE_DIR}/tests/support/wtq_fault_alloc.c)

function(wtq_add_stateful_fuzz name)
    add_executable(fuzz_${name} fuzz_${name}.c ${WTQ_ENGINE_SRCS} ${ARGN})
    target_include_directories(fuzz_${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/engine
        ${CMAKE_SOURCE_DIR}/src/api
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests/support)
    target_compile_options(fuzz_${name} PRIVATE ${WTQ_FUZZ_FLAGS})
    target_link_options(fuzz_${name} PRIVATE ${WTQ_FUZZ_FLAGS})
    add_test(NAME fuzz_${name}_smoke COMMAND fuzz_${name} -runs=1)
    set_tests_properties(fuzz_${name}_smoke PROPERTIES
        ENVIRONMENT "ASAN_OPTIONS=detect_stack_use_after_return=1")
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
        add_test(NAME fuzz_${name}_corpus
            COMMAND fuzz_${name} ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}
                    -runs=0)
        set_tests_properties(fuzz_${name}_corpus PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=detect_stack_use_after_return=1")
    endif()
endfunction()

wtq_add_stateful_fuzz(engine_control)
wtq_add_stateful_fuzz(engine_connect)
wtq_add_stateful_fuzz(api_soup ${CMAKE_SOURCE_DIR}/src/api/session.c)

message(STATUS "wtquic: fuzz targets enabled (8 proto + 3 stateful)")
