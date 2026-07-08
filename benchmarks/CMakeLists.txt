# Proto-plane microbenchmarks. Report-only (JSON to stdout); thresholds
# harden into CI gates per the plan's performance-contract schedule.

add_executable(bench_proto
    bench_proto.c
    $<TARGET_OBJECTS:wtq_proto>
)
target_include_directories(bench_proto PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
)
target_compile_options(bench_proto PRIVATE ${WTQ_WARN_FLAGS})

# Smoke keeps the binary building and running in every test lane.
add_test(NAME bench_proto_smoke COMMAND bench_proto --smoke)
