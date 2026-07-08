# EXPERIMENTAL Network.framework capability probe.
#
# Not a backend, not a library, not installed, not exported, not part of
# any package config, and not built unless explicitly asked for:
#
#   cmake -B build/nwprobe -DWTQ_BUILD_NW_EXPERIMENTAL=ON \
#         -DWTQ_BUILD_MSQUIC=ON
#   cmake --build build/nwprobe --target wtq_nw_probe
#   scripts/gen_test_certs.sh build/nwprobe/certs
#   ./build/nwprobe/backends/network_experimental/wtq_nw_probe \
#         build/nwprobe/certs
#
# It links the MsQuic backend only to stand up a REAL QUIC peer, so the
# observations come from the Apple runtime rather than a mock.

if(NOT APPLE)
    message(STATUS "wtquic: NW probe skipped (Apple only)")
    return()
endif()
if(NOT WTQ_MSQUIC_ENABLED)
    message(STATUS "wtquic: NW probe skipped (needs MsQuic for the raw peer)")
    return()
endif()

# raw_peer.c is an experimental bare-QUIC observer used to validate what the
# Apple client actually puts on the wire. It links MsQuic directly and does
# not touch the production backend or the wtquic engine.
#
# The probe is SELF-CHECKING: it exits nonzero if any required observation
# fails. It is still deliberately kept out of ctest/CI while experimental.
# send_sentinel.m is the probe's only Objective-C: an ARC-captured sentinel
# whose dealloc makes completion-block DISPOSAL observable from C.
add_executable(wtq_nw_probe EXCLUDE_FROM_ALL nw_probe.c raw_peer.c
    send_sentinel.m)
set_source_files_properties(send_sentinel.m PROPERTIES
    COMPILE_OPTIONS "-fobjc-arc")
target_link_libraries(wtq_nw_probe PRIVATE wtq::msquic
    "-framework Network" "-framework Security" "-framework Foundation")
# Blocks + the framework's nullability annotations; the probe is not held
# to the library's warning bar.
target_compile_options(wtq_nw_probe PRIVATE -fblocks -Wno-unused-parameter)

# Deliberately: no install(), no export(), no add_test(). The probe is
# run by hand and its findings are written up, not asserted.
message(STATUS "wtquic: NW probe target enabled (experimental)")
