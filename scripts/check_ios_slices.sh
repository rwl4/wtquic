#!/usr/bin/env bash
#
# Cross-build the iOS device and simulator slices (core + network, no
# tests), install each into a scratch prefix, and prove they are
# consumable: the installed archives export exactly the public wtq_nw_*
# surface (no test/probe symbols), the CMake package and pkg-config
# metadata resolve, and C99/C++17 consumers configure, compile, and
# LINK against the install (cross-compiled; never run).
#
# Usage: check_ios_slices.sh <repo-root> [workdir]

set -euo pipefail

ROOT="${1:?usage: check_ios_slices.sh <repo-root> [workdir]}"
WORK="${2:-$ROOT/build/ios-slices-work}"

NW_API="wtq_nw_conn_cfg_init wtq_nw_conn_create wtq_nw_conn_retain \
wtq_nw_conn_release wtq_nw_conn_post wtq_nw_conn_is_on_domain \
wtq_nw_conn_session wtq_nw_conn_stop_begin wtq_nw_conn_join \
wtq_nw_conn_doorbell_ring"

for SLICE in device sim; do
    PRESET="ios-$SLICE"
    PREFIX="$WORK/prefix-$SLICE"
    CBUILD="$WORK/consumer-$SLICE"
    rm -rf "$ROOT/build/$PRESET" "$PREFIX" "$CBUILD"

    echo "== $PRESET: configure + build + install"
    cmake -S "$ROOT" --preset "$PRESET" > "$WORK/$SLICE-configure.log" 2>&1
    cmake --build "$ROOT/build/$PRESET" -j > "$WORK/$SLICE-build.log" 2>&1
    cmake --install "$ROOT/build/$PRESET" --prefix "$PREFIX" \
        > "$WORK/$SLICE-install.log" 2>&1

    echo "== $PRESET: archive architecture + symbol surface"
    LIB="$PREFIX/lib/libwtquic-network.a"
    test -f "$LIB"
    lipo -archs "$LIB" | grep -q arm64
    NM="$(nm -gU "$LIB")"
    if grep -q "wtq_nw_test" <<< "$NM"; then
        echo "FAIL: $SLICE archive ships test seams"; exit 1
    fi
    for SYM in $NW_API; do
        grep -q "T _$SYM\$" <<< "$NM" || {
            echo "FAIL: $SLICE archive missing $SYM"; exit 1; }
    done
    COUNT=$(grep -oE "T _wtq_nw_[a-z0-9_]+" <<< "$NM" | sort -u | wc -l)
    if [ "$COUNT" -ne 10 ]; then
        echo "FAIL: $SLICE wtq_nw_* surface is $COUNT, expected 10"
        exit 1
    fi

    echo "== $PRESET: installed metadata"
    test -f "$PREFIX/lib/cmake/wtquic/wtquic-networkTargets.cmake"
    test -f "$PREFIX/lib/pkgconfig/wtquic-network.pc"
    test -f "$PREFIX/include/wtquic/wtquic_network.h"
    if ls "$PREFIX"/lib/cmake/wtquic/wtquic-msquic* >/dev/null 2>&1; then
        echo "FAIL: $SLICE install ships the msquic component"; exit 1
    fi
    if command -v pkg-config >/dev/null; then
        PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
            pkg-config --static --libs wtquic-network \
            | grep -q -- "-framework Network" || {
            echo "FAIL: $SLICE pc lacks the framework link flags"; exit 1; }
    fi

    echo "== $PRESET: C99 + C++17 consumers (configure/compile/link)"
    SDK=iphoneos; [ "$SLICE" = sim ] && SDK=iphonesimulator
    cmake -S "$ROOT/tests/consumer/network_pkg" -B "$CBUILD" \
        -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 \
        -DCMAKE_OSX_SYSROOT="$SDK" -DCMAKE_OSX_DEPLOYMENT_TARGET=16.0 \
        "-Dwtquic_DIR=$PREFIX/lib/cmake/wtquic" \
        > "$WORK/$SLICE-consumer-configure.log" 2>&1
    cmake --build "$CBUILD" > "$WORK/$SLICE-consumer-build.log" 2>&1
    for EXE in consumer consumer_cxx; do
        # CMake wraps iOS executables in .app bundles
        BIN="$CBUILD/$EXE.app/$EXE"
        [ -f "$BIN" ] || BIN="$CBUILD/$EXE"
        test -f "$BIN"
        lipo -archs "$BIN" | grep -q arm64
    done
done

echo "PASS: ios_slices (device + simulator consumable)"
