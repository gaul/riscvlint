#!/bin/sh
# Build Capstone at REV, RISC-V only and static, and install it under
# PREFIX -- what the Building section of README.md does by hand, for CI.
# Fetched rather than cloned so REV can be a commit as well as a tag:
# `clone --branch` takes only refs, while github.com serves any reachable
# SHA to a fetch. Extra arguments go to cmake, which is how a cross build
# names its compiler and system. An install already at PREFIX (a cache
# hit) is kept.
#
# usage: build_capstone.sh REV PREFIX [CMAKE_ARG]...

set -eu

if [ $# -lt 2 ]; then
    echo "usage: $0 REV PREFIX [CMAKE_ARG]..." >&2
    exit 2
fi
rev=$1
prefix=$2
shift 2

for lib in "$prefix"/lib64/libcapstone.a "$prefix"/lib/libcapstone.a; do
    if [ -f "$lib" ]; then
        echo "build_capstone: $lib already built"
        exit 0
    fi
done

src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git init -q "$src"
git -C "$src" remote add origin https://github.com/capstone-engine/capstone.git
git -C "$src" fetch -q --depth 1 origin "$rev"
git -C "$src" checkout -q FETCH_HEAD

cmake -S "$src" -B "$src/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_RISCV_SUPPORT=ON \
    -DCAPSTONE_BUILD_SHARED_LIBS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF \
    -DCMAKE_INSTALL_PREFIX="$prefix" "$@"
cmake --build "$src/build" -j "$(getconf _NPROCESSORS_ONLN)"
cmake --install "$src/build"
