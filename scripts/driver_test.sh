#!/bin/sh
# Driver test: riscvlint's exit status, which the snapshot suite under
# fixtures/ cannot cover because it compares stdout and discards the
# status (`|| true`).
#
# The convention is grep's -- 0 clean, 1 findings, 2 tool failure -- and
# the third value is the one worth a test: without it a CI job cannot
# tell a dirty scan from a broken run.
#
# Exit codes: 0 all cases passed, 1 a case failed, 2 the suite could not
# run (no riscvlint binary, or no assembler able to target riscv64).

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PASS=0
FAIL=0

if [ ! -x "$ROOT/riscvlint" ]; then
    echo "driver_test: no riscvlint binary; run make first" >&2
    exit 2
fi

CC=${CC:-clang}
CC_FLAGS="--target=riscv64-unknown-linux-gnu -march=rv64gc -mno-relax"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

printf '\t.text\n\tauipc\tra, 0\n\tjalr\tra, 16(ra)\n' > "$WORK/dirty.s"
if ! probe_err=$($CC $CC_FLAGS -c -o "$WORK/dirty.o" "$WORK/dirty.s" 2>&1); then
    echo "driver_test: $CC $CC_FLAGS -c cannot assemble RISC-V" >&2
    echo "$probe_err" >&2
    exit 2
fi
# Nothing to fold: one instruction that no check matches.
printf '\t.text\n\tnop\n' > "$WORK/clean.s"
$CC $CC_FLAGS -c -o "$WORK/clean.o" "$WORK/clean.s"
# Not an ELF at all, and an ELF that is not riscv64.
printf 'not an elf\n' > "$WORK/text.txt"

expect()
{
    want=$1
    shift
    set +e
    "$ROOT/riscvlint" "$@" > "$WORK/out" 2>&1
    got=$?
    set -e
    if [ "$got" = "$want" ]; then
        printf "  ok      %s -> %s\n" "$*" "$got"
        PASS=$((PASS + 1))
    else
        printf "  FAIL    %s -> %s, want %s\n" "$*" "$got" "$want"
        sed 's/^/          /' "$WORK/out"
        FAIL=$((FAIL + 1))
    fi
}

expect 0 -q "$WORK/clean.o"
expect 1 -q "$WORK/dirty.o"
# A tool failure outranks a dirty scan, in either argument order.
expect 2 -q "$WORK/dirty.o" "$WORK/does-not-exist"
expect 2 -q "$WORK/does-not-exist" "$WORK/dirty.o"
expect 2 -q "$WORK/text.txt"
expect 2 -q /dev/null
expect 2 --no-such-flag "$WORK/clean.o"
expect 2 -m no-such-extension "$WORK/clean.o"
expect 2
# The census describes a file rather than judging it, so a dirty binary
# is not a finding there -- but an unreadable one is still a failure.
expect 0 -q -i "$WORK/dirty.o"
expect 2 -q -i "$WORK/does-not-exist"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
