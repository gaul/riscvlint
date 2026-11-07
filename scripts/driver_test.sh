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

ok()  { printf "  ok      %s\n" "$1"; PASS=$((PASS + 1)); }
bad() { printf "  FAIL    %s\n" "$1"; shift; [ $# -eq 0 ] || printf "          %s\n" "$@"; FAIL=$((FAIL + 1)); }

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
# The fusion report likewise: a pair that fuses is not a finding.
expect 0 -u "$WORK/dirty.o"
expect 2 -u "$WORK/does-not-exist"
# -q asks for the default and is kept only so the invocations that
# passed it still work, so it must stay accepted.
expect 1 -q "$WORK/dirty.o"
expect 1 -v "$WORK/dirty.o"

# Every long name runs the same scan as its letter, with a value as the
# next argument or joined with '='.
expect 1 --verbose "$WORK/dirty.o"
expect 1 --quiet "$WORK/dirty.o"
expect 0 --isa "$WORK/dirty.o"
expect 0 --fusion "$WORK/dirty.o"
expect 1 --constants "$WORK/dirty.o"
expect 1 -m rva23 "$WORK/dirty.o"
expect 1 --assume rva23 "$WORK/dirty.o"
expect 1 --assume=rva23 "$WORK/dirty.o"
expect 1 --enable=imm "$WORK/dirty.o"
# Options are read wherever they stand, so a file may come first.
expect 1 "$WORK/dirty.o" -v
# The error paths: a value on a switch, a valued option without one, an
# unknown value, and the old fusion letter -- -f is --function in armlint
# and x86lint, so it is refused here rather than given a third meaning.
expect 2 --verbose=yes "$WORK/dirty.o"
expect 2 -m
expect 2 --assume
expect 2 --assume=no-such-extension "$WORK/clean.o"
expect 2 --enable no-such-audit "$WORK/clean.o"
expect 2 -f "$WORK/dirty.o"
# --help is an answer rather than a scan: it exits 0 and needs no file,
# and it names every option.
expect 0 --help
expect 0 -h
missing=""
for name in verbose quiet isa fusion constants json assume enable help; do
    "$ROOT/riscvlint" --help | grep -q -- "--$name" || missing="$missing --$name"
done
if [ -z "$missing" ]; then
    ok "--help names every option"
else
    bad "--help names every option" "missing:$missing"
fi

# The verbosity default, which is the other thing the snapshot suite
# cannot see: every fixture passes -v, so nothing there would notice the
# polarity flipping back.
lines()
{
    set +e
    "$ROOT/riscvlint" "$@" "$WORK/dirty.o" 2> /dev/null |
        grep -c 'at offset: 0x'
    set -e
}
n=$(lines)
if [ "$n" = 0 ]; then
    ok "the default prints no per-finding lines"
else
    bad "the default prints no per-finding lines" "got $n"
fi
n=$(lines -v)
if [ "$n" -gt 0 ]; then
    ok "-v prints them ($n)"
else
    bad "-v prints them" "got $n"
fi
# And the summary is in both, so the default is a report rather than a
# silence.
set +e
"$ROOT/riscvlint" "$WORK/dirty.o" 2>/dev/null | grep -q 'optimization opportunities in'
got=$?
set -e
if [ "$got" = 0 ]; then
    ok "the default still prints the summary"
else
    bad "the default still prints the summary"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
