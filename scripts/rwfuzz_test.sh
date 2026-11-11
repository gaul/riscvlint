#!/bin/sh
# Run riscvlint's advice: tools/rwfuzz applies every finding's rewrite
# to random programs and runs original and rewrite from the same state
# (see its header), in every mode. A mode with a control arm must also
# see some rewrite riscvlint refused change a result: a harness that had
# stopped seeing differences would pass everything else.
#
# The programs run natively, so tools/rwfuzz must be a riscv64 binary
# run on a riscv64 host -- or under an emulator, which RWFUZZ_EXEC
# names. Built for any other host it is a stub that exits 2, and so does
# this test.
#
#   RWFUZZ_PROGRAMS   programs per mode (default 10000)
#   RWFUZZ_SEED       seed (default 0: the same programs every run)
#   RWFUZZ_EXEC       a command to run rwfuzz under, such as
#                     "qemu-riscv64 -cpu max" (default: none)
#
# Exit status: 0 passed, 1 a mode failed, 2 the test could not run.

set -eu

cd "$(dirname "$0")/.."
RWFUZZ=./tools/rwfuzz
if [ ! -x "$RWFUZZ" ]; then
    echo "rwfuzz_test: $RWFUZZ not found; run 'make tools/rwfuzz' first" >&2
    exit 2
fi

PROGRAMS=${RWFUZZ_PROGRAMS:-10000}
SEED=${RWFUZZ_SEED:-0}
EXEC=${RWFUZZ_EXEC:-}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# With no mode rwfuzz prints its usage, modes included; the stub prints
# why it cannot run instead.
set +e
$EXEC "$RWFUZZ" > "$T/usage" 2>&1
set -e
MODES=$(sed -n 's/^ *modes: //p' "$T/usage")
if [ -z "$MODES" ]; then
    echo "rwfuzz_test: $RWFUZZ lists no modes" >&2
    cat "$T/usage" >&2
    exit 2
fi

# rwfuzz is one process, so the modes run side by side, one process
# each, and their reports print in order once all have finished.
for mode in $MODES; do
    $EXEC "$RWFUZZ" -n "$PROGRAMS" -s "$SEED" "$mode" > "$T/$mode.out" 2>&1 &
    echo $! > "$T/$mode.pid"
done

FAIL=0
for mode in $MODES; do
    set +e
    wait "$(cat "$T/$mode.pid")"
    rc=$?
    set -e
    echo "== $EXEC $RWFUZZ -n $PROGRAMS -s $SEED $mode"
    cat "$T/$mode.out"
    if [ "$rc" -ne 0 ]; then
        echo "  FAIL    $mode: rwfuzz exited $rc"
        FAIL=1
        continue
    fi
    diffs=$(sed -n 's/^  control: .*, \([0-9][0-9]*\) changed the result$/\1/p' "$T/$mode.out")
    if [ -n "$diffs" ] && [ "$diffs" -eq 0 ]; then
        echo "  FAIL    $mode: no refused rewrite changed a result"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo "rwfuzz: FAILED (replay: RWFUZZ_SEED=$SEED RWFUZZ_PROGRAMS=$PROGRAMS $0)"
    exit 1
fi
echo "rwfuzz: passed"
