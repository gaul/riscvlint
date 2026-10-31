#!/bin/sh
# Run JetStream 3 under d8 with the JIT code printers on, producing the
# dump tools/v8dump2elf.py reads.
#
#   tools/v8_jetstream_dump.sh OUTDIR [extra d8 flags...]
#
#   D8          the d8 binary (default: ~/work/v8/out/rv/d8); needs a build
#               with v8_enable_disassembler=true
#   JETSTREAM   a checkout of https://github.com/WebKit/JetStream
#   JETSTREAM_ARGS  the runner's own arguments (default: the default suite
#               minus the Wasm workloads and bomb-workers, see below)
#
# All of V8's code printers write to stdout (only the optimizing tiers
# honour --redirect-code-traces; baseline and regexp code do not), so stdout
# is the dump: OUTDIR/code.asm, with JetStream's own score lines mixed in,
# which v8dump2elf.py ignores. stderr goes to OUTDIR/jetstream.log and the
# score lines are extracted to OUTDIR/scores.txt.
#
# Two kinds of workload are excluded by default. --print-code also prints
# every Liftoff and TurboFan Wasm function, from background compile
# threads, which interleaves with and corrupts the JS code listing; and
# bomb-workers runs Worker isolates that print to the same stdout. d8 also
# fails to exit after a printing run (it idles with its threads parked
# after the final score), so the run is ended once the "Overall Score"
# line has appeared.
set -eu
out=${1:?usage: v8_jetstream_dump.sh OUTDIR [d8 flags]}
shift
mkdir -p "$out"
out=$(cd "$out" && pwd)
D8=${D8:-$HOME/work/v8/out/rv/d8}
JS=${JETSTREAM:-$HOME/work/JetStream}
cd "$JS"
list() {
    "$D8" cli.js -- --dump-test-list "$@" 2>/dev/null \
        | grep -v "^V8 is\|^Concurrent\|^$" | tr "\n" "," | sed "s/,$//"
}
if [ -z "${JETSTREAM_ARGS:-}" ]; then
    JETSTREAM_ARGS="--tag=default --exclude=$(list --tag=wasm),bomb-workers"
fi
flags="--print-opt-code --print-maglev-code --print-code --print-regexp-code $*"
echo "$flags" > "$out/d8.flags"
echo "$JETSTREAM_ARGS" > "$out/jetstream.args"
echo "start $(date -Is)" > "$out/jetstream.log"
# shellcheck disable=SC2086
"$D8" $flags cli.js -- $JETSTREAM_ARGS > "$out/code.asm" 2>> "$out/jetstream.log" &
pid=$!
# Wait for the run to finish or d8 to exit, then stop the parked process.
while kill -0 $pid 2>/dev/null; do
    if grep -q "^Overall Score" "$out/code.asm" 2>/dev/null; then
        sleep 10
        kill $pid 2>/dev/null || true
        sleep 5
        kill -9 $pid 2>/dev/null || true
        break
    fi
    sleep 15
done
wait $pid 2>/dev/null || echo "d8 exit $?" >> "$out/jetstream.log"
echo "end $(date -Is)" >> "$out/jetstream.log"
grep -E "^[A-Za-z0-9_-]+ +(First|Worst|Average|Score|Overall)" "$out/code.asm" > "$out/scores.txt" || true
ls -la "$out" >> "$out/jetstream.log"
