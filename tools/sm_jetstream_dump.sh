#!/bin/sh
# Run JetStream 3 under a SpiderMonkey shell carrying tools/sm_code_dump.patch,
# one shell process per test, producing the dumps tools/smdump2elf.py reads.
#
#   tools/sm_jetstream_dump.sh OUTDIR [test...]
#
#   JS          the js shell (default: ~/work/firefox/obj-js-opt/dist/bin/js);
#               native riscv64, or another host's build with
#               --enable-simulator=riscv64
#   JETSTREAM   a checkout of https://github.com/WebKit/JetStream
#               (default: ~/work/JetStream)
#   JOBS        tests run at once (default: half the online CPUs)
#   TIMEOUT     seconds before a test is killed (default: 7200)
#   JS_ARGS     extra shell flags, e.g. --no-ion
#
# With no tests named, the default suite (cli.js --dump-test-list) runs.
# Each test runs in its own process because the hook writes one file per
# process, OUTDIR/dump/<test>.<pid>.bin, and smdump2elf.py names the code
# after the <test> part. A test's log goes to OUTDIR/log/<test>.txt, one
# "<test> rc=N secs=N" line per test to OUTDIR/status.txt, and OUTDIR/DONE
# is written last, so a detached run can be waited on by polling for it.
#
# Under the simulator a JIT-bound test runs ~300x slower than natively; a
# full run took ~50 minutes at 12 jobs plus hours for the largest Wasm
# tests. The Wasm SIMD tests (dotnet-*, argon2-wasm,
# transformersjs-bert-wasm) fail on riscv64, which has no Wasm SIMD, but
# still dump what they compiled before failing.
set -eu
out=${1:?usage: sm_jetstream_dump.sh OUTDIR [test...]}
shift
mkdir -p "$out/dump" "$out/log"
out=$(cd "$out" && pwd)
JS=${JS:-$HOME/work/firefox/obj-js-opt/dist/bin/js}
JETSTREAM=${JETSTREAM:-$HOME/work/JetStream}
ncpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
JOBS=${JOBS:-$(( (ncpu + 1) / 2 ))}
TIMEOUT=${TIMEOUT:-7200}
JS_ARGS=${JS_ARGS:-}
cd "$JETSTREAM"
if [ $# -eq 0 ]; then
    # shellcheck disable=SC2046
    set -- $("$JS" cli.js --dump-test-list | grep -v '^Starting')
fi
rm -f "$out/DONE" "$out/status.txt"
{
    echo "js: $JS $JS_ARGS"
    echo "jetstream: $JETSTREAM"
    echo "jobs: $JOBS timeout: $TIMEOUT"
    echo "start: $(date)"
} > "$out/run.txt"
export JS JS_ARGS TIMEOUT out
# shellcheck disable=SC2016
printf '%s\n' "$@" | xargs -P "$JOBS" -n 1 sh -c '
    t=$1
    s=$(date +%s)
    rc=0
    # shellcheck disable=SC2086
    JS_CODE_DUMP=$out/dump/$t timeout -k 10 "$TIMEOUT" "$JS" $JS_ARGS \
        cli.js --test="$t" > "$out/log/$t.txt" 2>&1 || rc=$?
    echo "$t rc=$rc secs=$(( $(date +%s) - s ))" >> "$out/status.txt"
' _
echo "end: $(date)" >> "$out/run.txt"
echo "$(wc -l < "$out/status.txt") tests, $(grep -vc ' rc=0 ' "$out/status.txt" || true) failed" > "$out/DONE"
