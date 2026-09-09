#!/bin/sh
# Integration test harness: assemble each fixtures/*.s for riscv64, run
# riscvlint over the result, and diff against the matching .expected.
#
# Set MODE=regen as the first argument to write the .expected files from
# current output instead of comparing.
#
# Exit codes: 0 all fixtures matched, 1 a fixture differed, 2 the suite
# could not run (no riscvlint binary, or no assembler able to target
# riscv64). The distinction matters -- a missing assembler would
# otherwise report success having tested nothing.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=${1:-check}
PASS=0
FAIL=0

if [ ! -x "$ROOT/riscvlint" ]; then
    echo "run_fixtures: no riscvlint binary; run make first" >&2
    exit 2
fi

# -mno-relax keeps the assembler from deferring local branch targets to
# the linker: with relaxation on, a branch to a local label is left as a
# relocation and the side-entry fixture would not exercise anything.
CC=${CC:-clang}
CC_FLAGS="--target=riscv64-unknown-linux-gnu -march=rv64gc -mno-relax"

PROBE=$(mktemp -d)
trap 'rm -rf "$PROBE"' EXIT
printf '\t.text\n\tauipc\tra, 0\n\tjalr\tra, 16(ra)\n' > "$PROBE/probe.s"
if ! probe_err=$($CC $CC_FLAGS -c -o "$PROBE/probe.o" "$PROBE/probe.s" 2>&1); then
    echo "run_fixtures: $CC $CC_FLAGS -c cannot assemble RISC-V" >&2
    echo "run_fixtures: the integration suite requires it; install clang" >&2
    echo "$probe_err" >&2
    exit 2
fi

for src in "$ROOT"/fixtures/*.s; do
    name=$(basename "$src" .s)
    obj="$PROBE/$name.o"
    # A fixture may pin extra assembler flags in a sidecar
    # fixtures/<name>.flags -- an extension-gated check needs the object
    # to declare that extension in Tag_RISCV_arch, which is a property of
    # -march at assembly time rather than anything the source can say.
    extra=""
    if [ -f "$ROOT/fixtures/$name.flags" ]; then
        extra=$(cat "$ROOT/fixtures/$name.flags")
    fi
    if ! err=$($CC $CC_FLAGS $extra -c -o "$obj" "$src" 2>&1); then
        printf "  ERROR   %s  (assembly failed)\n" "$name"
        echo "$err" | sed 's/^/          /'
        FAIL=$((FAIL + 1))
        continue
    fi
    # And a fixtures/<name>.args sidecar pins riscvlint's own flags, so
    # the -m override paths get an end-to-end case rather than only a
    # unit test of the name table.
    args=""
    if [ -f "$ROOT/fixtures/$name.args" ]; then
        args=$(cat "$ROOT/fixtures/$name.args")
    fi
    got="$PROBE/$name.out"
    "$ROOT/riscvlint" $args "$obj" > "$got" 2>&1 || true
    # The note lines carry the object path, which is a temporary
    # directory; keep the fixture stable by reducing it to the basename.
    # Written through a copy rather than sed -i, whose in-place spelling
    # differs between GNU and BSD.
    sed "s|$PROBE/||g" "$got" > "$got.tmp" && mv "$got.tmp" "$got"
    exp="$ROOT/fixtures/$name.expected"
    if [ "$MODE" = regen ]; then
        cp "$got" "$exp"
        printf "  regen   %s\n" "$name"
        PASS=$((PASS + 1))
        continue
    fi
    if [ ! -f "$exp" ]; then
        printf "  MISSING %s.expected  (run: make integration-test-regen)\n" \
            "$name"
        FAIL=$((FAIL + 1))
        continue
    fi
    if diff -u "$exp" "$got" > "$PROBE/$name.diff"; then
        printf "  ok      %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  FAIL    %s\n" "$name"
        sed 's/^/          /' "$PROBE/$name.diff"
        FAIL=$((FAIL + 1))
    fi
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
