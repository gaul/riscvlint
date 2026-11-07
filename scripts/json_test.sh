#!/bin/sh
# --json test: the document parses, its totals agree with the human
# run's, the refused flag combinations are refused, and a file the
# driver rejects leaves stdout empty rather than half a document.
#
# Exit codes: 0 all cases passed, 1 a case failed, 2 the suite could not
# run (no riscvlint binary, no python3 to parse with, or no assembler
# able to target riscv64).

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PASS=0
FAIL=0

if [ ! -x "$ROOT/riscvlint" ]; then
    echo "json_test: no riscvlint binary; run make first" >&2
    exit 2
fi
if ! command -v python3 > /dev/null 2>&1; then
    echo "json_test: no python3 to parse the document with" >&2
    exit 2
fi

CC=${CC:-clang}
CC_FLAGS="--target=riscv64-unknown-linux-gnu -march=rv64gc -mno-relax"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# An `auipc`+`jalr` call pair whose target `jal` reaches, which is the
# smallest fixture that reports anything: the totals must not be
# trivially zero, or test 2 would agree about nothing.
cat > "$WORK/dirty.s" <<'EOF'
	.text
	.globl	target
target:
	auipc	ra, 0
	jalr	ra, 16(ra)
	addi	s0, sp, 16
	ret
EOF
if ! probe_err=$($CC $CC_FLAGS -c -o "$WORK/dirty.o" "$WORK/dirty.s" 2>&1); then
    echo "json_test: $CC $CC_FLAGS -c cannot assemble RISC-V" >&2
    echo "$probe_err" >&2
    exit 2
fi
printf '\t.text\n\tnop\n' > "$WORK/clean.s"
$CC $CC_FLAGS -c -o "$WORK/clean.o" "$WORK/clean.s"
printf 'not an elf\n' > "$WORK/text.txt"

ok()   { printf "  ok      %s\n" "$1"; PASS=$((PASS + 1)); }
bad()  { printf "  FAIL    %s\n" "$1"; shift; [ $# -eq 0 ] || printf "          %s\n" "$@"; FAIL=$((FAIL + 1)); }

# Every document in a stream, as one JSON array on stdout.
parse()
{
    python3 -c '
import json, sys
dec = json.JSONDecoder()
s = sys.stdin.read()
docs, i = [], 0
while i < len(s):
    while i < len(s) and s[i].isspace():
        i += 1
    if i >= len(s):
        break
    doc, i = dec.raw_decode(s, i)
    docs.append(doc)
json.dump(docs, sys.stdout)
'
}

field()
{
    python3 -c '
import json, sys
docs = json.load(sys.stdin)
print(sum(d[sys.argv[1]] for d in docs))
' "$1"
}

# 1. The document parses, and each finding carries the fields a consumer
#    joins on. riscvlint exits 1 on a dirty scan, so its status is not
#    part of the condition here -- test 6 is where it is checked.
set +e
"$ROOT/riscvlint" --json "$WORK/dirty.o" > "$WORK/doc" 2> "$WORK/doc.err"
set -e
if parse < "$WORK/doc" > "$WORK/docs.json"; then
    if python3 -c '
import json, sys
docs = json.load(open(sys.argv[1]))
assert len(docs) == 1, docs
d = docs[0]
for key in ("file", "arch", "extensions", "findings", "instructions",
            "skipped", "opportunities"):
    assert key in d, key
assert d["findings"], "no findings in the dirty fixture"
assert len(d["findings"]) == d["opportunities"]
for f in d["findings"]:
    for key in ("vaddr", "check", "detail", "section", "text", "length"):
        assert key in f, key
    assert isinstance(f["vaddr"], int), "vaddr must be a number"
    assert isinstance(f["text"], list), "text must be an array of lines"
    # bytes is omitted rather than truncated past the cap, so where it
    # is present it must be the whole window: two hex digits per byte.
    if "bytes" in f:
        assert len(f["bytes"]) == 2 * f["length"], (f["length"], f["bytes"])
' "$WORK/docs.json" 2> "$WORK/err"; then
        ok "document parses with the expected fields"
    else
        bad "document parses with the expected fields" "$(cat "$WORK/err")"
    fi
else
    bad "document parses" "$(cat "$WORK/doc")"
fi

# 2. The totals agree with the human run's, which is the property that
#    would break first if the callback and the report diverged.
human=$("$ROOT/riscvlint" -q "$WORK/dirty.o" | tail -1)
h_found=$(echo "$human" | awk '{print $1}')
h_insns=$(echo "$human" | awk '{print $5}')
j_found=$(field opportunities < "$WORK/docs.json")
j_insns=$(field instructions < "$WORK/docs.json")
if [ "$h_found" = "$j_found" ] && [ "$h_insns" = "$j_insns" ]; then
    ok "totals agree with the human run ($h_found in $h_insns)"
else
    bad "totals agree with the human run" \
        "human $h_found/$h_insns, json $j_found/$j_insns"
fi

# 3. Several files give several documents, each carrying its own file's
#    share rather than a running total.
if "$ROOT/riscvlint" --json "$WORK/dirty.o" "$WORK/clean.o" 2>/dev/null |
       parse > "$WORK/two.json" &&
   python3 -c '
import json, sys
docs = json.load(open(sys.argv[1]))
assert len(docs) == 2, len(docs)
assert docs[1]["opportunities"] == 0, docs[1]
assert docs[1]["instructions"] == 1, docs[1]
' "$WORK/two.json" 2> "$WORK/err"; then
    ok "one document per file, each with its own totals"
else
    bad "one document per file" "$(cat "$WORK/err")"
fi

# 4. A rejected file leaves stdout empty rather than half a document.
set +e
"$ROOT/riscvlint" --json "$WORK/text.txt" > "$WORK/out" 2> /dev/null
status=$?
set -e
if [ "$status" = 2 ] && [ ! -s "$WORK/out" ]; then
    ok "a rejected file leaves stdout empty (exit 2)"
else
    bad "a rejected file leaves stdout empty" \
        "status $status, $(wc -c < "$WORK/out") bytes"
fi

# 5. The censuses, the fusion report and the verbose report are separate
#    reports whose output would interleave with the document, so those
#    combinations are refused rather than one of them chosen for the
#    caller.
for flag in -i -r -u -v; do
    set +e
    "$ROOT/riscvlint" --json $flag "$WORK/clean.o" > "$WORK/out" 2> /dev/null
    status=$?
    set -e
    if [ "$status" = 2 ] && [ ! -s "$WORK/out" ]; then
        ok "--json with $flag is refused"
    else
        bad "--json with $flag is refused" "status $status"
    fi
done
# -q asks for what --json already does and is accepted, so a script that
# passed it before the verbosity default flipped still produces a
# document rather than an error.
set +e
"$ROOT/riscvlint" --json -q "$WORK/dirty.o" > "$WORK/out" 2> /dev/null
status=$?
set -e
if [ "$status" = 1 ] && parse < "$WORK/out" > /dev/null; then
    ok "--json with -q still yields a document"
else
    bad "--json with -q still yields a document" "status $status"
fi

# 6. The exit status is the scan's, unchanged by the output mode.
set +e
"$ROOT/riscvlint" --json "$WORK/dirty.o" > /dev/null 2>&1; dirty=$?
"$ROOT/riscvlint" --json "$WORK/clean.o" > /dev/null 2>&1; clean=$?
set -e
if [ "$dirty" = 1 ] && [ "$clean" = 0 ]; then
    ok "exit status unchanged under --json (1 dirty, 0 clean)"
else
    bad "exit status unchanged under --json" "dirty $dirty, clean $clean"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
