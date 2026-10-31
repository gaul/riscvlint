#!/bin/sh
# Turn a V8 code dump into riscvlint findings and the cross-tabs.
#
#   tools/v8_analyze.sh DIR        (DIR holds code.asm; outputs land beside it)
#
#   RISCVLINT   the riscvlint binary (default: the one next to tools/)
#   ARCH        Tag_RISCV_arch string to declare (default: the one the
#               host's own binaries carry, via readelf -A /usr/bin/ls --
#               right when the dump was produced on this host)
#   JOBS        parallel riscvlint processes (default: 8)
#
# Steps: v8dump2elf.py -> code.elf[.N] + code.map + code.relocs;
# riscvlint --json per ELF in parallel -> code.elf[.N].json; riscvlint's
# own summary of all parts -> summary.txt; v8_analyze_findings.py ->
# analysis.txt + analysis-samples.txt. Timestamps go to analysis.log.
set -eu
dir=$(cd "${1:?usage: v8_analyze.sh DIR}" && pwd)
tools=$(cd "$(dirname "$0")" && pwd)
RISCVLINT=${RISCVLINT:-$tools/../riscvlint}
ARCH=${ARCH:-$(readelf -A /usr/bin/ls 2>/dev/null | sed -n 's/.*Tag_RISCV_arch: "\(.*\)"/\1/p')}
JOBS=${JOBS:-8}
cd "$dir"
echo "arch: ${ARCH:-(none)}" > analysis.log
date -Is >> analysis.log
rm -f code.elf code.elf.* code.map code.relocs
python3 -I "$tools/v8dump2elf.py" code.asm -o code.elf --map code.map --relocs code.relocs ${ARCH:+--arch "$ARCH"} 2>&1 | tee -a analysis.log
date -Is >> analysis.log
# A small dump gives one code.elf; a large one code.elf.1, code.elf.2, ...
parts=$(for f in code.elf code.elf.[0-9]*; do
    case $f in
    (*.json) ;;
    (*) [ -f "$f" ] && echo "$f" ;;
    esac
done)
# riscvlint exits 1 when it has findings, which is the expected outcome.
echo "$parts" | xargs -P "$JOBS" -I{} sh -c "$RISCVLINT --json {} > {}.json || true"
date -Is >> analysis.log
# shellcheck disable=SC2086
"$RISCVLINT" $parts > summary.txt 2>&1 || true
date -Is >> analysis.log
# shellcheck disable=SC2046
python3 -I "$tools/v8_analyze_findings.py" code.map code.relocs analysis $(echo "$parts" | sed "s/$/.json/") > analysis.txt 2>> analysis.log
{ date -Is; echo "done"; } >> analysis.log
