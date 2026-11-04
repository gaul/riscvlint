#!/bin/sh
# Turn a SpiderMonkey JIT dump into riscvlint findings and the cross-tabs.
#
#   tools/sm_analyze.sh DIR     (DIR holds dump/ from sm_jetstream_dump.sh;
#                                outputs land beside it)
#
#   RISCVLINT   the riscvlint binary (default: the one next to tools/)
#   ARCH        Tag_RISCV_arch string to declare (default: RV64GC's base
#               without C, plus every extension SpiderMonkey's riscv64
#               backend can use: Zba, Zbb, Zbs, Zfa, Zfhmin and Zicond).
#               The backend emits no compressed instructions, so declaring
#               C would report nearly every instruction as compressible.
#   JOBS        parallel riscvlint processes (default: the online CPUs)
#   JAL_VENEERS set to 1 for a shell whose veneers are a single jal, to
#               pass --jal-veneers to sm_census.py
#
# Steps: smdump2elf.py --dedupe-startup -> code.elf.N + code.map;
# riscvlint --json per ELF in parallel -> code.elf.N.json; riscvlint's own
# summary of all parts -> summary.txt; sm_analyze_findings.py ->
# analysis.txt + analysis-samples.txt; sm_census.py -> census.txt (the
# fixed-shape sequences and veneer pools); sm_constants.py ->
# constants.txt (what the patchable loads hold and feed). Timestamps go
# to analysis.log.
set -eu
dir=$(cd "${1:?usage: sm_analyze.sh DIR}" && pwd)
tools=$(cd "$(dirname "$0")" && pwd)
RISCVLINT=${RISCVLINT:-$tools/../riscvlint}
ARCH=${ARCH:-rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0_zba1p0_zbb1p0_zbs1p0_zfa1p0_zfhmin1p0_zicond1p0}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
census_args=
[ "${JAL_VENEERS:-0}" = 1 ] && census_args=--jal-veneers
cd "$dir"
stamp() { date >> analysis.log; }
echo "arch: $ARCH" > analysis.log
stamp
rm -f code.elf.* code.map
python3 -I "$tools/smdump2elf.py" --dedupe-startup -o code.elf --map code.map \
    --arch "$ARCH" dump/*.bin 2>&1 | tee -a analysis.log
parts=$(for f in code.elf.*; do
    case $f in
    (*.json) ;;
    (*) echo "$f" ;;
    esac
done | sort -t. -k3 -n)
stamp
# riscvlint exits 1 when it has findings, which is the expected outcome.
# shellcheck disable=SC2016
echo "$parts" | xargs -P "$JOBS" -n 1 sh -c '"$0" --json "$1" > "$1.json" || true' "$RISCVLINT"
stamp
# shellcheck disable=SC2086
"$RISCVLINT" $parts > summary.txt 2>&1 || true
stamp
{
    # shellcheck disable=SC2046
    python3 -I "$tools/sm_analyze_findings.py" code.map analysis $(echo "$parts" | sed 's/$/.json/')
    # shellcheck disable=SC2086
    python3 -I "$tools/sm_census.py" $census_args code.map $parts > census.txt
    # shellcheck disable=SC2086
    python3 -I "$tools/sm_constants.py" code.map dump $parts > constants.txt
} 2>> analysis.log
stamp
echo "done" >> analysis.log
