#!/bin/sh
# Go pclntab test: that a finding in a Go binary is named after the
# function holding it, and that every way the table can be wrong falls
# back to no name rather than to a wrong one.
#
# The inputs are synthesized rather than taken from corpus/, which is
# not in the repository: python3 writes a minimal riscv64 ELF with one
# executable section, a .gopclntab describing two functions in it, and
# then a mutant per header field worth refusing.
#
# Exit codes: 0 all cases passed, 1 a case failed, 2 the suite could not
# run (no riscvlint binary, or no python3 to write the ELF with).

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PASS=0
FAIL=0

if [ ! -x "$ROOT/riscvlint" ]; then
    echo "gopclntab_test: no riscvlint binary; run make first" >&2
    exit 2
fi
if ! command -v python3 > /dev/null 2>&1; then
    echo "gopclntab_test: no python3 to write the test ELF with" >&2
    exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ok()  { printf "  ok      %s\n" "$1"; PASS=$((PASS + 1)); }
bad() { printf "  FAIL    %s\n" "$1"; shift; [ $# -eq 0 ] || printf "          %s\n" "$@"; FAIL=$((FAIL + 1)); }

python3 - "$WORK" <<'PY'
import struct, sys, os

out = sys.argv[1]

TEXT_ADDR = 0x11000
# Two functions, each an `auipc ra,0` + `jalr ra,16(ra)` call pair that
# folds to `jal` -- the smallest thing that reports a finding -- with the
# second starting eight bytes in.
TEXT = bytes.fromhex('97000000') + bytes.fromhex('e7800001') + \
       bytes.fromhex('97000000') + bytes.fromhex('e7800001')
NAMES = [b'main.alpha', b'main.beta']

def pclntab(magic=0xfffffff1, minlc=4, ptrsize=8, text_start=0,
            pad=0, entryoffs=(0, 8), nameoffs=None, sentinel=16,
            declared=None):
    # `declared` is what the header claims, which is not always what the
    # table holds: refusing an absurd nfunc has to happen before any
    # entry is read, so the mutant that tests it writes two entries and
    # claims millions.
    nfunc = 2
    # funcnametab, then the _func records, then the functab. cuOffset
    # bounds funcnametab, so it sits right after it.
    funcname = b'\0'.join([b''] + NAMES) + b'\0'
    funcname_off = 72
    cu_off = funcname_off + len(funcname)
    # The _func records: entryOff then nameOff, both uint32, which are
    # the only two fields a name needs.
    offs = nameoffs if nameoffs is not None else \
        [1 + sum(len(n) + 1 for n in NAMES[:i]) for i in range(len(NAMES))]
    pcln_off = cu_off
    funcs = b''
    func_at = []
    # functab first in the region, then the records after it: funcoff is
    # relative to the region's start, so anything inside works.
    functab_len = (nfunc + 1) * 8
    for i in range(len(NAMES)):
        func_at.append(functab_len + len(funcs))
        funcs += struct.pack('<II', entryoffs[i], offs[i])
    functab = b''
    for i in range(nfunc):
        j = min(i, len(NAMES) - 1)
        functab += struct.pack('<II', entryoffs[j], func_at[j])
    functab += struct.pack('<II', sentinel, 0)          # the sentinel
    hdr = struct.pack('<IBBBB', magic, pad, 0, minlc, ptrsize)
    hdr += struct.pack('<8Q', nfunc if declared is None else declared, 1,
                       text_start, funcname_off, cu_off, cu_off, cu_off,
                       pcln_off)
    assert len(hdr) == 72, len(hdr)
    return hdr + funcname + functab + funcs

def elf(path, pcln):
    shstr = b'\0.text\0.gopclntab\0.shstrtab\0'
    name_text = shstr.index(b'.text\0')
    name_pcln = shstr.index(b'.gopclntab\0')
    name_shstr = shstr.index(b'.shstrtab\0')
    ehsize, shentsize, nsec = 64, 64, 4
    off = ehsize
    text_off = off;  off += len(TEXT)
    pcln_off = off;  off += len(pcln)
    shstr_off = off; off += len(shstr)
    sh_off = (off + 7) & ~7

    eh = bytearray(ehsize)
    eh[0:4] = b'\x7fELF'
    eh[4] = 2            # ELFCLASS64
    eh[5] = 1            # little endian
    eh[6] = 1            # EV_CURRENT
    struct.pack_into('<HHI', eh, 16, 2, 243, 1)        # ET_EXEC, EM_RISCV
    struct.pack_into('<Q', eh, 24, TEXT_ADDR)          # e_entry
    struct.pack_into('<Q', eh, 40, sh_off)             # e_shoff
    struct.pack_into('<HHHHHH', eh, 52, ehsize, 0, 0, shentsize, nsec, 3)

    def shdr(name, typ, flags, addr, offset, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, offset,
                           size, 0, 0, 1, 0)
    sh = shdr(0, 0, 0, 0, 0, 0)
    sh += shdr(name_text, 1, 0x2 | 0x4, TEXT_ADDR, text_off, len(TEXT))
    sh += shdr(name_pcln, 1, 0x2, 0, pcln_off, len(pcln))
    sh += shdr(name_shstr, 3, 0, 0, shstr_off, len(shstr))

    blob = bytes(eh) + TEXT + pcln + shstr
    blob += b'\0' * (sh_off - len(blob)) + sh
    open(os.path.join(out, path), 'wb').write(blob)

elf('good', pclntab())
# textStart right in the header rather than recovered from .text, which
# is what `gh` looks like where `gofmt` and `compile` store a zero.
elf('textstart_set', pclntab(text_start=TEXT_ADDR))
# Every way the table can be wrong. Each must cost the names and
# nothing else.
elf('bad_magic', pclntab(magic=0xdeadbeef))
elf('old_magic', pclntab(magic=0xfffffffb))        # Go 1.2-1.15 layout
elf('bad_ptrsize', pclntab(ptrsize=4))
elf('bad_minlc', pclntab(minlc=7))
elf('pad_set', pclntab(pad=1))
elf('nfunc_zero', pclntab(declared=0))
elf('nfunc_huge', pclntab(declared=1 << 25))
elf('unsorted', pclntab(entryoffs=(8, 0)))
elf('nameoff_wild', pclntab(nameoffs=[1, 0x7fffffff]))
# A textStart that neither candidate can rescue: the functions would
# land outside every executable section.
elf('textstart_wild', pclntab(text_start=0xdead0000, sentinel=1 << 30))
PY

named()
{
    set +e
    "$ROOT/riscvlint" -v "$WORK/$1" 2> /dev/null |
        grep -c 'at offset: 0x[0-9a-f]* <'
    set -e
}
findings()
{
    set +e
    "$ROOT/riscvlint" -v "$WORK/$1" 2> /dev/null | grep -c 'at offset: 0x'
    set -e
}

# Both call pairs are found, and both are named after the function that
# holds them -- the second with no offset, since it is a function start.
got=$("$ROOT/riscvlint" -v "$WORK/good" 2>/dev/null |
          grep -o '<[^>]*>' | tr '\n' ' ')
if [ "$got" = "<main.alpha> <main.beta> " ]; then
    ok "both findings named from the pclntab"
else
    bad "both findings named from the pclntab" "got: $got"
fi

# The same, with the header carrying its own text base rather than
# leaving it to be recovered.
got=$("$ROOT/riscvlint" -v "$WORK/textstart_set" 2>/dev/null |
          grep -o '<[^>]*>' | tr '\n' ' ')
if [ "$got" = "<main.alpha> <main.beta> " ]; then
    ok "a header textStart is used when it validates"
else
    bad "a header textStart is used when it validates" "got: $got"
fi

# Every mutant: the scan is unchanged and the names are gone. A wrong
# name on every finding would be worse than none, which is why the
# validation refuses the whole table rather than part of it.
base=$(findings good)
for m in bad_magic old_magic bad_ptrsize bad_minlc pad_set nfunc_zero \
         nfunc_huge unsorted nameoff_wild textstart_wild; do
    n=$(named "$m")
    t=$(findings "$m")
    if [ "$n" = 0 ] && [ "$t" = "$base" ]; then
        ok "$m: table refused, scan intact ($t findings)"
    else
        bad "$m: table refused, scan intact" "named $n, $t findings (want 0, $base)"
    fi
done

# --json carries the same name, since it goes through the same lookup.
if command -v python3 > /dev/null 2>&1; then
    set +e
    "$ROOT/riscvlint" --json "$WORK/good" 2> /dev/null > "$WORK/doc"
    set -e
    if python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
fns = [f.get("function") for f in d["findings"]]
assert fns == ["main.alpha", "main.beta"], fns
assert d["findings"][1]["function_offset"] == 0, d["findings"][1]
' "$WORK/doc" 2> "$WORK/err"; then
        ok "--json carries function and function_offset"
    else
        bad "--json carries function and function_offset" "$(cat "$WORK/err")"
    fi
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
