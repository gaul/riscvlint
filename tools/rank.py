#!/usr/bin/env python3
"""rank: group pairscan output into candidate-check families.

pairscan ranks pair shapes by raw frequency, which puts the by-design
majority (prologue stores, argument moves) on top and buries the shapes a
check could act on. This groups the same rows into families and prints
each family's population, so the backlog is read off the data.

Families that depend on an immediate (sh#add needs a shift of 1-3,
zext.w needs 32) are only honest against `pairscan -x` output, where
small immediates are kept verbatim instead of collapsing to #i. Run
against a plain pairscan file they report an upper bound, and say so.

Usage: rank.py results/pairsx-all.txt [-n TOPN] [-f SUBSTR]
"""
import re
import sys


def mn(tok):
    """Mnemonic of a pairscan token, minus the :c compressed marker."""
    m = tok.split(" ", 1)[0]
    return m[:-2] if m.endswith(":c") else m


def ops(tok):
    """Operand list of a pairscan token."""
    return tok.split(" ", 1)[1].split(",") if " " in tok else []


def imm(tok, i):
    """Immediate operand i as an int, or None if collapsed/absent."""
    o = ops(tok)
    if i >= len(o) or not o[i].startswith("#"):
        return None
    try:
        return int(o[i][1:])
    except ValueError:
        return None


def shift_is(tok, values):
    return imm(tok, 2) in values


FAMILIES = [
    ("call sequence (auipc+jalr, relaxable to jal within +/-1MB)",
     lambda a, b, f: mn(a) == "auipc" and mn(b) == "jalr" and "dep" in f,
     "one jal reaches +/-1MB; the pair costs 8 bytes and a dependency",
     False),
    ("address materialization (auipc+addi / auipc+load)",
     lambda a, b, f: mn(a) == "auipc"
     and mn(b) in ("addi", "ld", "lw", "lwu", "lbu", "lhu", "sd", "sw")
     and "dep" in f,
     "candidate for gp-relative addressing (one instruction, no dependency)",
     False),
    ("shift-add (Zba sh1add/sh2add/sh3add)",
     lambda a, b, f: mn(a) == "slli" and mn(b) == "add" and "dep" in f
     and shift_is(a, (1, 2, 3)),
     "slli rd,rs,{1,2,3} then add is exactly one sh#add",
     True),
    ("zext.w idiom (Zba zext.w / add.uw)",
     lambda a, b, f: mn(a) == "slli" and mn(b) == "srli" and "dep" in f
     and shift_is(a, (32,)) and shift_is(b, (32,)),
     "slli rd,rs,32 + srli rd,rd,32 is zext.w",
     True),
    ("sext.w idiom",
     lambda a, b, f: mn(a) == "slli" and mn(b) == "srai" and "dep" in f
     and shift_is(a, (32,)) and shift_is(b, (32,)),
     "slli rd,rs,32 + srai rd,rd,32 is sext.w (addiw rd,rs,0)",
     True),
    ("bitfield shift pair (NOT foldable -- shifts other than 32)",
     lambda a, b, f: mn(a) == "slli" and mn(b) in ("srli", "srai")
     and "dep" in f and not shift_is(a, (32,)),
     "the population a shift-amount-blind check would wrongly claim",
     True),
    ("redundant mask after zero-extending load",
     lambda a, b, f: mn(a) in ("lbu", "lhu") and mn(b) == "andi"
     and "dep" in f and imm(b, 2) in (255, -1),
     "lbu already zero-extends; andi rd,rd,255 after it is dead",
     True),
    ("mask after sign-extending load (NOT redundant)",
     lambda a, b, f: mn(a) in ("lb", "lh") and mn(b) == "andi" and "dep" in f,
     "lb sign-extends, so the mask is doing real work -- excluded above",
     True),
    ("compare then branch (fold into blt/bgeu/beq/bne)",
     lambda a, b, f: mn(a) in ("slt", "sltu", "xor", "sub", "seqz", "snez")
     and mn(b) in ("beqz", "bnez") and "dep" in f,
     "RISC-V branch instructions compare two registers directly",
     False),
    ("consecutive register moves",
     lambda a, b, f: mn(a) == "mv" and mn(b) == "mv",
     "register-allocator leftovers; each mv is still an instruction",
     False),
    ("write-after-write (first def unused)",
     lambda a, b, f: "waw" in f,
     "second instruction overwrites what the first produced",
     False),
]


def main():
    args = sys.argv[1:]
    topn, only = 10, None
    if "-n" in args:
        i = args.index("-n"); topn = int(args[i + 1]); del args[i:i + 2]
    if "-f" in args:
        i = args.index("-f"); only = args[i + 1].lower(); del args[i:i + 2]
    path = args[0]

    rows, total = [], 0
    for line in open(path):
        m = re.match(r"(\d+)\t(.*?) \|\| (.*?) \|\| (.*)$", line.rstrip("\n"))
        if not m:
            continue
        n = int(m.group(1))
        rows.append((n, m.group(2), m.group(3), m.group(4)))
        total += n

    def has_exact(tok):
        # #0 survives the default normalization and #f is the FP-immediate
        # placeholder; only a spelled-out non-zero number means -x.
        return any(re.fullmatch(r"#-?\d+", o) and o != "#0" for o in ops(tok))
    exact = any(has_exact(a) or has_exact(b) for _, a, b, _ in rows)
    print(f"{path}: {total:,} pairs over {len(rows):,} distinct shapes")
    print(f"immediates: {'exact (-x)' if exact else 'collapsed -- '
          'imm-dependent families are UPPER BOUNDS'}\n")

    for name, pred, why, needs_imm in FAMILIES:
        if only and only not in name.lower():
            continue
        hits = [r for r in rows if pred(r[1], r[2], r[3])]
        if not hits:
            continue
        pop = sum(n for n, _, _, _ in hits)
        hits.sort(key=lambda r: -r[0])
        flag = "" if exact or not needs_imm else "  [UPPER BOUND]"
        print(f"== {name}: {pop:,} ({100.0*pop/total:.3f}%), "
              f"{len(hits)} shapes{flag}")
        print(f"   {why}")
        for n, a, b, f in hits[:topn]:
            print(f"   {n:>10,}  {a}  ;;  {b}   [{f}]")
        print()


if __name__ == "__main__":
    main()
