#!/usr/bin/env python3
"""Mine a converted V8 JIT dump for instruction patterns that could become
riscvlint checks.

usage: v8_corpus_mine.py DIR [-j N] [--parts 10,11] [--no-ngrams]
                         [--objdump PATH]

DIR holds the code.elf.N parts written by v8dump2elf.py. Each part is
disassembled with objdump and scanned by the detectors listed in
DETECTORS plus an abstracted-trigram census; counts are per tier (the
BL_/ML_/TF_/RE_/UN_ prefix of the symbol). Everything is an estimate from
straight-line context, the way README.md says mining tools are, so treat
the numbers as upper bounds that a check will come in under. The
JetStream section of TODO.md is this tool's output read against the
checks.
"""
import argparse
import collections
import glob
import os
import re
import subprocess
import sys
from multiprocessing import Pool

SYM_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
INS_RE = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
MEM_RE = re.compile(r"^(-?(?:0x)?[0-9a-fA-F]+)\((\w+)\)$")
HEX_RE = re.compile(r"^[0-9a-f]+$")
REG_RE = re.compile(r"^(zero|ra|sp|gp|tp|fp|[tsa][0-9]+|f[tsa][0-9]+|v[0-9]+)$")

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "blez",
            "bgez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu"}
STORES = {"sb", "sh", "sw", "sd", "fsw", "fsd", "sc.w", "sc.d"}
LOADS = {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "flw", "fld"}
NO_DEST = STORES | BRANCHES | {"j", "jr", "ret", "ebreak", "fence", "unimp",
                               "nop", "fence.i", "ecall"}
ALU_RR = {"add", "sub", "and", "or", "xor", "slt", "sltu", "sll", "srl", "sra",
          "addw", "subw", "sllw", "srlw", "sraw", "mul"}
MASKS = {0xff: "zext.b", 0xffff: "zext.h", 0xffffffff: "zext.w"}
KEEP_REGS = {"sp", "zero", "ra", "s6", "fp", "s0"}
M64 = (1 << 64) - 1


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


def s32(v):
    v &= 0xffffffff
    return v - (1 << 32) if v >> 31 else v


def sext12(v):
    v &= 0xfff
    return v - 0x1000 if v >> 11 else v


def li_len(v):
    """Instructions a plain RV64I li of v needs (the classic lui/addiw/slli/
    addi recurrence without the Zb* tricks), an upper bound on optimal."""
    v = s64(v)
    if -(1 << 31) <= v < (1 << 31):
        lo = sext12(v)
        hi = (v - lo) >> 12
        n = 1 if hi else 0
        if lo or not hi:
            n += 1
        return n
    lo = sext12(v)
    hi = (v - lo) >> 12
    tz = (hi & -hi).bit_length() - 1
    hi >>= tz
    return li_len(hi) + 1 + (1 if lo else 0)


def parse(mn, ops):
    ops = ops.split("#", 1)[0]
    ops = re.sub(r"<[^>]*>", "", ops).strip()
    out = []
    toks = [t.strip() for t in ops.split(",") if t.strip()]
    last = len(toks) - 1
    for k, tok in enumerate(toks):
        m = MEM_RE.match(tok)
        if m:
            out.append(("m", int(m.group(1), 0), m.group(2)))
            continue
        if REG_RE.match(tok):
            out.append(("r", tok))
            continue
        if k == last and (mn in BRANCHES or mn in ("j", "jal")) and HEX_RE.match(tok):
            out.append(("t", int(tok, 16)))
            continue
        try:
            out.append(("i", int(tok, 0)))
        except ValueError:
            out.append(("s", tok))
    return out


def dest(mn, ops):
    if mn in NO_DEST:
        return None
    if mn == "jal":
        return ops[0][1] if len(ops) > 1 and ops[0][0] == "r" else "ra"
    if mn == "jalr":
        return ops[0][1] if len(ops) > 1 and ops[0][0] == "r" else "ra"
    if ops and ops[0][0] == "r":
        return ops[0][1]
    return None


def sources(mn, ops):
    d = dest(mn, ops)
    srcs = []
    for k, o in enumerate(ops):
        if o[0] == "r" and not (k == 0 and d is not None and o[1] == d):
            srcs.append(o[1])
        elif o[0] == "m":
            srcs.append(o[2])
    return srcs


def tier_of(fn):
    return fn.split("_", 1)[0] if "_" in fn else "??"


def abstract(mn, ops, regmap):
    parts = []
    for o in ops:
        if o[0] == "r":
            r = o[1]
            if r in KEEP_REGS:
                parts.append(r)
            else:
                parts.append(regmap.setdefault(r, "R%d" % len(regmap)))
        elif o[0] == "m":
            b = o[2] if o[2] in KEEP_REGS else regmap.setdefault(o[2], "R%d" % len(regmap))
            parts.append(("0(" if o[1] == 0 else "o(") + b + ")")
        elif o[0] == "i":
            v = o[1]
            if mn in ("slli", "srli", "srai", "slliw", "srliw", "sraiw") or v in (0, 1, -1, 8, -8, 16, -16, 32):
                parts.append(str(v))
            else:
                parts.append("i")
        elif o[0] == "t":
            parts.append("L")
        else:
            parts.append(o[1])
    return mn + " " + ",".join(parts)


class Part:
    def __init__(self, objdump, path, ngrams):
        self.path = path
        self.ngrams = ngrams
        self.counts = collections.Counter()        # (detector, tier, key) -> n
        self.examples = collections.defaultdict(list)  # (detector, key) -> [text]
        self.tri = collections.Counter()           # (tier, trigram) -> n
        proc = subprocess.run([objdump, "-d", "--no-show-raw-insn", path],
                              capture_output=True, text=True, check=True)
        self.raw = []     # original text lines, parallel to insns
        self.insns = []   # (addr, mn, ops, func_no)
        self.funcs = []
        self.idx = {}
        func_no = -1
        for line in proc.stdout.splitlines():
            m = SYM_RE.match(line)
            if m:
                self.funcs.append(m.group(2))
                func_no += 1
                continue
            m = INS_RE.match(line)
            if not m or func_no < 0:
                continue
            addr = int(m.group(1), 16)
            mn = m.group(2)
            ops = parse(mn, m.group(3))
            self.idx[addr] = len(self.insns)
            self.insns.append((addr, mn, ops, func_no))
            self.raw.append(line.strip())

    def tier(self, i):
        return tier_of(self.funcs[self.insns[i][3]])

    def same_func(self, i, j):
        return 0 <= j < len(self.insns) and self.insns[j][3] == self.insns[i][3]

    def hit(self, det, i, key=""):
        t = self.tier(i)
        self.counts[(det, t, key)] += 1
        ex = self.examples[(det, key)]
        if len(ex) < 3:
            lo = max(0, i - 2)
            hi = min(len(self.insns), i + 3)
            ctx = [("  >> " if k == i else "     ") + self.raw[k][:110]
                   for k in range(lo, hi) if self.same_func(i, k)]
            ex.append("  %s %s\n%s" % (t, self.funcs[self.insns[i][3]][:60], "\n".join(ctx)))

    def writes_between(self, reg, i, j):
        """Does any instruction in (i, j) write reg?"""
        for k in range(i + 1, j):
            if dest(self.insns[k][1], self.insns[k][2]) == reg:
                return True
        return False

    def run(self):
        insns = self.insns
        n = len(insns)
        chain = {}        # reg -> [value, length, start]
        last_const = {}   # reg -> (value, index)
        push_run = 0
        pop_run = 0
        for i in range(n):
            addr, mn, ops, fno = insns[i]
            t = self.tier(i)
            self.counts[("insns", t, "")] += 1
            if i > 0 and insns[i - 1][3] != fno:
                chain.clear()
                last_const.clear()
                push_run = pop_run = 0
            d = dest(mn, ops)
            nxt = insns[i + 1] if self.same_func(i, i + 1) else None

            # ---- li chains: contiguous lui/li/addi/addiw/slli/ori/xori on one reg
            cont = None
            if mn == "lui" and len(ops) == 2 and ops[1][0] == "i":
                chain[d] = [s32(ops[1][1] << 12), 1, i]
                cont = d
            elif mn == "li" and len(ops) == 2 and ops[1][0] == "i":
                chain[d] = [s64(ops[1][1]), 1, i]
                cont = d
            elif mn == "mv" and len(ops) == 2 and ops[1] == ("r", "zero"):
                chain[d] = [0, 1, i]
                cont = d
            elif (mn in ("addi", "addiw", "slli", "ori", "xori") and len(ops) == 3
                  and ops[1] == ("r", d) and ops[2][0] == "i" and d in chain):
                v = chain[d][0]
                k = ops[2][1]
                if mn == "addi":
                    v = s64(v + k)
                elif mn == "addiw":
                    v = s32(v + k)
                elif mn == "slli":
                    v = s64(v << k)
                elif mn == "ori":
                    v = s64(v | s64(k))
                else:
                    v = s64(v ^ s64(k))
                chain[d][0] = v
                chain[d][1] += 1
                cont = d
            # finalize chains that this instruction does not continue
            for reg in list(chain):
                if reg == cont:
                    continue
                value, length, start = chain.pop(reg)
                last_const[reg] = (value, i - 1)
                if length >= 2:
                    opt = li_len(value)
                    self.counts[("lichain", self.tier(start), "len%d" % length)] += 1
                    if length > opt:
                        self.hit("li-long", start, "%d->%d" % (length, opt))
                    # absolute call or jump through the materialized value
                    if (mn in ("jalr", "jr") and ((ops and ops[0] == ("r", reg)) or
                                                  any(o[0] == "m" and o[2] == reg for o in ops))):
                        self.hit("li-abs-" + ("call" if mn == "jalr" else "jump"), start,
                                 "len%d" % length)
            if d is not None and cont is None and d in last_const:
                # a plain redefinition kills the known constant
                del last_const[d]
            if d is not None and cont is None and d in chain:
                del chain[d]

            # ---- D1: auipc + jr/jalr with a target inside jal's reach
            if mn == "auipc" and nxt and len(ops) == 2 and ops[1][0] == "i":
                rd = ops[0][1]
                imm = ops[1][1]
                if imm >= 0x80000:
                    imm -= 0x100000
                mn2, ops2 = nxt[1], nxt[2]
                mem = next((o for o in ops2 if o[0] == "m"), None)
                base = None
                off = 0
                if mn2 in ("jr", "jalr"):
                    if mem:
                        base, off = mem[2], mem[1]
                    elif mn2 == "jalr" and ops2 and ops2[0][0] == "r" and len(ops2) == 1:
                        base = ops2[0][1]
                if base == rd:
                    target = addr + (imm << 12) + off
                    delta = target - addr
                    kind = "call" if (mn2 == "jalr" and dest(mn2, ops2) == "ra") else "jump"
                    reach = "near" if -(1 << 20) <= delta < (1 << 20) else "far"
                    where = "same-func" if (target in self.idx and self.same_func(i, self.idx[target])) else "elsewhere"
                    self.hit("auipc-" + kind, i, reach + "/" + where)

            # ---- D3/D22: push and pop chains, adjacent sp adjustments
            if mn == "addi" and len(ops) == 3 and ops[0] == ("r", "sp") and ops[1] == ("r", "sp") and ops[2][0] == "i":
                if nxt and nxt[1] == "addi" and len(nxt[2]) == 3 and nxt[2][0] == ("r", "sp") and nxt[2][1] == ("r", "sp"):
                    self.hit("sp-adjust-pair", i)
                if ops[2][1] == -8 and nxt and nxt[1] in STORES and nxt[2] and nxt[2][-1] == ("m", 0, "sp"):
                    push_run += 1
                else:
                    if push_run >= 2:
                        self.hit("push-run", i - 2 * push_run, "run%d" % min(push_run, 6))
                    push_run = 0
            elif not (mn in STORES and i > 0 and insns[i - 1][1] == "addi"):
                if push_run >= 2:
                    self.hit("push-run", i - 2 * push_run, "run%d" % min(push_run, 6))
                push_run = 0
            if (mn in LOADS and ops and ops[-1] == ("m", 0, "sp") and nxt and nxt[1] == "addi"
                    and len(nxt[2]) == 3 and nxt[2][0] == ("r", "sp") and nxt[2][1] == ("r", "sp") and nxt[2][2] == ("i", 8)):
                pop_run += 1
            elif not (mn == "addi" and ops and ops[0] == ("r", "sp") and i > 0 and insns[i - 1][1] in LOADS):
                if pop_run >= 2:
                    self.hit("pop-run", i - 2 * pop_run, "run%d" % min(pop_run, 6))
                pop_run = 0

            # ---- D4/D53: shift pairs on one register
            if mn in ("slli", "srli") and nxt and len(ops) == 3 and ops[2][0] == "i":
                rd = ops[0][1]
                k = ops[2][1]
                mn2, ops2 = nxt[1], nxt[2]
                if (mn2 in ("srai", "srli", "slli") and len(ops2) == 3 and ops2[0] == ("r", rd)
                        and ops2[1] == ("r", rd) and ops2[2][0] == "i"):
                    k2 = ops2[2][1]
                    if mn == "slli" and mn2 == "srai" and k == k2:
                        self.hit("slli-srai", i, "k%d" % k)
                    elif mn == "slli" and mn2 == "srli" and k == k2:
                        self.hit("slli-srli", i, "k%d" % k)
                    elif mn == "srli" and mn2 == "slli" and k == k2:
                        self.hit("srli-slli", i, "k%d" % k)
                    elif mn == "slli" and mn2 == "srli" and k != k2:
                        self.hit("slli-srli-field", i, "k%d-%d" % (k, k2))

            # ---- D31: Smi tag / untag round trips
            if mn == "slli" and len(ops) == 3 and ops[2] == ("i", 32):
                rd, rs = ops[0][1], ops[1][1]
                for j in range(i + 1, min(n, i + 5)):
                    if not self.same_func(i, j):
                        break
                    mj, oj = insns[j][1], insns[j][2]
                    if mj == "srai" and len(oj) == 3 and oj[1] == ("r", rd) and oj[2] == ("i", 32):
                        if not self.writes_between(rs, i, j):
                            self.hit("untag-after-tag", j, "d%d" % (j - i))
                        break
                    if dest(mj, oj) == rd:
                        break
            if mn == "srai" and len(ops) == 3 and ops[2] == ("i", 32):
                rd, rs = ops[0][1], ops[1][1]
                for j in range(i + 1, min(n, i + 5)):
                    if not self.same_func(i, j):
                        break
                    mj, oj = insns[j][1], insns[j][2]
                    if mj == "slli" and len(oj) == 3 and oj[1] == ("r", rd) and oj[2] == ("i", 32):
                        if not self.writes_between(rs, i, j):
                            self.hit("retag-after-untag", j, "d%d" % (j - i))
                        break
                    if dest(mj, oj) == rd:
                        break

            # ---- D8: jump threading
            if mn == "j" and ops and ops[-1][0] == "t":
                ti = self.idx.get(ops[-1][1])
                if ti is not None:
                    tm = insns[ti][1]
                    if tm == "j":
                        self.hit("jump-to-jump", i)
                    elif tm == "ret":
                        self.hit("jump-to-ret", i)
            if mn in BRANCHES and ops and ops[-1][0] == "t":
                ti = self.idx.get(ops[-1][1])
                if ti is not None and insns[ti][1] == "j":
                    self.hit("branch-to-jump", i)
                # D37: branch over exactly one or two instructions
                if ti == i + 2:
                    self.hit("branch-over-1", i, insns[i + 1][1])
                elif ti == i + 3:
                    self.hit("branch-over-2", i, insns[i + 1][1] + "+" + insns[i + 2][1])

            # ---- D9: no-ops and markers
            if mn == "nop":
                self.hit("noop", i, "nop")
            elif mn in ("addi", "ori", "xori", "slli", "srli", "srai") and len(ops) == 3 and ops[0] == ops[1] and ops[2] == ("i", 0):
                self.hit("noop", i, mn + "-0")
            elif mn == "mv" and len(ops) == 2 and ops[0] == ops[1]:
                self.hit("noop", i, "mv-self")
            elif mn in ("lui", "auipc") and ops and ops[0] == ("r", "zero"):
                self.hit("noop", i, mn + "-zero")
            elif mn in ("ebreak", "unimp"):
                self.hit("noop", i, mn)

            # ---- D10/D25/D28: a constant materialized for one use
            if mn in ALU_RR and len(ops) == 3 and ops[1][0] == "r" and ops[2][0] == "r":
                for pos in (2, 1):
                    r = ops[pos][1]
                    if r in last_const and i - last_const[r][1] <= 3:
                        v = last_const[r][0]
                        if mn == "and" and v in MASKS:
                            self.hit("and-mask", i, MASKS[v])
                        elif mn in ("add", "and", "or", "xor", "slt", "sltu", "addw") and -2048 <= v <= 2047 and pos == 2:
                            self.hit("li-alu", i, mn)
                        elif mn in ("add", "and", "or", "xor", "addw") and -2048 <= v <= 2047 and pos == 1:
                            self.hit("li-alu", i, mn)
                        elif mn == "sub" and -2047 <= v <= 2048 and pos == 2:
                            self.hit("li-alu", i, "sub")
                        elif mn in ("sll", "srl", "sra", "sllw", "srlw", "sraw") and 0 <= v < 64 and pos == 2:
                            self.hit("li-alu", i, mn)
                        break
            if mn in STORES and ops and ops[0][0] == "r":
                r = ops[0][1]
                if r in last_const and last_const[r][0] == 0 and i - last_const[r][1] <= 3:
                    self.hit("store-li-zero", i, mn)
            if mn in BRANCHES and len(ops) == 3:
                for pos in (1, 0):
                    r = ops[pos][1] if ops[pos][0] == "r" else None
                    if r and r in last_const and i - last_const[r][1] <= 3:
                        v = last_const[r][0]
                        self.hit("li-branch", i, mn + ("/zero" if v == 0 else "/imm"))
                        break

            # ---- D12: call immediately followed by ret
            if mn in ("jal", "jalr") and d == "ra" and nxt and nxt[1] == "ret":
                self.hit("call-then-ret", i)

            # ---- trigram census
            if self.ngrams and i >= 2 and self.same_func(i, i - 2):
                regmap = {}
                tri = " ; ".join(abstract(insns[k][1], insns[k][2], regmap) for k in (i - 2, i - 1, i))
                self.tri[(t, tri)] += 1
        return self


def work(args):
    objdump, path, ngrams = args
    p = Part(objdump, path, ngrams).run()
    return dict(p.counts), {k: v for k, v in p.examples.items()}, dict(p.tri)


def parts_in(d, only):
    out = []
    for p in glob.glob(os.path.join(d, "code.elf*")):
        if p.endswith(".json"):
            continue
        tail = p.rsplit(".", 1)[1]
        num = int(tail) if tail.isdigit() else 0
        if only and num not in only:
            continue
        out.append((num, p))
    return [p for _, p in sorted(out)]


DETECTORS = [
    ("auipc-jump", "auipc + jr through the same register (jump); near = target within jal's +/-1 MiB"),
    ("auipc-call", "auipc + jalr ra through the same register (call); near = within +/-1 MiB"),
    ("li-long", "constant materialized in more instructions than a plain li needs (len -> optimal)"),
    ("li-abs-call", "call through an address materialized by a li chain"),
    ("li-abs-jump", "jump through an address materialized by a li chain"),
    ("push-run", "runs of addi sp,sp,-8 + store 0(sp) pairs (run length)"),
    ("pop-run", "runs of load 0(sp) + addi sp,sp,8 pairs (run length)"),
    ("sp-adjust-pair", "two consecutive addi sp,sp,K"),
    ("slli-srai", "slli k + srai k on one register (sext of the low 64-k bits)"),
    ("slli-srli", "slli k + srli k on one register (zext of the low 64-k bits)"),
    ("srli-slli", "srli k + slli k on one register (clear the low k bits)"),
    ("slli-srli-field", "slli k + srli j, j != k (bit-field extract)"),
    ("untag-after-tag", "srai 32 of a value slli 32 produced while the source still lives (distance)"),
    ("retag-after-untag", "slli 32 of a value srai 32 produced while the source still lives (distance)"),
    ("jump-to-jump", "j whose target is another j"),
    ("jump-to-ret", "j whose target is ret"),
    ("branch-to-jump", "conditional branch whose target is a j"),
    ("branch-over-1", "conditional branch skipping exactly one instruction (the skipped mnemonic)"),
    ("branch-over-2", "conditional branch skipping exactly two instructions"),
    ("noop", "instructions with no architectural effect, and markers"),
    ("and-mask", "and with a register just loaded with 0xff / 0xffff / 0xffffffff"),
    ("li-alu", "register ALU op whose one operand was just loaded with a 12-bit immediate"),
    ("store-li-zero", "store of a register just loaded with zero"),
    ("li-branch", "conditional branch against a register just loaded with a constant"),
    ("call-then-ret", "call immediately followed by ret"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("-j", type=int, default=6)
    ap.add_argument("--parts", default="")
    ap.add_argument("--no-ngrams", action="store_true")
    ap.add_argument("--objdump", default="objdump")
    a = ap.parse_args()
    only = {int(x) for x in a.parts.split(",") if x}
    parts = parts_in(a.dir, only)
    counts = collections.Counter()
    examples = {}
    tri = collections.Counter()
    with Pool(a.j) as pool:
        for c, e, tcount in pool.imap_unordered(work, [(a.objdump, p, not a.no_ngrams) for p in parts]):
            counts.update(c)
            for k, v in e.items():
                examples.setdefault(k, [])
                for ex in v:
                    if len(examples[k]) < 3:
                        examples[k].append(ex)
            tri.update(tcount)
    tiers = sorted({t for (_, t, _) in counts})
    print("== instructions per tier ==")
    for t in tiers:
        print("  %-4s %10d" % (t, counts[("insns", t, "")]))
    print("\n== li chains by length (all, not only over-long) ==")
    rows = collections.defaultdict(lambda: collections.Counter())
    for (det, t, key), v in counts.items():
        if det == "lichain":
            rows[key][t] += v
    for key in sorted(rows, key=lambda k: int(k[3:])):
        print("  %-6s " % key + " ".join("%s=%d" % (t, rows[key][t]) for t in tiers if rows[key][t]))
    for det, desc in DETECTORS:
        tot = sum(v for (dd, _, _), v in counts.items() if dd == det)
        print("\n== %s: %d ==  %s" % (det, tot, desc))
        keys = collections.defaultdict(lambda: collections.Counter())
        for (dd, t, key), v in counts.items():
            if dd == det:
                keys[key][t] += v
        for key in sorted(keys, key=lambda k: -sum(keys[k].values()))[:12]:
            print("  %-24s %8d  " % (key or "-", sum(keys[key].values())) +
                  " ".join("%s=%d" % (t, keys[key][t]) for t in tiers if keys[key][t]))
        shown = 0
        for key in sorted(keys, key=lambda k: -sum(keys[k].values())):
            for ex in examples.get((det, key), [])[:1]:
                if shown >= 2:
                    break
                print("  example [%s]:\n%s" % (key or "-", ex))
                shown += 1
    if tri:
        for t in tiers:
            print("\n== top trigrams, %s ==" % t)
            rows = [(k[1], v) for k, v in tri.items() if k[0] == t]
            for s, v in sorted(rows, key=lambda r: -r[1])[:40]:
                print("  %9d  %s" % (v, s))


if __name__ == "__main__":
    main()
