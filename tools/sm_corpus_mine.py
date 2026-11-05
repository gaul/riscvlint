#!/usr/bin/env python3
"""Size candidate checks over a converted SpiderMonkey JIT dump.

usage: sm_corpus_mine.py DIR [-j N] [--parts 1,2] [--objdump PATH]
                         [--readelf PATH]

DIR holds the code.elf.N parts written by smdump2elf.py. Each part is
disassembled with objdump, as v8_corpus_mine.py does, and run through the
probes in PROBES, one per candidate entry 48 to 52 of TODO.md; counts are
per tier (the ION_/BL_/RE_/TR_/WA_ prefix of the blob's symbol). Each
probe applies the preconditions its entry states, but it is still a
mining tool reading objdump text, not the check: treat the
figures as what a check would start from, not what it would report.

Two things v8_corpus_mine.py gets wrong on these parts, corrected here:
llvm-objdump labels every blob of a part <.text>, so the blob's name is
read from the symbol table with readelf (llvm-nm adds the section address
to a value that is already absolute); and it prints a branch target as
0x..., which v8_corpus_mine.parse takes for an immediate, so a branch's
last immediate operand is read as its target here.
"""
import argparse
import collections
import os
import re
import subprocess
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v8_corpus_mine as vm  # noqa: E402

# Instructions after which control does not reach the next one.
NO_FALL = {"j", "jr", "ret"}
TRANSFERS = NO_FALL | {"jal", "jalr", "ebreak", "ecall"}
CONTROL = TRANSFERS | vm.BRANCHES
# What a suffix moved to another address would compute differently.
PC_RELATIVE = {"auipc", "jal"}
WALK = 32


def sp_adjust(mn, ops):
    """K for `addi sp,sp,K`, else None."""
    if (mn == "addi" and len(ops) == 3 and ops[0] == ("r", "sp") and
            ops[1] == ("r", "sp") and ops[2][0] == "i"):
        return ops[2][1]
    return None


def mem_op(ops):
    return next((o for o in ops if o[0] == "m"), None)


def reads(mn, ops):
    return set(vm.sources(mn, ops))


def imm20(v):
    return v - 0x100000 if v >= 0x80000 else v


def text(raw):
    return re.sub(r"^\s*[0-9a-f]+:\s*", "", raw).split("<")[0].strip()


class Part(vm.Part):
    def __init__(self, objdump, readelf, path):
        names = {}
        out = subprocess.run([readelf, "-s", path], capture_output=True,
                             text=True, check=True).stdout
        for line in out.splitlines():
            f = line.split()
            if len(f) == 8 and f[3] == "FUNC":
                names[int(f[1], 16)] = f[7]
        super().__init__(objdump, path, False)
        first = {}
        for addr, _, _, fno in self.insns:
            first.setdefault(fno, addr)
        for fno, addr in first.items():
            if addr in names:
                self.funcs[fno] = names[addr]
        # preds[target] = [(index of the transfer, index its suffix ends
        # before, kind)]; kind is "j", "veneer" (auipc + jr), or "other".
        self.preds = collections.defaultdict(list)
        self.targets = set()
        ins = self.insns
        for i, (addr, mn, ops, fno) in enumerate(ins):
            if (mn in vm.BRANCHES or mn in ("j", "jal")) and ops and ops[-1][0] in ("t", "i"):
                t = ops[-1][1]
                self.targets.add(t)
                kind = "j" if mn == "j" else "other"
                self.preds[t].append((i, i, kind))
            elif mn == "auipc" and len(ops) == 2 and ops[1][0] == "i" and self.same_func(i, i + 1):
                m2, o2 = ins[i + 1][1], ins[i + 1][2]
                mem = mem_op(o2)
                if m2 in ("jr", "jalr") and mem and mem[2] == ops[0][1]:
                    t = (addr + (imm20(ops[1][1]) << 12) + mem[1]) & ~1
                    self.targets.add(t)
                    kind = "veneer" if m2 == "jr" else "other"
                    self.preds[t].append((i + 1, i, kind))

    def is_target(self, i):
        return self.insns[i][0] in self.targets

    def fate(self, start, reg):
        """'dead' if the straight line from start writes reg before reading
        it, 'live' if it reads it first, None if it leaves the line first."""
        ins = self.insns
        j = start
        while j < len(ins) and j < start + WALK and self.same_func(start, j):
            mn, ops = ins[j][1], ins[j][2]
            if reg in reads(mn, ops):
                return "live"
            if vm.dest(mn, ops) == reg:
                return "dead"
            if mn in CONTROL:
                return None
            j += 1
        return None

    def add(self, probe, i, key, nbytes):
        self.hit(probe, i, key)
        self.counts[(probe + "/bytes", self.tier(i), key)] += nbytes
        # The blob's name less its index: the tier and the test.
        prog = self.funcs[self.insns[i][3]].rsplit("_", 1)[0]
        self.counts[(probe + "/prog", prog, key)] += 1

    def run(self):
        ins = self.insns
        n = len(ins)
        release_end = -1
        run_last = set()        # the last release of each run 48 reports
        for i in range(n):
            addr, mn, ops, fno = ins[i]
            self.counts[("insns", self.tier(i), "")] += 1
            nxt = ins[i + 1] if self.same_func(i, i + 1) else None
            k = sp_adjust(mn, ops)

            # 48: releases one stack adjustment would do.
            if k is not None and k > 0 and i > release_end:
                total, nadj, last, fits = k, 1, i, True
                j = i + 1
                while j < n and j < i + 64 and self.same_func(i, j) and not self.is_target(j):
                    mj, oj = ins[j][1], ins[j][2]
                    kj = sp_adjust(mj, oj)
                    if kj is not None:
                        if kj <= 0 or total + kj > 2047:
                            break
                        total += kj
                        nadj += 1
                        last = j
                    elif mj in CONTROL:
                        break
                    else:
                        m = mem_op(oj)
                        if m and m[2] == "sp":
                            if oj[0] == ("r", "sp"):
                                break
                            # Re-offset by what was released before it.
                            if m[1] + total > 2047:
                                fits = False
                        elif "sp" in reads(mj, oj) or vm.dest(mj, oj) == "sp":
                            break
                    j += 1
                release_end = last
                if nadj >= 2 and fits:
                    self.add("release-run", i, "adj%d" % min(nadj, 5), 4 * (nadj - 1))
                    run_last.add(last)

            # 49: a release followed by a reservation.
            if k is not None and k > 0 and nxt is not None and not self.is_target(i + 1):
                k2 = sp_adjust(nxt[1], nxt[2])
                if k2 is not None and k2 < 0:
                    # /run-end: the release also ends a run of 48.
                    end = "/run-end" if i in run_last else ""
                    if k + k2 == 0:
                        self.add("release-reserve", i, "cancel" + end, 8)
                    else:
                        self.add("release-reserve", i, "net" + end, 4)

            # 50: a copy whose one reader could read the source.
            if (mn == "mv" and len(ops) == 2 and ops[0][0] == "r" and ops[1][0] == "r"
                    and ops[0] != ops[1] and ops[1] != ("r", "zero")):
                rd, rs = ops[0][1], ops[1][1]
                use, verdict = None, None
                j = i + 1
                while j < n and j <= i + WALK and self.same_func(i, j) and not self.is_target(j):
                    mj, oj = ins[j][1], ins[j][2]
                    rj, dj = reads(mj, oj), vm.dest(mj, oj)
                    if use is None:
                        if rd in rj:
                            if mj in CONTROL:
                                verdict = "read-by-transfer"
                                break
                            use = j
                            if dj == rd:
                                verdict = "dead"
                                break
                        elif dj == rd:
                            verdict = "never-read"
                            break
                        elif dj == rs:
                            verdict = "source-overwritten"
                            break
                        elif mj in CONTROL:
                            break
                    else:
                        if rd in rj:
                            verdict = "read-twice"
                            break
                        if dj == rd:
                            verdict = "dead"
                            break
                        if mj in CONTROL:
                            break
                    j += 1
                if verdict == "dead":
                    self.add("copy-prop", i, ins[use][1], 4)
                else:
                    self.hit("copy-prop-not", i, verdict or "unknown")

            # 51: a call through a scratch register that jal would reach.
            if (mn == "auipc" and len(ops) == 2 and ops[1][0] == "i" and nxt is not None
                    and nxt[1] == "jalr" and vm.dest(nxt[1], nxt[2]) == "ra"
                    and not self.is_target(i + 1)):
                rd = ops[0][1]
                mem = mem_op(nxt[2])
                if rd != "ra" and mem and mem[2] == rd:
                    target = (addr + (imm20(ops[1][1]) << 12) + mem[1]) & ~1
                    if not -(1 << 20) <= target - addr < (1 << 20):
                        self.hit("scratch-call", i, "out-of-reach")
                    else:
                        ti = self.idx.get(target)
                        at_target = self.fate(ti, rd) if ti is not None else None
                        at_return = self.fate(i + 2, rd) if self.same_func(i, i + 2) else None
                        if at_target == "dead" and at_return == "dead":
                            self.add("scratch-call", i, "dead", 4)
                        else:
                            key = "live" if "live" in (at_target, at_return) else "unknown"
                            self.hit("scratch-call", i, key)

            # 52's context: li rX,imm + a push of rX + j, the shape of a
            # SpiderMonkey out-of-line bailout.
            if (mn == "j" and i >= 3 and self.same_func(i, i - 3)
                    and sp_adjust(ins[i - 2][1], ins[i - 2][2]) == -8
                    and ins[i - 3][1] == "li" and ins[i - 1][1] == "sd"
                    and ins[i - 1][2] and ins[i - 1][2][0] == ins[i - 3][2][0]
                    and ins[i - 1][2][-1] == ("m", 0, "sp")):
                self.counts[("li-push-j", self.tier(i), "")] += 1

        # 52: a label reached only by jumps that each repeat the same tail.
        for t, ps in self.preds.items():
            li = self.idx.get(t)
            if li is None or len(ps) < 2:
                continue
            tier = self.tier(li)
            if any(kind == "other" for _, _, kind in ps):
                continue
            if not (li > 0 and self.same_func(li, li - 1) and ins[li - 1][1] in NO_FALL):
                continue
            k = 0
            while k < 8:
                seen = None
                ok = True
                for _, end, _ in ps:
                    # Only the top of the tail may be a branch target: a
                    # branch to the jump, or into the tail below its top,
                    # would run the part of the tail it skipped once the
                    # tail is at the label.
                    q = end - 1 - k
                    if q < 0 or not self.same_func(end, q) or self.is_target(q + 1):
                        ok = False
                        break
                    mq = ins[q][1]
                    if mq in CONTROL or mq in PC_RELATIVE:
                        ok = False
                        break
                    s = text(self.raw[q])
                    if seen is None:
                        seen = s
                    elif s != seen:
                        ok = False
                        break
                if not ok:
                    break
                k += 1
            if k:
                end0 = ps[0][1]
                shape = " ; ".join(vm.abstract(ins[q][1], ins[q][2], {})
                                   for q in range(end0 - k, end0))
                self.counts[("tail-merge/bytes", tier, shape)] += 4 * k * (len(ps) - 1)
                self.counts[("tail-merge", tier, shape)] += 1
                self.counts[("tail-merge/jumps", tier, shape)] += len(ps)
        return self


def work(args):
    objdump, readelf, path = args
    p = Part(objdump, readelf, path).run()
    return dict(p.counts), {k: v for k, v in p.examples.items()}


PROBES = [
    ("release-run", "48: addi sp,sp,+K runs one release would do (adjustments in the run)"),
    ("release-reserve", "49: addi sp,sp,+a then addi sp,sp,-b (cancel: a == b)"),
    ("copy-prop", "50: mv rd,rs whose one reader could read rs, rd then dead (the reader)"),
    ("copy-prop-not", "50, the moves that do not qualify, by reason"),
    ("scratch-call", "51: auipc rX + jalr ra,lo(rX) where jal reaches; dead = rX dead at target and return"),
    ("tail-merge", "52: labels reached only by jumps repeating the same tail (shape of the tail)"),
    ("li-push-j", "52's context: li rX,imm + addi sp,sp,-8 + sd rX,0(sp) + j"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("-j", type=int, default=6)
    ap.add_argument("--parts", default="")
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("--readelf", default="llvm-readelf")
    a = ap.parse_args()
    only = {int(x) for x in a.parts.split(",") if x}
    parts = vm.parts_in(a.dir, only)
    counts = collections.Counter()
    examples = {}
    with Pool(a.j) as pool:
        for c, e in pool.imap_unordered(work, [(a.objdump, a.readelf, p) for p in parts]):
            counts.update(c)
            for key, v in e.items():
                examples.setdefault(key, [])
                examples[key].extend(v[:3 - len(examples[key])])
    tiers = sorted({t for (d, t, _) in counts if d == "insns"})
    total = sum(counts[("insns", t, "")] for t in tiers)
    print("== %d instructions: " % total +
          " ".join("%s=%d" % (t, counts[("insns", t, "")]) for t in tiers))
    for probe, desc in PROBES:
        sites = sum(v for (d, _, _), v in counts.items() if d == probe)
        nbytes = sum(v for (d, _, _), v in counts.items() if d == probe + "/bytes")
        print("\n== %s: %d sites, %d bytes ==  %s" % (probe, sites, nbytes, desc))
        print("  " + " ".join("%s=%d/%dB" % (
            t, sum(v for (d, tt, _), v in counts.items() if d == probe and tt == t),
            sum(v for (d, tt, _), v in counts.items() if d == probe + "/bytes" and tt == t))
            for t in tiers))
        keys = collections.defaultdict(collections.Counter)
        for (d, t, key), v in counts.items():
            if d == probe:
                keys[key][t] += v
        for key in sorted(keys, key=lambda k: -sum(keys[k].values()))[:12]:
            extra = ""
            if probe == "tail-merge":
                extra = "  jumps=%d bytes=%d" % (
                    sum(v for (d, _, kk), v in counts.items() if d == "tail-merge/jumps" and kk == key),
                    sum(v for (d, _, kk), v in counts.items() if d == "tail-merge/bytes" and kk == key))
            print("  %-34s %8d  " % (key[:34] or "-", sum(keys[key].values())) +
                  " ".join("%s=%d" % (t, keys[key][t]) for t in tiers if keys[key][t]) + extra)
        progs = collections.Counter()
        for (d, prog, key), v in counts.items():
            if d == probe + "/prog":
                progs[(prog, key)] += v
        if progs:
            print("  by test: " + ", ".join("%s %s %d" % (prog, key, v)
                                            for (prog, key), v in progs.most_common(5)))
        shown = 0
        for key in sorted(keys, key=lambda k: -sum(keys[k].values())):
            for ex in examples.get((probe, key), [])[:1]:
                if shown < 2:
                    print("  example [%s]:\n%s" % (key, ex))
                    shown += 1


if __name__ == "__main__":
    main()
