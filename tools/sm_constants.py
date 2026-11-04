#!/usr/bin/env python3
"""Classify SpiderMonkey's patchable li_ptr / li_constant loads by value and use.

  sm_constants.py MAP DUMPDIR ELF...

DUMPDIR holds the <test>.<pid>.bin files the ELFs were made from; they
are read again for the JIT address ranges of every blob, including the
startup blobs --dedupe-startup left out of the ELFs, so that a load of a
trampoline's address is recognised as one.

Each sequence's value is decoded and classed as a placeholder (0 or -1,
patched later), an address in its own blob, in another JIT blob of the
same process, some other address below 2^47 (C++ functions, runtime
data, GC things), or a value with high bits set (a boxed Value or a tag);
and its first use as a call (jalr ra), jump (jalr zero), push (addi sp
then a store of the register), store, load base, branch operand, or
other. Calls and jumps to JIT code are what a pc-relative auipc + jalr
replaces outright. Calls to anything else -- C++, through a pointer the
backend could have built in fewer instructions since nothing moves it --
are listed by test with their number of distinct targets, since a few
hot helpers called from many sites is what a shared call stub would fix.
"""

import bisect
import collections
import glob
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sm_analyze_findings import (read_elf, read_map, section_words,  # noqa: E402
                                 li_sequence, LI_LEN)


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def imm12(w):
    return sx(w >> 20, 12)


def li_ptr_value(ws):
    v = sx((ws[0] >> 12) << 12, 32) + imm12(ws[1])
    v = (v << 11) | (imm12(ws[3]) & 0x7ff)
    v = (v << 6) | (imm12(ws[5]) & 0x3f)
    return sx(v, 64)


def li_const_value(ws):
    v = sx(sx((ws[0] >> 12) << 12, 32) + imm12(ws[1]), 32)
    for k in (3, 5, 7):
        v = (v << 12) + imm12(ws[k])
    return sx(v, 64)


def jit_ranges(dumpdir):
    ranges = collections.defaultdict(list)
    for dump in glob.glob(os.path.join(dumpdir, '*.bin')):
        test = os.path.basename(dump).split('.')[0]
        with open(dump, 'rb') as f:
            b = f.read()
        pos = 0
        while pos + 28 <= len(b) and b[pos:pos + 4] == b'SMJC':
            a, n = struct.unpack_from('<QQ', b, pos + 12)
            ranges[test].append((a, a + n))
            pos += 28 + n
    for r in ranges.values():
        r.sort()
    return ranges, {t: [a for a, _ in r] for t, r in ranges.items()}


def use(words, j, rd):
    if j >= len(words):
        return 'end'
    w = words[j]
    op = w & 0x7f
    rs1 = (w >> 15) & 31
    rs2 = (w >> 20) & 31
    if op == 0x67 and rs1 == rd:
        return 'call' if (w >> 7) & 31 == 1 else 'jump'
    if (op == 0x13 and (w >> 12) & 7 == 0 and (w >> 7) & 31 == 2 and
            rs1 == 2 and j + 1 < len(words)):
        w2 = words[j + 1]
        if w2 & 0x7f == 0x23 and (w2 >> 20) & 31 == rd:
            return 'push'
    if op == 0x23 and rs2 == rd:
        return 'store'
    if op == 0x03 and rs1 == rd:
        return 'load base'
    if op == 0x63 and rd in (rs1, rs2):
        return 'branch'
    return 'other'


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__.split('\n\n')[1])
    meta = read_map(sys.argv[1])
    ranges, starts = jit_ranges(sys.argv[2])

    def in_jit(test, v):
        i = bisect.bisect_right(starts.get(test, []), v) - 1
        return i >= 0 and v < ranges[test][i][1]

    c = collections.Counter()
    high = collections.Counter()
    calls = collections.defaultdict(collections.Counter)
    for path in sys.argv[3:]:
        data, secs = read_elf(path)
        for addr, size, off in secs:
            tier, jit, sz, test = meta[addr]
            words = section_words(data, size, off)
            i = 0
            while i < len(words):
                kind = li_sequence(words, i) if (words[i] >> 7) & 31 else None
                if not kind:
                    i += 1
                    continue
                n = LI_LEN[kind]
                ws = words[i:i + n]
                v = li_ptr_value(ws) if kind == 'li_ptr' else li_const_value(ws)
                if v in (0, -1):
                    vc = 'placeholder %d' % v
                elif jit <= v < jit + sz:
                    vc = 'same blob'
                elif in_jit(test, v):
                    vc = 'other JIT code'
                elif v >> 47 in (0, -1):
                    vc = 'other <2^47'
                else:
                    vc = 'high bits set'
                    high[(kind, (v >> 48) & 0xffff)] += 1
                u = use(words, i + n, (words[i] >> 7) & 31)
                c[(kind, tier, u, vc)] += 1
                if u == 'call' and vc == 'other <2^47':
                    calls[(kind, tier, test)][v] += 1
                i += n
    for kind in ('li_ptr', 'li_constant'):
        rows = {k: v for k, v in c.items() if k[0] == kind}
        seqs = sum(rows.values())
        print('== %s: %d sequences, %d words' % (
            kind, seqs, seqs * LI_LEN[kind]))
        agg = collections.Counter()
        by_tier = collections.Counter()
        for (_k, t, u, v), n in rows.items():
            agg[(u, v)] += n
            by_tier[t] += n
        print('  by tier: ' + ', '.join('%s %d' % kv for kv in
                                       by_tier.most_common()))
        print('  by use and value:')
        for (u, v), n in agg.most_common(16):
            print('    %9d  %-10s %s' % (n, u, v))
        print('  by tier, use and value (>= 1000):')
        for (_k, t, u, v), n in sorted(rows.items(), key=lambda kv: -kv[1]):
            if n >= 1000:
                print('    %9d  %-4s %-10s %s' % (n, t, u, v))
        hi = [(h, n) for (k, h), n in high.most_common() if k == kind][:8]
        if hi:
            print('  top 16 bits of the high values: ' +
                  ', '.join('0x%04x %d' % hn for hn in hi))
        print()
    print('calls outside the JIT by test (>= 1000 sites): sites, distinct '
          'targets, sites of the commonest five')
    for (kind, tier, test), t in sorted(calls.items(),
                                        key=lambda kv: -sum(kv[1].values())):
        n = sum(t.values())
        if n >= 1000:
            print('  %-11s %-4s %-28s %7d %4d  %s' % (
                kind, tier, test, n, len(t),
                ' '.join('%d' % m for _v, m in t.most_common(5))))


if __name__ == '__main__':
    main()
