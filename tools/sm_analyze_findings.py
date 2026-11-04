#!/usr/bin/env python3
"""Cross-tabulate riscvlint --json findings over a SpiderMonkey JIT corpus.

  sm_analyze_findings.py MAP OUTPREFIX JSON...

MAP is tools/smdump2elf.py's --map sidecar and each JSON is one part's
`riscvlint --json` output. Writes OUTPREFIX.txt (checks by tier, bytes,
the split of the two checks SpiderMonkey's patchable sequences dominate,
and the commonest shapes per check) and OUTPREFIX-samples.txt (one finding
per check and shape).

SpiderMonkey's riscv64 assembler loads every patchable pointer with a
fixed six-instruction Assembler::li_ptr and every patchable 64-bit
constant with a fixed eight-instruction Assembler::li_constant, whatever
the value, so that the value can be rewritten in place later. riscvlint
reads those as constants built in more instructions than needed, and the
`slli`/`ori` steps of one whose value fits in fewer bits as instructions
with no effect. They are split out here, since shortening one means
giving up the patching, not a peephole.
"""

import bisect
import collections
import json
import os
import re
import struct
import sys

TIERS = ['ION', 'BL', 'RE', 'TR', 'WA']
TIER_NAME = {'ION': 'Ion', 'BL': 'Baseline', 'RE': 'RegExp', 'TR': 'Trampoline',
             'WA': 'Wasm'}
SAVE_RE = re.compile(r'\((\d+) -> (\d+) bytes\)')
DEL_RE = re.compile(r'\((\d+) bytes\)')
LI_PTR = ['lui', 'addi', 'slli', 'ori', 'slli', 'ori']
REG_RE = re.compile(r'\b(zero|ra|sp|gp|tp|[ast]\d+|f[ast]?\d+|ft\d+|fs\d+)\b')
IMM_RE = re.compile(r'-?0x[0-9a-f]+|-?\b\d+\b')

# (opcode, funct3, shamt or None) of each word after the leading lui, for
# Assembler::li_ptr (48-bit, 6 words) and Assembler::li_constant (64-bit,
# 8 words). Every word reads and writes the lui's rd.
LI_PTR_TAIL = [(0x13, 0, None), (0x13, 1, 11), (0x13, 6, None),
               (0x13, 1, 6), (0x13, 6, None)]
LI_CONST_TAIL = [(0x1b, 0, None), (0x13, 1, 12), (0x13, 0, None),
                 (0x13, 1, 12), (0x13, 0, None), (0x13, 1, 12),
                 (0x13, 0, None)]


def read_elf(path):
    """(bytes, [(addr, size, file offset)] of each executable section)."""
    with open(path, 'rb') as f:
        data = f.read()
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shnum, = struct.unpack_from('<H', data, 0x3c)
    secs = []
    for i in range(shnum):
        (_name, typ, flags, addr, off, size, _l, _i, _a,
         _e) = struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * i)
        if typ == 1 and flags & 4:
            secs.append((addr, size, off))
    secs.sort()
    return data, secs


def section_words(data, size, off):
    return struct.unpack_from('<%dI' % (size // 4), data, off)


def read_map(path):
    """{synthetic addr: (tier, jit addr, size, test)}."""
    meta = {}
    with open(path) as f:
        for line in f:
            name, addr, size, jit, _kind, test = line.split()
            meta[int(addr, 16)] = (name.split('_')[0], int(jit, 16),
                                   int(size), test)
    return meta


def match_tail(words, i, rd, tail):
    if i + len(tail) >= len(words):
        return False
    for k, (op, f3, sh) in enumerate(tail):
        w = words[i + 1 + k]
        if (w & 0x7f != op or (w >> 12) & 7 != f3 or
                (w >> 7) & 31 != rd or (w >> 15) & 31 != rd or
                (sh is not None and (w >> 20) & 0x3f != sh)):
            return False
    return True


def li_sequence(words, i):
    """'li_ptr' or 'li_constant' if one starts at words[i], else None."""
    w = words[i]
    if w & 0x7f != 0x37:
        return None
    rd = (w >> 7) & 31
    if match_tail(words, i, rd, LI_PTR_TAIL):
        return 'li_ptr'
    if match_tail(words, i, rd, LI_CONST_TAIL):
        return 'li_constant'
    return None


LI_LEN = {'li_ptr': 6, 'li_constant': 8}


def li_words(words):
    """Indices of the words inside li_ptr and li_constant sequences."""
    hit = set()
    for i in range(len(words)):
        kind = li_sequence(words, i)
        if kind:
            hit.update(range(i, i + LI_LEN[kind]))
    return hit


class Image:
    def __init__(self, path):
        self.data, self.secs = read_elf(path)
        self.addrs = [a for a, _s, _o in self.secs]
        self.cache = {}

    def in_li(self, vaddr, length):
        j = bisect.bisect_right(self.addrs, vaddr) - 1
        if j < 0:
            return False
        addr, size, off = self.secs[j]
        if j not in self.cache:
            self.cache[j] = li_words(section_words(self.data, size, off))
        hit = self.cache[j]
        first = (vaddr - addr) // 4
        return any(k in hit for k in range(first, first + max(1, length // 4)))


def saved(detail):
    m = SAVE_RE.search(detail)
    if m:
        return int(m.group(1)) - int(m.group(2))
    m = DEL_RE.search(detail)
    return int(m.group(1)) if m else 0


def shape(text):
    return ' ; '.join(IMM_RE.sub('#', REG_RE.sub('r', t)) for t in text)


def subclass(f, in_li):
    ops = [t.split()[0] for t in f['text']]
    if f['check'] == 'constant built in more instructions than li needs':
        if ops == LI_PTR:
            return 'li_ptr (patchable 48-bit, fixed six instructions)'
        if in_li and len(ops) == 8:
            return 'li_constant (patchable 64-bit, fixed eight instructions)'
        return 'other constant'
    if f['check'] == 'instruction with no architectural effect':
        t = f['text'][0]
        if in_li:
            return 'inside li_ptr/li_constant (patchable, not removable)'
        if t.startswith('lui zero'):
            return 'lui zero after ebreak (break_ code word)'
        return shape([t])
    return None


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__.split('\n\n')[1])
    mapfile, outprefix = sys.argv[1], sys.argv[2]
    insns = collections.Counter()
    blobs = collections.Counter()
    tests = set()
    for tier, _jit, size, test in read_map(mapfile).values():
        insns[tier] += size // 4
        blobs[tier] += 1
        tests.add(test)
    by = collections.defaultdict(collections.Counter)
    bytes_by = collections.defaultdict(collections.Counter)
    sub = collections.defaultdict(collections.Counter)
    sub_bytes = collections.defaultdict(collections.Counter)
    shapes = collections.defaultdict(collections.Counter)
    samples = {}
    skipped = 0
    in_li = collections.Counter()
    for path in sys.argv[3:]:
        with open(path) as fp:
            d = json.load(fp)
        skipped += d.get('skipped', 0)
        elf = d['file']
        if not os.path.isabs(elf):
            elf = os.path.join(os.path.dirname(path), elf)
        img = Image(elf)
        for f in d['findings']:
            inl = img.in_li(f['vaddr'], f['length'])
            c = f['check']
            if inl:
                in_li[c] += 1
            tier = f['function'].split('_')[0]
            s = saved(f['detail'])
            by[c][tier] += 1
            bytes_by[c][tier] += s
            sc = subclass(f, inl)
            if sc:
                sub[c][sc] += 1
                sub_bytes[c][sc] += s
            sh = shape(f['text'])
            shapes[c][(tier, sh)] += 1
            samples.setdefault((c, tier, sh), f)

    total_insns = sum(insns.values())
    order = sorted(by, key=lambda c: -sum(by[c].values()))
    with open(outprefix + '.txt', 'w') as out:
        w = out.write
        w('corpus: %d tests, %d blobs, %d instructions\n' % (
            len(tests), sum(blobs.values()), total_insns))
        for t in TIERS:
            w('  %-10s %7d blobs %11d insns (%.1f%%)\n' % (
                TIER_NAME[t], blobs[t], insns[t],
                100.0 * insns[t] / max(1, total_insns)))
        w('bytes riscvlint skipped as undecodable: %d\n\n' % skipped)
        w('%-50s' % 'check' + ''.join('%11s' % TIER_NAME[t] for t in TIERS) +
          '%11s%12s\n' % ('total', 'bytes'))
        grand = grand_bytes = 0
        for c in order:
            n = sum(by[c].values())
            b = sum(bytes_by[c].values())
            grand += n
            grand_bytes += b
            w('%-50s' % c[:50] + ''.join('%11d' % by[c][t] for t in TIERS) +
              '%11d%12d\n' % (n, b))
        w('%-50s' % 'total' + ''.join(
            '%11d' % sum(by[c][t] for c in by) for t in TIERS) +
          '%11d%12d\n\n' % (grand, grand_bytes))
        w('findings that touch an li_ptr or li_constant sequence, by check:\n')
        for c in order:
            if in_li[c]:
                w('  %9d of %9d  %s\n' % (in_li[c], sum(by[c].values()), c))
        w('\n')
        for c in order:
            if c in sub:
                w('%s, split:\n' % c)
                for sc, n in sub[c].most_common():
                    w('  %9d %10d bytes  %s\n' % (n, sub_bytes[c][sc], sc))
                w('\n')
        w('\nTop shapes per check (tier: count  shape)\n')
        for c in order:
            w('\n== %s (%d)\n' % (c, sum(by[c].values())))
            for (tier, sh), n in shapes[c].most_common(8):
                w('  %-4s %8d  %s\n' % (tier, n, sh[:160]))

    with open(outprefix + '-samples.txt', 'w') as s:
        for c in order:
            for (tier, sh), _n in shapes[c].most_common(4):
                f = samples[(c, tier, sh)]
                s.write('%s <%s+0x%x>: %s\n' % (
                    c, f['function'], f['function_offset'], f['detail']))
                for t in f['text']:
                    s.write('    %s\n' % t)
                s.write('\n')


if __name__ == '__main__':
    main()
