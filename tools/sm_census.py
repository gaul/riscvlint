#!/usr/bin/env python3
"""Count the words SpiderMonkey's fixed-shape riscv64 sequences take, by tier.

  sm_census.py [--jal-veneers] MAP ELF...

These are sequences the assembler emits whole, whatever their operands,
so their cost is a share of all code rather than something a peephole
finds one site at a time:

  li_ptr           lui+addi+slli+ori+slli+ori, a patchable 48-bit pointer
  li_constant      lui+addiw+(slli+addi)x3, a patchable 64-bit constant
  ebreak+lui zero  MacroAssembler::breakpoint's code word: an ebreak and
                   a lui to zero that only the simulator reads
  auipc+jr         a 32-bit pc-relative jump

The auipc+jr pairs are then split into the veneer pools the branch
deadline machinery emits -- a guard `j` over a run of veneers -- and the
rest. A veneer is an auipc+jr pair or, with --jal-veneers for a shell
whose veneers are a single jal, also one `j`; the option is off by default
as runs of code jumps then pass for pools too. A veneer is inserted into
its label's jump chain as insurance: if the label binds within the
branch's own range, Assembler::bind patches the branch straight to it and
the veneer, patched to the label too, is
never reached. So each veneer slot is counted as targeted by a branch in
its blob or not, and the targeted ones are binned by the distance back
to their branch, which for a veneer emitted because its branch's
deadline came up is just under the 4 KiB B-type range. The spacing of
pools is binned the same way.
"""

import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sm_analyze_findings import (TIERS, read_elf, read_map,  # noqa: E402
                                 section_words, li_sequence, LI_LEN)

EBREAK = 0x00100073
SIZE = {'li_ptr': 6, 'li_constant': 8, 'ebreak+lui zero': 2, 'auipc+jr': 2}
BIN = 512
BINS = 8


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def is_jr_pair(words, i):
    if i + 1 >= len(words):
        return False
    w, w2 = words[i], words[i + 1]
    return (w & 0x7f == 0x17 and w2 & 0x7f == 0x67 and (w2 >> 7) & 31 == 0
            and (w2 >> 15) & 31 == (w >> 7) & 31)


def jal_offset(w):
    return sx((((w >> 31) & 1) << 20) | (((w >> 12) & 0xff) << 12) |
              (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3ff) << 1), 21)


def branch_offset(w):
    return sx((((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) |
              (((w >> 25) & 0x3f) << 5) | (((w >> 8) & 0xf) << 1), 13)


def branch_sources(words):
    """{word index: [indices of the branches and jals that target it]}."""
    src = collections.defaultdict(list)
    for i, w in enumerate(words):
        op = w & 0x7f
        if op == 0x63:
            src[i + branch_offset(w) // 4].append(i)
        elif op == 0x6f:
            src[i + jal_offset(w) // 4].append(i)
    return src


class Census:
    def __init__(self, jal_veneers=False):
        self.jal_veneers = jal_veneers
        self.total = collections.Counter()
        self.seq = collections.defaultdict(collections.Counter)
        self.pairs = collections.defaultdict(collections.Counter)
        self.slots = collections.defaultdict(collections.Counter)
        self.reach = collections.defaultdict(collections.Counter)
        self.spacing = collections.defaultdict(collections.Counter)

    def pool(self, words, tier, i, src, last):
        """Count the pool guarded at words[i]; return the index after it."""
        off = jal_offset(words[i])
        slots = []
        j = i + 1
        while (j - i) * 4 < off:
            if is_jr_pair(words, j):
                slots.append((j, 2))
                j += 2
            elif (self.jal_veneers and j < len(words) and
                  words[j] & 0xfff == 0x06f):
                slots.append((j, 1))
                j += 1
            else:
                break
        if off == 4:
            self.slots['guards that jump to the next word'][tier] += 1
        if not slots or (j - i) * 4 != off:
            return None
        self.slots['pools'][tier] += 1
        self.spacing[tier][min(BINS - 1, (i - last) * 4 // BIN)] += 1
        for k, size in slots:
            if size == 2:
                self.seq['auipc+jr'][tier] += 1
                self.pairs['veneer pool'][tier] += 1
                to_self = words[k] >> 12 == 0 and words[k + 1] >> 20 == 0
            else:
                self.slots['jal veneers'][tier] += 1
                to_self = jal_offset(words[k]) == 0
            self.slots['veneer slots'][tier] += 1
            self.slots['veneer words'][tier] += size
            if src.get(k):
                self.slots['targeted by a branch'][tier] += 1
                d = min(abs(k - b) for b in src[k]) * 4
                self.reach[tier][min(BINS - 1, d // BIN)] += 1
            else:
                self.slots['targeted by nothing'][tier] += 1
            if to_self:
                self.slots['jumping to itself'][tier] += 1
        return j

    def scan(self, words, tier):
        self.total[tier] += len(words)
        src = branch_sources(words)
        n = len(words)
        last = 0
        i = 0
        while i < n:
            w = words[i]
            op = w & 0x7f
            if op == 0x37:
                if (w >> 7) & 31 == 0 and i and words[i - 1] == EBREAK:
                    self.seq['ebreak+lui zero'][tier] += 1
                else:
                    kind = li_sequence(words, i)
                    if kind:
                        self.seq[kind][tier] += 1
                        i += LI_LEN[kind]
                        continue
            elif w & 0xfff == 0x06f:
                after = self.pool(words, tier, i, src, last)
                if after is not None:
                    last = i = after
                    continue
            if is_jr_pair(words, i):
                self.seq['auipc+jr'][tier] += 1
                self.pairs['standalone'][tier] += 1
                i += 2
                continue
            i += 1


def row(label, values, fmt='%12d'):
    print('%-34s' % label + ''.join(fmt % v for v in values))


def main():
    args = sys.argv[1:]
    jal_veneers = '--jal-veneers' in args
    args = [a for a in args if a != '--jal-veneers']
    if len(args) < 2:
        sys.exit(__doc__.split('\n\n')[1])
    meta = read_map(args[0])
    c = Census(jal_veneers)
    for path in args[1:]:
        data, secs = read_elf(path)
        for addr, size, off in secs:
            c.scan(section_words(data, size, off), meta[addr][0])
    alltotal = sum(c.total.values())
    row('words', TIERS + ['all'], '%12s')
    row('total', [c.total[t] for t in TIERS] + [alltotal])
    for k in ['li_ptr', 'li_constant', 'ebreak+lui zero', 'auipc+jr']:
        row(k + ' seqs', [c.seq[k][t] for t in TIERS] +
            [sum(c.seq[k].values())])
        print('%-34s' % '  % of words' + ''.join(
            '%11.2f%%' % (100.0 * SIZE[k] * c.seq[k][t] / max(1, c.total[t]))
            for t in TIERS) + '%11.2f%%' % (
            100.0 * SIZE[k] * sum(c.seq[k].values()) / max(1, alltotal)))
    print()
    row('auipc+jr pairs', TIERS, '%12s')
    for k in ['veneer pool', 'standalone']:
        row('  ' + k, [c.pairs[k][t] for t in TIERS])
    print()
    row('veneer pools', TIERS, '%12s')
    row('  pools', [c.slots['pools'][t] for t in TIERS])
    row('  guards that jump to the next word',
        [c.slots['guards that jump to the next word'][t] for t in TIERS])
    for k in ['veneer slots', 'jal veneers', 'veneer words']:
        row('  ' + k, [c.slots[k][t] for t in TIERS])
    for k in ['targeted by a branch', 'targeted by nothing',
              'jumping to itself']:
        row('    ' + k, [c.slots[k][t] for t in TIERS])
    for title, bins in (('targeted veneer slots by bytes back to the branch',
                         c.reach),
                        ('pools by bytes since the previous pool or the '
                         'blob start', c.spacing)):
        print()
        print(title + ':')
        for b in range(BINS):
            label = '  %d-%d' % (b * BIN, (b + 1) * BIN - 1)
            if b == BINS - 1:
                label = '  %d+' % (b * BIN)
            row(label, [bins[t][b] for t in TIERS])

if __name__ == '__main__':
    main()
