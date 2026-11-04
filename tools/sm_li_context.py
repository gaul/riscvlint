#!/usr/bin/env python3
"""Disassemble sample li_ptr / li_constant loads of one tier and use.

  sm_li_context.py DIR TIER KIND USE [N]

DIR is a tools/sm_analyze.sh output directory, TIER is ION, BL, RE, TR or
WA, KIND is li_ptr or li_constant, and USE is one of the uses
tools/sm_constants.py prints (call, jump, push, store, 'load base',
branch, other, end). N sequences (default 4), drawn at random with a
fixed seed, are printed with six instructions either side, headed by the
test and the decoded value. OBJDUMP names an llvm-objdump with RISC-V
support (default: llvm-objdump on PATH).
"""

import glob
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sm_analyze_findings import (read_elf, read_map, section_words,  # noqa: E402
                                 li_sequence, LI_LEN)
from sm_constants import li_const_value, li_ptr_value, use  # noqa: E402


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__.split('\n\n')[1])
    d, tier, kind, want = sys.argv[1:5]
    n = int(sys.argv[5]) if len(sys.argv) > 5 else 4
    objdump = os.environ.get('OBJDUMP', 'llvm-objdump')
    meta = read_map(os.path.join(d, 'code.map'))
    sites = []
    for p in sorted(glob.glob(os.path.join(d, 'code.elf.*'))):
        if p.endswith('.json'):
            continue
        data, secs = read_elf(p)
        for addr, size, off in secs:
            t, _jit, _sz, test = meta[addr]
            if t != tier:
                continue
            words = section_words(data, size, off)
            i = 0
            while i < len(words):
                k = li_sequence(words, i) if (words[i] >> 7) & 31 else None
                if not k:
                    i += 1
                    continue
                m = LI_LEN[k]
                if k == kind and use(words, i + m, (words[i] >> 7) & 31) == want:
                    ws = words[i:i + m]
                    v = li_ptr_value(ws) if k == 'li_ptr' else li_const_value(ws)
                    sites.append((p, addr + 4 * i, v, test))
                i += m
    print('%d sites' % len(sites))
    random.seed(1)
    for p, a, v, test in random.sample(sites, min(n, len(sites))):
        out = subprocess.run(
            [objdump, '-d', '--no-show-raw-insn',
             '--mattr=+zba,+zbb,+zbs,+zfa,+zfhmin,+zicond',
             '--start-address=%d' % (a - 24),
             '--stop-address=%d' % (a + 4 * LI_LEN[kind] + 24), p],
            capture_output=True, text=True).stdout
        print('## %s value %#x' % (test, v & (2 ** 64 - 1)))
        print('\n'.join(out.splitlines()[6:]))


if __name__ == '__main__':
    main()
