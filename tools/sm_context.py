#!/usr/bin/env python3
"""Disassemble the code around sample findings of one check in one tier.

  sm_context.py DIR CHECK TIER [N] [BEFORE] [AFTER] [SHAPE]

DIR is a tools/sm_analyze.sh output directory. CHECK and SHAPE are
substrings of the finding's check name and of its instruction text, and
TIER is ION, BL, RE, TR or WA. N findings (default 3) are printed with
BEFORE and AFTER instructions of context (default 8 and 6), spread across
the corpus by taking every seventh match; the finding's own first
instruction is marked with '>'. OBJDUMP names an llvm-objdump with RISC-V
support (default: llvm-objdump on PATH).
"""

import glob
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__.split('\n\n')[1])
    d, check, tier = sys.argv[1:4]
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    before = int(sys.argv[5]) if len(sys.argv) > 5 else 8
    after = int(sys.argv[6]) if len(sys.argv) > 6 else 6
    shape = sys.argv[7] if len(sys.argv) > 7 else None
    objdump = os.environ.get('OBJDUMP', 'llvm-objdump')
    seen = 0
    for p in sorted(glob.glob(os.path.join(d, 'code.elf.*.json'))):
        with open(p) as fp:
            findings = json.load(fp)['findings']
        for f in findings:
            if check not in f['check'] or not f['function'].startswith(tier + '_'):
                continue
            if shape and shape not in ' ; '.join(f['text']):
                continue
            seen += 1
            if seen % 7 != 1:
                continue
            a = f['vaddr']
            start = max(a - 4 * before, a - f['function_offset'])
            out = subprocess.run(
                [objdump, '-d', '--no-show-raw-insn',
                 '--mattr=+zba,+zbb,+zbs,+zfa,+zfhmin,+zicond',
                 '--start-address=%d' % start,
                 '--stop-address=%d' % (a + f['length'] + 4 * after),
                 p[:-len('.json')]],
                capture_output=True, text=True).stdout
            print('### %s <%s+0x%x> %s' % (f['check'], f['function'],
                                           f['function_offset'], f['detail']))
            for line in out.splitlines()[6:]:
                mark = '>' if line.strip().startswith('%x:' % a) else ' '
                print(mark + line)
            n -= 1
            if n == 0:
                return


if __name__ == '__main__':
    main()
