#!/usr/bin/env python3
"""Cross-reference riscvlint --json findings with a V8 dump's RelocInfo.

The port of armlint's tools/v8_analyze_findings.py. It reads the JSON
documents riscvlint --json writes for the ELFs that tools/v8dump2elf.py
built, the --map sidecar that names each section's tier and function,
and the --relocs sidecar that holds every object's RelocInfo entries.

Outputs:
  * check x compiler-tier cross-tab, plus the findings per tier that
    repeat an earlier copy of the same function: a JIT recompiles a
    function after every deopt, and the copies carry the same sites
  * per check: how many findings contain a relocated (patchable)
    instruction, broken down by reloc mode -- those are toolchain-forced.
    Deopt entries are left out: they annotate the return address of a
    call for the deoptimizer and constrain nothing about the encoding
  * top offender functions
  * sample finding blocks per check (with reloc annotation)

Usage: v8_analyze_findings.py MAP RELOCS OUTPREFIX FINDINGS.json...

Attribution is by the symbol riscvlint reports ("function" and
"function_offset" in its JSON), never by address: V8 reuses code
addresses across a run, so an address names many objects over time.
A JetStream dump yields millions of findings; the inputs are processed
one JSON file at a time and the reloc table and the repeat index are
kept as packed arrays and hashes rather than Python objects per site.
"""

import argparse
import bisect
import collections
import json
import re
import sys
from array import array

CONT_RE = re.compile(r'^(.*)@([0-9a-f]+)$')


def load_map(path):
    """name -> (elf addr, size, jit addr), plus sorted arrays for the
    address fallback when a finding carries no symbol."""
    by_name = {}
    entries = []
    for line in open(path):
        parts = line.split()
        name, addr, size = parts[0], int(parts[1], 16), int(parts[2])
        jit = int(parts[3], 16) if len(parts) > 3 else addr
        by_name[name] = (addr, size, jit)
        entries.append((addr, size, name))
    entries.sort()
    starts = array('Q', (e[0] for e in entries))
    sizes = array('Q', (e[1] for e in entries))
    names = [e[2] for e in entries]
    return by_name, starts, sizes, names


def load_relocs(path):
    """object -> (sorted array of offsets, bytes of mode ids), and the
    mode id -> name table."""
    modes = {}
    per_obj = collections.defaultdict(lambda: (array('Q'), bytearray()))
    for line in open(path):
        obj, off, mode = line.rstrip('\n').split(' ', 2)
        mid = modes.get(mode)
        if mid is None:
            mid = modes[mode] = len(modes)
        offs, ids = per_obj[obj]
        offs.append(int(off, 16))
        ids.append(mid)
    table = {}
    for obj, (offs, ids) in per_obj.items():
        order = sorted(range(len(offs)), key=offs.__getitem__)
        table[obj] = (array('Q', (offs[i] for i in order)),
                      bytes(ids[i] for i in order))
    names = [None] * len(modes)
    for k, v in modes.items():
        names[v] = k
    return table, names


def iter_documents(path):
    """Yield each JSON document in a riscvlint --json output file."""
    text = open(path, errors='replace').read()
    dec = json.JSONDecoder()
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        doc, pos = dec.raw_decode(text, pos)
        yield doc


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('map', help='the --map sidecar v8dump2elf.py wrote')
    ap.add_argument('relocs', help='the --relocs sidecar v8dump2elf.py wrote')
    ap.add_argument('outprefix', help='samples land in OUTPREFIX-samples.txt')
    ap.add_argument('findings', nargs='+',
                    help='riscvlint --json output, one file per ELF or one '
                         'for all of them')
    ap.add_argument('--samples', type=int, default=8,
                    help='sample blocks kept per check')
    ap.add_argument('--top', type=int, default=20,
                    help='functions listed in the top-offender table')
    a = ap.parse_args()

    by_name, starts, sizes, names = load_map(a.map)
    relocs, reloc_names = load_relocs(a.relocs)
    nrelocs = sum(len(v[0]) for v in relocs.values())
    print('v8_analyze_findings: %d chunks in the map, %d reloc entries in '
          '%d objects (%s)' % (len(names), nrelocs, len(relocs),
                               ', '.join(reloc_names) or 'none'),
          file=sys.stderr)

    def chunk_by_addr(vaddr):
        i = bisect.bisect_right(starts, vaddr) - 1
        if i >= 0 and vaddr < starts[i] + sizes[i]:
            return names[i], vaddr - starts[i]
        return None, 0

    def relocs_in(obj, lo, hi):
        entry = relocs.get(obj)
        if entry is None:
            return set()
        offs, ids = entry
        i = bisect.bisect_left(offs, lo)
        found = set()
        while i < len(offs) and offs[i] < hi:
            found.add(reloc_names[ids[i]])
            i += 1
        return found

    by_check_tier = collections.defaultdict(collections.Counter)
    repeats_by_tier = collections.Counter()
    by_check_reloc = collections.defaultdict(collections.Counter)
    by_func = collections.Counter()
    samples = collections.defaultdict(list)
    seen_sites = set()          # hashes of (function, size, offset, check, bytes)
    unmapped = 0
    total = 0
    instructions = 0
    files = 0
    for path in a.findings:
        for doc in iter_documents(path):
            files += 1
            instructions += doc.get('instructions', 0)
            for f in doc.get('findings', []):
                total += 1
                vaddr = f['vaddr']
                check = f['check']
                length = f.get('length', 0)
                sym = f.get('function')
                if sym is not None and sym in by_name:
                    off = f.get('function_offset', 0)
                else:
                    sym, off = chunk_by_addr(vaddr)
                if sym is None:
                    unmapped += 1
                    sym = 'UN_unmapped'
                    off = 0
                size = by_name.get(sym, (0, 0, 0))[1]
                # A section named NAME@HEX is the continuation of NAME
                # after a constant pool or jump table; fold it back into
                # the object with the offset relative to the object.
                m = CONT_RE.match(sym)
                if m:
                    sym = m.group(1)
                    off += int(m.group(2), 16)
                    size = by_name.get(sym, (0, size, 0))[1]
                tier = sym.split('_', 1)[0]
                func = re.sub(r'\.\d+$', '', sym)
                by_check_tier[check][tier] += 1
                by_func[func] += 1
                # The same site in a later copy of the same function:
                # keyed on the function, the size of its code (V8 leaves
                # most functions unnamed, and two different anonymous
                # functions almost never compile to the same length), the
                # offset into it and the bytes.
                key = hash((func, size, off, check,
                            f.get('bytes', length)))
                repeat = key in seen_sites
                seen_sites.add(key)
                if repeat:
                    repeats_by_tier[tier] += 1
                modes = {m for m in relocs_in(sym, off, off + length)
                         if not m.startswith('deopt')}
                if modes:
                    by_check_reloc[check]['(forced)'] += 1
                    for mode in modes:
                        by_check_reloc[check][mode] += 1
                else:
                    by_check_reloc[check]['(none)'] += 1
                if len(samples[check]) < a.samples:
                    tag = (' [reloc: %s]' % ', '.join(sorted(modes))
                           if modes else '')
                    tag += ' [repeat]' if repeat else ''
                    body = '\n'.join('  %s' % t for t in f.get('text', []))
                    jit = by_name.get(sym, (0, 0, 0))[2]
                    samples[check].append(
                        '%s <%s+0x%x> (jit 0x%x): %s (%d bytes)%s\n%s' %
                        (check, sym, off, jit + off, f.get('detail', ''),
                         length, tag, body))

    if unmapped:
        print('v8_analyze_findings: %d findings carried no symbol and '
              'matched no map entry; counted under tier UN' % unmapped,
              file=sys.stderr)

    tiers = sorted({t for c in by_check_tier.values() for t in c})
    print('== %d findings over %d instructions in %d ELF(s); check x tier ==' %
          (total, instructions, files))
    print('%-58s %s' % ('', ' '.join('%9s' % t for t in tiers)))
    for check, counter in sorted(by_check_tier.items(),
                                 key=lambda kv: -sum(kv[1].values())):
        print('%-58s %s' % (check[:58],
                            ' '.join('%9d' % counter.get(t, 0)
                                     for t in tiers)))
    print('%-58s %s' % ('total', ' '.join(
        '%9d' % sum(c.get(t, 0) for c in by_check_tier.values())
        for t in tiers)))
    if repeats_by_tier:
        print('%-58s %s' % ('of which repeat an earlier copy of the function',
                            ' '.join('%9d' % repeats_by_tier.get(t, 0)
                                     for t in tiers)))

    print('\n== reloc-forced analysis (findings containing a reloc site) ==')
    for check, counter in sorted(
            by_check_reloc.items(),
            key=lambda kv: -(kv[1].get('(forced)', 0) + kv[1].get('(none)', 0))):
        forced = counter.get('(forced)', 0)
        n = forced + counter.get('(none)', 0)
        if forced == 0:
            continue
        detail = ', '.join('%s: %d' % (m, c) for m, c in counter.most_common()
                           if m not in ('(none)', '(forced)'))
        print('%-58s %d/%d forced (%s)' % (check[:58], forced, n, detail))

    print('\n== top functions ==')
    for func, n in by_func.most_common(a.top):
        print('%8d  %s' % (n, func))

    with open(a.outprefix + '-samples.txt', 'w') as f:
        for check, blocks in sorted(samples.items()):
            f.write('===== %s =====\n' % check)
            f.write('\n\n'.join(blocks))
            f.write('\n\n')
    print('\nsamples -> %s-samples.txt' % a.outprefix)
    return 0


if __name__ == '__main__':
    sys.exit(main())
