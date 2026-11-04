#!/usr/bin/env python3
"""Convert SpiderMonkey JS_CODE_DUMP records into riscv64 ELF objects.

A shell built with tools/sm_code_dump.patch appends one record per linked
code blob to <JS_CODE_DUMP>.<pid>.bin when that variable is set:

  "SMJC"  kind[8] (Ion/Baseline/RegExp/Other/Wasm, NUL-padded)
  uint64 JIT address  uint64 length  <length bytes of code>

Every blob becomes one SHF_EXECINSTR section with an STT_FUNC symbol
<TIER>_<test>_<n> (ION, BL, RE, TR for the trampolines and stubs of kind
Other, WA for a whole Wasm module's code segment), laid out at unique
synthetic addresses with tools/v8dump2elf.py's writer, since the JIT
reuses addresses as code is discarded. The --map sidecar has one line per
section, "name 0xaddr size 0xjitaddr kind test", which is all the
sm_*.py analyses need to attribute a finding.

SpiderMonkey's riscv64 backend emits no compressed instructions and keeps
no constant pools: every blob is a whole number of 32-bit instructions,
and the only data inside one is a veneer pool, which is itself code
(a guard j over auipc + jr pairs). So unlike V8 a blob is never split.

Usage: smdump2elf.py [-o OUT.elf] [--map OUT.map] [--arch STRING]
       [--max-sections N] [--dedupe-startup] DUMP.bin...
A dump file named <test>.<pid>.bin contributes <test> to the names. The
output is split into OUT.1, OUT.2, ... of --max-sections each.

--dedupe-startup is for a corpus with one process per test, as
tools/sm_jetstream_dump.sh produces: every process links the same
JitRuntime trampolines and Wasm builtin thunks first, so without it a
75-test corpus counts that code 75 times. The blobs dropped are the first
--startup-other Other and --startup-wasm Wasm blobs of every dump after
the first. Their sizes are compared with the first dump's and the
mismatches reported. A few are expected, since the same trampolines come
out at slightly different sizes from process to process -- in a native
K3 run 22 of 592 differed, the largest by 1,536 of 60,440 bytes -- but
many more mean the counts are wrong for this shell.
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v8dump2elf  # noqa: E402

KIND_PREFIX = {
    'Ion': 'ION',
    'Baseline': 'BL',
    'RegExp': 'RE',
    'Other': 'TR',
    'Wasm': 'WA',
}


class Chunk:
    __slots__ = ('name', 'jit_addr', 'data', 'addr', 'kind', 'test')


def read_dump(path, test):
    with open(path, 'rb') as f:
        buf = f.read()
    chunks = []
    pos = 0
    while pos + 28 <= len(buf):
        if buf[pos:pos + 4] != b'SMJC':
            print('%s: bad record magic at offset %d; stopping' % (path, pos),
                  file=sys.stderr)
            break
        kind = buf[pos + 4:pos + 12].rstrip(b'\0').decode()
        addr, length = struct.unpack_from('<QQ', buf, pos + 12)
        pos += 28
        if pos + length > len(buf):
            print('%s: truncated record at offset %d' % (path, pos),
                  file=sys.stderr)
            break
        c = Chunk()
        c.kind = kind
        c.test = test
        c.jit_addr = addr
        c.data = buf[pos:pos + length]
        c.addr = 0
        c.name = '%s_%s_%d' % (KIND_PREFIX.get(kind, 'UN'), test, len(chunks))
        chunks.append(c)
        pos += length
    return chunks


def startup(chunks, limits):
    """Indices of the first limits[kind] blobs of each kind."""
    seen = {}
    out = []
    for i, c in enumerate(chunks):
        n = seen.get(c.kind, 0)
        if n < limits.get(c.kind, 0):
            out.append(i)
        seen[c.kind] = n + 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dumps', nargs='+')
    ap.add_argument('-o', '--output', default='smcode.elf')
    ap.add_argument('--map')
    ap.add_argument('--arch')
    ap.add_argument('--max-sections', type=int, default=4000)
    ap.add_argument('--dedupe-startup', action='store_true')
    ap.add_argument('--startup-other', type=int, default=6)
    ap.add_argument('--startup-wasm', type=int, default=2)
    args = ap.parse_args()

    per_file = []
    for path in sorted(args.dumps):
        test = os.path.basename(path).split('.')[0]
        per_file.append(read_dump(path, test))
    if args.dedupe_startup and len(per_file) > 1:
        limits = {'Other': args.startup_other, 'Wasm': args.startup_wasm}
        first = per_file[0]
        ref = [len(first[i].data) for i in startup(first, limits)]
        dropped = mismatched = 0
        for mine in per_file[1:]:
            idx = startup(mine, limits)
            for k, i in enumerate(idx):
                if k >= len(ref) or ref[k] != len(mine[i].data):
                    mismatched += 1
            dropped += len(idx)
            drop = set(idx)
            mine[:] = [c for i, c in enumerate(mine) if i not in drop]
        print('dropped %d repeated startup blobs, %d of a size the first '
              'dump does not have' % (dropped, mismatched), file=sys.stderr)
    chunks = [c for mine in per_file for c in mine if c.data]
    if not chunks:
        print('no code found', file=sys.stderr)
        return 1
    v8dump2elf.pack_layout(chunks)

    if args.map:
        with open(args.map, 'w') as f:
            for c in chunks:
                f.write('%s 0x%x %d 0x%x %s %s\n' % (
                    c.name, c.addr, len(c.data), c.jit_addr, c.kind, c.test))

    outs = []
    for i in range(0, len(chunks), args.max_sections):
        part = '%s.%d' % (args.output, len(outs) + 1)
        v8dump2elf.write_elf(chunks[i:i + args.max_sections], part, args.arch)
        outs.append(part)
    counts = {}
    for c in chunks:
        counts[c.kind] = counts.get(c.kind, 0) + len(c.data) // 4
    print('%d dumps, %d blobs, %d code bytes (%s) -> %d ELF parts' % (
        len(per_file), len(chunks), sum(len(c.data) for c in chunks),
        ', '.join('%s %d insns' % kv for kv in sorted(counts.items())),
        len(outs)), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
