#!/usr/bin/env python3
"""Convert V8 --print-opt-code style dumps into ELF objects for riscvlint.

V8's code printer (d8 --print-opt-code, --print-maglev-code,
--print-code, --print-regexp-code with v8_enable_disassembler=true)
emits, per code object, a header block (name/kind/compiler) followed by

  Instructions (size = 196)
  0x3fd07a3c080     0  fe010113       addi sp, sp, -32
  0x3fd07a3c084     4  00006b22       sd s0, 16(sp)
  0x3fd07a3c086     6  0000e406       sd ra, 8(sp)
  ...
  0x3fd07a3c0f8    78  00003017       constant pool begin (num_const = 3)
  0x3fd07a3c0fc    7c  0000006f       constant
  ...
  RelocInfo (size = 12)
  0x3fd07a3c0a4  full embedded object  (0x... <Map>)

The port of armlint's tools/v8dump2elf.py, with what RISC-V and a
long-running dump change:

  * Every line prints an 8-digit word, but a compressed instruction is
    two bytes and V8 prints its 16-bit encoding zero-extended. The
    length comes from the encoding itself (low two bits 11 = 32-bit,
    anything else = 16-bit), cross-checked against the next line's
    address, so the section carries exactly the bytes the JIT emitted.
  * Constant pools (marker `auipc x0, N` + N data words) and jump
    tables are data inside the instruction stream. riscvlint has no
    engine mode that steps over them, so by default a pool or table
    ends the current section and the code after it starts a new one
    (named NAME@OFFSET); --keep-pools leaves them in place.
  * V8 frees code and reuses its addresses, so over a benchmark run
    thousands of objects share JIT addresses and nothing keyed by
    address alone can tell them apart. Sections are therefore laid out
    at unique synthetic addresses (--layout packed, the default), the
    JIT address is kept as a fourth column of the --map sidecar, and
    each object's RelocInfo goes to --relocs as "object offset mode"
    lines, so tools/v8_analyze_findings.py attributes by symbol and
    offset and never by address. --layout jit keeps the JIT addresses
    for reading a single small dump against its listing.
  * The object is EM_RISCV with e_flags = RVC | double-float ABI, and
    --arch writes a Tag_RISCV_arch attribute so riscvlint gates its
    Zb*/Zcb checks on what the host had rather than on nothing
    (without it riscvlint reports the gate as "unrestricted").

As in armlint: one SHF_EXECINSTR section per contiguous run of
instructions and an STT_FUNC symbol per section carrying the tier and
the JS function name (TF_foo, ML_foo, BL_foo, RE_<pattern>, ...; a
later compile of the same name gets .2, .3, ...). Separate sections
also stop the adjacency matcher and the bounded liveness scans from
walking across unrelated code objects.

Usage: v8dump2elf.py DUMP [-o OUT.elf] [--map OUT.map] [--relocs OUT.relocs]
       [--arch STRING] [--layout packed|jit] [--keep-pools] [--max-sections N]
The output is split into OUT.1, OUT.2, ... of --max-sections chunks each
(one map covers them all); scan them in one riscvlint invocation, or one
each with --json so the analysis gets a file per ELF.
"""

import argparse
import re
import struct
import sys

LINE_RE = re.compile(r'^0x([0-9a-f]+)\s+([0-9a-f]+)\s+(.*)$')
WORD_RE = re.compile(r'^([0-9a-f]{8})\s+(.*)$')
PTR_RE = re.compile(r'^([0-9a-f]{16})\s+jump table entry\b')
TABLE_RE = re.compile(r'^jump table entry\b')
POOL_RE = re.compile(r'^constant pool begin \(num_const = (\d+)\)')
HEADER_FIELD_RE = re.compile(r'^(name|kind|compiler)\s*=\s*(.*)$')
INSTRUCTIONS_RE = re.compile(r'^Instructions\s*\(size')
RELOC_HDR_RE = re.compile(r'^RelocInfo \(size')
RELOC_RE = re.compile(r'^0x([0-9a-f]+)\s\s+([a-z][a-zA-Z0-9 _-]*?)\s*(?:\(|$)')

KIND_PREFIX = {
    'TURBOFAN_JS': 'TF',
    'TURBOFAN': 'TF',
    'MAGLEV': 'ML',
    'BASELINE': 'BL',
    'REGEXP': 'RE',
    'WASM_FUNCTION': 'WA',
    'WASM_TO_JS_FUNCTION': 'WJ',
    'JS_TO_WASM_FUNCTION': 'JW',
    'BUILTIN': 'BI',
    'BYTECODE_HANDLER': 'BH',
    'FOR_TESTING': 'XX',
}

SANITIZE_RE = re.compile(r'[^A-Za-z0-9_.@:<>/-]')

# A `j 0` -- jal x0, 0 -- is V8's pool guard (Assembler::EmitPoolGuard);
# it follows the marker and is never executed.
POOL_GUARD = 0x0000006f


class Chunk:
    __slots__ = ('name', 'jit_addr', 'data', 'addr')

    def __init__(self, name, jit_addr):
        self.name = name
        self.jit_addr = jit_addr
        self.data = bytearray()
        self.addr = jit_addr      # the address the ELF section gets


def insn_size(word):
    """Byte length of a RISC-V encoding from its low bits."""
    return 4 if (word & 3) == 3 else 2


def parse_dump(fp, keep_pools=False, warn=None, relocs_out=None):
    """Return the list of Chunk objects a V8 code dump stream holds.
    With relocs_out, write "object 0xoffset mode" lines for every
    RelocInfo entry, offsets relative to the object's first chunk."""
    chunks = []
    name = ''
    kind = ''
    in_code = False
    in_reloc = False
    cur = None
    seen = {}
    pool_left = 0        # data words still owed to the current pool
    after_marker = False  # the next word may be the `j 0` guard
    pending = None       # (addr, word, size) awaiting the next address
    obj = None           # (name, jit addr) of the code object being listed
    stats = {'insns': 0, 'short': 0, 'pool_words': 0, 'table_words': 0,
             'length_fixups': 0, 'relocs': 0}

    def display_name():
        prefix = KIND_PREFIX.get(kind, kind[:8] if kind else 'UN')
        base = SANITIZE_RE.sub('_', name)[:80] or 'anonymous'
        full = '%s_%s' % (prefix, base)
        n = seen.get(full, 0) + 1
        seen[full] = n
        return full if n == 1 else '%s.%d' % (full, n)

    def close_chunk():
        nonlocal cur
        if cur is not None and cur.data:
            chunks.append(cur)
        cur = None

    def emit(addr, data):
        nonlocal cur, obj
        if cur is None or addr != cur.jit_addr + len(cur.data):
            close_chunk()
            if obj is None:
                obj = (display_name(), addr)
                cur = Chunk(obj[0], addr)
            else:
                # Code after a pool or table inside the same object: name
                # it by its offset in the object, so the analysis can
                # fold it back and a genuine recompile (which gets a
                # ".N" suffix) stays distinguishable from a continuation.
                cur = Chunk('%s@%x' % (obj[0], addr - obj[1]), addr)
        cur.data += data

    def flush_pending(next_addr):
        """Append the held instruction; its size is confirmed (or
        corrected) by the address of whatever follows it."""
        nonlocal pending
        if pending is None:
            return
        addr, word, size = pending
        pending = None
        if next_addr is not None:
            delta = next_addr - addr
            if delta in (2, 4) and delta != size:
                stats['length_fixups'] += 1
                if warn:
                    warn('0x%x: word %08x decodes as %d bytes but the next '
                         'line is %d bytes on; using %d' %
                         (addr, word, size, delta, delta))
                size = delta
        stats['insns'] += 1
        if size == 2:
            stats['short'] += 1
        emit(addr, struct.pack('<I', word)[:size])

    def data_word(addr, raw, nbytes):
        """A constant-pool or jump-table entry."""
        if keep_pools:
            emit(addr, raw[:nbytes])
        else:
            close_chunk()

    def end_listing():
        nonlocal in_code, pool_left, after_marker
        flush_pending(None)
        close_chunk()
        in_code = False
        pool_left = 0
        after_marker = False

    for line in fp:
        line = line.rstrip('\n')
        if in_code:
            m = LINE_RE.match(line)
            if m:
                addr = int(m.group(1), 16)
                rest = m.group(3)
                flush_pending(addr)
                pm = PTR_RE.match(rest)
                if pm:
                    stats['table_words'] += 2
                    data_word(addr, struct.pack('<Q', int(pm.group(1), 16)), 8)
                    continue
                if TABLE_RE.match(rest):
                    # Offsets table; the dump prints the target, not the
                    # word, so nothing can be kept in place for it.
                    stats['table_words'] += 1
                    close_chunk()
                    continue
                wm = WORD_RE.match(rest)
                if not wm:
                    end_listing()
                    continue
                word = int(wm.group(1), 16)
                text = wm.group(2)
                raw = struct.pack('<I', word)
                pool = POOL_RE.match(text)
                if pool:
                    pool_left = int(pool.group(1))
                    after_marker = True
                    stats['pool_words'] += 1
                    data_word(addr, raw, 4)
                    continue
                if pool_left > 0 and text.strip() == 'constant':
                    pool_left -= 1
                    stats['pool_words'] += 1
                    data_word(addr, raw, 4)
                    continue
                if after_marker and word == POOL_GUARD:
                    after_marker = False
                    stats['pool_words'] += 1
                    data_word(addr, raw, 4)
                    continue
                after_marker = False
                pool_left = 0
                pending = (addr, word, insn_size(word))
                continue
            if not line.strip() or line.lstrip().startswith(';;'):
                continue
            # Any other line shape (Safepoints, RelocInfo, "--- End code
            # ---", benchmark output, ...) ends the listing; fall through
            # so the RelocInfo header and "--- " are still seen.
            end_listing()
        if in_reloc:
            m = RELOC_RE.match(line)
            if m and obj is not None:
                stats['relocs'] += 1
                if relocs_out is not None:
                    relocs_out.write('%s 0x%x %s\n' % (
                        obj[0], int(m.group(1), 16) - obj[1], m.group(2)))
                continue
            in_reloc = False
        if line.startswith('--- '):
            # Header boundary: forget the previous object's identity so
            # an unnamed object does not inherit its predecessor's name.
            name = ''
            kind = ''
            obj = None
            continue
        if RELOC_HDR_RE.match(line):
            in_reloc = obj is not None
            continue
        m = HEADER_FIELD_RE.match(line)
        if m:
            if m.group(1) == 'name':
                name = m.group(2).strip()
            elif m.group(1) == 'kind':
                kind = m.group(2).strip()
            continue
        if INSTRUCTIONS_RE.match(line):
            in_code = True
            cur = None
            obj = None
            pool_left = 0
            after_marker = False
            continue
    end_listing()
    return chunks, stats


def pack_layout(chunks, base=0x10000, gap=16):
    """Give every chunk its own address range, in dump order, 16-aligned
    and separated by a gap so no two sections are ever adjacent."""
    addr = base
    for c in chunks:
        c.addr = addr
        addr += (len(c.data) + gap + 15) & ~15


# === Minimal ELF64 writer ===

SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHT_RISCV_ATTRIBUTES = 0x70000003
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
EM_RISCV = 243
EF_RISCV_RVC = 0x1
EF_RISCV_FLOAT_ABI_DOUBLE = 0x4


def align4(n):
    return (n + 3) & ~3


def riscv_attributes(arch):
    """A .riscv.attributes payload declaring Tag_RISCV_arch = arch, in
    the layout the psABI specifies and riscvlint's find_arch_string
    reads: 'A', then a vendor subsection (uint32 length, "riscv\\0"),
    then a Tag_File sub-subsection (byte 1, uint32 size, attributes)."""
    attrs = bytes([5]) + arch.encode() + b'\0'          # Tag_RISCV_arch
    sub = bytes([1]) + struct.pack('<I', 5 + len(attrs)) + attrs
    vendor = b'riscv\0'
    body = struct.pack('<I', 4 + len(vendor) + len(sub)) + vendor + sub
    return b'A' + body


def write_elf(chunks, path, arch=None):
    ehsize = 64
    shentsize = 64

    # Section data payload, 4-aligned back to back after the header.
    payload = bytearray()
    offsets = []
    for c in chunks:
        off = ehsize + len(payload)
        offsets.append(off)
        payload += c.data
        pad = align4(len(payload)) - len(payload)
        payload += b'\0' * pad
    attr = riscv_attributes(arch) if arch else b''
    attr_off = ehsize + len(payload)
    payload += attr
    payload += b'\0' * (align4(len(payload)) - len(payload))

    shstrtab = bytearray(b'\0')

    def shname(s):
        off = len(shstrtab)
        shstrtab.extend(s.encode() + b'\0')
        return off
    text_name = shname('.text')
    symtab_name = shname('.symtab')
    strtab_name = shname('.strtab')
    shstrtab_name = shname('.shstrtab')
    attr_name = shname('.riscv.attributes') if arch else 0

    strtab = bytearray(b'\0')
    symtab = bytearray(b'\0' * 24)          # index 0: null symbol
    for i, c in enumerate(chunks):
        st_name = len(strtab)
        strtab.extend(c.name.encode() + b'\0')
        st_info = (0 << 4) | 2              # STB_LOCAL, STT_FUNC
        # st_value is the section's address rather than the ET_REL
        # section offset: riscvlint's symbolize() compares it with the
        # finding's absolute address, which is what makes the
        # <TF_foo+0x..> and the JSON "function" attribution work.
        symtab += struct.pack('<IBBHQQ', st_name, st_info, 0,
                              1 + i, c.addr, len(c.data))

    nsections = 1 + len(chunks) + 3 + (1 if arch else 0)
    symtab_idx = 1 + len(chunks)
    strtab_idx = symtab_idx + 1
    shstrtab_idx = strtab_idx + 1

    symtab_off = ehsize + len(payload)
    strtab_off = symtab_off + len(symtab)
    shstrtab_off = strtab_off + len(strtab)
    shoff = align4(shstrtab_off + len(shstrtab))

    def shdr(name, type_, flags, addr, off, size, link, info, align, entsize):
        return struct.pack('<IIQQQQIIQQ', name, type_, flags, addr, off,
                           size, link, info, align, entsize)

    shdrs = [shdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)]
    for c, off in zip(chunks, offsets):
        shdrs.append(shdr(text_name, SHT_PROGBITS,
                          SHF_ALLOC | SHF_EXECINSTR, c.addr, off,
                          len(c.data), 0, 0, 2, 0))
    shdrs.append(shdr(symtab_name, SHT_SYMTAB, 0, 0, symtab_off,
                      len(symtab), strtab_idx, 1 + len(chunks), 8, 24))
    shdrs.append(shdr(strtab_name, SHT_STRTAB, 0, 0, strtab_off,
                      len(strtab), 0, 0, 1, 0))
    shdrs.append(shdr(shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_off,
                      len(shstrtab), 0, 0, 1, 0))
    if arch:
        shdrs.append(shdr(attr_name, SHT_RISCV_ATTRIBUTES, 0, 0, attr_off,
                          len(attr), 0, 0, 1, 0))

    ehdr = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                       b'\x7fELF', 2, 1, 1, 0, 0,   # 64-bit LSB SysV
                       1, EM_RISCV,                 # ET_REL
                       1, 0, 0, shoff,
                       EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_DOUBLE,
                       ehsize, 0, 0, shentsize, nsections, shstrtab_idx)

    with open(path, 'wb') as f:
        f.write(ehdr)
        f.write(payload)
        f.write(symtab)
        f.write(strtab)
        f.write(shstrtab)
        f.write(b'\0' * (shoff - shstrtab_off - len(shstrtab)))
        for s in shdrs:
            f.write(s)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dump', help='V8 code dump (- for stdin)')
    ap.add_argument('-o', '--output', default='v8code.elf')
    ap.add_argument('--max-sections', type=int, default=2000,
                    help='chunks per ELF before splitting the output. The '
                         'ELF limit is 65535; below it, the split only '
                         'sets how many riscvlint runs the dump divides '
                         'into, and so how many can run in parallel')
    ap.add_argument('--map',
                    help='also write "name 0xaddr size 0xjitaddr" lines here')
    ap.add_argument('--relocs',
                    help='also write "object 0xoffset mode" lines here, one '
                         'per RelocInfo entry of every code object')
    ap.add_argument('--layout', choices=['packed', 'jit'], default='packed',
                    help='section addresses: unique synthetic ones (packed, '
                         'the default; the JIT reuses addresses across a '
                         'run) or the JIT addresses from the dump')
    ap.add_argument('--arch',
                    help='declare this Tag_RISCV_arch string, which is what '
                         'riscvlint gates its extension checks on. Spell it '
                         'the way an assembler does, with version suffixes '
                         '(riscvlint matches "_c2p0", "_zba1p0", ...), e.g. '
                         'rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zba1p0_zbb1p0_'
                         'zbs1p0_zcb1p0_zfa1p0; "readelf -A" on any native '
                         'binary of the host that ran the JIT prints one')
    ap.add_argument('--keep-pools', action='store_true',
                    help='leave constant pools and jump tables inside the '
                         'sections instead of splitting around them')
    args = ap.parse_args()

    warnings = []

    def warn(msg):
        if len(warnings) < 10:
            warnings.append(msg)
        elif len(warnings) == 10:
            warnings.append('...')

    relocs_out = open(args.relocs, 'w') if args.relocs else None
    if args.dump == '-':
        chunks, stats = parse_dump(sys.stdin, args.keep_pools, warn, relocs_out)
    else:
        with open(args.dump, 'r', errors='replace') as fp:
            chunks, stats = parse_dump(fp, args.keep_pools, warn, relocs_out)
    if relocs_out:
        relocs_out.close()
    for w in warnings:
        print('v8dump2elf: %s' % w, file=sys.stderr)
    if not chunks:
        print('no code found in dump', file=sys.stderr)
        return 1

    if args.layout == 'packed':
        pack_layout(chunks)

    if args.map:
        with open(args.map, 'w') as f:
            for c in chunks:
                f.write('%s 0x%x %d 0x%x\n' % (c.name, c.addr, len(c.data),
                                               c.jit_addr))

    total = sum(len(c.data) for c in chunks)
    if len(chunks) <= args.max_sections:
        write_elf(chunks, args.output, args.arch)
        outs = [args.output]
    else:
        outs = []
        for i in range(0, len(chunks), args.max_sections):
            part = '%s.%d' % (args.output, len(outs) + 1)
            write_elf(chunks[i:i + args.max_sections], part, args.arch)
            outs.append(part)
    shown = ' '.join(outs) if len(outs) <= 3 else '%s ... %s (%d files)' % (
        outs[0], outs[-1], len(outs))
    print('%d chunks, %d code bytes, %d instructions (%d compressed), '
          '%d pool and %d table words %s, %d reloc entries -> %s' %
          (len(chunks), total, stats['insns'], stats['short'],
           stats['pool_words'], stats['table_words'],
           'kept' if args.keep_pools else 'split out', stats['relocs'],
           shown), file=sys.stderr)
    if stats['length_fixups']:
        print('%d instruction lengths taken from the following address '
              'rather than the encoding' % stats['length_fixups'],
              file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
