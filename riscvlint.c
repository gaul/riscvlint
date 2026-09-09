// riscvlint check library. See riscvlint.h for why the checks decode
// raw encodings instead of reading capstone's operand model.

#include "riscvlint.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ABI register names, so a finding reads the way the disassembly does
// without needing a capstone handle to render it.
static const char *const rv_reg_names[32] = {
    "zero", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
    "s0",   "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
    "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};

static const char *rv_reg_name(unsigned n)
{
    return n < 32 ? rv_reg_names[n] : "?";
}

// ---- raw encoding helpers ----

static int64_t sign_extend(uint64_t v, unsigned bits)
{
    const uint64_t m = (uint64_t)1 << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

// The three-bit register fields of the compressed formats name x8-x15.
static bool rvc_reg(unsigned r) { return r >= 8 && r <= 15; }

// Sign-extended 6-bit immediate of the CI-format compressed forms.
static int64_t ci_imm6(uint32_t w)
{
    return sign_extend((((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu), 6);
}

bool rv_decode_auipc(uint32_t w, unsigned *rd, int64_t *imm)
{
    if (RV_OPCODE(w) != RV_OP_AUIPC) return false;
    *rd = (w >> 7) & 0x1fu;
    // The 20 immediate bits are the *high* bits of the addend, so the
    // sign extension happens on the shifted value, not before it.
    *imm = sign_extend((uint64_t)(w & 0xfffff000u), 32);
    return true;
}

bool rv_decode_jalr(uint32_t w, unsigned *rd, unsigned *rs1, int64_t *imm)
{
    if (RV_OPCODE(w) != RV_OP_JALR) return false;
    if (((w >> 12) & 0x7u) != 0) return false;   // funct3 must be 0
    *rd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    *imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
    return true;
}

bool rv_jal_reaches(int64_t offset)
{
    // J-type carries imm[20:1]: 21 bits signed with bit 0 implicitly
    // zero, so the reachable set is the even offsets in [-2^20, 2^20-2].
    return offset >= -1048576 && offset <= 1048574 && (offset & 1) == 0;
}

unsigned rv_insn_len(uint32_t w)
{
    return (w & 3u) == 3u ? 4u : 2u;
}

bool rv_decode_slli(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    unsigned *shamt)
{
    if (size == 4) {
        // I-type shift, RV64: opcode OP-IMM, funct3 001, funct6 000000.
        if (RV_OPCODE(w) != 0x13u) return false;
        if (((w >> 12) & 0x7u) != 1u) return false;
        if (((w >> 26) & 0x3fu) != 0u) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *shamt = (w >> 20) & 0x3fu;
        return true;
    }
    if (size != 2) return false;
    // CI-format c.slli: op 10, funct3 000. rd is also rs1, and rd == x0
    // or shamt == 0 are hints rather than shifts.
    if ((w & 0xe003u) != 0x0002u) return false;
    unsigned r = (w >> 7) & 0x1fu;
    unsigned sh = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
    if (r == 0 || sh == 0) return false;
    *rd = *rs1 = r;
    *shamt = sh;
    return true;
}

bool rv_decode_add(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                   unsigned *rs2)
{
    if (size == 4) {
        // R-type: opcode OP, funct3 000, funct7 0000000.
        if (RV_OPCODE(w) != 0x33u) return false;
        if (((w >> 12) & 0x7u) != 0u) return false;
        if (((w >> 25) & 0x7fu) != 0u) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *rs2 = (w >> 20) & 0x1fu;
        return true;
    }
    if (size != 2) return false;
    // CR-format c.add: funct4 1001, op 10, with both registers non-zero.
    // The same funct4 spells c.jalr (rs2 == 0) and c.ebreak (both zero),
    // so neither register may be x0.
    if ((w & 0xf003u) != 0x9002u) return false;
    unsigned r = (w >> 7) & 0x1fu;
    unsigned s2 = (w >> 2) & 0x1fu;
    if (r == 0 || s2 == 0) return false;
    *rd = *rs1 = r;
    *rs2 = s2;
    return true;
}

bool rv_decode_addi(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    int64_t *imm)
{
    if (size == 4) {
        // I-type: opcode OP-IMM, funct3 000.
        if (RV_OPCODE(w) != 0x13u) return false;
        if (((w >> 12) & 0x7u) != 0u) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
        return true;
    }
    if (size != 2) return false;
    // CIW-format c.addi4spn: op 00, funct3 000. rs1 is sp implicitly and
    // rd' names x8-x15, so `addi s0,sp,K` fits it and `addi a5,sp,K` does
    // not. The immediate is a byte offset assembled out of four
    // non-adjacent fields, and zero is the reserved encoding rather than
    // an addi of nothing.
    if ((w & 0xe003u) != 0x0000u) return false;
    unsigned nz = (((w >> 11) & 0x3u) << 4) | (((w >> 7) & 0xfu) << 6) |
                  (((w >> 6) & 0x1u) << 2) | (((w >> 5) & 0x1u) << 3);
    if (nz == 0) return false;
    *rd = 8u + ((w >> 2) & 0x7u);
    *rs1 = 2u;
    *imm = (int64_t)nz;
    return true;
}

bool rv_decode_srli(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    unsigned *shamt)
{
    if (size == 4) {
        // I-type shift right logical: funct3 101, funct6 000000. funct6
        // 010000 is srai, which shifts in the sign and is a different
        // rewrite.
        if (RV_OPCODE(w) != 0x13u) return false;
        if (((w >> 12) & 0x7u) != 5u) return false;
        if (((w >> 26) & 0x3fu) != 0u) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *shamt = (w >> 20) & 0x3fu;
        return true;
    }
    if (size != 2) return false;
    // CB-format c.srli: funct3 100, op 01, bits [11:10] zero. c.srai sets
    // bit 10 and c.andi bit 11. The register field is three bits wide, so
    // only x8-x15 can be named.
    if ((w & 0xec03u) != 0x8001u) return false;
    unsigned r = 8u + ((w >> 7) & 0x7u);
    unsigned sh = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
    if (sh == 0) return false;
    *rd = *rs1 = r;
    *shamt = sh;
    return true;
}

bool rv_pure_def(uint32_t w, unsigned size, unsigned *rd)
{
    if (size == 4) {
        // Every instruction under these opcodes writes rd and does
        // nothing else: OP-IMM, OP-IMM-32, OP, OP-32, LUI, AUIPC. That
        // covers the M and Zb extensions too, which reuse OP and OP-32,
        // so the rule needs no list of mnemonics to stay complete.
        switch (RV_OPCODE(w)) {
        case 0x13u: case 0x1bu: case 0x33u: case 0x3bu:
        case 0x37u: case 0x17u:
            *rd = (w >> 7) & 0x1fu;
            return *rd != 0;
        default:
            return false;
        }
    }
    if (size != 2) return false;
    unsigned quad = w & 3u;
    unsigned f3 = (w >> 13) & 7u;
    unsigned r = (w >> 7) & 0x1fu;
    unsigned rp = 8u + ((w >> 7) & 7u);
    if (quad == 0u) {
        // c.addi4spn is the only register-writing ALU op in this
        // quadrant; the rest are loads and stores.
        if (f3 == 0u && ((w >> 5) & 0xffu) != 0u) {
            *rd = 8u + ((w >> 2) & 7u);
            return true;
        }
        return false;
    }
    if (quad == 1u) {
        switch (f3) {
        case 0u:                       // c.addi / c.nop
        case 1u:                       // c.addiw
        case 2u:                       // c.li
        case 3u:                       // c.lui, or c.addi16sp when rd==2
            if (r == 0u) return false;
            *rd = r;
            return true;
        case 4u:                       // misc-ALU on the popular set
            *rd = rp;
            return true;
        default:
            return false;              // c.j, c.beqz, c.bnez
        }
    }
    // quad == 2
    if (f3 == 0u) {                    // c.slli
        if (r == 0u) return false;
        *rd = r;
        return true;
    }
    if (f3 == 4u) {
        // c.mv and c.add write rd; c.jr, c.jalr and c.ebreak share the
        // funct4 and are separated by a zero rs2.
        unsigned rs2 = (w >> 2) & 0x1fu;
        if (r == 0u || rs2 == 0u) return false;
        *rd = r;
        return true;
    }
    return false;                      // c.lwsp/c.ldsp, c.swsp/c.sdsp
}

unsigned riscvlint_parse_arch(const char *arch)
{
    if (!arch) return 0;
    unsigned exts = RISCVLINT_EXT_DECLARED;
    // Extensions are underscore-separated and carry a version suffix, so
    // match on the separator plus name to avoid "zba" inside a longer
    // token. The leading base ("rv64i2p1") never spells a Zb extension.
    if (strstr(arch, "_zba")) exts |= RISCVLINT_EXT_ZBA;
    if (strstr(arch, "_zbb")) exts |= RISCVLINT_EXT_ZBB;
    if (strstr(arch, "_zbs")) exts |= RISCVLINT_EXT_ZBS;
    if (strstr(arch, "_zcb")) exts |= RISCVLINT_EXT_ZCB;
    return exts;
}

// ---- state ----

// ---- memory accesses ----

static const struct {
    rv_mem_kind kind;
    const char *name;
    bool store, fp;
    unsigned width;          // access bytes, for the compressed offset scale
} rv_mem_table[] = {
    { RV_MEM_LB,  "lb",  false, false, 1 },
    { RV_MEM_LH,  "lh",  false, false, 2 },
    { RV_MEM_LW,  "lw",  false, false, 4 },
    { RV_MEM_LD,  "ld",  false, false, 8 },
    { RV_MEM_LBU, "lbu", false, false, 1 },
    { RV_MEM_LHU, "lhu", false, false, 2 },
    { RV_MEM_LWU, "lwu", false, false, 4 },
    { RV_MEM_SB,  "sb",  true,  false, 1 },
    { RV_MEM_SH,  "sh",  true,  false, 2 },
    { RV_MEM_SW,  "sw",  true,  false, 4 },
    { RV_MEM_SD,  "sd",  true,  false, 8 },
    { RV_MEM_FLW, "flw", false, true,  4 },
    { RV_MEM_FLD, "fld", false, true,  8 },
    { RV_MEM_FSW, "fsw", true,  true,  4 },
    { RV_MEM_FSD, "fsd", true,  true,  8 },
};

static const char *fp_reg_names[32] = {
    "ft0", "ft1", "ft2",  "ft3",  "ft4", "ft5", "ft6",  "ft7",
    "fs0", "fs1", "fa0",  "fa1",  "fa2", "fa3", "fa4",  "fa5",
    "fa6", "fa7", "fs2",  "fs3",  "fs4", "fs5", "fs6",  "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
};

static int mem_index(rv_mem_kind k)
{
    for (size_t i = 0; i < sizeof rv_mem_table / sizeof rv_mem_table[0]; i++)
        if (rv_mem_table[i].kind == k) return (int)i;
    return -1;
}

bool rv_mem_is_store(rv_mem_kind k)
{
    int i = mem_index(k);
    return i >= 0 && rv_mem_table[i].store;
}

bool rv_mem_is_fp(rv_mem_kind k)
{
    int i = mem_index(k);
    return i >= 0 && rv_mem_table[i].fp;
}

const char *rv_mem_name(rv_mem_kind k)
{
    int i = mem_index(k);
    return i >= 0 ? rv_mem_table[i].name : "?";
}

bool rv_decode_mem(uint32_t w, unsigned size, rv_mem_kind *kind,
                   unsigned *data, unsigned *base, int64_t *off)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
        unsigned rd = (w >> 7) & 0x1fu, rs1 = (w >> 15) & 0x1fu;
        unsigned rs2 = (w >> 20) & 0x1fu, f7 = (w >> 25) & 0x7fu;
        static const rv_mem_kind load3[8] = {
            RV_MEM_LB, RV_MEM_LH, RV_MEM_LW, RV_MEM_LD,
            RV_MEM_LBU, RV_MEM_LHU, RV_MEM_LWU, RV_MEM_NONE };
        static const rv_mem_kind store3[8] = {
            RV_MEM_SB, RV_MEM_SH, RV_MEM_SW, RV_MEM_SD,
            RV_MEM_NONE, RV_MEM_NONE, RV_MEM_NONE, RV_MEM_NONE };
        switch (op) {
        case 0x03u:                                   // LOAD
            if (load3[f3] == RV_MEM_NONE) return false;
            *kind = load3[f3]; *data = rd; *base = rs1;
            *off = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
            return true;
        case 0x07u:                                   // LOAD-FP
            if (f3 != 2 && f3 != 3) return false;      // flw, fld only
            *kind = f3 == 2 ? RV_MEM_FLW : RV_MEM_FLD;
            *data = rd; *base = rs1;
            *off = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
            return true;
        case 0x23u:                                   // STORE
            if (store3[f3] == RV_MEM_NONE) return false;
            *kind = store3[f3]; *data = rs2; *base = rs1;
            *off = sign_extend(((uint64_t)f7 << 5) | rd, 12);
            return true;
        case 0x27u:                                   // STORE-FP
            if (f3 != 2 && f3 != 3) return false;
            *kind = f3 == 2 ? RV_MEM_FSW : RV_MEM_FSD;
            *data = rs2; *base = rs1;
            *off = sign_extend(((uint64_t)f7 << 5) | rd, 12);
            return true;
        default:
            return false;
        }
    }
    if (size != 2) return false;
    unsigned f3 = (w >> 13) & 0x7u;
    if ((w & 0x3u) == 2u) {
        // Quadrant 2: the base is sp and the register field is the full
        // five bits. These are the frame accesses, so the window that
        // looks for a slot stored twice cannot do without them.
        unsigned r = (w >> 7) & 0x1fu, rs2 = (w >> 2) & 0x1fu;
        unsigned b12 = (w >> 12) & 1u;
        *base = 2;
        switch (f3) {
        case 1:  // c.fldsp: uimm[5]=12, uimm[4:3]=6:5, uimm[8:6]=4:2
            *kind = RV_MEM_FLD; *data = r;
            *off = (b12 << 5) | (((w >> 5) & 0x3u) << 3) |
                   (((w >> 2) & 0x7u) << 6);
            return true;
        case 2:  // c.lwsp: uimm[5]=12, uimm[4:2]=6:4, uimm[7:6]=3:2
            if (r == 0) return false;
            *kind = RV_MEM_LW; *data = r;
            *off = (b12 << 5) | (((w >> 4) & 0x7u) << 2) |
                   (((w >> 2) & 0x3u) << 6);
            return true;
        case 3:  // c.ldsp: uimm[5]=12, uimm[4:3]=6:5, uimm[8:6]=4:2
            if (r == 0) return false;
            *kind = RV_MEM_LD; *data = r;
            *off = (b12 << 5) | (((w >> 5) & 0x3u) << 3) |
                   (((w >> 2) & 0x7u) << 6);
            return true;
        case 5:  // c.fsdsp: uimm[5:3]=12:10, uimm[8:6]=9:7
            *kind = RV_MEM_FSD; *data = rs2;
            *off = (((w >> 10) & 0x7u) << 3) | (((w >> 7) & 0x7u) << 6);
            return true;
        case 6:  // c.swsp: uimm[5:2]=12:9, uimm[7:6]=8:7
            *kind = RV_MEM_SW; *data = rs2;
            *off = (((w >> 9) & 0xfu) << 2) | (((w >> 7) & 0x3u) << 6);
            return true;
        case 7:  // c.sdsp: uimm[5:3]=12:10, uimm[8:6]=9:7
            *kind = RV_MEM_SD; *data = rs2;
            *off = (((w >> 10) & 0x7u) << 3) | (((w >> 7) & 0x7u) << 6);
            return true;
        default:
            return false;
        }
    }
    // Quadrant 0: every form here names both registers with a three-bit
    // field, so x8-x15, and carries a scaled unsigned offset.
    if ((w & 0x3u) != 0) return false;
    unsigned rd_ = 8u + ((w >> 2) & 0x7u), rs1_ = 8u + ((w >> 7) & 0x7u);
    // The word and doubleword forms share two immediate layouts.
    unsigned off_w = (((w >> 10) & 0x7u) << 3) | (((w >> 6) & 1u) << 2) |
                     (((w >> 5) & 1u) << 6);
    unsigned off_d = (((w >> 10) & 0x7u) << 3) | (((w >> 5) & 0x3u) << 6);
    *base = rs1_;
    *data = rd_;
    switch (f3) {
    case 1: *kind = RV_MEM_FLD; *off = off_d; return true;   // c.fld
    case 2: *kind = RV_MEM_LW;  *off = off_w; return true;   // c.lw
    case 3: *kind = RV_MEM_LD;  *off = off_d; return true;   // c.ld
    case 5: *kind = RV_MEM_FSD; *off = off_d; return true;   // c.fsd
    case 6: *kind = RV_MEM_SW;  *off = off_w; return true;   // c.sw
    case 7: *kind = RV_MEM_SD;  *off = off_d; return true;   // c.sd
    case 4: {                                                // Zcb
        // uimm[0] is bit 6 and uimm[1] is bit 5 for the byte forms; the
        // halfword forms carry only uimm[1], with bit 6 selecting the
        // signed load.
        unsigned sel = (w >> 10) & 0x7u;
        unsigned b6 = (w >> 6) & 1u, b5 = (w >> 5) & 1u;
        switch (sel) {
        case 0: *kind = RV_MEM_LBU; *off = (b5 << 1) | b6; return true;
        case 1: *kind = b6 ? RV_MEM_LH : RV_MEM_LHU; *off = b5 << 1;
                return true;
        case 2: *kind = RV_MEM_SB;  *off = (b5 << 1) | b6; return true;
        case 3: *kind = RV_MEM_SH;  *off = b5 << 1; return true;
        default: return false;
        }
    }
    default:
        return false;
    }
}

unsigned rv_mem_encoded_size(rv_mem_kind kind, unsigned data, unsigned base,
                             int64_t off, bool zcb)
{
    int i = mem_index(kind);
    if (i < 0) return 4;
    unsigned width = rv_mem_table[i].width;
    bool fp = rv_mem_table[i].fp;

    // Quadrant 2: base is sp, the register may be any of the 32, and the
    // offset is scaled by the access width. Only the word and wider
    // forms have one.
    if (base == 2 && (width == 4 || width == 8) &&
        kind != RV_MEM_LWU && !(fp && width == 4)) {
        int64_t limit = width == 8 ? 504 : 252;
        // c.lwsp and c.ldsp cannot name x0 as the destination, since
        // that encoding is reserved. The float file has no such hole, so
        // `c.fldsp ft0` is a legal two bytes.
        bool load_ok = rv_mem_table[i].store || fp || data != 0;
        if (off >= 0 && off <= limit && off % width == 0 && load_ok) return 2;
    }
    // Quadrant 0: both registers in x8-x15.
    if (!rvc_reg(base)) return 4;
    if (!rvc_reg(data)) return 4;
    switch (kind) {
    case RV_MEM_LW: case RV_MEM_SW:
        return (off >= 0 && off <= 124 && off % 4 == 0) ? 2 : 4;
    case RV_MEM_LD: case RV_MEM_SD:
    case RV_MEM_FLD: case RV_MEM_FSD:
        return (off >= 0 && off <= 248 && off % 8 == 0) ? 2 : 4;
    case RV_MEM_LBU: case RV_MEM_SB:
        return (zcb && off >= 0 && off <= 3) ? 2 : 4;
    case RV_MEM_LHU: case RV_MEM_LH: case RV_MEM_SH:
        return (zcb && (off == 0 || off == 2)) ? 2 : 4;
    default:
        // lb, lwu, flw and fsw have no compressed spelling on RV64.
        return 4;
    }
}

bool rv_decode_base_add(uint32_t w, unsigned size, unsigned *rd,
                        unsigned *rs1, int64_t *imm)
{
    if (rv_decode_addi(w, size, rd, rs1, imm)) return true;
    if (size != 2) return false;
    // c.addi: rd is also rs1, so `addi a5,a5,8` -- adjusting a base in
    // place is as much an address computation as forming a new one.
    if ((w & 0xe003u) == 0x0001u) {
        unsigned r = (w >> 7) & 0x1fu;
        int64_t v = ci_imm6(w);
        if (r == 0 || v == 0) return false;            // c.nop and hints
        *rd = *rs1 = r;
        *imm = v;
        return true;
    }
    // c.mv: `add rd,x0,rs2`, which is an addition of zero. c.add sits in
    // the same funct3 and is separated by bit 12.
    if ((w & 0xf003u) == 0x8002u) {
        unsigned r = (w >> 7) & 0x1fu, s = (w >> 2) & 0x1fu;
        if (r == 0 || s == 0) return false;            // c.jr, hints
        *rd = r;
        *rs1 = s;
        *imm = 0;
        return true;
    }
    return false;
}

// ---- Zcb encodability ----

const char *rv_zcb_form(uint32_t w, unsigned size)
{
    if (size != 4) return NULL;
    unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
    unsigned rd = (w >> 7) & 0x1fu, rs1 = (w >> 15) & 0x1fu;
    unsigned rs2 = (w >> 20) & 0x1fu, f7 = (w >> 25) & 0x7fu;
    unsigned field = (w >> 20) & 0xfffu;

    switch (op) {
    case 0x03u: {                                     // LOAD
        int64_t off = sign_extend(field, 12);
        if (!rvc_reg(rd) || !rvc_reg(rs1)) return NULL;
        // c.lbu's offset field is two bits and unsigned; c.lhu and c.lh
        // share a one-bit field that names the halfword, so 0 or 2.
        if (f3 == 4 && off >= 0 && off <= 3) return "c.lbu";
        if (f3 == 5 && (off == 0 || off == 2)) return "c.lhu";
        if (f3 == 1 && (off == 0 || off == 2)) return "c.lh";
        return NULL;
    }
    case 0x23u: {                                     // STORE
        // S-type splits the immediate across two fields.
        int64_t off = sign_extend(((uint64_t)f7 << 5) | rd, 12);
        if (!rvc_reg(rs2) || !rvc_reg(rs1)) return NULL;
        if (f3 == 0 && off >= 0 && off <= 3) return "c.sb";
        if (f3 == 1 && (off == 0 || off == 2)) return "c.sh";
        return NULL;
    }
    case 0x13u:                                       // OP-IMM
        // The unary forms all write the register they read.
        if (rd != rs1 || !rvc_reg(rd)) return NULL;
        if (f3 == 7 && field == 255) return "c.zext.b";
        if (f3 == 4 && field == 0xfffu) return "c.not";   // xori rd,rd,-1
        if (f3 == 1 && field == 0x604u) return "c.sext.b";
        if (f3 == 1 && field == 0x605u) return "c.sext.h";
        return NULL;
    case 0x3bu:                                       // OP-32
        if (f7 != 0x04u || rs2 != 0) return NULL;
        if (rd != rs1 || !rvc_reg(rd)) return NULL;
        if (f3 == 0) return "c.zext.w";               // add.uw rd,rd,x0
        if (f3 == 4) return "c.zext.h";
        return NULL;
    case 0x33u:                                       // OP
        if (f7 != 0x01u || f3 != 0) return NULL;      // mul only
        if (!rvc_reg(rd)) return NULL;
        // c.mul is `rd = rd * rs2'`. Multiplication commutes, so the
        // operands can be swapped to fit -- clang does, GNU as does not,
        // and the site is compressible either way.
        if (rd == rs1 && rvc_reg(rs2)) return "c.mul";
        if (rd == rs2 && rvc_reg(rs1)) return "c.mul";
        return NULL;
    default:
        return NULL;
    }
}

// ---- what a result guarantees about its own high bits ----

#define G_S8  RISCVLINT_G_SEXT8
#define G_S16 RISCVLINT_G_SEXT16
#define G_S32 RISCVLINT_G_SEXT32
#define G_Z8  RISCVLINT_G_ZEXT8
#define G_Z16 RISCVLINT_G_ZEXT16
#define G_Z32 RISCVLINT_G_ZEXT32

// The closures, spelled out once. A value that fits 8 bits fits 16 and
// 32; a value that is zero above bit 15 is also sign-extended from bit
// 31, since its bit 31 is zero. The one relation that does not hold is
// zero-extension to 32 implying sign-extension to 32.
#define G_LB   (G_S8 | G_S16 | G_S32)
#define G_LH   (G_S16 | G_S32)
#define G_LW   (G_S32)
#define G_LBU  (G_Z8 | G_Z16 | G_Z32 | G_S32)
#define G_LHU  (G_Z16 | G_Z32 | G_S32)
#define G_LWU  (G_Z32)

// Guarantees implied by a value known to lie in [lo, hi]. Used for the
// constant materializations and for `andi`, whose mask bounds its
// result; writing it as a range keeps the closure implicit instead of
// repeating it per case.
static unsigned guarantees_for_range(int64_t lo, int64_t hi)
{
    unsigned g = 0;
    if (lo >= -128 && hi <= 127) g |= G_S8;
    if (lo >= -32768 && hi <= 32767) g |= G_S16;
    if (lo >= INT32_MIN && hi <= INT32_MAX) g |= G_S32;
    if (lo >= 0 && hi <= 255) g |= G_Z8;
    if (lo >= 0 && hi <= 65535) g |= G_Z16;
    if (lo >= 0 && hi <= 4294967295LL) g |= G_Z32;
    return g;
}

unsigned rv_result_guarantees(uint32_t w, unsigned size, unsigned *rd)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
        unsigned f7 = (w >> 25) & 0x7fu, rs2 = (w >> 20) & 0x1fu;
        int64_t imm12 = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
        *rd = (w >> 7) & 0x1fu;
        switch (op) {
        case 0x03u:                                   // LOAD
            switch (f3) {
            case 0: return G_LB;
            case 1: return G_LH;
            case 2: return G_LW;
            case 4: return G_LBU;
            case 5: return G_LHU;
            case 6: return G_LWU;
            default: return 0;                        // ld: all 64 bits
            }
        case 0x13u:                                   // OP-IMM
            if (f3 == 0 && ((w >> 15) & 0x1fu) == 0)  // li
                return guarantees_for_range(imm12, imm12);
            if (f3 == 7 && imm12 >= 0)                // andi with a mask
                return guarantees_for_range(0, imm12);
            if (f3 == 1 && ((w >> 20) & 0xfffu) == 0x604u) return G_LB;
            if (f3 == 1 && ((w >> 20) & 0xfffu) == 0x605u) return G_LH;
            return 0;
        case 0x1bu:                                   // OP-IMM-32
            return G_S32;                             // addiw/slliw/sr*iw
        case 0x37u:                                   // lui
            return guarantees_for_range(sign_extend(w & 0xfffff000u, 32),
                                        sign_extend(w & 0xfffff000u, 32));
        case 0x3bu:                                   // OP-32
            if (f7 == 0x04u) {                        // Zba/Zbb .uw forms
                if (f3 == 0 && rs2 == 0) return G_LWU;   // zext.w
                if (f3 == 4 && rs2 == 0) return G_LHU;   // zext.h
                return 0;                                // add.uw: 64-bit
            }
            return G_S32;                             // addw/subw/mulw/...
        default:
            return 0;
        }
    }
    if (size != 2) return 0;
    unsigned cop = w & 0x3u, f3 = (w >> 13) & 0x7u;
    switch (cop) {
    case 0:                                           // C0
        *rd = 8u + ((w >> 2) & 0x7u);
        if (f3 == 2) return G_LW;                     // c.lw
        if (f3 == 4) {                                // Zcb loads
            unsigned sel = (w >> 10) & 0x7u;
            if (sel == 0) return G_LBU;               // c.lbu
            if (sel == 1) return ((w >> 6) & 1u) ? G_LH : G_LHU;
        }
        return 0;                                     // c.ld, the stores
    case 1:                                           // C1
        *rd = (w >> 7) & 0x1fu;
        if (f3 == 1) return G_S32;                    // c.addiw
        if (f3 == 2) {                                // c.li
            int64_t v = ci_imm6(w);
            return guarantees_for_range(v, v);
        }
        if (f3 == 3 && *rd != 0 && *rd != 2) {        // c.lui (not addi16sp)
            int64_t v = ci_imm6(w) << 12;
            return guarantees_for_range(v, v);
        }
        if (f3 == 4) {
            unsigned sel = (w >> 10) & 0x3u;
            *rd = 8u + ((w >> 7) & 0x7u);
            if (sel == 2) {                           // c.andi
                int64_t m = ci_imm6(w);
                return m >= 0 ? guarantees_for_range(0, m) : 0;
            }
            // c.addw / c.subw share funct6 100111 with the 64-bit forms
            // and are separated by bit 12.
            if (sel == 3 && ((w >> 12) & 1u) && ((w >> 5) & 0x3u) < 2)
                return G_S32;
            // Zcb's unary group sits in the two funct2 slots C left
            // reserved. These are the compressed spellings of the
            // extensions themselves, and the assembler picks them
            // whenever the register is in x8-x15 -- so this is where
            // most of the corpus's extension instructions actually are.
            if (sel == 3 && ((w >> 12) & 1u) && ((w >> 5) & 0x3u) == 3) {
                switch ((w >> 2) & 0x7u) {
                case 0: return G_LBU;                 // c.zext.b
                case 1: return G_LB;                  // c.sext.b
                case 2: return G_LHU;                 // c.zext.h
                case 3: return G_LH;                  // c.sext.h
                case 4: return G_LWU;                 // c.zext.w
                default: return 0;                    // c.not, reserved
                }
            }
        }
        return 0;
    case 2:                                           // C2
        *rd = (w >> 7) & 0x1fu;
        if (f3 == 2) return G_LW;                     // c.lwsp
        return 0;
    default:
        return 0;
    }
}

bool rv_decode_extension(uint32_t w, unsigned size, unsigned *rd,
                         unsigned *rs1, unsigned *guarantee)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
        unsigned f7 = (w >> 25) & 0x7fu, rs2 = (w >> 20) & 0x1fu;
        unsigned field = (w >> 20) & 0xfffu;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        if (op == 0x1bu && f3 == 0 && field == 0) {   // sext.w = addiw rd,rs,0
            *guarantee = G_S32;
            return true;
        }
        if (op == 0x13u && f3 == 7 && field == 255) { // zext.b = andi rd,rs,255
            *guarantee = G_Z8;
            return true;
        }
        if (op == 0x13u && f3 == 1 && field == 0x604u) {
            *guarantee = G_S8;
            return true;
        }
        if (op == 0x13u && f3 == 1 && field == 0x605u) {
            *guarantee = G_S16;
            return true;
        }
        if (op == 0x3bu && f7 == 0x04u && rs2 == 0) { // zext.w / zext.h
            if (f3 == 0) { *guarantee = G_Z32; return true; }
            if (f3 == 4) { *guarantee = G_Z16; return true; }
        }
        return false;
    }
    if (size != 2) return false;
    // c.addiw rd,0 is `sext.w rd,rd`, and it is how the corpus spells
    // most of them: two bytes, so deleting one saves two rather than
    // four. c.addiw cannot name x0, which the shape needs anyway.
    if ((w & 0xe003u) == 0x2001u && ci_imm6(w) == 0) {
        *rd = *rs1 = (w >> 7) & 0x1fu;
        *guarantee = G_S32;
        return *rd != 0;
    }
    // Zcb's unary group: c.zext.b and its family, two bytes, rd' both
    // source and destination. Capstone prints them with the wide
    // mnemonic, so `andi a2,a2,0xff` in a disassembly is as often this
    // as it is the four-byte andi.
    if ((w & 0xe003u) == 0x8001u && ((w >> 10) & 0x3u) == 3 &&
        ((w >> 12) & 1u) && ((w >> 5) & 0x3u) == 3) {
        *rd = *rs1 = 8u + ((w >> 7) & 0x7u);
        switch ((w >> 2) & 0x7u) {
        case 0: *guarantee = G_Z8; return true;
        case 1: *guarantee = G_S8; return true;
        case 2: *guarantee = G_Z16; return true;
        case 3: *guarantee = G_S16; return true;
        case 4: *guarantee = G_Z32; return true;
        default: return false;                        // c.not, reserved
        }
    }
    return false;
}

bool rv_ends_region(uint32_t w, unsigned size)
{
    if (size == 4)
        return RV_OPCODE(w) == RV_OP_JAL || RV_OPCODE(w) == RV_OP_JALR;
    if (size != 2) return false;
    if ((w & 0xe003u) == 0xa001u) return true;        // c.j
    // c.jr / c.jalr: op 10, funct3 100, rs2 == 0, rd != 0. `ret` is
    // c.jr ra.
    if ((w & 0xe003u) == 0x8002u && ((w >> 2) & 0x1fu) == 0 &&
        ((w >> 7) & 0x1fu) != 0)
        return true;
    return false;
}

// ---- the windowed memory and constant table ----

// A location the region has touched. One record serves two questions
// that have different lifetimes, so each carries its own flag: `held`
// says the value at (base, disp) is still in `data`, which is what makes
// a second load redundant; `unread` says a store put it there and
// nothing has read it since, which is what makes that store dead.
#define RVL_SLOTS 24
typedef struct {
    bool held;
    bool unread;
    unsigned base;
    int64_t disp;
    unsigned width;
    rv_mem_kind kind;    // lb and lbu are the same width and not the same
                         // value, so a reload of one after the other is
                         // not redundant
    unsigned data;
    uint64_t addr;
    unsigned size;       // encoded bytes of the access that made the record
} rvl_slot;

struct riscvlint_state {
    const uint8_t *code;
    size_t size;
    uint64_t vaddr;
    uint8_t *targets;   // one bit per 2-byte unit
    uint8_t *relocs;    // one bit per 2-byte unit
    unsigned exts;      // extensions declared by Tag_RISCV_arch
    csh handle;         // for the liveness walk, which must disassemble
                        // ahead of the caller's own cursor
    cs_insn *probe;

    // The prologue check_redundant_sp_restore is waiting to match, and
    // whether anything has moved sp since. Every other check reads only
    // the instruction under the cursor and what follows it; this one
    // needs what came before, so it carries it rather than searching
    // backward through a variable-length encoding.
    struct {
        bool armed;      // an `addi s0,sp,K` has been seen
        int64_t k;       // its K
        uint64_t setup;  // its address, for the finding text
        bool sp_moved;   // something has written sp since
    } fp;

    // What each register's current value is known to guarantee about its
    // own high bits, for check_redundant_extension. Cleared at every
    // region boundary, so a guarantee is only read on the straight-line
    // path that established it.
    unsigned guarantees[32];

    // The windowed memory and constant table. See
    // riscvlint_state_observe.
    struct {
        rvl_slot slots[RVL_SLOTS];
        int nslots;
        bool const_live[32];
        int64_t const_val[32];
        uint64_t const_addr[32];
    } win;
};

riscvlint_state *riscvlint_state_create(void)
{
    return calloc(1, sizeof(riscvlint_state));
}

void riscvlint_state_destroy(riscvlint_state *state)
{
    if (!state) return;
    if (state->probe) cs_free(state->probe, 1);
    free(state->targets);
    free(state->relocs);
    free(state);
}

static bool bit_test(const uint8_t *bits, size_t unit)
{
    return bits && (bits[unit / 8] >> (unit % 8) & 1);
}

static void bit_set(uint8_t *bits, size_t unit)
{
    if (bits) bits[unit / 8] |= (uint8_t)(1u << (unit % 8));
}

static bool has_group(const cs_insn *insn, unsigned g)
{
    for (int i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == g) return true;
    return false;
}

bool riscvlint_state_set_section(riscvlint_state *state, csh handle,
                                 const uint8_t *code, size_t size,
                                 uint64_t vaddr)
{
    free(state->targets);
    free(state->relocs);
    state->targets = NULL;
    state->relocs = NULL;
    state->code = code;
    state->size = size;
    state->vaddr = vaddr;
    state->handle = handle;
    memset(&state->fp, 0, sizeof state->fp);
    memset(state->guarantees, 0, sizeof state->guarantees);
    memset(&state->win, 0, sizeof state->win);
    if (!state->probe) state->probe = cs_malloc(handle);
    if (!state->probe) return false;

    size_t nbytes = size / 2 / 8 + 1;
    state->targets = calloc(nbytes, 1);
    state->relocs = calloc(nbytes, 1);
    if (!state->targets || !state->relocs) return false;

    // Side-entry map. Capstone is fine for this: it only has to spot
    // relative transfers and hand back the absolute target, which it
    // does correctly even for the forms whose register access it
    // mis-models.
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return false;
    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;
    while (remain >= 2) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            p += 2; remain -= 2; addr += 2;
            continue;
        }
        // BRANCH_RELATIVE only. An indirect `jalr rd,<off>(rs)` is in
        // the JUMP group and carries an immediate too, but that
        // immediate is an offset from a register, not an address --
        // recording it marks an unrelated instruction as a side entry
        // and suppresses findings there.
        if (!has_group(insn, RISCV_GRP_BRANCH_RELATIVE))
            continue;
        const cs_riscv *a = &insn->detail->riscv;
        for (int i = 0; i < a->op_count; i++) {
            if (a->operands[i].type != RISCV_OP_IMM) continue;
            int64_t t = a->operands[i].imm - (int64_t)vaddr;
            if (t >= 0 && (uint64_t)t < size)
                bit_set(state->targets, (size_t)t / 2);
        }
    }
    cs_free(insn, 1);
    return true;
}

void riscvlint_state_set_relocs(riscvlint_state *state,
                                const uint64_t *offsets, size_t count)
{
    if (!state->relocs) return;
    for (size_t i = 0; i < count; i++)
        if (offsets[i] < state->size)
            bit_set(state->relocs, (size_t)offsets[i] / 2);
}

void riscvlint_state_set_extensions(riscvlint_state *state, unsigned exts)
{
    state->exts = exts;
}

unsigned riscvlint_state_extensions(const riscvlint_state *state)
{
    return state->exts;
}

bool riscvlint_is_branch_target(const riscvlint_state *state, uint64_t addr)
{
    if (addr < state->vaddr || addr >= state->vaddr + state->size)
        return false;
    return bit_test(state->targets, (size_t)(addr - state->vaddr) / 2);
}

bool riscvlint_is_relocated(const riscvlint_state *state, uint64_t addr)
{
    if (addr < state->vaddr || addr + 4 > state->vaddr + state->size)
        return false;
    size_t off = (size_t)(addr - state->vaddr);
    // A relocation is recorded at its own offset; a 4-byte instruction
    // covers two halfword units.
    return bit_test(state->relocs, off / 2) ||
           bit_test(state->relocs, off / 2 + 1);
}

bool riscvlint_word_at(const riscvlint_state *state, uint64_t addr,
                       uint32_t *out)
{
    if (addr < state->vaddr || addr + 4 > state->vaddr + state->size)
        return false;
    memcpy(out, state->code + (addr - state->vaddr), 4);
    return true;
}

// ---- checks ----

bool check_call_pair_to_jal(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    if (insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1;
    int64_t hi;
    if (!rv_decode_auipc(w1, &rd1, &hi)) return false;
    // auipc into x0 computes nothing; not a call sequence.
    if (rd1 == 0) return false;

    uint64_t second = insn->address + 4;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned rd2, rs1;
    int64_t lo;
    // Only the 4-byte jalr. `auipc rd,X` + `c.jalr rd` (a zero offset,
    // two bytes) is the same fold saving two bytes instead of four, but
    // it is a different encoding and gets its own check rather than
    // being smuggled into this one's arithmetic.
    if (!rv_decode_jalr(w2, &rd2, &rs1, &lo)) return false;

    // The jalr must consume the auipc, and must rewrite the same
    // register: `jal rd,target` writes the link register too, so the
    // rewrite is exact only when the pair's destination is that same
    // register. `jalr x0,...` (a tail call) would stop writing rd, which
    // needs a liveness proof this check does not have.
    if (rs1 != rd1 || rd2 != rd1) return false;

    // Something branching into the middle of the pair would land on the
    // jalr, which the rewrite deletes.
    if (riscvlint_is_branch_target(state, second)) return false;

    // In an unlinked object both immediates are placeholders waiting on
    // R_RISCV_CALL_PLT, so the target computed from them is fiction.
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // jalr clears bit 0 of the computed address.
    int64_t target = ((int64_t)insn->address + hi + lo) & ~(int64_t)1;
    // A backward displacement can only underflow past zero in an object
    // whose sections still sit at address 0. There is no such address to
    // call, so the site is an artefact rather than a finding.
    if (target < 0) return false;
    if (!rv_jal_reaches(target - (int64_t)insn->address)) return false;

    finding->title = "call pair foldable to jal";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "jal %s, 0x%" PRIx64, rv_reg_name(rd1), (uint64_t)target);
    return true;
}

bool riscvlint_parse_ext_name(const char *name, unsigned *exts)
{
    static const struct { const char *name; unsigned exts; } table[] = {
        { "zba",   RISCVLINT_EXT_ZBA },
        { "zbb",   RISCVLINT_EXT_ZBB },
        { "zbs",   RISCVLINT_EXT_ZBS },
        { "zcb",   RISCVLINT_EXT_ZCB },
        { "rva20", 0 },
        { "rva22", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS },
        // Zcb missed RVA22's ratification window and is mandatory in
        // RVA23U64, so this is where the two profiles part.
        { "rva23", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                   RISCVLINT_EXT_ZCB },
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
        if (strcmp(name, table[i].name) == 0) {
            *exts = table[i].exts;
            return true;
        }
    }
    return false;
}

bool riscvlint_may_use(const riscvlint_state *state, unsigned ext)
{
    unsigned e = riscvlint_state_extensions(state);
    if (!(e & RISCVLINT_EXT_DECLARED)) return true;   // nothing said
    return (e & ext) != 0;
}

bool check_slli_add_to_shadd(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBA)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1, rs1, shamt;
    if (!rv_decode_slli(w1, insn->size, &rd1, &rs1, &shamt)) return false;
    // Only 1, 2 and 3 have a shNadd; x0 is not a shift destination.
    if (shamt < 1 || shamt > 3 || rd1 == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd2, ars1, ars2;
    if (!rv_decode_add(w2, len2, &rd2, &ars1, &ars2)) return false;

    // The add must overwrite the shifted register and read it exactly
    // once. Overwriting it is what makes the intermediate dead without a
    // liveness query; reading it twice (`add rd,rd,rd`) doubles the
    // shifted value, which is a wider shift and not this rewrite.
    if (rd2 != rd1) return false;
    bool a_is_shift = ars1 == rd1, b_is_shift = ars2 == rd1;
    if (a_is_shift == b_is_shift) return false;
    unsigned addend = a_is_shift ? ars2 : ars1;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    unsigned before = insn->size + len2;
    finding->title = "slli + add foldable to shNadd";
    finding->address = insn->address;
    finding->insn_count = 2;
    // sh1add/sh2add/sh3add are all four bytes, so the byte delta depends
    // on which spellings the pair used; at 4 bytes the win is one
    // instruction and one dependency rather than any space.
    snprintf(finding->replacement, sizeof finding->replacement,
             "sh%uadd %s, %s, %s (%u -> 4 bytes)", shamt, rv_reg_name(rd2),
             rv_reg_name(rs1), rv_reg_name(addend), before);
    return true;
}

bool check_slli_srli_to_zext(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBA)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1, rs1, sh1;
    if (!rv_decode_slli(w1, insn->size, &rd1, &rs1, &sh1)) return false;
    if (sh1 != 32 || rd1 == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd2, srs1, sh2;
    if (!rv_decode_srli(w2, len2, &rd2, &srs1, &sh2)) return false;
    if (sh2 != 32) return false;

    // The srli must consume the shifted value and overwrite it, which is
    // what leaves nothing of the intermediate to keep alive.
    if (rd2 != rd1 || srs1 != rd1) return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    unsigned before = insn->size + len2;
    finding->title = "slli + srli foldable to zext.w";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "zext.w %s, %s (%u -> 4 bytes)", rv_reg_name(rd1),
             rv_reg_name(rs1), before);
    return true;
}

// ---- bounded liveness ----

#define LIVE_BUDGET 96   // instructions examined per query
#define LIVE_PATHS  16   // distinct path starts before giving up

static unsigned cs_reg_to_num(unsigned r)
{
    if (r >= RISCV_REG_X0 && r <= RISCV_REG_X31)
        return (unsigned)(r - RISCV_REG_X0);
    return 32;   // not a general register
}

static bool insn_in_group(const cs_insn *insn, unsigned g)
{
    for (int i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == g) return true;
    return false;
}

// Absolute target of a relative transfer, or 0 when it has none.
static uint64_t relative_target(const cs_insn *insn)
{
    if (!insn_in_group(insn, RISCV_GRP_BRANCH_RELATIVE)) return 0;
    const cs_riscv *a = &insn->detail->riscv;
    for (int i = 0; i < a->op_count; i++)
        if (a->operands[i].type == RISCV_OP_IMM)
            return (uint64_t)a->operands[i].imm;
    return 0;
}

int riscvlint_liveness(riscvlint_state *state, uint64_t addr, unsigned rd)
{
    if (!state->probe) return RISCVLINT_LIVE_UNKNOWN;
    uint64_t queue[LIVE_PATHS], seen[LIVE_PATHS];
    int nq = 0, nseen = 0, budget = LIVE_BUDGET;
    queue[nq++] = addr;

    while (nq > 0) {
        uint64_t at = queue[--nq];
        bool dup = false;
        for (int i = 0; i < nseen; i++)
            if (seen[i] == at) dup = true;
        if (dup) continue;
        if (nseen >= LIVE_PATHS) return RISCVLINT_LIVE_UNKNOWN;
        seen[nseen++] = at;
        if (at < state->vaddr || at >= state->vaddr + state->size)
            return RISCVLINT_LIVE_UNKNOWN;

        const uint8_t *p = state->code + (at - state->vaddr);
        size_t remain = state->size - (size_t)(at - state->vaddr);
        uint64_t a = at;
        for (;;) {
            if (budget-- <= 0) return RISCVLINT_LIVE_UNKNOWN;
            if (remain < 2 ||
                !cs_disasm_iter(state->handle, &p, &remain, &a, state->probe))
                return RISCVLINT_LIVE_UNKNOWN;
            const cs_insn *in = state->probe;
            const char *m = in->mnemonic;

            cs_regs rr, rw;
            uint8_t nr = 0, nw = 0;
            cs_regs_access(state->handle, in, rr, &nr, rw, &nw);
            // capstone leaves the ra-implicit link aliases writing
            // nothing and `ret` reading nothing.
            if ((!strcmp(m, "jal") || !strcmp(m, "jalr")) && nw == 0)
                rw[nw++] = RISCV_REG_X1;
            else if (!strcmp(m, "ret") && nr == 0)
                rr[nr++] = RISCV_REG_X1;

            for (int i = 0; i < nr; i++)
                if (cs_reg_to_num(rr[i]) == rd) return RISCVLINT_LIVE_READ;
            bool written = false;
            for (int i = 0; i < nw; i++)
                if (cs_reg_to_num(rw[i]) == rd) written = true;
            if (written) break;                 // redefined before any read

            bool call = insn_in_group(in, RISCV_GRP_CALL) ||
                        !strcmp(m, "jal") || !strcmp(m, "jalr");
            if (call) {
                // No shortcut here for the caller-saved temporaries.
                // That a callee cannot read t0-t6 is a property of the C
                // ABI, not of the architecture, and riscvlint cannot tell
                // which ABI a binary was built for: Go's runtime calling
                // sequences pass arguments in t0 and t1, where the
                // shortcut turned tens of thousands of argument set-ups
                // into "dead" definitions.
                return RISCVLINT_LIVE_UNKNOWN;
            }
            if (!strcmp(m, "ret")) {
                // Which registers a return makes observable is an ABI
                // question -- a0/a1 under the C ABI, a0-a7 under Go's,
                // plus every callee-saved register the caller expects
                // restored. The walk does not know which ABI it is
                // looking at, so it declines rather than guessing. What
                // survives is deadness proved by redefinition before
                // any read, which holds under any convention.
                return RISCVLINT_LIVE_UNKNOWN;
            }
            uint64_t t = relative_target(in);
            bool uncond = !strcmp(m, "j") || !strcmp(m, "jr") ||
                          !strcmp(m, "mret") || !strcmp(m, "sret");
            if (uncond) {
                if (!t) return RISCVLINT_LIVE_UNKNOWN;   // indirect
                if (nq >= LIVE_PATHS) return RISCVLINT_LIVE_UNKNOWN;
                queue[nq++] = t;
                break;
            }
            if (t) {                             // conditional branch
                if (nq >= LIVE_PATHS) return RISCVLINT_LIVE_UNKNOWN;
                queue[nq++] = t;
            }
        }
    }
    return RISCVLINT_LIVE_DEAD;
}


// ---- redundant stack-pointer restore ----

#define RV_REG_SP 2u
#define RV_REG_FP 8u   // s0

// Does this instruction write `rn`? Answering it by raw decode would mean
// decoding every instruction form in the ISA, which is the argument
// riscvlint_liveness already makes for consulting capstone's register
// model rather than the encoding. The model's known RISC-V gap is the
// ra-implicit link aliases, and ra is neither sp nor the frame pointer,
// so nothing needs correcting here. A failed query answers "yes", which
// disarms the check rather than licensing a finding.
static bool insn_writes(const riscvlint_state *state, const cs_insn *insn,
                        unsigned rn)
{
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(state->handle, insn, rr, &nr, rw, &nw) != CS_ERR_OK)
        return true;
    for (int i = 0; i < nw; i++)
        if (cs_reg_to_num(rw[i]) == rn) return true;
    return false;
}

bool check_redundant_sp_restore(riscvlint_state *state, const cs_insn *insn,
                                riscvlint_finding *finding)
{
    unsigned rd = 0, rs1 = 0;
    int64_t imm = 0;
    bool addi = false;
    if (insn->size == 2 || insn->size == 4) {
        uint32_t w;
        if (riscvlint_word_at(state, insn->address, &w))
            addi = rv_decode_addi(w, insn->size, &rd, &rs1, &imm);
    }

    bool found = false;
    if (addi && rd == RV_REG_SP && rs1 == RV_REG_FP && state->fp.armed &&
        !state->fp.sp_moved && imm == -state->fp.k &&
        !riscvlint_is_relocated(state, insn->address) &&
        // A restore something branches to can be entered from code that
        // has not been walked yet, and that code may move sp. The scan
        // is linear, so only a fall-through restore is covered by what
        // it has already seen. This costs the shared epilogue -- 17% of
        // the population in the corpus -- and is what keeps the rest
        // provable rather than likely.
        !riscvlint_is_branch_target(state, insn->address)) {
        finding->title = "redundant stack-pointer restore";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "delete; sp already holds %s-%" PRId64
                 " from 0x%" PRIx64 " (%u bytes)",
                 rv_reg_name(RV_REG_FP), state->fp.k, state->fp.setup,
                 insn->size);
        found = true;
    }

    // Carry the prologue forward. Order matters: the restore above is
    // judged against the state as it stood before this instruction, and
    // only then does this instruction get to change it.
    if (insn_writes(state, insn, RV_REG_SP)) state->fp.sp_moved = true;
    if (insn_writes(state, insn, RV_REG_FP)) state->fp.armed = false;
    if (addi && rd == RV_REG_FP && rs1 == RV_REG_SP && imm > 0) {
        state->fp.armed = true;
        state->fp.k = imm;
        state->fp.setup = insn->address;
        state->fp.sp_moved = false;
    }
    return found;
}

// ---- redundant sign or zero extension ----

static const char *guarantee_name(unsigned g)
{
    switch (g) {
    case RISCVLINT_G_SEXT8:  return "sext.b";
    case RISCVLINT_G_SEXT16: return "sext.h";
    case RISCVLINT_G_SEXT32: return "sext.w";
    case RISCVLINT_G_ZEXT8:  return "zext.b";
    case RISCVLINT_G_ZEXT16: return "zext.h";
    default:                 return "zext.w";
    }
}

bool check_redundant_extension(riscvlint_state *state, const cs_insn *insn,
                               riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) {
        memset(state->guarantees, 0, sizeof state->guarantees);
        return false;
    }
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) {
        memset(state->guarantees, 0, sizeof state->guarantees);
        return false;
    }
    // A side entry means the value reaching this instruction was not
    // produced by what precedes it in address order.
    if (riscvlint_is_branch_target(state, insn->address))
        memset(state->guarantees, 0, sizeof state->guarantees);

    bool found = false;
    unsigned rd = 0, rs1 = 0, want = 0;
    if (rv_decode_extension(w, insn->size, &rd, &rs1, &want) && rs1 != 0 &&
        (state->guarantees[rs1] & want) &&
        !riscvlint_is_relocated(state, insn->address)) {
        finding->title = "redundant sign or zero extension";
        finding->address = insn->address;
        finding->insn_count = 1;
        if (rd == rs1)
            snprintf(finding->replacement, sizeof finding->replacement,
                     "delete; %s is already %s (%u bytes)",
                     rv_reg_name(rs1), guarantee_name(want), insn->size);
        else
            // The rewrite is a copy, and c.mv can name any two non-zero
            // registers, so a four-byte extension becomes two bytes.
            snprintf(finding->replacement, sizeof finding->replacement,
                     "mv %s, %s; %s is already %s (%u -> 2 bytes)",
                     rv_reg_name(rd), rv_reg_name(rs1), rv_reg_name(rs1),
                     guarantee_name(want), insn->size);
        found = true;
    }

    // Record what this instruction leaves behind. Capstone decides what
    // was written and the raw decode decides what is guaranteed: an
    // under-reported write would leave a stale guarantee and a wrong
    // finding, so calls and unconditional transfers clear the table
    // outright rather than relying on the register model at exactly the
    // places it is known to be thin.
    unsigned grd = 0;
    unsigned g = rv_result_guarantees(w, insn->size, &grd);
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(state->handle, insn, rr, &nr, rw, &nw) != CS_ERR_OK) {
        memset(state->guarantees, 0, sizeof state->guarantees);
        return found;
    }
    bool wrote_grd = false;
    for (int i = 0; i < nw; i++) {
        unsigned n = cs_reg_to_num(rw[i]);
        if (n < 32) state->guarantees[n] = 0;
        if (n == grd) wrote_grd = true;
    }
    // The guarantee is only recorded when both models agree the
    // instruction wrote that register. They are decoding the same bytes
    // by different routes, and where they disagree the disagreement is a
    // bug in one of them -- so it costs a finding rather than inventing
    // a guarantee about a register this instruction never touched.
    if (g && grd != 0 && grd < 32 && wrote_grd) state->guarantees[grd] = g;
    if (rv_ends_region(w, insn->size))
        memset(state->guarantees, 0, sizeof state->guarantees);
    return found;
}

// ---- the windowed memory and constant table ----

static unsigned mem_width(rv_mem_kind k)
{
    int i = mem_index(k);
    return i >= 0 ? rv_mem_table[i].width : 0;
}

// Two frame-relative accesses through the same base provably miss each
// other when their byte ranges do not overlap. Through different bases
// nothing is provable, so the caller treats that as "may alias".
static bool ranges_overlap(int64_t a, unsigned aw, int64_t b, unsigned bw)
{
    return a < b + (int64_t)bw && b < a + (int64_t)aw;
}

// True when the instruction reads or writes memory, whether or not
// rv_decode_mem can say where. The vector loads and stores share LOAD-FP
// and STORE-FP with `flw` and `fld` and are told apart by a width field
// the decoder does not model, so they land here -- and they matter: a
// `vle64.v` through an address taken with `addi a0,s0,-272` reads a
// frame slot that a store just wrote, which is exactly the claim this
// window would otherwise make wrongly.
static bool touches_memory(uint32_t w, unsigned size)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w);
        return op == 0x03u || op == 0x07u || op == 0x23u || op == 0x27u ||
               op == 0x2fu;
    }
    if (size != 2) return false;
    unsigned q = w & 0x3u, f3 = (w >> 13) & 0x7u;
    if (q == 0) return f3 != 0;                    // all but c.addi4spn
    if (q == 2) return f3 != 0 && f3 != 4;         // all but c.slli, c.jr/mv
    return false;
}

static bool is_cond_branch_raw(uint32_t w, unsigned size)
{
    if (size == 4) return RV_OPCODE(w) == 0x63u;
    if (size != 2) return false;
    unsigned f3 = (w >> 13) & 0x7u;         // c.beqz, c.bnez
    return (w & 0x3u) == 1u && (f3 == 6 || f3 == 7);
}

// A fence, an atomic or a system instruction can make any location
// change under us, and a call can do anything at all.
static bool ends_memory_window(uint32_t w, unsigned size)
{
    if (rv_ends_region(w, size)) return true;
    if (size != 4) return false;
    unsigned op = RV_OPCODE(w);
    return op == 0x0fu || op == 0x2fu || op == 0x73u;  // fence, AMO, system
}

void riscvlint_state_drop_window(riscvlint_state *state)
{
    state->win.nslots = 0;
    memset(state->win.const_live, 0, sizeof state->win.const_live);
}

static rvl_slot *slot_for(riscvlint_state *state, unsigned base, int64_t disp,
                          rv_mem_kind kind)
{
    for (int i = 0; i < state->win.nslots; i++) {
        rvl_slot *sl = &state->win.slots[i];
        if (sl->base == base && sl->disp == disp && sl->kind == kind)
            return sl;
    }
    if (state->win.nslots < RVL_SLOTS)
        return &state->win.slots[state->win.nslots++];
    return NULL;                    // window full: stop recording, stay sound
}

// The value a constant materialization leaves in its destination, or
// false when the instruction is not one.
static bool decode_const(uint32_t w, unsigned size, unsigned *rd, int64_t *val)
{
    if (size == 4) {
        if (RV_OPCODE(w) == 0x13u && ((w >> 12) & 0x7u) == 0 &&
            ((w >> 15) & 0x1fu) == 0) {                 // li = addi rd,x0,imm
            *rd = (w >> 7) & 0x1fu;
            *val = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
            return *rd != 0;
        }
        if (RV_OPCODE(w) == 0x37u) {                    // lui
            *rd = (w >> 7) & 0x1fu;
            *val = sign_extend(w & 0xfffff000u, 32);
            return *rd != 0;
        }
        return false;
    }
    if (size != 2) return false;
    if ((w & 0xe003u) == 0x4001u) {                     // c.li
        *rd = (w >> 7) & 0x1fu;
        *val = ci_imm6(w);
        return *rd != 0;
    }
    if ((w & 0xe003u) == 0x6001u) {                     // c.lui (not addi16sp)
        *rd = (w >> 7) & 0x1fu;
        *val = ci_imm6(w) << 12;
        return *rd != 0 && *rd != 2 && ci_imm6(w) != 0;
    }
    return false;
}

void riscvlint_state_observe(riscvlint_state *state, const cs_insn *insn)
{
    uint32_t w;
    if (insn->size > 4 || !riscvlint_word_at(state, insn->address, &w)) {
        riscvlint_state_drop_window(state);
        return;
    }

    // 1. Register writes first, so a load's own destination is cleared
    //    before the load records itself into it.
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(state->handle, insn, rr, &nr, rw, &nw) != CS_ERR_OK) {
        riscvlint_state_drop_window(state);
        return;
    }
    for (int i = 0; i < nw; i++) {
        unsigned n = cs_reg_to_num(rw[i]);
        if (n >= 32) continue;
        state->win.const_live[n] = false;
        for (int j = 0; j < state->win.nslots; j++) {
            rvl_slot *sl = &state->win.slots[j];
            if (sl->data == n) sl->held = false;
            // Losing the base loses the address, and with it any claim
            // about what is or is not at that address.
            if (sl->base == n) sl->held = sl->unread = false;
        }
    }

    // 2. The access itself.
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    bool decoded = rv_decode_mem(w, insn->size, &kind, &data, &base, &off);
    if (!decoded && touches_memory(w, insn->size)) {
        // Something touched memory and we cannot say where. Every claim
        // in the window is about a place, so none of them survive.
        riscvlint_state_drop_window(state);
        return;
    }
    if (decoded) {
        unsigned width = mem_width(kind);
        bool store = rv_mem_is_store(kind);
        bool fp = rv_mem_is_fp(kind);
        for (int j = 0; j < state->win.nslots; j++) {
            rvl_slot *sl = &state->win.slots[j];
            if (store) {
                // Any store at all ends every held value. Proving two
                // addresses distinct needs more than the encoding gives,
                // and the reload rewrite is only worth having if it is
                // certainly right.
                sl->held = false;
                // A store that lands on the same bytes supersedes an
                // unread one; anywhere else it neither reads nor
                // overwrites, so the earlier claim stands.
                if (sl->base == base && sl->disp == off && sl->width == width)
                    sl->unread = false;
            } else if (sl->unread) {
                // A load may be the read that keeps the earlier store
                // alive. Through the same base a disjoint range provably
                // is not; through any other base nothing is provable.
                if (sl->base != base ||
                    ranges_overlap(sl->disp, sl->width, off, width))
                    sl->unread = false;
            }
        }
        // A load that overwrites its own base leaves the record
        // meaningless: the address it used was the old value of that
        // register, and nothing can name it any more. `ld a1,0(a1)`
        // followed by `ld a2,0(a1)` reads two different places.
        bool base_written = false;
        for (int i = 0; i < nw; i++)
            if (cs_reg_to_num(rw[i]) == base) base_written = true;
        rvl_slot *sl = base_written ? NULL : slot_for(state, base, off, kind);
        if (sl) {
            sl->base = base; sl->disp = off; sl->kind = kind;
            sl->width = width; sl->data = data; sl->addr = insn->address;
            sl->size = insn->size;
            // A store leaves the value in a register too, but forwarding
            // it to a later load is a different rewrite than collapsing
            // two loads, and one this corpus has never measured. Only
            // loads arm `held`.
            sl->held = !store && !fp;
            sl->unread = store && (base == 2 || base == 8);
        }
    }

    // 3. Constants, after the register invalidation above.
    unsigned crd;
    int64_t cval;
    if (decode_const(w, insn->size, &crd, &cval)) {
        state->win.const_live[crd] = true;
        state->win.const_val[crd] = cval;
        state->win.const_addr[crd] = insn->address;
    }

    // 4. A conditional branch takes away every claim that a store is
    //    dead, and only those. "Dead" means the overwrite is certain to
    //    happen before anyone reads the slot, and a branch is a path on
    //    which it does not happen at all -- the shape is
    //    `sd a1,-624(s0); beqz a1,L; ...; sd a0,-624(s0)`, and on the
    //    taken path the first store is the one that survives.
    //
    //    A held value is not affected. The instruction that would read
    //    it is reached by falling through, so everything recorded here
    //    ran; and if it can also be reached by a branch, it is a side
    //    entry and step 5 drops the window at it.
    if (is_cond_branch_raw(w, insn->size))
        for (int j = 0; j < state->win.nslots; j++)
            state->win.slots[j].unread = false;

    // 5. Anything that can change memory or control behind our back.
    if (ends_memory_window(w, insn->size)) {
        riscvlint_state_drop_window(state);
        return;
    }
    // 6. A side entry on the next instruction means what follows is not
    //    reached only from here.
    if (riscvlint_is_branch_target(state, insn->address + insn->size))
        riscvlint_state_drop_window(state);
}

// ---- a four-byte encoding Zcb spells in two ----

bool check_zcb_compressible(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZCB)) return false;
    if (insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    const char *form = rv_zcb_form(w, insn->size);
    if (!form) return false;
    // A relocated instruction's immediate is a placeholder the linker
    // fills, so whether the offset fits the compressed field is not yet
    // decided here.
    if (riscvlint_is_relocated(state, insn->address)) return false;

    finding->title = "instruction compressible to a Zcb form";
    finding->address = insn->address;
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s (4 -> 2 bytes)", form);
    return true;
}

// ---- an address computation folded into the access that uses it ----

bool check_base_add_to_offset(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd, rs1;
    int64_t imm1;
    if (!rv_decode_base_add(w1, insn->size, &rd, &rs1, &imm1)) return false;
    // x0 as the source makes this `li`, a constant rather than an
    // address; sp, gp and tp are established by convention and are never
    // dead, so folding one away is not on offer.
    if (rs1 == 0 || rd == 0) return false;
    if (rd == 2 || rd == 3 || rd == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    rv_mem_kind kind;
    unsigned data, base;
    int64_t imm2;
    if (!rv_decode_mem(w2, len2, &kind, &data, &base, &imm2)) return false;
    if (base != rd) return false;

    int64_t sum = imm1 + imm2;
    if (sum < -2048 || sum > 2047) return false;

    // A store whose data register is the computed address reads it for
    // the value as well as for the base, so the address computation is
    // still needed after the fold.
    if (rv_mem_is_store(kind) && !rv_mem_is_fp(kind) && data == rd)
        return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // A load that overwrites its own base kills the computed address by
    // construction, and that is half the population. Everything else
    // asks the walk, which answers DEAD only when every path leaving the
    // access redefines the register before reading it.
    bool self_killing = !rv_mem_is_store(kind) && !rv_mem_is_fp(kind) &&
                        data == rd;
    if (!self_killing &&
        riscvlint_liveness(state, second + len2, rd) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2;
    unsigned after = rv_mem_encoded_size(kind, data, rs1, sum,
                                         riscvlint_may_use(state,
                                                           RISCVLINT_EXT_ZCB));
    finding->title = "base add foldable into memory offset";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, %" PRId64 "(%s) (%u -> %u bytes)", rv_mem_name(kind),
             rv_mem_is_fp(kind) ? fp_reg_names[data] : rv_reg_name(data),
             sum, rv_reg_name(rs1), before, after);
    return true;
}

// ---- the three checks the window serves ----

// `mv rd, rs` is two bytes whenever neither register is x0, which both
// of these rewrites can rely on.
static unsigned mv_bytes(void) { return 2; }

bool check_redundant_reload(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w, insn->size, &kind, &data, &base, &off)) return false;
    if (rv_mem_is_store(kind) || rv_mem_is_fp(kind)) return false;
    if (data == 0) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        if (!sl->held || sl->kind != kind) continue;
        if (sl->base != base || sl->disp != off) continue;
        if (sl->data == 0 || sl->data == data) return false;  // same register
        finding->title = "redundant reload";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "mv %s, %s; loaded at 0x%" PRIx64 " (%u -> %u bytes)",
                 rv_reg_name(data), rv_reg_name(sl->data), sl->addr,
                 insn->size, mv_bytes());
        return true;
    }
    return false;
}

bool check_dead_store(riscvlint_state *state, const cs_insn *insn,
                      riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w, insn->size, &kind, &data, &base, &off)) return false;
    if (!rv_mem_is_store(kind)) return false;
    if (base != 2 && base != 8) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    unsigned width = mem_width(kind);
    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        if (!sl->unread) continue;
        // Only an exact overwrite proves the earlier store dead. A wider
        // store covering it would too, but the corpus has none and an
        // untested rule is worth less than the sites it would add.
        if (sl->base != base || sl->disp != off || sl->width != width)
            continue;
        if (riscvlint_is_branch_target(state, insn->address)) return false;
        finding->title = "dead store to a frame slot";
        finding->address = sl->addr;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "delete; %" PRId64 "(%s) is overwritten at 0x%" PRIx64
                 " (%u bytes)", off, rv_reg_name(base), insn->address,
                 sl->size);
        return true;
    }
    return false;
}

bool check_const_remat(riscvlint_state *state, const cs_insn *insn,
                       riscvlint_finding *finding)
{
    if (insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    unsigned rd;
    int64_t val;
    if (!decode_const(w, insn->size, &rd, &val)) return false;
    // The rewrite only saves anything when the constant is too wide for
    // `c.li`. Inside that range the materialization is two bytes and so
    // is the `mv`, so the trade is an instruction that depends on
    // nothing for one that depends on another register -- a small
    // pessimization, and 97% of the raw population.
    //
    // The test is the constant's magnitude, not the encoding's width.
    // Those agree wherever the assembler selects RVC, and Go's does not:
    // keyed on width this reported 41,813 sites in the Go corpus whose
    // constants all fit c.li, where the rewrite would save nothing on
    // any toolchain that left the `li` wide in the first place.
    if (val >= -32 && val <= 31) return false;
    if (rd == 0 || rd == 2 || rd == 3 || rd == 4) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    for (unsigned r = 1; r < 32; r++) {
        if (r == rd || !state->win.const_live[r]) continue;
        if (state->win.const_val[r] != val) continue;
        finding->title = "constant re-materialization";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "mv %s, %s; %" PRId64 " set at 0x%" PRIx64 " (4 -> %u bytes)",
                 rv_reg_name(rd), rv_reg_name(r), val,
                 state->win.const_addr[r], mv_bytes());
        return true;
    }
    return false;
}

bool check_dead_def(riscvlint_state *state, const cs_insn *insn,
                    riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    unsigned rd;
    if (!rv_pure_def(w, insn->size, &rd)) return false;
    // sp and the thread pointer are established by convention rather
    // than for a reader in this function; a prologue's stack adjustment
    // is not a dead definition even where nothing reads sp again.
    if (rd == 2 || rd == 3 || rd == 4) return false;
    // A relocated instruction's operands are placeholders, and the
    // sequence it belongs to is decided at link time.
    if (riscvlint_is_relocated(state, insn->address)) return false;

    if (riscvlint_liveness(state, insn->address + insn->size, rd) !=
        RISCVLINT_LIVE_DEAD)
        return false;

    finding->title = "dead register definition";
    finding->address = insn->address;
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "delete; nothing reads %s (%u bytes)", rv_reg_name(rd),
             insn->size);
    return true;
}
