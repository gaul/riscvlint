// riscvlint check library. See riscvlint.h for why the checks decode
// raw encodings instead of reading capstone's operand model.

#include "riscvlint.h"

#include <ctype.h>
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

static const char *const rv_freg_names[32] = {
    "ft0", "ft1", "ft2",  "ft3",  "ft4", "ft5", "ft6",  "ft7",
    "fs0", "fs1", "fa0",  "fa1",  "fa2", "fa3", "fa4",  "fa5",
    "fa6", "fa7", "fs2",  "fs3",  "fs4", "fs5", "fs6",  "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
};

static const char *rv_freg_name(unsigned n)
{
    return n < 32 ? rv_freg_names[n] : "f?";
}

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

// The immediate of `c.lui`, whose 6-bit field is the value's bits
// 17:12 rather than its low six. Shifted while still an unsigned field
// and sign-extended afterwards, which is the order the encoding
// describes -- and the only defined one, since a left shift of a
// negative value is undefined behaviour. `ci_imm6(w) << 12` reads the
// same and agrees on every input, but UBSan is right about it.
static int64_t ci_imm6_lui(uint32_t w)
{
    uint64_t field = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
    return sign_extend(field << 12, 18);
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

bool rv_decode_not(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1)
{
    if (size == 4) {
        // `not rd,rs` is `xori rd,rs,-1`, which is the only xori this
        // project has ever needed to name.
        if (RV_OPCODE(w) != 0x13u) return false;
        if (((w >> 12) & 0x7u) != 4u) return false;
        if (sign_extend((uint64_t)(w >> 20) & 0xfffu, 12) != -1) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        return *rd != 0;
    }
    if (size != 2) return false;
    // Zcb's `c.not`, in the unary group that shares c.andi's funct3. It
    // is in-place, so it only ever spells `not rd,rd`.
    if ((w & 0xfc7fu) != 0x9c75u) return false;
    *rd = *rs1 = 8u + ((w >> 7) & 0x7u);
    return true;
}

bool rv_decode_srai(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    unsigned *shamt)
{
    if (size == 4) {
        // The same encoding as srli with funct6 010000 rather than
        // 000000: the one bit that decides whether the sign or a zero
        // is shifted in, and so whether the pair above it is a sign
        // extension or a mask.
        if (RV_OPCODE(w) != 0x13u) return false;
        if (((w >> 12) & 0x7u) != 5u) return false;
        if (((w >> 26) & 0x3fu) != 0x10u) return false;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *shamt = (w >> 20) & 0x3fu;
        return true;
    }
    if (size != 2) return false;
    // CB-format c.srai: bit 10 set where c.srli has it clear, bit 11
    // clear where c.andi has it set. x8-x15 only, and a shift of zero
    // is the reserved encoding rather than a shift of nothing.
    if ((w & 0xec03u) != 0x8401u) return false;
    unsigned r = 8u + ((w >> 7) & 0x7u);
    unsigned sh = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
    if (sh == 0) return false;
    *rd = *rs1 = r;
    *shamt = sh;
    return true;
}

// The AMO opcode's width field: funct3 010 is the word form and 011 the
// doubleword. 000 and 001 are Zabha's byte and halfword, 100 the quad,
// and none of those is a width this project reads.
static bool amo_width(uint32_t w, unsigned *width)
{
    switch ((w >> 12) & 0x7u) {
    case 2u: *width = 4; return true;
    case 3u: *width = 8; return true;
    default: return false;
    }
}

bool rv_decode_lr(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                  unsigned *width, unsigned *aq, unsigned *rl)
{
    if (size != 4) return false;
    if (RV_OPCODE(w) != 0x2fu) return false;
    if (((w >> 27) & 0x1fu) != 0x02u) return false;          // funct5 00010
    // LR takes no second source and the field is required to be zero,
    // so a nonzero one is not an LR however it decodes elsewhere.
    if (((w >> 20) & 0x1fu) != 0u) return false;
    if (!amo_width(w, width)) return false;
    *aq = (w >> 26) & 1u;
    *rl = (w >> 25) & 1u;
    *rd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    return true;
}

bool rv_decode_sc(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                  unsigned *rs2, unsigned *width, unsigned *aq, unsigned *rl)
{
    if (size != 4) return false;
    if (RV_OPCODE(w) != 0x2fu) return false;
    if (((w >> 27) & 0x1fu) != 0x03u) return false;          // funct5 00011
    if (!amo_width(w, width)) return false;
    *aq = (w >> 26) & 1u;
    *rl = (w >> 25) & 1u;
    *rd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    *rs2 = (w >> 20) & 0x1fu;
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
    if (strstr(arch, "_zfa")) exts |= RISCVLINT_EXT_ZFA;
    if (strstr(arch, "_zilx")) exts |= RISCVLINT_EXT_ZILX;
    if (strstr(arch, "_zibi")) exts |= RISCVLINT_EXT_ZIBI;
    if (strstr(arch, "_zacas")) exts |= RISCVLINT_EXT_ZACAS;
    if (strstr(arch, "_zicfilp")) exts |= RISCVLINT_EXT_ZICFILP;
    // C is spelled `_c2p0` in the base run and `_zca1p0` once the
    // Zc* split gave it a name of its own; a conforming string carries
    // whichever the assembler wrote, and some carry both.
    for (const char *p = arch; (p = strstr(p, "_c")) != NULL; p += 2)
        if (p[2] >= '0' && p[2] <= '9') { exts |= RISCVLINT_EXT_C; break; }
    if (strstr(arch, "_zca")) exts |= RISCVLINT_EXT_C;
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

// ---- base C encodability ----

// True when the value fits the six-bit signed immediate the CI forms
// carry.
static bool fits6(int64_t v) { return v >= -32 && v <= 31; }

// A commutative two-register form fits whenever the destination is one
// of the sources and the other is nameable; which source it is does not
// matter, because the assembler will swap them.
static bool c_commutes(unsigned rd, unsigned rs1, unsigned rs2)
{
    if (rd == rs1 && rvc_reg(rs2)) return true;
    if (rd == rs2 && rvc_reg(rs1)) return true;
    return false;
}

bool rv_c_form(uint32_t w, unsigned size, char *out, size_t outsz)
{
    if (size != 4) return false;
    unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
    unsigned rd = (w >> 7) & 0x1fu, rs1 = (w >> 15) & 0x1fu;
    unsigned rs2 = (w >> 20) & 0x1fu, f7 = (w >> 25) & 0x7fu;
    int64_t imm12 = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
    const char *name = NULL;

    // The loads and stores, whose rules the memory model already holds.
    // Passing zcb = false keeps this to the base forms and leaves the
    // byte and halfword accesses to rv_zcb_form.
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (rv_decode_mem(w, 4, &kind, &data, &base, &off)) {
        if (rv_mem_encoded_size(kind, data, base, off, false) != 2)
            return false;
        snprintf(out, outsz, "c.%s%s", rv_mem_name(kind),
                 base == 2 ? "sp" : "");
        return true;
    }

    // The conditional branches, likewise.
    unsigned brs1, brs2, bf3;
    int64_t boff;
    if (rv_decode_cond_branch(w, 4, &brs1, &brs2, &bf3, &boff)) {
        if (rv_branch_encoded_size(bf3, brs1, brs2, boff) != 2) return false;
        snprintf(out, outsz, "c.%s", bf3 == 0 ? "beqz" : "bnez");
        return true;
    }

    switch (op) {
    case 0x13u:                                       // OP-IMM
        if (f3 == 0u) {                               // addi and its aliases
            // `nop` is left alone. A four-byte one is either alignment
            // padding, which exists for its width and would stop working
            // if it shrank, or it is dead and wants deleting rather than
            // compressing. Neither is what this check has to say, and it
            // is 1,621 sites in the GCC/LLVM cohort.
            if (rd == 0 && rs1 == 0) return false;
            if (rd == 0) return false;                 // discards its result
            else if (rs1 == 0 && fits6(imm12)) name = "c.li";
            else if (rd == 2 && rs1 == 2 && imm12 != 0 && imm12 % 16 == 0 &&
                     imm12 >= -512 && imm12 <= 496) name = "c.addi16sp";
            else if (rs1 == 2 && rvc_reg(rd) && imm12 > 0 &&
                     imm12 % 4 == 0 && imm12 <= 1020) name = "c.addi4spn";
            else if (rd == rs1 && imm12 != 0 && fits6(imm12)) name = "c.addi";
            // `mv rd,rs` is `addi rd,rs,0`, and c.mv is `add rd,x0,rs2`
            // -- a different encoding of the same move, which the
            // assembler reaches from either spelling.
            else if (imm12 == 0 && rs1 != 0) name = "c.mv";
            break;
        }
        if (f3 == 1u && ((w >> 26) & 0x3fu) == 0u) {  // slli
            unsigned sh = (w >> 20) & 0x3fu;
            if (rd != 0 && rd == rs1 && sh != 0) name = "c.slli";
            break;
        }
        if (f3 == 5u) {                               // srli, srai
            unsigned f6 = (w >> 26) & 0x3fu, sh = (w >> 20) & 0x3fu;
            if ((f6 != 0u && f6 != 0x10u) || sh == 0) break;
            if (rd == rs1 && rvc_reg(rd))
                name = f6 == 0u ? "c.srli" : "c.srai";
            break;
        }
        if (f3 == 7u && rd == rs1 && rvc_reg(rd) && fits6(imm12))
            name = "c.andi";
        break;
    case 0x1bu:                                       // OP-IMM-32
        if (f3 == 0u && rd != 0 && rd == rs1 && fits6(imm12))
            name = "c.addiw";                         // imm 0 is sext.w
        break;
    case 0x37u: {                                     // lui
        // c.lui carries imm[17:12], so the twenty-bit field has to be a
        // sign-extension of its own low six bits, and neither zero nor a
        // destination of x0 or sp.
        int64_t f = sign_extend((uint64_t)(w >> 12) & 0xfffffu, 20);
        if (rd != 0 && rd != 2 && f != 0 && fits6(f)) name = "c.lui";
        break;
    }
    case 0x33u:                                       // OP
        if (f7 == 0u && f3 == 0u) {                   // add, and its mv alias
            if (rs1 == 0 && rd != 0 && rs2 != 0) name = "c.mv";
            else if (rd != 0 && ((rd == rs1 && rs2 != 0) ||
                                 (rd == rs2 && rs1 != 0)))
                name = "c.add";                       // commutes
            break;
        }
        if (!rvc_reg(rd)) break;
        // The two-register forms put the destination in one source slot.
        // The commutative ones reach either slot, since the assembler
        // will swap the operands to fit; `sub` reaches only the first.
        if (f7 == 0x20u && f3 == 0u) {
            if (rd == rs1 && rvc_reg(rs2)) name = "c.sub";
            break;
        }
        if (f7 != 0u) break;
        if (!c_commutes(rd, rs1, rs2)) break;
        if (f3 == 4u) name = "c.xor";
        else if (f3 == 6u) name = "c.or";
        else if (f3 == 7u) name = "c.and";
        break;
    case 0x3bu:                                       // OP-32
        if (!rvc_reg(rd)) break;
        if (f7 == 0x20u && f3 == 0u) {
            if (rd == rs1 && rvc_reg(rs2)) name = "c.subw";
            break;
        }
        if (f7 == 0u && f3 == 0u && c_commutes(rd, rs1, rs2))
            name = "c.addw";
        break;
    case 0x67u:                                       // jalr
        if (f3 != 0u || imm12 != 0 || rs1 == 0) break;
        if (rd == 0) name = "c.jr";
        else if (rd == 1) name = "c.jalr";
        break;
    case 0x6fu: {                                     // jal
        // c.jal is RV32-only, so only the x0 link compresses here.
        unsigned jrd;
        int64_t o;
        if (!rv_decode_jump(w, 4, &jrd, &o) || jrd != 0) break;
        if (o >= -2048 && o <= 2046) name = "c.j";
        break;
    }
    case 0x73u:                                       // system
        if (w == 0x00100073u) name = "c.ebreak";
        break;
    default:
        break;
    }
    if (!name) return false;
    snprintf(out, outsz, "%s", name);
    return true;
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
            int64_t v = ci_imm6_lui(w);
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

// ---- conditions and branches ----

bool rv_decode_condition(uint32_t w, unsigned size, unsigned *rd,
                         unsigned *rs1, unsigned *rs2, rv_cond_kind *kind)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
        unsigned f7 = (w >> 25) & 0x7fu;
        unsigned d = (w >> 7) & 0x1fu, a = (w >> 15) & 0x1fu;
        unsigned b = (w >> 20) & 0x1fu;
        if (d == 0) return false;
        if (op == 0x13u && f3 == 3u && ((w >> 20) & 0xfffu) == 1u) {
            *rd = d; *rs1 = a; *rs2 = 0; *kind = RV_COND_SEQZ;  // sltiu rd,a,1
            return true;
        }
        if (op != 0x33u) return false;
        if (f7 == 0x20u && f3 == 0u) {                          // sub
            *rd = d; *rs1 = a; *rs2 = b; *kind = RV_COND_EQ;
            return true;
        }
        if (f7 != 0u) return false;
        if (f3 == 3u && a == 0) {                               // sltu rd,x0,b
            *rd = d; *rs1 = b; *rs2 = 0; *kind = RV_COND_SNEZ;
            return true;
        }
        switch (f3) {
        case 2: *kind = RV_COND_SLT;  break;
        case 3: *kind = RV_COND_SLTU; break;
        case 4: *kind = RV_COND_EQ;   break;                    // xor
        default: return false;
        }
        *rd = d; *rs1 = a; *rs2 = b;
        return true;
    }
    if (size != 2) return false;
    // c.sub and c.xor are `sub rd',rd',rs2'` and `xor rd',rd',rs2'`.
    // Both share funct6 100011 and are separated by the two bits below
    // it; the same field's other values are c.or and c.and, which say
    // nothing about equality.
    if ((w & 0xfc03u) == 0x8c01u) {
        unsigned sel = (w >> 5) & 0x3u;
        if (sel != 0 && sel != 1) return false;                 // c.sub, c.xor
        *rd = *rs1 = 8u + ((w >> 7) & 0x7u);
        *rs2 = 8u + ((w >> 2) & 0x7u);
        *kind = RV_COND_EQ;
        return true;
    }
    return false;
}

bool rv_decode_cond_branch(uint32_t w, unsigned size, unsigned *rs1,
                           unsigned *rs2, unsigned *funct3, int64_t *off)
{
    if (size == 4) {
        if (RV_OPCODE(w) != 0x63u) return false;
        unsigned f3 = (w >> 12) & 0x7u;
        if (f3 == 2u || f3 == 3u) return false;                 // reserved
        *funct3 = f3;
        *rs1 = (w >> 15) & 0x1fu;
        *rs2 = (w >> 20) & 0x1fu;
        uint64_t imm = (((uint64_t)(w >> 31) & 1u) << 12) |
                       (((uint64_t)(w >> 7) & 1u) << 11) |
                       (((uint64_t)(w >> 25) & 0x3fu) << 5) |
                       (((uint64_t)(w >> 8) & 0xfu) << 1);
        *off = sign_extend(imm, 13);
        return true;
    }
    if (size != 2) return false;
    // CB-format c.beqz and c.bnez, whose register field names x8-x15.
    if ((w & 0xe003u) != 0xc001u && (w & 0xe003u) != 0xe001u) return false;
    *funct3 = ((w >> 13) & 0x7u) == 6u ? 0u : 1u;
    *rs1 = 8u + ((w >> 7) & 0x7u);
    *rs2 = 0;
    // CB packs the displacement as imm[8|4:3] in bits 12:10 and
    // imm[7:6|2:1|5] in bits 6:2. Reading 11:10 as imm[7:6] and 6:5 as
    // imm[4:3] -- the two fields swapped -- decodes most short branches
    // to a plausible wrong address rather than to nothing, which is how
    // it survived until a finding was read against the disassembly.
    uint64_t imm = (((uint64_t)(w >> 12) & 1u) << 8) |
                   (((uint64_t)(w >> 10) & 0x3u) << 3) |
                   (((uint64_t)(w >> 5) & 0x3u) << 6) |
                   (((uint64_t)(w >> 3) & 0x3u) << 1) |
                   (((uint64_t)(w >> 2) & 1u) << 5);
    *off = sign_extend(imm, 9);
    return true;
}

bool rv_decode_jump(uint32_t w, unsigned size, unsigned *rd, int64_t *off)
{
    if (size == 4) {
        if (RV_OPCODE(w) != RV_OP_JAL) return false;
        *rd = (w >> 7) & 0x1fu;
        uint64_t imm = (((uint64_t)(w >> 31) & 1u) << 20) |
                       (((uint64_t)(w >> 12) & 0xffu) << 12) |
                       (((uint64_t)(w >> 20) & 1u) << 11) |
                       (((uint64_t)(w >> 21) & 0x3ffu) << 1);
        *off = sign_extend(imm, 21);
        return true;
    }
    if (size != 2) return false;
    if ((w & 0xe003u) != 0xa001u) return false;             // c.j
    *rd = 0;
    // CJ packs imm[11|4|9:8|10|6|7|3:1|5] into bits 12:2, in that order.
    // It is the same kind of scattered field the CB format above got
    // wrong once, so it has a unit test against the assembler's own
    // output rather than against this reading of the manual.
    uint64_t imm = (((uint64_t)(w >> 12) & 1u) << 11) |
                   (((uint64_t)(w >> 11) & 1u) << 4) |
                   (((uint64_t)(w >> 9) & 0x3u) << 8) |
                   (((uint64_t)(w >> 8) & 1u) << 10) |
                   (((uint64_t)(w >> 7) & 1u) << 6) |
                   (((uint64_t)(w >> 6) & 1u) << 7) |
                   (((uint64_t)(w >> 3) & 0x7u) << 1) |
                   (((uint64_t)(w >> 2) & 1u) << 5);
    *off = sign_extend(imm, 12);
    return true;
}

unsigned rv_branch_encoded_size(unsigned funct3, unsigned rs1, unsigned rs2,
                                int64_t off)
{
    if (funct3 != 0u && funct3 != 1u) return 4;                 // not beq/bne
    if (rs2 != 0 || !rvc_reg(rs1)) return 4;
    if (off < -256 || off > 254 || (off & 1)) return 4;
    return 2;
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

// A computation the region has performed, one record per register.
// `check_comp_remat` asks of the instruction under the cursor whether
// some live register already holds the value it is about to compute --
// the question `check_const_remat` asks about `li`, widened to
// everything that writes one register as a function of registers.
//
// The mnemonic is the key because capstone prints a compressed form and
// the form it compresses under the same name, so `c.addi4spn a0,sp,16`
// and `addi s3,sp,16` compare equal on everything that matters.
//
// A constant has no inputs, which is why the table beside this one gets
// away with clearing a record only when its own register is written.
// This one carries the rule that costs: a record dies when a *source*
// is written too, since a computation is only still in a register while
// the values it read are the ones still in its operands.
typedef struct {
    bool live;
    char mn[32];         // capstone's own mnemonic field, whole: a
                         // truncated key would make two mnemonics that
                         // share a prefix compare equal
    int rs1, rs2;        // -1 where absent; x0 counts as absent, since
                         // nothing can redefine it
    bool has_imm;
    int64_t imm;
    uint64_t addr;       // where the computation was performed
    unsigned size;       // its encoded bytes, which is what a delete saves
} rvl_comp;

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

    // Reads data outside the scanned section, for the one check that
    // resolves a pool address. NULL unless a caller offered one; see
    // riscvlint_state_set_image for what it is allowed to serve.
    riscvlint_read_fn read;
    void *read_ctx;

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

    // The address after the last store of the zero run
    // check_zero_store_run has already judged. A run is one finding
    // reported at its first store, so every store inside one has to
    // stay quiet -- and the driver walks a section in address order,
    // which is what makes a single watermark enough.
    uint64_t zrun_end;

    // The same watermark for check_push_run: the address after the last
    // instruction of the run it has already judged, so that the second
    // push of a run is not reported again as the start of a shorter one.
    uint64_t push_end;

    // The address of an `add` that a deeper Zilx fold has already
    // claimed -- check_scaled_indexed_load's triple or
    // check_zext_indexed_load's quad. The unscaled check matches that
    // same `add` and must not report it a second time: with Zilx
    // present the site is one `lxsd` or `lxsuwd`, not an `lxd` beside a
    // surviving shift. UINT64_MAX is "none", since a section can
    // legitimately begin at address 0.
    //
    // One address is enough for both writers, because they cannot
    // disagree. Each fires at an `slli` and writes the `add` one or two
    // instructions later; the scaled one wants a shift of 1, 2 or 3 and
    // the zero-extending one a shift of 32, so no instruction is both;
    // and nothing between the write and the read can be an `slli` --
    // it is the quad's `srli` or the triple's own `add`.
    uint64_t zilx_folded;

    // What each register's current value is known to guarantee about its
    // own high bits, for check_redundant_extension. Cleared at every
    // region boundary, so a guarantee is only read on the straight-line
    // path that established it.
    unsigned guarantees[32];

    // ---- the SWAR popcount matcher's state ----
    //
    // Two per-register tables, both cleared at a region boundary.
    //
    // `cknown`/`cval` is ordinary constant propagation, not the `-c`
    // census's chain tracking: it holds a value until the register is
    // *written*, where the census closes a chain when the register is
    // read. A mask is read many times -- 0x3333... twice in one
    // sequence -- so closing on the first read would lose it.
    //
    // `pckind` is where in the expansion a register's value sits, with
    // `pcsrc` naming the register the sequence started from and
    // `pcinsn`/`pcbytes`/`pcstart` accumulating what it has cost so
    // far. A write to a register clears its own entry and every entry
    // whose `pcsrc` names it: the rewrite is `cpop rd,src`, so a stage
    // whose source is gone cannot be spelled that way.
    struct {
        bool cknown[32];
        int64_t cval[32];
        uint8_t pckind[32];
        uint8_t pcsrc[32];
        bool pcwide[32];
        bool pcclob[32];        // the sequence overwrote its own source
        // The counts at stage one, which both halves of the middle
        // stage descend from: adding their totals at the join would
        // charge that shared prefix twice.
        uint16_t pcbase[32];
        uint16_t pcbaseb[32];
        uint16_t pcinsn[32];
        uint16_t pcbytes[32];
        uint64_t pcstart[32];
    } pc;

    // The windowed memory and constant table. See
    // riscvlint_state_observe.
    struct {
        rvl_slot slots[RVL_SLOTS];
        int nslots;
        bool const_live[32];
        int64_t const_val[32];
        uint64_t const_addr[32];
        rvl_comp comp[32];
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
    state->zrun_end = 0;
    state->push_end = 0;
    state->zilx_folded = UINT64_MAX;
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

void riscvlint_state_set_image(riscvlint_state *state, riscvlint_read_fn read,
                               void *ctx)
{
    state->read = read;
    state->read_ctx = ctx;
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
        { "c",     RISCVLINT_EXT_C },
        { "zfa",   RISCVLINT_EXT_ZFA },
        // Zilx is in no profile -- not RVA20, RVA22, RVA23 or RVB23 --
        // so it is named on its own and never arrives with one.
        { "zilx",  RISCVLINT_EXT_ZILX },
        // Zibi is in no profile either, and is a stage earlier than
        // Zilx: LLVM has it as an RISCVExperimentalExtension at 0.1,
        // where Zilx at least has a ratification plan behind it.
        { "zibi",  RISCVLINT_EXT_ZIBI },
        // Zacas is ratified rather than experimental, and still in no
        // profile -- RVA23 does not mandate it. Same treatment as the
        // other two: named on its own or not at all.
        { "zacas", RISCVLINT_EXT_ZACAS },
        // Every profile from RVA20 up mandates C.
        { "rva20", RISCVLINT_EXT_C },
        { "rva22", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                   RISCVLINT_EXT_C },
        // Zcb missed RVA22's ratification window and is mandatory in
        // RVA23U64, so this is where the two profiles part. Zfa is
        // mandatory there too (RISCVProfiles.td's RVA23U64Features).
        { "rva23", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                   RISCVLINT_EXT_ZCB | RISCVLINT_EXT_C |
                   RISCVLINT_EXT_ZFA },
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

// The same for the other register file. Capstone names f0 three times
// over -- once per width it can hold -- and all three are the same
// register, which is the whole reason a bit-cast through memory is
// spelled the way it is.
static unsigned cs_freg_to_num(unsigned r)
{
    if (r >= RISCV_REG_F0_D && r <= RISCV_REG_F31_D)
        return (unsigned)(r - RISCV_REG_F0_D);
    if (r >= RISCV_REG_F0_F && r <= RISCV_REG_F31_F)
        return (unsigned)(r - RISCV_REG_F0_F);
    if (r >= RISCV_REG_F0_H && r <= RISCV_REG_F31_H)
        return (unsigned)(r - RISCV_REG_F0_H);
    return 32;   // not a floating-point register
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
    for (int i = 0; i < 32; i++) state->win.comp[i].live = false;
    // The popcount matcher's tables go with it: a dropped window means
    // the instructions before this point are not known to have run.
    memset(&state->pc, 0, sizeof state->pc);
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
        *val = ci_imm6_lui(w);
        return *rd != 0 && *rd != 2 && ci_imm6(w) != 0;
    }
    return false;
}

// A register operand as the computation table numbers it: -1 for an
// operand that is absent, an immediate, or x0 -- three things this table
// cannot tell apart and does not need to, since an alias that names x0
// and one that omits the operand have different mnemonics, and nothing
// can redefine x0. -2 is a register the table cannot follow at all,
// which disqualifies the instruction rather than being recorded as
// "absent".
static int comp_reg(const cs_insn *insn, int i)
{
    const cs_riscv *a = &insn->detail->riscv;
    if (i >= a->op_count || a->operands[i].type != RISCV_OP_REG) return -1;
    unsigned n = cs_reg_to_num(a->operands[i].reg);
    if (n >= 32) return -2;                 // the other register file
    return n == 0 ? -1 : (int)n;
}

static bool comp_imm(const cs_insn *insn, int i, int64_t *v)
{
    const cs_riscv *a = &insn->detail->riscv;
    if (i >= a->op_count || a->operands[i].type != RISCV_OP_IMM) return false;
    *v = a->operands[i].imm;
    return true;
}

// Which instructions this table can follow. The test is structural
// rather than a list of mnemonics, because the match itself is on the
// mnemonic: two instructions with the same mnemonic, the same sources
// and the same immediate compute the same value. What has to be
// excluded is instructions whose result is not a function of their
// register operands at all.
static bool comp_eligible(const cs_insn *insn, unsigned nw)
{
    const char *m = insn->mnemonic;
    if (nw != 1) return false;
    if (insn_in_group(insn, RISCV_GRP_CALL) ||
        insn_in_group(insn, RISCV_GRP_BRANCH_RELATIVE) ||
        insn_in_group(insn, RISCV_GRP_JUMP) ||
        insn_in_group(insn, RISCV_GRP_RET) ||
        !strcmp(m, "jal") || !strcmp(m, "jalr"))
        return false;
    const cs_riscv *a = &insn->detail->riscv;
    for (int i = 0; i < a->op_count; i++)
        if (a->operands[i].type == RISCV_OP_MEM) return false;
    // csrr and rdtime read state this window does not model; the
    // f-prefixed writers of a general register read the other register
    // file; li and lui are check_const_remat's, auipc is the address
    // re-materialization measured at 39 and rejected, and `mv` is move
    // coalescing, measured at 192 and rejected. See TODO.md.
    if (!strncmp(m, "csr", 3) || !strncmp(m, "rd", 2) || m[0] == 'f')
        return false;
    return strcmp(m, "li") && strcmp(m, "lui") && strcmp(m, "auipc") &&
           strcmp(m, "mv");
}

// The computation an instruction performs, in the form the table
// records it. False when it is not one this table can follow.
//
// `wreg` is the one register cs_regs_access says the instruction writes.
// The key reads the destination off operand 0, which is where every
// eligible form puts it; requiring the two to agree means a form that
// does not is refused rather than recorded against the wrong register.
static bool comp_key(const cs_insn *insn, unsigned nw, unsigned wreg,
                     unsigned *rd, rvl_comp *k)
{
    if (!comp_eligible(insn, nw)) return false;
    int d = comp_reg(insn, 0);
    if (d < 1 || d != (int)wreg) return false;
    memset(k, 0, sizeof *k);
    k->rs1 = comp_reg(insn, 1);
    k->rs2 = comp_reg(insn, 2);
    if (k->rs1 < -1 || k->rs2 < -1) return false;
    k->has_imm = comp_imm(insn, 2, &k->imm);
    snprintf(k->mn, sizeof k->mn, "%s", insn->mnemonic);
    k->addr = insn->address;
    k->size = insn->size;
    k->live = true;
    *rd = (unsigned)d;
    return true;
}

static bool comp_same(const rvl_comp *a, const rvl_comp *b)
{
    return a->rs1 == b->rs1 && a->rs2 == b->rs2 &&
           a->has_imm == b->has_imm && (!a->has_imm || a->imm == b->imm) &&
           !strcmp(a->mn, b->mn);
}

// Defined with check_swar_popcount, which is the only reader of what
// it records.
static void pc_observe(riscvlint_state *state, const cs_insn *insn,
                       uint32_t w);

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
        unsigned fn = cs_freg_to_num(rw[i]);
        if (fn < 32)
            for (int j = 0; j < state->win.nslots; j++) {
                rvl_slot *sl = &state->win.slots[j];
                if (rv_mem_is_fp(sl->kind) && sl->data == fn)
                    sl->held = false;
            }
        unsigned n = cs_reg_to_num(rw[i]);
        if (n >= 32) continue;
        state->win.const_live[n] = false;
        state->win.comp[n].live = false;
        // A computation stays available only while the values it read
        // are still in the registers it read them from, so losing a
        // source loses the record. This is the rule the constant table
        // beside it does not need.
        for (unsigned j = 1; j < 32; j++)
            if (state->win.comp[j].live &&
                (state->win.comp[j].rs1 == (int)n ||
                 state->win.comp[j].rs2 == (int)n))
                state->win.comp[j].live = false;
        for (int j = 0; j < state->win.nslots; j++) {
            rvl_slot *sl = &state->win.slots[j];
            if (sl->data == n && !rv_mem_is_fp(sl->kind)) sl->held = false;
            // Losing the base loses the address, and with it any claim
            // about what is or is not at that address. A base is always
            // an x register, whichever file the value came from.
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
        // about a *place* goes with it -- but the computation table's
        // claims are about registers, and an access through an address
        // we cannot name cannot disturb one; whatever it writes, step 1
        // above already took away. Vector code is where the two part:
        // `vse64.v v8,(a0)` between two `addi a0,s0,-K` is 145 of
        // ripgrep's 646 sites, and dropping the whole window at it lost
        // every one of them.
        state->win.nslots = 0;
        memset(state->win.const_live, 0, sizeof state->win.const_live);
    }
    if (decoded) {
        unsigned width = mem_width(kind);
        bool store = rv_mem_is_store(kind);
        for (int j = 0; j < state->win.nslots; j++) {
            rvl_slot *sl = &state->win.slots[j];
            if (store) {
                // A store ends a held value unless it provably lands
                // somewhere else, which is the same question the branch
                // below asks about `unread` and gets the same answer:
                // through this base a disjoint byte range misses it,
                // through any other base nothing is provable.
                //
                // The rule used to be that any store at all ended every
                // held value. It cost more than it looked like it would.
                // A spill sequence writes several adjacent slots before
                // reading any of them back, so the first claim died at
                // the second store -- 6,585 sites of check_store_to_load
                // alone, two thirds of that family.
                if (sl->base != base ||
                    ranges_overlap(sl->disp, sl->width, off, width))
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
            // A store leaves the value in a register just as a load
            // does, and a later load of the same bytes is a move from
            // it: check_store_to_load. A floating-point access arms a
            // record too, and its `data` names an f register rather than
            // an x one -- which is what check_bitcast_through_frame
            // reads. `rv_mem_is_fp(sl->kind)` is the discriminator;
            // there is no second field for it, because the kind that
            // made the record already says which file its register is
            // in.
            //
            // Only check_silent_store has to be told: it matches on
            // `data` alone, and f10 and x10 are two registers. The
            // others are safe without being told, and one of them
            // deserves the argument written down. check_store_to_load
            // looks for a held *store* record at exactly (base, disp)
            // and gives up on the first one whose widths do not line
            // up -- but two store records at the same displacement
            // always share the byte at that displacement, so a store
            // arriving there clears whatever was held before it. At
            // most one is ever held, and if it is the f one there is no
            // integer forward to lose.
            sl->held = true;
            sl->unread = store && (base == 2 || base == 8);
        }
    }

    // 3. The SWAR popcount matcher, which keeps its own per-register
    //    tables for the reason pc_observe gives.
    pc_observe(state, insn, w);

    // 4. Constants, after the register invalidation above.
    unsigned crd;
    int64_t cval;
    if (decode_const(w, insn->size, &crd, &cval)) {
        state->win.const_live[crd] = true;
        state->win.const_val[crd] = cval;
        state->win.const_addr[crd] = insn->address;
    }

    // 5. The computation this instruction performs, after the
    //    invalidation above and never when the destination is one of
    //    its own sources: `add a0,a0,a1` leaves nothing that can name
    //    the a0 it read, so a later `add rd,a0,a1` computes something
    //    else. That was a false positive in the probe before it was a
    //    rule here.
    rvl_comp key;
    unsigned krd;
    if (nw == 1 && comp_key(insn, nw, cs_reg_to_num(rw[0]), &krd, &key) &&
        key.rs1 != (int)krd && key.rs2 != (int)krd)
        state->win.comp[krd] = key;

    // 5. A conditional branch takes away every claim that a store is
    //    dead, and only those. "Dead" means the overwrite is certain to
    //    happen before anyone reads the slot, and a branch is a path on
    //    which it does not happen at all -- the shape is
    //    `sd a1,-624(s0); beqz a1,L; ...; sd a0,-624(s0)`, and on the
    //    taken path the first store is the one that survives.
    //
    //    A held value is not affected. The instruction that would read
    //    it is reached by falling through, so everything recorded here
    //    ran; and if it can also be reached by a branch, it is a side
    //    entry and step 7 drops the window at it.
    if (is_cond_branch_raw(w, insn->size))
        for (int j = 0; j < state->win.nslots; j++)
            state->win.slots[j].unread = false;

    // 6. Anything that can change memory or control behind our back. A
    //    fence or an atomic is a memory event: it takes the place
    //    claims and leaves the register claims standing, for the reason
    //    the unknown-address case above gives. A transfer ends the
    //    region, and a system instruction can change a register nothing
    //    here is watching, so those two take everything.
    if (ends_memory_window(w, insn->size)) {
        state->win.nslots = 0;
        memset(state->win.const_live, 0, sizeof state->win.const_live);
        // 0x73 is the CSR opcode as well as the environment one, and
        // the two do not deserve the same answer. A CSR access writes
        // the register step 1 already saw and nothing else, and no
        // computation this table follows reads a control register --
        // the vector and floating-point instructions that do are not
        // eligible. `csrr t0,vlenb` between the two halves is 25 of
        // libLLVM's 17,132 probe sites. funct3 == 0 is the environment
        // half, which can change anything.
        bool env = RV_OPCODE(w) == 0x73u && ((w >> 12) & 0x7u) == 0;
        if (rv_ends_region(w, insn->size) || env) {
            for (int i = 0; i < 32; i++) state->win.comp[i].live = false;
            // A call clobbers registers the matcher is tracking stages
            // in, and an environment instruction can change anything.
            memset(&state->pc, 0, sizeof state->pc);
        }
    }
    // 7. A side entry on the next instruction means what follows is not
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

// ---- the four checks the window serves ----

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

// The one instruction a load becomes when the bytes it reads are still
// in a register: a move where the store and the load are the same width
// and the same file, and otherwise the extension the load's own
// signedness implies. `sext.w` is `addiw rd,rs,0` and `zext.b` is
// `andi rd,rs,255`, so neither needs an extension; `zext.h` and
// `zext.w` have no such spelling and cost two shifts without theirs,
// which is no longer a rewrite worth making.
static bool forward_form(rv_mem_kind st, rv_mem_kind ld, const char **name,
                         unsigned *ext)
{
    static const struct {
        rv_mem_kind st, ld;
        const char *name;
        unsigned ext;
    } t[] = {
        { RV_MEM_SD, RV_MEM_LD,  "mv",     0 },
        { RV_MEM_SW, RV_MEM_LW,  "sext.w", 0 },
        { RV_MEM_SW, RV_MEM_LWU, "zext.w", RISCVLINT_EXT_ZBA },
        { RV_MEM_SH, RV_MEM_LH,  "sext.h", RISCVLINT_EXT_ZBB },
        { RV_MEM_SH, RV_MEM_LHU, "zext.h", RISCVLINT_EXT_ZBB },
        { RV_MEM_SB, RV_MEM_LB,  "sext.b", RISCVLINT_EXT_ZBB },
        { RV_MEM_SB, RV_MEM_LBU, "zext.b", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++)
        if (t[i].st == st && t[i].ld == ld) {
            *name = t[i].name;
            *ext = t[i].ext;
            return true;
        }
    return false;
}

bool check_store_to_load(riscvlint_state *state, const cs_insn *insn,
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

    // A held load of the same kind at the same address is
    // check_redundant_reload's finding, and its source is the nearer of
    // the two. One rewrite per site, so this one stands down.
    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        if (sl->held && sl->kind == kind && sl->base == base &&
            sl->disp == off)
            return false;
    }

    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        if (!sl->held || !rv_mem_is_store(sl->kind)) continue;
        if (sl->base != base || sl->disp != off) continue;
        // The width has to match exactly. A narrower load of a wider
        // store is a field extraction rather than a move, and a wider
        // load reads bytes the store never wrote.
        const char *name;
        unsigned ext;
        if (!forward_form(sl->kind, kind, &name, &ext)) return false;
        if (ext && !riscvlint_may_use(state, ext)) return false;
        // Storing x0 makes the rewrite `li rd,0` rather than a move, and
        // a load into the register that already holds the value makes
        // the load redundant by itself. Both are real and neither is
        // this; see candidates in TODO.md.
        if (sl->data == 0 || sl->data == data) return false;

        // `c.mv` names any two registers, so a move is two bytes
        // whenever it is a move at all. Every extension form writes a
        // register it does not read, which no compressed spelling can
        // express, so all of them are four -- and against a load the
        // assembler already compressed that is two bytes spent to save
        // an access. check_const_remat refuses the same trade, and so
        // does this.
        unsigned after = strcmp(name, "mv") ? 4u : mv_bytes();
        if (after > insn->size) return false;

        finding->title = "load of a just-stored value";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, %s; stored at 0x%" PRIx64 " (%u -> %u bytes)",
                 name, rv_reg_name(data), rv_reg_name(sl->data), sl->addr,
                 insn->size, after);
        return true;
    }
    return false;
}

bool check_redundant_load(riscvlint_state *state, const cs_insn *insn,
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
        if (!sl->held || sl->data != data) continue;
        if (sl->base != base || sl->disp != off) continue;
        // Two ways the register can already hold what this load would
        // put in it, and both have to be exact rather than merely
        // likely. The same load again recomputes the same value from
        // the same bytes, whatever its width. A store back is exact
        // only at the full width: `sw a0,K(sp)` then `lw a0,K(sp)`
        // leaves a0 sign-extended from bit 31, which is a0 again only
        // if it was already, and that is a fact about the value rather
        // than about the two encodings.
        if (sl->kind != kind &&
            !(sl->kind == RV_MEM_SD && kind == RV_MEM_LD))
            continue;

        finding->title = "load of a value the register still holds";
        finding->address = insn->address;
        finding->insn_count = 1;
        // Which of the two shapes it was is worth printing rather
        // than leaving to whoever reads the disassembly: they come from
        // different mistakes, and their populations are nothing alike.
        snprintf(finding->replacement, sizeof finding->replacement,
                 "delete; %s still holds %" PRId64 "(%s) from the %s at "
                 "0x%" PRIx64 " (%u bytes)", rv_reg_name(data), off,
                 rv_reg_name(base), rv_mem_is_store(sl->kind) ? "store"
                                                              : "load",
                 sl->addr, insn->size);
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

bool check_silent_store(riscvlint_state *state, const cs_insn *insn,
                        riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w, insn->size, &kind, &data, &base, &off)) return false;
    if (!rv_mem_is_store(kind) || rv_mem_is_fp(kind)) return false;
    if (base != 2 && base != 8) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    unsigned width = mem_width(kind);
    // The same instruction is check_dead_store's finding wherever an
    // unread store to the same bytes is still on the record: that check
    // deletes the first store of the pair and this one would delete the
    // second, for the same saving. One rewrite per site, and the older
    // check keeps it. The condition is that check's own, branch-target
    // test included, so this stands down exactly where it fires.
    if (!riscvlint_is_branch_target(state, insn->address))
        for (int i = 0; i < state->win.nslots; i++) {
            const rvl_slot *sl = &state->win.slots[i];
            if (sl->unread && sl->base == base && sl->disp == off &&
                sl->width == width)
                return false;
        }

    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        // An f register and an x register with the same number are two
        // registers, and `data` alone cannot tell them apart.
        if (rv_mem_is_fp(sl->kind)) continue;
        if (!sl->held || sl->data != data) continue;
        if (sl->base != base || sl->disp != off || sl->width != width)
            continue;
        // A store of x0 over a slot a *store* of x0 armed is a finding:
        // x0 cannot change, so the bytes are still zero. Over a slot a
        // load armed it is not -- `ld x0,K(sp)` is a legal no-op that
        // puts nothing anywhere, and the record would be claiming that
        // x0 holds what is at K(sp). The neighbouring checks refuse
        // every x0 record for a different reason; this one has to
        // distinguish them.
        if (data == 0 && !rv_mem_is_store(sl->kind)) continue;
        // The record's kind is not consulted, and this is the one window
        // check where it must not be. Its neighbours claim something
        // about the register a load produced, where `lb` and `lbu` are
        // the same bytes and not the same value; this claims something
        // about the bytes, which do not record how they were read. A
        // slot armed by `lwu a0,K(sp)` is written back unchanged by
        // `sw a0,K(sp)` exactly as one armed by `lw`.
        finding->title = "store of a value the slot already holds";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "delete; %" PRId64 "(%s) already holds %s from the %s at "
                 "0x%" PRIx64 " (%u bytes)", off, rv_reg_name(base),
                 rv_reg_name(data), rv_mem_is_store(sl->kind) ? "store"
                                                              : "load",
                 sl->addr, insn->size);
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

// ---- a computation a live register already holds ----

bool check_comp_remat(riscvlint_state *state, const cs_insn *insn,
                      riscvlint_finding *finding)
{
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(state->handle, insn, rr, &nr, rw, &nw) != CS_ERR_OK)
        return false;
    if (nw != 1) return false;
    rvl_comp key;
    unsigned rd;
    if (!comp_key(insn, nw, cs_reg_to_num(rw[0]), &rd, &key)) return false;
    // sp, gp and tp hold what the ABI says they hold rather than a value
    // a region computed, and the one shape that writes sp this way --
    // `addi sp,s0,-K` restoring a frame that never moved -- is
    // check_redundant_sp_restore's finding, which says why. Excluding
    // them here is what keeps the two checks off each other's sites: 27
    // of ripgrep's 646 probe sites write one of the three, and 26 of
    // those are already reported as that restore.
    if (rd == 2 || rd == 3 || rd == 4) return false;
    // A relocated immediate is a placeholder the linker fills, so two
    // instructions carrying it are not yet known to compute the same
    // value.
    if (riscvlint_is_relocated(state, insn->address)) return false;

    // The destination register first. Where it already holds the value,
    // the instruction goes away instead of turning into a move, which
    // is worth more -- and worth more than whatever a scan in register
    // order would have found first.
    const rvl_comp *own = &state->win.comp[rd];
    if (own->live && comp_same(own, &key)) {
        finding->title = "computation a live register already holds";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "delete; %s already holds this from 0x%" PRIx64 " (%u bytes)",
                 rv_reg_name(rd), own->addr, insn->size);
        return true;
    }

    // Anywhere else the rewrite is `c.mv rd,r`, which names any two
    // non-zero registers and costs two bytes. Against a computation
    // already spelled in two it saves nothing and trades an instruction
    // that depends on nothing for one that depends on another register
    // -- the same trade check_const_remat declines inside c.li's range,
    // and 9,622 of the 39,274 sites in the corpus.
    if (insn->size != 4) return false;
    for (unsigned r = 1; r < 32; r++) {
        if (r == rd || !state->win.comp[r].live) continue;
        if (!comp_same(&state->win.comp[r], &key)) continue;
        finding->title = "computation a live register already holds";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "mv %s, %s; computed at 0x%" PRIx64 " (4 -> %u bytes)",
                 rv_reg_name(rd), rv_reg_name(r), state->win.comp[r].addr,
                 mv_bytes());
        return true;
    }
    return false;
}

// ---- a comparison a branch could have made ----

static const char *branch_name(unsigned funct3, unsigned rs2)
{
    if (rs2 == 0 && funct3 == 0) return "beqz";
    if (rs2 == 0 && funct3 == 1) return "bnez";
    switch (funct3) {
    case 0: return "beq";
    case 1: return "bne";
    case 4: return "blt";
    case 5: return "bge";
    case 6: return "bltu";
    default: return "bgeu";
    }
}

// Which branch absorbs this condition, given whether the test was
// `bnez` (the condition held) or `beqz` (it did not).
static unsigned folded_funct3(rv_cond_kind kind, bool on_nonzero)
{
    switch (kind) {
    case RV_COND_SLT:  return on_nonzero ? 4u : 5u;    // blt  : bge
    case RV_COND_SLTU: return on_nonzero ? 6u : 7u;    // bltu : bgeu
    case RV_COND_EQ:   return on_nonzero ? 1u : 0u;    // bne  : beq
    case RV_COND_SEQZ: return on_nonzero ? 0u : 1u;    // beqz : bnez
    default:           return on_nonzero ? 1u : 0u;    // snez: bnez : beqz
    }
}

bool check_cond_to_branch(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd, a, b;
    rv_cond_kind kind;
    if (!rv_decode_condition(w1, insn->size, &rd, &a, &b, &kind)) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned brs1, brs2, bf3;
    int64_t off;
    if (!rv_decode_cond_branch(w2, len2, &brs1, &brs2, &bf3, &off))
        return false;
    // The branch has to be the zero test of the condition: `beqz rd` or
    // `bnez rd`, in either operand order.
    if (bf3 != 0u && bf3 != 1u) return false;
    unsigned tested;
    if (brs2 == 0) tested = brs1;
    else if (brs1 == 0) tested = brs2;
    else return false;
    if (tested != rd) return false;

    // Folding deletes the comparison, so the branch must not be somewhere
    // else can arrive at with rd set by something other than what
    // precedes it here.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The rewrite reads a and b at the branch instead of at the
    // comparison, which is the same value only if nothing between them
    // wrote either -- and nothing is between them.
    //
    // The condition register has to be dead on *both* successors. A scan
    // can see the fall-through and not the taken path, which is where
    // half of the raw population turns out to be live.
    uint64_t fallthrough = second + len2;
    uint64_t taken = second + (uint64_t)off;
    if (riscvlint_liveness(state, fallthrough, rd) != RISCVLINT_LIVE_DEAD)
        return false;
    if (riscvlint_liveness(state, taken, rd) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned f3 = folded_funct3(kind, bf3 == 1u);
    unsigned ra = a, rb = (kind == RV_COND_SEQZ || kind == RV_COND_SNEZ) ? 0 : b;
    unsigned before = insn->size + len2;
    // The branch keeps its own displacement, so its reach is unchanged;
    // only the two bytes the comparison took can go, plus whatever the
    // folded branch gives back if it cannot take the compressed form the
    // original had.
    unsigned after = rv_branch_encoded_size(f3, ra, rb, off);

    finding->title = "comparison a branch could have made";
    finding->address = insn->address;
    finding->insn_count = 2;
    if (rb == 0 && (f3 == 0u || f3 == 1u))
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, 0x%" PRIx64 " (%u -> %u bytes)",
                 branch_name(f3, rb), rv_reg_name(ra), taken, before, after);
    else
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, %s, 0x%" PRIx64 " (%u -> %u bytes)",
                 branch_name(f3, rb), rv_reg_name(ra), rv_reg_name(rb),
                 taken, before, after);
    return true;
}

// ---- a conditional branch over an unconditional jump ----

bool check_branch_over_jump(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rs1, rs2, f3;
    int64_t boff;
    if (!rv_decode_cond_branch(w1, insn->size, &rs1, &rs2, &f3, &boff))
        return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned jsize = (w2 & 3u) == 3u ? 4u : 2u;
    unsigned jrd;
    int64_t joff;
    // `jal ra,X` would stop writing the link register if it went, so
    // only the x0 link is a jump this can delete.
    if (!rv_decode_jump(w2, jsize, &jrd, &joff) || jrd != 0) return false;

    // The branch has to clear exactly the jump: its target is the
    // instruction the jump would fall through to.
    if ((int64_t)insn->address + boff != (int64_t)second + (int64_t)jsize)
        return false;

    // Something branching to the jump loses its transfer when it goes.
    if (riscvlint_is_branch_target(state, second)) return false;

    // An unlinked object leaves both displacements as placeholders, so
    // the shape is an artefact of the relocations rather than the code.
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    int64_t target = (int64_t)second + joff;
    // Where the jump goes exactly where the branch already goes, both
    // paths already meet and the pair is dead rather than foldable.
    // check_transfer_to_next has the jump.
    if (target == (int64_t)insn->address + boff) return false;

    int64_t reach = target - (int64_t)insn->address;
    if (reach < -4096 || reach > 4094 || (reach & 1)) return false;

    // beq/bne, blt/bge and bltu/bgeu are each other with the low bit of
    // funct3 flipped, so every conditional branch inverts.
    unsigned inv = f3 ^ 1u;
    // Priced at the branch's own encoding class. Asking
    // rv_branch_encoded_size of a four-byte branch could answer two --
    // Go leaves compressible branches wide -- and that saving is the
    // compression check's, not this one's.
    unsigned nbr = insn->size == 2
                       ? rv_branch_encoded_size(inv, rs1, rs2, reach)
                       : 4u;
    unsigned before = insn->size + jsize;

    finding->title = "conditional branch over an unconditional jump";
    finding->address = insn->address;
    finding->insn_count = 2;
    const char *name = branch_name(inv, rs2);
    if (rs2 == 0 && (inv == 0u || inv == 1u))
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, 0x%" PRIx64 " (%u -> %u bytes)", name,
                 rv_reg_name(rs1), (uint64_t)target, before, nbr);
    else
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, %s, 0x%" PRIx64 " (%u -> %u bytes)", name,
                 rv_reg_name(rs1), rv_reg_name(rs2), (uint64_t)target,
                 before, nbr);
    return true;
}

// ---- a transfer to the instruction that follows it ----

bool check_transfer_to_next(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;

    unsigned rs1, rs2, f3, rd;
    int64_t off;
    const char *what;
    if (rv_decode_cond_branch(w, insn->size, &rs1, &rs2, &f3, &off))
        what = "branch";
    else if (rv_decode_jump(w, insn->size, &rd, &off) && rd == 0)
        what = "jump";
    else
        return false;
    if ((int64_t)insn->address + off != (int64_t)(insn->address + insn->size))
        return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    finding->title = "transfer to the instruction that follows it";
    finding->address = insn->address;
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "delete; the %s goes where control already goes (%u bytes)",
             what, insn->size);
    return true;
}

// ---- a run of zero stores one wider store would do ----

// The store of x0 covering `bytes` bytes at `off`, priced at the
// smallest base-C encoding that can hold it.
static unsigned zrun_cost(unsigned bytes, unsigned base, int64_t off)
{
    rv_mem_kind k = bytes == 8 ? RV_MEM_SD : bytes == 4 ? RV_MEM_SW
                    : bytes == 2 ? RV_MEM_SH : RV_MEM_SB;
    return rv_mem_encoded_size(k, 0, base, off, false);
}

// The cheapest cover of [lo,hi) by naturally aligned stores: the widest
// whose alignment the offset satisfies, repeatedly. Greedy from the low
// end is minimal, since every width is a power of two and each one has
// to start on its own multiple. Returns how many stores it takes and
// writes their encoded bytes to *cost -- one walk for both, so the
// count and the price cannot drift apart.
//
// The offsets are signed and C truncates toward zero, but `pos % w == 0`
// is still exactly "w divides pos", which is all the test asks.
static int zrun_cover(int64_t lo, int64_t hi, unsigned base, unsigned *cost)
{
    int n = 0;
    *cost = 0;
    for (int64_t pos = lo; pos < hi; ) {
        int64_t w = 8;
        while (w > 1 && (pos % w != 0 || pos + w > hi)) w /= 2;
        n++;
        *cost += zrun_cost((unsigned)w, base, pos);
        pos += w;
    }
    return n;
}

// A store of x0 to a frame slot at `addr`, decoded from the raw
// halfwords rather than from capstone, because the run is walked ahead
// of the driver's own cursor.
static bool zrun_store(const riscvlint_state *state, uint64_t addr,
                       unsigned *size, unsigned *base, int64_t *off,
                       unsigned *width)
{
    uint32_t w;
    if (!riscvlint_word_at(state, addr, &w)) return false;
    unsigned sz = (w & 3u) == 3u ? 4u : 2u;
    rv_mem_kind kind;
    unsigned data, b;
    int64_t o;
    if (!rv_decode_mem(w, sz, &kind, &data, &b, &o)) return false;
    // A floating-point store names f0 rather than x0 with the same
    // field, and f0 is a value rather than a zero.
    if (!rv_mem_is_store(kind) || rv_mem_is_fp(kind) || data != 0)
        return false;
    // sp and fp are the two bases whose alignment the ABI fixes, which
    // is what lets the offset decide whether the merged store is
    // naturally aligned. Through any other base the encoding says
    // nothing about alignment, and a byte-at-a-time store may be the
    // deliberate choice rather than the missed one.
    if (b != 2 && b != 8) return false;
    if (riscvlint_is_relocated(state, addr)) return false;
    *size = sz;
    *base = b;
    *off = o;
    *width = mem_width(kind);
    return true;
}

bool check_zero_store_run(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (insn->address < state->zrun_end) return false;

    unsigned size, base, width;
    int64_t off;
    if (!zrun_store(state, insn->address, &size, &base, &off, &width))
        return false;

    int64_t lo = off, hi = off + width;
    unsigned n = 1;
    // Both sides are priced at the best encoding the base C extension
    // offers rather than at the bytes the binary happens to carry, which
    // is what keeps this check off check_c_compressible's ground: where
    // a run is left wide on a toolchain that does not compress,
    // shrinking it is already that check's finding, and what is left
    // here is only what merging saves on top. For a run with no missed
    // compression in it -- most of them, since `sb zero` and `sh zero`
    // have no compressed spelling at all -- the two agree and the
    // finding matches the disassembly byte for byte.
    unsigned bytes = zrun_cost(width, base, off);
    uint64_t at = insn->address + size;
    for (;;) {
        // A side entry inside the run would reach the merged store
        // having skipped the ones before it, and the merged store
        // writes all of them.
        if (riscvlint_is_branch_target(state, at)) break;
        unsigned s2, b2, w2;
        int64_t o2;
        if (!zrun_store(state, at, &s2, &b2, &o2, &w2) || b2 != base) break;
        // Only a range the run covers without a gap can be stood in for,
        // and it may grow at either end.
        if (o2 == hi) hi = o2 + w2;
        else if (o2 + w2 == lo) lo = o2;
        else break;
        n++;
        bytes += zrun_cost(w2, b2, o2);
        at += s2;
    }
    state->zrun_end = at;
    if (n < 2) return false;

    unsigned cost;
    int k = zrun_cover(lo, hi, base, &cost);
    // The first test is what the finding claims and the second is its
    // price. The first never decides on its own: the run's own stores
    // are already a cover of the range, so an aligned cover that costs
    // less than they do is necessarily a shorter one -- and where the
    // run is misaligned enough that the aligned cover is *longer*, it
    // costs more as well. It stays because it says what the rewrite
    // does, and because a later change to the pricing would need it.
    if ((unsigned)k >= n || cost >= bytes) return false;

    finding->title = "run of zero stores one wider store would do";
    finding->address = insn->address;
    finding->insn_count = n;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%d instead of %u stores for %" PRId64 " bytes at %" PRId64
             "(%s) (%u -> %u bytes)", k, n, hi - lo, lo, rv_reg_name(base),
             bytes, cost);
    return true;
}

// ---- a bit-cast routed through a frame slot ----

// The move that does in one instruction, and without touching memory,
// what a store and a load through the same slot do between the two
// register files. The pairing has to be exact on width and on what the
// load does with the bits: `fmv.x.w` sign-extends the 32 it moves, and
// so does `lw`, but `lwu` does not -- so `fsw` and `lwu` is not one of
// these.
static const char *bitcast_form(rv_mem_kind held, rv_mem_kind ld)
{
    switch (held) {
    case RV_MEM_FSD: case RV_MEM_FLD:
        return ld == RV_MEM_LD ? "fmv.x.d" : NULL;
    case RV_MEM_FSW: case RV_MEM_FLW:
        return ld == RV_MEM_LW ? "fmv.x.w" : NULL;
    case RV_MEM_SD: case RV_MEM_LD:
        return ld == RV_MEM_FLD ? "fmv.d.x" : NULL;
    case RV_MEM_SW: case RV_MEM_LW:
        return ld == RV_MEM_FLW ? "fmv.w.x" : NULL;
    default:
        return NULL;
    }
}

bool check_bitcast_through_frame(riscvlint_state *state, const cs_insn *insn,
                                 riscvlint_finding *finding)
{
    // None of these moves has a compressed spelling, so a two-byte load
    // would grow by two. What the rewrite buys is the memory access, and
    // this is the one check here that will not pay bytes for it: 869 of
    // the 2,380 sites in the corpus are a `c.ldsp` or a `c.fldsp` and
    // are refused. See TODO.md.
    if (insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w, insn->size, &kind, &data, &base, &off)) return false;
    if (rv_mem_is_store(kind)) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    for (int i = 0; i < state->win.nslots; i++) {
        const rvl_slot *sl = &state->win.slots[i];
        if (!sl->held) continue;
        if (sl->base != base || sl->disp != off) continue;
        // bitcast_form pairs a record with a load only across the two
        // files, so it is the one place that decides: a same-file pair
        // is check_store_to_load's site or check_redundant_reload's and
        // gets no spelling here.
        const char *name = bitcast_form(sl->kind, kind);
        // A slot can carry a record per kind, so a width that does not
        // line up is another record's business rather than the end of
        // the search.
        if (!name) continue;

        finding->title = "bit-cast routed through a frame slot";
        finding->address = insn->address;
        finding->insn_count = 1;
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s %s, %s; drops the load, %s at 0x%" PRIx64
                 " (4 -> 4 bytes)", name,
                 rv_mem_is_fp(kind) ? rv_freg_name(data) : rv_reg_name(data),
                 rv_mem_is_fp(kind) ? rv_reg_name(sl->data)
                                    : rv_freg_name(sl->data),
                 rv_mem_is_store(sl->kind) ? "stored" : "loaded", sl->addr);
        return true;
    }
    return false;
}

// ---- a four-byte encoding the base C extension spells in two ----

bool check_c_compressible(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_C)) return false;
    if (insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    char form[24];
    if (!rv_c_form(w, insn->size, form, sizeof form)) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    finding->title = "instruction compressible to a base C form";
    finding->address = insn->address;
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s (4 -> 2 bytes)", form);
    return true;
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

// ---- constant-chain decoding, shared by -c and the popcount
//      matcher ----

// One step of a chain: `addi`/`addiw`/`slli` reading a register whose
// chain is in flight. `reg` is the one read and `dst` the one written,
// and they need not be the same -- the allocator writes the finished
// constant somewhere else whenever the partial value is still live,
// and requiring `rd == rs1` lost 46% of the chains in libLLVM's
// baseline build. The transform is left to the caller to apply, since
// which chain this extends is not a property of the instruction.
//
// `addi rd,rd,imm` and `c.addi` are the same step; so are `slli` and
// `c.slli`, which rv_decode_slli already folds together. `addiw` is
// its own case because it truncates, and that truncation is exactly
// what RISCVMatInt uses it for.
typedef struct {
    unsigned reg;       // the register read: whose chain this extends
    unsigned dst;       // the register written, which may be another
    bool shift;         // slli, rather than an addition
    unsigned shamt;
    int64_t imm;
    bool w_form;        // addiw: the result is sign-extended from bit 31
} cchain_step;

static bool cchain_step_of(uint32_t w, unsigned size, cchain_step *st)
{
    unsigned rd, rs1, shamt;
    int64_t imm;
    if (rv_decode_slli(w, size, &rd, &rs1, &shamt)) {
        st->reg = rs1;
        st->dst = rd;
        st->shift = true;
        st->shamt = shamt;
        return true;
    }
    bool w_form;
    if (size == 4) {
        unsigned op = RV_OPCODE(w);
        if ((op != 0x13u && op != 0x1bu) || ((w >> 12) & 0x7u) != 0)
            return false;
        w_form = op == 0x1bu;
        rd = (w >> 7) & 0x1fu;
        rs1 = (w >> 15) & 0x1fu;
        imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
    } else if (size == 2) {
        // c.addi is op 01 funct3 000; c.addiw is op 01 funct3 001. Both
        // read and write the same register, and a zero immediate is a
        // hint rather than an addition.
        if ((w & 0xe003u) == 0x0001u) w_form = false;
        else if ((w & 0xe003u) == 0x2001u) w_form = true;
        else return false;
        rd = rs1 = (w >> 7) & 0x1fu;
        imm = ci_imm6(w);
        if (rd == 0 || imm == 0) return false;
    } else {
        return false;
    }
    st->reg = rs1;
    st->dst = rd;
    st->shift = false;
    st->imm = imm;
    st->w_form = w_form;
    return true;
}

// A composition: `add` or `or` of two registers that both hold chains
// in flight. Unlike a step there is no ambiguity about what this does
// -- the sum or union of two known constants is a constant whatever
// else is true -- which is why it may close both sources where the
// cross-register step has to leave its one open.
//
// This is how RISCVMatInt joins the halves of a 64-bit value, and
// without it a 64-bit constant surfaces as its shifted high half:
// `0x5555555500000000` appeared 2,867 times in libxul where the value
// being built was `0x5555555555555555`.
typedef struct {
    unsigned dst, a, b;
    bool is_or;
} cchain_merge;

static bool cchain_merge_of(uint32_t w, unsigned size, cchain_merge *m)
{
    if (size == 4) {
        if (RV_OPCODE(w) != 0x33u) return false;
        if (((w >> 25) & 0x7fu) != 0u) return false;    // funct7 0: not M
        unsigned f3 = (w >> 12) & 0x7u;
        if (f3 != 0u && f3 != 6u) return false;         // add, or
        m->is_or = f3 == 6u;
        m->dst = (w >> 7) & 0x1fu;
        m->a = (w >> 15) & 0x1fu;
        m->b = (w >> 20) & 0x1fu;
        return m->dst != 0 && m->a != 0 && m->b != 0;
    }
    if (size != 2) return false;
    // c.add rd,rs2 -- op 10, funct3 100, bit 12 set.
    if ((w & 0xf003u) == 0x9002u) {
        m->dst = m->a = (w >> 7) & 0x1fu;
        m->b = (w >> 2) & 0x1fu;
        m->is_or = false;
        return m->dst != 0 && m->b != 0;
    }
    // c.or rd',rs2' -- op 01, funct3 100, bit 12 clear, bits 11:10 set,
    // bits 6:5 == 10. c.and, c.xor and c.sub share the shape and are
    // separated by those two bits.
    if ((w & 0xfc63u) == 0x8c41u) {
        m->dst = m->a = 8u + ((w >> 7) & 7u);
        m->b = 8u + ((w >> 2) & 7u);
        m->is_or = true;
        return true;
    }
    return false;
}

static void cchain_apply(const cchain_step *st, int64_t *val)
{
    if (st->shift) {
        *val = (int64_t)((uint64_t)*val << st->shamt);
        return;
    }
    uint64_t sum = (uint64_t)*val + (uint64_t)st->imm;
    *val = st->w_form ? (int64_t)(int32_t)(uint32_t)sum : (int64_t)sum;
}

// ---- an address computed for one indexed load ----
//
// See riscvlint.h for what Zilx is and why only the unscaled shape is
// reported.

// The indexed mnemonic for a load kind, or NULL where Zilx has none.
// Byte loads exist only in scaled form, whose scale factor is 1, so
// they fold here with identical arithmetic.
static const char *zilx_name(rv_mem_kind kind)
{
    switch (kind) {
    case RV_MEM_LB:  return "lxsb";
    case RV_MEM_LBU: return "lxsbu";
    case RV_MEM_LH:  return "lxh";
    case RV_MEM_LHU: return "lxhu";
    case RV_MEM_LW:  return "lxw";
    case RV_MEM_LWU: return "lxwu";
    case RV_MEM_LD:  return "lxd";
    default:         return NULL;   // stores, and the FP loads
    }
}

bool check_indexed_load(riscvlint_state *state, const cs_insn *insn,
                        riscvlint_finding *finding)
{
    // Positively present, not merely un-denied. riscvlint_may_use
    // answers true when an object declares no attributes, because
    // "absent" must not silence a check on the code it exists for; that
    // rule assumes the extension is one some target plausibly has. Zilx
    // is in no profile and in no shipping core, so defaulting to
    // permissive would put 3,528 findings on the Go objects suggesting
    // an instruction nobody can execute. It fires when the object
    // declares `_zilx` or when `-m zilx` asks the what-if, and
    // otherwise not at all.
    //
    // The three Zilx checks and check_const_eq_branch are the only ones
    // that read the set this way; every other gate is riscvlint_may_use.
    if (!(riscvlint_state_extensions(state) & RISCVLINT_EXT_ZILX))
        return false;
    // An `add` a deeper fold has already turned into one `lxs*`. Both
    // of those shapes start earlier than this one, so they have been
    // judged by the time the cursor arrives here. See `zilx_folded`.
    if (insn->address == state->zilx_folded) return false;
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd, rb, ri;
    if (!rv_decode_add(w1, insn->size, &rd, &rb, &ri)) return false;
    // x0 anywhere makes this a move rather than an address: `add rd,rs,x0`
    // has nothing to index by, and a write to x0 computes nothing.
    if (rd == 0 || rb == 0 || ri == 0) return false;
    // sp, gp and tp hold what the ABI says they hold and are never dead,
    // so folding the write away is not on offer. The same rule the
    // immediate-offset fold applies.
    if (rd == 2 || rd == 3 || rd == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w2, len2, &kind, &data, &base, &off)) return false;
    if (base != rd || off != 0) return false;
    const char *name = zilx_name(kind);
    if (!name) return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The fold stops writing rd. A load into the address register kills
    // it by construction -- `add a0,a0,a1` then `ld a0,0(a0)` -- and
    // everything else has to be proved, by the same walk and with the
    // same answer-or-decline the immediate-offset fold uses.
    if (data != rd &&
        riscvlint_liveness(state, second + len2, rd) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2;
    finding->title = "address computed for one indexed load";
    finding->address = insn->address;
    finding->insn_count = 2;
    // base+index is symmetric in the unscaled form, so which operand of
    // the `add` is called the base does not change the address. They are
    // named in the order the `add` wrote them.
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, (%s), %s (%u -> 4 bytes)", name, rv_reg_name(data),
             rv_reg_name(rb), rv_reg_name(ri), before);
    return true;
}

// ---- an address scaled for one indexed load ----
//
// See riscvlint.h for the shape, why the shift must agree with the
// access width, and why this one tells the unscaled check to be quiet.

// The scaled indexed mnemonic for a load kind, and the shift amount the
// scaled form implies -- log2 of the access size and nothing else.
// Byte loads scale by 1, so their shift is zero, there is no `slli` to
// fold, and that site is the unscaled check's.
static const char *zilx_scaled_name(rv_mem_kind kind, unsigned *shamt)
{
    switch (kind) {
    case RV_MEM_LH:  *shamt = 1; return "lxsh";
    case RV_MEM_LHU: *shamt = 1; return "lxshu";
    case RV_MEM_LW:  *shamt = 2; return "lxsw";
    case RV_MEM_LWU: *shamt = 2; return "lxswu";
    case RV_MEM_LD:  *shamt = 3; return "lxsd";
    default:         return NULL;   // bytes, stores, and the FP loads
    }
}

bool check_scaled_indexed_load(riscvlint_state *state, const cs_insn *insn,
                               riscvlint_finding *finding)
{
    // Positively present, not merely un-denied, for the reason
    // check_indexed_load states at length.
    if (!(riscvlint_state_extensions(state) & RISCVLINT_EXT_ZILX))
        return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rt, ri, shamt;
    if (!rv_decode_slli(w1, insn->size, &rt, &ri, &shamt)) return false;
    // x0 is not a shift destination, a shift by nothing is a hint
    // rather than a scale, and x0 indexes nothing.
    if (rt == 0 || ri == 0 || shamt == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd, ars1, ars2;
    if (!rv_decode_add(w2, len2, &rd, &ars1, &ars2)) return false;
    if (rd == 0) return false;
    // The add must read the shifted register exactly once. `add rd,rt,rt`
    // doubles the shifted value, which is a wider shift and not this
    // rewrite, and it leaves no second operand to call the base.
    bool a_is_shift = ars1 == rt, b_is_shift = ars2 == rt;
    if (a_is_shift == b_is_shift) return false;
    unsigned rb = a_is_shift ? ars2 : ars1;
    if (rb == 0) return false;

    uint64_t third = second + len2;
    uint32_t w3;
    if (!riscvlint_word_at(state, third, &w3)) return false;
    unsigned len3 = rv_insn_len(w3);
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w3, len3, &kind, &data, &base, &off)) return false;
    if (base != rd || off != 0) return false;
    unsigned want;
    const char *name = zilx_scaled_name(kind, &want);
    // The scale is the access width, so a shift that disagrees with it
    // is some other computation and folding it would change the
    // address. This is the condition the population depends on.
    if (!name || shamt != want) return false;

    // sp, gp and tp hold what the ABI says they hold and are never
    // dead, so folding either write away is not on offer. Both of this
    // fold's writes are subject to it, unlike the unscaled shape's one.
    if (rd == 2 || rd == 3 || rd == 4) return false;
    if (rt == 2 || rt == 3 || rt == 4) return false;

    // Three instructions means two interior addresses something could
    // branch to, and either one makes the triple not a straight line.
    if (riscvlint_is_branch_target(state, second) ||
        riscvlint_is_branch_target(state, third))
        return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second) ||
        riscvlint_is_relocated(state, third))
        return false;

    // The fold stops writing both the shifted index and the address.
    // Each is killed by construction where a later instruction of the
    // triple overwrites it -- the add over the shift, the load over
    // either -- and everything else is proved or declined.
    uint64_t after = third + len3;
    if (data != rd &&
        riscvlint_liveness(state, after, rd) != RISCVLINT_LIVE_DEAD)
        return false;
    if (rt != rd && data != rt &&
        riscvlint_liveness(state, after, rt) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2 + len3;
    finding->title = "address scaled for one indexed load";
    finding->address = insn->address;
    finding->insn_count = 3;
    // Unlike the unscaled form this is not symmetric: the scale applies
    // to the index and not to the base, so which register goes in the
    // parentheses is decided by which one the slli shifted.
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, (%s), %s (%u -> 4 bytes)", name, rv_reg_name(data),
             rv_reg_name(rb), rv_reg_name(ri), before);
    // The add is the unscaled check's match too, and one site is one
    // rewrite rather than two.
    state->zilx_folded = second;
    return true;
}

// ---- an address scaled from a zero-extended index ----
//
// See riscvlint.h for the shape and for why the `srli` amount is what
// decides both the scale and whether this is an array index at all.

// The zero-extending indexed mnemonic for a load kind, and the scale
// the form implies -- log2 of the access size, exactly as the plain
// scaled mode. The `srli` that follows a `slli ...,32` shifts right by
// 32 minus that, so a byte load's pair is `zext.w` itself.
static const char *zilx_zext_name(rv_mem_kind kind, unsigned *scale)
{
    switch (kind) {
    case RV_MEM_LB:  *scale = 0; return "lxsuwb";
    case RV_MEM_LBU: *scale = 0; return "lxsuwbu";
    case RV_MEM_LH:  *scale = 1; return "lxsuwh";
    case RV_MEM_LHU: *scale = 1; return "lxsuwhu";
    case RV_MEM_LW:  *scale = 2; return "lxsuww";
    case RV_MEM_LWU: *scale = 2; return "lxsuwwu";
    case RV_MEM_LD:  *scale = 3; return "lxsuwd";
    default:         return NULL;   // stores, and the FP loads
    }
}

bool check_zext_indexed_load(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding)
{
    // Positively present, not merely un-denied, for the reason
    // check_indexed_load states at length.
    if (!(riscvlint_state_extensions(state) & RISCVLINT_EXT_ZILX))
        return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rt1, ri, sh1;
    if (!rv_decode_slli(w1, insn->size, &rt1, &ri, &sh1)) return false;
    // Only 32. The zero-extension is from bit 31 and nothing else, so a
    // different left shift is a different value however the right shift
    // that follows it is spelled.
    if (sh1 != 32 || rt1 == 0 || ri == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rt2, srs, sh2;
    if (!rv_decode_srli(w2, len2, &rt2, &srs, &sh2)) return false;
    // It has to be this slli's result being shifted back, and srli
    // rather than srai: the value is zero-extended, not sign-extended.
    if (srs != rt1 || rt2 == 0) return false;

    uint64_t third = second + len2;
    uint32_t w3;
    if (!riscvlint_word_at(state, third, &w3)) return false;
    unsigned len3 = rv_insn_len(w3);
    unsigned rd, ars1, ars2;
    if (!rv_decode_add(w3, len3, &rd, &ars1, &ars2)) return false;
    if (rd == 0) return false;
    // Read exactly once, for the reason the scaled check gives.
    bool a_is_idx = ars1 == rt2, b_is_idx = ars2 == rt2;
    if (a_is_idx == b_is_idx) return false;
    unsigned rb = a_is_idx ? ars2 : ars1;
    if (rb == 0) return false;

    uint64_t fourth = third + len3;
    uint32_t w4;
    if (!riscvlint_word_at(state, fourth, &w4)) return false;
    unsigned len4 = rv_insn_len(w4);
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (!rv_decode_mem(w4, len4, &kind, &data, &base, &off)) return false;
    if (base != rd || off != 0) return false;
    unsigned scale;
    const char *name = zilx_zext_name(kind, &scale);
    // The right shift carries the scale, and the scale is the access
    // width: `slli x,32` + `srli x,28` scales by 16, which is a stride
    // through 16-byte structures and not something a load width can
    // name. That shape is most of what reaches here -- 10,133 sites in
    // debian-libllvm22 at `srli 28` alone -- so without this test the
    // check would read more than three times its real population.
    if (!name || sh2 != 32 - scale) return false;

    // sp, gp and tp hold what the ABI says they hold and are never
    // dead. Three writes are on offer here, so the test covers all of
    // them.
    if (rd == 2 || rd == 3 || rd == 4) return false;
    if (rt1 == 2 || rt1 == 3 || rt1 == 4) return false;
    if (rt2 == 2 || rt2 == 3 || rt2 == 4) return false;

    // Four instructions means three interior addresses, any one of
    // which being a branch target makes this not a straight line.
    if (riscvlint_is_branch_target(state, second) ||
        riscvlint_is_branch_target(state, third) ||
        riscvlint_is_branch_target(state, fourth))
        return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second) ||
        riscvlint_is_relocated(state, third) ||
        riscvlint_is_relocated(state, fourth))
        return false;

    // Three writes disappear rather than the scaled shape's two: the
    // widened index, the narrowed index and the address. Each is killed
    // by construction wherever a later instruction of the quad
    // overwrites it, and the rest is the walk's to prove. The common
    // case writes one register throughout -- `slli a5,a5,32` +
    // `srli a5,a5,29` + `add a5,a0,a5` + `ld a5,0(a5)` -- and needs no
    // walk at all.
    uint64_t after = fourth + len4;
    if (data != rd &&
        riscvlint_liveness(state, after, rd) != RISCVLINT_LIVE_DEAD)
        return false;
    if (rt2 != rd && data != rt2 &&
        riscvlint_liveness(state, after, rt2) != RISCVLINT_LIVE_DEAD)
        return false;
    if (rt1 != rt2 && rt1 != rd && data != rt1 &&
        riscvlint_liveness(state, after, rt1) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2 + len3 + len4;
    finding->title = "address scaled from a zero-extended index";
    finding->address = insn->address;
    finding->insn_count = 4;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, (%s), %s (%u -> 4 bytes)", name, rv_reg_name(data),
             rv_reg_name(rb), rv_reg_name(ri), before);
    // The add is the unscaled check's match too. See `zilx_folded`.
    state->zilx_folded = third;
    return true;
}

// ---- a bit count spelled out longhand ----
//
// See riscvlint.h for what the sequence is and why this is matched as
// dataflow rather than as a window.

// Where in the expansion a register's value sits. The order is the
// order TargetLowering::expandCTPOP emits, and nothing but a complete
// walk from PC_SHR1 to PC_MUL produces a finding.
enum {
    PC_NONE = 0,
    PC_SHR1,        // x >> 1
    PC_AND55,       // (x >> 1) & 0x5555...
    PC_STAGE1,      // x - ((x >> 1) & 0x5555...)
    PC_AND33,       // stage1 & 0x3333...
    PC_SHR2,        // stage1 >> 2
    PC_AND33S,      // (stage1 >> 2) & 0x3333...
    PC_STAGE2,      // the sum of those two
    PC_SHR4,        // stage2 >> 4
    PC_SUM4,        // stage2 + (stage2 >> 4)
    PC_STAGE3,      // that & 0x0f0f...
    PC_MUL,         // stage3 * 0x0101...
};

// The four masks, in both widths. A sequence may not mix them: the
// 32-bit form ends in a shift of 24 and the 64-bit form in 56, and the
// masks and the shift are checked together.
#define PC_M55_W 0x55555555ll
#define PC_M33_W 0x33333333ll
#define PC_M0F_W 0x0f0f0f0fll
#define PC_M01_W 0x01010101ll
#define PC_M55_D ((int64_t)0x5555555555555555ull)
#define PC_M33_D ((int64_t)0x3333333333333333ull)
#define PC_M0F_D ((int64_t)0x0f0f0f0f0f0f0f0full)
#define PC_M01_D ((int64_t)0x0101010101010101ull)

// Register-register ALU forms these checks use, in both spellings:
// the popcount sequence needs all four, check_const_mul_to_shadd only
// the multiply.
typedef enum { RRR_NONE = 0, RRR_ADD, RRR_SUB, RRR_AND, RRR_MUL } rrr_op;

static rrr_op decode_rrr(uint32_t w, unsigned size, unsigned *rd,
                         unsigned *rs1, unsigned *rs2)
{
    if (size == 4) {
        if (RV_OPCODE(w) != 0x33u) return RRR_NONE;
        unsigned f3 = (w >> 12) & 7u, f7 = (w >> 25) & 0x7fu;
        rrr_op op = RRR_NONE;
        if (f7 == 0x00u && f3 == 0u) op = RRR_ADD;
        else if (f7 == 0x20u && f3 == 0u) op = RRR_SUB;
        else if (f7 == 0x00u && f3 == 7u) op = RRR_AND;
        else if (f7 == 0x01u && f3 == 0u) op = RRR_MUL;
        else return RRR_NONE;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *rs2 = (w >> 20) & 0x1fu;
        return *rd == 0 ? RRR_NONE : op;
    }
    if (size != 2) return RRR_NONE;
    // c.add: op 10, funct4 1001, both registers non-zero -- c.jr and
    // c.jalr share the funct4 with a zero rs2.
    if ((w & 0xf003u) == 0x9002u) {
        *rd = *rs1 = (w >> 7) & 0x1fu;
        *rs2 = (w >> 2) & 0x1fu;
        return (*rd && *rs2) ? RRR_ADD : RRR_NONE;
    }
    // The C1 misc-ALU register ops, which name x8-x15 only: bits 6:5
    // pick sub/xor/or/and at bit 12 clear, and subw/addw/mul at bit 12
    // set. Only sub, and and mul matter here.
    if ((w & 0xfc63u) == 0x8c01u || (w & 0xfc63u) == 0x8c61u ||
        (w & 0xfc63u) == 0x9c41u) {
        *rd = *rs1 = 8u + ((w >> 7) & 7u);
        *rs2 = 8u + ((w >> 2) & 7u);
        if ((w & 0xfc63u) == 0x8c01u) return RRR_SUB;
        if ((w & 0xfc63u) == 0x8c61u) return RRR_AND;
        return RRR_MUL;
    }
    return RRR_NONE;
}

// Everything a register's popcount entry holds, cleared together.
static void pc_clear(riscvlint_state *state, unsigned r)
{
    state->pc.pckind[r] = PC_NONE;
    state->pc.pcinsn[r] = 0;
    state->pc.pcbytes[r] = 0;
    state->pc.pcclob[r] = false;
}

// A write to `r` invalidates its own entry and every stage computed
// *from* r -- the rewrite names the source register, so a stage whose
// source has been overwritten by something outside the sequence cannot
// be spelled `cpop rd,src`.
//
// The sequence overwriting its own source is the common case and is not
// this: `sub a1,a1,a2` is how stage one is spelled, and `pcclob`
// records it so the check can demand the source be dead instead.
static void pc_kill(riscvlint_state *state, unsigned r)
{
    if (r >= 32) return;
    state->pc.cknown[r] = false;
    pc_clear(state, r);
    for (unsigned i = 0; i < 32; i++)
        if (state->pc.pckind[i] != PC_NONE && state->pc.pcsrc[i] == r)
            pc_clear(state, i);
}

// Clearing the destination of an instruction that *is* a stage of a
// sequence, which is not the same as an unrelated write. pc_kill's
// sweep over entries whose source this register is would take the
// sibling half of the very sequence being matched: `srli a1,a1,2`
// writes a1 while a2 holds `stage1 & M33` computed from a1, and the
// sweep cost 98% of the population before this existed. The stages it
// spares already carry `pcclob`, so the check still has to prove the
// source dead.
static void pc_clear_dst(riscvlint_state *state, unsigned r)
{
    if (r >= 32) return;
    state->pc.cknown[r] = false;
    pc_clear(state, r);
}

// A register's entry, read out before the destination is cleared. Every
// arm below snapshots first, because the destination is routinely one
// of the operands and routinely the source register too.
typedef struct {
    unsigned kind, src;
    bool wide, clob;
    uint16_t insn, bytes;
    uint16_t base, baseb;       // the counts at stage one
    uint64_t start;
} pc_snap;

static pc_snap pc_read(const riscvlint_state *state, unsigned r)
{
    pc_snap sn;
    sn.kind = state->pc.pckind[r];
    sn.src = state->pc.pcsrc[r];
    sn.wide = state->pc.pcwide[r];
    sn.clob = state->pc.pcclob[r];
    sn.insn = state->pc.pcinsn[r];
    sn.bytes = state->pc.pcbytes[r];
    sn.base = state->pc.pcbase[r];
    sn.baseb = state->pc.pcbaseb[r];
    sn.start = state->pc.pcstart[r];
    return sn;
}

static void pc_write(riscvlint_state *state, unsigned dst, const pc_snap *sn,
                     unsigned kind, unsigned insn_added, unsigned bytes_added)
{
    state->pc.pckind[dst] = (uint8_t)kind;
    state->pc.pcsrc[dst] = (uint8_t)sn->src;
    state->pc.pcwide[dst] = sn->wide;
    // Writing the register the sequence started from is how it is
    // ordinarily spelled; the check then has to prove that register
    // dead rather than name it in a rewrite that would change it.
    state->pc.pcclob[dst] = sn->clob || dst == sn->src;
    state->pc.pcinsn[dst] = (uint16_t)(sn->insn + insn_added);
    state->pc.pcbytes[dst] = (uint16_t)(sn->bytes + bytes_added);
    state->pc.pcbase[dst] = sn->base;
    state->pc.pcbaseb[dst] = sn->baseb;
    state->pc.pcstart[dst] = sn->start;
    // Stage one is the fork: everything after it descends from here,
    // and the two halves of the middle stage both carry this count.
    if (kind == PC_STAGE1) {
        state->pc.pcbase[dst] = state->pc.pcinsn[dst];
        state->pc.pcbaseb[dst] = state->pc.pcbytes[dst];
    }
}

// True when `r` holds the given mask, in the width this sequence is in.
// `*wide` is decided by the first mask seen and checked against the
// rest, so a sequence mixing widths matches neither.
static bool pc_is_mask(const riscvlint_state *state, unsigned r,
                       int64_t narrow, int64_t full, bool known_wide,
                       bool *wide)
{
    if (r >= 32 || !state->pc.cknown[r]) return false;
    int64_t v = state->pc.cval[r];
    if (v == narrow && (!known_wide || !*wide)) { *wide = false; return true; }
    if (v == full && (!known_wide || *wide)) { *wide = true; return true; }
    return false;
}

// `srli` or `srliw`. The 32-bit sequence on RV64 shifts with plain
// `srli` throughout and finishes with `srliw`, so both spellings have
// to be read and the width of the final one is what pins the form.
static bool pc_decode_srl(uint32_t w, unsigned size, unsigned *rd,
                          unsigned *rs1, unsigned *shamt, bool *word)
{
    if (rv_decode_srli(w, size, rd, rs1, shamt)) { *word = false; return true; }
    if (size != 4 || RV_OPCODE(w) != 0x1bu) return false;
    if (((w >> 12) & 7u) != 5u) return false;
    if (((w >> 25) & 0x7fu) != 0u) return false;        // funct7 0: not sraiw
    *rd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    *shamt = (w >> 20) & 0x1fu;
    *word = true;
    return true;
}

// Fold this instruction into the per-register state. Called from
// riscvlint_state_observe, so a check sees everything up to but not
// including the instruction under the cursor.
static void pc_observe(riscvlint_state *state, const cs_insn *insn,
                       uint32_t w)
{
    unsigned size = insn->size;
    unsigned rd, rs1, rs2, shamt;
    int64_t val;
    bool word;

    // Constant propagation first: a mask is read many times, so unlike
    // the -c census this holds a value until the register is written.
    cchain_step st;
    cchain_merge mg;
    if (decode_const(w, size, &rd, &val)) {
        pc_kill(state, rd);
        state->pc.cknown[rd] = true;
        state->pc.cval[rd] = val;
        return;
    }
    if (cchain_step_of(w, size, &st) && st.dst != 0 &&
        state->pc.cknown[st.reg]) {
        int64_t v = state->pc.cval[st.reg];
        cchain_apply(&st, &v);
        pc_kill(state, st.dst);
        state->pc.cknown[st.dst] = true;
        state->pc.cval[st.dst] = v;
        return;
    }
    if (cchain_merge_of(w, size, &mg) && state->pc.cknown[mg.a] &&
        state->pc.cknown[mg.b]) {
        int64_t v = mg.is_or ? (state->pc.cval[mg.a] | state->pc.cval[mg.b])
                             : (int64_t)((uint64_t)state->pc.cval[mg.a] +
                                         (uint64_t)state->pc.cval[mg.b]);
        pc_kill(state, mg.dst);
        state->pc.cknown[mg.dst] = true;
        state->pc.cval[mg.dst] = v;
        return;
    }

    if (pc_decode_srl(w, size, &rd, &rs1, &shamt, &word)) {
        if (shamt == 1 && !word) {
            // Opens a sequence. The destination has to be a different
            // register, or nothing is left to name the source by.
            if (rd == rs1) { pc_kill(state, rd); return; }
            pc_kill(state, rd);
            state->pc.pckind[rd] = PC_SHR1;
            state->pc.pcsrc[rd] = (uint8_t)rs1;
            state->pc.pcwide[rd] = false;
            state->pc.pcclob[rd] = false;
            state->pc.pcinsn[rd] = 1;
            state->pc.pcbytes[rd] = (uint16_t)size;
            state->pc.pcstart[rd] = insn->address;
            return;
        }
        pc_snap sn = pc_read(state, rs1);
        unsigned kind = PC_NONE;
        if (!word && shamt == 2 && sn.kind == PC_STAGE1) kind = PC_SHR2;
        else if (!word && shamt == 4 && sn.kind == PC_STAGE2) kind = PC_SHR4;
        if (kind == PC_NONE) { pc_kill(state, rd); return; }
        pc_clear_dst(state, rd);
        pc_write(state, rd, &sn, kind, 1, size);
        return;
    }

    rrr_op op = decode_rrr(w, size, &rd, &rs1, &rs2);
    if (op == RRR_NONE) {
        // Everything else: whatever it writes is no longer a stage.
        cs_regs rr, rw;
        uint8_t nr = 0, nw = 0;
        if (cs_regs_access(state->handle, insn, rr, &nr, rw, &nw) ==
            CS_ERR_OK) {
            for (uint8_t i = 0; i < nw; i++) {
                unsigned n = cs_reg_to_num(rw[i]);
                if (n < 32) pc_kill(state, n);
            }
        } else {
            for (unsigned i = 0; i < 32; i++) pc_kill(state, i);
        }
        return;
    }

    pc_snap a = pc_read(state, rs1), b = pc_read(state, rs2);
    if (op == RRR_AND) {
        // (x >> 1) & M55, stage1 & M33, (stage1 >> 2) & M33, sum4 & M0F.
        static const struct { unsigned want, give; } arms[] = {
            { PC_SHR1, PC_AND55 }, { PC_STAGE1, PC_AND33 },
            { PC_SHR2, PC_AND33S }, { PC_SUM4, PC_STAGE3 },
        };
        static const int64_t narrow[] = { PC_M55_W, PC_M33_W, PC_M33_W,
                                          PC_M0F_W };
        static const int64_t full[] = { PC_M55_D, PC_M33_D, PC_M33_D,
                                        PC_M0F_D };
        for (unsigned i = 0; i < 4; i++) {
            const pc_snap *sn;
            unsigned mask;
            if (a.kind == arms[i].want) { sn = &a; mask = rs2; }
            else if (b.kind == arms[i].want) { sn = &b; mask = rs1; }
            else continue;
            // The first mask decides the width; the rest must match it.
            bool wide = sn->wide, known = arms[i].want != PC_SHR1;
            if (!pc_is_mask(state, mask, narrow[i], full[i], known, &wide))
                continue;
            pc_snap use = *sn;
            use.wide = wide;
            pc_clear_dst(state, rd);
            pc_write(state, rd, &use, arms[i].give, 1, size);
            return;
        }
        pc_kill(state, rd);
        return;
    }
    if (op == RRR_SUB) {
        // x - ((x >> 1) & M55), where the left operand has to be the
        // very register the opening shift read.
        if (b.kind == PC_AND55 && b.src == rs1) {
            pc_clear_dst(state, rd);
            pc_write(state, rd, &b, PC_STAGE1, 1, size);
            return;
        }
        pc_kill(state, rd);
        return;
    }
    if (op == RRR_ADD) {
        // The two halves of the middle stage. Both descend from stage
        // one, so their counts share that prefix and adding them whole
        // would charge it twice.
        if (((a.kind == PC_AND33 && b.kind == PC_AND33S) ||
             (a.kind == PC_AND33S && b.kind == PC_AND33)) &&
            a.src == b.src && a.wide == b.wide && a.base == b.base) {
            pc_snap j = a;
            j.insn = (uint16_t)(a.insn + b.insn - a.base);
            j.bytes = (uint16_t)(a.bytes + b.bytes - a.baseb);
            j.clob = a.clob || b.clob;
            j.start = a.start < b.start ? a.start : b.start;
            pc_clear_dst(state, rd);
            pc_write(state, rd, &j, PC_STAGE2, 1, size);
            return;
        }
        // stage2 + (stage2 >> 4): the shift was taken *of* stage2, so
        // the longer count already contains the shorter.
        if (((a.kind == PC_STAGE2 && b.kind == PC_SHR4) ||
             (a.kind == PC_SHR4 && b.kind == PC_STAGE2)) &&
            a.src == b.src && a.wide == b.wide) {
            const pc_snap *keep = a.insn > b.insn ? &a : &b;
            pc_snap use = *keep;
            use.clob = a.clob || b.clob;
            pc_clear_dst(state, rd);
            pc_write(state, rd, &use, PC_SUM4, 1, size);
            return;
        }
        pc_kill(state, rd);
        return;
    }
    // RRR_MUL: stage3 * M01.
    {
        const pc_snap *sn = NULL;
        unsigned mask = 0;
        if (a.kind == PC_STAGE3) { sn = &a; mask = rs2; }
        else if (b.kind == PC_STAGE3) { sn = &b; mask = rs1; }
        if (sn) {
            bool wide = sn->wide;
            if (pc_is_mask(state, mask, PC_M01_W, PC_M01_D, true, &wide)) {
                pc_snap use = *sn;
                pc_clear_dst(state, rd);
                pc_write(state, rd, &use, PC_MUL, 1, size);
                return;
            }
        }
        pc_kill(state, rd);
    }
}

bool check_swar_popcount(riscvlint_state *state, const cs_insn *insn,
                         riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBB)) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    unsigned rd, rs1, shamt;
    bool word;
    if (!pc_decode_srl(w, insn->size, &rd, &rs1, &shamt, &word)) return false;
    if (state->pc.pckind[rs1] != PC_MUL) return false;

    // The mask width and the final shift have to agree, and so does the
    // shift's own width: 32 bits ends in `srliw ...,24` and 64 in
    // `srli ...,56`.
    bool wide = state->pc.pcwide[rs1];
    if (wide) {
        if (word || shamt != 56u) return false;
    } else {
        if (!word || shamt != 24u) return false;
    }
    // A branch into the middle means the instructions before the target
    // are not the ones that ran.
    if (riscvlint_is_branch_target(state, insn->address)) return false;

    unsigned src = state->pc.pcsrc[rs1];
    // The sequence ordinarily computes in place, overwriting the very
    // register the rewrite would name. `cpop rd,src` leaves src holding
    // what it held, where the sequence left it holding a partial sum,
    // so the rewrite is only equivalent once src is dead.
    if (state->pc.pcclob[rs1] &&
        riscvlint_liveness(state, insn->address + insn->size, src) !=
            RISCVLINT_LIVE_DEAD)
        return false;

    unsigned ninsn = (unsigned)state->pc.pcinsn[rs1] + 1;
    unsigned bytes = (unsigned)state->pc.pcbytes[rs1] + insn->size;
    finding->title = "a bit count spelled out longhand";
    finding->address = state->pc.pcstart[rs1];
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "cpop%s %s, %s (%u instructions, %u -> 4 bytes, plus the masks)",
             wide ? "" : "w", rv_reg_name(rd), rv_reg_name(src), ninsn,
             bytes);
    return true;
}

// ---- a floating-point constant `fli` would have materialized ----

// Entries 2..31 of Zfa's `fli` table, as the (exponent, 2-bit mantissa)
// pair each one has in binary32. Transcribed from LLVM's
// LoadFP32ImmArr (RISCVBaseInfo.cpp) rather than from the spec table,
// for the same reason the census's profile rungs came from
// RISCVProfiles.td: the assembler is what has to accept the suggestion,
// so the assembler's own table is the one to agree with. Entry 0
// (-1.0) and entry 1 (the smallest positive normal, which differs per
// type) are not in it and are handled separately, exactly as LLVM does.
static const struct { uint8_t exp, mant; } fli_table[30] = {
    { 0x6f, 0 }, { 0x70, 0 }, { 0x77, 0 }, { 0x78, 0 }, { 0x7b, 0 },
    { 0x7c, 0 }, { 0x7d, 0 }, { 0x7d, 1 }, { 0x7d, 2 }, { 0x7d, 3 },
    { 0x7e, 0 }, { 0x7e, 1 }, { 0x7e, 2 }, { 0x7e, 3 }, { 0x7f, 0 },
    { 0x7f, 1 }, { 0x7f, 2 }, { 0x7f, 3 }, { 0x80, 0 }, { 0x80, 1 },
    { 0x80, 2 }, { 0x81, 0 }, { 0x82, 0 }, { 0x83, 0 }, { 0x86, 0 },
    { 0x87, 0 }, { 0x8e, 0 }, { 0x8f, 0 }, { 0xff, 0 }, { 0xff, 2 },
};

int rv_fli_entry(uint64_t bits, unsigned width)
{
    unsigned sign, exp;
    unsigned mant;      // the two mantissa bits the table indexes on

    if (width == 8) {
        // The smallest positive normal is entry 1 and is type-specific:
        // 2^-1022 here, 2^-126 for a single.
        if (bits == 0x0010000000000000ull) return 1;
        sign = (unsigned)(bits >> 63);
        unsigned e64 = (unsigned)((bits >> 52) & 0x7ff);
        uint64_t frac = bits & 0xfffffffffffffull;
        // A binary64 pattern is a binary32 one exactly when its
        // mantissa fits 23 bits and its exponent is in range. The
        // table's test then clears the low 21 of those 23, so all told
        // the low 50 mantissa bits have to be zero -- which is the same
        // condition, reached without converting anything.
        if (frac & 0x3ffffffffffffull) return -1;
        mant = (unsigned)(frac >> 50);
        if (e64 == 0x7ff) {
            exp = 0xff;                 // inf and the canonical NaN
        } else if (e64 == 0) {
            return -1;                  // zero and the subnormals
        } else {
            int e32 = (int)e64 - 1023 + 127;
            if (e32 < 1 || e32 > 254) return -1;
            exp = (unsigned)e32;
        }
    } else if (width == 4) {
        if (bits > 0xffffffffull) return -1;
        if (bits == 0x00800000ull) return 1;
        sign = (unsigned)((bits >> 31) & 1);
        exp = (unsigned)((bits >> 23) & 0xff);
        if (bits & 0x1fffffull) return -1;
        mant = (unsigned)((bits >> 21) & 3);
        if (exp == 0) return -1;
    } else {
        return -1;
    }

    int entry = -1;
    for (int i = 0; i < 30; i++)
        if (fli_table[i].exp == exp && fli_table[i].mant == mant) {
            entry = i + 2;
            break;
        }
    if (entry < 0) return -1;
    // The only negative value the table holds is -1.0, which is 1.0's
    // entry with the sign set.
    if (sign) return entry == 16 ? 0 : -1;
    return entry;
}

const char *rv_fli_spell(int entry, char *out, size_t outsz)
{
    // The three LLVM's printer spells by name rather than by value.
    if (entry == 1) { snprintf(out, outsz, "min"); return out; }
    if (entry == 30) { snprintf(out, outsz, "inf"); return out; }
    if (entry == 31) { snprintf(out, outsz, "nan"); return out; }
    if (entry < 0 || entry > 31) { snprintf(out, outsz, "?"); return out; }
    // Entry 0 is -1.0; everything else is the table's pattern with a
    // clear sign.
    unsigned idx = entry == 0 ? 16 : (unsigned)entry;
    uint32_t pat = (uint32_t)(entry == 0 ? 1u << 31 : 0u) |
                   (uint32_t)fli_table[idx - 2].exp << 23 |
                   (uint32_t)fli_table[idx - 2].mant << 21;
    float f;
    memcpy(&f, &pat, sizeof f);
    // LLVM prints an integral value with one fraction digit and
    // everything else with %.12g, which is the precision the smallest
    // entry needs. Matched so the text is what the assembler reads
    // back.
    if (f == (float)(int)f) snprintf(out, outsz, "%.1f", (double)f);
    else snprintf(out, outsz, "%.12g", (double)f);
    return out;
}

// fld/flw frd, imm12(rs1): the FP loads, which rv_decode_mem reports as
// memory records but not in the form this needs.
static bool rv_decode_fp_load(uint32_t w, unsigned *frd, unsigned *rs1,
                              int64_t *imm, unsigned *width)
{
    if (RV_OPCODE(w) != 0x07u) return false;
    unsigned f3 = (w >> 12) & 7u;
    if (f3 == 2) *width = 4;            // flw
    else if (f3 == 3) *width = 8;       // fld
    else return false;                  // flh, and the vector loads
    *frd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    *imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
    return true;
}

bool check_fp_pool_to_fli(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (insn->size != 4) return false;
    if (!state->read) return false;     // no image to resolve against
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZFA)) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1;
    int64_t hi;
    // The `auipc` spelling only. `lui %hi` + `fld %lo` is the same fold
    // and measures **zero** in the corpus: the absolute form appears
    // only where its `lui` fits `c.lui`, which pairs with a two-byte
    // `c.fld` and so is a different pair entirely. Recorded so the
    // omission is a measurement rather than an oversight.
    if (!rv_decode_auipc(w1, &rd1, &hi)) return false;
    if (rd1 == 0) return false;         // computes nothing

    uint64_t second = insn->address + 4;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned frd, rs1, width;
    int64_t lo;
    if (!rv_decode_fp_load(w2, &frd, &rs1, &lo, &width)) return false;
    if (rs1 != rd1) return false;       // not this address

    // Something branching onto the load would lose its address.
    if (riscvlint_is_branch_target(state, second)) return false;
    // In an unlinked object both immediates wait on R_RISCV_PCREL_HI20
    // and its LO12, so the address computed from them is fiction.
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    int64_t target = (int64_t)insn->address + hi + lo;
    if (target < 0) return false;

    uint8_t pool[8];
    if (!state->read(state->read_ctx, (uint64_t)target, pool, width))
        return false;
    uint64_t bits = 0;
    for (unsigned i = 0; i < width; i++)
        bits |= (uint64_t)pool[i] << (8 * i);

    // Tested before the liveness walk, which is much the more expensive
    // of the two: most of the population fails here -- 3,459 of
    // libxul's 14,992 pool loads hold a value any entry holds.
    int entry = rv_fli_entry(bits, width);
    if (entry < 0) return false;

    // The rewrite stops writing rd1. A pool address is sometimes reused
    // for the slot next door, so this has to be proved rather than
    // assumed.
    if (riscvlint_liveness(state, second + 4, rd1) != RISCVLINT_LIVE_DEAD)
        return false;

    char value[32];
    rv_fli_spell(entry, value, sizeof value);
    finding->title = "floating-point constant fli would have built";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "fli.%c %s, %s (8 -> 4 bytes, pool 0x%" PRIx64 ")",
             width == 8 ? 'd' : 's', rv_freg_name(frd), value,
             (uint64_t)target);
    return true;
}

// The shift amount whose shNadd multiplies by `v`, or 0 for a factor no
// shNadd reaches. `sh1add rd,rs1,rs2` computes rs2 + (rs1 << 1), which
// is three times one register when both operands name it; sh2add and
// sh3add give five and nine the same way. 2, 4 and 8 are absent because
// a multiply by a power of two is a shift, which the compilers emit
// directly: four dependent `li` + `mul` pairs in the corpus load a
// power of two, against 712 that load a 3, 5 or 9.
static unsigned rv_shadd_shift(int64_t v)
{
    switch (v) {
    case 3: return 1;
    case 5: return 2;
    case 9: return 3;
    default: return 0;
    }
}

bool check_const_mul_to_shadd(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBA)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rc;
    int64_t val;
    if (!decode_const(w1, insn->size, &rc, &val)) return false;
    unsigned shamt = rv_shadd_shift(val);
    if (!shamt) return false;
    // decode_const also spells lui and c.lui, whose values are multiples
    // of 4096 and so never 3, 5 or 9; the multiplier test is what
    // excludes them, rather than a second look at the encoding.
    //
    // sp, gp and tp hold what the ABI says they hold rather than a
    // constant some region loaded, and nothing here would make one of
    // them dead. check_const_remat declines the same three.
    if (rc == 2 || rc == 3 || rc == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd, mrs1, mrs2;
    // `mul` and `c.mul` only. decode_rrr reaches neither `mulw` nor
    // `mulh`: the first is a different major opcode and the rest a
    // different funct3, which is the exclusion this rewrite needs rather
    // than an accident. mulw sign-extends its 32-bit product and shNadd
    // does not, so that pair needs a following `sext.w` and trades two
    // instructions for two; mulh returns the other half of the product
    // and is not a scaled value at all.
    if (decode_rrr(w2, len2, &rd, &mrs1, &mrs2) != RRR_MUL) return false;

    // The multiply has to read the constant exactly once. Twice is
    // `rc * rc`, a constant of its own and a different rewrite; not at
    // all means these two instructions are unrelated and the `li` was
    // loaded for something further on.
    bool a_is_const = mrs1 == rc, b_is_const = mrs2 == rc;
    if (a_is_const == b_is_const) return false;
    unsigned rx = a_is_const ? mrs2 : mrs1;
    // x0 as the multiplicand makes the product zero rather than a scaled
    // value, and the rewrite would have to be `li rd,0`.
    if (rx == 0) return false;

    // Reaching the multiply from somewhere else means the register it
    // reads need not hold 3, 5 or 9 when it executes.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The constant stops existing, so it has to be dead after the pair.
    // When the multiply overwrites it that is free. This is the only
    // precondition here that costs anything: 296 of the corpus's 712
    // shapes are lost to it, and nothing is lost to the branch,
    // relocation or register tests above.
    if (rd != rc &&
        riscvlint_liveness(state, second + len2, rc) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2;
    finding->title = "li + mul foldable to shNadd";
    finding->address = insn->address;
    finding->insn_count = 2;
    // Both operands are the multiplicand: the shift supplies the even
    // part of the factor and the addend the odd one.
    snprintf(finding->replacement, sizeof finding->replacement,
             "sh%uadd %s, %s, %s (%u -> 4 bytes)", shamt, rv_reg_name(rd),
             rv_reg_name(rx), rv_reg_name(rx), before);
    return true;
}

// Which unsigned divide or remainder an encoding spells. The signed
// forms -- funct3 4 and 6 -- are deliberately absent: `div rd,rx,2^k`
// rounds toward zero and a bare `srai` rounds toward minus infinity, so
// folding one needs a bias added back and is three instructions rather
// than one.
typedef enum {
    RV_UDIV_NONE = 0,
    RV_UDIV_D,          // divu
    RV_UDIV_W,          // divuw
    RV_UREM_D,          // remu
    RV_UREM_W,          // remuw
} rv_udiv_op;

static rv_udiv_op decode_udiv(uint32_t w, unsigned size, unsigned *rd,
                              unsigned *rs1, unsigned *rs2)
{
    // Four bytes only. Zcb's `c.mul` is the whole of the M extension's
    // compressed surface, so no divide has a two-byte spelling to miss.
    if (size != 4) return RV_UDIV_NONE;
    unsigned op = RV_OPCODE(w);
    if (op != 0x33u && op != 0x3bu) return RV_UDIV_NONE;
    if (((w >> 25) & 0x7fu) != 0x01u) return RV_UDIV_NONE;      // not M
    unsigned f3 = (w >> 12) & 7u;
    if (f3 != 5u && f3 != 7u) return RV_UDIV_NONE;    // 4 and 6 are signed
    *rd = (w >> 7) & 0x1fu;
    *rs1 = (w >> 15) & 0x1fu;
    *rs2 = (w >> 20) & 0x1fu;
    if (*rd == 0) return RV_UDIV_NONE;
    if (op == 0x33u) return f3 == 5u ? RV_UDIV_D : RV_UREM_D;
    return f3 == 5u ? RV_UDIV_W : RV_UREM_W;
}

bool check_udiv_pow2(riscvlint_state *state, const cs_insn *insn,
                     riscvlint_finding *finding)
{
    // No extension gate: srli, srliw and andi are all RV64I, so the
    // finding stands whatever the object's arch string says.
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rc;
    int64_t val;
    if (!decode_const(w1, insn->size, &rc, &val)) return false;
    // A power of two, and at least 2. `val & (val - 1)` is the
    // power-of-two test; the `val < 2` beside it does the rest of the
    // work, excluding 1, where dividing is a move and the remainder is
    // zero, and excluding 0, which no shift amount describes and which
    // would not terminate the loop below.
    if (val < 2 || (val & (val - 1)) != 0) return false;
    unsigned k = 0;
    while (((int64_t)1 << (k + 1)) <= val) k++;
    // sp, gp and tp hold what the ABI says they hold rather than a
    // divisor, as in check_const_mul_to_shadd and check_const_remat.
    if (rc == 2 || rc == 3 || rc == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd, rx, drs2;
    rv_udiv_op op = decode_udiv(w2, len2, &rd, &rx, &drs2);
    if (op == RV_UDIV_NONE) return false;
    // Division does not commute, so the constant has to be the divisor
    // and nothing else. Both operands naming it is `rc / rc`, which is
    // 1 or 0 and a constant of its own.
    if (drs2 != rc || rx == rc) return false;
    // x0 as the dividend makes the result zero rather than a shift of
    // anything.
    if (rx == 0) return false;

    char rewrite[48];
    switch (op) {
    case RV_UDIV_D:
        // Unsigned, so the quotient is the dividend shifted down, with
        // no case distinction and no bias. srli's shift amount is six
        // bits and k cannot exceed 30 here, `li` and `lui` between them
        // reaching no higher.
        snprintf(rewrite, sizeof rewrite, "srli %s, %s, %u",
                 rv_reg_name(rd), rv_reg_name(rx), k);
        break;
    case RV_UDIV_W:
        // divuw divides the low words and sign-extends the 32-bit
        // quotient, which is exactly what srliw does with its shift.
        // srliw's shift amount is five bits, and above 31 the divisor's
        // low word is not a power of two at all.
        if (k > 31) return false;
        snprintf(rewrite, sizeof rewrite, "srliw %s, %s, %u",
                 rv_reg_name(rd), rv_reg_name(rx), k);
        break;
    case RV_UREM_D:
    case RV_UREM_W:
        // The remainder is the low k bits, so the fold is a mask of
        // 2^k - 1. andi's immediate is twelve bits signed: 2047 is the
        // largest mask it holds, so k of 12 or more would need the mask
        // materialized and the pair would not shrink. The `w` form
        // needs no separate case -- the mask clears everything above
        // bit 10, where the low word and the register agree.
        if (k > 11) return false;
        snprintf(rewrite, sizeof rewrite, "andi %s, %s, %lld",
                 rv_reg_name(rd), rv_reg_name(rx),
                 (long long)(((int64_t)1 << k) - 1));
        break;
    default:
        return false;
    }

    // Arriving at the divide from elsewhere means the divisor need not
    // be a power of two when it executes.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The divisor stops being loaded, so it has to be dead after the
    // pair. The divide overwriting it is the free case.
    if (rd != rc &&
        riscvlint_liveness(state, second + len2, rc) != RISCVLINT_LIVE_DEAD)
        return false;

    unsigned before = insn->size + len2;
    finding->title = "unsigned divide or remainder by a power of two";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s (%u -> 4 bytes)", rewrite, before);
    return true;
}

// A constant loaded only to be compared for equality, where Zibi's
// `beqi`/`bnei` takes the constant as a five-bit immediate and the `li`
// disappears. RV64I has no compare-immediate-and-branch, so every
// comparison against a constant has to materialize it first; this is
// the shape that forces.
//
// imm5_zibi is 1 through 31, or -1. Zero is absent from the range
// because `beq rs,x0` already compares against it, which is also why
// decode_const's `lui` spellings never reach here: a lui's value is a
// multiple of 4096 and a c.lui's the same, so the range test excludes
// them without a second look at the encoding.
static bool zibi_immediate(int64_t v)
{
    return v == -1 || (v >= 1 && v <= 31);
}

bool check_const_eq_branch(riscvlint_state *state, const cs_insn *insn,
                           riscvlint_finding *finding)
{
    // Positively present, not merely un-denied, for the reason
    // check_indexed_load states at length -- and more so here. Zibi is
    // in no profile and LLVM carries it as an experimental extension at
    // 0.1, where Zilx at least has a ratification plan; the permissive
    // reading would put 177,581 findings across the corpus, 47,115 of
    // them in libxul alone, for an instruction no target can execute.
    if (!(riscvlint_state_extensions(state) & RISCVLINT_EXT_ZIBI))
        return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rc;
    int64_t val;
    if (!decode_const(w1, insn->size, &rc, &val)) return false;
    if (!zibi_immediate(val)) return false;
    // sp, gp and tp hold what the ABI says they hold rather than a
    // comparand, as in check_const_mul_to_shadd and check_const_remat.
    if (rc == 2 || rc == 3 || rc == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned brs1, brs2, bf3;
    int64_t off;
    if (!rv_decode_cond_branch(w2, len2, &brs1, &brs2, &bf3, &off))
        return false;
    // Equality only: Zibi has beqi and bnei and nothing else, its
    // condition predicate being isIntEqualitySetCC. The ordered
    // comparisons are a larger population and have no Zibi form -- see
    // TODO.md, where that number is recorded rather than reported.
    if (bf3 != 0u && bf3 != 1u) return false;
    // beq and bne commute, so the constant may be either operand, but
    // it has to be exactly one of them: `beq rc,rc` is a condition that
    // does not read anything else, and a branch naming it in neither
    // operand is unrelated to the `li`.
    unsigned rx;
    if (brs2 == rc && brs1 != rc) rx = brs1;
    else if (brs1 == rc && brs2 != rc) rx = brs2;
    else return false;
    // x0 as the other operand compares zero against a constant, which
    // is a condition decided at assembly time rather than a comparison.
    if (rx == 0) return false;

    // Folding deletes the `li`, so the branch must not be reachable from
    // anywhere that did not run it.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The constant has to be dead on *both* successors, which is where
    // most of this shape's population goes: a scan sees the fall-through
    // and not the taken path, and the comparand is very often still
    // wanted on one of them. check_cond_to_branch proves the same thing
    // the same way.
    uint64_t fallthrough = second + len2;
    uint64_t taken = second + (uint64_t)off;
    if (riscvlint_liveness(state, fallthrough, rc) != RISCVLINT_LIVE_DEAD)
        return false;
    if (riscvlint_liveness(state, taken, rc) != RISCVLINT_LIVE_DEAD)
        return false;

    // The branch keeps its own displacement and so its reach, and beqi
    // is a B-type four bytes with no compressed form. The branch being
    // replaced cannot have been compressed either -- c.beqz and c.bnez
    // compare against x0 and this one compares two registers -- so the
    // saving is exactly what the `li` took.
    unsigned before = insn->size + len2;
    finding->title = "constant loaded for one equality branch";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, %lld, 0x%" PRIx64 " (%u -> 4 bytes)",
             bf3 == 0u ? "beqi" : "bnei", rv_reg_name(rx), (long long)val,
             taken, before);
    return true;
}

// The branch against x0 that an ordered comparison against 0 or 1 is.
// RV64I has no compare-immediate-and-branch -- that is Zibi's subject,
// and Zibi is equality-only -- but against these two constants no
// immediate is needed: the comparison is already a zero test, and x0
// serves where the loaded register did.
//
// Signed against 0 is a plain substitution. Signed against 1
// reformulates: `rx < 1` is `rx <= 0`, which is `bge x0,rx`, so the
// comparison flips and the operands swap. Unsigned against 0 or 1
// collapses to equality, 0 being the only unsigned value below 1.
//
// Ten of the sixteen combinations have a form. The two left out are the
// ones the assembler settles rather than folds -- `bltu rx,0` is never
// taken and `bgeu rx,0` always is, which is a dead-branch finding and
// not this one -- and the four `K,rx` rows with K of 1, where `1 < rx`
// and `1 >= rx` have no zero form. Every row was checked by brute force
// over both signed extremes, 0, 1 and values straddling the sign bit,
// rather than reasoned about twice.
typedef struct {
    unsigned f3;            // the branch the rewrite uses
    bool reg_is_rs1;        // and which operand the surviving register takes
} zero_branch;

static bool zero_branch_form(unsigned f3, int64_t k, bool const_is_rs2,
                             zero_branch *out)
{
    switch (f3) {
    case 4u:                                            // blt
        if (k == 0) {
            out->f3 = 4u; out->reg_is_rs1 = const_is_rs2; return true;
        }
        if (k == 1 && const_is_rs2) {                   // rx < 1 == rx <= 0
            out->f3 = 5u; out->reg_is_rs1 = false; return true;
        }
        return false;
    case 5u:                                            // bge
        if (k == 0) {
            out->f3 = 5u; out->reg_is_rs1 = const_is_rs2; return true;
        }
        if (k == 1 && const_is_rs2) {                   // rx >= 1 == rx > 0
            out->f3 = 4u; out->reg_is_rs1 = false; return true;
        }
        return false;
    case 6u:                                            // bltu
        if (k == 1 && const_is_rs2) {                   // rx <u 1 == rx == 0
            out->f3 = 0u; out->reg_is_rs1 = true; return true;
        }
        if (k == 0 && !const_is_rs2) {                  // 0 <u rx == rx != 0
            out->f3 = 1u; out->reg_is_rs1 = true; return true;
        }
        return false;
    case 7u:                                            // bgeu
        if (k == 1 && const_is_rs2) {                   // rx >=u 1 == rx != 0
            out->f3 = 1u; out->reg_is_rs1 = true; return true;
        }
        if (k == 0 && !const_is_rs2) {                  // 0 >=u rx == rx == 0
            out->f3 = 0u; out->reg_is_rs1 = true; return true;
        }
        return false;
    default:
        return false;
    }
}

// The pseudo each form is spelled as. `bltz`/`bgez` put the register in
// rs1 and `bgtz`/`blez` in rs2, which is the whole difference between
// them.
static const char *zero_branch_name(unsigned f3, bool reg_is_rs1)
{
    switch (f3) {
    case 0u: return "beqz";
    case 1u: return "bnez";
    case 4u: return reg_is_rs1 ? "bltz" : "bgtz";
    default: return reg_is_rs1 ? "bgez" : "blez";
    }
}

bool check_const_ord_branch(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding)
{
    // No extension gate: the rewrite is another RV64I branch.
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rc;
    int64_t val;
    if (!decode_const(w1, insn->size, &rc, &val)) return false;
    if (val != 0 && val != 1) return false;
    // sp, gp and tp hold what the ABI says they hold rather than a
    // comparand, as in check_const_eq_branch and check_const_remat.
    if (rc == 2 || rc == 3 || rc == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned brs1, brs2, bf3;
    int64_t off;
    if (!rv_decode_cond_branch(w2, len2, &brs1, &brs2, &bf3, &off))
        return false;
    // The ordered comparisons only. beq and bne against a constant are
    // check_const_eq_branch's, which needs Zibi to say anything, and
    // against zero check_zero_eq_branch's; these need nothing, which is
    // the whole point of the split.
    if (bf3 < 4u) return false;

    // Ordered comparison does not commute, so which operand holds the
    // constant decides the rewrite rather than being a detail. It has to
    // be exactly one of them: both is a condition reading nothing else,
    // neither makes the pair unrelated.
    bool const_is_rs2;
    unsigned rx;
    if (brs2 == rc && brs1 != rc) { const_is_rs2 = true;  rx = brs1; }
    else if (brs1 == rc && brs2 != rc) { const_is_rs2 = false; rx = brs2; }
    else return false;
    // x0 as the other operand compares two constants.
    if (rx == 0) return false;

    zero_branch form;
    if (!zero_branch_form(bf3, val, const_is_rs2, &form)) return false;

    // Folding deletes the `li`, so the branch must not be reachable from
    // anywhere that did not run it.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // Dead on both successors, for check_const_eq_branch's reason: a
    // scan sees the fall-through and not the taken path.
    uint64_t fallthrough = second + len2;
    uint64_t taken = second + (uint64_t)off;
    if (riscvlint_liveness(state, fallthrough, rc) != RISCVLINT_LIVE_DEAD)
        return false;
    if (riscvlint_liveness(state, taken, rc) != RISCVLINT_LIVE_DEAD)
        return false;

    // The two unsigned forms become beqz or bnez, which compress when
    // the register is one of x8-x15 and the displacement fits CB format
    // -- so those sites give back the branch's two bytes as well as the
    // `li`'s. The four signed forms have no compressed spelling and stay
    // at four. rv_branch_encoded_size decides which, as it does for
    // check_cond_to_branch.
    //
    // It is asked with the displacement as encoded now, which deleting
    // the `li` does not make optimistic. A forward branch and its target
    // both shift down by the `li`'s size, leaving the displacement
    // exactly as it was; a backward one keeps its target and moves
    // closer to it, so the magnitude shrinks. Either way the current
    // value is the larger, and a size computed from it can only
    // understate what the rewrite saves.
    unsigned nrs1 = form.reg_is_rs1 ? rx : 0u;
    unsigned nrs2 = form.reg_is_rs1 ? 0u : rx;
    unsigned after = rv_branch_encoded_size(form.f3, nrs1, nrs2, off);
    unsigned before = insn->size + len2;

    finding->title = "constant loaded for a branch against zero";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, 0x%" PRIx64 " (%u -> %u bytes)",
             zero_branch_name(form.f3, form.reg_is_rs1), rv_reg_name(rx),
             taken, before, after);
    return true;
}

// `slli rd,rs,48` + `srli rd,rd,48` clears all but the low halfword in
// two dependent instructions, where Zbb's `zext.h` does it in one. The
// sibling of check_slli_srli_to_zext, which is the same shape at 32 and
// Zba's `zext.w`; this is the half that check was never written for.
//
// `(rs << 48) >> 48` logical is `rs & 0xffff`, and `zext.h` is exactly
// that. LLVM spells it ZEXT_H_RV64 under [HasStdExtZbbOrZbkb, IsRV64],
// encoded as `packw rd,rs,x0`, and marks it IsSignExtendingOpW -- which
// changes nothing here, a value below 0x10000 being its own sign
// extension.
//
// Unlike the sibling this one accepts an srli that writes a register
// other than the one the slli wrote, on a liveness proof. The arm is
// worth having: the sibling's doc can say every site in its corpus
// overwrites, and for this shape that is true of all 9,522 Go sites and
// false of 43 of libgkcodecs's 151, which are reachable only under
// `-m zbb` but are not nothing. Whether the sibling would gain sites
// from the same arm has not been measured.
bool check_slli_srli_to_zexth(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBB)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1, rs1, sh1;
    if (!rv_decode_slli(w1, insn->size, &rd1, &rs1, &sh1)) return false;
    if (sh1 != 48 || rd1 == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd2, srs1, sh2;
    if (!rv_decode_srli(w2, len2, &rd2, &srs1, &sh2)) return false;
    if (sh2 != 48 || rd2 == 0) return false;

    // The srli has to consume what the slli produced. `srai` in its
    // place is a sign extension and a different rewrite, which
    // rv_decode_srli already refuses.
    if (srs1 != rd1) return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // Overwriting the shifted register leaves nothing of the
    // intermediate to keep alive; writing elsewhere has to be proved.
    if (rd2 != rd1 &&
        riscvlint_liveness(state, second + len2, rd1) != RISCVLINT_LIVE_DEAD)
        return false;

    // Zcb has a two-byte `c.zext.h` for x8-x15, so on a target with both
    // extensions some of these would save six bytes rather than four.
    // The figure stays at four for the same reason the sibling's does:
    // the rewrite is named for one extension and sized without assuming
    // a second, and the byte column is a lower bound by construction.
    unsigned before = insn->size + len2;
    finding->title = "slli + srli foldable to zext.h";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "zext.h %s, %s (%u -> 4 bytes)", rv_reg_name(rd2),
             rv_reg_name(rs1), before);
    return true;
}

// `slli rd,rs,48` + `srai rd,rd,48` sign-extends the low halfword and
// `slli 56` + `srai 56` the low byte, where Zbb's `sext.h` and `sext.b`
// do either in one instruction. The arithmetic twin of
// check_slli_srli_to_zexth: one funct6 bit apart in the second
// instruction, and the difference between keeping the low bits and
// broadcasting their sign.
//
// Both replacements are Zbb and rv_decode_extension already decodes
// them -- `sext.b` is OP-IMM funct3 001 with immediate 0x604 and
// `sext.h` 0x605 -- for check_redundant_extension to recognise as
// guarantees. What was missing is only the two-instruction producer of
// the same value.
//
// 32 is deliberately absent. `slli 32` + `srai 32` is `sext.w`, which
// is base-ISA `addiw rd,rs,0` and needs no extension, so it would want
// a different gate; it is also one dependent pair in the whole corpus,
// both compilers emitting `sext.w` directly. The measurement is in
// TODO.md rather than an arm here.
static const char *sext_name(unsigned amount)
{
    return amount == 48 ? "sext.h" : "sext.b";
}

bool check_slli_srai_to_sext(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBB)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1, rs1, sh1;
    if (!rv_decode_slli(w1, insn->size, &rd1, &rs1, &sh1)) return false;
    if ((sh1 != 48 && sh1 != 56) || rd1 == 0) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned rd2, srs1, sh2;
    if (!rv_decode_srai(w2, len2, &rd2, &srs1, &sh2)) return false;
    // The amounts have to match each other as well as the widths: a
    // left shift of 48 and an arithmetic right shift of 55 is a signed
    // field extract, and the corpus has 6,738 of those against 3,660
    // real sext.h pairs.
    if (sh2 != sh1 || rd2 == 0) return false;

    // The srai has to consume what the slli produced.
    if (srs1 != rd1) return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // Overwriting the shifted register leaves nothing of the
    // intermediate to keep alive; writing elsewhere has to be proved,
    // as in the zext.h twin.
    if (rd2 != rd1 &&
        riscvlint_liveness(state, second + len2, rd1) != RISCVLINT_LIVE_DEAD)
        return false;

    // Zcb spells both of these in two bytes for x8-x15, so on a target
    // with Zcb as well some of these would save more. The figure does
    // not assume a second extension, for the reason the zext.h twin
    // gives.
    unsigned before = insn->size + len2;
    finding->title = "slli + srai foldable to sext.b or sext.h";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, %s (%u -> 4 bytes)", sext_name(sh1), rv_reg_name(rd2),
             rv_reg_name(rs1), before);
    return true;
}

// A compare-exchange written as an LR/SC retry loop, which Zacas does
// with one `amocas`:
//
//     L: lr.d.aq  rt, (ra)
//        bne      rt, rexp, fail      <- the comparison, and the body
//        sc.d.rl  rs, rnew, (ra)
//        bnez     rs, L               <- retry on a failed store
//
// becomes `mv rt,rexp` (or `li rt,0`) and then
// `amocas.d.aqrl rt, rnew, (ra)`, with the comparison left where it is.
// Four instructions and a backward branch become two, and the `bne`
// still decides the same thing afterwards: amocas leaves the loaded
// value in rt exactly as the loop did, on both paths.
//
// This is the only check here whose window is a loop rather than a
// straight line, and the only one whose replacement is two
// instructions. Both follow from amocas's operand constraint --
// LLVM ties $rd to $rd_wb, so the expected value arrives in the same
// register the loaded value leaves in, and getting it there costs an
// instruction the loop did not need.
//
// Scoped to a body of exactly one instruction, which is 13,072 of the
// corpus's 14,655 LR/SC loops. A longer body is a read-modify-write
// around the comparison and a different claim.
//
// Three things are deliberately not matched. `beq` in the body exits on
// a match rather than a mismatch, which is a different idiom and not a
// compare-exchange. A loop whose body is anything but a branch on the
// loaded value is not a comparison. And the plain and sub-word
// read-modify-write loops that the A extension and Zabha would fold are
// absent from this corpus entirely -- 0 of 14,655 -- so neither has an
// arm here.
//
// The ordering bits are the union of the pair's: an `lr.aq` with an
// `sc.rl` becomes `amocas.aqrl`. That is at least as strong as the two
// instructions it replaces and never weaker, which is the direction a
// suggestion is allowed to err in.
static const char *amocas_suffix(unsigned aq, unsigned rl)
{
    if (aq && rl) return ".aqrl";
    if (aq) return ".aq";
    if (rl) return ".rl";
    return "";
}

bool check_cas_loop_to_amocas(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding)
{
    // Positively present, for check_indexed_load's reason: Zacas is
    // ratified but in no profile, and no object in the corpus declares
    // it, so the permissive reading would put 14,499 findings on code
    // that cannot execute one.
    if (!(riscvlint_state_extensions(state) & RISCVLINT_EXT_ZACAS))
        return false;
    if (insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rt, ra, width, laq, lrl;
    if (!rv_decode_lr(w1, insn->size, &rt, &ra, &width, &laq, &lrl))
        return false;
    if (rt == 0 || ra == 0) return false;

    // The body: one conditional branch that leaves the loop when the
    // loaded value is not the expected one. `bne`/`bnez` only, funct3 1.
    uint64_t second = insn->address + 4;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned b1, b2, bf3;
    int64_t boff;
    if (!rv_decode_cond_branch(w2, len2, &b1, &b2, &bf3, &boff)) return false;
    if (bf3 != 1u) return false;
    unsigned rexp;
    if (b1 == rt) rexp = b2;
    else if (b2 == rt) rexp = b1;
    else return false;

    uint64_t third = second + len2;
    uint32_t w3;
    if (!riscvlint_word_at(state, third, &w3)) return false;
    unsigned rs, sa, rnew, swidth, saq, srl;
    if (!rv_decode_sc(w3, rv_insn_len(w3), &rs, &sa, &rnew, &swidth, &saq,
                      &srl))
        return false;
    // Same location, same width, and a result register to retry on.
    if (sa != ra || swidth != width || rs == 0) return false;

    uint64_t fourth = third + 4;
    uint32_t w4;
    if (!riscvlint_word_at(state, fourth, &w4)) return false;
    unsigned len4 = rv_insn_len(w4);
    unsigned r1, r2, rf3;
    int64_t roff;
    if (!rv_decode_cond_branch(w4, len4, &r1, &r2, &rf3, &roff)) return false;
    // `bnez rs` back to the lr: sc writes zero on success, so a retry is
    // a branch taken on nonzero.
    if (rf3 != 1u) return false;
    if (!((r1 == rs && r2 == 0) || (r2 == rs && r1 == 0))) return false;
    if ((uint64_t)((int64_t)fourth + roff) != insn->address) return false;

    uint64_t after = fourth + len4;
    // The comparison has to leave the loop rather than land inside it.
    uint64_t exit = (uint64_t)((int64_t)second + boff);
    if (exit >= insn->address && exit < after) return false;

    // The loop head is a branch target by construction -- its own retry
    // branch targets it -- so only the three instructions after it are
    // asked. Anything arriving in the middle of a compare-exchange
    // would not have run the lr.
    if (riscvlint_is_branch_target(state, second) ||
        riscvlint_is_branch_target(state, third) ||
        riscvlint_is_branch_target(state, fourth))
        return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second) ||
        riscvlint_is_relocated(state, third) ||
        riscvlint_is_relocated(state, fourth))
        return false;

    // The sc's result register disappears, so it has to be dead on both
    // ways out: past the retry branch and at the comparison's target.
    if (riscvlint_liveness(state, after, rs) != RISCVLINT_LIVE_DEAD)
        return false;
    if (riscvlint_liveness(state, exit, rs) != RISCVLINT_LIVE_DEAD)
        return false;

    // The setup is `li rt,0` where the comparison was against x0 and
    // `mv rt,rexp` otherwise. Both compress: c.li names any register
    // and c.mv any two nonzero ones, and rt is nonzero here. So the
    // replacement is two bytes plus the four of the amocas, and the
    // comparison -- unchanged, and counted on both sides -- keeps its
    // own length.
    char setup[24];
    if (rexp == 0) snprintf(setup, sizeof setup, "li %s, 0", rv_reg_name(rt));
    else snprintf(setup, sizeof setup, "mv %s, %s", rv_reg_name(rt),
                  rv_reg_name(rexp));
    unsigned before = 4 + len2 + 4 + len4;
    unsigned fold = 2 + 4 + len2;

    finding->title = "compare-exchange loop foldable to amocas";
    finding->address = insn->address;
    finding->insn_count = 4;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s ; amocas.%c%s %s, %s, (%s) (%u -> %u bytes)", setup,
             width == 8 ? 'd' : 'w', amocas_suffix(laq | saq, lrl | srl),
             rv_reg_name(rt), rv_reg_name(rnew), rv_reg_name(ra), before,
             fold);
    return true;
}

// `and`, `or` and `xor` in both spellings, which is the set Zbb has a
// complement-taking form of. The funct3 comes back so the caller can
// say which, and `c.and`/`c.or`/`c.xor` are in-place, so rd and rs1
// coincide there -- which costs nothing, the operation commuting.
static bool decode_logic(uint32_t w, unsigned size, unsigned *f3,
                         unsigned *rd, unsigned *rs1, unsigned *rs2)
{
    if (size == 4) {
        if (RV_OPCODE(w) != 0x33u || ((w >> 25) & 0x7fu) != 0u) return false;
        unsigned k = (w >> 12) & 7u;
        if (k != 7u && k != 6u && k != 4u) return false;   // and, or, xor
        *f3 = k;
        *rd = (w >> 7) & 0x1fu;
        *rs1 = (w >> 15) & 0x1fu;
        *rs2 = (w >> 20) & 0x1fu;
        return *rd != 0;
    }
    if (size != 2) return false;
    // The C1 misc-ALU register group with bit 12 clear: bits 6:5 pick
    // c.sub, c.xor, c.or and c.and, and only the last three are here.
    if ((w & 0xfc03u) != 0x8c01u) return false;
    unsigned sel = (w >> 5) & 3u;
    if (sel == 0u) return false;                           // c.sub
    *f3 = sel == 1u ? 4u : (sel == 2u ? 6u : 7u);
    *rd = *rs1 = 8u + ((w >> 7) & 0x7u);
    *rs2 = 8u + ((w >> 2) & 0x7u);
    return true;
}

// Zbb's complement-taking logical forms: `andn rd,rs1,rs2` is
// rs1 & ~rs2, `orn` the same with or, and `xnor` is ~(rs1 ^ rs2). So a
// `not` feeding any of the three folds into one instruction, and so
// does an `xor` feeding a `not`:
//
//     not  rt, rb          and  rd, ra, rt   ->  andn rd, ra, rb
//     not  rt, rb          or   rd, ra, rt   ->  orn  rd, ra, rb
//     not  rt, rb          xor  rd, ra, rt   ->  xnor rd, ra, rb
//     xor  rt, ra, rb      not  rd, rt       ->  xnor rd, ra, rb
//
// The last two are the same instruction because ~a ^ b and ~(a ^ b) are
// the same value, which is also why `xor` is the only operation whose
// two orders both fold.
//
// The two orders that do not fold are worth naming: `or` then `not` is
// NOR and `and` then `not` is NAND, and Zbb has neither. That is 5,477
// dependent pairs in the corpus against 12,474 that do fold, so the
// direction test is doing real work rather than tidying.
static const char *zbb_logic_name(unsigned f3)
{
    if (f3 == 7u) return "andn";
    if (f3 == 6u) return "orn";
    return "xnor";
}

bool check_not_logic_fold(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (!riscvlint_may_use(state, RISCVLINT_EXT_ZBB)) return false;
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);

    unsigned f3, rd, ra, rb, inter;
    unsigned nrd, nrs;
    if (rv_decode_not(w1, insn->size, &nrd, &nrs)) {
        // The complement first, consumed by the logical operation.
        unsigned s1, s2;
        if (!decode_logic(w2, len2, &f3, &rd, &s1, &s2)) return false;
        // Read exactly once: twice is `rt & rt`, which is a move of the
        // complement and not a fold, and never means the two are
        // unrelated.
        bool a = s1 == nrd, b = s2 == nrd;
        if (a == b) return false;
        ra = a ? s2 : s1;
        rb = nrs;
        inter = nrd;
    } else if (decode_logic(w1, insn->size, &f3, &inter, &ra, &rb)) {
        // The logical operation first, complemented after -- which only
        // xor folds, `or` then `not` being NOR and `and` then `not`
        // NAND, neither of which Zbb has.
        if (f3 != 4u) return false;
        if (!rv_decode_not(w2, len2, &rd, &nrs)) return false;
        if (nrs != inter) return false;
    } else {
        return false;
    }
    // x0 as the surviving operand makes the result a constant or a
    // plain complement, either of which is a different rewrite.
    if (ra == 0 || rb == 0) return false;

    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // The intermediate goes, so it has to be dead unless the second
    // instruction overwrote it. 575 of the corpus's 3,093 shapes lose
    // here and nothing else rejects any of them.
    if (rd != inter &&
        riscvlint_liveness(state, second + len2, inter) != RISCVLINT_LIVE_DEAD)
        return false;

    // None of the three has a compressed form, so the fold is always
    // four bytes. Where both halves were already compressed it buys an
    // instruction and a dependency rather than space, as the shift-add
    // family does. In the `xor`-then-`not` order the `not` is also
    // check_zcb_compressible's finding -- c.not, two bytes rather than
    // four -- and both stand: Zcb shrinks the instruction and Zbb
    // removes it.
    unsigned before = insn->size + len2;
    finding->title = "not + and/or/xor foldable to andn/orn/xnor";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, %s, %s (%u -> 4 bytes)", zbb_logic_name(f3),
             rv_reg_name(rd), rv_reg_name(ra), rv_reg_name(rb), before);
    return true;
}

// ---- a far jump that j would reach ----

bool check_jump_pair_to_j(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rd1;
    int64_t hi;
    if (!rv_decode_auipc(w1, &rd1, &hi)) return false;
    // auipc into x0 computes nothing; not a jump sequence.
    if (rd1 == 0) return false;

    uint64_t second = insn->address + 4;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned rd2, rs1;
    int64_t lo;
    // The four-byte jalr with x0 for the link register, printed `jr`.
    // The spelling that writes a link register is the call pair's, and
    // `auipc rd,X` + `c.jr rd` is the same fold saving two bytes with a
    // different encoding, left to its own check as the call pair leaves
    // `c.jalr`.
    if (!rv_decode_jalr(w2, &rd2, &rs1, &lo)) return false;
    if (rd2 != 0 || rs1 != rd1) return false;

    // Something branching to the jr would lose its transfer.
    if (riscvlint_is_branch_target(state, second)) return false;

    // In an unlinked object both immediates are placeholders waiting on
    // a relocation, so the target computed from them is fiction.
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // jalr clears bit 0 of the computed address.
    int64_t target = ((int64_t)insn->address + hi + lo) & ~(int64_t)1;
    if (target < 0) return false;
    if (!rv_jal_reaches(target - (int64_t)insn->address)) return false;

    // This is where the jump parts from the call. `jal rd` writes the
    // register the pair's jalr wrote, so that fold is exact; `j` writes
    // nothing, and after it rd holds whatever it held before the pair
    // instead of the auipc's result. The fold is sound only where
    // nothing reads rd before writing it, and there is no fall-through
    // to ask about: the walk starts where control lands.
    if (riscvlint_liveness(state, (uint64_t)target, rd1) !=
        RISCVLINT_LIVE_DEAD)
        return false;

    finding->title = "jump pair foldable to j";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "j 0x%" PRIx64 " (8 -> 4 bytes)", (uint64_t)target);
    return true;
}

// ---- a constant built in more instructions than li needs ----

typedef enum { LI_NONE, LI_START, LI_STEP } li_step_kind;

// What the instruction `w` does to a constant being built in a register:
// starts one (lui, c.lui, li, c.li) or extends one it reads and writes
// in the same register (addi, addiw, slli, ori, xori and the compressed
// addi, addiw and slli). `cur` is the value so far; on a START it is
// ignored. The arithmetic is done unsigned and reinterpreted, since the
// chains that matter here wrap by design.
static li_step_kind li_chain_step(uint32_t w, unsigned size, int64_t cur,
                                  unsigned *rd, int64_t *val)
{
    uint64_t u = (uint64_t)cur;
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u;
        unsigned d = (w >> 7) & 0x1fu, s1 = (w >> 15) & 0x1fu;
        int64_t imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
        if (d == 0) return LI_NONE;
        if (op == 0x37u) {                                      // lui
            *rd = d;
            *val = sign_extend((uint64_t)(w & 0xfffff000u), 32);
            return LI_START;
        }
        if (op == 0x13u && f3 == 0 && s1 == 0) {                // li
            *rd = d;
            *val = imm;
            return LI_START;
        }
        if (s1 != d) return LI_NONE;
        *rd = d;
        if (op == 0x13u) {
            switch (f3) {
            case 0: *val = (int64_t)(u + (uint64_t)imm); return LI_STEP;
            case 1:                                             // slli
                if ((w >> 26) != 0) return LI_NONE;
                *val = (int64_t)(u << ((w >> 20) & 0x3fu));
                return LI_STEP;
            case 4: *val = (int64_t)(u ^ (uint64_t)imm); return LI_STEP;
            case 6: *val = (int64_t)(u | (uint64_t)imm); return LI_STEP;
            default: return LI_NONE;
            }
        }
        if (op == 0x1bu && f3 == 0) {                           // addiw
            *val = sign_extend((u + (uint64_t)imm) & 0xffffffffu, 32);
            return LI_STEP;
        }
        return LI_NONE;
    }
    if (size != 2) return LI_NONE;
    unsigned cop = w & 0x3u, f3 = (w >> 13) & 0x7u;
    unsigned d = (w >> 7) & 0x1fu;
    int64_t imm6 = sign_extend((uint64_t)(((w >> 12) & 1u) << 5) |
                               ((w >> 2) & 0x1fu), 6);
    if (d == 0) return LI_NONE;
    if (cop == 1) {
        switch (f3) {
        case 2:                                                 // c.li
            *rd = d;
            *val = imm6;
            return LI_START;
        case 3:                                                 // c.lui
            if (d == 2 || imm6 == 0) return LI_NONE;
            *rd = d;
            *val = imm6 << 12;
            return LI_START;
        case 0:                                                 // c.addi
            if (imm6 == 0) return LI_NONE;                      // a hint
            *rd = d;
            *val = (int64_t)(u + (uint64_t)imm6);
            return LI_STEP;
        case 1:                                                 // c.addiw
            *rd = d;
            *val = sign_extend((u + (uint64_t)imm6) & 0xffffffffu, 32);
            return LI_STEP;
        default:
            return LI_NONE;
        }
    }
    if (cop == 2 && f3 == 0) {                                  // c.slli
        unsigned sh = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
        if (sh == 0) return LI_NONE;                            // a hint
        *rd = d;
        *val = (int64_t)(u << sh);
        return LI_STEP;
    }
    return LI_NONE;
}

// The plain RV64I recurrence for materializing `v`: lui and addiw, or
// either alone, for a value that fits 32 bits; otherwise the high part
// recursively, one slli by its trailing zeros plus twelve, and an addi
// for the low twelve bits where they are not zero. It is a construction
// and so achievable, which is all a check saying "more than needed" has
// to know; the assemblers find shorter ones for some values, which
// makes this an upper bound and the check conservative.
//
// It is priced at the encoding class of the chain it replaces -- four
// bytes an instruction where the chain had a four-byte instruction in
// it, the compressed form where the chain was all compressed and the
// form exists -- the rule the branch-over-jump check uses, so that
// compression stays the compression check's finding.
static void li_plan(int64_t v, unsigned rd, bool compressed, unsigned *insns,
                    unsigned *bytes)
{
    int64_t lo = sign_extend((uint64_t)v & 0xfffu, 12);
    bool fits6 = lo >= -32 && lo <= 31;
    if (v >= INT32_MIN && v <= INT32_MAX) {
        int64_t hi20 = sign_extend((((uint64_t)v - (uint64_t)lo) >> 12) &
                                   0xfffffu, 20);
        if (hi20 != 0) {
            (*insns)++;
            *bytes += (compressed && rd != 2 && hi20 >= -32 && hi20 <= 31)
                          ? 2 : 4;
        }
        if (lo != 0 || hi20 == 0) {
            (*insns)++;
            *bytes += (compressed && fits6) ? 2 : 4;
        }
        return;
    }
    int64_t hi = (int64_t)((uint64_t)v - (uint64_t)lo) >> 12;
    while ((hi & 1) == 0) hi >>= 1;
    li_plan(hi, rd, compressed, insns, bytes);
    (*insns)++;
    *bytes += compressed ? 2 : 4;
    if (lo != 0) {
        (*insns)++;
        *bytes += (compressed && fits6) ? 2 : 4;
    }
}

bool check_long_li(riscvlint_state *state, const cs_insn *insn,
                   riscvlint_finding *finding)
{
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    unsigned rd, r;
    int64_t val;
    if (li_chain_step(w, insn->size, 0, &rd, &val) != LI_START) return false;
    // In an unlinked object the immediates are placeholders waiting on
    // HI20/LO12 relocations and the value computed from them is fiction.
    if (riscvlint_is_relocated(state, insn->address)) return false;

    unsigned len = 1, bytes = insn->size;
    bool compressed = insn->size == 2;
    uint64_t at = insn->address + insn->size;
    for (;;) {
        uint32_t w2;
        if (!riscvlint_word_at(state, at, &w2)) break;
        unsigned size2 = rv_insn_len(w2);
        int64_t next;
        if (li_chain_step(w2, size2, val, &r, &next) != LI_STEP || r != rd)
            break;
        // A side entry into the chain arrives with a value this chain
        // did not build, so the chain ends where another path joins it.
        if (riscvlint_is_branch_target(state, at)) break;
        if (riscvlint_is_relocated(state, at)) return false;
        val = next;
        len++;
        bytes += size2;
        if (size2 == 4) compressed = false;
        at += size2;
    }
    if (len < 2) return false;

    unsigned need = 0, nbytes = 0;
    li_plan(val, rd, compressed, &need, &nbytes);
    if (need >= len || nbytes > bytes) return false;

    finding->title = "constant built in more instructions than li needs";
    finding->address = insn->address;
    finding->insn_count = len;
    snprintf(finding->replacement, sizeof finding->replacement,
             "li %s, 0x%" PRIx64 " in %u instructions (%u -> %u bytes)",
             rv_reg_name(rd), (uint64_t)val, need, bytes, nbytes);
    return true;
}

// ---- an instruction with no architectural effect ----

// The no-ops that are not `nop`: an integer or floating-point operation
// whose result is the value it read, or a write to x0 other than the
// canonical nop and the two hint families the ISA has assigned there --
// Zicbop's prefetches, which are `ori x0,rs1,imm`, and Zihintntl's
// non-temporal hints, which are `add x0,x0,x2..x5` in either width.
// Every other write to x0 is hint space nobody has claimed, and what a
// processor does with it is nothing. `what` names the form.
static bool rv_decode_no_effect(uint32_t w, unsigned size, const char **what)
{
    if (size == 4) {
        unsigned op = RV_OPCODE(w), f3 = (w >> 12) & 0x7u, f7 = w >> 25;
        unsigned rd = (w >> 7) & 0x1fu, rs1 = (w >> 15) & 0x1fu;
        unsigned rs2 = (w >> 20) & 0x1fu;
        int64_t imm = sign_extend((uint64_t)(w >> 20) & 0xfffu, 12);
        switch (op) {
        case 0x37u:                                   // lui
        case 0x17u:                                   // auipc
            if (rd != 0) return false;
            *what = "a write to x0";
            return true;
        case 0x13u:                                   // OP-IMM
            if (rd == 0) {
                if (f3 == 0 && rs1 == 0 && imm == 0) return false;   // nop
                if (f3 == 6) return false;            // a prefetch hint
                *what = "a write to x0";
                return true;
            }
            if (rs1 != rd) return false;
            switch (f3) {
            case 0:
                if (imm != 0) return false;
                *what = "a move onto itself";
                return true;
            case 1:
            case 5:
                if (((w >> 20) & 0x3fu) != 0) return false;
                if (f7 != 0 && f7 != 0x20u) return false;
                *what = "a shift by zero";
                return true;
            case 4:
            case 6:
                if (imm != 0) return false;
                *what = f3 == 4 ? "an xor with zero" : "an or with zero";
                return true;
            case 7:
                if (imm != -1) return false;
                *what = "an and with all ones";
                return true;
            default:
                return false;
            }
        case 0x33u:                                   // OP
            if (rd == 0) {
                if (f7 == 0 && f3 == 0 && rs1 == 0 && rs2 >= 2 && rs2 <= 5)
                    return false;                     // a non-temporal hint
                *what = "a write to x0";
                return true;
            }
            if (f7 == 0) {
                bool self_zero = (rs1 == rd && rs2 == 0) || (rs2 == rd && rs1 == 0);
                if (f3 == 0 && self_zero) { *what = "an add of zero"; return true; }
                if (f3 == 6 && self_zero) { *what = "an or with zero"; return true; }
                if (f3 == 4 && self_zero) { *what = "an xor with zero"; return true; }
                if (f3 == 6 && rs1 == rd && rs2 == rd) { *what = "an or with itself"; return true; }
                if (f3 == 7 && rs1 == rd && rs2 == rd) { *what = "an and with itself"; return true; }
                if ((f3 == 1 || f3 == 5) && rs1 == rd && rs2 == 0) { *what = "a shift by zero"; return true; }
                return false;
            }
            if (f7 == 0x20u) {
                if (f3 == 0 && rs1 == rd && rs2 == 0) { *what = "a subtract of zero"; return true; }
                if (f3 == 5 && rs1 == rd && rs2 == 0) { *what = "a shift by zero"; return true; }
            }
            return false;
        case 0x1bu:                                   // OP-IMM-32
        case 0x3bu:                                   // OP-32: the W forms sign-extend
            if (rd != 0) return false;
            *what = "a write to x0";
            return true;
        case 0x53u:                                   // OP-FP: fsgnj with one source is fmv
            if (f3 != 0 || rs1 != rd || rs2 != rd) return false;
            if (f7 != 0x10u && f7 != 0x11u && f7 != 0x12u) return false;
            *what = "a floating-point move onto itself";
            return true;
        default:
            return false;
        }
    }
    if (size != 2) return false;
    unsigned cop = w & 0x3u, f3 = (w >> 13) & 0x7u, rd = (w >> 7) & 0x1fu;
    unsigned rs2 = (w >> 2) & 0x1fu;
    unsigned u6 = (((w >> 12) & 1u) << 5) | ((w >> 2) & 0x1fu);
    int64_t imm6 = sign_extend((uint64_t)u6, 6);
    if (cop == 1) {
        switch (f3) {
        case 0:                                       // c.addi; rd x0 is c.nop
            if (rd == 0 || imm6 != 0) return false;
            *what = "a move onto itself";
            return true;
        case 2:                                       // c.li
        case 3:                                       // c.lui
            if (rd != 0) return false;
            *what = "a write to x0";
            return true;
        case 4: {
            unsigned sel = (w >> 10) & 0x3u;
            if (sel == 2 && imm6 == -1) { *what = "an and with all ones"; return true; }
            if (sel < 2 && u6 == 0) { *what = "a shift by zero"; return true; }
            return false;
        }
        default:
            return false;
        }
    }
    if (cop == 2) {
        if (f3 == 0) {                                // c.slli
            if (rd == 0 && u6 == 0) return false;
            if (rd == 0) { *what = "a write to x0"; return true; }
            if (u6 == 0) { *what = "a shift by zero"; return true; }
            return false;
        }
        if (f3 == 4 && rs2 != 0) {                    // c.mv / c.add
            bool add = ((w >> 12) & 1u) != 0;
            if (rd == 0) {
                if (add && rs2 >= 2 && rs2 <= 5) return false;   // non-temporal hint
                *what = "a write to x0";
                return true;
            }
            if (!add && rd == rs2) { *what = "a move onto itself"; return true; }
            return false;
        }
    }
    return false;
}

bool check_no_effect(riscvlint_state *state, const cs_insn *insn,
                     riscvlint_finding *finding)
{
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    const char *what;
    if (!rv_decode_no_effect(w, insn->size, &what)) return false;
    // `auipc x0,imm` is Zicfilp's `lpad`, the landing pad an object
    // built for that extension relies on. It is a no-op only where the
    // declared architecture positively lacks the extension; an unknown
    // architecture might have it, and is given the benefit of the doubt.
    if (insn->size == 4 && RV_OPCODE(w) == RV_OP_AUIPC &&
        riscvlint_may_use(state, RISCVLINT_EXT_ZICFILP))
        return false;
    // A relocation would fill the immediate in later; whatever it fills
    // in, an instruction that does not write is not changed by it, but
    // a `lui x0` in an unlinked object is still a placeholder and not a
    // marker, so leave it to the linker.
    if (riscvlint_is_relocated(state, insn->address)) return false;

    finding->title = "instruction with no architectural effect";
    finding->address = insn->address;
    finding->insn_count = 1;
    snprintf(finding->replacement, sizeof finding->replacement,
             "delete; %s (%u bytes)", what, insn->size);
    return true;
}

// ---- walking ahead of the cursor ----

// Whether `w` might read or write integer register `r`, answered from
// the register fields rather than by decoding the instruction: true
// whenever a field that names a register in some format names r here,
// whatever this format makes of those bits, and true for the registers
// the compressed forms name implicitly. An immediate whose bits happen
// to spell r answers true as well, which costs a finding and never
// licenses one. The walks that use it run ahead of the driver's
// cursor, where there is no decoded instruction to ask, as
// zrun_store's does.
//
// Zcmp and Zcmt share the c.fsdsp encoding space and name lists of
// registers that no field spells, so everything there answers true.
static bool rv_may_name(uint32_t w, unsigned size, unsigned r)
{
    if (size == 4)
        return ((w >> 7) & 0x1fu) == r || ((w >> 15) & 0x1fu) == r ||
               ((w >> 20) & 0x1fu) == r;
    if (size != 2) return true;
    unsigned q = w & 0x3u, f3 = (w >> 13) & 0x7u;
    if (q == 2 && f3 == 5) return true;               // c.fsdsp, Zcmp, Zcmt
    if (r == 2 && q == 0 && f3 == 0) return true;     // c.addi4spn
    if (r == 2 && q == 2 && f3 != 0 && f3 != 4) return true;   // sp-based
    if (r == 1 && q == 2 && f3 == 4 && ((w >> 12) & 1u) &&
        ((w >> 2) & 0x1fu) == 0)
        return true;                                  // c.jalr links ra
    return ((w >> 7) & 0x1fu) == r || ((w >> 2) & 0x1fu) == r ||
           8u + ((w >> 7) & 0x7u) == r || 8u + ((w >> 2) & 0x7u) == r;
}

// An instruction a forward walk cannot see past: a transfer of any kind,
// which leaves the straight line, or a system instruction, which reads
// registers no field names -- ecall's arguments -- or hands control to
// a debugger that may read any of them.
static bool rv_stops_walk(uint32_t w, unsigned size)
{
    if (rv_ends_region(w, size) || is_cond_branch_raw(w, size)) return true;
    if (size == 4) return RV_OPCODE(w) == 0x73u;
    return (w & 0xffffu) == 0x9002u;                  // c.ebreak
}

// ---- pushes one stack adjustment would do ----

// The constant an instruction adds to sp in place: `addi sp,sp,K`,
// `c.addi16sp K`, or `c.addi sp,K`, which CI format allows since it
// takes any rd.
static bool rv_decode_sp_adjust(uint32_t w, unsigned size, int64_t *k)
{
    if (size == 4) {
        unsigned rd, rs1;
        return rv_decode_addi(w, 4, &rd, &rs1, k) && rd == 2 && rs1 == 2;
    }
    if (size != 2 || ((w >> 7) & 0x1fu) != 2) return false;
    if ((w & 0xe003u) == 0x6001u) {                   // c.addi16sp
        // nzimm[9] is bit 12 and bits 6:2 are nzimm[4|6|8:7|5].
        uint64_t v = (((uint64_t)(w >> 12) & 1u) << 9) |
                     (((uint64_t)(w >> 6) & 1u) << 4) |
                     (((uint64_t)(w >> 5) & 1u) << 6) |
                     (((uint64_t)(w >> 3) & 0x3u) << 7) |
                     (((uint64_t)(w >> 2) & 1u) << 5);
        *k = sign_extend(v, 10);
        return *k != 0;
    }
    if ((w & 0xe003u) == 0x0001u) {                   // c.addi sp,K
        *k = ci_imm6(w);
        return *k != 0;
    }
    return false;
}

// What `addi sp,sp,K` costs at the encoding class of the run it
// replaces, as check_long_li prices its chain: in a compressed run,
// c.addi16sp for a multiple of 16 in its range and c.addi for a six-bit
// value; otherwise four bytes, whatever the compression check would say
// about them.
static unsigned sp_adjust_bytes(int64_t k, bool compressed)
{
    if (!compressed || k == 0) return 4;
    if (k % 16 == 0 && k >= -512 && k <= 496) return 2;
    return fits6(k) ? 2 : 4;
}

#define PUSH_WALK     64    // instructions a run may span
#define PUSH_ACCESSES 32    // sp-relative accesses it may carry

bool check_push_run(riscvlint_state *state, const cs_insn *insn,
                    riscvlint_finding *finding)
{
    if (insn->address < state->push_end) return false;
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    int64_t k;
    if (!rv_decode_sp_adjust(w, insn->size, &k) || k >= 0) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    // Every access through sp between the first adjustment and the last
    // is re-offset by what the adjustments after it would have
    // subtracted, so that it reaches the same address with sp already
    // at its final value. Memory sees the same stores in the same order;
    // only sp's intermediate values are gone.
    struct {
        rv_mem_kind kind;
        unsigned data, size;
        int64_t off;
        int64_t below;          // what the run had subtracted by then
    } acc[PUSH_ACCESSES];
    unsigned nacc = 0, nadj = 1, bytes = insn->size;
    unsigned seen = 1, span = 1;
    int64_t total = -k;
    uint64_t at = insn->address + insn->size, end = at;
    for (int budget = PUSH_WALK; budget > 0; budget--) {
        // A side entry would arrive expecting sp where the run had it.
        if (riscvlint_is_branch_target(state, at)) break;
        uint32_t w2;
        if (!riscvlint_word_at(state, at, &w2)) break;
        unsigned len = rv_insn_len(w2);
        if (riscvlint_is_relocated(state, at)) break;
        seen++;
        int64_t k2, off;
        rv_mem_kind kind;
        unsigned data, base;
        if (rv_decode_sp_adjust(w2, len, &k2)) {
            // A release ends the run, and so does a total one addi
            // cannot subtract.
            if (k2 >= 0 || total - k2 > 2048) break;
            total -= k2;
            nadj++;
        } else if (len == 2 && (w2 & 0x3u) == 2u && ((w2 >> 13) & 0x7u) == 5u) {
            break;      // c.fsdsp's space, which Zcmp's push reuses
        } else if (rv_decode_mem(w2, len, &kind, &data, &base, &off) &&
                   base == 2) {
            // An integer access naming sp as its data either stores sp's
            // own value, which the fold changes, or loads into sp.
            if (!rv_mem_is_fp(kind) && data == 2) break;
            if (nacc == PUSH_ACCESSES) break;
            acc[nacc].kind = kind;
            acc[nacc].data = data;
            acc[nacc].size = len;
            acc[nacc].off = off;
            acc[nacc].below = total;
            nacc++;
        } else {
            // Anything else may sit between pushes -- baseline code loads
            // each value just before pushing it -- provided it neither
            // reads sp, which would see the wrong value, nor writes it.
            if (rv_may_name(w2, len, 2) || rv_stops_walk(w2, len)) break;
            at += len;
            continue;
        }
        bytes += len;
        at += len;
        end = at;
        span = seen;
    }
    state->push_end = end;
    if (nadj < 2) return false;

    bool zcb = riscvlint_may_use(state, RISCVLINT_EXT_ZCB);
    unsigned after = sp_adjust_bytes(-total, insn->size == 2);
    for (unsigned i = 0; i < nacc; i++) {
        int64_t off = acc[i].off + (total - acc[i].below);
        if (off > 2047) return false;
        after += acc[i].size == 2
                     ? rv_mem_encoded_size(acc[i].kind, acc[i].data, 2, off,
                                           zcb)
                     : 4;
    }
    if (after >= bytes) return false;

    finding->title = "pushes one stack adjustment would do";
    finding->address = insn->address;
    finding->insn_count = span;
    snprintf(finding->replacement, sizeof finding->replacement,
             "one addi sp, sp, -%" PRId64 " for %u adjustments (%u -> %u "
             "bytes)", total, nadj, bytes, after);
    return true;
}

// ---- zero loaded for a store ----

#define ZSTORE_WALK 16      // instructions the stores may span

bool check_zero_for_store(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    if (insn->size != 2 && insn->size != 4) return false;
    uint32_t w;
    if (!riscvlint_word_at(state, insn->address, &w)) return false;
    unsigned rt;
    int64_t val;
    if (!decode_const(w, insn->size, &rt, &val) || val != 0) return false;
    // sp, gp and tp hold what the ABI says they hold rather than a
    // value to store, as in check_const_remat.
    if (rt == 2 || rt == 3 || rt == 4) return false;
    if (riscvlint_is_relocated(state, insn->address)) return false;

    // Every integer store of rt that follows before anything else might
    // touch it becomes a store of x0. The walk stops at the first
    // instruction that might, at a transfer, and at a side entry, where
    // a path that never ran the `li` would arrive at a store expecting
    // whatever rt held there.
    bool zcb = riscvlint_may_use(state, RISCVLINT_EXT_ZCB);
    unsigned nst = 0, before = insn->size, after = 0, seen = 1, span = 1;
    rv_mem_kind kind1 = RV_MEM_NONE;
    unsigned base1 = 0;
    int64_t off1 = 0;
    uint64_t at = insn->address + insn->size, end = at;
    for (int budget = ZSTORE_WALK; budget > 0; budget--) {
        if (riscvlint_is_branch_target(state, at)) break;
        uint32_t w2;
        if (!riscvlint_word_at(state, at, &w2)) break;
        unsigned len = rv_insn_len(w2);
        seen++;
        rv_mem_kind kind;
        unsigned data, base;
        int64_t off;
        if (rv_decode_mem(w2, len, &kind, &data, &base, &off) &&
            rv_mem_is_store(kind) && !rv_mem_is_fp(kind) && data == rt &&
            base != rt) {
            if (riscvlint_is_relocated(state, at)) break;
            if (nst++ == 0) {
                kind1 = kind;
                base1 = base;
                off1 = off;
            }
            before += len;
            // c.sdsp and c.swsp name x0 as freely as any register; the
            // quadrant-0 forms cannot, so a compressed store through any
            // other base grows back to four bytes.
            after += len == 2 ? rv_mem_encoded_size(kind, 0, base, off, zcb)
                              : 4;
            end = at + len;
            span = seen;
        } else if (rv_may_name(w2, len, rt) || rv_stops_walk(w2, len)) {
            break;
        }
        at += len;
    }
    if (nst == 0 || after >= before) return false;
    // After the fold rt no longer holds zero, so nothing past the last
    // store may read it.
    if (riscvlint_liveness(state, end, rt) != RISCVLINT_LIVE_DEAD)
        return false;

    finding->title = "zero loaded for a store";
    finding->address = insn->address;
    finding->insn_count = span;
    if (nst == 1)
        snprintf(finding->replacement, sizeof finding->replacement,
                 "%s zero, %" PRId64 "(%s) (%u -> %u bytes)",
                 rv_mem_name(kind1), off1, rv_reg_name(base1), before, after);
    else
        snprintf(finding->replacement, sizeof finding->replacement,
                 "zero for %s in %u stores (%u -> %u bytes)", rv_reg_name(rt),
                 nst, before, after);
    return true;
}

// ---- zero loaded for an equality branch ----

bool check_zero_eq_branch(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding)
{
    // No extension gate: `beqz` and `bnez` are `beq` and `bne` against
    // x0, which is also why Zibi's immediate range leaves zero out and
    // check_const_eq_branch never sees this pair.
    if (insn->size != 2 && insn->size != 4) return false;

    uint32_t w1;
    if (!riscvlint_word_at(state, insn->address, &w1)) return false;
    unsigned rc;
    int64_t val;
    if (!decode_const(w1, insn->size, &rc, &val) || val != 0) return false;
    // sp, gp and tp hold what the ABI says they hold rather than a
    // comparand, as in check_const_ord_branch.
    if (rc == 2 || rc == 3 || rc == 4) return false;

    uint64_t second = insn->address + insn->size;
    uint32_t w2;
    if (!riscvlint_word_at(state, second, &w2)) return false;
    unsigned len2 = rv_insn_len(w2);
    unsigned brs1, brs2, bf3;
    int64_t off;
    if (!rv_decode_cond_branch(w2, len2, &brs1, &brs2, &bf3, &off))
        return false;
    // Equality only. The ordered comparisons against zero are
    // check_const_ord_branch's.
    if (bf3 != 0u && bf3 != 1u) return false;
    // Exactly one operand is the zero, as in check_const_eq_branch, and
    // the other is not x0: zero against zero is settled at assembly
    // time rather than compared.
    unsigned rx;
    if (brs2 == rc && brs1 != rc) rx = brs1;
    else if (brs1 == rc && brs2 != rc) rx = brs2;
    else return false;
    if (rx == 0) return false;

    // Folding deletes the `li`, so the branch must not be reachable from
    // anywhere that did not run it.
    if (riscvlint_is_branch_target(state, second)) return false;
    if (riscvlint_is_relocated(state, insn->address) ||
        riscvlint_is_relocated(state, second))
        return false;

    // Dead on both successors, for check_const_eq_branch's reason.
    uint64_t fallthrough = second + len2;
    uint64_t taken = second + (uint64_t)off;
    if (riscvlint_liveness(state, fallthrough, rc) != RISCVLINT_LIVE_DEAD)
        return false;
    if (riscvlint_liveness(state, taken, rc) != RISCVLINT_LIVE_DEAD)
        return false;

    // Priced as check_const_ord_branch prices its beqz and bnez, from the
    // displacement as encoded now.
    unsigned after = rv_branch_encoded_size(bf3, rx, 0, off);
    unsigned before = insn->size + len2;

    finding->title = "zero loaded for an equality branch";
    finding->address = insn->address;
    finding->insn_count = 2;
    snprintf(finding->replacement, sizeof finding->replacement,
             "%s %s, 0x%" PRIx64 " (%u -> %u bytes)",
             bf3 == 0u ? "beqz" : "bnez", rv_reg_name(rx), taken, before,
             after);
    return true;
}

// ---- running every check ----

static const riscvlint_check_fn riscvlint_checks[] = {
    check_call_pair_to_jal,
    check_slli_add_to_shadd,
    check_slli_srli_to_zext,
    check_dead_def,
    check_redundant_sp_restore,
    check_redundant_extension,
    check_zcb_compressible,
    check_c_compressible,
    check_base_add_to_offset,
    check_redundant_reload,
    check_store_to_load,
    check_redundant_load,
    check_dead_store,
    check_silent_store,
    check_const_remat,
    check_comp_remat,
    check_cond_to_branch,
    check_branch_over_jump,
    check_transfer_to_next,
    check_zero_store_run,
    check_bitcast_through_frame,
    check_fp_pool_to_fli,
    check_swar_popcount,
    check_indexed_load,
    check_scaled_indexed_load,
    check_zext_indexed_load,
    check_const_mul_to_shadd,
    check_udiv_pow2,
    check_const_eq_branch,
    check_const_ord_branch,
    check_slli_srli_to_zexth,
    check_slli_srai_to_sext,
    check_cas_loop_to_amocas,
    check_not_logic_fold,
    check_jump_pair_to_j,
    check_long_li,
    check_no_effect,
    check_push_run,
    check_zero_for_store,
    check_zero_eq_branch,
};

size_t riscvlint_scan(riscvlint_state *state, csh handle,
                      const uint8_t *code, size_t len, uint64_t vaddr,
                      riscvlint_finding_fn on_finding, void *ctx,
                      uint64_t *instructions, uint64_t *skipped)
{
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return 0;
    size_t found = 0;
    const uint8_t *p = code;
    size_t remain = len;
    uint64_t addr = vaddr;
    while (remain >= 2) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            // Resynchronising past a halfword we could not read means we
            // do not know what it did to memory.
            riscvlint_state_drop_window(state);
            p += 2; remain -= 2; addr += 2;
            if (skipped) *skipped += 2;
            continue;
        }
        if (instructions) (*instructions)++;
        for (size_t i = 0;
             i < sizeof riscvlint_checks / sizeof riscvlint_checks[0]; i++) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            if (riscvlint_checks[i](state, insn, &f)) {
                found++;
                if (on_finding) on_finding(ctx, &f);
            }
        }
        // After the checks: the ones that read the window judge this
        // instruction against the table as it stood before it.
        riscvlint_state_observe(state, insn);
    }
    cs_free(insn, 1);
    return found;
}

// ---- constant chains ----
//
// See riscvlint.h for what a chain is and what the two hooks are for.

#define CCHAIN_SAMPLES 4
#define CCHAIN_TOP     15

typedef struct {
    int64_t value;
    uint64_t chains;            // times built
    uint64_t insns;             // instructions those builds cost
    uint64_t rebuilt;           // builds of a value the function had
    uint64_t rebuilt_insns;
    bool address;               // lands in something the file maps
    uint64_t samples[CCHAIN_SAMPLES];
    unsigned nsamples;
    bool used;
} cchain_val;

// One (function, value) pair that has been built. A second chain
// hitting the same pair is a rebuild.
typedef struct {
    uint64_t anchor;
    int64_t value;
    bool used;
} cchain_seen;

struct riscvlint_cchain {
    cchain_val *vals;
    size_t vals_cap, vals_used;
    cchain_seen *seen;
    size_t seen_cap, seen_used;
    uint64_t chains, insns;
    // Materializations that took one instruction. Counted but not
    // tallied by value: `li a0,0` has no cheaper spelling, so ranking
    // it by cost puts 229,650 copies of "build zero" at the top of a
    // report about what constants are expensive. Restricting the tally
    // to chains of two or more is also what makes the address
    // classification mean anything -- a one-instruction value that
    // happens to equal a mapped address is a small literal, and in a
    // shared object whose sections start near zero that is most of
    // them.
    uint64_t singles;
    uint64_t rebuilt, rebuilt_insns;
    uint64_t anchors_rebuilt;   // distinct functions holding a rebuild
    bool anchored;              // some chain was placed in a function
    uint64_t *anchor_list;      // their identities, for the count
    size_t anchor_cap, anchor_used;
    bool overflowed;            // a table could not grow; figures are low
    riscvlint_mapped_fn mapped;
    void *mapped_ctx;
    riscvlint_anchor_fn anchor;
    void *anchor_ctx;
};

static uint64_t cchain_hash(uint64_t v)
{
    // splitmix64's finalizer: the values are often small and often
    // differ only in their low bits, which a weaker mix leaves
    // colliding in runs.
    v += 0x9e3779b97f4a7c15ull;
    v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ull;
    v = (v ^ (v >> 27)) * 0x94d049bb133111ebull;
    return v ^ (v >> 31);
}

riscvlint_cchain *riscvlint_cchain_create(void)
{
    riscvlint_cchain *c = calloc(1, sizeof *c);
    return c;
}

void riscvlint_cchain_destroy(riscvlint_cchain *c)
{
    if (!c) return;
    free(c->vals);
    free(c->seen);
    free(c->anchor_list);
    free(c);
}

void riscvlint_cchain_set_hooks(riscvlint_cchain *c,
                                riscvlint_mapped_fn mapped, void *mapped_ctx,
                                riscvlint_anchor_fn anchor, void *anchor_ctx)
{
    if (!c) return;
    c->mapped = mapped;
    c->mapped_ctx = mapped_ctx;
    c->anchor = anchor;
    c->anchor_ctx = anchor_ctx;
}

static bool cchain_vals_grow(riscvlint_cchain *c)
{
    size_t cap = c->vals_cap ? c->vals_cap * 2 : 1024;
    cchain_val *grown = calloc(cap, sizeof *grown);
    if (!grown) return false;
    for (size_t i = 0; i < c->vals_cap; i++) {
        if (!c->vals[i].used) continue;
        size_t j = cchain_hash((uint64_t)c->vals[i].value) & (cap - 1);
        while (grown[j].used) j = (j + 1) & (cap - 1);
        grown[j] = c->vals[i];
    }
    free(c->vals);
    c->vals = grown;
    c->vals_cap = cap;
    return true;
}

static cchain_val *cchain_val_at(riscvlint_cchain *c, int64_t value)
{
    if (c->vals_used * 10 >= c->vals_cap * 7 && !cchain_vals_grow(c)) {
        c->overflowed = true;
        return NULL;
    }
    size_t i = cchain_hash((uint64_t)value) & (c->vals_cap - 1);
    while (c->vals[i].used) {
        if (c->vals[i].value == value) return &c->vals[i];
        i = (i + 1) & (c->vals_cap - 1);
    }
    c->vals[i].used = true;
    c->vals[i].value = value;
    c->vals_used++;
    return &c->vals[i];
}

static bool cchain_seen_grow(riscvlint_cchain *c)
{
    size_t cap = c->seen_cap ? c->seen_cap * 2 : 1024;
    cchain_seen *grown = calloc(cap, sizeof *grown);
    if (!grown) return false;
    for (size_t i = 0; i < c->seen_cap; i++) {
        if (!c->seen[i].used) continue;
        size_t j = cchain_hash(c->seen[i].anchor ^
                               cchain_hash((uint64_t)c->seen[i].value)) &
                   (cap - 1);
        while (grown[j].used) j = (j + 1) & (cap - 1);
        grown[j] = c->seen[i];
    }
    free(c->seen);
    c->seen = grown;
    c->seen_cap = cap;
    return true;
}

// True when this function has built this value before.
static bool cchain_seen_before(riscvlint_cchain *c, uint64_t anchor,
                               int64_t value)
{
    if (!anchor) return false;          // no function: nothing to repeat in
    if (c->seen_used * 10 >= c->seen_cap * 7 && !cchain_seen_grow(c)) {
        c->overflowed = true;
        return false;
    }
    uint64_t h = cchain_hash(anchor ^ cchain_hash((uint64_t)value));
    size_t i = h & (c->seen_cap - 1);
    while (c->seen[i].used) {
        if (c->seen[i].anchor == anchor && c->seen[i].value == value)
            return true;
        i = (i + 1) & (c->seen_cap - 1);
    }
    c->seen[i].used = true;
    c->seen[i].anchor = anchor;
    c->seen[i].value = value;
    c->seen_used++;
    return false;
}

// Counts a function once however many rebuilds it holds.
static void cchain_note_anchor(riscvlint_cchain *c, uint64_t anchor)
{
    for (size_t i = 0; i < c->anchor_used; i++)
        if (c->anchor_list[i] == anchor) return;
    if (c->anchor_used == c->anchor_cap) {
        size_t cap = c->anchor_cap ? c->anchor_cap * 2 : 256;
        uint64_t *grown = realloc(c->anchor_list, cap * sizeof *grown);
        if (!grown) { c->overflowed = true; return; }
        c->anchor_list = grown;
        c->anchor_cap = cap;
    }
    c->anchor_list[c->anchor_used++] = anchor;
    c->anchors_rebuilt++;
}

// Count a finished chain.
static void cchain_finish(riscvlint_cchain *c, int64_t value, unsigned ninsn,
                          uint64_t start)
{
    c->chains++;
    c->insns += ninsn;
    if (ninsn < 2) { c->singles++; return; }

    cchain_val *v = cchain_val_at(c, value);
    if (!v) return;
    v->chains++;
    v->insns += ninsn;
    if (v->nsamples < CCHAIN_SAMPLES) v->samples[v->nsamples++] = start;
    // Only a two-instruction chain can be a `%hi`/`%lo` pair, which is
    // the only way `lui`+`addi` spells an address: `lui` sets bits
    // 31:12 and the `addi` the low twelve, so the idiom is exactly two
    // and anything longer is arithmetic on a literal. A PC-relative
    // address is `auipc`-based and is not a chain at all.
    if (ninsn == 2 && c->mapped && c->mapped(c->mapped_ctx, (uint64_t)value))
        v->address = true;

    uint64_t anchor = c->anchor ? c->anchor(c->anchor_ctx, start) : 0;
    if (anchor) c->anchored = true;
    if (cchain_seen_before(c, anchor, value)) {
        v->rebuilt++;
        v->rebuilt_insns += ninsn;
        c->rebuilt++;
        c->rebuilt_insns += ninsn;
        cchain_note_anchor(c, anchor);
    }
}

// A chain in flight, one slot per general register.
typedef struct {
    bool open;
    int64_t val;
    unsigned ninsn;
    uint64_t start;
} cchain_live;

static void cchain_close(riscvlint_cchain *c, cchain_live *slot)
{
    if (!slot->open) return;
    slot->open = false;
    cchain_finish(c, slot->val, slot->ninsn, slot->start);
}

static void cchain_close_all(riscvlint_cchain *c, cchain_live *live)
{
    for (unsigned i = 0; i < 32; i++) cchain_close(c, &live[i]);
}

void riscvlint_cchain_scan(riscvlint_cchain *c, csh handle,
                           const riscvlint_state *targets,
                           const uint8_t *code, size_t len, uint64_t vaddr)
{
    if (!c) return;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return;

    // One chain per register rather than one at a time, because the
    // steps of a chain are not adjacent. A scheduler puts unrelated
    // work between a `lui` and its `addi` -- in the SWAR popcount at
    // libLLVM 0x4c92640 they are five instructions apart, with another
    // chain opening in between -- and an adjacency rule counted the
    // pairs it left alone and missed the ones it split. That is not a
    // flat undercount: it reads a value whose chain the scheduler tends
    // to separate as rarer than one it leaves alone, which reorders the
    // ranking. On libxul it reported 27 sites for `0x0f0f0f0f` where
    // the true figure is 3,972.
    //
    // A chain ends when its value is consumed, which is the rule that
    // makes this safe to carry: the first instruction to *read* the
    // register closes it, so a later `addi` on the same register starts
    // a new chain rather than extending a finished one.
    cchain_live live[32];
    memset(live, 0, sizeof live);

    const uint8_t *p = code;
    size_t remain = len;
    uint64_t addr = vaddr;
    while (remain >= 2) {
        uint64_t at = addr;
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            // An unreadable halfword: what follows is not reached from
            // what came before in any way worth tracking.
            cchain_close_all(c, live);
            p += 2; remain -= 2; addr += 2;
            continue;
        }
        uint32_t w = 0;
        memcpy(&w, code + (at - vaddr), insn->size < 4 ? insn->size : 4);

        // A branch landing here means the instructions before are not
        // necessarily the ones that ran.
        if (targets && riscvlint_is_branch_target(targets, at))
            cchain_close_all(c, live);

        // A step first, since it both reads and writes its register and
        // would otherwise close the chain it is part of.
        cchain_step st;
        if (cchain_step_of(w, insn->size, &st) && live[st.reg].open &&
            st.dst != 0) {
            cchain_live moved = live[st.reg];
            cchain_apply(&st, &moved.val);
            moved.ninsn++;
            if (st.dst != st.reg) {
                // The step derived the value into another register, and
                // the source stays in flight: an `addi` reading a
                // register whose chain is open may be *completing* that
                // constant into a fresh register, or may be *using* it
                // as a base, and nothing in the instruction tells the
                // two apart. Dropping the source assumed the first and
                // cost 23% of libLLVM's mask chains, because the second
                // is what an address computation off a built constant
                // looks like. Keeping it counts both, so the price is
                // that instructions shared between a value and a value
                // derived from it are counted under each.
                cchain_close(c, &live[st.dst]);
            }
            live[st.dst] = moved;
            continue;
        }

        // Then a composition, which likewise reads the registers whose
        // chains it consumes.
        cchain_merge mg;
        if (cchain_merge_of(w, insn->size, &mg) && live[mg.a].open &&
            live[mg.b].open) {
            cchain_live out;
            out.open = true;
            out.val = mg.is_or ? (live[mg.a].val | live[mg.b].val)
                               : (int64_t)((uint64_t)live[mg.a].val +
                                           (uint64_t)live[mg.b].val);
            // Where both halves grew from the same root instruction --
            // which is what a cross-register step leaves behind, since
            // it copies the chain rather than moving it -- their
            // instruction counts overlap and adding them would charge
            // the shared prefix twice.
            out.ninsn = live[mg.a].start == live[mg.b].start
                            ? (live[mg.a].ninsn > live[mg.b].ninsn
                                   ? live[mg.a].ninsn : live[mg.b].ninsn) + 1
                            : live[mg.a].ninsn + live[mg.b].ninsn + 1;
            out.start = live[mg.a].start < live[mg.b].start
                            ? live[mg.a].start : live[mg.b].start;
            // Both sources are consumed here, so they are closed
            // without being counted: their instructions belong to the
            // value they were built for. A half that was also used
            // elsewhere is lost, which is the safe direction.
            live[mg.a].open = false;
            live[mg.b].open = false;
            cchain_close(c, &live[mg.dst]);
            live[mg.dst] = out;
            continue;
        }

        // Anything else ends the chains it touches: a write supersedes
        // the value being built, and a read is what the value was built
        // for.
        cs_regs rr, rw;
        uint8_t nr = 0, nw = 0;
        if (cs_regs_access(handle, insn, rr, &nr, rw, &nw) == CS_ERR_OK) {
            for (uint8_t i = 0; i < nr; i++) {
                unsigned n = cs_reg_to_num(rr[i]);
                if (n < 32) cchain_close(c, &live[n]);
            }
            for (uint8_t i = 0; i < nw; i++) {
                unsigned n = cs_reg_to_num(rw[i]);
                if (n < 32) cchain_close(c, &live[n]);
            }
        } else {
            // No answer about the registers is no basis for keeping any
            // chain open.
            cchain_close_all(c, live);
        }

        // And it may itself start one. After the closes above, so that
        // `lui rd,X` over a register already building something counts
        // the old chain and begins a new one.
        unsigned rd;
        int64_t v0;
        if (decode_const(w, insn->size, &rd, &v0) && rd < 32) {
            live[rd].open = true;
            live[rd].val = v0;
            live[rd].ninsn = 1;
            live[rd].start = at;
        }

        // A call or an unconditional transfer ends the straight line,
        // and nothing in flight survives it.
        if (rv_ends_region(w, insn->size)) cchain_close_all(c, live);
    }
    // Chains running to the end of the section still happened.
    cchain_close_all(c, live);
    cs_free(insn, 1);
}

size_t riscvlint_cchain_chains(const riscvlint_cchain *c)
{
    return c ? c->chains : 0;
}

size_t riscvlint_cchain_instructions(const riscvlint_cchain *c)
{
    return c ? c->insns : 0;
}

size_t riscvlint_cchain_values(const riscvlint_cchain *c)
{
    return c ? c->vals_used : 0;
}

bool riscvlint_cchain_lookup(const riscvlint_cchain *c, int64_t value,
                             size_t *chains, size_t *insns, size_t *rebuilt,
                             bool *address)
{
    if (!c || !c->vals_cap) return false;
    size_t i = cchain_hash((uint64_t)value) & (c->vals_cap - 1);
    for (size_t n = 0; n < c->vals_cap; n++) {
        const cchain_val *v = &c->vals[i];
        if (!v->used) return false;
        if (v->value == value) {
            if (chains) *chains = v->chains;
            if (insns) *insns = v->insns;
            if (rebuilt) *rebuilt = v->rebuilt;
            if (address) *address = v->address;
            return true;
        }
        i = (i + 1) & (c->vals_cap - 1);
    }
    return false;
}

static int cchain_cmp_cost(const void *a, const void *b)
{
    const cchain_val *const *pa = a, *const *pb = b;
    const cchain_val *x = *pa, *y = *pb;
    if (x->insns != y->insns) return y->insns > x->insns ? 1 : -1;
    if (x->chains != y->chains) return y->chains > x->chains ? 1 : -1;
    return x->value < y->value ? -1 : x->value > y->value ? 1 : 0;
}

static int cchain_cmp_rebuilt(const void *a, const void *b)
{
    const cchain_val *const *pa = a, *const *pb = b;
    const cchain_val *x = *pa, *y = *pb;
    if (x->rebuilt_insns != y->rebuilt_insns)
        return y->rebuilt_insns > x->rebuilt_insns ? 1 : -1;
    return x->value < y->value ? -1 : x->value > y->value ? 1 : 0;
}

// A value as both hex and signed decimal. The hex is what a reader
// recognizes a magic number by and the decimal is what they recognize a
// struct size by, and which of the two a given constant wants is not
// something the tool can know.
static void cchain_render(int64_t v, char *out, size_t outsz)
{
    snprintf(out, outsz, "0x%" PRIx64 " (%" PRId64 ")", (uint64_t)v, v);
}

static void cchain_rows(const riscvlint_cchain *c, const char *title,
                        int (*cmp)(const void *, const void *),
                        bool rebuilt_only, bool samples)
{
    const cchain_val **rows = malloc(c->vals_used * sizeof *rows);
    if (!rows) return;
    size_t n = 0;
    for (size_t i = 0; i < c->vals_cap; i++) {
        if (!c->vals[i].used) continue;
        if (rebuilt_only && !c->vals[i].rebuilt) continue;
        rows[n++] = &c->vals[i];
    }
    if (!n) { free(rows); return; }
    qsort(rows, n, sizeof rows[0], cmp);

    printf("  %s:\n", title);
    size_t shown = n < CCHAIN_TOP ? n : CCHAIN_TOP;
    for (size_t i = 0; i < shown; i++) {
        const cchain_val *v = rows[i];
        char text[48];
        cchain_render(v->value, text, sizeof text);
        if (rebuilt_only)
            printf("    %8" PRIu64 " insns  %-28s %" PRIu64 " rebuilt of %"
                   PRIu64 "\n", v->rebuilt_insns, text, v->rebuilt,
                   v->chains);
        else
            printf("    %8" PRIu64 " insns  %-28s %" PRIu64 " chain%s%s\n",
                   v->insns, text, v->chains, v->chains == 1 ? "" : "s",
                   v->address ? ", an address" : "");
        if (samples && v->nsamples) {
            printf("             at");
            for (unsigned j = 0; j < v->nsamples; j++)
                printf(" 0x%" PRIx64, v->samples[j]);
            printf("%s\n", v->chains > v->nsamples ? " ..." : "");
        }
    }
    if (n > shown)
        printf("    %zu more value%s\n", n - shown, n - shown == 1 ? "" : "s");
    free(rows);
}

void riscvlint_cchain_print(const riscvlint_cchain *c, const char *path,
                            bool samples)
{
    if (!c) return;
    uint64_t multi = c->chains - c->singles;
    printf("Constant chains in %s: %" PRIu64 " materializations, %" PRIu64
           " instructions\n", path, c->chains, c->insns);
    printf("  one instruction: %" PRIu64 "\n", c->singles);
    printf("  two or more: %" PRIu64 " chains, %" PRIu64
           " instructions, %zu distinct values\n", multi,
           c->insns - c->singles, c->vals_used);
    if (!multi) { printf("\n"); return; }

    uint64_t addr_chains = 0, addr_insns = 0;
    for (size_t i = 0; i < c->vals_cap; i++) {
        if (!c->vals[i].used || !c->vals[i].address) continue;
        addr_chains += c->vals[i].chains;
        addr_insns += c->vals[i].insns;
    }
    // The split is the whole reason this report is readable. In a
    // linked object `lui`+`addi` of a symbol's %hi/%lo looks exactly
    // like arithmetic on a literal, and only the container can say
    // which it is. Not proof either way: a literal that happens to
    // equal a mapped address reads as an address, which is why the
    // single-instruction values are kept out of this -- they are where
    // the collisions nearly all are.
    printf("    of which addresses: %" PRIu64 " chains, %" PRIu64
           " instructions\n", addr_chains, addr_insns);
    printf("    of which constants: %" PRIu64 " chains, %" PRIu64
           " instructions\n", multi - addr_chains,
           c->insns - c->singles - addr_insns);

    cchain_rows(c, "costliest values", cchain_cmp_cost, false, samples);
    if (c->rebuilt) {
        printf("  rebuilt inside one function: %" PRIu64 " chains, %" PRIu64
               " instructions, %" PRIu64 " function%s\n", c->rebuilt,
               c->rebuilt_insns, c->anchors_rebuilt,
               c->anchors_rebuilt == 1 ? "" : "s");
        cchain_rows(c, "costliest rebuilds", cchain_cmp_rebuilt, true,
                    samples);
    } else if (!c->anchored) {
        // Not "none found": nothing said where a function begins, so
        // the question was never asked. A stripped C++ or Rust binary
        // is this case; see "Attribution" in README.md.
        printf("  rebuilt inside one function: not counted, nothing named "
               "the functions\n");
    } else {
        printf("  rebuilt inside one function: none\n");
    }
    if (c->overflowed)
        printf("  note: a table could not grow; the figures above are low\n");
    printf("\n");
}

// ---- ISA census ----
//
// See riscvlint.h for what the census claims, where the profile rungs
// come from, and why the attribution is capstone's feature groups when
// nothing else here trusts capstone with anything but iteration.

#define CENSUS_SAMPLES  4
#define CENSUS_NAME_MAX 24

// Capstone hands group ids back in a uint8_t, so 256 bounds the whole
// space and the census can index it directly. The extension table is
// bounded by the same space plus the four names raw decode adds.
#define CENSUS_GROUP_MAX 256
#define CENSUS_MAX_EXTS  128

// What a level means. The positive ones are RVA U-mode profile numbers
// and are ordered, so the profile a census implies is the largest level
// with a nonzero tally.
enum {
    CENSUS_VENDOR = -2,       // not in the standard encoding space
    CENSUS_HINT = -1,         // a base-ISA no-op on a core without it
    CENSUS_UNPROFILED = 0,    // no RVA U-mode profile mandates it
    CENSUS_RVA20 = 20,
    CENSUS_RVA22 = 22,
    CENSUS_RVA23 = 23,
};

// Every extension an RVA U-mode profile mandates, transcribed from
// llvm/lib/Target/RISCV/RISCVProfiles.td -- RVA20U64Features,
// RVA22U64Features, RVA23U64Features -- less the ones that define no
// instruction a census could count: the memory-model tags (Ziccif,
// Ziccrse, Ziccamoa, Zicclsm, Za128rs, Za64rs, Zic64b), Zkt's timing
// guarantee, and Supm. RVA22's B is written out as the three it
// bundles, which is how capstone's predicates spell it.
//
// Anything missing here is CENSUS_UNPROFILED, and that is the right
// answer rather than an omission: Zbc, Zbkb, Zfh, Zacas, Ztso, Zcmp,
// the scalar- and vector-crypto families and Zifencei are in no RVA
// U-mode profile at all, and each is one `-march=` token away on any
// target, so its presence says nothing about what the build targeted.
static const struct {
    const char *name;
    int level;
} census_levels[] = {
    { "I", CENSUS_RVA20 },        { "M", CENSUS_RVA20 },
    { "A", CENSUS_RVA20 },        { "F", CENSUS_RVA20 },
    { "D", CENSUS_RVA20 },        { "C", CENSUS_RVA20 },
    { "Zicsr", CENSUS_RVA20 },    { "Zicntr", CENSUS_RVA20 },

    { "Zba", CENSUS_RVA22 },      { "Zbb", CENSUS_RVA22 },
    { "Zbs", CENSUS_RVA22 },      { "Zfhmin", CENSUS_RVA22 },
    { "Zicbom", CENSUS_RVA22 },   { "Zicboz", CENSUS_RVA22 },
    { "Zihpm", CENSUS_RVA22 },

    { "V", CENSUS_RVA23 },        { "Zvfhmin", CENSUS_RVA23 },
    { "Zvbb", CENSUS_RVA23 },     { "Zicond", CENSUS_RVA23 },
    { "Zimop", CENSUS_RVA23 },    { "Zcmop", CENSUS_RVA23 },
    { "Zcb", CENSUS_RVA23 },      { "Zfa", CENSUS_RVA23 },
    { "Zawrs", CENSUS_RVA23 },

    // Mandatory at RVA22 (Zicbop, Zihintpause) and RVA23 (Zihintntl),
    // but all three are hint encodings: `prefetch.r` is an `ori x0`,
    // `pause` a `fence w`, `ntl.all` an `add x0,x0,x5`. A core without
    // the extension executes them as those and ignores them, so they
    // are evidence of a build flag and not of a target.
    { "Zihintpause", CENSUS_HINT }, { "Zihintntl", CENSUS_HINT },
    { "Zicbop", CENSUS_HINT },
};

typedef struct {
    char name[CENSUS_NAME_MAX];
    int level;
    size_t count;
    // First few sites, so a surprising tally can be checked in a
    // disassembler: real vector code and a string pool misread as
    // vector code both count, and only the address tells them apart.
    uint64_t samples[CENSUS_SAMPLES];
    unsigned nsamples;
} census_ext;

struct riscvlint_census {
    census_ext exts[CENSUS_MAX_EXTS];
    size_t next;
    // Group id to slot, filled on first sight. Both the name lookup and
    // the table search are too slow to repeat per instruction on a
    // 35-million-instruction object, and capstone's ids do not move
    // within a run even though they move between releases.
    // CENSUS_UNSEEN means not yet looked up and CENSUS_NOT_EXT means
    // looked up and not an extension.
    short group_slot[CENSUS_GROUP_MAX];
    size_t baseline;
    size_t instructions;
    size_t skipped;
    bool overflowed;          // more distinct extensions than the table holds
};

#define CENSUS_UNSEEN   (-2)
#define CENSUS_NOT_EXT  (-1)

riscvlint_census *riscvlint_census_create(void)
{
    riscvlint_census *census = calloc(1, sizeof *census);
    if (!census) return NULL;
    for (size_t i = 0; i < CENSUS_GROUP_MAX; i++)
        census->group_slot[i] = CENSUS_UNSEEN;
    return census;
}

void riscvlint_census_destroy(riscvlint_census *census)
{
    free(census);
}

size_t riscvlint_census_instructions(const riscvlint_census *census)
{
    return census ? census->instructions : 0;
}

size_t riscvlint_census_skipped(const riscvlint_census *census)
{
    return census ? census->skipped : 0;
}

size_t riscvlint_census_baseline(const riscvlint_census *census)
{
    return census ? census->baseline : 0;
}

size_t riscvlint_census_extension_count(const riscvlint_census *census,
                                        const char *name)
{
    if (!census || !name) return 0;
    for (size_t i = 0; i < census->next; i++)
        if (strcmp(census->exts[i].name, name) == 0)
            return census->exts[i].count;
    return 0;
}

static int census_level(const char *name, bool vendor)
{
    if (vendor) return CENSUS_VENDOR;
    for (size_t i = 0; i < sizeof census_levels / sizeof census_levels[0]; i++)
        if (strcmp(census_levels[i].name, name) == 0)
            return census_levels[i].level;
    return CENSUS_UNPROFILED;
}

// A capstone feature-group name reduced to the extension it names:
// "HasStdExtZba" -> "Zba", "HasStdExtCOrZcd" -> "C",
// "HasVInstructionsI64" -> "V". False when the group names no
// extension -- the IsRV64/IsRV32/IsRVE target groups, and the
// jump/call/ret/branch groups every capstone architecture carries.
static bool census_group_name(const char *group, char *out, size_t outsz,
                              bool *vendor)
{
    // Groups whose name is not the extension with a prefix on it.
    static const struct { const char *prefix, *name; } irregular[] = {
        // The vector groups split by what the instruction needs of the
        // element types (I64, AnyF, F16Minimal); all of them are V, and
        // capstone could not tell full V from the Zve* embedded subsets
        // in any case, since those define the same encodings.
        { "HasVInstructions", "V" },
        // c.nop and the rest of the RVC hint encodings.
        { "HasRVCHints", "C" },
        // flh/fsh/fmv.h.x: what Zfhmin has without the arithmetic.
        { "HasHalfFPLoadStoreMove", "Zfhmin" },
    };

    *vendor = false;
    if (!group) return false;
    if (strncmp(group, "Is", 2) == 0) return false;   // IsRV64, IsRV32, IsRVE

    const char *rest = NULL;
    if (strncmp(group, "HasVendor", 9) == 0) {
        rest = group + 9;
        *vendor = true;
    } else if (strncmp(group, "HasStdExt", 9) == 0) {
        rest = group + 9;
    } else {
        for (size_t i = 0; i < sizeof irregular / sizeof irregular[0]; i++)
            if (strncmp(group, irregular[i].prefix,
                        strlen(irregular[i].prefix)) == 0) {
                snprintf(out, outsz, "%s", irregular[i].name);
                return true;
            }
        return false;
    }
    if (*rest == '\0') return false;
    snprintf(out, outsz, "%s", rest);

    // "COrZcd", "ZbbOrZbkb", "ZvknhaOrZvknhb": an encoding that two
    // extensions both define. The first alternative is the one a
    // profile mandates -- the second is always the crypto or Zc*
    // spelling of the same instruction -- so reporting the first keeps
    // the ladder right. No extension name contains a capital O
    // followed by a lowercase r, so the separator cannot be mistaken
    // for part of one.
    char *sep = strstr(out, "Or");
    if (sep) *sep = '\0';
    return out[0] != '\0';
}

// Record one use of `name`, allocating its slot on first sight. Returns
// the slot, or -1 when the table is full.
static int census_bump(riscvlint_census *census, const char *name,
                       bool vendor, uint64_t addr)
{
    size_t i;
    for (i = 0; i < census->next; i++)
        if (strcmp(census->exts[i].name, name) == 0) break;
    if (i == census->next) {
        if (census->next == CENSUS_MAX_EXTS) {
            census->overflowed = true;
            return -1;
        }
        census->next++;
        snprintf(census->exts[i].name, CENSUS_NAME_MAX, "%s", name);
        census->exts[i].level = census_level(census->exts[i].name, vendor);
    }
    census->exts[i].count++;
    if (census->exts[i].nsamples < CENSUS_SAMPLES)
        census->exts[i].samples[census->exts[i].nsamples++] = addr;
    return (int)i;
}

// The four extensions capstone marks no feature group on, picked out of
// the encoding. Without this `csrr a0,cycle` and `fence.i` would be
// reported as base RV64I, which is what they are not.
static const char *census_by_encoding(uint32_t w)
{
    // `pause` is a FENCE with pred=W and succ=none; `ntl.*` are
    // `add x0,x0,rs2` for rs2 in x2..x5. Both are hints: the encodings
    // are legal base instructions that do nothing.
    if (w == 0x0100000fu) return "Zihintpause";
    if ((w & 0xfe0fffffu) == 0x00000033u) {
        unsigned rs2 = (w >> 20) & 0x1fu;
        if (rs2 >= 2 && rs2 <= 5) return "Zihintntl";
    }
    // SYSTEM with a funct3 of its own is a CSR access rather than
    // ecall/ebreak/mret; MISC-MEM funct3 1 is `fence.i`.
    if (RV_OPCODE(w) == 0x73u && ((w >> 12) & 7u) != 0) return "Zicsr";
    if (RV_OPCODE(w) == 0x0fu && ((w >> 12) & 7u) == 1) return "Zifencei";
    return NULL;
}

void riscvlint_census_scan(riscvlint_census *census, csh handle,
                           const uint8_t *code, size_t len, uint64_t vaddr)
{
    if (!census) return;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return;

    const uint8_t *p = code;
    size_t remain = len;
    uint64_t addr = vaddr;
    while (remain >= 2) {
        uint64_t at = addr;
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            // The same resynchronisation the check driver uses, so the
            // census and the findings are taken over one instruction
            // stream and not two.
            p += 2;
            remain -= 2;
            addr += 2;
            census->skipped++;
            continue;
        }
        census->instructions++;

        bool attributed = false;
        if (insn->detail) {
            for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
                uint8_t id = insn->detail->groups[g];
                short slot = census->group_slot[id];
                if (slot == CENSUS_UNSEEN) {
                    char name[CENSUS_NAME_MAX];
                    bool vendor;
                    slot = census_group_name(cs_group_name(handle, id), name,
                                             sizeof name, &vendor)
                        ? (short)census_bump(census, name, vendor, at)
                        : CENSUS_NOT_EXT;
                    census->group_slot[id] = slot;
                    if (slot >= 0) attributed = true;
                    continue;
                }
                if (slot == CENSUS_NOT_EXT) continue;
                census->exts[slot].count++;
                if (census->exts[slot].nsamples < CENSUS_SAMPLES)
                    census->exts[slot].samples[
                        census->exts[slot].nsamples++] = at;
                attributed = true;
            }
        }

        // Only where capstone marked nothing, and only the four-byte
        // forms. Both restrictions matter: Zimop's `mop.r.N` sits in
        // the SYSTEM opcode with a funct3 of its own and would read as
        // a CSR access, and the compressed hints carry capstone's
        // RVC-hint group and are already counted as C.
        if (!attributed && insn->size == 4) {
            uint32_t w = (uint32_t)insn->bytes[0] |
                         ((uint32_t)insn->bytes[1] << 8) |
                         ((uint32_t)insn->bytes[2] << 16) |
                         ((uint32_t)insn->bytes[3] << 24);
            const char *name = census_by_encoding(w);
            if (name) {
                census_bump(census, name, false, at);
                attributed = true;
            }
        }

        if (!attributed) census->baseline++;
    }
    cs_free(insn, 1);
}

const char *riscvlint_census_profile(const riscvlint_census *census)
{
    int highest = CENSUS_RVA20;
    if (census)
        for (size_t i = 0; i < census->next; i++)
            if (census->exts[i].count != 0 && census->exts[i].level > highest)
                highest = census->exts[i].level;
    if (highest >= CENSUS_RVA23) return "RVA23U64";
    if (highest >= CENSUS_RVA22) return "RVA22U64";
    return "RVA20U64";
}

// Does `arch` declare extension `name`? Tag_RISCV_arch is a base token
// and then underscore-separated extensions, each with a version suffix
// ("rv64i2p1_m2p0_..._zba1p0"), so the comparison is against a token's
// alphabetic prefix. A substring search would not do: "_zba" is inside
// "_zbahalf" too, and a search for "c" matches nearly every string.
static bool census_arch_declares(const char *arch, const char *name)
{
    size_t namelen = strlen(name);
    for (const char *tok = arch; tok != NULL; ) {
        size_t n = 0;
        while ((tok[n] >= 'a' && tok[n] <= 'z') ||
               (tok[n] >= 'A' && tok[n] <= 'Z'))
            n++;
        if (n == namelen) {
            size_t i = 0;
            while (i < n && tolower((unsigned char)tok[i]) ==
                            tolower((unsigned char)name[i]))
                i++;
            if (i == n) return true;
        }
        tok = strchr(tok, '_');
        if (tok) tok++;
    }
    return false;
}

// One "  <label>: Zba (12), ..." line for the extensions at `level`, by
// descending count with ties broken by name, "none" when empty -- so
// two censuses diff line for line.
static void census_print_level(const riscvlint_census *census, int level,
                               const char *label)
{
    size_t order[CENSUS_MAX_EXTS];
    size_t n = 0;
    for (size_t i = 0; i < census->next; i++)
        if (census->exts[i].count != 0 && census->exts[i].level == level)
            order[n++] = i;

    printf("  %s: ", label);
    if (n == 0) {
        printf("none\n");
        return;
    }
    for (size_t i = 0; i < n; i++) {
        size_t best = i;
        for (size_t j = i + 1; j < n; j++) {
            const census_ext *a = &census->exts[order[j]];
            const census_ext *b = &census->exts[order[best]];
            if (a->count > b->count ||
                (a->count == b->count && strcmp(a->name, b->name) < 0))
                best = j;
        }
        size_t tmp = order[i];
        order[i] = order[best];
        order[best] = tmp;
        printf("%s%s (%zu)", i == 0 ? "" : ", ", census->exts[order[i]].name,
               census->exts[order[i]].count);
    }
    printf("\n");
}

void riscvlint_census_print(const riscvlint_census *census, const char *path,
                            const char *arch, bool samples)
{
    if (!census) return;

    printf("ISA census");
    if (path) printf(" of %s", path);
    printf(": %zu instructions, %zu undecodable halfword%s skipped\n",
           census->instructions, census->skipped,
           census->skipped == 1 ? "" : "s");
    if (census->overflowed)
        printf("  warning: more than %d extensions; the rest went "
               "uncounted\n", CENSUS_MAX_EXTS);
    printf("  RV64I baseline: %zu\n", census->baseline);
    census_print_level(census, CENSUS_RVA20, "RVA20U64");
    census_print_level(census, CENSUS_RVA22, "RVA22U64");
    census_print_level(census, CENSUS_RVA23, "RVA23U64");
    census_print_level(census, CENSUS_UNPROFILED, "outside the RVA profiles");
    census_print_level(census, CENSUS_HINT, "hint space");
    census_print_level(census, CENSUS_VENDOR, "vendor");

    size_t unprofiled = 0;
    for (size_t i = 0; i < census->next; i++)
        if (census->exts[i].count != 0 &&
            census->exts[i].level == CENSUS_UNPROFILED)
            unprofiled++;
    printf("  minimum profile implied: %s", riscvlint_census_profile(census));
    if (unprofiled)
        printf(", plus %zu extension%s no RVA profile mandates", unprofiled,
               unprofiled == 1 ? "" : "s");
    printf("\n");

    printf("  declared: %s\n", arch ? arch : "nothing (no build attributes)");
    if (arch) {
        // Only the Z* and X* extensions are cross-checked. The
        // single-letter ones live in the base token, which a producer
        // may spell "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0" or "rv64gc" as
        // it likes, and a census that read the second as declaring
        // nothing would report six extensions undeclared on every
        // object built that way.
        size_t order[CENSUS_MAX_EXTS];
        size_t n = 0;
        for (size_t i = 0; i < census->next; i++) {
            const census_ext *e = &census->exts[i];
            if (e->count == 0 || (e->name[0] != 'Z' && e->name[0] != 'X'))
                continue;
            if (!census_arch_declares(arch, e->name)) order[n++] = i;
        }
        // By name: this is a set rather than a ranking, and sorting it
        // keeps the line from moving when unrelated code motion changes
        // which extension the census meets first.
        for (size_t i = 0; i < n; i++) {
            size_t best = i;
            for (size_t j = i + 1; j < n; j++)
                if (strcmp(census->exts[order[j]].name,
                           census->exts[order[best]].name) < 0)
                    best = j;
            size_t tmp = order[i];
            order[i] = order[best];
            order[best] = tmp;
            printf("%s%s", i == 0 ? "  used but not declared: " : ", ",
                   census->exts[order[i]].name);
        }
        if (n) printf("\n");
    }

    if (!samples) return;
    for (size_t i = 0; i < census->next; i++) {
        const census_ext *e = &census->exts[i];
        if (e->count == 0) continue;
        printf("    %s at", e->name);
        for (unsigned k = 0; k < e->nsamples; k++)
            printf("%s 0x%" PRIx64, k == 0 ? "" : ",", e->samples[k]);
        if (e->count > e->nsamples)
            printf(" (+%zu more)", e->count - e->nsamples);
        printf("\n");
    }
}
