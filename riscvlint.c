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
    return exts;
}

// ---- state ----

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
        { "rva20", 0 },
        { "rva22", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS },
        { "rva23", RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS },
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
