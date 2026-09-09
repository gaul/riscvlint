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

// ---- state ----

struct riscvlint_state {
    const uint8_t *code;
    size_t size;
    uint64_t vaddr;
    uint8_t *targets;   // one bit per 2-byte unit
    uint8_t *relocs;    // one bit per 2-byte unit
};

riscvlint_state *riscvlint_state_create(void)
{
    return calloc(1, sizeof(riscvlint_state));
}

void riscvlint_state_destroy(riscvlint_state *state)
{
    if (!state) return;
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
