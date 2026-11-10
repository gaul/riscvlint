// rwfuzz: check that the rewrites riscvlint suggests compute what the
// code they replace computed, by running both.
//
// A check's decision can be right and its advice still wrong -- a proof
// that misses a write, a rendering that names the wrong register -- and
// the unit tests and fixtures cover only the cases someone thought to
// write down. rwfuzz generates random riscv64 programs, lets riscvlint's
// scan find the opportunities of one mode's kinds in each, applies every
// finding's rewrite to a copy of the program, and runs original and
// rewrite natively from the same random registers and memory. Any
// difference in a0..a7, the frame or the scratch buffer at the end is a
// soundness bug in the check -- or in the harness.
//
// It is armlint's tools/rwfuzz with what RISC-V changes. Instructions
// are two or four bytes and riscvlint's rewrites change sizes as often
// as not, so a program is a list of slots, one instruction each, rather
// than of words: a rewrite replaces slots, the program is laid out
// again, and every transfer is re-aimed at the slot it named. And the
// advice is text -- `mv a3, a0`, `andi s4, s4, 7`, `j 0x10016` -- so
// rwfuzz carries an assembler for the instructions the renderings use
// and follows the text itself: what is tested is the advice a reader
// gets.
//
// Each program is a fixed prologue that reserves a 64-byte frame and
// fills it, loads a0..a7, and points s0 at the frame's top and s1 at a
// scratch buffer, all from a state block; a random body; and an epilogue
// that records where the body left sp, restores it from s0, and stores
// a0..a7 and the frame back. After it sit a stub the body
// can call, which reads its arguments, the frame and the buffer and
// writes a0..a7 and a word of the frame and of the buffer, as a callee
// handed their addresses may, and a `j` to the stub. The body writes
// a0..a7, memory, and two pointer registers, t3 and t4, that only ever
// hold the frame's address or one 0 to 64 bytes into the buffer, so that
// an access through them is safe whatever path reached it: RV64IM
// arithmetic and the Zba, Zbb and Zbs operations, loads and stores
// through sp, s0, s1, t3 and t4, forward branches and jumps, V8's far
// jump through t5, direct calls and calls through auipc, and the shapes
// the mode plants for its checks to find -- each instruction in its
// compressed spelling half the time where C or Zcb has one. Register
// values lean on the edges -- zero, all ones, the 32-bit boundaries,
// small constants and their negatives -- where a rewrite and the
// original part.
//
// A thunk runs each program on a stack of its own, so that the frame is
// at one address in every run, and with s0..s11 zero; what they and sp
// hold when it returns is compared with the rest, and so is the whole
// stack, below sp included, since a rewrite that moves sp must leave
// memory as the original did. A guard above the frame takes a body that
// releases more than it reserved. A rewrite that writes gp or tp is
// reported without being run, since rwfuzz reaches its own globals and
// its thread's data through them.
//
// t1 and t5 are written only by an auipc, so they hold zero or a code
// address, which the layout moves; the body reads them only through
// `snez`, which is the same in both. That is what makes a wrong claim
// that an auipc's register is dead visible without making every rewrite
// that moves code look like one.
//
// Modes, one or more checks each:
//   ext    check_redundant_extension: delete the extension, or make it
//          the mv the finding renders.
//   dead   check_dead_def: delete the definition nothing reads.
//   remat  check_comp_remat and check_const_remat: delete the
//          computation or constant its register already holds, or make
//          it the mv the finding renders.
//   mem    the five window checks over loads and stores -- the redundant
//          reload, the load of a just-stored value, the load of a value
//          the register still holds, the dead store to a frame slot and
//          the store of a value the slot already holds: delete the
//          access, or make the load the move or extension rendered;
//          the base add folded into the access's offset; and a run of
//          zero stores as the aligned stores rwfuzz works out cover the
//          bytes rendered.
//   const  the constants built for their uses: a constant loaded for
//          operations with an immediate form, zero loaded for stores, a
//          mask loaded for ands, a constant whose complement builds
//          shorter, and a constant built in more instructions than li
//          needs. Their windows hold unrelated instructions between the
//          uses, so the chain goes and each use is rewritten -- as the
//          rendering spells it where it spells it, and where it gives
//          only a count, as rwfuzz itself works out.
//   stack  the stack adjustments: pushes or pops one adjustment would do
//          -- the adjustments merged into one by the total rendered, and
//          the accesses between moved by what rwfuzz works out the run
//          had yet to reserve or had already released -- a release
//          followed by a reservation, and the restore of an sp that
//          never moved from the frame pointer.
//   shift  the pair folds: slli + srli to zext.w, zext.h or andi, slli +
//          srai to sext.b or sext.h, slli + add and li + mul to shNadd,
//          not + and/or/xor to andn/orn/xnor, li + divu/remu to a shift
//          or a mask.
//   branch the control-flow rewrites: a branch its operands decide, a
//          constant or a comparison made for one branch, a branch over
//          a jump, a transfer to the next instruction or to a jump, the
//          jump and call pairs that fold to j and jal, and a branch over
//          a move that max or min does.
//   copy   check_copy_for_reader: delete the mv and have its reader name
//          the register the finding renders; and check_odd_move and
//          check_no_effect, the moves spelled otherwise and the
//          instructions that change nothing.
//   self   the harness's own check: each program against its spelling
//          with nothing compressed. Any difference is a bug in rwfuzz's
//          encoders.
//
// A control arm applies the same kind of rewrite where riscvlint REFUSED
// to -- an unflagged extension deleted, an unflagged write deleted, an
// unflagged pair folded -- and counts how often that changes the result:
// a harness that never saw a difference there could not see one
// anywhere. To check the harness itself after changing it, break the
// proof a mode exercises in riscvlint.c, rebuild libriscvlint.a and
// rwfuzz, and expect mismatches within a few thousand programs.
//
// Usage: rwfuzz [-n PROGRAMS] [-s SEED] MODE
//   -n  programs to generate (default 100000)
//   -s  seed, mixed into the fixed default one (default 0)
// Exit status: 0 when every finding was applied and matched; 1 on a
// mismatch, or on a finding the harness could not apply (a rendering it
// no longer reads would otherwise drop out of the test silently); 2 on
// a usage or environment error, a run that tested no finding included.
//
// The programs run on the host, so rwfuzz needs a riscv64 one with Zba,
// Zbb and Zbs, which RVA23 hosts such as the SpacemiT K3 have. Built by
// `make tools`; it links libriscvlint.a.

#define _GNU_SOURCE

#include <stdio.h>

#if !defined(__riscv) || __riscv_xlen != 64

int main(void)
{
    fprintf(stderr, "rwfuzz: the programs it generates run natively, so "
            "it needs a riscv64 host\n");
    return 2;
}

#else

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "riscvlint.h"

// === Randomness ===

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

// xorshift64*: fast, and reproducible from the seed.
static uint64_t rnd(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
}

static unsigned rr(unsigned n)
{
    return (unsigned)(rnd() % n);
}

// True one time in n.
static bool coin(unsigned n)
{
    return rr(n) == 0;
}

// === Registers ===

enum {
    X0 = 0, RA = 1, SP = 2, T0 = 5, T1 = 6, T2 = 7, S0 = 8, S1 = 9,
    A0 = 10, S2 = 18, S3 = 19, T3 = 28, T4 = 29, T5 = 30, T6 = 31,
};

static const char *const xnames[32] = {
    "zero", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2",
    "s0",   "s1", "a0", "a1", "a2",  "a3",  "a4", "a5",
    "a6",   "a7", "s2", "s3", "s4",  "s5",  "s6", "s7",
    "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};

// The body computes in a0..a7; a source is x0 now and then.
static unsigned breg(void)
{
    return A0 + rr(8);
}

static unsigned sreg(void)
{
    return coin(12) ? X0 : breg();
}

static bool creg(unsigned r)
{
    return r >= 8 && r <= 15;
}

// === Encoders ===

enum {
    OP_LOAD = 0x03, OP_IMM = 0x13, OP_AUIPC = 0x17, OP_IMM32 = 0x1b,
    OP_STORE = 0x23, OP_OP = 0x33, OP_LUI = 0x37, OP_OP32 = 0x3b,
    OP_BRANCH = 0x63, OP_JALR = 0x67, OP_JAL = 0x6f,
};

static int64_t sext(uint64_t v, unsigned bits)
{
    if (bits >= 64) {
        return (int64_t)v;
    }
    uint64_t m = 1ull << (bits - 1);
    v &= (m << 1) - 1;
    return (int64_t)((v ^ m) - m);
}

static uint32_t enc_r(unsigned op, unsigned f3, unsigned f7, unsigned rd,
                      unsigned rs1, unsigned rs2)
{
    return f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
}

static uint32_t enc_i(unsigned op, unsigned f3, unsigned rd, unsigned rs1,
                      int32_t imm)
{
    return ((uint32_t)imm & 0xfffu) << 20 | rs1 << 15 | f3 << 12 | rd << 7 |
           op;
}

static uint32_t enc_s(unsigned f3, unsigned rs1, unsigned rs2, int32_t imm)
{
    uint32_t u = (uint32_t)imm;
    return (u >> 5 & 0x7fu) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 |
           (u & 0x1fu) << 7 | OP_STORE;
}

static uint32_t enc_b(unsigned f3, unsigned rs1, unsigned rs2, int32_t off)
{
    uint32_t u = (uint32_t)off;
    return (u >> 12 & 1u) << 31 | (u >> 5 & 0x3fu) << 25 | rs2 << 20 |
           rs1 << 15 | f3 << 12 | (u >> 1 & 0xfu) << 8 | (u >> 11 & 1u) << 7 |
           OP_BRANCH;
}

static uint32_t enc_u(unsigned op, unsigned rd, uint32_t imm20)
{
    return (imm20 & 0xfffffu) << 12 | rd << 7 | op;
}

static uint32_t enc_j(unsigned rd, int32_t off)
{
    uint32_t u = (uint32_t)off;
    return (u >> 20 & 1u) << 31 | (u >> 1 & 0x3ffu) << 21 |
           (u >> 11 & 1u) << 20 | (u >> 12 & 0xffu) << 12 | rd << 7 | OP_JAL;
}

static uint32_t addi(unsigned d, unsigned s, int32_t i) { return enc_i(OP_IMM, 0, d, s, i); }
static uint32_t addiw(unsigned d, unsigned s, int32_t i) { return enc_i(OP_IMM32, 0, d, s, i); }
static uint32_t andi(unsigned d, unsigned s, int32_t i) { return enc_i(OP_IMM, 7, d, s, i); }
static uint32_t ori(unsigned d, unsigned s, int32_t i) { return enc_i(OP_IMM, 6, d, s, i); }
static uint32_t xori(unsigned d, unsigned s, int32_t i) { return enc_i(OP_IMM, 4, d, s, i); }
static uint32_t slli(unsigned d, unsigned s, unsigned k) { return enc_i(OP_IMM, 1, d, s, (int32_t)k); }
static uint32_t srli(unsigned d, unsigned s, unsigned k) { return enc_i(OP_IMM, 5, d, s, (int32_t)k); }
static uint32_t srai(unsigned d, unsigned s, unsigned k) { return enc_i(OP_IMM, 5, d, s, (int32_t)(0x400u | k)); }
static uint32_t sext_b(unsigned d, unsigned s) { return enc_i(OP_IMM, 1, d, s, 0x604); }
static uint32_t sext_h(unsigned d, unsigned s) { return enc_i(OP_IMM, 1, d, s, 0x605); }
static uint32_t zext_h(unsigned d, unsigned s) { return enc_r(OP_OP32, 4, 0x04, d, s, X0); }
static uint32_t zext_w(unsigned d, unsigned s) { return enc_r(OP_OP32, 0, 0x04, d, s, X0); }
static uint32_t add(unsigned d, unsigned a, unsigned b) { return enc_r(OP_OP, 0, 0x00, d, a, b); }
static uint32_t sub(unsigned d, unsigned a, unsigned b) { return enc_r(OP_OP, 0, 0x20, d, a, b); }
static uint32_t xor_(unsigned d, unsigned a, unsigned b) { return enc_r(OP_OP, 4, 0x00, d, a, b); }
static uint32_t or_(unsigned d, unsigned a, unsigned b) { return enc_r(OP_OP, 6, 0x00, d, a, b); }
static uint32_t and_(unsigned d, unsigned a, unsigned b) { return enc_r(OP_OP, 7, 0x00, d, a, b); }
static uint32_t lui(unsigned d, uint32_t imm20) { return enc_u(OP_LUI, d, imm20); }
static uint32_t auipc(unsigned d, uint32_t imm20) { return enc_u(OP_AUIPC, d, imm20); }
static uint32_t mv(unsigned d, unsigned s) { return addi(d, s, 0); }
static uint32_t li(unsigned d, int32_t v) { return addi(d, X0, v); }
static uint32_t ld(unsigned d, unsigned b, int32_t off) { return enc_i(OP_LOAD, 3, d, b, off); }
static uint32_t sd(unsigned s, unsigned b, int32_t off) { return enc_s(3, b, s, off); }
static uint32_t jalr(unsigned d, unsigned s, int32_t off) { return enc_i(OP_JALR, 0, d, s, off); }

// The register-register operations: the assembler's table, and the
// generator draws from the first N_GEN_ROPS. Zicond is the K3's, but
// capstone 6 does not decode it, and a scan that cannot read an
// instruction drops its windows there.
typedef struct {
    const char *name;
    uint8_t op, f3, f7;
} rop_t;

static const rop_t rops[] = {
    { "add", OP_OP, 0, 0x00 },        { "sub", OP_OP, 0, 0x20 },
    { "sll", OP_OP, 1, 0x00 },        { "slt", OP_OP, 2, 0x00 },
    { "sltu", OP_OP, 3, 0x00 },       { "xor", OP_OP, 4, 0x00 },
    { "srl", OP_OP, 5, 0x00 },        { "sra", OP_OP, 5, 0x20 },
    { "or", OP_OP, 6, 0x00 },         { "and", OP_OP, 7, 0x00 },
    { "mul", OP_OP, 0, 0x01 },        { "mulh", OP_OP, 1, 0x01 },
    { "mulhsu", OP_OP, 2, 0x01 },     { "mulhu", OP_OP, 3, 0x01 },
    { "div", OP_OP, 4, 0x01 },        { "divu", OP_OP, 5, 0x01 },
    { "rem", OP_OP, 6, 0x01 },        { "remu", OP_OP, 7, 0x01 },
    { "addw", OP_OP32, 0, 0x00 },     { "subw", OP_OP32, 0, 0x20 },
    { "sllw", OP_OP32, 1, 0x00 },     { "srlw", OP_OP32, 5, 0x00 },
    { "sraw", OP_OP32, 5, 0x20 },     { "mulw", OP_OP32, 0, 0x01 },
    { "divw", OP_OP32, 4, 0x01 },     { "divuw", OP_OP32, 5, 0x01 },
    { "remw", OP_OP32, 6, 0x01 },     { "remuw", OP_OP32, 7, 0x01 },
    { "sh1add", OP_OP, 2, 0x10 },     { "sh2add", OP_OP, 4, 0x10 },
    { "sh3add", OP_OP, 6, 0x10 },     { "add.uw", OP_OP32, 0, 0x04 },
    { "sh1add.uw", OP_OP32, 2, 0x10 }, { "sh2add.uw", OP_OP32, 4, 0x10 },
    { "sh3add.uw", OP_OP32, 6, 0x10 },
    { "andn", OP_OP, 7, 0x20 },       { "orn", OP_OP, 6, 0x20 },
    { "xnor", OP_OP, 4, 0x20 },       { "min", OP_OP, 4, 0x05 },
    { "minu", OP_OP, 5, 0x05 },       { "max", OP_OP, 6, 0x05 },
    { "maxu", OP_OP, 7, 0x05 },       { "rol", OP_OP, 1, 0x30 },
    { "ror", OP_OP, 5, 0x30 },        { "rolw", OP_OP32, 1, 0x30 },
    { "rorw", OP_OP32, 5, 0x30 },     { "bset", OP_OP, 1, 0x14 },
    { "bclr", OP_OP, 1, 0x24 },       { "binv", OP_OP, 1, 0x34 },
    { "bext", OP_OP, 5, 0x24 },
    { "czero.eqz", OP_OP, 5, 0x07 },  { "czero.nez", OP_OP, 7, 0x07 },
};
#define N_ROPS (sizeof rops / sizeof rops[0])
#define N_GEN_ROPS (N_ROPS - 2)

// The immediate operations. `hi` is what the immediate field holds above
// a shift amount, or all of it for a unary operation.
enum { I_IMM, I_SH6, I_SH5, I_UNARY };

typedef struct {
    const char *name;
    uint8_t op, f3, form;
    uint16_t hi;
} iop_t;

static const iop_t iops[] = {
    { "addi", OP_IMM, 0, I_IMM, 0 },       { "slti", OP_IMM, 2, I_IMM, 0 },
    { "sltiu", OP_IMM, 3, I_IMM, 0 },      { "xori", OP_IMM, 4, I_IMM, 0 },
    { "ori", OP_IMM, 6, I_IMM, 0 },        { "andi", OP_IMM, 7, I_IMM, 0 },
    { "slli", OP_IMM, 1, I_SH6, 0x000 },   { "srli", OP_IMM, 5, I_SH6, 0x000 },
    { "srai", OP_IMM, 5, I_SH6, 0x400 },   { "addiw", OP_IMM32, 0, I_IMM, 0 },
    { "slliw", OP_IMM32, 1, I_SH5, 0x000 }, { "srliw", OP_IMM32, 5, I_SH5, 0x000 },
    { "sraiw", OP_IMM32, 5, I_SH5, 0x400 }, { "slli.uw", OP_IMM32, 1, I_SH6, 0x080 },
    { "rori", OP_IMM, 5, I_SH6, 0x600 },   { "roriw", OP_IMM32, 5, I_SH5, 0x600 },
    { "bseti", OP_IMM, 1, I_SH6, 0x280 },  { "bclri", OP_IMM, 1, I_SH6, 0x480 },
    { "binvi", OP_IMM, 1, I_SH6, 0x680 },  { "bexti", OP_IMM, 5, I_SH6, 0x480 },
    { "clz", OP_IMM, 1, I_UNARY, 0x600 },  { "ctz", OP_IMM, 1, I_UNARY, 0x601 },
    { "cpop", OP_IMM, 1, I_UNARY, 0x602 }, { "sext.b", OP_IMM, 1, I_UNARY, 0x604 },
    { "sext.h", OP_IMM, 1, I_UNARY, 0x605 }, { "clzw", OP_IMM32, 1, I_UNARY, 0x600 },
    { "ctzw", OP_IMM32, 1, I_UNARY, 0x601 }, { "cpopw", OP_IMM32, 1, I_UNARY, 0x602 },
    { "orc.b", OP_IMM, 5, I_UNARY, 0x287 }, { "rev8", OP_IMM, 5, I_UNARY, 0x6b8 },
};
#define N_IOPS (sizeof iops / sizeof iops[0])

static uint32_t iop_word(const iop_t *o, unsigned d, unsigned s, int64_t imm)
{
    switch (o->form) {
    case I_IMM: return enc_i(o->op, o->f3, d, s, (int32_t)imm);
    case I_UNARY: return enc_i(o->op, o->f3, d, s, o->hi);
    case I_SH5: return enc_i(o->op, o->f3, d, s, (int32_t)(o->hi | (imm & 31)));
    default: return enc_i(o->op, o->f3, d, s, (int32_t)(o->hi | (imm & 63)));
    }
}

static const rop_t *rop(const char *name)
{
    for (size_t i = 0; i < N_ROPS; i++) {
        if (strcmp(rops[i].name, name) == 0) {
            return &rops[i];
        }
    }
    abort();
}

static const iop_t *iop(const char *name)
{
    for (size_t i = 0; i < N_IOPS; i++) {
        if (strcmp(iops[i].name, name) == 0) {
            return &iops[i];
        }
    }
    abort();
}

static uint32_t rop_word(const char *name, unsigned d, unsigned a, unsigned b)
{
    const rop_t *o = rop(name);
    return enc_r(o->op, o->f3, o->f7, d, a, b);
}

static const char *const load_names[7] = {
    "lb", "lh", "lw", "ld", "lbu", "lhu", "lwu",
};
static const char *const store_names[4] = { "sb", "sh", "sw", "sd" };

static const unsigned branch_f3[6] = { 0, 1, 4, 5, 6, 7 };

static unsigned width_of(unsigned f3)
{
    return 1u << (f3 & 3u);
}

// The li a planner without Zb* builds: lui + addiw for a 32-bit value,
// and otherwise the upper part, a shift and an addi, recursively --
// RISCVMatInt's generateInstSeqImpl without its special cases. Any
// correct sequence will do; what riscvlint claims is the value.
static int li_seq(unsigned rd, int64_t v, uint32_t *out)
{
    int64_t lo = sext((uint64_t)v, 12);
    if (v >= INT32_MIN && v <= INT32_MAX) {
        uint32_t hi = (uint32_t)((uint64_t)(v - lo) >> 12) & 0xfffffu;
        if (hi == 0) {
            out[0] = addi(rd, X0, (int32_t)lo);
            return 1;
        }
        out[0] = lui(rd, hi);
        if (lo == 0) {
            return 1;
        }
        out[1] = addiw(rd, rd, (int32_t)lo);
        return 2;
    }
    uint64_t hi52 = ((uint64_t)v + 0x800u) >> 12;
    unsigned sh = 12u + (unsigned)__builtin_ctzll(hi52);
    int n = li_seq(rd, sext(hi52 >> (sh - 12u), 64u - sh), out);
    out[n++] = slli(rd, rd, sh);
    if (lo != 0) {
        out[n++] = addi(rd, rd, (int32_t)lo);
    }
    return n;
}

// === Compressed spellings ===

static bool fits6(int64_t v)
{
    return v >= -32 && v <= 31;
}

// CI format: c.li, c.addi, c.addiw, c.lui, c.slli.
static uint16_t c_i(unsigned base, unsigned rd, int64_t v)
{
    return (uint16_t)(base | ((uint32_t)v >> 5 & 1u) << 12 | rd << 7 |
                      ((uint32_t)v & 0x1fu) << 2);
}

// CB format with a six-bit immediate: c.srli, c.srai, c.andi.
static uint16_t c_b6(unsigned base, unsigned rd, int64_t v)
{
    return (uint16_t)(base | ((uint32_t)v >> 5 & 1u) << 12 | (rd - 8u) << 7 |
                      ((uint32_t)v & 0x1fu) << 2);
}

// CA format: c.sub, c.xor, c.or, c.and, c.subw, c.addw, c.mul.
static uint16_t c_a(unsigned f6, unsigned f2, unsigned rd, unsigned rs2)
{
    return (uint16_t)(f6 << 10 | (rd - 8u) << 7 | f2 << 5 | (rs2 - 8u) << 2 |
                      1u);
}

// Zcb's unary group: c.zext.b, c.sext.b, c.zext.h, c.sext.h, c.zext.w,
// c.not, by `sel`.
static uint16_t c_unary(unsigned rd, unsigned sel)
{
    return (uint16_t)(0x9c61u | (rd - 8u) << 7 | sel << 2);
}

// The two-byte spelling of a four-byte word, where C or Zcb has one, or
// 0. The control transfers are spelled at layout time instead.
static uint16_t compress(uint32_t w)
{
    unsigned op = w & 0x7fu, f3 = w >> 12 & 7u, f7 = w >> 25;
    unsigned rd = w >> 7 & 31u, rs1 = w >> 15 & 31u, rs2 = w >> 20 & 31u;
    int64_t imm = sext(w >> 20, 12);
    unsigned sh = w >> 20 & 63u, top6 = w >> 26;
    switch (op) {
    case OP_IMM:
        switch (f3) {
        case 0:
            if (rd == 0) {
                return 0;
            }
            if (rs1 == 0 && fits6(imm)) {
                return c_i(0x4001u, rd, imm);                       // c.li
            }
            if (rd == SP && rs1 == SP && imm != 0 && imm % 16 == 0 &&
                    imm >= -512 && imm <= 496) {                    // c.addi16sp
                uint32_t u = (uint32_t)imm;
                return (uint16_t)(0x6101u | (u >> 9 & 1u) << 12 |
                                  (u >> 4 & 1u) << 6 | (u >> 6 & 1u) << 5 |
                                  (u >> 7 & 3u) << 3 | (u >> 5 & 1u) << 2);
            }
            if (rs1 == SP && creg(rd) && imm > 0 && imm < 1024 &&
                    imm % 4 == 0) {                                 // c.addi4spn
                uint32_t u = (uint32_t)imm;
                return (uint16_t)((u >> 4 & 3u) << 11 | (u >> 6 & 15u) << 7 |
                                  (u >> 2 & 1u) << 6 | (u >> 3 & 1u) << 5 |
                                  (rd - 8u) << 2);
            }
            if (imm == 0 && rs1 != 0) {
                return (uint16_t)(0x8002u | rd << 7 | rs1 << 2);    // c.mv
            }
            if (rs1 == rd && imm != 0 && fits6(imm)) {
                return c_i(0x0001u, rd, imm);                       // c.addi
            }
            return 0;
        case 1:
            if (rd != rs1) {
                return 0;
            }
            if (top6 == 0 && rd != 0 && sh != 0) {
                return c_i(0x0002u, rd, sh);                        // c.slli
            }
            if (creg(rd) && (w >> 20) == 0x604u) {
                return c_unary(rd, 1);                              // c.sext.b
            }
            if (creg(rd) && (w >> 20) == 0x605u) {
                return c_unary(rd, 3);                              // c.sext.h
            }
            return 0;
        case 4:
            if (rd == rs1 && creg(rd) && imm == -1) {
                return c_unary(rd, 5);                              // c.not
            }
            return 0;
        case 5:
            if (rd != rs1 || !creg(rd) || sh == 0) {
                return 0;
            }
            if (top6 == 0x00) {
                return c_b6(0x8001u, rd, sh);                       // c.srli
            }
            if (top6 == 0x10) {
                return c_b6(0x8401u, rd, sh);                       // c.srai
            }
            return 0;
        case 7:
            if (rd != rs1 || !creg(rd)) {
                return 0;
            }
            if (imm == 255) {
                return c_unary(rd, 0);                              // c.zext.b
            }
            if (fits6(imm)) {
                return c_b6(0x8801u, rd, imm);                      // c.andi
            }
            return 0;
        default:
            return 0;
        }
    case OP_IMM32:
        if (f3 == 0 && rd == rs1 && rd != 0 && fits6(imm)) {
            return c_i(0x2001u, rd, imm);                           // c.addiw
        }
        return 0;
    case OP_LUI: {
        int64_t v = sext(w >> 12, 20);
        if (rd != 0 && rd != SP && v != 0 && fits6(v)) {
            return c_i(0x6001u, rd, v);                             // c.lui
        }
        return 0;
    }
    case OP_OP: {
        if (f7 == 0 && f3 == 0) {                                   // add
            if (rd == 0) {
                return 0;
            }
            if (rs1 == 0 && rs2 != 0) {
                return (uint16_t)(0x8002u | rd << 7 | rs2 << 2);    // c.mv
            }
            if (rd == rs1 && rs2 != 0) {
                return (uint16_t)(0x9002u | rd << 7 | rs2 << 2);    // c.add
            }
            if (rd == rs2 && rs1 != 0) {
                return (uint16_t)(0x9002u | rd << 7 | rs1 << 2);
            }
            return 0;
        }
        int f2 = -1;
        unsigned f6 = 0x23u;
        bool commutes = true;
        if (f7 == 0x20 && f3 == 0) {
            f2 = 0;                                                 // c.sub
            commutes = false;
        } else if (f7 == 0 && f3 == 4) {
            f2 = 1;                                                 // c.xor
        } else if (f7 == 0 && f3 == 6) {
            f2 = 2;                                                 // c.or
        } else if (f7 == 0 && f3 == 7) {
            f2 = 3;                                                 // c.and
        } else if (f7 == 1 && f3 == 0) {
            f2 = 2;                                                 // c.mul
            f6 = 0x27u;
        }
        if (f2 < 0) {
            return 0;
        }
        if (rd == rs1 && creg(rd) && creg(rs2)) {
            return c_a(f6, (unsigned)f2, rd, rs2);
        }
        if (commutes && rd == rs2 && creg(rd) && creg(rs1)) {
            return c_a(f6, (unsigned)f2, rd, rs1);
        }
        return 0;
    }
    case OP_OP32:
        if (f7 == 0x04 && rs2 == 0 && rd == rs1 && creg(rd)) {
            if (f3 == 0) {
                return c_unary(rd, 4);                              // c.zext.w
            }
            if (f3 == 4) {
                return c_unary(rd, 2);                              // c.zext.h
            }
            return 0;
        }
        if (f3 == 0 && (f7 == 0 || f7 == 0x20)) {
            unsigned f2 = f7 == 0 ? 1u : 0u;                        // c.addw, c.subw
            if (rd == rs1 && creg(rd) && creg(rs2)) {
                return c_a(0x27u, f2, rd, rs2);
            }
            if (f7 == 0 && rd == rs2 && creg(rd) && creg(rs1)) {
                return c_a(0x27u, f2, rd, rs1);
            }
        }
        return 0;
    case OP_LOAD: {
        uint32_t off = (uint32_t)imm;
        if (rs1 == SP && rd != 0 && imm >= 0) {
            if (f3 == 3 && off < 512 && off % 8 == 0) {             // c.ldsp
                return (uint16_t)(0x6002u | (off >> 5 & 1u) << 12 | rd << 7 |
                                  (off >> 3 & 3u) << 5 | (off >> 6 & 7u) << 2);
            }
            if (f3 == 2 && off < 256 && off % 4 == 0) {             // c.lwsp
                return (uint16_t)(0x4002u | (off >> 5 & 1u) << 12 | rd << 7 |
                                  (off >> 2 & 7u) << 4 | (off >> 6 & 3u) << 2);
            }
            return 0;
        }
        if (!creg(rd) || !creg(rs1) || imm < 0) {
            return 0;
        }
        unsigned b = rs1 - 8u, d = rd - 8u;
        if (f3 == 3 && off < 256 && off % 8 == 0) {                 // c.ld
            return (uint16_t)(0x6000u | (off >> 3 & 7u) << 10 | b << 7 |
                              (off >> 6 & 3u) << 5 | d << 2);
        }
        if (f3 == 2 && off < 128 && off % 4 == 0) {                 // c.lw
            return (uint16_t)(0x4000u | (off >> 3 & 7u) << 10 | b << 7 |
                              (off >> 2 & 1u) << 6 | (off >> 6 & 1u) << 5 |
                              d << 2);
        }
        if (f3 == 4 && off < 4) {                                   // c.lbu
            return (uint16_t)(0x8000u | b << 7 | (off & 1u) << 6 |
                              (off >> 1 & 1u) << 5 | d << 2);
        }
        if ((f3 == 5 || f3 == 1) && (off == 0 || off == 2)) {       // c.lhu, c.lh
            return (uint16_t)((f3 == 5 ? 0x8400u : 0x8440u) | b << 7 |
                              (off >> 1 & 1u) << 5 | d << 2);
        }
        return 0;
    }
    case OP_STORE: {
        int64_t simm = sext((w >> 25) << 5 | (w >> 7 & 31u), 12);
        uint32_t off = (uint32_t)simm;
        if (simm < 0) {
            return 0;
        }
        if (rs1 == SP) {
            if (f3 == 3 && off < 512 && off % 8 == 0) {             // c.sdsp
                return (uint16_t)(0xe002u | (off >> 3 & 7u) << 10 |
                                  (off >> 6 & 7u) << 7 | rs2 << 2);
            }
            if (f3 == 2 && off < 256 && off % 4 == 0) {             // c.swsp
                return (uint16_t)(0xc002u | (off >> 2 & 15u) << 9 |
                                  (off >> 6 & 3u) << 7 | rs2 << 2);
            }
            return 0;
        }
        if (!creg(rs2) || !creg(rs1)) {
            return 0;
        }
        unsigned b = rs1 - 8u, s = rs2 - 8u;
        if (f3 == 3 && off < 256 && off % 8 == 0) {                 // c.sd
            return (uint16_t)(0xe000u | (off >> 3 & 7u) << 10 | b << 7 |
                              (off >> 6 & 3u) << 5 | s << 2);
        }
        if (f3 == 2 && off < 128 && off % 4 == 0) {                 // c.sw
            return (uint16_t)(0xc000u | (off >> 3 & 7u) << 10 | b << 7 |
                              (off >> 2 & 1u) << 6 | (off >> 6 & 1u) << 5 |
                              s << 2);
        }
        if (f3 == 0 && off < 4) {                                   // c.sb
            return (uint16_t)(0x8800u | b << 7 | (off & 1u) << 6 |
                              (off >> 1 & 1u) << 5 | s << 2);
        }
        if (f3 == 1 && (off == 0 || off == 2)) {                    // c.sh
            return (uint16_t)(0x8c00u | b << 7 | (off >> 1 & 1u) << 5 |
                              s << 2);
        }
        return 0;
    }
    default:
        return 0;
    }
}

static uint16_t c_branch(bool bnez, unsigned rs1, int32_t off)
{
    uint32_t u = (uint32_t)off;
    return (uint16_t)((bnez ? 0xe001u : 0xc001u) | (u >> 8 & 1u) << 12 |
                      (u >> 3 & 3u) << 10 | (rs1 - 8u) << 7 |
                      (u >> 6 & 3u) << 5 | (u >> 1 & 3u) << 3 |
                      (u >> 5 & 1u) << 2);
}

static uint16_t c_jump(int32_t off)
{
    uint32_t u = (uint32_t)off;
    return (uint16_t)(0xa001u | (u >> 11 & 1u) << 12 | (u >> 4 & 1u) << 11 |
                      (u >> 8 & 3u) << 9 | (u >> 10 & 1u) << 8 |
                      (u >> 6 & 1u) << 7 | (u >> 7 & 1u) << 6 |
                      (u >> 1 & 7u) << 3 | (u >> 5 & 1u) << 2);
}

// === Programs ===
//
// A program is slots, one instruction each. A transfer names the slot
// it goes to, and layout() turns that into a displacement, so that a
// rewrite can replace slots of any size and the program still holds
// together.

enum { S_PLAIN, S_BRANCH, S_JUMP, S_CALL, S_AUIPC, S_JALR };

typedef struct {
    uint8_t kind;
    bool c;             // spelled in two bytes where a form reaches
    uint8_t f3;         // S_BRANCH
    uint8_t ra, rb;     // S_BRANCH: rs1, rs2; S_AUIPC: rd;
                        // S_JALR: rs1, and the link in rb
    int8_t aim;         // while generating: the target this many slots
                        // on, or 0 to draw one
    uint16_t half;      // S_PLAIN: the two-byte form, when c
    uint32_t word;      // S_PLAIN: the four-byte form
    int target;         // a transfer's slot; S_AUIPC: its pair's
} slot_t;

#define SLOTS_MAX 400
#define FRAME 64
#define BUF_SIZE 4096
#define VADDR 0x10000u

// The state block: what the prologue loads and the epilogue stores;
// where the body left sp, from the frame's top; and what the
// callee-saved registers and sp held when the program returned.
typedef struct {
    uint64_t a[8];
    uint64_t frame[FRAME / 8];
    uint64_t buf;
    uint64_t s[12];
    int64_t sp_end;
    int64_t sp_ret;
} state_t;

#define STATE_FRAME 64
#define STATE_BUF 128
#define STATE_S 136
#define STATE_SP_END 232
#define STATE_SP_RET 240

typedef struct {
    slot_t s[SLOTS_MAX];
    int n;
    int body, epi, tramp, stub;     // where each part starts
    uint32_t addr[SLOTS_MAX + 1];   // each slot's offset, and the end
    uint8_t code[SLOTS_MAX * 4];
} prog_t;

static bool is_transfer(const slot_t *s)
{
    return s->kind != S_PLAIN;
}

static unsigned slot_size(const slot_t *s, bool wide)
{
    switch (s->kind) {
    case S_PLAIN:
        return s->c && s->half != 0 ? 2 : 4;
    case S_BRANCH:
        return s->c && !wide && s->f3 <= 1 && s->rb == X0 && creg(s->ra)
            ? 2 : 4;
    case S_JUMP:
        return s->c && !wide ? 2 : 4;
    default:
        return 4;
    }
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)v);
    put16(p + 2, (uint16_t)(v >> 16));
}

// Places every slot and encodes it. A compressed branch or jump that
// does not reach takes its four-byte form, which moves what follows, so
// the placing repeats until nothing changes.
static void layout(prog_t *p)
{
    bool wide[SLOTS_MAX] = { false };
    for (;;) {
        uint32_t a = 0;
        for (int i = 0; i < p->n; i++) {
            p->addr[i] = a;
            a += slot_size(&p->s[i], wide[i]);
        }
        p->addr[p->n] = a;
        bool again = false;
        for (int i = 0; i < p->n; i++) {
            const slot_t *s = &p->s[i];
            if ((s->kind != S_BRANCH && s->kind != S_JUMP) ||
                    slot_size(s, wide[i]) != 2) {
                continue;
            }
            int64_t off = (int64_t)p->addr[s->target] - (int64_t)p->addr[i];
            int64_t lim = s->kind == S_BRANCH ? 256 : 2048;
            if (off < -lim || off >= lim) {
                wide[i] = true;
                again = true;
            }
        }
        if (!again) {
            break;
        }
    }
    for (int i = 0; i < p->n; i++) {
        const slot_t *s = &p->s[i];
        uint8_t *at = p->code + p->addr[i];
        bool two = slot_size(s, wide[i]) == 2;
        int32_t off = is_transfer(s)
            ? (int32_t)((int64_t)p->addr[s->target] - (int64_t)p->addr[i])
            : 0;
        switch (s->kind) {
        case S_PLAIN:
            if (two) {
                put16(at, s->half);
            } else {
                put32(at, s->word);
            }
            break;
        case S_BRANCH:
            if (two) {
                put16(at, c_branch(s->f3 == 1, s->ra, off));
            } else {
                put32(at, enc_b(s->f3, s->ra, s->rb, off));
            }
            break;
        case S_JUMP:
            if (two) {
                put16(at, c_jump(off));
            } else {
                put32(at, enc_j(X0, off));
            }
            break;
        case S_CALL:
            put32(at, enc_j(RA, off));
            break;
        case S_AUIPC:
            put32(at, enc_u(OP_AUIPC, s->ra,
                            (uint32_t)((int64_t)(off + 0x800) >> 12)));
            break;
        default: {
            // The jalr's half of the displacement is measured from the
            // auipc before it.
            int64_t from = i > 0 ? (int64_t)p->addr[i - 1] : 0;
            int64_t pair = (int64_t)p->addr[s->target] - from;
            put32(at, jalr(s->rb, s->ra, (int32_t)sext((uint64_t)pair, 12)));
            break;
        }
        }
    }
}

// The slot at byte offset `a`, or -1.
static int slot_at(const prog_t *p, uint64_t a)
{
    int lo = 0, hi = p->n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (p->addr[mid] == a) {
            return mid;
        }
        if (p->addr[mid] < a) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return -1;
}

// === Generation ===

static prog_t gen;
static int sp_up, sp_down;      // what the body releases and reserves

static slot_t *push_slot(uint8_t kind)
{
    slot_t *s = &gen.s[gen.n++];
    memset(s, 0, sizeof *s);
    s->kind = kind;
    s->target = -1;
    return s;
}

static void put(uint32_t w, bool c)
{
    slot_t *s = push_slot(S_PLAIN);
    s->word = w;
    s->half = c ? compress(w) : 0;
    s->c = s->half != 0;
}

// A body instruction, compressed half the time where it can be.
static void push(uint32_t w)
{
    put(w, coin(2));
}

static void push_branch_to(unsigned f3, unsigned a, unsigned b, int aim)
{
    slot_t *s = push_slot(S_BRANCH);
    s->f3 = (uint8_t)f3;
    s->ra = (uint8_t)a;
    s->rb = (uint8_t)b;
    s->aim = (int8_t)aim;
    s->c = coin(2);
}

static void push_branch(void)
{
    unsigned f3 = branch_f3[rr(6)];
    unsigned a = sreg(), b = coin(3) ? X0 : sreg();
    push_branch_to(f3, a, b, 0);
}

static void push_jump(int aim)
{
    slot_t *s = push_slot(S_JUMP);
    s->aim = (int8_t)aim;
    s->c = coin(2);
}

// V8's far jump: `auipc t5,hi` + `jr lo(t5)`.
static void push_far(int aim)
{
    slot_t *s = push_slot(S_AUIPC);
    s->ra = T5;
    s = push_slot(S_JALR);
    s->ra = T5;
    s->rb = X0;
    s->aim = (int8_t)aim;
}

// A call: jal, the call pair `auipc ra` + `jalr ra`, or the same with a
// scratch register carrying the address.
static void push_call(void)
{
    switch (rr(4)) {
    case 0:
    case 1: {
        unsigned rx = coin(2) ? RA : T1;
        slot_t *s = push_slot(S_AUIPC);
        s->ra = (uint8_t)rx;
        s = push_slot(S_JALR);
        s->ra = (uint8_t)rx;
        s->rb = RA;
        break;
    }
    default:
        push_slot(S_CALL);
        break;
    }
}

static int32_t small_imm(void)
{
    return coin(4) ? (int32_t)rr(4096) - 2048 : (int32_t)rr(81) - 40;
}

// A register-register or immediate operation into d.
static uint32_t alu_op(unsigned d)
{
    if (coin(2)) {
        const rop_t *o = &rops[rr(N_GEN_ROPS)];
        unsigned a = sreg(), b = sreg();
        return enc_r(o->op, o->f3, o->f7, d, a, b);
    }
    const iop_t *o = &iops[rr(N_IOPS)];
    unsigned s = sreg();
    int64_t imm = o->form == I_IMM ? small_imm()
                : o->form == I_SH5 ? (int64_t)rr(32) : (int64_t)rr(64);
    return iop_word(o, d, s, imm);
}

// Where an access of `width` bytes may go: the frame through sp or s0;
// the buffer through s1; and through t3 or t4, each of which holds the
// frame's address or one 0 to 64 bytes into the buffer, at an offset
// either allows.
static void mem_where(unsigned width, unsigned *base, int32_t *off)
{
    int32_t slots = (int32_t)(FRAME / width);
    switch (rr(8)) {
    case 0:
    case 1:
        *base = SP;
        *off = (int32_t)width * (int32_t)rr((unsigned)slots);
        break;
    case 2:
    case 3:
        *base = S0;
        *off = -(int32_t)width * (1 + (int32_t)rr((unsigned)slots));
        break;
    case 4:
        *base = T4;
        *off = (int32_t)width * (int32_t)rr((unsigned)slots);
        break;
    case 5:
        *base = T3;
        *off = (int32_t)width * (int32_t)rr((unsigned)slots);
        break;
    default:
        *base = S1;
        *off = (int32_t)width *
               (int32_t)rr(coin(4) ? 2048u / width : (unsigned)slots);
        break;
    }
}

static uint32_t load_into(unsigned d)
{
    unsigned f3 = rr(7), base;
    int32_t off;
    mem_where(width_of(f3), &base, &off);
    return enc_i(OP_LOAD, f3, d, base, off);
}

static uint32_t store_of(unsigned s)
{
    unsigned f3 = rr(4), base;
    int32_t off;
    mem_where(width_of(f3), &base, &off);
    return enc_s(f3, base, s, off);
}

// t3 and t4 hold addresses and nothing else, so an access through them
// is always safe -- whichever path reached it, and across a call, whose
// stub leaves them pointing where they may. Rewriting them is how the
// windows see a base change.
static uint32_t pointer_write(void)
{
    switch (rr(4)) {
    case 0:
    case 1: return addi(T3, S1, 8 * (int32_t)rr(9));
    case 2: return addi(T4, S0, -FRAME);
    default: return add(T4, X0, SP);
    }
}

// Anything else the body may do.
static uint32_t filler(void)
{
    unsigned d = breg();
    switch (rr(24)) {
    case 12:
    case 13:
    case 14: return load_into(d);
    case 15:
    case 16: return store_of(sreg());
    case 17: return li(d, small_imm());
    case 18: return lui(d, coin(4) ? 0x80000u | rr(16) : rr(0x100000));
    case 19: return mv(d, breg());
    case 20: return coin(2) ? zext_w(d, sreg()) : zext_h(d, sreg());
    case 21: return pointer_write();
    case 22: return coin(2) ? addiw(d, sreg(), 0) : andi(d, sreg(), 255);
    case 23: return enc_r(OP_OP, 3, 0, d, X0, coin(2) ? T1 : T5);    // snez
    default: return alu_op(d);
    }
}

static void gap(unsigned max)
{
    for (unsigned k = rr(max + 1); k > 0; k--) {
        if (coin(8)) {
            push_branch();
        } else if (coin(16)) {
            push_call();
        } else {
            push(filler());
        }
    }
}

// ext: a producer of r, a gap, and an extension of r.

// The W operations, which sign-extend from bit 31, and the operations
// near them that do not: slli.uw and the shNadd.uw family share their
// major opcodes and produce 64 bits.
static const char *const w_rops[] = {
    "addw", "subw", "sllw", "srlw", "sraw", "mulw", "divw", "divuw",
    "remw", "remuw", "rolw", "rorw", "add.uw", "sh1add.uw", "sh2add.uw",
    "sh3add.uw",
};
static const char *const w_iops[] = {
    "addiw", "slliw", "srliw", "sraiw", "roriw", "slli.uw", "clzw", "ctzw",
    "cpopw",
};
static const char *const small_iops[] = {
    "clz", "ctz", "cpop", "sext.b", "sext.h", "sltiu", "slti", "andi",
};

static uint32_t ext_producer(unsigned r)
{
    unsigned a = sreg(), b = sreg();
    switch (rr(14)) {
    case 0:
    case 1: return load_into(r);
    case 2: return li(r, small_imm());
    case 3: return lui(r, coin(2) ? 0x80000u - rr(3) : rr(0x100000));
    case 4: return andi(r, a, coin(4) ? small_imm() : (int32_t)rr(2048));
    case 5:
    case 6: return rop_word(w_rops[rr(sizeof w_rops / sizeof w_rops[0])],
                            r, a, b);
    case 7:
    case 8: return iop_word(iop(w_iops[rr(sizeof w_iops / sizeof w_iops[0])]),
                            r, a, rr(64));
    case 9: return coin(2) ? zext_w(r, a) : zext_h(r, a);
    case 10: return coin(2) ? andi(r, a, 255) : addiw(r, a, 0);
    case 11: return iop_word(iop(small_iops[rr(8)]), r, a, rr(2048));
    case 12: return coin(2) ? srli(r, a, 32 + rr(32)) : srai(r, a, 32 + rr(32));
    default: return coin(2) ? rop_word(coin(2) ? "slt" : "sltu", r, a, b)
                            : add(r, a, b);
    }
}

static uint32_t ext_consumer(unsigned d, unsigned r)
{
    switch (rr(6)) {
    case 0: return addiw(d, r, 0);
    case 1: return andi(d, r, 255);
    case 2: return sext_b(d, r);
    case 3: return sext_h(d, r);
    case 4: return zext_h(d, r);
    default: return zext_w(d, r);
    }
}

static void plant_ext(void)
{
    unsigned r = breg();
    push(ext_producer(r));
    gap(3);
    if (coin(3)) {
        push(ext_consumer(r, r));        // one extension feeding another
    }
    push(ext_consumer(coin(3) ? breg() : r, r));
}

// dead: a write of r, a gap, and an overwrite of r that may read it
// first.
static void plant_dead(void)
{
    unsigned r = breg();
    push(coin(3) ? load_into(r) : alu_op(r));
    gap(4);
    switch (rr(5)) {
    case 0: push(li(r, small_imm())); break;
    case 1: push(load_into(r)); break;
    case 2: push(alu_op(r)); break;
    case 3: push(slli(r, r, 1 + rr(63))); break;
    default: push(mv(r, breg())); break;
    }
}

// remat: a computation, a gap, and the same computation again, into the
// same register or another; or the same with a source changed between.
static uint32_t with_rd(uint32_t w, unsigned rd)
{
    return (w & ~(31u << 7)) | rd << 7;
}

static void plant_remat(void)
{
    unsigned r = breg(), r2 = coin(3) ? r : breg();
    uint32_t w;
    switch (rr(6)) {
    case 0:
        w = coin(2) ? addi(r, SP, 8 * (int32_t)rr(8))
                    : addi(r, S0, 8 * (int32_t)rr(8) - FRAME);
        break;
    case 1:
        w = coin(2) ? li(r, small_imm())
                    : lui(r, coin(2) ? rr(64) : rr(0x100000));
        break;
    default:
        w = alu_op(r);
        break;
    }
    push(w);
    if (coin(4)) {
        // A source of it, or its own register, written in between.
        unsigned s = coin(2) ? (w >> 15 & 31u) : r;
        if (s >= A0 && s < A0 + 8) {
            push(alu_op(s));
        }
    }
    gap(3);
    push(with_rd(w, r2));
}

// mem: two accesses to the same bytes -- through the same base or
// another that names them, now and then neighbouring bytes -- with a
// gap between.

// The same bytes, `width` wide, through another base: sp, s0 and t4 all
// name the frame.
static void alias(unsigned *base, int32_t *off)
{
    if (*base != SP && *base != S0 && *base != T4) {
        return;
    }
    int32_t from_sp = *base == S0 ? *off + FRAME : *off;
    switch (rr(3)) {
    case 0: *base = SP; *off = from_sp; break;
    case 1: *base = S0; *off = from_sp - FRAME; break;
    default: *base = T4; *off = from_sp; break;
    }
}

// Moves an access by one width, where that stays inside its region.
static void nudge(unsigned base, unsigned width, int32_t *off)
{
    int32_t o = *off + (coin(2) ? (int32_t)width : -(int32_t)width);
    int32_t lo = base == S0 ? -FRAME : 0;
    int32_t hi = base == S0 ? 0 : base == S1 ? 2048 : FRAME;
    if (o >= lo && o + (int32_t)width <= hi) {
        *off = o;
    }
}

// A run of stores of zero through sp or s0 to bytes that abut, each
// aligned to its own width, growing up or down -- now and then with a
// gap, an overlap or a store of something else, which the run must end
// at.
static void plant_zero_run(void)
{
    unsigned base = coin(2) ? SP : S0;
    int32_t lo = base == SP ? 0 : -FRAME, hi = lo + FRAME;
    bool up = !coin(4);
    int32_t pos = lo + (int32_t)rr(FRAME + 1);
    for (unsigned k = 2 + rr(6); k > 0; k--) {
        // The widths an aligned store there can take, widest first.
        unsigned widths[4], nw = 0;
        for (unsigned w = 8; w >= 1; w /= 2) {
            int32_t at = up ? pos : pos - (int32_t)w;
            if (at >= lo && at + (int32_t)w <= hi && at % (int32_t)w == 0) {
                widths[nw++] = w;
            }
        }
        if (nw == 0) {
            return;
        }
        unsigned w = widths[rr(nw)];
        int32_t at = up ? pos : pos - (int32_t)w;
        unsigned data = coin(10) ? breg() : X0;
        push(enc_s(w == 8 ? 3 : w == 4 ? 2 : w == 2 ? 1 : 0, base, data, at));
        pos = up ? at + (int32_t)w : at;
        if (coin(12)) {
            pos += up ? 1 : -1;                 // a gap
        } else if (coin(12)) {
            pos -= up ? 1 : -1;                 // an overlap
        }
    }
    if (coin(2)) {
        push(load_into(breg()));
    }
}

static void plant_mem(void)
{
    if (coin(5)) {
        plant_zero_run();
        return;
    }
    unsigned r = breg(), r2 = coin(3) ? r : breg();
    unsigned f3 = rr(4), w = width_of(f3);
    // A load of the width the store wrote, signed or not, mostly.
    unsigned lf3 = coin(4) ? rr(7) : f3 == 3 || coin(2) ? f3 : f3 + 4;
    unsigned base;
    int32_t off;
    mem_where(w, &base, &off);
    unsigned b2 = base;
    int32_t o2 = off;
    if (coin(4)) {
        alias(&b2, &o2);
    }
    if (coin(6)) {
        nudge(b2, w, &o2);
    }
    if (coin(5)) {
        // An address computed for an access: into t3 or t4, which may
        // hold the buffer's or the frame's, and used at once or later.
        unsigned rp = coin(2) ? T3 : T4;
        push(coin(2) ? addi(rp, S1, 8 * (int32_t)rr(9))
                     : coin(2) ? addi(rp, S0, -FRAME) : add(rp, X0, SP));
        gap(1);
        int32_t at = (int32_t)w * (int32_t)rr(FRAME / w);
        push(coin(2) ? enc_i(OP_LOAD, lf3, r, rp, at) : enc_s(f3, rp, r, at));
        if (coin(2)) {
            push(coin(2) ? pointer_write() : ld(breg(), rp, 0));
        }
        return;
    }
    uint32_t first, second;
    switch (rr(5)) {
    case 0:                                         // store, then load
        first = enc_s(f3, base, r, off);
        second = enc_i(OP_LOAD, lf3, r2, b2, o2);
        break;
    case 1:                                         // load twice
        first = enc_i(OP_LOAD, lf3, r, base, off);
        second = enc_i(OP_LOAD, lf3, r2, b2, o2);
        break;
    case 2:                                         // store twice
        first = enc_s(f3, base, r, off);
        second = enc_s(f3, b2, r2, o2);
        break;
    case 3:                                         // load, store it back
        first = enc_i(OP_LOAD, lf3, r, base, off);
        second = enc_s(f3, b2, r, o2);
        break;
    default:                                        // the same store again
        first = enc_s(f3, base, r, off);
        second = enc_s(f3, b2, r, o2);
        break;
    }
    push(first);
    if (coin(3)) {
        // A store to the same bytes through another base, which no
        // window can tell from a store anywhere else.
        unsigned b3 = base;
        int32_t o3 = off;
        alias(&b3, &o3);
        push(enc_s(rr(f3 + 1), b3, sreg(), o3));     // no wider: o3 is aligned to w
    }
    gap(4);
    push(second);
}

// shift: the pairs that fold into one instruction, at their own shift
// amounts and around them, with the intermediate dead, overwritten or
// read again.
static void plant_shift(void)
{
    unsigned r = breg(), s = sreg(), d = coin(3) ? breg() : r;
    unsigned t = breg(), x = sreg();
    switch (rr(9)) {
    case 0: {
        unsigned k = coin(4) ? 31 + rr(3) : 32;
        push(slli(r, s, k));
        push(srli(d, r, coin(4) ? 31 + rr(3) : k));
        break;
    }
    case 1: {
        unsigned k = coin(4) ? 47 + rr(3) : 48;
        push(slli(r, s, k));
        push(srli(d, r, coin(4) ? 47 + rr(3) : k));
        break;
    }
    case 2: {
        unsigned k = 50 + rr(14);
        push(slli(r, s, k));
        push(srli(d, r, coin(4) ? 50 + rr(14) : k));
        break;
    }
    case 3: {
        unsigned k = coin(2) ? 48 : 56;
        push(slli(r, s, k));
        push(srai(d, r, coin(4) ? k - 1 + rr(3) : k));
        break;
    }
    case 4: {
        push(slli(r, s, rr(5)));
        unsigned a = coin(2) ? r : x, b = coin(2) ? r : x;
        push(add(d, a, b));
        break;
    }
    case 5: {
        push(xori(t, s, -1));                       // not t, s
        const unsigned f3s[3] = { 7, 6, 4 };       // and, or, xor
        unsigned f3 = f3s[rr(3)];
        push(coin(2) ? enc_r(OP_OP, f3, 0, d, x, t) : enc_r(OP_OP, f3, 0, d, t, x));
        r = t;
        break;
    }
    case 6:
        push(xor_(t, s, x));
        push(xori(d, t, -1));
        r = t;
        break;
    case 7: {
        const int32_t ks[4] = { 3, 5, 9, 7 };
        int32_t k = ks[rr(4)];
        push(li(t, k));
        unsigned f7 = 1, op = coin(4) ? OP_OP32 : OP_OP;
        push(coin(2) ? enc_r(op, 0, f7, d, x, t) : enc_r(op, 0, f7, d, t, x));
        r = t;
        break;
    }
    default: {
        unsigned k = rr(13);
        push(li(t, coin(5) ? (int32_t)rr(4096) - 2048 : 1 << k));
        // divu, remu; divuw, remuw now and then
        unsigned f3 = coin(2) ? 5 : 7, op = coin(3) ? OP_OP32 : OP_OP;
        push(coin(4) ? enc_r(op, f3, 1, d, t, x) : enc_r(op, f3, 1, d, x, t));
        r = t;
        break;
    }
    }
    switch (rr(3)) {
    case 0: push(add(breg(), r, sreg())); break;
    case 1: push(li(r, small_imm())); break;
    default: break;
    }
}

// branch: shapes for each of the control-flow checks.
static void plant_branch(void)
{
    unsigned r = breg(), x = sreg(), c = breg();
    unsigned f3 = branch_f3[rr(6)];
    switch (rr(10)) {
    case 0:                                     // decided by its operands
        push_branch_to(f3, r, coin(3) ? X0 : r, 0);
        break;
    case 1:                                     // li 0 or 1 + ordered branch
        push(li(c, (int32_t)rr(2)));
        f3 = 4 + rr(4);
        push_branch_to(f3, coin(2) ? x : c, coin(2) ? c : x, 0);
        break;
    case 2:                                     // li 0 + equality branch
        push(li(c, 0));
        push_branch_to(rr(2), coin(2) ? x : c, coin(2) ? c : x, 0);
        break;
    case 3: {                                   // a condition, then beqz/bnez
        unsigned a = sreg(), b = sreg();
        switch (rr(5)) {
        case 0: push(enc_r(OP_OP, 2 + rr(2), 0, c, a, b)); break;   // slt, sltu
        case 1: push(xor_(c, a, b)); break;
        case 2: push(sub(c, a, b)); break;
        case 3: push(enc_i(OP_IMM, 2 + rr(2), c, a, small_imm())); break;
        default: push(enc_r(OP_OP, 3, 0, c, X0, a)); break;         // snez
        }
        push_branch_to(rr(2), c, X0, 0);
        break;
    }
    case 4:                                     // a branch over a jump
        push_branch_to(f3, x, sreg(), 2);
        if (coin(3)) {
            push_far(0);
        } else {
            push_jump(0);
        }
        break;
    case 5:                                     // to the next instruction
        if (coin(2)) {
            push_jump(1);
        } else {
            push_branch_to(f3, x, sreg(), 1);
        }
        break;
    case 6: {                                   // to a jump
        unsigned n = rr(3);
        if (coin(3)) {
            push_call();
            break;
        }
        push_branch_to(f3, x, sreg(), (int)n + 1);
        for (unsigned k = 0; k < n; k++) {
            push(filler());
        }
        if (coin(3)) {
            push_far(0);
        } else {
            push_jump(0);
        }
        break;
    }
    case 7:                                     // V8's far jump
        push_far(0);
        if (coin(2)) {
            push(enc_r(OP_OP, 3, 0, breg(), X0, T5));
        }
        break;
    case 8: {                                   // a branch over a move
        unsigned d = breg(), v = breg();
        f3 = 4 + rr(4);
        switch (rr(3)) {
        case 0:
            push_branch_to(f3, coin(2) ? d : v, coin(2) ? v : d, 2);
            push(mv(d, v));
            break;
        case 1:
            push_branch_to(f3, coin(2) ? d : X0, coin(2) ? X0 : d, 2);
            push(li(d, 0));
            break;
        default: {
            int32_t k = (int32_t)rr(64) - 32;
            push(li(v, k));
            push_branch_to(f3, coin(2) ? v : d, coin(2) ? d : v, 2);
            push(li(d, k));
            break;
        }
        }
        break;
    }
    default:                                    // a call pair
        push_call();
        if (coin(2)) {
            push(enc_r(OP_OP, 3, 0, breg(), X0, T1));
        }
        break;
    }
}

// copy: a mv and its reader; a move spelled otherwise; an instruction
// that changes nothing. A copy of an address is between t3 and t4,
// which may hold either one's: a body register holding one could reach
// its load by a path that never set it, or across a call.
static void plant_copy(void)
{
    unsigned d = breg(), y = sreg(), s = breg();
    switch (rr(3)) {
    case 0:
        if (coin(4)) {
            d = coin(2) ? T3 : T4;
            push(mv(d, d == T3 ? T4 : T3));
            gap(2);
            push(coin(2) ? ld(breg(), d, 8 * (int32_t)rr(8))
                         : sd(sreg(), d, 8 * (int32_t)rr(8)));
            if (coin(2)) {
                push(pointer_write());
            }
            break;
        }
        push(mv(d, s));
        gap(2);
        switch (rr(5)) {
        case 0: push(add(breg(), coin(2) ? d : y, coin(2) ? y : d)); break;
        case 1: push(addi(breg(), d, small_imm())); break;
        case 2: push(sd(d, S1, 8 * (int32_t)rr(8))); break;
        case 3: push(enc_i(OP_IMM, 1, breg(), d, (int32_t)rr(64))); break;
        default: push(enc_r(OP_OP, 4, 1, breg(), d, y)); break;    // div
        }
        switch (rr(3)) {
        case 0: push(alu_op(d)); break;
        case 1: push(add(breg(), d, y)); break;
        default: break;
        }
        break;
    case 1:
        switch (rr(10)) {
        case 0: push(or_(d, coin(2) ? s : X0, coin(2) ? X0 : s)); break;
        case 1: push(ori(d, s, 0)); break;
        case 2: push(slli(d, s, 0)); break;
        case 3: push(coin(2) ? srli(d, s, 0) : srai(d, s, 0)); break;
        case 4: push(xori(d, s, 0)); break;
        case 5: push(xor_(d, s, s)); break;
        case 6: push(sub(d, s, s)); break;
        case 7: push(andi(d, s, 0)); break;
        case 8: push(and_(d, s, coin(2) ? X0 : s)); break;
        default: push(add(d, X0, s)); break;
        }
        break;
    default:
        switch (rr(9)) {
        case 0: push(mv(d, d)); break;
        case 1: push(ori(d, d, 0)); break;
        case 2: push(xori(d, d, 0)); break;
        case 3: push(slli(d, d, 0)); break;
        case 4: push(andi(d, d, -1)); break;
        case 5: push(and_(d, d, d)); break;
        case 6: push(or_(d, d, d)); break;
        case 7: push(alu_op(X0)); break;
        default: push(add(X0, sreg(), sreg())); break;
        }
        break;
    }
}

// const: a constant built and then used, with unrelated instructions
// between the uses: for operations with an immediate form, stored, as
// a mask, as a constant whose complement builds shorter, or built the
// long way round.

// A value whose bits run in one block, now and then complemented: the
// masks and their complements that a planner builds in a few ways.
static int64_t run_value(void)
{
    unsigned len = 1 + rr(63), at = rr(64 - len);
    uint64_t v = (len == 64 ? ~0ull : ((1ull << len) - 1)) << at;
    return (int64_t)(coin(3) ? ~v : v);
}

// Builds v in rc: li_seq's way, or a longer one -- an extra slli and
// srli pair, or an addi of 0 -- now and then.
static void push_chain(unsigned rc, int64_t v)
{
    uint32_t w[8];
    int n = li_seq(rc, v, w);
    for (int i = 0; i < n; i++) {
        push(w[i]);
    }
    if (coin(4)) {
        push(addi(rc, rc, 0));
    }
}

// A use of rc as one operand of an operation: `kind` 0 the immediate
// forms' operations, 1 a store, 2 an and, 3 a logical operation.
static void push_use(unsigned rc, int kind)
{
    unsigned d = coin(4) ? rc : breg(), x = breg();
    if (x == rc) {
        x = A0 + (x - A0 + 1) % 8;
    }
    switch (kind) {
    case 0: {
        static const char *const ops[] = {
            "add", "addw", "and", "or", "xor", "sub", "subw", "slt", "sltu",
            "sll", "srl", "sra", "sllw", "srlw", "sraw", "mul",
        };
        const char *op = ops[rr(sizeof ops / sizeof ops[0])];
        push(coin(2) ? rop_word(op, d, x, rc) : rop_word(op, d, rc, x));
        break;
    }
    case 1: {
        unsigned f3 = rr(4), base;
        int32_t off;
        mem_where(width_of(f3), &base, &off);
        push(enc_s(f3, base, rc, off));
        break;
    }
    case 2:
        push(coin(2) ? and_(d, x, rc) : and_(d, rc, x));
        break;
    default: {
        static const char *const ops[] = {
            "and", "or", "xor", "andn", "orn", "xnor",
        };
        const char *op = ops[rr(6)];
        // andn and orn complement their second operand, so a constant
        // they take the complement of is that one.
        bool either = strcmp(op, "andn") != 0 && strcmp(op, "orn") != 0;
        push(either && coin(2) ? rop_word(op, d, rc, x) : rop_word(op, d, x, rc));
        break;
    }
    }
}

static void plant_const(void)
{
    unsigned rc = breg();
    int kind = (int)rr(5);
    switch (kind) {
    case 0:
        push(coin(4) ? lui(rc, rr(4)) : li(rc, coin(3) ? small_imm()
                                                     : (int32_t)rr(64) - 32));
        break;
    case 1:
        push(li(rc, coin(6) ? 1 : 0));
        break;
    case 2: {
        unsigned n = coin(3) ? 16 : coin(2) ? 32 : 12 + rr(52);
        push_chain(rc, (int64_t)(n == 64 ? ~0ull : (1ull << n) - 1));
        break;
    }
    case 3:
        push_chain(rc, coin(4) ? (int64_t)rnd() : run_value());
        break;
    default:
        push_chain(rc, coin(3) ? (int64_t)rnd() : run_value());
        if (coin(2)) {
            push(add(breg(), rc, sreg()));
        }
        return;
    }
    for (unsigned k = 1 + rr(3); k > 0; k--) {
        if (coin(3)) {
            push(filler());
        }
        push_use(rc, kind == 4 ? 0 : kind);
    }
    switch (rr(3)) {
    case 0: push(li(rc, small_imm())); break;
    case 1: push(add(breg(), rc, sreg())); break;
    default: break;
    }
}

// stack: sp moved by pushes and pops, a release and a reservation side
// by side, and a restore from the frame pointer. What the body releases
// is capped over the whole program, since a path that skips a push and
// takes its pop leaves sp higher than the frame: the cap keeps every
// path's sp, and the accesses through it, inside the guard above the
// frame.
#define SP_UP_MAX 512
#define SP_DOWN_MAX 4096

static void push_sp(int32_t k)
{
    push(addi(SP, SP, k));
    if (k > 0) {
        sp_up += k;
    } else {
        sp_down -= k;
    }
}

static void plant_stack(void)
{
    unsigned n = 2 + rr(3);
    switch (rr(5)) {
    case 0:                                     // pushes
        if (sp_down + 16 * (int)n > SP_DOWN_MAX) {
            return;
        }
        for (unsigned k = 0; k < n; k++) {
            if (coin(3)) {
                push(coin(2) ? load_into(breg()) : alu_op(breg()));
            }
            int32_t step = 8 * (1 + (int32_t)rr(2));
            push_sp(-step);
            for (int32_t j = 0; j < step; j += 8) {
                if (!coin(5)) {
                    push(sd(sreg(), SP, j));
                }
            }
            if (coin(6)) {
                push(ld(breg(), SP, 8 * (int32_t)rr(4)));
            }
            if (coin(12)) {
                push(coin(2) ? mv(breg(), SP) : sd(SP, SP, 0));
            }
        }
        break;
    case 1:                                     // pops
        for (unsigned k = 0; k < n; k++) {
            int32_t step = 8 * (1 + (int32_t)rr(2));
            if (sp_up + step > SP_UP_MAX) {
                return;
            }
            push(ld(breg(), SP, 8 * (int32_t)rr((unsigned)step / 8)));
            push_sp(step);
            if (coin(4)) {
                push(coin(2) ? sd(sreg(), SP, 8 * (int32_t)rr(4))
                             : alu_op(breg()));
            }
        }
        break;
    case 2: {                                   // a release, a reservation
        int32_t a = 8 * (1 + (int32_t)rr(4));
        int32_t b = coin(2) ? a : 8 * (1 + (int32_t)rr(4));
        if (sp_up + a > SP_UP_MAX) {
            return;
        }
        push_sp(a);
        push_sp(-b);
        break;
    }
    case 3:                                     // the frame pointer's restore
        push(addi(SP, S0, -FRAME));
        break;
    default:                                    // a push, a call, a pop
        if (sp_up + 16 > SP_UP_MAX) {
            return;
        }
        push_sp(-16);
        push(sd(breg(), SP, 0));
        push(sd(breg(), SP, 8));
        if (coin(2)) {
            push_call();
        }
        push(ld(breg(), SP, 0));
        push(ld(breg(), SP, 8));
        push_sp(16);
        break;
    }
}

// self: any of the shapes.
static void plant_any(void)
{
    static void (*const planters[])(void) = {
        plant_ext, plant_dead, plant_remat, plant_mem, plant_shift,
        plant_branch, plant_copy, plant_const, plant_stack,
    };
    planters[rr(sizeof planters / sizeof planters[0])]();
}

static void gen_body(void (*plant)(void))
{
    int len = 10 + (int)rr(20);
    while (gen.n - gen.body < len) {
        unsigned p = rr(100);
        if (p < 35) {
            plant();
        } else if (p < 45) {
            push_branch();
        } else if (p < 48) {
            push_jump(0);
        } else if (p < 52) {
            push_call();
        } else if (p < 54) {
            push_far(0);
        } else {
            push(filler());
        }
    }
}

// A forward target for the transfer at i: `aim` slots on when it asks,
// otherwise anywhere up to the epilogue -- never a pair's jalr, which
// would run without the auipc that sets its register.
static int forward(int i, int aim)
{
    int t = aim > 0 && i + aim <= gen.epi
        ? i + aim : i + 1 + (int)rr((unsigned)(gen.epi - i));
    while (t < gen.epi && gen.s[t].kind == S_JALR) {
        t++;
    }
    return t;
}

static void build(void (*plant)(void))
{
    gen.n = 0;
    sp_up = sp_down = 0;
    // s2 keeps the state block and s3 the return address, so nothing the
    // body does to sp or the memory around it can lose either. The
    // thunk saves and restores s0..s11 itself.
    put(mv(S2, A0), false);
    put(mv(S3, RA), false);
    put(addi(SP, SP, -FRAME), false);
    put(addi(S0, SP, FRAME), false);
    put(ld(S1, S2, STATE_BUF), false);
    for (int i = 0; i < FRAME / 8; i++) {
        put(ld(T0, S2, STATE_FRAME + 8 * i), false);
        put(sd(T0, SP, 8 * i), false);
    }
    for (unsigned i = 0; i < 8; i++) {
        put(ld(A0 + i, S2, 8 * (int32_t)i), false);
    }
    put(li(T1, 0), false);
    put(li(T5, 0), false);
    put(mv(T3, S1), false);
    put(mv(T4, SP), false);

    gen.body = gen.n;
    gen_body(plant);
    gen.epi = gen.n;

    // t1, t5, t3 and t4 are written before anything else, so that a
    // walk which reaches the epilogue sees them redefined; a `ret` it
    // would not see past.
    put(li(T1, 0), false);
    put(li(T5, 0), false);
    put(mv(T3, S1), false);
    put(addi(T4, S0, -FRAME), false);
    // Where the body left sp, which a stack-moving rewrite must not
    // change, and then the frame back from s0 whatever it did.
    put(sub(T0, SP, S0), false);
    put(sd(T0, S2, STATE_SP_END), false);
    put(addi(SP, S0, -FRAME), false);
    for (unsigned i = 0; i < 8; i++) {
        put(sd(A0 + i, S2, 8 * (int32_t)i), false);
    }
    for (int i = 0; i < FRAME / 8; i++) {
        put(ld(T0, SP, 8 * i), false);
        put(sd(T0, S2, STATE_FRAME + 8 * i), false);
    }
    put(addi(SP, SP, FRAME), false);
    put(mv(RA, S3), false);
    put(jalr(X0, RA, 0), false);

    gen.tramp = gen.n;
    push_slot(S_JUMP)->target = gen.tramp + 1;
    gen.stub = gen.n;
    // The callee: it writes t1 and t5 before reading anything, reads
    // every argument, the caller's frame and the buffer, and leaves its
    // results, t3 and t4 pointing where they may, and a word written in
    // the frame and in the buffer.
    put(li(T1, 0), false);
    put(li(T5, 0), false);
    for (unsigned i = 0; i < 8; i++) {
        put(ld(T0, SP, 8 * (int32_t)i), false);
        put(ld(T2, S1, 8 * (int32_t)i), false);
        put(xor_(T0, T0, T2), false);
        put(add(A0 + i, A0 + i, T0), false);
        put(xori(A0 + i, A0 + i, 0x5a5 + 0x11 * (int32_t)i), false);
    }
    put(addi(T3, S1, 64), false);
    put(mv(T4, SP), false);
    put(sd(A0, S1, 0), false);
    put(sd(A0 + 1, SP, 8), false);
    put(jalr(X0, RA, 0), false);

    for (int i = gen.body; i < gen.epi; i++) {
        slot_t *s = &gen.s[i];
        switch (s->kind) {
        case S_BRANCH:
        case S_JUMP:
            s->target = forward(i, s->aim);
            break;
        case S_JALR:
            s->target = s->rb != X0 ? (coin(3) ? gen.tramp : gen.stub)
                                    : forward(i, s->aim);
            break;
        case S_CALL:
            s->target = coin(3) ? gen.tramp : gen.stub;
            break;
        default:
            break;
        }
    }
    for (int i = gen.body; i < gen.epi; i++) {
        if (gen.s[i].kind == S_AUIPC) {
            gen.s[i].target = gen.s[i + 1].target;
        }
    }
    layout(&gen);
}

// === riscvlint ===

static csh cs;

typedef struct {
    int title;          // index into the mode's titles
    int slot;           // the finding's first instruction
    unsigned count;
    char text[sizeof(((riscvlint_finding *)0)->replacement)];
} hit_t;

#define HITS_MAX 64
static hit_t hits[HITS_MAX];
static int nhits;
static long outside;            // findings that reached past the body

typedef struct mode mode_t_;
static const mode_t_ *mode;

static int title_index(const char *title);

static void record(void *ctx, const riscvlint_finding *f)
{
    const prog_t *p = ctx;
    int t = title_index(f->title);
    if (t < 0 || nhits == HITS_MAX || f->address < VADDR) {
        return;
    }
    int s = slot_at(p, f->address - VADDR);
    if (s < p->body || s >= p->epi) {
        return;
    }
    if (s + (int)f->insn_count > p->epi) {
        outside++;
        return;
    }
    hit_t *h = &hits[nhits++];
    h->title = t;
    h->slot = s;
    h->count = f->insn_count;
    snprintf(h->text, sizeof h->text, "%s", f->replacement);
}

// What the scan claims every instruction it reads leaves behind: the
// targets declared in an RVA23 object, so that the Zb* folds fire, and
// nothing the K3 cannot run -- not Zilx, Zibi or Zacas.
#define EXTENSIONS                                                         \
    (RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_C | RISCVLINT_EXT_ZBA |        \
     RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS | RISCVLINT_EXT_ZCB |           \
     RISCVLINT_EXT_ZFA)

static long undecoded;

// Runs the scan over the program the way the driver does and keeps the
// mode's findings.
static void analyze(const prog_t *p)
{
    nhits = 0;
    riscvlint_state *st = riscvlint_state_create();
    riscvlint_state_set_extensions(st, EXTENSIONS);
    uint64_t skipped = 0;
    if (riscvlint_state_set_section(st, cs, p->code, p->addr[p->n], VADDR)) {
        riscvlint_scan(st, cs, p->code, p->addr[p->n], VADDR, record,
                       (void *)p, NULL, &skipped);
    }
    riscvlint_state_destroy(st);
    if (skipped == 0) {
        return;
    }
    if (++undecoded <= 5) {
        cs_insn *insn = cs_malloc(cs);
        for (int i = 0; i < p->n; i++) {
            const uint8_t *code = p->code + p->addr[i];
            size_t size = p->addr[i + 1] - p->addr[i];
            uint64_t a = VADDR + p->addr[i];
            if (!cs_disasm_iter(cs, &code, &size, &a, insn)) {
                printf("undecoded: %0*" PRIx32 "\n",
                       2 * (int)(p->addr[i + 1] - p->addr[i]),
                       p->s[i].kind == S_PLAIN && p->s[i].c ? p->s[i].half
                                                            : p->s[i].word);
            }
        }
        cs_free(insn, 1);
    }
}

// === Rewrites ===

#define REP_MAX 16

// One original slot replaced by n slots, or deleted when n is 0. A
// transfer in a replacement names an original slot, as every other one
// does until apply() renumbers them.
typedef struct {
    int at;
    int n;
    slot_t rep[REP_MAX];
} edit_t;

// Enough for the widest window: a constant's chain and the sixteen
// instructions its uses may span.
#define EDITS_MAX 48

typedef struct {
    edit_t e[EDITS_MAX];
    int n;
} edits_t;

static edit_t *add_edit(edits_t *ed, int at)
{
    if (ed->n == EDITS_MAX) {
        fprintf(stderr, "rwfuzz: more than %d edits\n", EDITS_MAX);
        abort();
    }
    edit_t *e = &ed->e[ed->n++];
    e->at = at;
    e->n = 0;
    return e;
}

static slot_t plain(uint32_t w)
{
    slot_t s;
    memset(&s, 0, sizeof s);
    s.kind = S_PLAIN;
    s.word = w;
    s.target = -1;
    return s;
}

static void apply(const prog_t *p, const edits_t *ed, prog_t *out)
{
    int map[SLOTS_MAX + 1];
    out->n = 0;
    for (int i = 0; i < p->n; i++) {
        const edit_t *e = NULL;
        for (int k = 0; k < ed->n; k++) {
            if (ed->e[k].at == i) {
                e = &ed->e[k];
            }
        }
        // A deleted slot's transfers go on to whatever follows it.
        map[i] = out->n;
        if (e == NULL) {
            out->s[out->n++] = p->s[i];
        } else {
            for (int k = 0; k < e->n && out->n < SLOTS_MAX; k++) {
                out->s[out->n++] = e->rep[k];
            }
        }
    }
    map[p->n] = out->n;
    for (int i = 0; i < out->n; i++) {
        if (is_transfer(&out->s[i])) {
            out->s[i].target = map[out->s[i].target];
        }
    }
    out->body = map[p->body];
    out->epi = map[p->epi];
    out->tramp = map[p->tramp];
    out->stub = map[p->stub];
    layout(out);
}

// === The assembler ===
//
// Enough of one to read the instructions riscvlint's renderings name,
// in the spelling capstone prints: ABI register names, decimal or hex
// immediates, `off(base)` operands, and absolute branch targets, which
// name a slot of the program the finding was made in.

typedef struct {
    slot_t s[REP_MAX];
    int n;
} seq_t;

static bool seq_add(seq_t *q, slot_t s)
{
    if (q->n == REP_MAX) {
        return false;
    }
    q->s[q->n++] = s;
    return true;
}

static bool seq_word(seq_t *q, uint32_t w)
{
    return seq_add(q, plain(w));
}

static bool parse_reg(const char *t, unsigned *r)
{
    for (unsigned i = 0; i < 32; i++) {
        if (strcmp(t, xnames[i]) == 0) {
            *r = i;
            return true;
        }
    }
    if (strcmp(t, "fp") == 0) {
        *r = S0;
        return true;
    }
    return false;
}

static bool parse_int(const char *t, int64_t *v)
{
    bool neg = *t == '-';
    const char *u = neg ? t + 1 : t;
    if (!isdigit((unsigned char)*u)) {
        return false;
    }
    char *end;
    errno = 0;
    uint64_t x = strtoull(u, &end, strncmp(u, "0x", 2) == 0 ? 16 : 10);
    if (*end != '\0' || errno != 0) {
        return false;
    }
    *v = neg ? (int64_t)(0 - x) : (int64_t)x;
    return true;
}

static bool parse_mem(const char *t, int64_t *off, unsigned *base)
{
    const char *lp = strchr(t, '('), *rp = strrchr(t, ')');
    if (lp == NULL || rp == NULL || rp[1] != '\0' || lp == t || rp < lp) {
        return false;
    }
    char num[32], reg[16];
    size_t nl = (size_t)(lp - t), rl = (size_t)(rp - lp - 1);
    if (nl >= sizeof num || rl == 0 || rl >= sizeof reg) {
        return false;
    }
    memcpy(num, t, nl);
    num[nl] = '\0';
    memcpy(reg, lp + 1, rl);
    reg[rl] = '\0';
    return parse_int(num, off) && parse_reg(reg, base);
}

static bool parse_target(const prog_t *p, const char *t, int *slot)
{
    int64_t a;
    if (!parse_int(t, &a) || a < VADDR) {
        return false;
    }
    *slot = slot_at(p, (uint64_t)a - VADDR);
    return *slot >= 0;
}

static bool in_imm12(int64_t v)
{
    return v >= -2048 && v <= 2047;
}

static bool branch_slot(seq_t *q, unsigned f3, unsigned a, unsigned b,
                        int target)
{
    slot_t s;
    memset(&s, 0, sizeof s);
    s.kind = S_BRANCH;
    s.f3 = (uint8_t)f3;
    s.ra = (uint8_t)a;
    s.rb = (uint8_t)b;
    s.target = target;
    return seq_add(q, s);
}

static bool transfer_slot(seq_t *q, uint8_t kind, int target)
{
    slot_t s;
    memset(&s, 0, sizeof s);
    s.kind = kind;
    s.target = target;
    return seq_add(q, s);
}

// Assembles one rendered instruction onto q. False where the text is
// not an instruction this assembler knows -- which is how the
// annotations after a rendering's instructions are told from them.
static bool assemble(const prog_t *p, const char *text, seq_t *q)
{
    char buf[128];
    size_t len = strnlen(text, sizeof buf - 1);
    memcpy(buf, text, len);
    buf[len] = '\0';
    char *cut = strstr(buf, " (");     // the byte count
    if (cut != NULL) {
        *cut = '\0';
    }
    char *mn = buf;
    while (*mn == ' ') {
        mn++;
    }
    char *ops[4];
    int nops = 0;
    char *sp = strchr(mn, ' ');
    if (sp != NULL) {
        *sp = '\0';
        char *rest = sp + 1;
        // check_long_li's `li REG, VALUE in N instructions: ...`
        char *in = strcmp(mn, "li") == 0 ? strstr(rest, " in ") : NULL;
        if (in != NULL) {
            *in = '\0';
        }
        while (*rest != '\0') {
            if (nops == 4) {
                return false;
            }
            char *comma = strchr(rest, ',');
            if (comma != NULL) {
                *comma = '\0';
            }
            while (*rest == ' ') {
                rest++;
            }
            char *end = rest + strlen(rest);
            while (end > rest && end[-1] == ' ') {
                *--end = '\0';
            }
            ops[nops++] = rest;
            if (comma == NULL) {
                break;
            }
            rest = comma + 1;
        }
    }

    unsigned rd = 0, ra = 0, rb = 0;
    int64_t imm = 0;
    int target;
    bool r0 = nops > 0 && parse_reg(ops[0], &rd);
    bool r1 = nops > 1 && parse_reg(ops[1], &ra);
    bool r2 = nops > 2 && parse_reg(ops[2], &rb);

    if (strcmp(mn, "nop") == 0 && nops == 0) {
        return seq_word(q, addi(X0, X0, 0));
    }
    if (strcmp(mn, "li") == 0 && nops == 2 && r0 && parse_int(ops[1], &imm)) {
        uint32_t w[8];
        int n = li_seq(rd, imm, w);
        for (int i = 0; i < n; i++) {
            if (!seq_word(q, w[i])) {
                return false;
            }
        }
        return true;
    }
    if (nops == 2 && r0 && r1) {
        static const struct {
            const char *name;
            uint32_t base;          // the word with rd and rs zero
        } unary[] = {
            { "mv", 0x00000013u },      // addi rd, rs, 0
            { "not", 0xfff04013u },     // xori rd, rs, -1
            { "sext.w", 0x0000001bu },  // addiw rd, rs, 0
            { "zext.b", 0x0ff07013u },  // andi rd, rs, 255
            { "zext.h", 0x0800403bu },
            { "zext.w", 0x0800003bu },  // add.uw rd, rs, zero
            { "seqz", 0x00103013u },    // sltiu rd, rs, 1
        };
        for (size_t i = 0; i < sizeof unary / sizeof unary[0]; i++) {
            if (strcmp(mn, unary[i].name) == 0) {
                return seq_word(q, unary[i].base | rd << 7 | ra << 15);
            }
        }
        if (strcmp(mn, "neg") == 0) {
            return seq_word(q, sub(rd, X0, ra));
        }
        if (strcmp(mn, "negw") == 0) {
            return seq_word(q, enc_r(OP_OP32, 0, 0x20, rd, X0, ra));
        }
        if (strcmp(mn, "snez") == 0) {
            return seq_word(q, enc_r(OP_OP, 3, 0, rd, X0, ra));
        }
        if (strcmp(mn, "sltz") == 0) {
            return seq_word(q, enc_r(OP_OP, 2, 0, rd, ra, X0));
        }
        if (strcmp(mn, "sgtz") == 0) {
            return seq_word(q, enc_r(OP_OP, 2, 0, rd, X0, ra));
        }
    }
    if (strcmp(mn, "lui") == 0 && nops == 2 && r0 &&
            parse_int(ops[1], &imm) && imm >= 0 && imm <= 0xfffff) {
        return seq_word(q, lui(rd, (uint32_t)imm));
    }
    for (size_t i = 0; i < N_ROPS; i++) {
        const rop_t *o = &rops[i];
        if (strcmp(mn, o->name) == 0) {
            return nops == 3 && r0 && r1 && r2 &&
                   seq_word(q, enc_r(o->op, o->f3, o->f7, rd, ra, rb));
        }
    }
    for (size_t i = 0; i < N_IOPS; i++) {
        const iop_t *o = &iops[i];
        if (strcmp(mn, o->name) != 0) {
            continue;
        }
        if (o->form == I_UNARY) {
            return nops == 2 && r0 && r1 && seq_word(q, iop_word(o, rd, ra, 0));
        }
        if (nops != 3 || !r0 || !r1 || !parse_int(ops[2], &imm)) {
            return false;
        }
        bool ok = o->form == I_IMM ? in_imm12(imm)
                : o->form == I_SH6 ? imm >= 0 && imm < 64
                                   : imm >= 0 && imm < 32;
        return ok && seq_word(q, iop_word(o, rd, ra, imm));
    }
    for (unsigned f3 = 0; f3 < 7; f3++) {
        if (strcmp(mn, load_names[f3]) == 0) {
            return nops == 2 && r0 && parse_mem(ops[1], &imm, &ra) &&
                   in_imm12(imm) &&
                   seq_word(q, enc_i(OP_LOAD, f3, rd, ra, (int32_t)imm));
        }
    }
    for (unsigned f3 = 0; f3 < 4; f3++) {
        if (strcmp(mn, store_names[f3]) == 0) {
            return nops == 2 && r0 && parse_mem(ops[1], &imm, &ra) &&
                   in_imm12(imm) &&
                   seq_word(q, enc_s(f3, ra, rd, (int32_t)imm));
        }
    }
    static const struct {
        const char *name;
        unsigned f3;
        bool swap;              // compares its operands the other way
    } branches[] = {
        { "beq", 0, false },  { "bne", 1, false },  { "blt", 4, false },
        { "bge", 5, false },  { "bltu", 6, false }, { "bgeu", 7, false },
        { "bgt", 4, true },   { "ble", 5, true },   { "bgtu", 6, true },
        { "bleu", 7, true },
    };
    for (size_t i = 0; i < sizeof branches / sizeof branches[0]; i++) {
        if (strcmp(mn, branches[i].name) == 0) {
            if (nops != 3 || !r0 || !r1 || !parse_target(p, ops[2], &target)) {
                return false;
            }
            return branches[i].swap ? branch_slot(q, branches[i].f3, ra, rd, target)
                                    : branch_slot(q, branches[i].f3, rd, ra, target);
        }
    }
    static const struct {
        const char *name;
        unsigned f3;
        bool zero_first;        // x0 is the first operand
    } zbranches[] = {
        { "beqz", 0, false }, { "bnez", 1, false }, { "bltz", 4, false },
        { "bgez", 5, false }, { "blez", 5, true },  { "bgtz", 4, true },
    };
    for (size_t i = 0; i < sizeof zbranches / sizeof zbranches[0]; i++) {
        if (strcmp(mn, zbranches[i].name) == 0) {
            if (nops != 2 || !r0 || !parse_target(p, ops[1], &target)) {
                return false;
            }
            return zbranches[i].zero_first
                ? branch_slot(q, zbranches[i].f3, X0, rd, target)
                : branch_slot(q, zbranches[i].f3, rd, X0, target);
        }
    }
    if (strcmp(mn, "j") == 0 && nops == 1 && parse_target(p, ops[0], &target)) {
        return transfer_slot(q, S_JUMP, target);
    }
    if (strcmp(mn, "jal") == 0) {
        if (nops == 1 && parse_target(p, ops[0], &target)) {
            return transfer_slot(q, S_CALL, target);
        }
        if (nops == 2 && r0 && (rd == RA || rd == X0) &&
                parse_target(p, ops[1], &target)) {
            return transfer_slot(q, rd == RA ? S_CALL : S_JUMP, target);
        }
    }
    return false;
}

// Splits a rendering at its "; " separators.
static int split(const char *text, char pieces[][96], int max)
{
    int n = 0;
    const char *at = text;
    while (n < max) {
        const char *semi = strstr(at, "; ");
        size_t len = semi != NULL ? (size_t)(semi - at) : strlen(at);
        if (len >= 96) {
            len = 95;
        }
        memcpy(pieces[n], at, len);
        pieces[n][len] = '\0';
        n++;
        if (semi == NULL) {
            break;
        }
        at = semi + 2;
    }
    return n;
}

// The finding's window, replaced by what it renders: `delete` and
// `delete both` take every instruction of it away; otherwise the
// rendering's leading instructions take its first slot's place and the
// rest of the window goes. What follows the instructions is commentary.
static bool window_edits(const prog_t *p, const hit_t *h, edits_t *ed)
{
    char pieces[8][96];
    int np = split(h->text, pieces, 8);
    ed->n = 0;
    if (strncmp(pieces[0], "delete", 6) == 0) {
        for (unsigned k = 0; k < h->count; k++) {
            add_edit(ed, h->slot + (int)k);
        }
        return true;
    }
    seq_t q = { .n = 0 };
    for (int i = 0; i < np; i++) {
        // check_release_reserve's `one addi sp, sp, K`
        const char *text = strncmp(pieces[i], "one ", 4) == 0
            ? pieces[i] + 4 : pieces[i];
        if (!assemble(p, text, &q)) {
            break;
        }
    }
    if (q.n == 0) {
        return false;
    }
    edit_t *e = add_edit(ed, h->slot);
    memcpy(e->rep, q.s, sizeof(slot_t) * (size_t)q.n);
    e->n = q.n;
    for (unsigned k = 1; k < h->count; k++) {
        add_edit(ed, h->slot + (int)k);
    }
    return true;
}

// Whether a word reads register r through a register field: rs1 and rs2
// by format.
static uint32_t rename_reads(uint32_t w, unsigned from, unsigned to)
{
    unsigned op = w & 0x7fu;
    bool rs1 = op == OP_OP || op == OP_OP32 || op == OP_STORE ||
               op == OP_BRANCH || op == OP_IMM || op == OP_IMM32 ||
               op == OP_LOAD || op == OP_JALR;
    bool rs2 = op == OP_OP || op == OP_OP32 || op == OP_STORE ||
               op == OP_BRANCH;
    if (rs1 && (w >> 15 & 31u) == from) {
        w = (w & ~(31u << 15)) | to << 15;
    }
    if (rs2 && (w >> 20 & 31u) == from) {
        w = (w & ~(31u << 20)) | to << 20;
    }
    return w;
}

static bool reads(uint32_t w, unsigned r)
{
    return rename_reads(w, r, r == 1 ? 2 : 1) != w;
}

// check_copy_for_reader's `delete; <reader> at 0x<addr> names <reg>`:
// the mv goes and its reader names that register where it named the
// mv's destination.
static bool copy_edits(const prog_t *p, const hit_t *h, edits_t *ed)
{
    const char *at = strstr(h->text, " at 0x");
    const char *names = strstr(h->text, " names ");
    if (strncmp(h->text, "delete; ", 8) != 0 || at == NULL || names == NULL) {
        return false;
    }
    char reg[16];
    if (sscanf(names + 7, "%15[a-z0-9]", reg) != 1) {
        return false;
    }
    unsigned to;
    int reader = slot_at(p, strtoull(at + 4, NULL, 16) - VADDR);
    const slot_t *m = &p->s[h->slot];
    if (!parse_reg(reg, &to) || reader <= h->slot || m->kind != S_PLAIN ||
            p->s[reader].kind != S_PLAIN) {
        return false;
    }
    unsigned from = m->word >> 7 & 31u;
    ed->n = 0;
    add_edit(ed, h->slot);
    edit_t *e = add_edit(ed, reader);
    e->rep[0] = p->s[reader];
    e->rep[0].word = rename_reads(p->s[reader].word, from, to);
    e->rep[0].half = e->rep[0].c ? compress(e->rep[0].word) : 0;
    e->n = 1;
    return true;
}

// The constant checks' windows: the chain building rc, then rc's uses
// with unrelated instructions between them. The chain goes -- or, for
// the complement, becomes the li the rendering opens with -- and each
// use takes the instruction the rendering spells for it. A rendering
// that counts the uses rather than spelling them leaves the rest to
// derive(), which works each one out from the constant: the rewrite
// still runs, and still has to agree.
enum { K_IMM, K_ZERO, K_MASK, K_COMP };

// A step of a chain building rc, of the kinds riscvlint's chain takes:
// an immediate operation, addiw or slli.uw on rc, zext.w of rc, or
// shNadd of rc with itself. An `or rc, zero, rc` reads only rc too, but
// it is a use of the constant rather than a step in building it.
static bool chain_step(const slot_t *s, unsigned rc)
{
    if (s->kind != S_PLAIN || (s->word >> 7 & 31u) != rc ||
            (s->word >> 15 & 31u) != rc) {
        return false;
    }
    unsigned op = s->word & 0x7fu, f3 = s->word >> 12 & 7u;
    unsigned b = s->word >> 20 & 31u, f7 = s->word >> 25;
    switch (op) {
    case OP_IMM:
        return true;
    case OP_IMM32:
        return f3 == 0 || (f3 == 1 && (s->word >> 26) == 0x02);
    case OP_OP32:
        return f3 == 0 && f7 == 0x04 && b == X0;
    case OP_OP:
        return f7 == 0x10 && f3 != 0 && (f3 & 1) == 0 && b == rc;
    default:
        return false;
    }
}

// The value a chain leaves, for the steps riscvlint follows: li, lui
// or bseti from x0 to start, then the immediate operations, addiw,
// slli.uw, zext.w and shNadd of the register with itself. Worked out
// here from the words, so that a chain riscvlint misreads is a
// difference rather than an agreement.
static bool chain_value(const prog_t *p, int first, int end, int64_t *v)
{
    for (int i = first; i < end; i++) {
        uint32_t w = p->s[i].word;
        unsigned op = w & 0x7fu, f3 = w >> 12 & 7u, sh = w >> 20 & 63u;
        unsigned f6 = w >> 26, f7 = w >> 25;
        int64_t imm = sext(w >> 20, 12);
        uint64_t u = i == first ? 0 : (uint64_t)*v;
        if (op == OP_LUI) {
            *v = sext(w & 0xfffff000u, 32);
            continue;
        }
        if (op == OP_IMM) {
            switch (f3) {
            case 0: *v = (int64_t)(u + (uint64_t)imm); continue;
            case 4: *v = (int64_t)(u ^ (uint64_t)imm); continue;
            case 6: *v = (int64_t)(u | (uint64_t)imm); continue;
            case 7: *v = (int64_t)(u & (uint64_t)imm); continue;
            case 1:
                if (f6 == 0x00) { *v = (int64_t)(u << sh); continue; }
                if (f6 == 0x0a) { *v = (int64_t)(u | 1ull << sh); continue; }
                if (f6 == 0x12) { *v = (int64_t)(u & ~(1ull << sh)); continue; }
                if (f6 == 0x1a) { *v = (int64_t)(u ^ 1ull << sh); continue; }
                return false;
            case 5:
                if (f6 == 0x00) { *v = (int64_t)(u >> sh); continue; }
                if (f6 == 0x10) { *v = (int64_t)u >> sh; continue; }
                if (f6 == 0x18) {
                    *v = (int64_t)(sh == 0 ? u : u >> sh | u << (64 - sh));
                    continue;
                }
                return false;
            default:
                return false;
            }
        }
        if (op == OP_IMM32 && f3 == 0) {
            *v = sext((u + (uint64_t)imm) & 0xffffffffu, 32);
        } else if (op == OP_IMM32 && f3 == 1 && f6 == 0x02) {      // slli.uw
            *v = (int64_t)((u & 0xffffffffu) << sh);
        } else if (op == OP_OP32 && f3 == 0 && f7 == 0x04) {       // zext.w
            *v = (int64_t)(u & 0xffffffffu);
        } else if (op == OP_OP && f7 == 0x10 && (f3 & 1) == 0 && f3 != 0) {
            *v = (int64_t)((u << (f3 >> 1)) + u);                   // shNadd
        } else {
            return false;
        }
    }
    return true;
}

// The use at w rewritten the way the check's kind does it, with k the
// constant rc held.
static bool derive(int kind, uint32_t w, unsigned rc, int64_t k, seq_t *q)
{
    unsigned op = w & 0x7fu, f3 = w >> 12 & 7u, f7 = w >> 25;
    unsigned rd = w >> 7 & 31u, a = w >> 15 & 31u, b = w >> 20 & 31u;
    unsigned x = a == rc ? b : a;
    switch (kind) {
    case K_ZERO:
        return op == OP_STORE && seq_word(q, (w & ~(31u << 20)));
    case K_MASK: {
        unsigned n = (unsigned)__builtin_popcountll((uint64_t)k);
        if (n == 16) {
            return seq_word(q, zext_h(rd, x));
        }
        if (n == 32) {
            return seq_word(q, zext_w(rd, x));
        }
        return seq_word(q, slli(rd, x, 64 - n)) &&
               seq_word(q, srli(rd, rd, 64 - n));
    }
    case K_COMP: {
        static const struct {
            uint8_t f3, f7, to_f7;      // and <-> andn, or <-> orn, xor <-> xnor
        } swaps[] = {
            { 7, 0x00, 0x20 }, { 6, 0x00, 0x20 }, { 4, 0x00, 0x20 },
            { 7, 0x20, 0x00 }, { 6, 0x20, 0x00 }, { 4, 0x20, 0x00 },
        };
        for (size_t i = 0; i < sizeof swaps / sizeof swaps[0]; i++) {
            if (op == OP_OP && f3 == swaps[i].f3 && f7 == swaps[i].f7) {
                return seq_word(q, enc_r(OP_OP, f3, swaps[i].to_f7, rd, x, rc));
            }
        }
        return false;
    }
    default:
        break;
    }
    // K_IMM: the immediate form of the operation, rc's value in place
    // of rc.
    bool second = b == rc && a != rc;
    if (op != OP_OP && op != OP_OP32) {
        return false;
    }
    if (op == OP_OP && f7 == 0 && (f3 == 0 || f3 == 4 || f3 == 6 || f3 == 7)) {
        return in_imm12(k) && seq_word(q, enc_i(OP_IMM, f3, rd, x, (int32_t)k));
    }
    if (op == OP_OP32 && f7 == 0 && f3 == 0) {
        return in_imm12(k) && seq_word(q, addiw(rd, x, (int32_t)k));
    }
    if (!second) {
        return false;
    }
    if (f7 == 0x20 && f3 == 0) {                            // sub, subw
        return in_imm12(-k) &&
               seq_word(q, enc_i(op == OP_OP ? OP_IMM : OP_IMM32, 0, rd, a,
                                 (int32_t)-k));
    }
    if (op == OP_OP && f7 == 0 && (f3 == 2 || f3 == 3)) {    // slt, sltu
        return in_imm12(k) && seq_word(q, enc_i(OP_IMM, f3, rd, a, (int32_t)k));
    }
    // The shifts read their amount modulo the width, whatever k is.
    if ((f7 == 0 || f7 == 0x20) && (f3 == 1 || f3 == 5)) {
        unsigned mask = op == OP_OP ? 63u : 31u;
        return seq_word(q, enc_i(op == OP_OP ? OP_IMM : OP_IMM32, f3, rd, a,
                                 (int32_t)((f7 << 5) | ((uint64_t)k & mask))));
    }
    return false;
}

static bool const_edits(const prog_t *p, const hit_t *h, int kind,
                        edits_t *ed)
{
    char pieces[8][96];
    int np = split(h->text, pieces, 8);
    int first = h->slot, end = h->slot + (int)h->count;
    if (p->s[first].kind != S_PLAIN) {
        return false;
    }
    unsigned rc = p->s[first].word >> 7 & 31u;
    int chain_end = first + 1;
    if (kind == K_MASK || kind == K_COMP) {
        while (chain_end < end && chain_step(&p->s[chain_end], rc)) {
            chain_end++;
        }
    }
    int64_t k = 0;
    if ((kind == K_IMM || kind == K_MASK) &&
            !chain_value(p, first, chain_end, &k)) {
        return false;
    }
    ed->n = 0;
    int piece = 0;
    seq_t q = { .n = 0 };
    if (kind == K_COMP) {
        if (!assemble(p, pieces[0], &q)) {
            return false;
        }
        piece = 1;
    }
    edit_t *e = add_edit(ed, first);
    memcpy(e->rep, q.s, sizeof(slot_t) * (size_t)q.n);
    e->n = q.n;
    for (int i = first + 1; i < chain_end; i++) {
        add_edit(ed, i);
    }
    int uses = 0;
    for (int i = chain_end; i < end; i++) {
        const slot_t *u = &p->s[i];
        if (u->kind != S_PLAIN || !reads(u->word, rc)) {
            continue;
        }
        e = add_edit(ed, i);
        seq_t r = { .n = 0 };
        // A rendering spells the first use, or for the immediate forms
        // the first two; a mask's use may take two instructions.
        bool spelled = uses == 0 || (kind == K_IMM && uses == 1);
        if (spelled && piece < np && assemble(p, pieces[piece], &r)) {
            piece++;
            while (kind == K_MASK && piece < np &&
                   assemble(p, pieces[piece], &r)) {
                piece++;
            }
        } else if (!derive(kind, u->word, rc, k, &r)) {
            return false;
        }
        memcpy(e->rep, r.s, sizeof(slot_t) * (size_t)r.n);
        e->n = r.n;
        uses++;
    }
    return uses > 0;
}

static int32_t store_off(uint32_t w)
{
    return (int32_t)sext((w >> 25) << 5 | (w >> 7 & 31u), 12);
}

// An `addi sp,sp,K`, and K.
static bool sp_adjust(const slot_t *s, int64_t *k)
{
    if (s->kind != S_PLAIN || (s->word & 0xfffffu) != 0x10113u) {
        return false;
    }
    *k = sext(s->word >> 20, 12);
    return true;
}

// A load or store through sp, and its offset.
static bool sp_access(const slot_t *s, int64_t *off)
{
    if (s->kind != S_PLAIN || (s->word >> 15 & 31u) != SP) {
        return false;
    }
    unsigned op = s->word & 0x7fu;
    if (op == OP_LOAD) {
        *off = sext(s->word >> 20, 12);
        return true;
    }
    if (op == OP_STORE) {
        *off = store_off(s->word);
        return true;
    }
    return false;
}

static uint32_t with_off(uint32_t w, int64_t off)
{
    if ((w & 0x7fu) == OP_LOAD) {
        return (w & 0x000fffffu) | ((uint32_t)off & 0xfffu) << 20;
    }
    return enc_s(w >> 12 & 7u, w >> 15 & 31u, w >> 20 & 31u, (int32_t)off);
}

// check_push_run's and check_release_run's `one addi sp, sp, K for N
// adjustments`: the run's adjustments become one by the K rendered --
// at the first reservation for pushes, at the last release for pops --
// and each access through sp between them moves by what the run had
// yet to reserve, or had already released, when it ran. The rendering
// says only the total, so rwfuzz works out the rest.
static bool run_edits(const prog_t *p, const hit_t *h, bool pushes,
                      edits_t *ed)
{
    int64_t total, k, off;
    if (sscanf(h->text, "one addi sp, sp, %" SCNd64, &total) != 1) {
        return false;
    }
    int first = h->slot, end = h->slot + (int)h->count, last = -1;
    int64_t all = 0;
    for (int i = first; i < end; i++) {
        if (sp_adjust(&p->s[i], &k)) {
            all += k;
            last = i;
        }
    }
    int at = pushes ? first : last;
    if (last < 0 || !sp_adjust(&p->s[at], &k)) {
        return false;
    }
    ed->n = 0;
    int64_t sofar = 0;
    for (int i = first; i < end; i++) {
        if (sp_adjust(&p->s[i], &k)) {
            sofar += k;
            edit_t *e = add_edit(ed, i);
            if (i == at) {
                e->rep[0] = plain(addi(SP, SP, (int32_t)total));
                e->n = 1;
            }
        } else if (sp_access(&p->s[i], &off)) {
            // Pushes: sp is already at the total, which is lower by what
            // is still to come. Pops: sp is still where the run began,
            // lower by what had been released.
            int64_t moved = pushes ? off + (sofar - all) : off + sofar;
            if (!in_imm12(moved)) {
                return false;
            }
            edit_t *e = add_edit(ed, i);
            e->rep[0] = plain(with_off(p->s[i].word, moved));
            e->n = 1;
        }
    }
    return true;
}

// check_zero_store_run's `N instead of M stores for B bytes at
// OFF(BASE)`: the run's stores replaced by the cover of those bytes with
// naturally aligned stores of zero, the widest that fits at each step,
// which rwfuzz works out itself and holds to N.
static bool zero_run_edits(const hit_t *h, edits_t *ed)
{
    int n, m;
    int64_t bytes, off;
    char base[8];
    unsigned b;
    if (sscanf(h->text, "%d instead of %d stores for %" SCNd64 " bytes at %"
               SCNd64 "(%7[a-z0-9])", &n, &m, &bytes, &off, base) != 5 ||
            !parse_reg(base, &b) || m != (int)h->count) {
        return false;
    }
    seq_t q = { .n = 0 };
    for (int64_t pos = off; pos < off + bytes; ) {
        int64_t w = 8;
        while (w > 1 && (pos % w != 0 || pos + w > off + bytes)) {
            w /= 2;
        }
        unsigned f3 = w == 8 ? 3 : w == 4 ? 2 : w == 2 ? 1 : 0;
        if (!seq_word(&q, enc_s(f3, b, X0, (int32_t)pos))) {
            return false;
        }
        pos += w;
    }
    if (q.n != n) {
        return false;
    }
    ed->n = 0;
    edit_t *e = add_edit(ed, h->slot);
    memcpy(e->rep, q.s, sizeof(slot_t) * (size_t)q.n);
    e->n = q.n;
    for (unsigned k = 1; k < h->count; k++) {
        add_edit(ed, h->slot + (int)k);
    }
    return true;
}

// The advice a finding gives, as edits to the program.
static bool advice(const prog_t *p, const hit_t *h, const char *title,
                   edits_t *ed)
{
    static const struct {
        const char *title;
        int kind;
    } consts[] = {
        { "constant loaded for an immediate operand", K_IMM },
        { "zero loaded for a store", K_ZERO },
        { "mask loaded for a zero extension", K_MASK },
        { "and/or/xor constant whose complement builds shorter", K_COMP },
    };
    for (size_t i = 0; i < sizeof consts / sizeof consts[0]; i++) {
        if (strcmp(title, consts[i].title) == 0) {
            return const_edits(p, h, consts[i].kind, ed);
        }
    }
    if (strcmp(title, "copy its only reader could do without") == 0) {
        return copy_edits(p, h, ed);
    }
    if (strcmp(title, "run of zero stores one wider store would do") == 0) {
        return zero_run_edits(h, ed);
    }
    if (strcmp(title, "pushes one stack adjustment would do") == 0) {
        return run_edits(p, h, true, ed);
    }
    if (strcmp(title, "releases one stack adjustment would do") == 0) {
        return run_edits(p, h, false, ed);
    }
    return window_edits(p, h, ed);
}

// === Execution ===

// The executable region: a thunk, its save area, then the program. The
// thunk runs the program on a stack of its own, so that the frame --
// whose address the body may copy into a register or memory -- is at
// the same place in every run, whatever called it, and so that the
// whole stack can be compared afterwards: a stack-moving rewrite must
// leave the memory below sp as the original did. GUARD bytes above the
// frame take a body that releases more than it reserved. The thunk
// starts the program with s0..s11 zero, records what they and sp hold
// when it returns, and puts back the caller's from its save area, which
// it reaches pc-relative: whatever the program did to its registers and
// its stack, rwfuzz itself survives it.
static uint8_t *jit;
#define SAVE_AT 512
#define CODE_AT 1024
#define STACK_SIZE 16384
#define GUARD 1024
static uint8_t exec_stack[STACK_SIZE] __attribute__((aligned(16)));
static uint8_t exec_mem[BUF_SIZE] __attribute__((aligned(64)));
static uint8_t mem_init[BUF_SIZE];
static uint8_t stack_init[STACK_SIZE];
static state_t run_state;

static sigjmp_buf escape;
static volatile sig_atomic_t in_jit, caught;

static void on_signal(int sig)
{
    if (in_jit) {
        in_jit = 0;
        caught = sig;
        siglongjmp(escape, 1);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static bool exec_open(void)
{
    void *m = mmap(NULL, CODE_AT + SLOTS_MAX * 4u,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        perror("rwfuzz: mmap");
        return false;
    }
    jit = m;
    // a0 the state, a1 the program, a2 the sp to call it with. The save
    // area holds sp, ra, the state, that sp and s0..s11, in that order.
    static const unsigned saved[12] = { 8, 9, 18, 19, 20, 21, 22, 23, 24,
                                        25, 26, 27 };
    uint32_t thunk[SAVE_AT / 4];
    int n = 0;
    thunk[n++] = auipc(T0, 0);
    thunk[n++] = addi(T0, T0, SAVE_AT);
    thunk[n++] = sd(SP, T0, 0);
    thunk[n++] = sd(RA, T0, 8);
    thunk[n++] = sd(A0, T0, 16);
    thunk[n++] = sd(A0 + 2, T0, 24);
    for (int i = 0; i < 12; i++) {
        thunk[n++] = sd(saved[i], T0, 32 + 8 * i);
        thunk[n++] = li(saved[i], 0);
    }
    thunk[n++] = mv(SP, A0 + 2);
    thunk[n++] = jalr(RA, A0 + 1, 0);
    int back = n;
    thunk[n++] = auipc(T0, 0);
    thunk[n++] = addi(T0, T0, SAVE_AT - 4 * back);
    thunk[n++] = ld(T6, T0, 16);
    for (int i = 0; i < 12; i++) {
        thunk[n++] = sd(saved[i], T6, STATE_S + 8 * i);
        thunk[n++] = ld(saved[i], T0, 32 + 8 * i);
    }
    thunk[n++] = ld(T1, T0, 24);
    thunk[n++] = sub(T1, SP, T1);
    thunk[n++] = sd(T1, T6, STATE_SP_RET);
    thunk[n++] = ld(RA, T0, 8);
    thunk[n++] = ld(SP, T0, 0);
    thunk[n++] = jalr(X0, RA, 0);
    for (int i = 0; i < n; i++) {
        put32(jit + 4 * i, thunk[i]);
    }
    static uint8_t altstack[65536];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack };
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_ONSTACK | SA_NODEFER;
    const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGALRM };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        sigaction(sigs[i], &sa, NULL);
    }
    return true;
}

typedef struct {
    state_t st;
    int sig;            // what stopped it, or 0
    uint8_t mem[BUF_SIZE];
    uint8_t stack[STACK_SIZE];
} result_t;

static void run(const prog_t *p, const state_t *in, result_t *out)
{
    size_t len = p->addr[p->n];
    memcpy(jit + CODE_AT, p->code, len);
    __builtin___clear_cache((char *)jit, (char *)jit + CODE_AT + len);
    memcpy(exec_mem, mem_init, BUF_SIZE);
    memcpy(exec_stack, stack_init, STACK_SIZE);
    run_state = *in;
    run_state.buf = (uint64_t)(uintptr_t)exec_mem;
    out->sig = 0;
    if (sigsetjmp(escape, 0) == 0) {
        in_jit = 1;
        ((void (*)(state_t *, void *, void *))(void *)jit)(
            &run_state, jit + CODE_AT, exec_stack + STACK_SIZE - GUARD);
        in_jit = 0;
    } else {
        out->sig = caught;
    }
    out->st = run_state;
    memcpy(out->mem, exec_mem, BUF_SIZE);
    memcpy(out->stack, exec_stack, STACK_SIZE);
}

static uint64_t edge_value(void)
{
    switch (rr(12)) {
    case 0: return 0;
    case 1: return ~0ull;
    case 2: return 0xffffffffull;
    case 3: return 0x80000000ull;
    case 4: return 0x7fffffffull;
    case 5: return 0xffffffff80000000ull | rr(0x10000);
    case 6: return rr(4) == 0 ? rr(0x1000) : rr(48);
    case 7: return 0 - (uint64_t)rr(48);
    case 8: return (uint64_t)(1u + rr(3)) << 32;     // W zero, X not
    case 9: return 1ull << rr(64);
    case 10: return (coin(2) ? 0xffull : 0xffffull) + rr(3) - 1;
    default: return rnd();
    }
}

#define TRIALS 6

static state_t trial_in[TRIALS];
static uint8_t trial_mem[TRIALS][BUF_SIZE];
static uint8_t trial_stack[TRIALS][STACK_SIZE];
static result_t base[TRIALS];

// Draws the states every rewrite of this program runs from, and runs
// the original from each.
static void run_original(void)
{
    for (int t = 0; t < TRIALS; t++) {
        for (int i = 0; i < 8; i++) {
            trial_in[t].a[i] = edge_value();
        }
        for (int i = 0; i < FRAME / 8; i++) {
            trial_in[t].frame[i] = edge_value();
        }
        for (int i = 0; i < BUF_SIZE / 8; i++) {
            uint64_t v = edge_value();
            memcpy(&trial_mem[t][8 * i], &v, 8);
        }
        for (int i = 0; i < STACK_SIZE / 8; i++) {
            uint64_t v = rnd();
            memcpy(&trial_stack[t][8 * i], &v, 8);
        }
        memcpy(mem_init, trial_mem[t], BUF_SIZE);
        memcpy(stack_init, trial_stack[t], STACK_SIZE);
        run(&gen, &trial_in[t], &base[t]);
    }
}

static bool same(const result_t *a, const result_t *b)
{
    return a->sig == b->sig &&
           memcmp(a->st.a, b->st.a, sizeof a->st.a) == 0 &&
           memcmp(a->st.s, b->st.s, sizeof a->st.s) == 0 &&
           memcmp(a->st.frame, b->st.frame, sizeof a->st.frame) == 0 &&
           a->st.sp_end == b->st.sp_end && a->st.sp_ret == b->st.sp_ret &&
           memcmp(a->mem, b->mem, BUF_SIZE) == 0 &&
           memcmp(a->stack, b->stack, STACK_SIZE) == 0;
}

// Runs a rewrite from each trial state; -1 if all agreed with the
// original, else the trial that showed the difference.
static result_t alt_result;

static int differs(const prog_t *alt)
{
    for (int t = 0; t < TRIALS; t++) {
        memcpy(mem_init, trial_mem[t], BUF_SIZE);
        memcpy(stack_init, trial_stack[t], STACK_SIZE);
        run(alt, &trial_in[t], &alt_result);
        if (!same(&base[t], &alt_result)) {
            return t;
        }
    }
    return -1;
}

static void dump(const prog_t *p, const char *heading, int first, int last)
{
    printf("---- %s\n", heading);
    cs_insn *insn = cs_malloc(cs);
    for (int i = 0; i < p->n; i++) {
        if (i == p->body || i == p->epi) {
            printf("  ----\n");
        }
        if (i == p->tramp) {
            break;
        }
        const uint8_t *code = p->code + p->addr[i];
        size_t size = p->addr[i + 1] - p->addr[i];
        uint64_t a = VADDR + p->addr[i];
        bool ok = cs_disasm_iter(cs, &code, &size, &a, insn);
        printf("  %c %5" PRIx32 ": %-10s %s\n",
               i >= first && i <= last ? '>' : ' ', VADDR + p->addr[i],
               ok ? insn->mnemonic : "?", ok ? insn->op_str : "");
    }
    cs_free(insn, 1);
}

static void dump_result(const char *what, const state_t *st, int sig)
{
    printf("  %s:", what);
    for (int i = 0; i < 8; i++) {
        printf(" %" PRIx64, st->a[i]);
    }
    if (sig != 0) {
        printf(" (signal %d)", sig);
    }
    printf("\n");
}

static void dump_mismatch(const prog_t *alt, const char *heading, int first,
                          int last, int trial)
{
    dump(&gen, heading, first, last);
    dump(alt, "rewritten", -1, -1);
    dump_result("from    ", &trial_in[trial], 0);
    dump_result("original", &base[trial].st, base[trial].sig);
    dump_result("rewrite ", &alt_result.st, alt_result.sig);
    if (memcmp(base[trial].st.frame, alt_result.st.frame,
               sizeof alt_result.st.frame) != 0) {
        printf("  the frames differ\n");
    }
    if (memcmp(base[trial].mem, alt_result.mem, BUF_SIZE) != 0) {
        printf("  the buffers differ\n");
    }
    if (memcmp(base[trial].st.s, alt_result.st.s, sizeof alt_result.st.s)) {
        printf("  the callee-saved registers differ\n");
    }
    if (memcmp(base[trial].stack, alt_result.stack, STACK_SIZE) != 0) {
        printf("  the stacks differ\n");
    }
    if (base[trial].st.sp_end != alt_result.st.sp_end ||
            base[trial].st.sp_ret != alt_result.st.sp_ret) {
        printf("  sp differs: %" PRId64 "/%" PRId64 " against %" PRId64
               "/%" PRId64 "\n", base[trial].st.sp_end, base[trial].st.sp_ret,
               alt_result.st.sp_end, alt_result.st.sp_ret);
    }
}

// === Modes ===

// The register a plain slot writes, or false for one that writes none.
static bool writes(const slot_t *s, unsigned *rd)
{
    if (s->kind != S_PLAIN) {
        return false;
    }
    unsigned op = s->word & 0x7fu;
    if (op == OP_STORE || op == OP_BRANCH) {
        return false;
    }
    *rd = s->word >> 7 & 31u;
    return *rd != 0;
}

static bool body_reg(unsigned r)
{
    return r >= A0 && r < A0 + 8;
}

// ext: delete an unflagged extension that reads and writes one
// register, or make an unflagged one into another register a mv.
static bool is_extension(uint32_t w)
{
    uint32_t f = w & 0xfff0707fu;
    return f == 0x0000001bu || f == 0x0ff07013u || f == 0x60401013u ||
           f == 0x60501013u || f == 0x0800403bu || f == 0x0800003bu;
}

static bool ext_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    if (s->kind != S_PLAIN || !is_extension(s->word) || coin(2)) {
        return false;
    }
    unsigned rd = s->word >> 7 & 31u, rs = s->word >> 15 & 31u;
    edit_t *e = add_edit(ed, i);
    if (rd != rs) {
        e->rep[0] = plain(mv(rd, rs));
        e->n = 1;
    }
    return true;
}

// dead: delete an unflagged write whose register is written again
// within four slots.
static bool dead_control(const prog_t *p, int i, edits_t *ed)
{
    unsigned rd, rd2;
    if (!writes(&p->s[i], &rd) || !body_reg(rd)) {
        return false;
    }
    for (int k = i + 1; k <= i + 4 && k < p->epi; k++) {
        if (writes(&p->s[k], &rd2) && rd2 == rd) {
            add_edit(ed, i);
            return true;
        }
    }
    return false;
}

// remat: an unflagged instruction whose word, but for its destination,
// one of the six before it had: deleted where the destinations match,
// a mv from the earlier one's otherwise.
static bool remat_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    unsigned rd, rd2;
    if (!writes(s, &rd) || !body_reg(rd) || (s->word & 0x7fu) == OP_LOAD) {
        return false;
    }
    for (int k = i - 1; k >= i - 6 && k >= p->body; k--) {
        const slot_t *e0 = &p->s[k];
        if (writes(e0, &rd2) && with_rd(e0->word, 0) == with_rd(s->word, 0)) {
            edit_t *e = add_edit(ed, i);
            if (rd2 != rd) {
                e->rep[0] = plain(mv(rd, rd2));
                e->n = 1;
            }
            return true;
        }
    }
    return false;
}

// mem: a load of what one of the six before it loaded -- same base,
// offset and width -- made a mv from that load's register; or a frame
// store with a store to the same bytes after it deleted.
static bool same_place(uint32_t a, uint32_t b)
{
    return (a & 0x000ff000u) == (b & 0x000ff000u) &&       // f3, rs1
           (a >> 15 & 31u) == (b >> 15 & 31u);
}

// A store of zero through sp or s0: its width and offset.
static bool zero_store(const slot_t *s, unsigned *base, int64_t *off,
                       int64_t *width)
{
    if (s->kind != S_PLAIN || (s->word & 0x7fu) != OP_STORE ||
            (s->word >> 20 & 31u) != X0) {
        return false;
    }
    *base = s->word >> 15 & 31u;
    *off = store_off(s->word);
    *width = 1 << (s->word >> 12 & 3u);
    return *base == SP || *base == S0;
}

static bool mem_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    if (s->kind != S_PLAIN || coin(2)) {
        return false;
    }
    // Two adjacent stores of zero to abutting bytes, as one store where
    // their union is one aligned width.
    unsigned b0, b1;
    int64_t o0, o1, w0, w1;
    if (i + 1 < p->epi && zero_store(s, &b0, &o0, &w0) &&
            zero_store(&p->s[i + 1], &b1, &o1, &w1) && b0 == b1 &&
            w0 == w1 && w0 < 8 && (o1 == o0 + w0 || o0 == o1 + w1)) {
        int64_t lo = o0 < o1 ? o0 : o1;
        if (lo % (2 * w0) == 0) {
            unsigned f3 = w0 == 4 ? 3 : w0 == 2 ? 2 : 1;
            edit_t *e = add_edit(ed, i);
            e->rep[0] = plain(enc_s(f3, b0, X0, (int32_t)lo));
            e->n = 1;
            add_edit(ed, i + 1);
            return true;
        }
    }
    unsigned op = s->word & 0x7fu;
    if (op == OP_LOAD) {
        for (int k = i - 1; k >= i - 6 && k >= p->body; k--) {
            const slot_t *e0 = &p->s[k];
            if (e0->kind == S_PLAIN && (e0->word & 0x7fu) == OP_LOAD &&
                    same_place(e0->word, s->word) &&
                    (e0->word >> 20) == (s->word >> 20)) {
                edit_t *e = add_edit(ed, i);
                e->rep[0] = plain(mv(s->word >> 7 & 31u, e0->word >> 7 & 31u));
                e->n = 1;
                return true;
            }
        }
        return false;
    }
    if (op != OP_STORE) {
        return false;
    }
    unsigned base = s->word >> 15 & 31u;
    if (base != SP && base != S0) {
        return false;
    }
    for (int k = i + 1; k <= i + 6 && k < p->epi; k++) {
        const slot_t *e1 = &p->s[k];
        if (e1->kind == S_PLAIN && (e1->word & 0x7fu) == OP_STORE &&
                same_place(e1->word, s->word) &&
                store_off(e1->word) == store_off(s->word)) {
            add_edit(ed, i);
            return true;
        }
    }
    return false;
}

// shift: an unflagged adjacent slli + srli/srai/add folded the way the
// shape suggests, whatever the registers do.
static bool shift_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *a = &p->s[i], *b = &p->s[i + 1];
    if (i + 1 >= p->epi || a->kind != S_PLAIN || b->kind != S_PLAIN ||
            (a->word & 0xfc00707fu) != 0x00001013u) {          // slli
        return false;
    }
    unsigned r = a->word >> 7 & 31u, s = a->word >> 15 & 31u;
    unsigned k = a->word >> 20 & 63u, d = b->word >> 7 & 31u;
    uint32_t w;
    if ((b->word & 0xfc00707fu) == 0x00005013u &&               // srli
            (b->word >> 15 & 31u) == r && (b->word >> 20 & 63u) == k) {
        if (k == 32) {
            w = zext_w(d, s);
        } else if (k == 48) {
            w = zext_h(d, s);
        } else if (k >= 53) {
            w = andi(d, s, (1 << (64 - k)) - 1);
        } else {
            return false;
        }
    } else if ((b->word & 0xfc00707fu) == 0x40005013u &&        // srai
               (b->word >> 15 & 31u) == r && (b->word >> 20 & 63u) == k &&
               (k == 48 || k == 56)) {
        w = k == 48 ? sext_h(d, s) : sext_b(d, s);
    } else if ((b->word & 0xfe00707fu) == 0x00000033u && k >= 1 && k <= 3 &&
               ((b->word >> 15 & 31u) == r) != ((b->word >> 20 & 31u) == r)) {
        unsigned x = (b->word >> 15 & 31u) == r ? b->word >> 20 & 31u
                                                 : b->word >> 15 & 31u;
        w = enc_r(OP_OP, 2 * k, 0x10, d, s, x);                 // shNadd
    } else {
        return false;
    }
    edit_t *e = add_edit(ed, i);
    e->rep[0] = plain(w);
    e->n = 1;
    add_edit(ed, i + 1);
    return true;
}

// branch: delete an unflagged conditional branch, or make it a j to its
// target.
static bool branch_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    if (s->kind != S_BRANCH || coin(2)) {
        return false;
    }
    edit_t *e = add_edit(ed, i);
    if (coin(2)) {
        e->rep[0] = *s;
        e->rep[0].kind = S_JUMP;
        e->rep[0].c = false;
        e->n = 1;
    }
    return true;
}

// copy: delete an unflagged mv and rename the next reader of its
// destination to its source.
static bool copy_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    if (s->kind != S_PLAIN || (s->word & 0xfff0707fu) != 0x00000013u) {
        return false;
    }
    unsigned rd = s->word >> 7 & 31u, rs = s->word >> 15 & 31u;
    if (!body_reg(rd) || rs == 0 || rs == rd) {
        return false;
    }
    for (int k = i + 1; k <= i + 4 && k < p->epi; k++) {
        const slot_t *r = &p->s[k];
        if (r->kind != S_PLAIN || !reads(r->word, rd)) {
            continue;
        }
        add_edit(ed, i);
        edit_t *e = add_edit(ed, k);
        e->rep[0] = plain(rename_reads(r->word, rd, rs));
        e->n = 1;
        return true;
    }
    return false;
}

// const: an unflagged li deleted and the next operation reading its
// register given the immediate form, whatever else reads it.
static bool const_control(const prog_t *p, int i, edits_t *ed)
{
    const slot_t *s = &p->s[i];
    if (s->kind != S_PLAIN || (s->word & 0x000ff07fu) != OP_IMM) {
        return false;                           // li: addi rd, x0, imm
    }
    unsigned rc = s->word >> 7 & 31u;
    int64_t k = sext(s->word >> 20, 12);
    for (int u = i + 1; u <= i + 6 && u < p->epi; u++) {
        const slot_t *r = &p->s[u];
        if (r->kind != S_PLAIN || !reads(r->word, rc)) {
            continue;
        }
        seq_t q = { .n = 0 };
        if (!derive(K_IMM, r->word, rc, k, &q)) {
            return false;
        }
        add_edit(ed, i);
        edit_t *e = add_edit(ed, u);
        e->rep[0] = q.s[0];
        e->n = 1;
        return true;
    }
    return false;
}

// stack: an unflagged restore from the frame pointer deleted, or an
// unflagged pair of adjacent sp adjustments made one.
static bool stack_control(const prog_t *p, int i, edits_t *ed)
{
    int64_t a, b;
    if (p->s[i].kind == S_PLAIN && p->s[i].word == addi(SP, S0, -FRAME)) {
        add_edit(ed, i);
        return true;
    }
    if (i + 1 >= p->epi || !sp_adjust(&p->s[i], &a) ||
            !sp_adjust(&p->s[i + 1], &b) || !in_imm12(a + b)) {
        return false;
    }
    edit_t *e = add_edit(ed, i);
    if (a + b != 0) {
        e->rep[0] = plain(addi(SP, SP, (int32_t)(a + b)));
        e->n = 1;
    }
    add_edit(ed, i + 1);
    return true;
}

#define TITLES_MAX 12

struct mode {
    const char *name;
    const char *titles[TITLES_MAX];
    void (*plant)(void);
    bool (*control)(const prog_t *, int, edits_t *);
};

static const mode_t_ modes[] = {
    { "ext", { "redundant sign or zero extension" }, plant_ext, ext_control },
    { "dead", { "dead register definition" }, plant_dead, dead_control },
    { "remat", { "computation a live register already holds",
                 "constant re-materialization" },
      plant_remat, remat_control },
    { "mem", { "redundant reload", "load of a just-stored value",
               "load of a value the register still holds",
               "dead store to a frame slot",
               "store of a value the slot already holds",
               "base add foldable into memory offset",
               "run of zero stores one wider store would do" },
      plant_mem, mem_control },
    { "const", { "constant loaded for an immediate operand",
                 "zero loaded for a store",
                 "mask loaded for a zero extension",
                 "and/or/xor constant whose complement builds shorter",
                 "constant built in more instructions than li needs" },
      plant_const, const_control },
    { "stack", { "pushes one stack adjustment would do",
                 "releases one stack adjustment would do",
                 "release followed by a reservation",
                 "redundant stack-pointer restore" },
      plant_stack, stack_control },
    { "shift", { "slli + srli foldable to zext.w",
                 "slli + srli foldable to zext.h",
                 "slli + srli foldable to andi",
                 "slli + srai foldable to sext.b or sext.h",
                 "slli + add foldable to shNadd",
                 "not + and/or/xor foldable to andn/orn/xnor",
                 "li + mul foldable to shNadd",
                 "unsigned divide or remainder by a power of two" },
      plant_shift, shift_control },
    { "branch", { "conditional branch whose operands fix its outcome",
                  "constant loaded for a branch against zero",
                  "zero loaded for an equality branch",
                  "comparison a branch could have made",
                  "conditional branch over an unconditional jump",
                  "transfer to the instruction that follows it",
                  "transfer to an unconditional jump",
                  "jump pair foldable to j",
                  "call pair foldable to jal",
                  "call through a scratch register foldable to jal",
                  "branch over a move foldable to max or min" },
      plant_branch, branch_control },
    { "copy", { "copy its only reader could do without",
                "move or zeroing spelled other than mv or li",
                "instruction with no architectural effect" },
      plant_copy, copy_control },
    { "self", { NULL }, plant_any, NULL },
};

static int title_index(const char *title)
{
    for (int i = 0; i < TITLES_MAX && mode->titles[i] != NULL; i++) {
        if (strcmp(title, mode->titles[i]) == 0) {
            return i;
        }
    }
    return -1;
}

static void usage(void)
{
    fprintf(stderr, "usage: rwfuzz [-n PROGRAMS] [-s SEED] MODE\n  modes:");
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        fprintf(stderr, " %s", modes[i].name);
    }
    fprintf(stderr, "\n");
}

// Whether p writes gp or tp. Nothing rwfuzz generates does, so a rewrite
// that does is wrong; and it is not run, since rwfuzz's own code -- the
// signal handler included -- reaches its globals through gp and its
// thread's data through tp.
static bool writes_gp_tp(const prog_t *p)
{
    for (int i = 0; i < p->n; i++) {
        unsigned rd;
        if (writes(&p->s[i], &rd) && (rd == 3 || rd == 4)) {
            return true;
        }
    }
    return false;
}

// Whether some transfer of p goes to slot i.
static bool targeted(const prog_t *p, int i)
{
    for (int k = 0; k < p->n; k++) {
        if (is_transfer(&p->s[k]) && p->s[k].target == i) {
            return true;
        }
    }
    return false;
}

static prog_t alt;

// The self mode: the program spelled with nothing compressed must do
// what it does.
static long self_check(void)
{
    alt = gen;
    for (int i = 0; i < alt.n; i++) {
        alt.s[i].c = false;
        alt.s[i].half = 0;
    }
    layout(&alt);
    int t = differs(&alt);
    if (t >= 0) {
        dump_mismatch(&alt, "MISMATCH: the program with nothing compressed",
                      -1, -1, t);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    long programs = 100000;
    int opt;
    while ((opt = getopt(argc, argv, "n:s:")) != -1) {
        switch (opt) {
        case 'n':
            programs = atol(optarg);
            break;
        case 's':
            rng_state ^= strtoull(optarg, NULL, 0);
            break;
        default:
            usage();
            return 2;
        }
    }
    if (optind + 1 != argc || programs <= 0) {
        usage();
        return 2;
    }
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        if (strcmp(argv[optind], modes[i].name) == 0) {
            mode = &modes[i];
        }
    }
    if (mode == NULL) {
        usage();
        return 2;
    }
    if (cs_open(CS_ARCH_RISCV, RISCVLINT_CS_MODE, &cs) != CS_ERR_OK) {
        fprintf(stderr, "rwfuzz: cs_open failed\n");
        return 2;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    if (!exec_open()) {
        return 2;
    }

    long tested = 0, mismatches = 0, unapplied = 0, entries = 0;
    long controls = 0, control_diffs = 0;
    long per_title[TITLES_MAX] = { 0 };
    for (long it = 0; it < programs; it++) {
        alarm(10);
        build(mode->plant);
        run_original();
        if (mode->control == NULL) {
            mismatches += self_check();
            tested++;
            continue;
        }
        analyze(&gen);
        bool flagged[SLOTS_MAX] = { false };
        for (int k = 0; k < nhits; k++) {
            const hit_t *h = &hits[k];
            edits_t ed;
            if (!advice(&gen, h, mode->titles[h->title], &ed)) {
                unapplied++;
                if (unapplied <= 5) {
                    printf("could not apply: %s: %s\n",
                           mode->titles[h->title], h->text);
                }
                continue;
            }
            // A transfer into the window past its first instruction would
            // arrive at an instruction the rewrite took away.
            bool entered = false;
            for (unsigned c = 1; c < h->count; c++) {
                entered |= targeted(&gen, h->slot + (int)c);
            }
            if (entered) {
                entries++;
                mismatches++;
                if (mismatches <= 5) {
                    char heading[256];
                    snprintf(heading, sizeof heading,
                             "SIDE ENTRY: %s: %s", mode->titles[h->title],
                             h->text);
                    dump(&gen, heading, h->slot,
                         h->slot + (int)h->count - 1);
                }
                continue;
            }
            for (int e = 0; e < ed.n; e++) {
                flagged[ed.e[e].at] = true;
            }
            apply(&gen, &ed, &alt);
            tested++;
            per_title[h->title]++;
            bool reserved = writes_gp_tp(&alt);
            int t = reserved ? -1 : differs(&alt);
            if (reserved || t >= 0) {
                mismatches++;
                if (mismatches <= 5) {
                    char heading[256];
                    snprintf(heading, sizeof heading, "MISMATCH: %s: %s%s",
                             mode->titles[h->title], h->text,
                             reserved ? " (writes gp or tp)" : "");
                    if (reserved) {
                        dump(&gen, heading, h->slot,
                             h->slot + (int)h->count - 1);
                        dump(&alt, "rewritten", -1, -1);
                    } else {
                        dump_mismatch(&alt, heading, h->slot,
                                      h->slot + (int)h->count - 1, t);
                    }
                }
            }
        }
        for (int i = gen.body; i < gen.epi; i++) {
            edits_t ed = { .n = 0 };
            if (flagged[i] || !mode->control(&gen, i, &ed)) {
                continue;
            }
            bool skip = false;
            for (int e = 0; e < ed.n; e++) {
                skip |= flagged[ed.e[e].at];
            }
            if (skip) {
                continue;
            }
            apply(&gen, &ed, &alt);
            controls++;
            control_diffs += writes_gp_tp(&alt) || differs(&alt) >= 0;
        }
    }
    alarm(0);

    if (mode->control == NULL) {
        printf("rwfuzz %s: %ld programs, %ld mismatches\n", mode->name,
               programs, mismatches);
        return mismatches != 0 ? 1 : 0;
    }
    printf("rwfuzz %s: %ld programs, %ld findings run, %ld mismatches "
           "(%ld side entries), %ld not applied\n", mode->name, programs,
           tested, mismatches, entries, unapplied);
    for (int i = 0; i < TITLES_MAX && mode->titles[i] != NULL; i++) {
        printf("  %8ld  %s\n", per_title[i], mode->titles[i]);
    }
    printf("  control: %ld refused rewrites applied anyway, %ld changed the "
           "result\n", controls, control_diffs);
    if (outside != 0) {
        printf("  %ld findings reached past the body and were not run\n",
               outside);
    }
    if (undecoded != 0) {
        printf("  %ld programs had bytes the scan could not decode\n",
               undecoded);
    }
    if (tested == 0) {
        fprintf(stderr, "rwfuzz: no finding was tested -- has the finding "
                "title or the check changed?\n");
        return 2;
    }
    return mismatches != 0 || unapplied != 0 ? 1 : 0;
}

#endif
