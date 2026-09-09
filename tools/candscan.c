// candscan: size candidate checks by counting the shapes they would fire
// on, with each candidate's real preconditions applied.
//
// pairscan ranks adjacent pairs by frequency and defuse profiles def-use
// distance; both answer "is there something here?". Neither answers "how
// many findings would this check actually report?", which is the question
// that decides what gets written next -- and the gap between the two has
// been an order of magnitude every time it was measured (see "What the
// measurements changed" in TODO.md). This tool closes that gap for one
// candidate at a time: it decodes operands, applies the register,
// immediate and encodability conditions the check would apply, and runs
// the same bounded liveness walk defuse uses where a fold needs one.
//
// Every probe here corresponds to a row in TODO.md, including the ones
// that came back empty. A candidate measured at zero is worth as much as
// one measured at a hundred thousand -- it is what stops the shape being
// re-derived from intuition later -- so the rejected probes stay in.
//
// Two things it reports that a fold count alone would misstate:
//
//   * the xbr split. A conditional branch between a def and its use
//     means the intermediate may escape on the taken path, which a walk
//     starting after the use cannot see. Sites carrying one are counted
//     apart rather than claimed.
//   * the ABI split. The liveness walk answers UNKNOWN at every call and
//     return because what a callee may read and what a return exposes
//     differ between the C and Go conventions. Some candidates live or
//     die on that answer, so each such probe is run twice, once with the
//     LP64D convention asserted, and both verdicts are reported. Where
//     the two agree the candidate is ABI-independent; where the ABI run
//     turns UNKNOWN into LIVE rather than DEAD, the candidate is not an
//     opportunity at all and no ABI flag would rescue it.
//
// Output is one row per key: a count plus the def-use distance
// histogram, sorted by count. `-e SUBSTR` prints the disassembled site
// behind each finding whose key matches, which is how these counts were
// checked against the code rather than trusted.
//
// Usage: candscan [-e SUBSTR -n MAX] <binary>...

#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// === Minimal ELF64 definitions (mirrors tools/pairscan.c) ===


#define EI_NIDENT     16
#define EI_CLASS      4
#define ELFMAG        "\x7f""ELF"
#define SELFMAG       4
#define ELFCLASS64    2
#define EM_RISCV      243
#define SHT_PROGBITS  1
#define SHF_EXECINSTR 0x4

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

#define RV_MODE (CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD |    \
                 CS_MODE_RISCV_A | CS_MODE_RISCV_V |                       \
                 CS_MODE_RISCV_ZBA |                                       \
                 CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC |                   \
                 CS_MODE_RISCV_ZBS | CS_MODE_RISCV_ZBKB |                  \
                 CS_MODE_RISCV_ZBKC | CS_MODE_RISCV_ZBKX)

#define NSLOT 96  // 1-31 GPR, 32+ FP, 64+ vector

static const char *example_cat = NULL;
static long example_max = 20, example_printed = 0;
static uint64_t total_insns = 0, total_undecodable = 0;

typedef struct {
    uint64_t c[6];  // distance buckets 1,2,3,4-7,8-15,16+
} hist;

static int bucket(long d)
{
    return d <= 1 ? 0 : d == 2 ? 1 : d == 3 ? 2 : d <= 7 ? 3 : d <= 15 ? 4 : 5;
}

// key -> histogram, tiny open hash
typedef struct { char *key; hist h; uint64_t n; } entry;
#define HB 16
#define HS (1u << HB)
static entry table[HS];

static void bump(const char *key, long dist)
{
    uint32_t h = 5381;
    for (const char *s = key; *s; s++) h = h * 33 + (uint8_t)*s;
    h &= HS - 1;
    for (;;) {
        if (!table[h].key) { table[h].key = strdup(key); break; }
        if (!strcmp(table[h].key, key)) break;
        h = (h + 1) & (HS - 1);
    }
    table[h].n++;
    if (dist >= 0) table[h].h.c[bucket(dist)]++;
}

// x0 is -1: it reads as zero and discards writes, carrying no dependency.
static int reg_slot(unsigned r)
{
    if (r >= RISCV_REG_X0 && r <= RISCV_REG_X31) {
        int n = (int)(r - RISCV_REG_X0);
        return n == 0 ? -1 : n;
    }
    if (r >= RISCV_REG_F0_D && r <= RISCV_REG_F31_D)
        return 32 + (int)(r - RISCV_REG_F0_D);
    if (r >= RISCV_REG_F0_F && r <= RISCV_REG_F31_F)
        return 32 + (int)(r - RISCV_REG_F0_F);
    if (r >= RISCV_REG_F0_H && r <= RISCV_REG_F31_H)
        return 32 + (int)(r - RISCV_REG_F0_H);
    if (r >= RISCV_REG_V0 && r <= RISCV_REG_V31)
        return 64 + (int)(r - RISCV_REG_V0);
    return -1;
}

static bool has_group(const cs_insn *insn, unsigned g)
{
    for (int i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == g) return true;
    return false;
}

static bool mn_in(const char *m, const char *const *set)
{
    for (int i = 0; set[i]; i++)
        if (strcmp(m, set[i]) == 0) return true;
    return false;
}

// The second capstone handle the liveness walks disassemble through,
// so a walk never disturbs the iterator driving the main scan.
static csh probe_handle;

static bool is_cond_branch(const cs_insn *insn)
{
    return insn->mnemonic[0] == 'b' &&
           has_group(insn, RISCV_GRP_BRANCH_RELATIVE);
}

// Any jal/jalr links into a register and ends the region. The group is
// not enough: capstone marks `jalr ra, 86(ra)` -- the ordinary PLT call
// sequence, and by far the most common call in the corpus -- as JUMP
// rather than CALL, and marks `jal <imm>` as neither. Missing those
// leaves argument setup tracked across the call, where the callee's
// clobbers make it look like a dead definition and its memory writes
// make a reload look redundant. The rd == x0 spellings print as `j` and
// `jr`, so any surviving jal/jalr mnemonic links.
static bool is_call(const cs_insn *insn)
{
    return has_group(insn, RISCV_GRP_CALL) ||
           strcmp(insn->mnemonic, "jal") == 0 ||
           strcmp(insn->mnemonic, "jalr") == 0;
}

static bool uncond_transfer(const cs_insn *insn)
{
    const char *m = insn->mnemonic;
    return strcmp(m, "j") == 0 || strcmp(m, "jr") == 0 ||
           strcmp(m, "ret") == 0 || strcmp(m, "mret") == 0 ||
           strcmp(m, "sret") == 0 || strcmp(m, "uret") == 0;
}

// capstone leaves the ra-implicit link aliases writing nothing and `ret`
// reading nothing; without the fix a reloaded ra looks like a dead def.
static void fix_implicit_ra(const cs_insn *insn, cs_regs rr, uint8_t *nr,
                            cs_regs rw, uint8_t *nw)
{
    const char *m = insn->mnemonic;
    if ((strcmp(m, "jal") == 0 || strcmp(m, "jalr") == 0) && *nw == 0)
        rw[(*nw)++] = RISCV_REG_X1;
    else if (strcmp(m, "ret") == 0 && *nr == 0)
        rr[(*nr)++] = RISCV_REG_X1;
}

// Branch-target bitset, one bit per 2-byte unit (see pairscan.c).
static uint8_t *mark_branch_targets(csh handle, const uint8_t *code,
                                    size_t size, uint64_t vaddr)
{
    uint8_t *bits = calloc(size / 2 / 8 + 1, 1);
    if (!bits) return NULL;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) { free(bits); return NULL; }
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
                bits[(size_t)t / 2 / 8] |= (uint8_t)(1u << ((size_t)t / 2 % 8));
        }
    }
    cs_free(insn, 1);
    return bits;
}

// ---- bounded liveness, for the compare-then-branch category ----
//
// Folding `slt rd,a,b` + `bnez rd,L` into `blt a,b,L` only removes an
// instruction if rd is dead on every path leaving the branch. defuse
// scans linearly and cannot see the taken path, so this walks it: a
// bounded breadth-first search from both successors, answering DEAD only
// when every path redefines rd (or discards it) before reading it.
//
// Everything ambiguous answers UNKNOWN rather than guessing: an
// exhausted budget, an indirect jump, a branch out of the section, or a
// call that might read rd as an argument. UNKNOWN is counted separately
// from LIVE so the split between "provably not foldable" and "not
// provable either way" stays visible.

enum { LIVE_DEAD, LIVE_READ, LIVE_UNKNOWN };

#define LIVE_BUDGET 96   // instructions examined per query
#define LIVE_PATHS  16   // distinct path starts before giving up

// Absolute target of a relative branch/jump, or 0 if it has none.
static uint64_t branch_target(const cs_insn *insn)
{
    const cs_riscv *a = &insn->detail->riscv;
    for (int i = 0; i < a->op_count; i++)
        if (a->operands[i].type == RISCV_OP_IMM)
            return (uint64_t)a->operands[i].imm;
    return 0;
}

static int liveness(csh handle, cs_insn *probe, const uint8_t *code,
                    size_t size, uint64_t vaddr, const uint64_t *starts,
                    int nstarts, int slot)
{
    uint64_t queue[LIVE_PATHS], seen[LIVE_PATHS];
    int nq = 0, nseen = 0, budget = LIVE_BUDGET;
    for (int i = 0; i < nstarts && nq < LIVE_PATHS; i++)
        queue[nq++] = starts[i];

    while (nq > 0) {
        uint64_t addr = queue[--nq];
        bool dup = false;
        for (int i = 0; i < nseen; i++)
            if (seen[i] == addr) dup = true;
        if (dup) continue;
        if (nseen >= LIVE_PATHS) return LIVE_UNKNOWN;
        seen[nseen++] = addr;
        if (addr < vaddr || addr >= vaddr + size) return LIVE_UNKNOWN;

        const uint8_t *p = code + (addr - vaddr);
        size_t remain = size - (size_t)(addr - vaddr);
        uint64_t a = addr;
        for (;;) {
            if (budget-- <= 0) return LIVE_UNKNOWN;
            if (remain < 2 ||
                !cs_disasm_iter(handle, &p, &remain, &a, probe))
                return LIVE_UNKNOWN;

            cs_regs rr, rw; uint8_t nr = 0, nw = 0;
            cs_regs_access(handle, probe, rr, &nr, rw, &nw);
            fix_implicit_ra(probe, rr, &nr, rw, &nw);
            for (int i = 0; i < nr; i++)
                if (reg_slot(rr[i]) == slot) return LIVE_READ;
            bool written = false;
            for (int i = 0; i < nw; i++)
                if (reg_slot(rw[i]) == slot) written = true;
            if (written) break;          // redefined before any read

            const char *m = probe->mnemonic;
            if (is_call(probe)) {
                // No shortcut for the caller-saved temporaries: that a
                // callee cannot read t0-t6 holds for the C ABI, not for
                // every ABI, and Go passes arguments in t0/t1.
                return LIVE_UNKNOWN;
            }
            if (!strcmp(m, "ret")) {
                // Which registers a return exposes is ABI-specific --
                // a0/a1 under the C ABI, a0-a7 under Go's -- so the walk
                // declines rather than guessing.
                return LIVE_UNKNOWN;
            }
            if (is_cond_branch(probe)) {
                uint64_t t = branch_target(probe);
                if (!t) return LIVE_UNKNOWN;
                if (nq >= LIVE_PATHS) return LIVE_UNKNOWN;
                queue[nq++] = t;
                continue;                        // and fall through
            }
            if (uncond_transfer(probe)) {
                uint64_t t = branch_target(probe);
                if (!t) return LIVE_UNKNOWN;     // jr/ret-like: indirect
                if (nq >= LIVE_PATHS) return LIVE_UNKNOWN;
                queue[nq++] = t;
                break;
            }
        }
    }
    return LIVE_DEAD;
}

static int load_size(const char *m)
{
    if (!strcmp(m, "lb") || !strcmp(m, "lbu")) return 1;
    if (!strcmp(m, "lh") || !strcmp(m, "lhu")) return 2;
    if (!strcmp(m, "lw") || !strcmp(m, "lwu")) return 4;
    if (!strcmp(m, "ld")) return 8;
    return 0;
}
// ---- per-region tracking ----
//
// One record per register: what wrote it, from which sources, how many
// instructions ago, and how many reads it has had since. `cgen` is a
// per-register generation counter, so a probe can ask whether a def's
// *sources* are still intact -- folding `addi rd,rs,i1` into a later
// consumer is only legal if nothing redefined rs in between, and a
// liveness query on rd cannot answer that.

typedef struct {
    bool live;
    char mn[32];   // long enough for the vector mnemonics
    long idx;
    uint64_t addr;
    int rs1, rs2;
    unsigned g1, g2;
    int64_t imm;
    bool has_imm;
    int uses;
    int nwrite;
    bool xbr;       // a conditional branch sits between the def and here
} cdr;

static cdr cd[NSLOT];
static unsigned cgen[NSLOT];

// region-local address materializations: auipc(+addi) results
typedef struct { uint64_t val; int slot; unsigned gen; bool page; } amat;
static amat amats[64];
static int namats;

// ---- a frame slot stored twice with nothing reading it between ----
//
// The store analogue of the dead-definition check, and it shares the
// windowed memory table the TODO already wants for redundant reloads.
// Only frame-relative slots (sp/fp base) are considered: a heap address
// may alias anything, and nothing in the encoding says it does not. Any
// call, fence, or write to the base register ends the window, as does a
// load from the same slot.
typedef struct { bool live; int base; int64_t disp; int sz; long idx;
                 uint64_t adr; } strec;
static strec stores[48];
static int nstores;

static void creset(void)
{
    memset(cd, 0, sizeof cd);
    namats = 0;
    nstores = 0;
}

static int op_reg(const cs_insn *in, int i)
{
    const cs_riscv *a = &in->detail->riscv;
    if (i >= a->op_count || a->operands[i].type != RISCV_OP_REG) return -2;
    return reg_slot(a->operands[i].reg);
}

static bool op_imm(const cs_insn *in, int i, int64_t *v)
{
    const cs_riscv *a = &in->detail->riscv;
    if (i >= a->op_count || a->operands[i].type != RISCV_OP_IMM) return false;
    *v = a->operands[i].imm;
    return true;
}

// Producer classes for the redundant-extension probe. A producer
// "guarantees" an extension when its result already has the bit pattern
// the extension would produce, so the extension is a no-op.
static const char *const G_SEXTW[] = {
    "lw", "lb", "lh", "lbu", "lhu", "addw", "subw", "mulw", "divw", "divuw",
    "remw", "remuw", "addiw", "sllw", "srlw", "sraw", "slliw", "srliw",
    "sraiw", "negw", "sext.w", "sext.b", "sext.h", "zext.h", "zext.b",
    "lui", "li", NULL};
static const char *const G_ZEXTW[] = {
    "lwu", "zext.w", "zext.h", "zext.b", "lbu", "lhu", NULL};
static const char *const G_ZEXTH[] = {
    "lhu", "zext.h", "zext.b", "lbu", NULL};
static const char *const G_SEXTB[] = {"lb", "sext.b", NULL};
static const char *const G_SEXTH[] = {"lh", "sext.h", "sext.b", "lb", NULL};
static const char *const G_ZEXTB[] = {"lbu", "zext.b", NULL};

// Instructions whose sole effect is writing one GPR, so that redirecting
// that write to another register is a legal rewrite.
static const char *const PURE_DEF[] = {
    "ld", "lw", "lwu", "lh", "lhu", "lb", "lbu",
    "addi", "add", "sub", "and", "or", "xor", "andi", "ori", "xori",
    "sll", "srl", "sra", "slli", "srli", "srai", "addiw", "addw", "subw",
    "sllw", "srlw", "sraw", "slliw", "srliw", "sraiw",
    "mul", "mulw", "mulh", "mulhu", "div", "divu", "divw", "divuw",
    "rem", "remu", "remw", "remuw",
    "sext.w", "sext.b", "sext.h", "zext.w", "zext.h", "zext.b",
    "sh1add", "sh2add", "sh3add", "sh1add.uw", "sh2add.uw", "sh3add.uw",
    "add.uw", "slli.uw", "li", "lui", "auipc", "mv",
    "czero.eqz", "czero.nez", "min", "max", "minu", "maxu",
    "slt", "sltu", "slti", "sltiu", "seqz", "snez", "neg", "not",
    "andn", "orn", "xnor", "clz", "ctz", "cpop", "rev8", "orc.b",
    "bset", "bclr", "binv", "bext", "bseti", "bclri", "binvi", "bexti",
    "rol", "ror", "rori", "rolw", "rorw", "roriw", NULL};


// ---- the same walk, told the LP64D C ABI ----
//
// The ABI-agnostic walk answers UNKNOWN at every call and every return,
// because what a callee may read and what a return exposes differ
// between the C and Go conventions. That is the right default for a
// corpus holding both. But a riscv64 object that carries
// .riscv.attributes was built by a C toolchain -- Go emits none -- so
// the convention can be asserted rather than guessed. This measures what
// asserting it would buy.
static bool abi_caller_saved(int s)
{
    return s == 1 || (s >= 5 && s <= 7) || (s >= 10 && s <= 17) ||
           (s >= 28 && s <= 31);          // ra, t0-t2, a0-a7, t3-t6
}
static bool abi_arg_reg(int s) { return s >= 10 && s <= 17; }   // a0-a7
static bool abi_ret_reg(int s) { return s == 10 || s == 11; }   // a0, a1

static int liveness_abi(csh handle, cs_insn *probe, const uint8_t *code,
                        size_t size, uint64_t vaddr, const uint64_t *starts,
                        int nstarts, int slot)
{
    uint64_t queue[LIVE_PATHS], seen[LIVE_PATHS];
    int nq = 0, nseen = 0, budget = LIVE_BUDGET;
    for (int i = 0; i < nstarts && nq < LIVE_PATHS; i++) queue[nq++] = starts[i];

    while (nq > 0) {
        uint64_t addr = queue[--nq];
        bool dup = false;
        for (int i = 0; i < nseen; i++) if (seen[i] == addr) dup = true;
        if (dup) continue;
        if (nseen >= LIVE_PATHS) return LIVE_UNKNOWN;
        seen[nseen++] = addr;
        if (addr < vaddr || addr >= vaddr + size) return LIVE_UNKNOWN;

        const uint8_t *p = code + (addr - vaddr);
        size_t remain = size - (size_t)(addr - vaddr);
        uint64_t a = addr;
        for (;;) {
            if (budget-- <= 0) return LIVE_UNKNOWN;
            if (remain < 2 || !cs_disasm_iter(handle, &p, &remain, &a, probe))
                return LIVE_UNKNOWN;
            cs_regs rr, rw; uint8_t nr = 0, nw = 0;
            cs_regs_access(handle, probe, rr, &nr, rw, &nw);
            fix_implicit_ra(probe, rr, &nr, rw, &nw);
            for (int i = 0; i < nr; i++)
                if (reg_slot(rr[i]) == slot) return LIVE_READ;
            bool written = false;
            for (int i = 0; i < nw; i++)
                if (reg_slot(rw[i]) == slot) written = true;
            if (written) break;
            if (is_call(probe)) {
                if (abi_arg_reg(slot)) return LIVE_READ;   // may be an argument
                if (abi_caller_saved(slot)) break;         // clobbered: dead
                continue;                                  // callee-saved
            }
            if (!strcmp(probe->mnemonic, "ret"))
                return abi_ret_reg(slot) ? LIVE_READ : LIVE_DEAD;
            if (is_cond_branch(probe)) {
                uint64_t t = branch_target(probe);
                if (!t) return LIVE_UNKNOWN;
                if (nq >= LIVE_PATHS) return LIVE_UNKNOWN;
                queue[nq++] = t;
                continue;
            }
            if (uncond_transfer(probe)) {
                uint64_t t = branch_target(probe);
                if (!t) return LIVE_UNKNOWN;
                if (nq >= LIVE_PATHS) return LIVE_UNKNOWN;
                queue[nq++] = t;
                break;
            }
        }
    }
    return LIVE_DEAD;
}


// ---- frame-pointer teardown over a static frame ----
//
// Region discipline cannot see this one: the fp is set in the prologue
// and read in the epilogue, with every call and branch of the function
// in between. What makes `addi sp,fp,-K` removable is not locality but
// that the frame is static -- sp is written only by `addi sp,sp,imm`
// anywhere in the function, so no alloca or VLA moved it. Tracked
// linearly across the whole function, which for a contiguous function
// covers a superset of every path between the two.
static int fp_k;              // K from `addi s0,sp,K`, or INT_MIN when idle
static bool fp_dirty;         // sp written by something other than addi imm
static uint64_t fp_setup_addr;
#define FP_IDLE (-100000)

static bool fits12(int64_t v) { return v >= -2048 && v <= 2047; }

static const char *verdict(int v)
{
    return v == LIVE_DEAD ? "fold" : v == LIVE_READ ? "live" : "unk";
}

// Print the site behind a finding when -e names its category, so the
// counts can be read against the actual code rather than trusted.
static const uint8_t *ex_code;
static size_t ex_size;
static uint64_t ex_vaddr;
static const char *ex_path;

static void show(const char *key, uint64_t from, uint64_t to)
{
    if (!example_cat || !strstr(key, example_cat)) return;
    if (example_printed++ >= example_max) return;
    printf("EX %s [%s]\n", key, ex_path);
    cs_insn *in = cs_malloc(probe_handle);
    if (!in) return;
    const uint8_t *p = ex_code + (from - ex_vaddr);
    size_t rem = ex_size - (size_t)(from - ex_vaddr);
    uint64_t a = from;
    while (a <= to && rem >= 2 && cs_disasm_iter(probe_handle, &p, &rem, &a, in))
        printf("   %#" PRIx64 ": %s %s\n", in->address, in->mnemonic,
               in->op_str);
    cs_free(in, 1);
}

static void scan_section(csh handle, const char *path, const uint8_t *code,
                         size_t size, uint64_t vaddr)
{
    ex_code = code; ex_size = size; ex_vaddr = vaddr; ex_path = path;
    fp_k = FP_IDLE; fp_dirty = true; nstores = 0;
    uint8_t *bits = mark_branch_targets(handle, code, size, vaddr);
    if (!bits) return;
    cs_insn *insn = cs_malloc(handle);
    cs_insn *probe = cs_malloc(probe_handle);
    if (!insn || !probe) { free(bits); return; }

    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;
    long idx = 0;
    creset();
    memset(cgen, 0, sizeof cgen);

    while (remain >= 2) {
        uint64_t here = addr;
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            p += 2; remain -= 2; addr += 2;
            total_undecodable++;
            creset();
            continue;
        }
        total_insns++;
        idx++;
        uint64_t off = here - vaddr;
        if (bits[off / 2 / 8] & (1u << (off / 2 % 8)))
            creset();                       // side entry: nothing carries in

        const char *m = insn->mnemonic;
        uint64_t next = addr;               // address after this instruction
        cs_regs rr, rw; uint8_t nr = 0, nw = 0;
        cs_regs_access(handle, insn, rr, &nr, rw, &nw);
        fix_implicit_ra(insn, rr, &nr, rw, &nw);

        int d0 = op_reg(insn, 0), s1 = op_reg(insn, 1), s2 = op_reg(insn, 2);
        int64_t i2 = 0, i1 = 0;
        bool hasi2 = op_imm(insn, 2, &i2), hasi1 = op_imm(insn, 1, &i1);

        // ---- an extension whose producer already guarantees it ----
        {
            const char *const *g = NULL;
            const char *tag = NULL;
            int src = s1;
            if (!strcmp(m, "sext.w")) { g = G_SEXTW; tag = "sext.w"; }
            else if (!strcmp(m, "zext.w")) { g = G_ZEXTW; tag = "zext.w"; }
            else if (!strcmp(m, "zext.h")) { g = G_ZEXTH; tag = "zext.h"; }
            else if (!strcmp(m, "sext.b")) { g = G_SEXTB; tag = "sext.b"; }
            else if (!strcmp(m, "sext.h")) { g = G_SEXTH; tag = "sext.h"; }
            else if (!strcmp(m, "zext.b")) { g = G_ZEXTB; tag = "zext.b"; }
            else if (!strcmp(m, "andi") && hasi2 && i2 == 255) {
                g = G_ZEXTB; tag = "zext.b(andi)";
            }
            if (g && src >= 0 && cd[src].live && mn_in(cd[src].mn, g)) {
                bool inplace = (d0 == src);
                char key[96];
                snprintf(key, sizeof key, "redext|%s|after %s|%s", tag,
                         cd[src].mn, inplace ? "delete" : "->mv");
                bump(key, idx - cd[src].idx);
                snprintf(key, sizeof key, "redext|BYTES|%s|%u",
                         inplace ? "delete" : "->mv", insn->size);
                bump(key, idx - cd[src].idx);
                snprintf(key, sizeof key, "redext|TOTAL|%s|%s",
                         inplace ? "delete" : "->mv",
                         cd[src].xbr ? "xbr" : "clean");
                bump(key, idx - cd[src].idx);
                show(key, cd[src].addr, here);
            }
        }

        // ---- addi + addi chain ----
        if ((!strcmp(m, "addi") || !strcmp(m, "mv")) && d0 >= 0 && s1 >= 0 &&
            cd[s1].live && cd[s1].uses == 0 &&
            (!strcmp(cd[s1].mn, "addi") || !strcmp(cd[s1].mn, "mv")) &&
            cd[s1].rs1 >= 0 && cd[s1].g1 == cgen[cd[s1].rs1]) {
            int64_t add2 = hasi2 ? i2 : 0;
            int64_t sum = cd[s1].imm + add2;
            const char *kind = strcmp(m, "mv") ? "addi" : "mv";
            char key[96];
            if (!fits12(sum)) {
                snprintf(key, sizeof key, "addichain|%s|sum does not fit "
                         "imm12", kind);
                bump(key, idx - cd[s1].idx);
            } else if (d0 == s1) {
                snprintf(key, sizeof key, "addichain|%s|writeback (free)|%s",
                         kind, cd[s1].xbr ? "xbr" : "clean");
                bump(key, idx - cd[s1].idx);
            } else {
                int v = liveness(probe_handle, probe, code, size, vaddr,
                                 &next, 1, s1);
                int va = liveness_abi(probe_handle, probe, code, size, vaddr,
                                      &next, 1, s1);
                // The dominant shape is the frame-pointer teardown
                // `addi s0,sp,N` ... `addi sp,s0,-N`, which folds to
                // `addi sp,sp,0` -- nothing at all. Count it apart: it is
                // one idiom rather than a general opportunity, and both
                // instructions go, not one.
                int root = cd[s1].rs1;
                const char *shape =
                    (d0 == 2 && root == 2) ? "sp restore from fp"
                    : (sum == 0 && d0 == root) ? "folds to a nop"
                    : (sum == 0) ? "folds to mv" : "folds to one addi";
                snprintf(key, sizeof key, "addichain|%s|third reg|%s|%s",
                         kind, verdict(v), cd[s1].xbr ? "xbr" : "clean");
                bump(key, idx - cd[s1].idx);
                if (v == LIVE_DEAD) {
                    snprintf(key, sizeof key, "addishape|%s|%s|%s", kind,
                             shape, cd[s1].xbr ? "xbr" : "clean");
                    bump(key, idx - cd[s1].idx);
                }
                show(key, cd[s1].addr, here);
                snprintf(key, sizeof key, "addichain|%s|third reg|ABI %s|%s",
                         kind, verdict(va), cd[s1].xbr ? "xbr" : "clean");
                bump(key, idx - cd[s1].idx);
            }
        }

        // ---- slli + srli/srai with equal shifts ----
        if ((!strcmp(m, "srli") || !strcmp(m, "srai")) && s1 >= 0 && hasi2 &&
            cd[s1].live && cd[s1].uses == 0 && !strcmp(cd[s1].mn, "slli") &&
            cd[s1].rs1 >= 0 && cd[s1].g1 == cgen[cd[s1].rs1]) {
            int64_t a = cd[s1].imm, b = i2;
            const char *rewrite = NULL;
            bool arith = !strcmp(m, "srai");
            if (a == b) {
                int keep = 64 - (int)a;
                if (!arith) {
                    if (keep == 32) rewrite = "zext.w (implemented)";
                    else if (keep == 16) rewrite = "zext.h [Zbb]";
                    else if (keep <= 11) rewrite = "andi [base ISA]";
                } else {
                    if (keep == 32) rewrite = "sext.w [base ISA]";
                    else if (keep == 16) rewrite = "sext.h [Zbb]";
                    else if (keep == 8) rewrite = "sext.b [Zbb]";
                }
            }
            char key[96];
            if (rewrite)
                snprintf(key, sizeof key, "shiftpair|%s|%s", rewrite,
                         d0 == s1 ? "in-place" : "third reg");
            else if (a == b)
                snprintf(key, sizeof key, "shiftpair|equal shift, no 1-insn "
                         "form|keep=%d", 64 - (int)a);
            else
                snprintf(key, sizeof key, "shiftpair|bitfield extract "
                         "(a!=b)|-");
            bump(key, idx - cd[s1].idx);
        }

        // ---- slli.uw / zext.w feeding an add: the Zba .uw forms ----
        if (!strcmp(m, "add") && d0 >= 0 && s1 >= 0 && s2 >= 0) {
            for (int which = 0; which < 2; which++) {
                int prod = which ? s2 : s1, other = which ? s1 : s2;
                if (prod < 0 || !cd[prod].live || cd[prod].uses != 0) continue;
                if (d0 != prod || other == prod) continue;
                if (cd[prod].rs1 < 0 || cd[prod].g1 != cgen[cd[prod].rs1])
                    continue;
                if (!strcmp(cd[prod].mn, "slli.uw") && cd[prod].imm >= 1 &&
                    cd[prod].imm <= 3) {
                    char key[64];
                    snprintf(key, sizeof key, "zba.uw|sh%dadd.uw [Zba]",
                             (int)cd[prod].imm);
                    bump(key, idx - cd[prod].idx);
                } else if (!strcmp(cd[prod].mn, "zext.w")) {
                    bump("zba.uw|add.uw [Zba]", idx - cd[prod].idx);
                }
            }
        }

        // ---- a producer immediately consumed by a move ----
        if (!strcmp(m, "mv") && d0 >= 0 && s1 >= 0 && cd[s1].live &&
            cd[s1].uses == 0 && cd[s1].idx == idx - 1 && d0 != s1 &&
            cd[s1].nwrite == 1 && mn_in(cd[s1].mn, PURE_DEF) &&
            strcmp(cd[s1].mn, "mv")) {
            int v = liveness(probe_handle, probe, code, size, vaddr,
                             &next, 1, s1);
            int va = liveness_abi(probe_handle, probe, code, size, vaddr,
                                  &next, 1, s1);
            char key[96];
            snprintf(key, sizeof key, "movecoal|%s", verdict(v));
            bump(key, 1);
            snprintf(key, sizeof key, "movecoal|ABI %s", verdict(va));
            bump(key, 1);
            if (v == LIVE_DEAD) {
                snprintf(key, sizeof key, "movecoal|fold|producer %s",
                         cd[s1].mn);
                bump(key, 1);
            } else if (v == LIVE_UNKNOWN) {
                // The walk stops at a call because a callee may read the
                // register as an argument -- true of no ABI in particular.
                // Split it out: under the C ABI these are folds.
                const uint8_t *q = code + (next - vaddr);
                size_t rem2 = size - (size_t)(next - vaddr);
                uint64_t a2 = next;
                bool call_next = rem2 >= 2 &&
                    cs_disasm_iter(probe_handle, &q, &rem2, &a2, probe) &&
                    is_call(probe);
                bump(call_next ? "movecoal|unk|blocked by the call after it"
                               : "movecoal|unk|other", 1);
            }
        }

        // ---- li feeding an op that has an immediate form ----
        {
            static const char *const COMM[] = {"add", "and", "or", "xor",
                                               NULL};
            static const char *const SND[] = {"sll", "srl", "sra", "slt",
                                              "sltu", "sub", NULL};
            bool comm = mn_in(m, COMM), snd = mn_in(m, SND);
            if ((comm || snd) && d0 >= 0 && s1 >= 0 && s2 >= 0) {
                for (int which = 0; which < 2; which++) {
                    if (which == 0 && !comm) continue;   // s1 side
                    int prod = which ? s2 : s1, other = which ? s1 : s2;
                    if (prod < 0 || other == prod) continue;
                    if (!cd[prod].live || cd[prod].uses != 0) continue;
                    if (strcmp(cd[prod].mn, "li")) continue;
                    int64_t c = cd[prod].imm;
                    bool ok = fits12(c);
                    if (!strcmp(m, "sub")) ok = fits12(-c);
                    if (!strcmp(m, "sll") || !strcmp(m, "srl") ||
                        !strcmp(m, "sra"))
                        ok = (c >= 0 && c <= 63);
                    if (!ok) { bump("liimm|constant does not fit", -1); continue; }
                    int v = (d0 == prod)
                        ? LIVE_DEAD
                        : liveness(probe_handle, probe, code, size, vaddr,
                                   &next, 1, prod);
                    char key[96];
                    snprintf(key, sizeof key, "liimm|%s|%s", m, verdict(v));
                    bump(key, idx - cd[prod].idx);
                    snprintf(key, sizeof key, "liimm|TOTAL|%s", verdict(v));
                    bump(key, idx - cd[prod].idx);
                    break;
                }
            }
        }


        // ---- not + logic: the Zbb andn/orn/xnor forms ----
        if ((!strcmp(m, "and") || !strcmp(m, "or") || !strcmp(m, "xor")) &&
            d0 >= 0 && s1 >= 0 && s2 >= 0) {
            for (int w = 0; w < 2; w++) {
                int prod = w ? s2 : s1, other = w ? s1 : s2;
                if (prod < 0 || other == prod) continue;
                if (!cd[prod].live || cd[prod].uses != 0) continue;
                if (strcmp(cd[prod].mn, "not")) continue;
                char key[96];
                snprintf(key, sizeof key, "zbblogic|%sn [Zbb]|%s",
                         !strcmp(m, "xor") ? "x" : m,
                         d0 == prod ? "writeback" : "third reg");
                bump(key, idx - cd[prod].idx);
                break;
            }
        }

        // ---- srli + andi 1: the Zbs bexti form ----
        if (!strcmp(m, "andi") && hasi2 && i2 == 1 && s1 >= 0 &&
            cd[s1].live && cd[s1].uses == 0 && cd[s1].has_imm &&
            (!strcmp(cd[s1].mn, "srli") || !strcmp(cd[s1].mn, "srliw")) &&
            cd[s1].rs1 >= 0 && cd[s1].g1 == cgen[cd[s1].rs1]) {
            bump("zbs|srli+andi 1 -> bexti [Zbs]", idx - cd[s1].idx);
        }

        // ---- li of a mask + and: a one-instruction extension ----
        if (!strcmp(m, "and") && d0 >= 0 && s1 >= 0 && s2 >= 0) {
            for (int w = 0; w < 2; w++) {
                int prod = w ? s2 : s1, other = w ? s1 : s2;
                if (prod < 0 || other == prod) continue;
                if (!cd[prod].live || cd[prod].uses != 0) continue;
                if (strcmp(cd[prod].mn, "li") && strcmp(cd[prod].mn, "lui"))
                    continue;
                int64_t c = cd[prod].imm;
                const char *rw = NULL;
                if (c == 0xffff) rw = "zext.h [Zbb]";
                else if (c == 0xffffffffLL) rw = "zext.w [Zba]";
                else if (c == 0xff) rw = "andi (base ISA)";
                if (!rw) continue;
                char key[96];
                snprintf(key, sizeof key, "maskconst|%s", rw);
                bump(key, idx - cd[prod].idx);
                break;
            }
        }

        // ---- 4-byte encodings a Zcb form would spell in 2 ----
        //
        // The whole C++/Rust corpus declares zcb1p0, so any of these is
        // two bytes the assembler left on the table. Zcb's register
        // fields are three bits: x8-x15 only.
        if (insn->size == 4) {
            bool r0 = d0 >= 8 && d0 <= 15;
            bool r2 = s2 >= 8 && s2 <= 15;
            const char *form = NULL;
            if (r0 && d0 == s1) {
                if (!strcmp(m, "zext.b")) form = "c.zext.b";
                else if (!strcmp(m, "sext.b")) form = "c.sext.b";
                else if (!strcmp(m, "zext.h")) form = "c.zext.h";
                else if (!strcmp(m, "sext.h")) form = "c.sext.h";
                else if (!strcmp(m, "zext.w")) form = "c.zext.w";
                else if (!strcmp(m, "not")) form = "c.not";
                else if (!strcmp(m, "andi") && hasi2 && i2 == 255)
                    form = "c.zext.b (andi rd,rd,255)";
                else if (!strcmp(m, "mul") && r2) form = "c.mul";
            }
            if (form) {
                char key[96];
                snprintf(key, sizeof key, "zcb|%s", form);
                bump(key, -1);
                bump("zcb|TOTAL", -1);
            }
            // c.lbu/c.lhu/c.lh/c.sb/c.sh: base and data both x8-x15, and a
            // displacement inside the two-bit (byte) or one-bit (half) field
            const cs_riscv *ra = &insn->detail->riscv;
            if (ra->op_count == 2 && ra->operands[1].type == RISCV_OP_MEM) {
                int base = reg_slot(ra->operands[1].mem.base);
                int64_t disp = ra->operands[1].mem.disp;
                bool ok = r0 && base >= 8 && base <= 15;
                const char *f2 = NULL;
                if (ok && !strcmp(m, "lbu") && disp >= 0 && disp <= 3)
                    f2 = "c.lbu";
                else if (ok && !strcmp(m, "lhu") && (disp == 0 || disp == 2))
                    f2 = "c.lhu";
                else if (ok && !strcmp(m, "lh") && (disp == 0 || disp == 2))
                    f2 = "c.lh";
                else if (ok && !strcmp(m, "sb") && disp >= 0 && disp <= 3)
                    f2 = "c.sb";
                else if (ok && !strcmp(m, "sh") && (disp == 0 || disp == 2))
                    f2 = "c.sh";
                if (f2) {
                    char key[96];
                    snprintf(key, sizeof key, "zcb|%s", f2);
                    bump(key, -1);
                    bump("zcb|TOTAL", -1);
                }
            }
        }

        // ---- two shifts of one source ORed together: Zbb rori ----
        if (!strcmp(m, "or") && d0 >= 0 && s1 >= 0 && s2 >= 0 && s1 != s2 &&
            cd[s1].live && cd[s2].live && cd[s1].uses == 0 &&
            cd[s2].uses == 0 && cd[s1].has_imm && cd[s2].has_imm &&
            cd[s1].rs1 >= 0 && cd[s1].rs1 == cd[s2].rs1 &&
            cd[s1].g1 == cgen[cd[s1].rs1] && cd[s2].g1 == cgen[cd[s2].rs1]) {
            bool a_l = !strcmp(cd[s1].mn, "slli"), a_r = !strcmp(cd[s1].mn, "srli");
            bool b_l = !strcmp(cd[s2].mn, "slli"), b_r = !strcmp(cd[s2].mn, "srli");
            if ((a_l && b_r) || (a_r && b_l)) {
                if (cd[s1].imm + cd[s2].imm == 64)
                    bump("rotate|slli+srli+or -> rori [Zbb]", -1);
                else
                    bump("rotate|shift pair ORed, not a rotation", -1);
            }
        }

        // ---- a frame slot stored twice with nothing reading it between ----
        {
            const cs_riscv *ra = &insn->detail->riscv;
            int msz = 0;
            if (!strcmp(m, "sd")) msz = 8;
            else if (!strcmp(m, "sw")) msz = 4;
            else if (!strcmp(m, "sh")) msz = 2;
            else if (!strcmp(m, "sb")) msz = 1;
            int lsz = load_size(m);
            int mbase = -1; int64_t mdisp = 0;
            for (int i = 0; i < ra->op_count; i++)
                if (ra->operands[i].type == RISCV_OP_MEM) {
                    mbase = reg_slot(ra->operands[i].mem.base);
                    mdisp = ra->operands[i].mem.disp;
                }
            if (msz && (mbase == 2 || mbase == 8)) {
                for (int i = 0; i < nstores; i++)
                    if (stores[i].live && stores[i].base == mbase &&
                        stores[i].disp == mdisp && stores[i].sz == msz) {
                        char key[64];
                        snprintf(key, sizeof key, "deadstore|%s|sz%d",
                                 mbase == 2 ? "sp" : "fp", msz);
                        bump(key, idx - stores[i].idx);
                        bump("deadstore|TOTAL", idx - stores[i].idx);
                        stores[i].live = false;
                        break;
                    }
                if (nstores < 48)
                    stores[nstores++] = (strec){true, mbase, mdisp, msz, idx,
                                                here};
            } else if (lsz || msz) {
                // a load from the slot keeps the earlier store alive; a
                // store through any other base may alias it
                for (int i = 0; i < nstores; i++)
                    if (stores[i].live &&
                        (mbase < 0 || (stores[i].base == mbase &&
                                       stores[i].disp == mdisp) ||
                         (mbase != 2 && mbase != 8)))
                        stores[i].live = false;
            }
            if (is_call(insn)) nstores = 0;
        }

        // ---- frame pointer set from sp, later used to restore it ----
        {
            bool wr_sp = false, wr_fp = false;
            for (int i = 0; i < nw; i++) {
                int t = reg_slot(rw[i]);
                if (t == 2) wr_sp = true;
                if (t == 8) wr_fp = true;         // x8 == s0/fp
            }
            bool is_setup = !strcmp(m, "addi") && d0 == 8 && s1 == 2 && hasi2;
            bool is_teardown = !strcmp(m, "addi") && d0 == 2 && s1 == 8 &&
                               hasi2 && fp_k != FP_IDLE && i2 == -fp_k;
            if (is_teardown && !fp_dirty) {
                bump("fpteardown|sp restore over a static frame", -1);
                { char k2[64];
                  snprintf(k2, sizeof k2, "fpteardown|BYTES|%u", insn->size);
                  bump(k2, -1); }
                show("fpteardown", fp_setup_addr, here);
            } else if (is_teardown) {
                bump("fpteardown|frame moved (alloca/VLA): forced", -1);
            }
            // Strict: any write to sp between the two disqualifies the
            // site, including the balanced `addi sp,sp,imm` pair a body
            // may use, because a linear scan cannot prove a branch did
            // not skip one half of it. `ret` clears the flag, so a
            // second exit path is judged from the same static frame the
            // first one was rather than from the first one's epilogue.
            if (wr_sp && !is_teardown) fp_dirty = true;
            if (!strcmp(m, "ret")) fp_dirty = false;
            if (is_setup) { fp_k = (int)i2; fp_dirty = false;
                            fp_setup_addr = here; }
            else if (wr_fp) fp_k = FP_IDLE;
        }

        // ---- address re-materialization (auipc / auipc+addi) ----
        //
        // capstone hands back auipc's raw imm20 field rather than the
        // sign-extended addend, so the page is decoded from the word.
        bool new_page = false;
        uint64_t page_val = 0;
        if (!strcmp(m, "auipc") && d0 >= 0 && off + 4 <= size) {
            uint32_t w;
            memcpy(&w, code + off, 4);
            page_val = here + (uint64_t)(int64_t)(int32_t)(w & 0xfffff000u);
            new_page = true;
            for (int i = 0; i < namats; i++)
                if (amats[i].page && amats[i].val == page_val &&
                    amats[i].slot >= 0 &&
                    cgen[amats[i].slot] == amats[i].gen) {
                    bump("addrcse|auipc: page already in a live register", -1);
                    break;
                }
        }
        // auipc + addi is the full symbol address; a repeat of the same
        // one is 8 bytes that a 2-byte mv would replace.
        bool new_addr = false;
        uint64_t addr_val = 0;
        if (!strcmp(m, "addi") && d0 >= 0 && s1 == d0 && hasi2 &&
            cd[s1].live && !strcmp(cd[s1].mn, "auipc") &&
            cd[s1].idx == idx - 1 && cd[s1].has_imm) {
            addr_val = (uint64_t)cd[s1].imm + (uint64_t)i2;
            new_addr = true;
            for (int i = 0; i < namats; i++)
                if (!amats[i].page && amats[i].val == addr_val &&
                    amats[i].slot >= 0 &&
                    cgen[amats[i].slot] == amats[i].gen) {
                    bump("addrcse|auipc+addi: same address materialized "
                         "again", -1);
                    break;
                }
        }

        // ---- bookkeeping ----
        for (int i = 0; i < nr; i++) {
            int s = reg_slot(rr[i]);
            if (s >= 0 && cd[s].live) cd[s].uses++;
        }
        bool isc = is_call(insn);
        for (int i = 0; i < nw; i++) {
            int s = reg_slot(rw[i]);
            if (s < 0) continue;
            cgen[s]++;
            memset(&cd[s], 0, sizeof cd[s]);
            for (int j = 0; j < namats; j++)
                if (amats[j].slot == s) amats[j].slot = -1;
            if (isc) continue;
            cd[s].live = true;
            snprintf(cd[s].mn, sizeof cd[s].mn, "%s", m);
            cd[s].idx = idx;
            cd[s].addr = here;
            cd[s].nwrite = nw;
            cd[s].rs1 = s1 >= 0 ? s1 : -1;
            cd[s].rs2 = s2 >= 0 ? s2 : -1;
            cd[s].g1 = cd[s].rs1 >= 0 ? cgen[cd[s].rs1] : 0;
            cd[s].g2 = cd[s].rs2 >= 0 ? cgen[cd[s].rs2] : 0;
            if (!strcmp(m, "auipc")) {
                cd[s].has_imm = new_page;
                cd[s].imm = (int64_t)page_val;
                cd[s].rs1 = -1;
            } else if (!strcmp(m, "li") || !strcmp(m, "lui")) {
                cd[s].has_imm = hasi1;
                cd[s].imm = i1;
                cd[s].rs1 = -1;
            } else if (hasi2) {
                cd[s].has_imm = true;
                cd[s].imm = i2;
            } else if (!strcmp(m, "mv")) {
                cd[s].has_imm = true;
                cd[s].imm = 0;
            }
        }
        if (new_page && namats < 64 && d0 >= 0) {
            amats[namats++] = (amat){page_val, d0, cgen[d0], true};
        } else if (new_addr && namats < 64 && d0 >= 0) {
            amats[namats++] = (amat){addr_val, d0, cgen[d0], false};
        }
        if (is_cond_branch(insn))
            for (int i = 0; i < NSLOT; i++) cd[i].xbr = true;
        if (isc || uncond_transfer(insn)) creset();
    }
    cs_free(insn, 1);
    cs_free(probe, 1);
    free(bits);
}
static int scan_elf(csh handle, const char *path, const uint8_t *base,
                    size_t map_len)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (map_len < sizeof *eh || eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_machine != EM_RISCV) {
        fprintf(stderr, "%s: not a RISC-V ELF64\n", path);
        return -1;
    }
    if (eh->e_shoff > map_len ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > map_len - eh->e_shoff) {
        fprintf(stderr, "%s: section headers out of bounds\n", path);
        return -1;
    }
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_EXECINSTR) == 0 ||
            sh[i].sh_type != SHT_PROGBITS || sh[i].sh_size == 0)
            continue;
        if (sh[i].sh_offset > map_len ||
            sh[i].sh_size > map_len - sh[i].sh_offset)
            continue;
        scan_section(handle, path, base + sh[i].sh_offset, sh[i].sh_size,
                     sh[i].sh_addr);
    }
    return 0;
}

static int scan_file(csh handle, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4) {
        fprintf(stderr, "%s: not a readable binary\n", path);
        close(fd);
        return -1;
    }
    size_t map_len = (size_t)st.st_size;
    uint8_t *base = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror(path); return -1; }
    int rc;
    if (memcmp(base, ELFMAG, SELFMAG) == 0) {
        rc = scan_elf(handle, path, base, map_len);
    } else {
        fprintf(stderr, "%s: unsupported file format\n", path);
        rc = -1;
    }
    munmap(base, map_len);
    return rc;
}
static int cmp_entry(const void *a, const void *b)
{
    const entry *ea = a, *eb = b;
    if (eb->n != ea->n) return eb->n > ea->n ? 1 : -1;
    return strcmp(ea->key, eb->key);
}

int main(int argc, char **argv)
{
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example_cat = argv[++argi];
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            example_max = atol(argv[++argi]);
        } else {
            fprintf(stderr, "usage: %s [-e SUBSTR -n MAX] <binary>...\n",
                    argv[0]);
            return 2;
        }
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-e SUBSTR -n MAX] <binary>...\n", argv[0]);
        return 2;
    }
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RV_MODE, &handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (cs_open(CS_ARCH_RISCV, RV_MODE, &probe_handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(probe_handle, CS_OPT_DETAIL, CS_OPT_ON);
    for (; argi < argc; argi++)
        scan_file(handle, argv[argi]);
    cs_close(&handle);
    cs_close(&probe_handle);

    size_t n = 0;
    for (size_t i = 0; i < HS; i++)
        if (table[i].key) n++;
    entry *flat = malloc(n * sizeof *flat);
    if (!flat) { fprintf(stderr, "out of memory\n"); return 2; }
    size_t k = 0;
    for (size_t i = 0; i < HS; i++)
        if (table[i].key) flat[k++] = table[i];
    qsort(flat, n, sizeof *flat, cmp_entry);
    fprintf(stderr, "TOTAL insns=%" PRIu64 " undecodable=%" PRIu64
            " keys=%zu\n", total_insns, total_undecodable, n);
    printf("%-44s %10s  %7s %7s %7s %7s %7s %7s\n", "key", "n",
           "d=1", "d=2", "d=3", "d4-7", "d8-15", "d16+");
    for (size_t i = 0; i < n; i++)
        printf("%-44s %10" PRIu64 "  %7" PRIu64 " %7" PRIu64 " %7" PRIu64
               " %7" PRIu64 " %7" PRIu64 " %7" PRIu64 "\n",
               flat[i].key, flat[i].n, flat[i].h.c[0], flat[i].h.c[1],
               flat[i].h.c[2], flat[i].h.c[3], flat[i].h.c[4], flat[i].h.c[5]);
    free(flat);
    return 0;
}
