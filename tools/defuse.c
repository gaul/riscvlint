// defuse: block-local def->use distance profiler for RISC-V code in ELF
// binaries.
//
// Answers "does riscvlint need deeper-than-adjacent analysis?" with
// numbers: for several def patterns, how far away is the sole consumer,
// and how many multi-instruction-only redundancies (dead defs, redundant
// reloads, re-materialized constants, computed conditions that a compare
// branch could have folded) exist that no pair check can see.
//
// Ported from armlint's tools/defuse.c. Two structural changes beyond the
// instruction set. First, RISC-V mixes 2- and 4-byte encodings, so the
// branch-target bitset is 2-byte granular and filled by a capstone
// pre-pass instead of hand-decoded branch immediates. Second, RISC-V has
// no condition flags, so the original's "cmp #0 after a flag-capable ALU
// op" category has no meaning. Its place is taken by `br`, which is the
// same idea in flagless form: a condition materialized into a GPR by
// slt/xor/sub and then tested with beqz/bnez, where one compare-branch
// would have done both.
//
// Region discipline (mirrors armlint): tracking fully resets at branch
// targets (side entries), calls (jal/jalr), unconditional transfers, and
// undecodable halfwords. Conditional branches do NOT reset; defs whose
// use lies beyond one are tagged "xbr" (would need path reasoning).
//
// Def patterns profiled (sole-use only, def and use both in-region):
//   ext   : sext.w/sext.b/sext.h/zext.h/zext.w rd, rs -> consumer class
//   load  : lb/lbu/lh/lhu/lw/lwu rd, [..]             -> consumer class
//   mov   : mv rd, rs                                 -> any consumer
// Multi-instruction-only categories:
//   dead  : pure ALU/mv/li def overwritten with zero uses
//   reload: same (base,disp,size) loaded again, no store/call/fence/redef
//   remat : li/lui of a value already live in another register, split by
//           whether the duplicate already fits c.li (no size win) or not
//   br    : beqz/bnez on a value produced by slt/sltu/xor/sub/seqz/snez,
//           which a blt/bgeu/beq/bne would have computed and branched on,
//           split by whether the condition register is provably dead on
//           both successors (fold), provably read (live), or neither (unk)
//
// Usage: defuse [-e CAT -n MAX] <binary>...
//        (CAT: ext load mov dead reload remat br)

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

// ---- per-region state ----

typedef struct {
    bool live;          // def being tracked
    long idx;           // instruction index of def
    uint64_t adr;
    char text[192];
    int uses;           // uses seen since def
    long first_use_idx; // index of first (and, if uses==1, sole) use
    char first_use_cls[24];
    bool xbr;           // a conditional branch sits between def and now
    char kind;          // 'e' ext, 'l' load, 'm' mov, 'a' alu, 0
    char detail[40];    // mnemonic
    bool pure;          // no side effects: candidate for dead-def counting
} defrec;

typedef struct {
    bool live;
    long idx;
    int base;           // slot
    int64_t disp;
    int size;           // access bytes
    char mn[12];        // exact mnemonic: lb and lbu are the same width
                        // but not the same value, so a reload of one
                        // after the other is not redundant
    int dest;           // slot loaded into
} loadrec;

typedef struct {
    bool live;
    long idx;
    int64_t val;
    int slot;
} constrec;

static defrec defs[NSLOT];
static loadrec loads[64];
static int nloads;
static constrec consts[48];
static int nconsts;
// Slot holding a materialized condition, and how it was produced. The
// flagless stand-in for armlint's flags_def_slot.
static csh probe_handle;
static int cond_slot = -1;
static long cond_idx = -1;
static char cond_mn[32];

static void region_reset(void)
{
    memset(defs, 0, sizeof defs);
    nloads = 0;
    nconsts = 0;
    cond_slot = -1;
}

static const char *use_class(const cs_insn *insn)
{
    const char *m = insn->mnemonic;
    static const char *const ext[] = {"sext.w", "sext.b", "sext.h",
                                      "zext.h", "zext.w", "zext.b", NULL};
    static const char *const shift[] = {"sll", "srl", "sra", "slli", "srli",
                                        "srai", "sllw", "srlw", "sraw",
                                        "slliw", "srliw", "sraiw", NULL};
    static const char *const addsub[] = {"add", "addi", "sub", "addw",
                                         "addiw", "subw", "auipc", "sh1add",
                                         "sh2add", "sh3add", "add.uw", NULL};
    static const char *const cmp[] = {"slt", "sltu", "slti", "sltiu",
                                      "seqz", "snez", "sltz", "sgtz", NULL};
    static const char *const logic[] = {"and", "andi", "or", "ori", "xor",
                                        "xori", "not", "andn", "orn", "xnor",
                                        NULL};
    static const char *const load[] = {"lb", "lbu", "lh", "lhu", "lw", "lwu",
                                       "ld", "flw", "fld", "lr.w", "lr.d",
                                       NULL};
    static const char *const store[] = {"sb", "sh", "sw", "sd", "fsw", "fsd",
                                        "sc.w", "sc.d", NULL};
    static const char *const mul[] = {"mul", "mulh", "mulhu", "mulhsu",
                                      "mulw", "div", "divu", "divw", "divuw",
                                      "rem", "remu", "remw", "remuw", NULL};
    if (mn_in(m, ext)) return "extend";
    if (mn_in(m, shift)) return "shift";
    if (mn_in(m, addsub)) return "addsub";
    if (mn_in(m, cmp)) return "cmp";
    if (mn_in(m, logic)) return "logic";
    if (mn_in(m, load)) return "load";
    if (mn_in(m, store)) return "store";
    if (mn_in(m, mul)) return "mul";
    if (!strcmp(m, "mv")) return "mv";
    if (m[0] == 'b' && has_group(insn, RISCV_GRP_BRANCH_RELATIVE))
        return "branch";
    if (has_group(insn, RISCV_GRP_CALL) || !strcmp(m, "jal") ||
        !strcmp(m, "jr") || !strcmp(m, "ret"))
        return "transfer";
    if (m[0] == 'f') return "fp";
    if (m[0] == 'v') return "vec";
    return "other";
}

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

static void finalize_def(int s, const char *why, const char *path,
                         const char *rtext)
{
    defrec *d = &defs[s];
    if (!d->live) return;
    char key[96];
    if (d->uses == 0 && d->pure && strcmp(why, "redef") == 0) {
        snprintf(key, sizeof key, "dead|%c|%s%s", d->kind, d->detail,
                 d->xbr ? "|xbr" : "");
        bump(key, -1);
        if (example_cat && !strcmp(example_cat, "dead") &&
            example_printed < example_max) {
            printf("EX dead %s %#" PRIx64 ": %s ;; killed by %s\n", path,
                   d->adr, d->text, rtext);
            example_printed++;
        }
    } else if (d->uses == 1) {
        snprintf(key, sizeof key, "sole|%c|%s->%s%s", d->kind, d->detail,
                 d->first_use_cls, d->xbr ? "|xbr" : "");
        bump(key, d->first_use_idx - d->idx);
    } else if (d->uses > 1) {
        snprintf(key, sizeof key, "multi|%c|%s", d->kind, d->detail);
        bump(key, -1);
    }
    d->live = false;
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

static void scan_section(csh handle, const char *path, const uint8_t *code,
                         size_t size, uint64_t vaddr)
{
    uint8_t *bits = mark_branch_targets(handle, code, size, vaddr);
    cs_insn *insn = cs_malloc(handle);
    // The liveness walk disassembles ahead of the main cursor, so it gets
    // its own handle rather than interleaving iterator state on this one.
    cs_insn *probe = cs_malloc(probe_handle);
    if (!insn || !probe) { free(bits); return; }
    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;
    long idx = 0;
    region_reset();

    static const char *const ext_mn[] = {"sext.w", "sext.b", "sext.h",
                                         "zext.h", "zext.w", "zext.b", NULL};
    static const char *const alu_mn[] = {"add", "addi", "sub", "addw",
                                         "addiw", "subw", "and", "andi",
                                         "or", "ori", "xor", "xori", "sll",
                                         "slli", "srl", "srli", "sra",
                                         "srai", "slliw", "srliw", "sraiw",
                                         "not", "neg", "sh1add", "sh2add",
                                         "sh3add", "add.uw", NULL};
    // Conditions a compare-branch could have folded. The reg-reg forms
    // fold outright (slt+bnez -> blt); the immediate forms are kept
    // separate because RISC-V has no compare-immediate-and-branch.
    static const char *const cond_mn_set[] = {"slt", "sltu", "xor", "sub",
                                              "seqz", "snez", "sltz",
                                              "sgtz", "slti", "sltiu",
                                              "xori", NULL};
    static const char *const store_mn[] = {"sb", "sh", "sw", "sd", "fsw",
                                           "fsd", "fsh", "sc.w", "sc.d",
                                           NULL};

    while (remain >= 2) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            p += 2; remain -= 2; addr += 2;
            total_undecodable++;
            region_reset();
            continue;
        }
        total_insns++;
        idx++;
        size_t off = (size_t)(insn->address - vaddr);
        if (bits && (bits[off / 2 / 8] >> (off / 2 % 8) & 1)) region_reset();
        const char *mn = insn->mnemonic;
        if (!strcmp(mn, "unimp") || !strcmp(mn, "ebreak")) {
            region_reset(); continue;
        }
        const cs_riscv *a = &insn->detail->riscv;

        cs_regs rr, rw; uint8_t nr = 0, nw = 0;
        cs_regs_access(handle, insn, rr, &nr, rw, &nw);
        fix_implicit_ra(insn, rr, &nr, rw, &nw);

        // ---- uses ----
        for (int j = 0; j < nr; j++) {
            int s = reg_slot(rr[j]);
            if (s < 0 || s >= NSLOT) continue;
            defrec *d = &defs[s];
            if (d->live) {
                d->uses++;
                if (d->uses == 1) {
                    d->first_use_idx = idx;
                    snprintf(d->first_use_cls, sizeof d->first_use_cls,
                             "%s", use_class(insn));
                    if (example_cat && d->kind ==
                        (!strcmp(example_cat, "ext") ? 'e' :
                         !strcmp(example_cat, "load") ? 'l' :
                         !strcmp(example_cat, "mov") ? 'm' : 0) &&
                        idx - d->idx > 1 && example_printed < example_max) {
                        printf("EX %s %s %#" PRIx64 ": d=%ld %s -> %s %s\n",
                               example_cat, path, insn->address,
                               idx - d->idx, d->detail, insn->mnemonic,
                               insn->op_str);
                        example_printed++;
                    }
                }
            }
        }

        // ---- beqz/bnez on a materialized condition ----
        if ((!strcmp(mn, "beqz") || !strcmp(mn, "bnez")) && a->op_count >= 1 &&
            a->operands[0].type == RISCV_OP_REG) {
            int s = reg_slot(a->operands[0].reg);
            if (s >= 0 && s == cond_slot) {
                uint64_t starts[2] = { insn->address + insn->size,
                                       branch_target(insn) };
                int live = starts[1]
                    ? liveness(probe_handle, probe, code, size, vaddr,
                               starts, 2, s)
                    : LIVE_UNKNOWN;
                char key[96];
                snprintf(key, sizeof key, "br|%s->%s|%s", cond_mn, mn,
                         live == LIVE_DEAD ? "fold" :
                         live == LIVE_READ ? "live" : "unk");
                bump(key, idx - cond_idx);
                if (example_cat && !strcmp(example_cat, "br") &&
                    example_printed < example_max) {
                    printf("EX br %s %#" PRIx64 ": d=%ld %s -> %s %s\n", path,
                           insn->address, idx - cond_idx, cond_mn, mn,
                           insn->op_str);
                    example_printed++;
                }
            }
        }

        // ---- redundant reload / store invalidation ----
        bool is_store = mn_in(mn, store_mn);
        bool call = is_call(insn);
        bool is_barrier = !strncmp(mn, "fence", 5) || !strncmp(mn, "amo", 3) ||
                          !strncmp(mn, "lr.", 3) || !strncmp(mn, "sc.", 3) ||
                          !strcmp(mn, "ecall");
        if (is_store || call || is_barrier) nloads = 0;

        int ldsize = load_size(mn);
        if (ldsize && a->op_count == 2 && a->operands[1].type == RISCV_OP_MEM) {
            int bs = reg_slot(a->operands[1].mem.base);
            int dest = a->operands[0].type == RISCV_OP_REG ?
                       reg_slot(a->operands[0].reg) : -1;
            if (bs >= 0) {
                bool matched = false;
                for (int k = 0; k < nloads; k++) {
                    loadrec *L = &loads[k];
                    if (L->live && L->base == bs &&
                        L->disp == a->operands[1].mem.disp &&
                        L->size == ldsize && strcmp(L->mn, mn) == 0) {
                        char key[64];
                        snprintf(key, sizeof key, "reload|%s|sz%d",
                                 bs == 2 ? "sp" : bs == 3 ? "gp" :
                                 bs == 4 ? "tp" : "heap", ldsize);
                        bump(key, idx - L->idx);
                        if (example_cat && !strcmp(example_cat, "reload") &&
                            example_printed < example_max) {
                            printf("EX reload %s %#" PRIx64
                                   ": d=%ld [x%d%+" PRId64 "] sz%d\n",
                                   path, insn->address, idx - L->idx, bs,
                                   (int64_t)a->operands[1].mem.disp, ldsize);
                            example_printed++;
                        }
                        L->idx = idx;  // re-arm from the later load
                        matched = true;
                        break;  // records are unique per (base,disp,size)
                    }
                }
                if (!matched && nloads < 64) {
                    loadrec *L = &loads[nloads++];
                    *L = (loadrec){true, idx, bs,
                                   a->operands[1].mem.disp, ldsize, "", dest};
                    snprintf(L->mn, sizeof L->mn, "%s", mn);
                }
            }
        }

        // ---- writes: finalize + invalidate ----
        for (int j = 0; j < nw; j++) {
            int s = reg_slot(rw[j]);
            if (s < 0 || s >= NSLOT) continue;
            char rtext[192];
            snprintf(rtext, sizeof rtext, "%s %s", insn->mnemonic,
                     insn->op_str);
            finalize_def(s, "redef", path, rtext);
            for (int k = 0; k < nloads; k++)
                if (loads[k].live && loads[k].base == s) loads[k].live = false;
            for (int k = 0; k < nconsts; k++)
                if (consts[k].live && consts[k].slot == s)
                    consts[k].live = false;
            if (cond_slot == s) cond_slot = -1;
        }

        // ---- new defs ----
        int dslot = -1;
        if (a->op_count >= 1 && a->operands[0].type == RISCV_OP_REG &&
            !is_store) {
            int cand = reg_slot(a->operands[0].reg);
            for (int j = 0; j < nw; j++)
                if (reg_slot(rw[j]) == cand) { dslot = cand; break; }
        }
        if (dslot >= 0 && dslot < NSLOT) {
            defrec *d = &defs[dslot];
            uint64_t def_adr = insn->address;
            char def_text[192];
            snprintf(def_text, sizeof def_text, "%s %s", insn->mnemonic,
                     insn->op_str);
            if (mn_in(mn, ext_mn)) {
                memset(d, 0, sizeof *d);
                d->live = true; d->idx = idx; d->kind = 'e'; d->pure = true;
                snprintf(d->detail, sizeof d->detail, "%s", mn);
            } else if (ldsize && ldsize < 8) {
                memset(d, 0, sizeof *d);
                d->live = true; d->idx = idx; d->kind = 'l'; d->pure = false;
                snprintf(d->detail, sizeof d->detail, "%s", mn);
            } else if (!strcmp(mn, "mv")) {
                memset(d, 0, sizeof *d);
                d->live = true; d->idx = idx; d->kind = 'm'; d->pure = true;
                snprintf(d->detail, sizeof d->detail, "movrr");
            } else if (!strcmp(mn, "li") || !strcmp(mn, "lui")) {
                // constant re-materialization tracking
                int64_t v = 0;
                for (int j = 1; j < a->op_count; j++)
                    if (a->operands[j].type == RISCV_OP_IMM)
                        v = a->operands[j].imm;
                // lui's operand is the raw imm20; without the shift a
                // `lui rd,16` and a `li rd,16` compare equal and match
                // as the same constant, which they are not.
                if (!strcmp(mn, "lui")) v <<= 12;
                for (int k = 0; k < nconsts; k++)
                    if (consts[k].live && consts[k].val == v &&
                        consts[k].slot != dslot) {
                        char key[64];
                        // Rewriting the duplicate as `mv` only saves
                        // bytes when the constant did not already fit
                        // c.li, since mv is 2 bytes either way. Split
                        // the population so the saving is not assumed.
                        snprintf(key, sizeof key, "remat|%s|%s", mn,
                                 (v >= -32 && v <= 31) ? "fits-c.li"
                                                       : "wide");
                        bump(key, idx - consts[k].idx);
                        if (example_cat && !strcmp(example_cat, "remat") &&
                            example_printed < example_max) {
                            printf("EX remat %s %#" PRIx64
                                   ": d=%ld #%" PRId64 "\n", path,
                                   insn->address, idx - consts[k].idx, v);
                            example_printed++;
                        }
                        break;
                    }
                if (nconsts < 48)
                    consts[nconsts++] = (constrec){true, idx, v, dslot};
                memset(d, 0, sizeof *d);
                d->live = true; d->idx = idx; d->kind = 'a'; d->pure = true;
                snprintf(d->detail, sizeof d->detail, "%s", mn);
            } else if (mn_in(mn, alu_mn)) {
                memset(d, 0, sizeof *d);
                d->live = true; d->idx = idx; d->kind = 'a'; d->pure = true;
                snprintf(d->detail, sizeof d->detail, "%s", mn);
            } else {
                d->live = false;  // untracked def kinds stop tracking the slot
            }
            if (d->live && d->idx == idx) {
                d->adr = def_adr;
                snprintf(d->text, sizeof d->text, "%s", def_text);
            }
            // Arm the compare-branch pattern independently of the def
            // record above: sub/xor are both ALU defs and condition
            // producers, and the two categories count different things.
            if (mn_in(mn, cond_mn_set)) {
                cond_slot = dslot;
                cond_idx = idx;
                snprintf(cond_mn, sizeof cond_mn, "%s", mn);
            }
        }

        // conditional branches taint open defs
        if (is_cond_branch(insn)) {
            for (int s = 0; s < NSLOT; s++)
                if (defs[s].live) defs[s].xbr = true;
        }

        // region enders
        if (uncond_transfer(insn) || call)
            region_reset();
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
            fprintf(stderr, "usage: %s [-e CAT -n MAX] <binary>...\n",
                    argv[0]);
            return 2;
        }
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-e CAT -n MAX] <binary>...\n", argv[0]);
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
