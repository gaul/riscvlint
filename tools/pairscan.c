// pairscan: disassemble the RISC-V code in ELF files and count
// adjacent-instruction pairs by normalized shape, to surface frequent
// patterns worth new riscvlint checks.
//
// Ported from armlint's tools/pairscan.c. The AArch64 original assumes
// fixed 4-byte instructions in three places -- the branch-target bitset,
// the resync stride after an undecodable word, and the loop bound. RISC-V
// mixes 2- and 4-byte encodings, so the bitset is 2-byte granular, resync
// steps 2 bytes, and branch targets come from a capstone pre-pass rather
// than hand-decoded immediates (RISC-V splits branch offsets across five
// bit fields; decoding them by hand buys nothing here).
//
// Normalization: mnemonic + operand shapes. Capstone prints the ABI
// aliases (mv, li, ret, beqz, sext.w), which is the form a reader thinks
// in, so they are kept as-is. Register classes: zero, ra, sp, gp, tp, fp
// kept distinct; a (a0-a7), s (s1-s11), t (t0-t6), f, v collapsed.
// Immediates: #0 vs #i. Mem: [base], [base+i].
//
// A ":c" suffix on the mnemonic marks a 2-byte (compressed) encoding.
// Capstone prints c.mv as "mv" and c.addi as "addi", so without this the
// single most RISC-V-specific question -- did this instruction take the
// 2-byte form it was entitled to? -- is invisible in the pair counts.
//
// Pair flags: dep (second reads a register the first wrote),
// waw (second overwrites a register the first wrote without reading it).
// Pairs are skipped when the second insn is a branch target (side entry),
// when the first is an unconditional control transfer (j/jr/ret), or
// across undecodable halfwords / section boundaries.
//
// Usage: pairscan [-e SUBSTR -n MAXPRINT] <binary>...
//   default: print "count<TAB>tokA || tokB || flags" for all pairs
//   -e: additionally print example sites (file addr: textA ;; textB)
//   -x: keep small immediates (-256..255) verbatim instead of #i, so that
//       shift-amount-sensitive families size honestly
//   -1: count single instructions by shape rather than pairs

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

// === Minimal ELF64 definitions ===
//
// Reproducing the on-disk layout keeps the tool single-file and free of
// any dependency beyond capstone, matching the armlint tools it mirrors.
// Unlike those, there is no Mach-O path: RISC-V has no Darwin target.

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

// Every extension a distro riscv64 binary can plausibly contain. The
// aggregate CS_MODE_RISCV_BITMANIP is not a legal mode on its own (cs_open
// rejects it), so the Zb* sets are named individually.
// vendor sets (COREV, THEAD, SIFIVE, VENTANA) are deliberately left out:
// they reuse encoding space and would turn unrelated words into
// confident-looking vendor instructions. Zfinx is left out for the same
// reason -- it redefines the FP encodings onto the integer registers.
#define RV_MODE (CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD |    \
                 CS_MODE_RISCV_A | CS_MODE_RISCV_V |                       \
                 CS_MODE_RISCV_ZBA |                                       \
                 CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC |                   \
                 CS_MODE_RISCV_ZBS | CS_MODE_RISCV_ZBKB |                  \
                 CS_MODE_RISCV_ZBKC | CS_MODE_RISCV_ZBKX |                 \
                 CS_MODE_RISCV_ZCMP_ZCMT_ZCE)

#define HASH_BITS 22
#define HASH_SIZE (1u << HASH_BITS)

typedef struct {
    char *key;
    uint64_t count;
} entry;

static entry table[HASH_SIZE];
static uint64_t total_pairs = 0;
static uint64_t total_insns = 0;
static uint64_t total_undecodable = 0;
static uint64_t total_compressed = 0;
// Immediates normalize to #0/#i by default, as in armlint. That makes
// every shift-amount-sensitive family an upper bound: slli+add looks like
// sh#add whatever the shift is. -x keeps small immediates verbatim, which
// is what separates a population from a pair count.
static bool exact_imm = false;
// -1 counts single instructions by shape instead of pairs. A pair table
// cannot answer "how many instructions of shape X are there", because
// each instruction appears in up to two pairs and region boundaries drop
// some entirely -- and that census is what sizing missed compression
// needs.
static bool unigram = false;
static const char *example_substr = NULL;
static long example_max = 20;
static long example_printed = 0;

static uint32_t hash_str(const char *s)
{
    uint32_t h = 5381;
    while (*s) h = h * 33 + (uint8_t)*s++;
    return h;
}

static void bump(const char *key)
{
    uint32_t h = hash_str(key) & (HASH_SIZE - 1);
    for (;;) {
        if (table[h].key == NULL) {
            table[h].key = strdup(key);
            table[h].count = 1;
            return;
        }
        if (strcmp(table[h].key, key) == 0) {
            table[h].count++;
            return;
        }
        h = (h + 1) & (HASH_SIZE - 1);
    }
}

// Canonical architectural slot for dependency tracking: 1-31 GPRs,
// 32+n FP, 64+n vector, -1 = ignore. x0 is -1: it reads as zero and
// discards writes, so it carries no dependency in either direction.
static int reg_slot(unsigned r)
{
    if (r >= RISCV_REG_X0 && r <= RISCV_REG_X31) {
        int n = (int)(r - RISCV_REG_X0);
        return n == 0 ? -1 : n;
    }
    // The _D/_F/_H triples are three views of one physical register.
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

static const char *reg_class(unsigned r)
{
    if (r >= RISCV_REG_X0 && r <= RISCV_REG_X31) {
        unsigned n = r - RISCV_REG_X0;
        switch (n) {
        case 0:  return "zero";
        case 1:  return "ra";
        case 2:  return "sp";
        case 3:  return "gp";
        case 4:  return "tp";
        case 8:  return "fp";   // s0 doubles as the frame pointer
        default: break;
        }
        if (n >= 10 && n <= 17) return "a";
        if (n == 9 || (n >= 18 && n <= 27)) return "s";
        return "t";             // t0-t2 (x5-x7), t3-t6 (x28-x31)
    }
    if ((r >= RISCV_REG_F0_D && r <= RISCV_REG_F31_D) ||
        (r >= RISCV_REG_F0_F && r <= RISCV_REG_F31_F) ||
        (r >= RISCV_REG_F0_H && r <= RISCV_REG_F31_H))
        return "f";
    if (r >= RISCV_REG_V0 && r <= RISCV_REG_V31) return "v";
    return "r?";
}

static void build_token(const cs_insn *insn, char *out, size_t outsz)
{
    const cs_riscv *a = &insn->detail->riscv;
    char buf[160];
    size_t p = 0;
    // ":c" separates a 2-byte encoding from the 4-byte spelling of the
    // same mnemonic; capstone prints both as e.g. "addi".
    p += (size_t)snprintf(buf + p, sizeof buf - p, "%s%s", insn->mnemonic,
                          insn->size == 2 ? ":c" : "");
    for (int i = 0; i < a->op_count && p < sizeof buf - 24; i++) {
        const cs_riscv_op *op = &a->operands[i];
        buf[p++] = i == 0 ? ' ' : ',';
        switch (op->type) {
        case RISCV_OP_REG:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "%s",
                                  reg_class(op->reg));
            break;
        case RISCV_OP_IMM:
            // -256..255 covers every shift amount and the common masks
            // while leaving branch and address immediates collapsed.
            if (exact_imm && op->imm >= -256 && op->imm <= 255)
                p += (size_t)snprintf(buf + p, sizeof buf - p, "#%d",
                                      (int)op->imm);
            else
                p += (size_t)snprintf(buf + p, sizeof buf - p, "%s",
                                      op->imm == 0 ? "#0" : "#i");
            break;
        case RISCV_OP_FP:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "#f");
            break;
        case RISCV_OP_MEM:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "[%s%s]",
                                  reg_class(op->mem.base),
                                  op->mem.disp != 0 ? "+i" : "");
            break;
        case RISCV_OP_CSR:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "csr");
            break;
        default:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "?");
            break;
        }
    }
    buf[p] = '\0';
    snprintf(out, outsz, "%s", buf);
}

static bool has_group(const cs_insn *insn, unsigned g)
{
    for (int i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == g) return true;
    return false;
}

// Branch-target bitset over one section, one bit per 2-byte unit.
//
// The armlint original hand-decodes the four AArch64 branch encodings.
// Here a capstone pre-pass is both shorter and more complete: it picks
// up every relative transfer including the compressed ones, and the
// absolute target already sits in the immediate operand.
static uint8_t *mark_branch_targets(csh handle, const uint8_t *code,
                                    size_t size, uint64_t vaddr)
{
    size_t units = size / 2;
    uint8_t *bits = calloc(units / 8 + 1, 1);
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

static bool is_target(const uint8_t *bits, size_t off)
{
    return bits && (bits[off / 2 / 8] >> (off / 2 % 8) & 1);
}

static bool uncond_transfer(const cs_insn *insn)
{
    const char *m = insn->mnemonic;
    return strcmp(m, "j") == 0 || strcmp(m, "jr") == 0 ||
           strcmp(m, "ret") == 0 || strcmp(m, "mret") == 0 ||
           strcmp(m, "sret") == 0 || strcmp(m, "uret") == 0;
}

// capstone models the ra-implicit link aliases as writing nothing and
// `ret` as reading nothing. Both matter here: without the fix a saved-ra
// reload looks dead and a call looks like it preserves ra.
static void fix_implicit_ra(const cs_insn *insn, cs_regs rr, uint8_t *nr,
                            cs_regs rw, uint8_t *nw)
{
    const char *m = insn->mnemonic;
    if ((strcmp(m, "jal") == 0 || strcmp(m, "jalr") == 0) && *nw == 0)
        rw[(*nw)++] = RISCV_REG_X1;
    else if (strcmp(m, "ret") == 0 && *nr == 0)
        rr[(*nr)++] = RISCV_REG_X1;
}

static void scan_section(csh handle, const char *path, const uint8_t *code,
                         size_t size, uint64_t vaddr)
{
    uint8_t *targets = mark_branch_targets(handle, code, size, vaddr);
    cs_insn *insn = cs_malloc(handle);
    if (!insn) { free(targets); return; }
    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;

    bool have_prev = false;
    char prev_tok[160];
    char prev_text[200];
    int prev_writes[16];
    int prev_nwrites = 0;

    while (remain >= 2) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            // Undecodable halfword (literal pool, padding): resync at the
            // next 2-byte boundary and break the chain.
            p += 2; remain -= 2; addr += 2;
            total_undecodable++;
            have_prev = false;
            continue;
        }
        total_insns++;
        if (insn->size == 2) total_compressed++;
        // c.unimp (0x0000) and ebreak sit between functions and in
        // alignment padding; treat them as region boundaries.
        if (strcmp(insn->mnemonic, "unimp") == 0 ||
            strcmp(insn->mnemonic, "ebreak") == 0) {
            have_prev = false;
            continue;
        }
        char tok[160];
        build_token(insn, tok, sizeof tok);

        cs_regs regs_read, regs_write;
        uint8_t nread = 0, nwrite = 0;
        cs_regs_access(handle, insn, regs_read, &nread, regs_write, &nwrite);
        fix_implicit_ra(insn, regs_read, &nread, regs_write, &nwrite);

        if (unigram) {
            bump(tok);
            total_pairs++;
        }

        size_t sec_off = (size_t)(insn->address - vaddr);
        if (!unigram && have_prev && !is_target(targets, sec_off)) {
            bool dep = false, waw = false;
            for (int i = 0; i < prev_nwrites; i++) {
                int s = prev_writes[i];
                for (int j = 0; j < nread; j++)
                    if (reg_slot(regs_read[j]) == s) { dep = true; break; }
            }
            for (int i = 0; i < prev_nwrites && !waw; i++) {
                int s = prev_writes[i];
                bool w2 = false, r2 = false;
                for (int j = 0; j < nwrite; j++)
                    if (reg_slot(regs_write[j]) == s) { w2 = true; break; }
                for (int j = 0; j < nread; j++)
                    if (reg_slot(regs_read[j]) == s) { r2 = true; break; }
                if (w2 && !r2) waw = true;
            }
            char key[420];
            snprintf(key, sizeof key, "%s || %s || %s%s", prev_tok, tok,
                     dep ? "dep" : (waw ? "" : "-"),
                     waw ? (dep ? ",waw" : "waw") : "");
            bump(key);
            total_pairs++;
            if (example_substr && example_printed < example_max &&
                strstr(key, example_substr)) {
                printf("EX %s %#" PRIx64 ": %s ;; %s %s\n", path,
                       insn->address - insn->size, prev_text, insn->mnemonic,
                       insn->op_str);
                example_printed++;
            }
        }

        // Current becomes prev unless it ends a straight-line region.
        if (uncond_transfer(insn)) {
            have_prev = false;
        } else {
            have_prev = true;
            memcpy(prev_tok, tok, sizeof prev_tok);
            snprintf(prev_text, sizeof prev_text, "%s %s", insn->mnemonic,
                     insn->op_str);
            prev_nwrites = 0;
            for (int j = 0; j < nwrite && prev_nwrites < 16; j++) {
                int s = reg_slot(regs_write[j]);
                if (s >= 0) prev_writes[prev_nwrites++] = s;
            }
        }
    }
    cs_free(insn, 1);
    free(targets);
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
    if (eb->count != ea->count) return eb->count > ea->count ? 1 : -1;
    return strcmp(ea->key, eb->key);
}

int main(int argc, char **argv)
{
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-x") == 0) {
            exact_imm = true;
        } else if (strcmp(argv[argi], "-1") == 0) {
            unigram = true;
        } else if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example_substr = argv[++argi];
        } else if (strcmp(argv[argi], "-E") == 0 && argi + 1 < argc) {
            example_substr = argv[++argi];
            example_max = 1L << 60;
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            example_max = atol(argv[++argi]);
        } else {
            fprintf(stderr, "usage: %s [-x] [-1] [-e SUBSTR -n MAX] <binary>...\n",
                    argv[0]);
            return 2;
        }
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-x] [-1] [-e SUBSTR -n MAX] <binary>...\n", argv[0]);
        return 2;
    }
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RV_MODE, &handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    for (; argi < argc; argi++)
        scan_file(handle, argv[argi]);
    cs_close(&handle);

    size_t n = 0;
    for (size_t i = 0; i < HASH_SIZE; i++)
        if (table[i].key) n++;
    entry *flat = malloc(n * sizeof *flat);
    if (!flat) { fprintf(stderr, "out of memory\n"); return 2; }
    size_t k = 0;
    for (size_t i = 0; i < HASH_SIZE; i++)
        if (table[i].key) flat[k++] = table[i];
    qsort(flat, n, sizeof *flat, cmp_entry);
    fprintf(stderr, "TOTAL pairs=%" PRIu64 " distinct=%zu insns=%" PRIu64
            " compressed=%" PRIu64 " (%.1f%%) undecodable=%" PRIu64 "\n",
            total_pairs, n, total_insns, total_compressed,
            total_insns ? 100.0 * (double)total_compressed / (double)total_insns : 0.0,
            total_undecodable);
    for (size_t i = 0; i < n; i++)
        printf("%" PRIu64 "\t%s\n", flat[i].count, flat[i].key);
    free(flat);
    return 0;
}
