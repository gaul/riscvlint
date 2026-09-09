// riscvlint driver: walk the executable sections of a riscv64 ELF,
// run the checks over each, and report findings.

#include "riscvlint.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// === Minimal ELF64 definitions ===

#define EI_NIDENT     16
#define EI_CLASS      4
#define ELFMAG        "\x7f""ELF"
#define SELFMAG       4
#define ELFCLASS64    2
#define EM_RISCV      243
#define SHT_PROGBITS  1
#define SHT_SYMTAB    2
#define SHT_RELA      4
#define SHF_EXECINSTR 0x4
#define STT_FUNC      2
#define SHT_RISCV_ATTRIBUTES 0x70000003

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

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

// ---- Tag_RISCV_arch ----
//
// The build attributes say which extensions the object was compiled for.
// Suggesting a Zba instruction to something built for plain rv64gc would
// be advice that does not assemble, so the Zb-shaped checks are gated on
// this rather than on what the corpus happened to use.
//
// Layout: 'A', then per-vendor subsections of
//   uint32 length, vendor name, then tagged sub-subsections of
//   byte tag, uint32 size, attributes.
// An attribute is a ULEB128 tag followed by a ULEB128 value when the tag
// is even and a NUL-terminated string when it is odd; Tag_RISCV_arch is
// 5, so it is a string.

static uint64_t read_uleb(const uint8_t **p, const uint8_t *end)
{
    uint64_t v = 0;
    unsigned shift = 0;
    while (*p < end) {
        uint8_t b = *(*p)++;
        if (shift < 64) v |= (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    return v;
}

static const char *find_arch_string(const uint8_t *base, size_t map_len,
                                    const Elf64_Ehdr *eh)
{
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_RISCV_ATTRIBUTES) continue;
        if (sh[i].sh_offset > map_len ||
            sh[i].sh_size > map_len - sh[i].sh_offset || sh[i].sh_size < 5)
            continue;
        const uint8_t *p = base + sh[i].sh_offset;
        const uint8_t *end = p + sh[i].sh_size;
        if (*p++ != 'A') continue;
        while (p + 4 <= end) {
            uint32_t sublen;
            memcpy(&sublen, p, 4);
            if (sublen < 5 || p + sublen > end) break;
            const uint8_t *sub_end = p + sublen;
            const uint8_t *q = p + 4;
            const uint8_t *vendor = q;
            while (q < sub_end && *q) q++;
            if (q >= sub_end) break;
            q++;  // past the NUL
            if (strcmp((const char *)vendor, "riscv") != 0) {
                p = sub_end;
                continue;
            }
            while (q + 5 <= sub_end) {
                uint8_t tag = *q;
                uint32_t size;
                memcpy(&size, q + 1, 4);
                if (size < 5 || q + size > sub_end) break;
                const uint8_t *attr_end = q + size;
                const uint8_t *a = q + 5;
                if (tag != 1) { q = attr_end; continue; }   // Tag_File only
                while (a < attr_end) {
                    uint64_t t = read_uleb(&a, attr_end);
                    if (t & 1) {                    // odd tags carry a string
                        const char *str = (const char *)a;
                        while (a < attr_end && *a) a++;
                        if (a < attr_end) a++;
                        if (t == 5) return str;     // Tag_RISCV_arch
                    } else {
                        read_uleb(&a, attr_end);
                    }
                }
                q = attr_end;
            }
            p = sub_end;
        }
    }
    return NULL;
}

// ---- reporting ----

#define MAX_TITLES 16

typedef struct {
    const char *title;
    uint64_t count;
} tally_entry;

static tally_entry tally[MAX_TITLES];
static size_t ntitles;
static bool quiet;      // -q: summary only, for corpus-scale runs
// -m replaces what the object declares, in both directions: it enables a
// gated check against a declaration that omits the extension ("what
// would rebuilding for RVA23 buy me?") and disables one against an
// object that declares nothing ("this Go binary is going on rv64gc
// hardware"). Neither is expressible if the flag merely unions.
static unsigned forced_exts;
static bool have_forced;
static uint64_t total_findings;
static uint64_t total_insns;

static void tally_add(const char *title)
{
    for (size_t i = 0; i < ntitles; i++)
        if (strcmp(tally[i].title, title) == 0) { tally[i].count++; return; }
    if (ntitles < MAX_TITLES) {
        tally[ntitles].title = title;
        tally[ntitles].count = 1;
        ntitles++;
    }
}

// Nearest preceding function symbol, for the "<name+0x..>" in a finding.
static const char *symbolize(const uint8_t *base, size_t map_len,
                             const Elf64_Ehdr *eh, uint64_t addr,
                             uint64_t *delta)
{
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    const char *best = NULL;
    uint64_t best_val = 0;
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB || sh[i].sh_entsize == 0) continue;
        if (sh[i].sh_link >= eh->e_shnum) continue;
        const Elf64_Shdr *str = &sh[sh[i].sh_link];
        if (sh[i].sh_offset > map_len || sh[i].sh_size > map_len - sh[i].sh_offset)
            continue;
        if (str->sh_offset > map_len) continue;
        const Elf64_Sym *sym = (const Elf64_Sym *)(base + sh[i].sh_offset);
        size_t n = sh[i].sh_size / sh[i].sh_entsize;
        for (size_t j = 0; j < n; j++) {
            if ((sym[j].st_info & 0xf) != STT_FUNC || sym[j].st_name == 0)
                continue;
            if (sym[j].st_value > addr) continue;
            if (sym[j].st_size && addr >= sym[j].st_value + sym[j].st_size)
                continue;
            if (best && sym[j].st_value <= best_val) continue;
            best = (const char *)(base + str->sh_offset + sym[j].st_name);
            best_val = sym[j].st_value;
        }
    }
    if (!best) return NULL;
    *delta = addr - best_val;
    return best;
}

static void report(const riscvlint_finding *f, csh handle,
                   const riscvlint_state *state, const uint8_t *base,
                   size_t map_len, const Elf64_Ehdr *eh)
{
    tally_add(f->title);
    total_findings++;
    if (quiet) return;

    uint64_t delta = 0;
    const char *sym = symbolize(base, map_len, eh, f->address, &delta);
    printf("%s at offset: 0x%" PRIx64, f->title, f->address);
    if (sym) {
        if (delta) printf(" <%s+0x%" PRIx64 ">", sym, delta);
        else printf(" <%s>", sym);
    }
    printf(": -> %s (%u instructions)\n", f->replacement, f->insn_count);

    // Print the instructions the finding covers, disassembled fresh so
    // the report shows exactly what is in the file.
    cs_insn *insn = cs_malloc(handle);
    if (insn) {
        uint64_t addr = f->address;
        for (unsigned i = 0; i < f->insn_count; i++) {
            uint32_t w;
            if (!riscvlint_word_at(state, addr, &w)) break;
            uint8_t bytes[4];
            memcpy(bytes, &w, 4);
            const uint8_t *p = bytes;
            size_t remain = 4;
            uint64_t a = addr;
            if (!cs_disasm_iter(handle, &p, &remain, &a, insn)) break;
            printf("  %s %s\n", insn->mnemonic, insn->op_str);
            addr = a;
        }
        cs_free(insn, 1);
    }
    printf("\n");
}

// ---- scanning ----

static const riscvlint_check_fn checks[] = {
    check_call_pair_to_jal,
    check_slli_add_to_shadd,
};

static void scan_section(csh handle, riscvlint_state *state,
                         const uint8_t *code, size_t size, uint64_t vaddr,
                         const uint8_t *base, size_t map_len,
                         const Elf64_Ehdr *eh)
{
    if (!riscvlint_state_set_section(state, handle, code, size, vaddr))
        return;

    // Relocations against this section make its call immediates
    // placeholders; collect them so the checks can skip those sites.
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    unsigned self = eh->e_shnum;
    for (unsigned i = 0; i < eh->e_shnum; i++)
        if (sh[i].sh_offset == (uint64_t)(code - base)) { self = i; break; }
    for (unsigned i = 0; i < eh->e_shnum && self < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_RELA || sh[i].sh_info != self) continue;
        if (sh[i].sh_entsize == 0 || sh[i].sh_offset > map_len ||
            sh[i].sh_size > map_len - sh[i].sh_offset)
            continue;
        const Elf64_Rela *r = (const Elf64_Rela *)(base + sh[i].sh_offset);
        size_t n = sh[i].sh_size / sh[i].sh_entsize;
        uint64_t *offs = malloc(n * sizeof *offs);
        if (!offs) continue;
        for (size_t j = 0; j < n; j++) offs[j] = r[j].r_offset;
        riscvlint_state_set_relocs(state, offs, n);
        free(offs);
    }

    cs_insn *insn = cs_malloc(handle);
    if (!insn) return;
    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;
    while (remain >= 2) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            p += 2; remain -= 2; addr += 2;
            continue;
        }
        total_insns++;
        for (size_t i = 0; i < sizeof checks / sizeof checks[0]; i++) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            if (checks[i](state, insn, &f))
                report(&f, handle, state, base, map_len, eh);
        }
    }
    cs_free(insn, 1);
}

static int scan_file(csh handle, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: not a readable binary\n", path);
        close(fd);
        return -1;
    }
    size_t map_len = (size_t)st.st_size;
    const uint8_t *base = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror(path); return -1; }

    int rc = 0;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (memcmp(base, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_RISCV) {
        fprintf(stderr, "%s: not a RISC-V ELF64\n", path);
        rc = -1;
    } else if (eh->e_shoff > map_len ||
               (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) >
                   map_len - eh->e_shoff) {
        fprintf(stderr, "%s: section headers out of bounds\n", path);
        rc = -1;
    } else {
        riscvlint_state *state = riscvlint_state_create();
        if (!state) { munmap((void *)base, map_len); return -1; }
        // Say which extension set is in force whenever it was not simply
        // read from the object. Reporting a Zba finding because nothing
        // said otherwise is a guess, and a guess the reader cannot see is
        // the shape of every wrong number this project has produced.
        unsigned declared = riscvlint_parse_arch(
            find_arch_string(base, map_len, eh));
        unsigned effective;
        if (have_forced) {
            effective = forced_exts | RISCVLINT_EXT_DECLARED;
            if (declared & RISCVLINT_EXT_DECLARED)
                printf("note: %s: -m overrides the arch declared in the "
                       "object\n", path);
        } else {
            effective = declared;
            if (!(declared & RISCVLINT_EXT_DECLARED))
                printf("note: %s: no RISC-V arch attributes; "
                       "extension-gated checks left unrestricted "
                       "(pass -m to pin)\n", path);
        }
        riscvlint_state_set_extensions(state, effective);
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
        for (unsigned i = 0; i < eh->e_shnum; i++) {
            if ((sh[i].sh_flags & SHF_EXECINSTR) == 0 ||
                sh[i].sh_type != SHT_PROGBITS || sh[i].sh_size == 0)
                continue;
            if (sh[i].sh_offset > map_len ||
                sh[i].sh_size > map_len - sh[i].sh_offset)
                continue;
            scan_section(handle, state, base + sh[i].sh_offset,
                         sh[i].sh_size, sh[i].sh_addr, base, map_len, eh);
        }
        riscvlint_state_destroy(state);
    }
    munmap((void *)base, map_len);
    return rc;
}

static int cmp_tally(const void *a, const void *b)
{
    const tally_entry *ta = a, *tb = b;
    if (ta->count != tb->count) return tb->count > ta->count ? 1 : -1;
    return strcmp(ta->title, tb->title);
}

int main(int argc, char **argv)
{
    static const char usage[] =
        "usage: %s [-q] [-m zba|zbb|zbs|rva20|rva22|rva23]... <binary>...\n";
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-' && argv[argi][1]) {
        if (strcmp(argv[argi], "-q") == 0) {
            quiet = true;
        } else if (strcmp(argv[argi], "-m") == 0 && argi + 1 < argc) {
            unsigned e;
            if (!riscvlint_parse_ext_name(argv[++argi], &e)) {
                fprintf(stderr, "%s: unknown -m name '%s'\n", argv[0],
                        argv[argi]);
                fprintf(stderr, usage, argv[0]);
                return 2;
            }
            forced_exts |= e;
            have_forced = true;
        } else {
            fprintf(stderr, usage, argv[0]);
            return 2;
        }
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, usage, argv[0]);
        return 2;
    }
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RISCVLINT_CS_MODE, &handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    for (; argi < argc; argi++)
        scan_file(handle, argv[argi]);
    cs_close(&handle);

    if (ntitles) {
        qsort(tally, ntitles, sizeof tally[0], cmp_tally);
        printf("Optimization opportunities by type:\n");
        for (size_t i = 0; i < ntitles; i++)
            printf("%8" PRIu64 "  %s\n", tally[i].count, tally[i].title);
        printf("\n");
    }
    printf("%" PRIu64 " optimization opportunities in %" PRIu64
           " instructions\n", total_findings, total_insns);
    return 0;
}
