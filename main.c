// riscvlint driver: walk the executable sections of a riscv64 ELF,
// run the checks over each, and report findings.
//
// The exit status follows the grep convention: 0 for a clean scan, 1
// when any opportunity was found, 2 on a tool failure -- a bad
// invocation, an unreadable or malformed file, an allocation failure.
// Without the third value a CI job cannot tell a dirty scan from a
// broken run, and `riscvlint ./bianry && echo clean` reports a typo as
// a clean binary.

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
#define ET_REL        1
#define EM_RISCV      243
#define SHT_PROGBITS  1
#define SHT_SYMTAB    2
#define SHT_RELA      4
#define SHT_NOBITS    8
#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
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

typedef struct {
    const char *title;
    uint64_t count;
} tally_entry;

// One entry per finding class that actually fired. The table grows instead
// of stopping at a fixed bound: a dropped class leaves the summary silently
// disagreeing with the total below it, and the bound is easy to outgrow
// without noticing when a check is added.
static tally_entry *tally;
static size_t ntitles, ntitles_cap;
// -v: print each opportunity as it is found, ahead of the by-type
// summary. Off by default, which is armlint's and x86lint's polarity
// and the only one that makes a bare invocation useful: libxul has
// 567,706 findings, and printing them plus their disassembly is not a
// report anyone asked for. `-q` asks for that default and is kept as a
// no-op so the corpus-scale invocations that passed it still work.
static bool verbose;
// -i: report which extensions the binary uses instead of what it could
// drop. It replaces the lint scan rather than adding to it -- the two
// answer different questions and nothing in the census is a finding.
static bool census_mode;
// -m replaces what the object declares, in both directions: it enables a
// gated check against a declaration that omits the extension ("what
// would rebuilding for RVA23 buy me?") and disables one against an
// object that declares nothing ("this Go binary is going on rv64gc
// hardware"). Neither is expressible if the flag merely unions.
static unsigned forced_exts;
static bool have_forced;
// -c: also report the constants the code materializes, tallied by value
// and ranked by what they cost. An additional report rather than a
// replacement, as armlint's is: it answers a question about the binary
// that the findings do not.
static bool cchain_mode;
// --json: the findings as a document keyed by absolute address instead
// of the human report. It replaces that report rather than adding to
// it, so the notes and the summary stay off stdout under it.
static bool json_mode;
static uint64_t total_findings;
static uint64_t total_insns;
// Bytes the scan stepped over without linting: halfwords this capstone
// build could not decode. Reported so that a resynchronized sweep of a
// data-laden section is not read as a clean one.
static uint64_t total_skipped;

// ---- the by-function tally ----
//
// A whole-binary count says how much there is; this says where to
// start. Keyed by the name the -v annotation prints, so the two cannot
// disagree about which function a finding is in.
//
// A hash rather than the by-type table's linear scan: that one has one
// entry per check and this has one per function with a finding, which
// in `gh` is tens of thousands against 1,358,204 findings.
typedef struct {
    char *name;             // owned: the file is unmapped before printing
    uint64_t count;
} func_entry;

static func_entry *func_tally;
static size_t func_cap, func_used;
// Findings the symbol tables and Go's table both place under no
// function: code before a section's first symbol, or past the end of a
// sized one. Counted apart rather than attributed to the nearest
// neighbour, which would be a guess dressed as a fact.
static uint64_t func_unattributed;

static uint64_t name_hash(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ull;             // FNV-1a
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 0x100000001b3ull;
    }
    return h;
}

static bool func_tally_grow(void)
{
    size_t cap = func_cap ? func_cap * 2 : 1024;
    func_entry *old = func_tally;
    size_t old_cap = func_cap;
    func_entry *grown = calloc(cap, sizeof *grown);
    if (!grown) return false;
    func_tally = grown;
    func_cap = cap;
    func_used = 0;
    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].name) continue;
        // Rehash by moving the owned pointer rather than copying the
        // string again.
        size_t j = name_hash(old[i].name) & (cap - 1);
        while (func_tally[j].name) j = (j + 1) & (cap - 1);
        func_tally[j] = old[i];
        func_used++;
    }
    free(old);
    return true;
}

static void func_tally_add(const char *name)
{
    if (func_used * 10 >= func_cap * 7 && !func_tally_grow()) {
        fprintf(stderr, "out of memory tallying functions\n");
        exit(2);
    }
    size_t i = name_hash(name) & (func_cap - 1);
    while (func_tally[i].name) {
        if (strcmp(func_tally[i].name, name) == 0) {
            func_tally[i].count++;
            return;
        }
        i = (i + 1) & (func_cap - 1);
    }
    // The name points into the mapped file, which is unmapped before
    // the summary prints, so it has to be copied. Written out rather
    // than reaching for strdup, which -std=c11 does not declare.
    size_t len = strlen(name);
    char *owned = malloc(len + 1);
    if (owned) memcpy(owned, name, len + 1);
    if (!owned) {
        fprintf(stderr, "out of memory tallying functions\n");
        exit(2);
    }
    func_tally[i].name = owned;
    func_tally[i].count = 1;
    func_used++;
}

static int cmp_func(const void *a, const void *b)
{
    const func_entry *fa = a, *fb = b;
    if (fa->count != fb->count) return fb->count > fa->count ? 1 : -1;
    return strcmp(fa->name, fb->name);
}

#define FUNC_TOP 10

static void func_tally_print(void)
{
    // Nothing to attribute against -- a Debian C++ or Rust binary --
    // leaves this out rather than printing one row saying so.
    if (!func_used) return;

    func_entry *rows = malloc(func_used * sizeof *rows);
    if (!rows) return;
    size_t n = 0;
    for (size_t i = 0; i < func_cap; i++)
        if (func_tally[i].name) rows[n++] = func_tally[i];
    qsort(rows, n, sizeof rows[0], cmp_func);

    printf("Optimization opportunities by function:\n");
    size_t shown = n < FUNC_TOP ? n : FUNC_TOP;
    for (size_t i = 0; i < shown; i++)
        printf("%8" PRIu64 "  %s\n", rows[i].count, rows[i].name);
    if (n > shown) {
        uint64_t rest = 0;
        for (size_t i = shown; i < n; i++) rest += rows[i].count;
        printf("%8" PRIu64 "  in %zu more function%s\n", rest, n - shown,
               n - shown == 1 ? "" : "s");
    }
    if (func_unattributed)
        printf("%8" PRIu64 "  outside every function range\n",
               func_unattributed);
    printf("\n");
    free(rows);
}

static void tally_add(const char *title)
{
    for (size_t i = 0; i < ntitles; i++)
        if (strcmp(tally[i].title, title) == 0) { tally[i].count++; return; }
    if (ntitles == ntitles_cap) {
        size_t cap = ntitles_cap ? ntitles_cap * 2 : 32;
        tally_entry *grown = realloc(tally, cap * sizeof *grown);
        if (!grown) {
            fprintf(stderr, "out of memory tallying findings\n");
            exit(2);
        }
        tally = grown;
        ntitles_cap = cap;
    }
    tally[ntitles].title = title;
    tally[ntitles].count = 1;
    ntitles++;
}

// ---- Go's pclntab ----
//
// A Go binary carries nothing this driver could attribute a finding
// against: `golang-1.26-go--compile` has zero STT_FUNC symbols, and no
// corpus object has a `.symtab` at all. Its runtime's own function
// table does survive the strip, because traceback needs it, and it is
// what names the Go half of the corpus -- 12 of 29 objects, the largest
// cohort here.
//
// The layout is runtime.pcHeader (runtime/symtab.go) followed by the
// regions its offsets name. Only two of them are needed for a name: the
// functab, an array of nfunc+1 {uint32 entryoff, uint32 funcoff} pairs
// sorted by entryoff, and funcnametab, which the `_func` record at each
// funcoff indexes with its second field.

#define GO_PCLN_MAGIC_118 0xfffffff0u   // Go 1.18 and 1.19
#define GO_PCLN_MAGIC_120 0xfffffff1u   // Go 1.20 and later

typedef struct {
    const uint8_t *functab;     // nfunc+1 entries, 8 bytes each
    const uint8_t *funcdata;    // the _func records funcoff indexes
    size_t funcdata_len;
    const char *funcname;       // funcnametab
    size_t funcname_len;
    uint64_t nfunc;
    uint64_t text;              // what entryoff is relative to
    bool valid;
} go_functab;

static uint32_t go_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

// entryoff and funcoff of functab entry `i`, which may be the sentinel
// at index nfunc.
static void go_entry(const go_functab *g, uint64_t i, uint32_t *entryoff,
                     uint32_t *funcoff)
{
    *entryoff = go_u32(g->functab + i * 8);
    *funcoff = go_u32(g->functab + i * 8 + 4);
}

// The name at a functab index, or NULL where the record or the string
// is out of bounds. The `_func` record's first two fields are entryOff
// (uint32) and nameOff (int32 into funcnametab); they have been the
// first two since Go 1.18 and are all a name needs.
static const char *go_name(const go_functab *g, uint64_t i)
{
    uint32_t entryoff, funcoff;
    go_entry(g, i, &entryoff, &funcoff);
    if (funcoff > g->funcdata_len || g->funcdata_len - funcoff < 8)
        return NULL;
    uint32_t nameoff = go_u32(g->funcdata + funcoff + 4);
    if (nameoff >= g->funcname_len) return NULL;
    // The region must hold a terminator, or the name runs off the end.
    if (!memchr(g->funcname + nameoff, '\0', g->funcname_len - nameoff))
        return NULL;
    return g->funcname + nameoff;
}

// Walk every entry once and refuse the table unless all of it holds
// together. A header field this driver cannot sanity-check is a wrong
// function name on every finding in the file, which is worse than no
// name: the whole point of the annotation is to be trusted.
static bool go_validate(const go_functab *g, const uint8_t *base,
                        const Elf64_Ehdr *eh)
{
    uint32_t prev = 0;
    for (uint64_t i = 0; i <= g->nfunc; i++) {
        uint32_t entryoff, funcoff;
        go_entry(g, i, &entryoff, &funcoff);
        if (i && entryoff < prev) return false;      // the runtime binary
        prev = entryoff;                             // searches it sorted
        if (i == g->nfunc) break;                    // sentinel: no record
        if (!go_name(g, i)) return false;
    }
    // Every function has to land in an executable section, which is
    // what catches a wrong text base: the offsets are small and a base
    // that is off by the load address puts all of them nowhere.
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    uint64_t lo = g->text, hi = g->text + prev;
    if (hi < lo) return false;
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_EXECINSTR) == 0) continue;
        if (sh[i].sh_type != SHT_PROGBITS) continue;
        if (lo >= sh[i].sh_addr && hi <= sh[i].sh_addr + sh[i].sh_size)
            return true;
    }
    return false;
}

static go_functab go_read(const uint8_t *base, size_t map_len,
                          const Elf64_Ehdr *eh)
{
    go_functab g;
    memset(&g, 0, sizeof g);

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    const Elf64_Shdr *pcln = NULL, *text = NULL;
    const char *shstr = NULL;
    size_t shstr_len = 0;
    if (eh->e_shstrndx < eh->e_shnum) {
        const Elf64_Shdr *s = &sh[eh->e_shstrndx];
        if (s->sh_offset < map_len && s->sh_size &&
            s->sh_size <= map_len - s->sh_offset &&
            base[s->sh_offset + s->sh_size - 1] == '\0') {
            shstr = (const char *)(base + s->sh_offset);
            shstr_len = s->sh_size;
        }
    }
    if (!shstr) return g;
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_name >= shstr_len) continue;
        const char *name = shstr + sh[i].sh_name;
        if (sh[i].sh_offset > map_len ||
            sh[i].sh_size > map_len - sh[i].sh_offset)
            continue;
        if (strcmp(name, ".gopclntab") == 0) pcln = &sh[i];
        else if (strcmp(name, ".text") == 0) text = &sh[i];
    }
    // Found by section name only. x86lint also scans the data sections
    // for the header, which is what a binary whose section names were
    // stripped needs; every Go object in this corpus names it, so that
    // is a measurement away rather than written on spec.
    if (!pcln || pcln->sh_size < 72) return g;

    const uint8_t *h = base + pcln->sh_offset;
    uint32_t magic = go_u32(h);
    if (magic != GO_PCLN_MAGIC_118 && magic != GO_PCLN_MAGIC_120) return g;
    if (h[4] || h[5]) return g;                     // pad1, pad2
    unsigned min_lc = h[6], ptr_size = h[7];
    // riscv64 is 8-byte pointers, and minLC is 2 with the C extension
    // and 4 without -- both appear in this corpus.
    if (ptr_size != 8 || (min_lc != 2 && min_lc != 4)) return g;

    uint64_t f[8];
    for (unsigned i = 0; i < 8; i++) memcpy(&f[i], h + 8 + i * 8, 8);
    // f[] is nfunc, nfiles, textStart, funcnameOffset, cuOffset,
    // filetabOffset, pctabOffset, pclnOffset.
    uint64_t nfunc = f[0], text_start = f[2], funcname_off = f[3];
    uint64_t cu_off = f[4], pcln_off = f[7];
    if (!nfunc || nfunc > (1u << 24)) return g;
    if (funcname_off >= cu_off || cu_off > pcln->sh_size) return g;
    if (pcln_off >= pcln->sh_size) return g;
    // nfunc+1 entries: the last is a sentinel carrying the end of the
    // text the table covers.
    if ((pcln->sh_size - pcln_off) / 8 < nfunc + 1) return g;

    g.functab = h + pcln_off;
    g.funcdata = h + pcln_off;
    g.funcdata_len = pcln->sh_size - pcln_off;
    g.funcname = (const char *)(h + funcname_off);
    g.funcname_len = cu_off - funcname_off;
    g.nfunc = nfunc;

    // The header's textStart is not to be trusted: of this corpus's Go
    // objects it is 0 in `gofmt` and `compile` and right in `gh`, so
    // two thirds of them would place every function at the bottom of
    // the address space. Try it when it is set, then the section
    // layout, and take whichever the whole table validates against --
    // entryoff 0 is the first function either way.
    uint64_t candidates[2];
    unsigned ncand = 0;
    if (text_start) candidates[ncand++] = text_start;
    if (text && text->sh_addr) candidates[ncand++] = text->sh_addr;
    for (unsigned i = 0; i < ncand; i++) {
        g.text = candidates[i];
        if (go_validate(&g, base, eh)) {
            g.valid = true;
            return g;
        }
    }
    memset(&g, 0, sizeof g);
    return g;
}

// Nearest preceding Go function, bounded by where the next one starts.
static const char *go_symbolize(const go_functab *g, uint64_t addr,
                                uint64_t *delta)
{
    if (!g->valid || addr < g->text) return NULL;
    uint64_t off = addr - g->text;
    if (off > 0xffffffffu) return NULL;

    // The last entry whose entryoff does not pass `off`. The sentinel
    // at nfunc is the end of the covered text, so an address at or past
    // it belongs to no function.
    uint64_t lo = 0, hi = g->nfunc;             // invariant: answer < hi
    while (hi - lo > 1) {
        uint64_t mid = lo + (hi - lo) / 2;
        uint32_t entryoff, funcoff;
        go_entry(g, mid, &entryoff, &funcoff);
        if (entryoff <= off) lo = mid;
        else hi = mid;
    }
    uint32_t entryoff, funcoff;
    go_entry(g, lo, &entryoff, &funcoff);
    if (entryoff > off) return NULL;
    uint32_t sentinel, unused;
    go_entry(g, g->nfunc, &sentinel, &unused);
    if (off >= sentinel) return NULL;

    // Go's riscv64 linker emits a `$x<arch string>` entry beside each
    // cgo function -- the ISA mapping symbol, sharing its address and
    // sorting after it. 12 of gh's 32,233 entries and 12 of restic's,
    // and naming a finding after one would be absurd, so step back off
    // them to the function they mark.
    while (lo > 0) {
        const char *name = go_name(g, lo);
        if (name && name[0] != '$') break;
        uint32_t prev_entry, prev_func;
        go_entry(g, lo - 1, &prev_entry, &prev_func);
        if (prev_entry != entryoff) break;      // a different function
        lo--;
    }
    const char *name = go_name(g, lo);
    if (!name || !name[0] || name[0] == '$') return NULL;
    go_entry(g, lo, &entryoff, &funcoff);
    *delta = off - entryoff;
    return name;
}

// Nearest preceding function symbol, for the "<name+0x..>" in a
// finding. The ELF symbol table first, since it is what a locally built
// object carries, then Go's own table.
static const char *symbolize(const uint8_t *base, size_t map_len,
                             const Elf64_Ehdr *eh, const go_functab *go,
                             uint64_t addr, uint64_t *delta)
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
    if (!best) return go ? go_symbolize(go, addr, delta) : NULL;
    *delta = addr - best_val;
    return best;
}

// What a finding needs to be printed that the finding itself does not
// carry: the container it came out of. Passed to riscvlint_scan as the
// callback's ctx.
typedef struct {
    csh handle;
    const riscvlint_state *state;
    const uint8_t *base;
    size_t map_len;
    const Elf64_Ehdr *eh;
    const go_functab *go;
    const char *section;    // name of the section being scanned
} report_ctx;

// Walk the instructions a finding covers, disassembled fresh from the
// file so the report shows exactly what is in it. Each one's text goes
// through `line`; its encoding is appended to `bytes` while that has
// room. Returns how many instructions were decoded and writes their
// total byte length to `*len`, which is the true length whether or not
// the bytes fit: a run of zero stores has no fixed bound, and reporting
// a short length for one would be worse than reporting no bytes.
static unsigned walk_finding(const report_ctx *c, const riscvlint_finding *f,
                             void (*line)(void *, unsigned, const cs_insn *),
                             void *lctx, uint8_t *bytes, size_t cap,
                             size_t *len)
{
    if (len) *len = 0;
    cs_insn *insn = cs_malloc(c->handle);
    if (!insn) return 0;
    unsigned n = 0;
    uint64_t addr = f->address;
    for (unsigned i = 0; i < f->insn_count; i++) {
        uint32_t w;
        if (!riscvlint_word_at(c->state, addr, &w)) break;
        uint8_t buf[4];
        memcpy(buf, &w, 4);
        const uint8_t *p = buf;
        size_t remain = 4;
        uint64_t a = addr;
        if (!cs_disasm_iter(c->handle, &p, &remain, &a, insn)) break;
        if (line) line(lctx, i, insn);
        if (len) {
            if (bytes && *len + insn->size <= cap)
                memcpy(bytes + *len, buf, insn->size);
            *len += insn->size;
        }
        n++;
        addr = a;
    }
    cs_free(insn, 1);
    return n;
}

static void print_line(void *ctx, unsigned i, const cs_insn *insn)
{
    (void)ctx; (void)i;
    printf("  %s %s\n", insn->mnemonic, insn->op_str);
}

static void report(void *ctx, const riscvlint_finding *f)
{
    const report_ctx *c = ctx;
    tally_add(f->title);
    total_findings++;

    // Looked up in every mode, not only under -v: the by-function
    // summary is keyed by the same name the annotation prints, so the
    // two cannot disagree about where a finding is.
    uint64_t delta = 0;
    const char *sym = symbolize(c->base, c->map_len, c->eh, c->go,
                                f->address, &delta);
    if (sym) func_tally_add(sym);
    else func_unattributed++;

    if (!verbose) return;
    printf("%s at offset: 0x%" PRIx64, f->title, f->address);
    if (sym) {
        if (delta) printf(" <%s+0x%" PRIx64 ">", sym, delta);
        else printf(" <%s>", sym);
    }
    printf(": -> %s (%u instructions)\n", f->replacement, f->insn_count);
    walk_finding(c, f, print_line, NULL, NULL, 0, NULL);
    printf("\n");
}

// ---- --json ----
//
// The findings as one document per input file, keyed by absolute
// address. x86lint's and armlint's shape, with the differences RISC-V
// forces: a finding spans a window of whole instructions, so `text` is
// an array of lines rather than one string, and `length` is a sum of
// 2-byte and 4-byte encodings rather than a multiple of four.
//
// `vaddr` is absolute and a number rather than a hex string, which is
// the point of the mode: findings compose with arithmetic and so join
// against anything else keyed by address.
//
// `arch` and `extensions` carry what the human report's `note:` lines
// say, because a gated finding means nothing without them -- a Zcb
// finding against an object that declares no Zcb is the answer to "what
// would rebuilding buy me", not a defect.

#define JSON_BYTES_MAX 256      // 64 instructions, see json_finding

static bool json_first;         // no finding written to this document yet
// The running totals as they stood when this file's document opened:
// each document reports its own file's share, and the driver's counters
// are cumulative across the argument list.
static uint64_t json_insns, json_skipped, json_findings;

// Copy a string from the file into a JSON string body. Section and
// symbol names are whatever bytes the file holds, so only what JSON
// requires is escaped and everything else is passed through: a binary
// whose string tables are not UTF-8 yields strings that are not either.
static void json_puts(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20) printf("\\u%04x", *p);
            else putchar(*p);
        }
    }
}

static void json_line(void *ctx, unsigned i, const cs_insn *insn)
{
    (void)ctx;
    if (i) fputs(", ", stdout);
    putchar('"');
    json_puts(insn->mnemonic);
    if (insn->op_str[0]) {
        putchar(' ');
        json_puts(insn->op_str);
    }
    putchar('"');
}

static void json_finding(void *ctx, const riscvlint_finding *f)
{
    const report_ctx *c = ctx;
    tally_add(f->title);
    total_findings++;

    // Streamed as they are found rather than collected first: libxul
    // has 567,706 of them, which is not a document to hold in memory.
    fputs(json_first ? "    {" : ",\n    {", stdout);
    json_first = false;
    printf("\"vaddr\": %" PRIu64 ", \"check\": \"", f->address);
    json_puts(f->title);
    fputs("\", \"detail\": \"", stdout);
    json_puts(f->replacement);
    fputs("\", \"section\": \"", stdout);
    json_puts(c->section ? c->section : "");
    putchar('"');

    uint64_t delta = 0;
    const char *sym = symbolize(c->base, c->map_len, c->eh, c->go,
                                f->address, &delta);
    if (sym) {
        fputs(", \"function\": \"", stdout);
        json_puts(sym);
        printf("\", \"function_offset\": %" PRIu64, delta);
    }

    // Enough for every check but an unbounded run of zero stores, whose
    // window has no fixed size. `length` is still exact there; `bytes`
    // is omitted rather than truncated, so a consumer never reads a
    // short encoding as the whole finding.
    uint8_t bytes[JSON_BYTES_MAX];
    size_t len = 0;
    fputs(", \"text\": [", stdout);
    walk_finding(c, f, json_line, NULL, bytes, sizeof bytes, &len);
    printf("], \"length\": %zu", len);
    if (len && len <= sizeof bytes) {
        fputs(", \"bytes\": \"", stdout);
        for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
        putchar('"');
    }
    putchar('}');
}

// ---- the image, for the checks that resolve an address into data ----

typedef struct {
    const uint8_t *base;
    size_t map_len;
    const Elf64_Ehdr *eh;
} image;

// riscvlint_read_fn over the mapped file. Only allocated, non-writable
// sections with contents are served, which is the contract
// riscvlint_state_set_image states and the reason
// check_fp_pool_to_fli's rewrite is sound: a constant the program can
// overwrite is not a constant, and a section the dynamic linker
// relocates into is writable at load time precisely so that it can be.
// `.rodata` qualifies; `.data` and `.data.rel.ro` do not.
static bool image_read(void *ctx, uint64_t vaddr, void *out, size_t n)
{
    const image *im = ctx;
    // A relocatable object's sections all sit at address 0, so "the
    // section containing this address" names nothing. Serving reads
    // there would hand back whichever section matched first, which for
    // a .o is usually .text -- the code, read as data.
    if (im->eh->e_type == ET_REL) return false;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(im->base + im->eh->e_shoff);
    for (unsigned i = 0; i < im->eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_ALLOC) == 0) continue;
        if (sh[i].sh_flags & SHF_WRITE) continue;
        if (sh[i].sh_type == SHT_NOBITS) continue;   // .bss has no contents
        if (!sh[i].sh_addr || !sh[i].sh_size) continue;
        if (vaddr < sh[i].sh_addr) continue;
        uint64_t off = vaddr - sh[i].sh_addr;
        if (off >= sh[i].sh_size || sh[i].sh_size - off < n) continue;
        if (sh[i].sh_offset > im->map_len ||
            sh[i].sh_size > im->map_len - sh[i].sh_offset)
            continue;
        memcpy(out, im->base + sh[i].sh_offset + off, n);
        return true;
    }
    return false;
}

// ---- the hooks the constant census needs ----

typedef struct {
    const uint8_t *base;
    size_t map_len;
    const Elf64_Ehdr *eh;
    const go_functab *go;
} anchor_ctx;

// riscvlint_mapped_fn: whether a value addresses something the file
// maps. Program data only -- SHT_PROGBITS and the .bss-shaped
// SHT_NOBITS -- not the linker's own metadata, which in a shared object
// is everything at the low addresses a small literal collides with.
// libLLVM's first PROGBITS section is at 0xe5ef80 and the nine below it
// are notes, symbol and version tables, hashes, strings and
// relocations; without this test `0xffff` and `0xc00` read as addresses
// because they land in `.dynstr`.
//
// This stays a heuristic, and the irreducible part is a literal that
// numerically coincides with real program data: libLLVM builds
// `0x7ffffff` 696 times, which is 2^27-1 and a mask, and it falls
// inside a loaded section all the same. Nothing in the bytes tells the
// two apart once the linker has consumed the relocation that did.
static bool value_is_mapped(void *ctx, uint64_t value)
{
    const anchor_ctx *a = ctx;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(a->base + a->eh->e_shoff);
    for (unsigned i = 0; i < a->eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_ALLOC) == 0) continue;
        if (sh[i].sh_type != SHT_PROGBITS && sh[i].sh_type != SHT_NOBITS)
            continue;
        if (!sh[i].sh_addr || !sh[i].sh_size) continue;
        if (value >= sh[i].sh_addr && value < sh[i].sh_addr + sh[i].sh_size)
            return true;
    }
    return false;
}

// riscvlint_anchor_fn: the start of the function holding `addr`, which
// is its identity. Derived from the same lookup the annotation and the
// by-function summary use, so all three agree on what a function is.
static uint64_t anchor_of(void *ctx, uint64_t addr)
{
    const anchor_ctx *a = ctx;
    uint64_t delta = 0;
    if (!symbolize(a->base, a->map_len, a->eh, a->go, addr, &delta))
        return 0;
    return addr - delta;
}

// ---- scanning ----

static void scan_section(csh handle, riscvlint_state *state,
                         const uint8_t *code, size_t size, uint64_t vaddr,
                         const uint8_t *base, size_t map_len,
                         const Elf64_Ehdr *eh, const go_functab *go,
                         const char *name)
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

    report_ctx ctx = { handle, state, base, map_len, eh, go, name };
    riscvlint_scan(state, handle, code, size, vaddr,
                   json_mode ? json_finding : report, &ctx,
                   &total_insns, &total_skipped);
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
        const char *arch = find_arch_string(base, map_len, eh);
        image im = { base, map_len, eh };
        // Read once per file rather than per finding: validating it is
        // a walk of every entry.
        go_functab go = go_read(base, map_len, eh);
        // The census reads the arch string for its own report and gates
        // nothing on it, so it needs no state and no extension mask.
        riscvlint_state *state = NULL;
        riscvlint_census *census = NULL;
        anchor_ctx actx = { base, map_len, eh, &go };
        riscvlint_cchain *cchain = NULL;
        if (cchain_mode) {
            cchain = riscvlint_cchain_create();
            if (!cchain) { munmap((void *)base, map_len); return -1; }
            riscvlint_cchain_set_hooks(cchain, value_is_mapped, &actx,
                                       anchor_of, &actx);
        }
        if (census_mode) {
            census = riscvlint_census_create();
            if (!census) { munmap((void *)base, map_len); return -1; }
        } else {
            state = riscvlint_state_create();
            if (!state) { munmap((void *)base, map_len); return -1; }
            // Say which extension set is in force whenever it was not
            // simply read from the object. Reporting a Zba finding
            // because nothing said otherwise is a guess, and a guess the
            // reader cannot see is the shape of every wrong number this
            // project has produced.
            unsigned declared = riscvlint_parse_arch(arch);
            unsigned effective;
            const char *source;
            if (have_forced) {
                effective = forced_exts | RISCVLINT_EXT_DECLARED;
                source = "forced";
                if (declared & RISCVLINT_EXT_DECLARED && !json_mode)
                    printf("note: %s: -m overrides the arch declared in the "
                           "object\n", path);
            } else {
                effective = declared;
                source = declared & RISCVLINT_EXT_DECLARED ? "declared"
                                                           : "unrestricted";
                if (!(declared & RISCVLINT_EXT_DECLARED) && !json_mode)
                    printf("note: %s: no RISC-V arch attributes; "
                           "extension-gated checks left unrestricted "
                           "(pass -m to pin)\n", path);
            }
            riscvlint_state_set_extensions(state, effective);
            riscvlint_state_set_image(state, image_read, &im);
            // The two notes above as fields: a reader of the document
            // needs them for the same reason a reader of the report
            // does, and stdout is the document's now.
            if (json_mode) {
                fputs("{\"file\": \"", stdout);
                json_puts(path);
                fputs("\", \"arch\": ", stdout);
                if (arch) {
                    putchar('"');
                    json_puts(arch);
                    putchar('"');
                } else {
                    fputs("null", stdout);
                }
                printf(", \"extensions\": \"%s\",\n  \"findings\": [\n",
                       source);
                json_first = true;
            }
        }
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
        // The section header string table, for --json's `section`. A
        // name is used only when its offset lands inside the table and
        // the table's last byte is a NUL, so a truncated or hostile
        // table yields no name rather than a read off the end.
        const char *shstr = NULL;
        size_t shstr_len = 0;
        if (eh->e_shstrndx < eh->e_shnum) {
            const Elf64_Shdr *s = &sh[eh->e_shstrndx];
            if (s->sh_offset < map_len && s->sh_size &&
                s->sh_size <= map_len - s->sh_offset &&
                base[s->sh_offset + s->sh_size - 1] == '\0') {
                shstr = (const char *)(base + s->sh_offset);
                shstr_len = s->sh_size;
            }
        }
        for (unsigned i = 0; i < eh->e_shnum; i++) {
            if ((sh[i].sh_flags & SHF_EXECINSTR) == 0 ||
                sh[i].sh_type != SHT_PROGBITS || sh[i].sh_size == 0)
                continue;
            if (sh[i].sh_offset > map_len ||
                sh[i].sh_size > map_len - sh[i].sh_offset)
                continue;
            if (cchain) {
                // The scan wants the side-entry map to know where a
                // branch lands, and only the lint state builds one. A
                // -i -c run has no state, so the chains a target splits
                // are read as one -- stated in the report rather than
                // silently absorbed.
                if (state &&
                    riscvlint_state_set_section(state, handle,
                                                base + sh[i].sh_offset,
                                                sh[i].sh_size, sh[i].sh_addr))
                    riscvlint_cchain_scan(cchain, handle, state,
                                          base + sh[i].sh_offset,
                                          sh[i].sh_size, sh[i].sh_addr);
                else
                    riscvlint_cchain_scan(cchain, handle, NULL,
                                          base + sh[i].sh_offset,
                                          sh[i].sh_size, sh[i].sh_addr);
            }
            if (census)
                riscvlint_census_scan(census, handle, base + sh[i].sh_offset,
                                      sh[i].sh_size, sh[i].sh_addr);
            else
                scan_section(handle, state, base + sh[i].sh_offset,
                             sh[i].sh_size, sh[i].sh_addr, base, map_len, eh,
                             &go,
                             shstr && sh[i].sh_name < shstr_len
                                 ? shstr + sh[i].sh_name : NULL);
        }
        if (json_mode && !census) {
            // The totals close the document because the scan only knows
            // them then. They are this file's share, which is why they
            // are recorded before the next file resets them.
            printf("%s  ],\n  \"instructions\": %" PRIu64
                   ", \"skipped\": %" PRIu64 ", \"opportunities\": %" PRIu64
                   "}\n", json_first ? "" : "\n",
                   total_insns - json_insns, total_skipped - json_skipped,
                   total_findings - json_findings);
            json_insns = total_insns;
            json_skipped = total_skipped;
            json_findings = total_findings;
        }
        if (census) {
            // -v adds the sample addresses, which are the census's
            // per-finding detail: the same thing -v adds to a scan.
            riscvlint_census_print(census, path, arch, verbose);
            riscvlint_census_destroy(census);
        } else {
            riscvlint_state_destroy(state);
        }
        if (cchain) {
            riscvlint_cchain_print(cchain, path, verbose);
            riscvlint_cchain_destroy(cchain);
        }
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
        "usage: %s [-v] [-i] [-c] [--json] "
        "[-m zba|zbb|zbs|zcb|zfa|zilx|zibi|c|rva20|rva22|rva23]... "
        "<binary>...\n";
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-' && argv[argi][1]) {
        if (strcmp(argv[argi], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[argi], "-q") == 0) {
            // What the default already does. Accepted silently rather
            // than refused or warned about: it was the flag for
            // corpus-scale runs, and those are the last place to add a
            // line of noise.
        } else if (strcmp(argv[argi], "-i") == 0) {
            census_mode = true;
        } else if (strcmp(argv[argi], "-c") == 0) {
            cchain_mode = true;
        } else if (strcmp(argv[argi], "--json") == 0) {
            json_mode = true;
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
    // -m pins what the checks may assume, and the census assumes
    // nothing: it reports the extensions that are there. Saying so beats
    // ignoring a flag the caller thought was doing something.
    if (census_mode && have_forced)
        fprintf(stderr, "%s: -m has no effect with -i; the census reports "
                "what the binary uses\n", argv[0]);
    // --json describes the lint scan. The census is a separate report
    // whose output would interleave with the document, so the two are
    // refused rather than one of them chosen for the caller.
    if (census_mode && json_mode) {
        fprintf(stderr, "%s: --json and -i are separate reports; pick one\n",
                argv[0]);
        return 2;
    }
    // -v prints the human report's per-finding half, which would
    // interleave with the document line for line. Refused for the same
    // reason -i is: the caller gets to pick, rather than being picked
    // for.
    if (json_mode && verbose) {
        fprintf(stderr, "%s: --json and -v are separate reports; pick one\n",
                argv[0]);
        return 2;
    }
    if (json_mode && cchain_mode) {
        fprintf(stderr, "%s: --json and -c are separate reports; pick one\n",
                argv[0]);
        return 2;
    }
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RISCVLINT_CS_MODE, &handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    unsigned failures = 0;
    for (; argi < argc; argi++)
        if (scan_file(handle, argv[argi]) != 0) failures++;
    cs_close(&handle);

    // The census is the whole report of a -i run; there are no findings
    // to summarize below it. It is a description of the file rather than
    // a verdict on it, so it never sets the "found something" status --
    // but a file that could not be read is still a tool failure.
    if (census_mode) return failures ? 2 : 0;

    // --json already closed each file's document with that file's
    // totals; there is no cross-file summary to print below them.
    if (!json_mode) {
        if (ntitles) {
            qsort(tally, ntitles, sizeof tally[0], cmp_tally);
            printf("Optimization opportunities by type:\n");
            for (size_t i = 0; i < ntitles; i++)
                printf("%8" PRIu64 "  %s\n", tally[i].count, tally[i].title);
            printf("\n");
        }
        func_tally_print();
        // Only when there were any, so the usual run is unchanged: a
        // scan that resynchronized past undecodable halfwords is not a
        // clean sweep of the section, and nothing else said so.
        if (total_skipped)
            printf("%" PRIu64 " bytes skipped unlinted\n", total_skipped);
        printf("%" PRIu64 " optimization opportunities in %" PRIu64
               " instructions\n", total_findings, total_insns);
    }
    // A tool failure outranks a dirty scan: if one of five files could
    // not be read, what the other four reported is not the answer to the
    // question that was asked.
    if (failures) return 2;
    return total_findings ? 1 : 0;
}
