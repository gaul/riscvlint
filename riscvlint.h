// riscvlint: static checker for missed peephole opportunities in
// riscv64 code.
//
// The checks decode raw encodings rather than reading capstone's operand
// model. That is not stylistic: capstone's RISC-V model has holes in
// exactly the places a call-shaped check cares about -- it reports no
// register write for the ra-implicit link aliases (`jal <imm>`,
// `jalr <rs>`) and marks `jalr ra,<off>(<rs>)`, the ordinary PLT call,
// as a jump rather than a call. The mining tools in tools/ lean on that
// model and had to correct it twice; a checker that inherits it reports
// wrong findings to users. Capstone is used here only to iterate
// instructions and to render them for output.

#ifndef RISCVLINT_H
#define RISCVLINT_H

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Every extension a distro riscv64 binary can plausibly contain; the
// vendor sets are excluded because they reuse encoding space. Kept
// identical to the mining tools so the checker and the measurements see
// the same instruction stream.
#define RISCVLINT_CS_MODE                                                  \
    (CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD |                \
     CS_MODE_RISCV_A | CS_MODE_RISCV_V | CS_MODE_RISCV_ZBA |               \
     CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS |           \
     CS_MODE_RISCV_ZBKB | CS_MODE_RISCV_ZBKC | CS_MODE_RISCV_ZBKX |        \
     CS_MODE_RISCV_ZCMP_ZCMT_ZCE)

// ---- raw encoding helpers ----

#define RV_OPCODE(w)   ((uint32_t)(w) & 0x7fu)
#define RV_OP_AUIPC    0x17u
#define RV_OP_JALR     0x67u
#define RV_OP_JAL      0x6fu

// U-type: auipc rd, imm20. `imm` is returned already shifted left 12 and
// sign-extended, i.e. the value added to the pc.
bool rv_decode_auipc(uint32_t w, unsigned *rd, int64_t *imm);

// I-type: jalr rd, imm12(rs1), funct3 == 0.
bool rv_decode_jalr(uint32_t w, unsigned *rd, unsigned *rs1, int64_t *imm);

// J-type reach: a 21-bit signed offset whose low bit is implicitly zero.
bool rv_jal_reaches(int64_t offset);

// Instruction length from the low bits of the first halfword: the
// standard encodings are two bytes unless bits [1:0] are both set.
unsigned rv_insn_len(uint32_t w);

// slli and add, in either the 4-byte or the 2-byte spelling. `size`
// selects which encoding to read; c.slli implies rd == rs1, and c.add
// implies rd == rs1 as well, so both hand back the expanded three-
// register form. The compressed forms carry most of this shape in real
// code, so a check that read only the 4-byte encodings would miss the
// majority of its own population.
bool rv_decode_slli(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    unsigned *shamt);
bool rv_decode_add(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                   unsigned *rs2);

// ---- analysis state ----
//
// One section at a time. The state owns the side-entry map, which is
// what keeps a check from rewriting a pair that something branches into
// the middle of.

// Extensions the object declares in Tag_RISCV_arch. Suggesting an
// instruction the target does not implement is worse than staying quiet,
// so every Zb-shaped check is gated on this.
//
// The gate is deliberately three-valued rather than two. Go emits no
// .riscv.attributes section at all, and Go binaries hold essentially the
// whole shift-add population -- so treating "absent" as "no" would
// silence the check on exactly the code it exists for. A check suppresses
// itself only on positive evidence of absence: attributes that are
// present and do not name the extension. DECLARED records which case a
// given object is.
typedef enum {
    RISCVLINT_EXT_ZBA = 1u << 0,
    RISCVLINT_EXT_ZBB = 1u << 1,
    RISCVLINT_EXT_ZBS = 1u << 2,
    RISCVLINT_EXT_DECLARED = 1u << 31,
} riscvlint_ext;

// Parses a Tag_RISCV_arch string such as
// "rv64i2p1_m2p0_a2p1_..._zba1p0_zbb1p0_zbs1p0" into that bitmask, with
// DECLARED set. A NULL string yields 0: nothing known either way.
unsigned riscvlint_parse_arch(const char *arch);


typedef struct riscvlint_state riscvlint_state;

riscvlint_state *riscvlint_state_create(void);
void riscvlint_state_destroy(riscvlint_state *state);

// Installs the section and builds its side-entry map. Returns false if
// the map could not be built, in which case no check should run: without
// it a check cannot tell a fall-through pair from a branch target.
bool riscvlint_state_set_section(riscvlint_state *state, csh handle,
                                 const uint8_t *code, size_t size,
                                 uint64_t vaddr);

// Marks the section offsets that carry a relocation. In an unlinked
// object the immediates of a call sequence are zero placeholders, so a
// range test on them measures nothing; the check skips any instruction
// covered here. Offsets are relative to the section.
void riscvlint_state_set_relocs(riscvlint_state *state,
                                const uint64_t *offsets, size_t count);

void riscvlint_state_set_extensions(riscvlint_state *state, unsigned exts);
unsigned riscvlint_state_extensions(const riscvlint_state *state);

// True unless the object positively declares an arch without `ext`.
bool riscvlint_may_use(const riscvlint_state *state, unsigned ext);

// One -m argument: an extension name (zba, zbb, zbs) or a profile name
// (rva20, rva22, rva23) naming a bundle of them. Returns false for an
// unrecognised name; a recognised name may still yield no bits, since
// rva20 is the baseline and mandates none of the extensions gated here.
// rva22 and rva23 differ only in extensions this checker does not yet
// gate on, so they expand alike.
bool riscvlint_parse_ext_name(const char *name, unsigned *exts);

// True when something branches to `addr`, making it a side entry.
bool riscvlint_is_branch_target(const riscvlint_state *state, uint64_t addr);

// True when the four bytes at `addr` carry a relocation.
bool riscvlint_is_relocated(const riscvlint_state *state, uint64_t addr);

// Reads the 32-bit word at `addr`, or false if it lies outside the
// section or would straddle its end.
bool riscvlint_word_at(const riscvlint_state *state, uint64_t addr,
                       uint32_t *out);

// ---- findings ----

typedef struct {
    const char *title;      // finding class; also the summary tally key
    uint64_t address;       // address of the first instruction covered
    unsigned insn_count;    // how many instructions the finding spans
    char replacement[96];   // the suggested rewrite
} riscvlint_finding;

typedef bool (*riscvlint_check_fn)(riscvlint_state *state,
                                   const cs_insn *insn,
                                   riscvlint_finding *finding);

// ---- checks ----

// A call built as `auipc rd,X` + `jalr rd,Y(rd)` reaches +/-2GB in eight
// bytes and a register dependency. Where the target is inside jal's
// +/-1MB, one four-byte `jal rd,target` does the same job.
//
// The pair is reported only when the jalr's destination is the auipc's
// destination. That is the shape the toolchains emit and it folds
// exactly: both spellings leave the link register holding the address of
// the following instruction. The tail-call spelling `jalr x0,Y(rd)`
// (printed `jr`) is deliberately not reported -- collapsing it to `j`
// would stop writing rd, which is only safe if rd is dead, and that
// needs liveness this check does not have.
//
// Measured population: 89,860 sites across the corpus, 89,804 of them in
// Rust binaries, 0 in C++ (libLLVM's text is far past jal's reach). See
// TODO.md.
bool check_call_pair_to_jal(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

// `slli rd,rs,{1,2,3}` + `add rd,rd,rs2` computes a scaled-index address
// in two dependent instructions; Zba's `sh1add`/`sh2add`/`sh3add` does it
// in one. Reported only when the add writes back the register the slli
// wrote and reads it exactly once, which makes the shifted value dead by
// construction -- no liveness needed. `add rd,rd,rd` is excluded: that
// doubles the shifted value, which is a wider shift rather than a
// shift-add.
//
// Both halves have compressed spellings, and c.slli + c.add is the
// commonest form in the corpus. That case is four bytes either way, so
// the rewrite trades two dependent instructions for one at no size
// change; the finding says which it is.
//
// Gated on Zba: suppressed when the object declares an arch string
// without it, reported when it declares one with it or declares none.
//
// Measured population: 19,933 across the corpus, 19,671 of them in Go
// binaries -- GCC and LLVM already use the extension. See TODO.md.
bool check_slli_add_to_shadd(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding);

#endif  // RISCVLINT_H
