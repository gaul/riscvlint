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

// ---- analysis state ----
//
// One section at a time. The state owns the side-entry map, which is
// what keeps a check from rewriting a pair that something branches into
// the middle of.

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
// Measured population: 30,175 sites across the corpus, 30,119 of them in
// Rust binaries, 0 in C++ (libLLVM's text is far past jal's reach). See
// TODO.md.
bool check_call_pair_to_jal(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

#endif  // RISCVLINT_H
