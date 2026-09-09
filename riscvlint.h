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
// vendor sets are excluded because they reuse encoding space, and so is
// Zcmp: it is mutually exclusive with Zcd and occupies the same
// encodings, so enabling both makes capstone read `fsd fs0,24(sp)` as
// `cm.mvsa01 s0,s0` -- an instruction that writes s0 where the real one
// writes no register at all. The corpus declares zcd and not zcmp. Kept
// identical to the mining tools so the checker and the measurements see
// the same instruction stream.
#define RISCVLINT_CS_MODE                                                  \
    (CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD |                \
     CS_MODE_RISCV_A | CS_MODE_RISCV_V | CS_MODE_RISCV_ZBA |               \
     CS_MODE_RISCV_ZBB | CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBS |           \
     CS_MODE_RISCV_ZBKB | CS_MODE_RISCV_ZBKC | CS_MODE_RISCV_ZBKX)

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

// ---- what a result guarantees about its own high bits ----
//
// An extension is redundant when the value it is handed already has the
// form the extension would impose. Deciding that means classifying a
// producer by what its result guarantees, which is a property of the
// instruction rather than of anything downstream -- so unlike every
// other multi-instruction check here, this one needs no liveness query.
//
// The relations between these are one-way and are applied when the
// guarantee is recorded rather than when it is tested: a value known to
// fit 8 bits also fits 16 and 32, and a value sign-extended from bit 7
// is sign-extended from bit 31. Zero-extension to 32 does NOT imply
// sign-extension to 32 -- `lwu` of 0x80000000 is the counter-example,
// and it is why `sext.w` after `lwu` is a real instruction.
enum {
    RISCVLINT_G_SEXT8  = 1u << 0,   // sign-extended from bit 7
    RISCVLINT_G_SEXT16 = 1u << 1,
    RISCVLINT_G_SEXT32 = 1u << 2,
    RISCVLINT_G_ZEXT8  = 1u << 3,   // zero above bit 7
    RISCVLINT_G_ZEXT16 = 1u << 4,
    RISCVLINT_G_ZEXT32 = 1u << 5,
};

// The guarantees `w`'s result carries, with `rd` set to the register it
// writes. 0 when it guarantees nothing, which is the answer for most of
// the ISA and the safe one: a missing guarantee costs a finding.
unsigned rv_result_guarantees(uint32_t w, unsigned size, unsigned *rd);

// True when `w` is one of the extension spellings -- an instruction
// whose only effect is to impose `*guarantee` on `*rs1`. `sext.w` is
// `addiw rd,rs,0` and `zext.w` is `add.uw rd,rs,x0`, so these are
// aliases the raw decode has to recognise rather than mnemonics.
//
// Zcb's two-byte spellings are decoded too, and they are not an
// afterthought: `c.zext.b` and its family are where most of the corpus's
// extension instructions actually are, because the assembler selects
// them whenever the register is in x8-x15. Capstone prints them with the
// wide mnemonic, so an `andi a2,a2,0xff` in a disassembly is as often
// two bytes as four -- which is also why deleting one usually saves two
// bytes rather than four.
bool rv_decode_extension(uint32_t w, unsigned size, unsigned *rd,
                         unsigned *rs1, unsigned *guarantee);

// True when `w` ends a straight-line region: a call or an unconditional
// transfer, in any of their spellings.
bool rv_ends_region(uint32_t w, unsigned size);

// ---- memory accesses ----

typedef enum {
    RV_MEM_NONE = 0,
    RV_MEM_LB, RV_MEM_LH, RV_MEM_LW, RV_MEM_LD,
    RV_MEM_LBU, RV_MEM_LHU, RV_MEM_LWU,
    RV_MEM_SB, RV_MEM_SH, RV_MEM_SW, RV_MEM_SD,
    RV_MEM_FLW, RV_MEM_FLD, RV_MEM_FSW, RV_MEM_FSD,
} rv_mem_kind;

bool rv_mem_is_store(rv_mem_kind k);
bool rv_mem_is_fp(rv_mem_kind k);
const char *rv_mem_name(rv_mem_kind k);

// A load or store, in the four-byte spelling or in a quadrant-0
// compressed one. `data` is the loaded or stored register, in its own
// file: a GPR number for the integer forms and an f-register number for
// the floating-point ones.
//
// The quadrant-2 forms -- `c.ldsp` and its family -- are deliberately
// not decoded. Their base is always sp, so the only way one could pair
// with a preceding address computation is if that computation wrote sp,
// and a check that folds an address into an access has to refuse sp as
// a destination anyway. Skipping them costs nothing.
bool rv_decode_mem(uint32_t w, unsigned size, rv_mem_kind *kind,
                   unsigned *data, unsigned *base, int64_t *off);

// Bytes the access would assemble to with this data register, base and
// offset: 2 when some compressed form can encode it, 4 otherwise. Unlike
// the decoder this does model the quadrant-2 forms, because folding an
// address can *produce* an sp-relative access even though it can never
// consume one -- and reporting such a site as four bytes when the
// assembler will spell it in two understates the finding.
//
// `zcb` says whether the byte and halfword compressed forms are
// available; without them `lbu` and its family are always four bytes.
unsigned rv_mem_encoded_size(rv_mem_kind kind, unsigned data, unsigned base,
                             int64_t off, bool zcb);

// An addition that forms an address, in every spelling that can express
// one: the four-byte `addi`, `c.addi4spn`, `c.addi`, and `c.mv`, which
// is an addition of zero. `c.addi16sp` is left out because it writes sp,
// which the check that uses this refuses as a destination.
bool rv_decode_base_add(uint32_t w, unsigned size, unsigned *rd,
                        unsigned *rs1, int64_t *imm);

// The name of the Zcb two-byte form `w` could be spelled as, or NULL
// when it has none. Only asked of four-byte encodings: the question is
// whether a wide encoding was left wide.
//
// Every Zcb form names its registers with a three-bit field, so x8-x15
// only, and the memory forms carry an unsigned two-bit byte offset or a
// one-bit halfword offset. Those constraints were checked against both
// GNU as and clang before being written down; the two agree everywhere
// except `mul rd,rs1,rd`, which clang compresses by commuting the
// operands and GNU as leaves wide.
const char *rv_zcb_form(uint32_t w, unsigned size);

// True when `w` is an instruction whose only effect is to write one
// general register: the ALU opcodes and their compressed spellings.
// Deleting such an instruction is observationally free once its result
// is known to be dead, which is what makes it a candidate.
bool rv_pure_def(uint32_t w, unsigned size, unsigned *rd);

// addi, in the two spellings that can express a frame-pointer prologue
// or its matching stack restore. `c.addi4spn` is not optional here:
// `addi s0,sp,48` assembles to it, and that is how every frame-pointer
// prologue in the Rust corpus is spelled, so a decoder that read only
// the 4-byte encoding would miss most of the population. The other
// compressed addi forms cannot express either shape -- `c.addi` writes
// the register it reads and `c.addi16sp` writes sp from sp -- so they
// are left out rather than decoded and rejected.
bool rv_decode_addi(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    int64_t *imm);

// srli, in either spelling. The compressed form is CB-format and can
// only name x8-x15, so `srli a6,a6,32` stays four bytes where
// `srli s0,s0,32` does not; c.srai and c.andi share its funct3 and are
// separated by two bits the decoder must check.
bool rv_decode_srli(uint32_t w, unsigned size, unsigned *rd, unsigned *rs1,
                    unsigned *shamt);

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
    RISCVLINT_EXT_ZCB = 1u << 3,
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

// One -m argument: an extension name (zba, zbb, zbs, zcb) or a profile
// name (rva20, rva22, rva23) naming a bundle of them. Returns false for
// an unrecognised name; a recognised name may still yield no bits, since
// rva20 is the baseline and mandates none of the extensions gated here.
//
// rva22 and rva23 no longer expand alike. Zcb was not ratified in time
// for RVA22 and is mandatory in RVA23U64, so it is the first extension
// gated here that tells the two profiles apart -- and on a baseline
// build it is also the largest thing -m has to say.
bool riscvlint_parse_ext_name(const char *name, unsigned *exts);

// True when something branches to `addr`, making it a side entry.
bool riscvlint_is_branch_target(const riscvlint_state *state, uint64_t addr);

// True when the four bytes at `addr` carry a relocation.
bool riscvlint_is_relocated(const riscvlint_state *state, uint64_t addr);

// Liveness of `slot` on every path leaving `addr`, bounded. DEAD only
// when every reachable path redefines the register before reading it;
// READ when a read is found; UNKNOWN for anything ambiguous -- an
// exhausted budget, an indirect jump, a branch out of the section, or a
// call that might read the register as an argument. Only DEAD licenses a
// rewrite.
//
// This is the one place a check consults capstone's register model
// rather than the raw encoding, because answering it by raw decode would
// mean decoding every instruction form in the ISA. The model's known
// RISC-V gap -- no register write on the ra-implicit link aliases, no
// read of ra by `ret` -- is corrected here, and any jal/jalr is treated
// as a call regardless of the group capstone assigns it.
enum { RISCVLINT_LIVE_DEAD, RISCVLINT_LIVE_READ, RISCVLINT_LIVE_UNKNOWN };
int riscvlint_liveness(riscvlint_state *state, uint64_t addr, unsigned rd);

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

// `slli rd,rs,32` + `srli rd,rd,32` clears the upper word in two
// dependent instructions; Zba's `zext.w` (an alias of `add.uw rd,rs,x0`)
// does it in one. Reported only when the srli both reads and overwrites
// the register the slli wrote, so the intermediate is dead by
// construction.
//
// Unlike the shift-add family this shape is essentially always written
// that way: of the sites in the corpus, none use a third register, so
// the population does not shrink when the precondition is applied.
//
// The rewrite is costed at `zext.w`'s four bytes. Zcb has a two-byte
// `c.zext.w` for a destination in x8-x15, which would save two more, but
// claiming it would mean gating on Zcb as well; the figure here is a
// floor on the saving rather than the best case.
//
// Gated on Zba, on the same three-valued rule as the shift-add check.
//
// Measured population: 18,073 across the corpus, all but two of them in
// Go binaries. See TODO.md.
bool check_slli_srli_to_zext(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding);

// An instruction whose only effect is to write a register nothing goes
// on to read. Deleting it is free. The commonest shape in the corpus is
// a frame pointer established and never used:
//
//     sd    s0,0(sp)
//     addi  s0,sp,16      <- nothing reads s0
//     ...
//     ld    s0,0(sp)
//
// Unlike the first three checks this one cannot be decided from the pair
// alone; it needs the liveness walk, and reports only what the walk
// proves dead on every path. UNKNOWN is not a finding.
//
// Needs no extension and is the first check here that fires on C++ code,
// where the earlier three find almost nothing.
// `addi s0,sp,K` in the prologue and `addi sp,s0,-K` at the exit. When
// nothing has written sp in between, the frame did not move, so the
// restore assigns sp the value it already holds and deleting it is
// free. No liveness query is involved: the instruction's whole effect is
// already in force, which is what separates this from a dead definition.
//
// This is the one check that cannot be decided from the instruction
// under the cursor and what follows it. The prologue that makes the
// restore redundant sits at the top of the function, past every call and
// branch in it, and the variable-length encoding makes searching
// backward unreliable. So the prologue is carried forward in the state
// instead, which is sound because the driver walks each section forward
// exactly once and riscvlint_state_set_section resets it.
bool check_redundant_sp_restore(riscvlint_state *state, const cs_insn *insn,
                                riscvlint_finding *finding);

// An extension applied to a value that already has that form: `sext.w`
// after `lw`, `andi rd,rd,255` after `lbu`, and the rest of the family.
// Where it writes back the register it read, deleting it leaves that
// register bit-identical and nothing downstream has to be proved;
// where it writes elsewhere it becomes a `mv`.
//
// Like check_redundant_sp_restore this carries state across the section
// -- one guarantee mask per register -- and for the same reason: what
// makes the extension redundant is upstream, not under the cursor. The
// table is cleared at a side entry, a call and an unconditional
// transfer, so a guarantee is only ever read on the straight-line path
// that established it.
bool check_redundant_extension(riscvlint_state *state, const cs_insn *insn,
                               riscvlint_finding *finding);

// A four-byte encoding that Zcb spells in two. Unlike the other checks
// this one reports an assembler's choice rather than a compiler's: RVC
// selection happens at assembly time, so a finding here means the
// instruction was legal to compress and was not.
bool check_zcb_compressible(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

// `addi rd,rs,imm1` + `<load|store> rt,imm2(rd)` is one access at
// `imm1+imm2` from rs whenever the sum fits the 12-bit field and nothing
// goes on to read rd. The direct analogue of armlint's `add` + `ldr`
// check, and its largest.
//
// Where the access is a load that overwrites its own base the value is
// dead by construction and no liveness query is needed; that is half the
// population. Everything else asks the walk, and takes only DEAD.
bool check_base_add_to_offset(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding);

bool check_dead_def(riscvlint_state *state, const cs_insn *insn,
                    riscvlint_finding *finding);

#endif  // RISCVLINT_H
