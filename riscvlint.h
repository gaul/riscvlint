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

// A load or store, in the four-byte spelling or in either compressed
// quadrant. `data` is the loaded or stored register, in its own file: a
// GPR number for the integer forms and an f-register number for the
// floating-point ones.
//
// The quadrant-2 forms -- `c.ldsp` and its family, whose base is always
// sp -- are decoded because the windowed memory table cannot do without
// them: a frame slot stored twice is spelled `c.sdsp` far more often
// than it is spelled `sd`. They are inert for the check that folds an
// address into an access, which refuses sp as a destination and so can
// never pair with one.
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

// The name of the base C extension's two-byte form for `w`, written into
// `out`, or false when it has none. Only asked of four-byte encodings.
//
// This is the whole of C on RV64 rather than the dozen forms Zcb needed,
// and the forms disagree about almost everything: which registers they
// can name, whether the destination must also be a source, whether the
// immediate is scaled, signed, or forbidden from being zero. The rules
// were checked against `riscv64-linux-gnu-as` over a matrix that sweeps
// each of those boundaries.
//
// Zcb's forms are left to rv_zcb_form. The two do not overlap: `c.andi`
// cannot hold 255, there is no base-C form for `xori`, and the widths
// `c.lbu` and its family carry are exactly the ones the base memory
// forms do not.
bool rv_c_form(uint32_t w, unsigned size, char *out, size_t outsz);

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
    RISCVLINT_EXT_C   = 1u << 4,
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

// ---- conditions and branches ----
//
// RISC-V has no condition flags, so the shape armlint spells `cmp #0`
// is here a comparison materialized into a register and then tested.
// These are the producers that a branch can absorb.
typedef enum {
    RV_COND_NONE = 0,
    RV_COND_SLT,        // rd = a <s b
    RV_COND_SLTU,       // rd = a <u b
    RV_COND_EQ,         // rd == 0 iff a == b: `xor` and `sub` alike
    RV_COND_SEQZ,       // rd = (a == 0)
    RV_COND_SNEZ,       // rd = (a != 0)
} rv_cond_kind;

// A condition written into `rd` from `rs1` and `rs2`. The single-source
// forms set rs2 to x0. `seqz` is `sltiu rd,rs,1` and `snez` is
// `sltu rd,x0,rs`, so both are aliases the raw decode has to recognise
// rather than mnemonics -- and `snez` has to be picked out before the
// general `sltu`, which would otherwise claim it.
bool rv_decode_condition(uint32_t w, unsigned size, unsigned *rd,
                         unsigned *rs1, unsigned *rs2, rv_cond_kind *kind);

// A conditional branch: `funct3` selects which comparison (0 beq, 1 bne,
// 4 blt, 5 bge, 6 bltu, 7 bgeu) and `off` is the signed byte
// displacement from this instruction. `beqz` and `bnez` are `beq` and
// `bne` against x0, in either operand order, and c.beqz/c.bnez are the
// two-byte spellings of those.
bool rv_decode_cond_branch(uint32_t w, unsigned size, unsigned *rs1,
                           unsigned *rs2, unsigned *funct3, int64_t *off);

// An unconditional jump and where it goes. `jal rd,off` is spelled `j`
// when rd is x0 and `jal` when it is ra -- the difference is the whole
// question for a check that wants to delete one, since the second form
// writes a link register. `off` is the signed byte displacement from
// the instruction. c.jal is RV32-only, so the two-byte form is always
// the x0 link.
bool rv_decode_jump(uint32_t w, unsigned size, unsigned *rd, int64_t *off);

// Bytes the branch would assemble to. Only `beqz` and `bnez` have a
// compressed spelling, and only for a register in x8-x15 with a
// displacement inside the nine-bit field.
unsigned rv_branch_encoded_size(unsigned funct3, unsigned rs1, unsigned rs2,
                                int64_t off);

// ---- the windowed memory and constant table ----
//
// Seven checks -- redundant reload, dead store, constant
// re-materialization, the load of a just-stored value, the load of a
// value the register still holds, the store of a value the slot already
// holds and the computation a live register already holds -- need the
// same thing: a region-local record of what is already in a register
// and what is already in a frame slot. None of them can be decided from
// a pair, which is why the distances cluster at 4-15 instructions and
// why no pair scan ever saw them.
//
// It is three tables under one owner: the memory slots, the constant
// table and the computation table. They do not have the same lifetime.
// A slot is a claim about a *place*, and the other two are claims about
// a *register*, so an event that reaches memory and not the register
// file takes the first kind and leaves the last -- an access through an
// address rv_decode_mem cannot name, a fence, an atomic, a CSR read.
// The constant table does not yet take advantage of that; only the
// computation table does, and TODO.md records what it is worth.
//
// The driver calls this once per instruction, **after** the checks have
// run, because each of the seven judges the instruction under the cursor
// against the table as it stood before it. Recording an instruction also
// clears the table when the *next* address is a side entry, which is
// what keeps a check from reading a value across a branch into the
// middle of a region.
//
// The two other stateful checks carry a scalar or two and update it
// inline. This one is a table seven checks read, so it gets a single
// owner rather than seven writers racing to keep it consistent.
void riscvlint_state_observe(riscvlint_state *state, const cs_insn *insn);

// Drops the whole window. The driver calls it where it cannot keep the
// record honest -- an undecodable halfword, which it resynchronises past
// without knowing what it skipped.
void riscvlint_state_drop_window(riscvlint_state *state);

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

// The same (base, displacement, width, signedness) loaded twice with
// nothing in between that could have changed it. The second load is a
// `mv` from wherever the first one put the value.
//
// This one carries a soundness caveat no binary can resolve: a load from
// a volatile or device address must be repeated, and nothing in the
// encoding says which loads those are. The window is otherwise strict:
// a call, fence, atomic or system instruction ends it, as does a write
// to either the base or the register holding the value, as does any
// store that cannot be shown to land elsewhere -- through this base a
// disjoint byte range shows it, through any other base nothing does.
bool check_redundant_reload(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

// The bytes a store just wrote, read straight back: `sd a0,8(sp)` then
// `ld a1,8(sp)` puts in a1 what a0 already holds, so the load is
// `mv a1,a0`. Where the two are narrower than a doubleword the rewrite
// is the extension the load's own signedness implies, and two of those
// spellings need Zba or Zbb.
//
// This is the cheapest of the seven to decide. Nothing is deleted -- the
// store stays and the load becomes a register operation -- so there is
// no liveness query, and both of the questions there are look backward
// into the window that is already there: the record goes when the base
// or the stored register is written, and when a store lands that
// cannot be shown to miss it.
//
// Floating-point accesses are refused on both sides. The window drops a
// held value when the register holding it is written, and its write
// scan cannot see the f registers, so an f-register claim would never
// be taken away. That costs the `fmv.s` and `fmv.d` forms, 409 sites
// across the corpus.
bool check_store_to_load(riscvlint_state *state, const cs_insn *insn,
                         riscvlint_finding *finding);

// A load whose destination already holds what it would load. The value
// never left the register, so the load is not a move to be shortened --
// it is an instruction to delete. That makes it one of the three window
// checks whose finding is always worth its own encoding in bytes, with
// the dead store and the silent store; the three that rewrite a load
// into a move often save nothing at all.
//
// Two shapes reach it, and each has to be exact. The same load again
// recomputes the same value from the same bytes at any width. A store
// read straight back into the register it came from is exact only at
// the full width: `sw a0,K(sp)` then `lw a0,K(sp)` leaves a0
// sign-extended from bit 31, which is a0 again only if it already was,
// and nothing in the pair says whether it was.
//
// It carries the reload check's caveat, for the same reason: a load
// from a volatile or device address must be repeated, and the encoding
// does not say which loads those are.
bool check_redundant_load(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding);

// A frame slot stored twice with nothing reading it in between. The
// store analogue of a dead register definition, and it is limited to sp-
// and fp-relative slots for the mirror of the reload caveat: a heap
// address may alias anything, and nothing in the encoding says it does
// not.
bool check_dead_store(riscvlint_state *state, const cs_insn *insn,
                      riscvlint_finding *finding);

// A store of bytes the slot already holds, which is the dead store read
// from the other end: that check deletes the first of two stores, this
// deletes the second. Same frame-only restriction, for the same reason.
//
// The two differ in which of the window's flags they read, and the
// flags do not have the same lifetime. Two things take `unread` away
// and leave `held` alone: a conditional branch, because "dead" means
// the overwrite is certain and on the taken path it does not happen,
// and a load through a base that cannot be shown to miss the slot,
// which may be the read that keeps the earlier store alive. Neither
// disturbs the register, so both belong here. What is left -- two
// stores of the same register with neither between them -- is 274 of
// the 6,765 sites, and this stands down on those.
//
// Unlike its neighbours it does not compare the record's kind, only its
// width: those claim something about the register a load produced, and
// this claims something about the bytes, which do not record how they
// were read. Floating point is refused on both sides for the reason
// check_store_to_load gives, and x0 is not -- storing zero over a slot
// that already holds zero is this finding like any other, where for the
// checks that rewrite a load it would be `li rd,0` rather than a move.
bool check_silent_store(riscvlint_state *state, const cs_insn *insn,
                        riscvlint_finding *finding);

// A constant materialized into a register while the same value is still
// live in another, where the duplicate takes four bytes and the `mv`
// that would replace it takes two. Where the duplicate already fits
// `c.li` the rewrite saves nothing and trades an independent instruction
// for a dependent one, so it is not reported.
bool check_const_remat(riscvlint_state *state, const cs_insn *insn,
                       riscvlint_finding *finding);

// The same question widened from `li` to everything that writes one
// register as a function of registers: a computation whose result is
// still live in a register, which is `mv rd,rprev`, or a deletion where
// the register it is about to write already holds it.
//
// Most of the population is a frame address -- `addi rd,sp,K` or
// `addi rd,s0,-K` -- and the rest is ordinary arithmetic. They are one
// check rather than two: the same table, the same match, the same byte
// rule, told apart only by whether the mnemonic is `addi` and the base
// is a frame register. Sized separately at 34,687 and 4,587, they were
// two rows of the ranked backlog before they were one check.
//
// The table this reads carries the rule the constant table does not
// need: a record dies when a *source* is written, not only when its own
// register is. Two rules came out of the probe as false positives
// first. A computation whose destination is one of its own sources
// (`add a0,a0,a1`) is not recorded at all, because nothing is left that
// can name the value it read. And an instruction whose result is not a
// function of its register operands -- `csrr`, `rdtime`, the f-prefixed
// writers of a general register -- is refused, which is a structural
// test rather than a list, since the match is on the mnemonic anyway.
//
// A conditional branch between the two does not matter, for the reason
// the window's held values do not care about one: the second
// instruction is reached by falling through, and a side entry resets
// the region. 4,972 sites sit behind such a branch.
//
// sp, gp and tp are not reported. `addi sp,s0,-K` over a frame that
// never moved is check_redundant_sp_restore's finding and says more,
// and the other two hold what the ABI says they hold.
//
// Measured population: 29,595 sites and 62,212 bytes -- C++ 21,230,
// Rust 3,450, Go 4,915 -- of which 28,052 become a move and 1,543
// delete. It matches its probe exactly in all three cohorts. See
// TODO.md.
bool check_comp_remat(riscvlint_state *state, const cs_insn *insn,
                      riscvlint_finding *finding);

// A comparison materialized into a register and then tested with
// `beqz`/`bnez`, where one branch would do both. The flagless analogue
// of armlint's `cmp #0` check.
//
// The fold only removes an instruction if the condition register is dead
// on **both** successors, which is why this needs a walk rather than a
// scan: the taken path is elsewhere in the section, and half of the raw
// population is a difference the code goes on to use.
bool check_cond_to_branch(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding);

// `beqz a0,L` + `j X` + `L:` is `bnez a0,X` with the jump gone: the
// branch inverts, takes the jump's target, and the jump goes. Every
// conditional branch inverts -- beq/bne, blt/bge and bltu/bgeu are each
// other with the low bit of funct3 flipped.
//
// The shape is 128,361 sites in the corpus and almost all of it is the
// standard way to spell a conditional branch out of range: the branch
// reaches +/-4KB and the jump reaches +/-1MB, so an assembler that
// cannot encode the branch writes this pair instead. 5,362 have a
// target the branch could reach on its own, and those are the findings.
//
// The jump must not itself be a branch target, or the paths that reach
// it lose their transfer, and it must be `j` rather than `jal` -- the
// second writes a link register that would stop being written.
//
// The inverted branch is priced at the original's own encoding class: a
// four-byte branch stays four even where the new displacement would fit
// c.beqz, because Go leaves compressible branches wide and that saving
// belongs to check_c_compressible. Where the pair is a two-byte branch
// and a two-byte jump and the new target is outside c.beqz's +/-256,
// the rewrite is four bytes for four -- it still removes an instruction
// and a taken branch, so it is reported, and the finding says so.
// Where the jump goes exactly where the branch goes, both paths already
// meet: the pair is dead rather than foldable, and inverting the branch
// would leave a branch to the next instruction rather than removing
// anything. Those are check_transfer_to_next's, and this stands down.
//
// Measured population: 5,362 sites and 15,514 bytes -- C++ 4,691, Rust
// 340, Go 331 -- which is exactly what the probe reports. See TODO.md.
bool check_branch_over_jump(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

// A relative transfer whose target is the instruction after it. Control
// arrives there either way, so it does nothing and deleting it is free.
// Mostly `c.j` to the next instruction -- a block-placement leftover in
// LLVM's output -- and a few conditional branches that do the same.
//
// `jal rd,next` with rd other than x0 is not reported: it writes a link
// register, which makes it a PC materialization rather than a no-op.
// That is 16 sites the probe counted and this does not, all of them in
// Firefox; the three four-byte jumps in Go's binaries are the x0 link
// and are reported.
//
// Measured population: 3,702 sites and 7,458 bytes -- C++ 2,851, Rust
// 831, Go 20. See TODO.md.
bool check_transfer_to_next(riscvlint_state *state, const cs_insn *insn,
                            riscvlint_finding *finding);

// A run of consecutive stores of x0 to abutting frame slots, where
// fewer naturally aligned stores would cover the same bytes. GCC zeroes
// a frame buffer one byte at a time:
//
//     sb zero,-0x6f(s0)   ... seven of them ... sb zero,-0x69(s0)
//
// Covering [-111,-104) with aligned stores takes three -- `sb -111`,
// `sh -110`, `sw -108` -- so 16 of the 28 bytes go.
//
// Only a zero value merges. `sd rD` in place of two `sw rD` would write
// rD's high half to the second slot, and nothing says a register's
// halves are the two values that were stored.
//
// Restricted to sp and fp, where the ABI fixes the base alignment and
// the offset decides the rest. Another 23,973 sites run through a base
// whose alignment the encoding does not give, and those are the ones
// where a byte-at-a-time store may be the deliberate choice.
//
// The replacement is priced at the widest encoding the run itself used,
// never at a compressed form it did not: `c.sdsp` takes a full five-bit
// rs2, so crediting a merged `sd zero,K(sp)` with it would report Go's
// uncompressed stores as a merge when what they are is the missed
// compression check_c_compressible already counts.
//
// One finding per run rather than per pair. Read as adjacent pairs the
// same code is 50,755 sites and read as runs it is 30,321: a run of
// seven `sb` is one finding worth 16 bytes, not three pair-merges worth
// four each, and the pair count cannot tell the difference.
// Measured population: 6,348 sites and 32,960 bytes -- C++ 4,913, Rust
// 143, Go 1,292, and 4,401 through sp against 1,947 through fp. The
// sites are the probe's exactly; the bytes are 1,151 higher, because
// the probe priced the whole replacement at the run's average encoded
// size and that is not the size of any instruction in a run of mixed
// widths. See TODO.md.
bool check_zero_store_run(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding);

// A value moved between the two register files by storing it to a frame
// slot and loading it back:
//
//     fsd fa0,K(sp)   ...   ld a0,K(sp)   ->   fmv.x.d a0,fa0
//
// and the same in the other direction, at both widths. The move does it
// in one instruction and no memory at all.
//
// This is the one check here whose value is not bytes. None of the four
// moves has a compressed spelling, so the rewrite breaks even against a
// four-byte load and would cost two against a two-byte one -- and it is
// refused there, which is 869 of the 2,380 sites the probe finds. What
// it removes is a load, a store-to-load dependency through memory, and
// often the frame slot with them.
//
// The pairing has to be exact on width and on what the load does with
// the bits: `fmv.x.w` sign-extends the 32 it moves and so does `lw`,
// but `lwu` does not.
//
// It is the reason the windowed table records floating-point accesses
// at all. Every other reader of that table skips a record whose data
// register is in the other file, since an f register and an x register
// with the same number are two registers and the record's `data` field
// alone cannot tell them apart -- `rv_mem_is_fp` of the record's kind
// is what does.
// Measured population: 1,155 sites and 0 bytes -- C++ 1,145, Go 10. The
// probe with the same preconditions finds 2,380, of which 869 have a
// two-byte load and are refused here; 327 of the rest are lost to the
// window filling, which TODO.md prices. The ledger carried 3,258 for
// years, which was a rejection count with no preconditions applied at
// all.
bool check_bitcast_through_frame(riscvlint_state *state, const cs_insn *insn,
                                 riscvlint_finding *finding);

// A four-byte encoding the base C extension spells in two. Like the Zcb
// check this reports an assembler's choice rather than a compiler's, and
// on a toolchain that selects RVC at all the residue is nearly nothing:
// what it finds is the shape of an assembler that does not.
bool check_c_compressible(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding);

bool check_dead_def(riscvlint_state *state, const cs_insn *insn,
                    riscvlint_finding *finding);

#endif  // RISCVLINT_H
