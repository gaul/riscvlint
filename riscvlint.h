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
    RISCVLINT_EXT_ZFA = 1u << 5,
    RISCVLINT_EXT_ZILX = 1u << 6,
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

// Reads `n` bytes at `vaddr` out of the image the code came from, for
// the one check that has to resolve an address into data. Returns false
// where it cannot, which is the common answer and not an error.
//
// The provider must serve only bytes that cannot change between the
// file and the running program: allocated, **non-writable** sections
// with contents. That rules out `.data`, which a program may overwrite,
// and `.data.rel.ro`, which is writable at load time precisely so the
// dynamic linker can relocate into it -- in both cases the bytes in the
// file are not the bytes the load would see. A provider that is laxer
// than this makes check_fp_pool_to_fli unsound, which is why the rule
// is stated here rather than left to the driver.
typedef bool (*riscvlint_read_fn)(void *ctx, uint64_t vaddr, void *out,
                                  size_t n);
// Installs it. Without one -- the default -- the checks that need it
// stand down, so a caller that has no image to offer loses findings
// rather than correctness.
void riscvlint_state_set_image(riscvlint_state *state, riscvlint_read_fn read,
                               void *ctx);

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

// ---- an address computed for one indexed load ----

// `add rd,rb,ri` + `lw rt,0(rd)`, which Zilx's indexed loads do in one
// instruction: `lxw rt,(rb),ri`.
//
// Zilx (Indexed Integer Load) is the extension that gives RV64 the
// addressing mode it has never had. The base ISA has exactly one --
// `imm12(base)` -- which is why `a[i]` costs a shift, an add and a
// load where AArch64 writes `ldr x0,[x1,x2,lsl #3]`, and why
// RISCVMergeBaseOffset and RISCVFoldMemOffset exist at all. Zilx adds
// base+index and base+(index<<log2(size)) forms, reusing the AMO major
// opcode with funct5 values that were reserved: 0b10010 unscaled,
// 0b11010 scaled, 0b11110 scaled with a zero-extended 32-bit index.
// Taken from LLVM's RISCVInstrInfoZilx.td rather than from the
// ratification plan's prose, for the reason the `fli` check gives --
// the assembler is what has to accept the suggestion.
//
// This reports the unscaled shape: two adjacent instructions, an `add`
// of two registers feeding a zero-offset integer load of the register
// it wrote. The two deeper shapes are separate checks below --
// check_scaled_indexed_load's three instructions and
// check_zext_indexed_load's four -- and each tells this one to stay
// quiet at an `add` it has already claimed, since one site is one
// rewrite.
//
// Loads only, and integer loads only. Zilx has no indexed store and no
// indexed floating-point load, so a store or an `flw` through a
// computed base is not a finding however much it looks like one.
//
// Byte loads have no unscaled encoding, but the scaled byte form's
// scale factor is 1, so `lb`/`lbu` fold to `lxsb`/`lxsbu` and the
// address arithmetic is identical.
//
// Gated on `-m zilx`, which no profile turns on: Zilx is in none of
// RVA20, RVA22, RVA23 or RVB23 as of LLVM's RISCVProfiles.td, so unlike
// Zcb or Zfa there is no "what would rebuilding for RVA23 buy me"
// reading. It asserts a specific target, which is armlint's `-m cssc`
// position.
bool check_indexed_load(riscvlint_state *state, const cs_insn *insn,
                        riscvlint_finding *finding);

// `slli rt,ri,3` + `add rd,rb,rt` + `ld rt2,0(rd)`, which Zilx's
// scaled indexed loads do in one: `lxsd rt2,(rb),ri`. This is the
// shape the base ISA actually pays for `a[i]` with, and the one
// AArch64 has had since the beginning.
//
// The scale factor is log2 of the access size and nothing else, so the
// shift the code already performs has to agree with the width the load
// reads. That condition is the whole difference between a population
// and a coincidence: `slli rt,ri,3` + an `lw` is some other
// computation, and folding it would change the address. Without it the
// triple reads 78% higher on libLLVM -- 13,561 of its matches shift by
// the wrong amount. Byte loads scale by 1, so their shift amount is
// zero, there is no `slli`, and that site belongs to the unscaled
// check above.
//
// Two writes disappear here rather than one, the shifted index and the
// address, so both have to be gone. Each is killed by construction
// wherever a later instruction of the triple overwrites it -- the
// `add` over the shift, the load over either -- which is what the
// common `slli a5,a5,3` + `add a5,a0,a5` + `ld a5,0(a5)` is; anything
// else is proved by the liveness walk or declined.
//
// The `add` in the middle is also the unscaled check's match, and the
// two are not independent findings: with Zilx present a compiler emits
// one `lxsd`, not an `lxd` and a surviving `slli`. So this check
// records the `add` it covered and the unscaled one declines there,
// which keeps a site counted once and counted as the better rewrite.
//
// Measured population under `-m zilx`: see TODO.md. ripgrep has 0 of
// it, and that is Zba rather than a compiler difference -- where Zba is
// declared the `slli`+`add` is already one `sh3add` and this triple
// never forms. Which makes the check's own reading of the corpus an
// argument about extensions rather than about compilers: Zba halves the
// sequence and Zilx removes it.
bool check_scaled_indexed_load(riscvlint_state *state, const cs_insn *insn,
                               riscvlint_finding *finding);

// `slli rt,ri,32` + `srli rt,rt,32-N` + `add rd,rb,rt` +
// `ld rt2,0(rd)`, which Zilx's third addressing mode does in one:
// `lxsuwd rt2,(rb),ri`. That mode is funct5 0b11110 and computes
// base + (zext32(index) << log2(size)), so it folds the zero-extension
// as well as the scale -- which is what `a[i]` costs when the index is
// a 32-bit unsigned value and the array is addressed through a 64-bit
// base. Four instructions on the base ISA, two with Zba's `shNadd.uw`,
// one with Zilx.
//
// The `slli` must be by 32 exactly, because the zero-extension is from
// bit 31 and nothing else. The `srli` then carries the scale, and the
// scale is the access width: `slli x,32` + `srli x,28` scales by 16,
// which is a stride through 16-byte structures and not anything a load
// width can name. A byte load's scale is 1 and its pair is therefore
// `zext.w` itself.
//
// What that test costs is not uniform, and the two big C++ objects
// disagree about it by a factor of thirty. In libxul 82 of 3,829
// width-tested quads disagree, 2%. In debian-libllvm22 12,799 of
// 18,411 do, 70% -- 10,133 of them at `srli 28` alone, which is one
// program's 16-byte structures showing up as a shape this extension
// cannot address. So the test is nearly free on one object and decides
// the number on the other, which is the argument for keeping it rather
// than reporting the quad on its shape alone.
//
// Three writes disappear rather than two, the widened index, the
// narrowed index and the address, so the liveness walk can be asked
// three times. The common case writes one register throughout and
// needs no walk: `slli a5,a5,32` + `srli a5,a5,29` + `add a5,a0,a5` +
// `ld a5,0(a5)`. The `srli` writing a register the `slli` did not is
// allowed and is the case that needs all three proofs; it is 1,194 of
// libxul's 3,747 width-matching quads and 347 of libLLVM's 5,612, so
// refusing it to save a query would cost real sites.
//
// Like the scaled shape this claims the `add` and silences the
// unscaled check there, for the same reason: with Zilx present the
// site is one `lxsuwd`, not an `lxd` with two surviving shifts.
//
// Measured population under `-m zilx`: see TODO.md. ripgrep has none
// of it and neither does any object declaring Zba, which here is a
// stronger statement than it was for the scaled shape -- Zba's
// `add.uw` and `shNadd.uw` do base + zext32(index) scaled in a single
// instruction, so the four-instruction sequence does not exist on
// those targets at all.
bool check_zext_indexed_load(riscvlint_state *state, const cs_insn *insn,
                             riscvlint_finding *finding);

// ---- a bit count spelled out longhand ----

// Twelve instructions and four mask constants that compute a
// population count, which Zbb's `cpop` does in one.
//
// RV64GC has no bit-counting instruction, so `llvm.ctpop` is expanded
// inline by TargetLowering::expandCTPOP into the Hacker's Delight
// sequence:
//
//     v -= (v >> 1) & 0x5555...        three instructions
//     v  = (v & 0x3333...) + ((v >> 2) & 0x3333...)   four
//     v  = (v + (v >> 4)) & 0x0f0f...  three
//     v  = (v * 0x0101...) >> (len-8)  two
//
// plus two instructions apiece to build the four masks. On a target
// with Zbb it is `cpop rd,rs`.
//
// Measured population: 3,976 sites in libxul and 3,109 in Debian's
// baseline libLLVM 22.1.8 -- and **0** in Ubuntu's build of that same
// release, which declares Zbb and uses `cpop` 2,016 times instead. Like
// the Zcb and `fli` checks this is a question about the target rather
// than a compiler miss, and most of the population is the 64-bit
// sequence rather than the 32-bit one. See TODO.md.
//
// Matched as dataflow, not as a window. Every other check here reads
// adjacent instructions or a table keyed by address, and neither works
// on this: the scheduler interleaves the four mask materializations
// with the arithmetic and with unrelated work, and it reorders the
// independent halves of the middle stage. So each register carries what
// it is known to hold -- a stage of the expansion, and which register
// the whole sequence started from -- and the finding is reported at the
// final shift, when one register's history reaches all the way back. A
// missing link anywhere means no finding, so the match is
// false-negative-safe by construction rather than by a bound.
//
// Three things it will not claim. The suggestion names the source
// register, so the sequence is abandoned the moment anything writes
// that register -- a stage computed from a value that is gone cannot be
// rewritten as `cpop` of it. The byte figure counts only the twelve
// instructions matched, never the mask materializations, since whether
// those die with the sequence needs liveness this does not have. And
// the 32-bit and 64-bit forms are kept apart by their masks and their
// final shift together, so a mixed sequence matches neither.
bool check_swar_popcount(riscvlint_state *state, const cs_insn *insn,
                         riscvlint_finding *finding);

// ---- a floating-point constant `fli` would have materialized ----

// Which of Zfa's 32 `fli` entries holds the value whose bit pattern is
// `bits`, or -1 for a value no entry holds. `width` is 4 for a binary32
// pattern (`fli.s`) and 8 for a binary64 one (`fli.d`).
//
// A port of LLVM's RISCVLoadFPImm::getLoadFPImm (RISCVBaseInfo.cpp),
// which is the oracle that matters: a finding is only advice if the
// assembler agrees the immediate exists. Done in integer arithmetic
// rather than through a float, so the answer does not depend on the
// host's rounding mode or on what a double-to-float conversion does
// with a NaN payload -- the test is simply that the pattern's low bits
// are clear and its (exponent, 2-bit mantissa) pair is in the table.
int rv_fli_entry(uint64_t bits, unsigned width);

// How the assembler spells that entry: `min`, `inf` and `nan` for
// entries 1, 30 and 31, and otherwise the value, matching LLVM's
// RISCVInstPrinter::printFPImmOperand so the suggested instruction is
// one that assembles. Writes to `out` and returns it.
const char *rv_fli_spell(int entry, char *out, size_t outsz);

// `auipc rd,%pcrel_hi(L)` + `fld frd,%pcrel_lo(L)(rd)` where the eight
// bytes at L are a value Zfa's `fli.d` builds in one instruction: the
// pair, the load and the pool slot all go. Also the `flw`/`fli.s`
// spelling; the absolute `lui %hi` one measures zero, for the reason
// the implementation records.
//
// This is armlint's "`ldr` literal of an encodable constant" with the
// architectures the other way round. AArch64 has `fmov #imm8` at
// baseline, so LLVM materializes every encodable FP constant and that
// check measured 35 sites in 42,324 pool loads -- 0.08%, and closed.
// RISC-V has no floating-point immediate at all without Zfa, so the
// pool is where *every* constant goes on a baseline target, and the
// check armlint rejected is the largest one left here.
//
// Measured population: 18,539 adjacent pool loads across the corpus, of
// which 4,328 hold a value `fli` encodes -- 3,907 in the nine baseline
// Firefox objects (libxul alone has 3,459: 1.0 x909, nan x787, 0.5
// x664, inf x468, -1.0 x207) and 421 in Go, whose assembler selects no
// Zfa. **Zero** in the eight objects that declare `zfa1p0`: where the
// compiler was allowed to use `fli` it already did, 798 times. So this
// is an `-m rva23` finding in the same sense as the Zcb check -- "what
// would rebuilding for RVA23 buy me" -- rather than a peephole anyone
// missed. See TODO.md.
//
// Four things it requires beyond the shape. The pool address must
// resolve through riscvlint_state_set_image, whose contract is that
// only non-writable contents are served: a constant a program can
// overwrite is not a constant. Neither instruction may carry a
// relocation, since in an unlinked object both immediates are
// placeholders. Nothing may branch between them. And the `auipc`'s own
// register must be provably dead afterwards -- the rewrite stops
// writing it, and a pool address is sometimes used again for the slot
// next door.
bool check_fp_pool_to_fli(riscvlint_state *state, const cs_insn *insn,
                          riscvlint_finding *finding);

// `li rd,3` (or 5, or 9) followed by a multiply by it: Zba's
// `sh1add`/`sh2add`/`sh3add` computes the same product in one
// instruction, with both operands naming the multiplicand --
// `sh1add rd,rx,rx` is rx + (rx << 1).
//
// The factor has to be one of exactly those three. A power of two is a
// shift and no compiler in the corpus emits a multiply for one: four
// dependent `li` + `mul` pairs across 108 million instructions load a
// power of two, against 712 that load a 3, 5 or 9. Every other small factor needs two shifts and
// an add at best, which is no better than the two instructions already
// there.
//
// Only `mul`. `mulw` sign-extends its 32-bit product and shNadd does
// not, so folding one needs a following `sext.w` and trades two
// instructions for two; the corpus has 387 of those, which is why the
// decoder's reach -- a different major opcode for mulw, a different
// funct3 for the mulh family -- is the test rather than a mnemonic
// list.
//
// The constant must be dead after the pair, since the rewrite stops
// loading it. Usually the multiply overwrites it and that is free.
//
// Gated on Zba: suppressed when the object declares an arch string
// without it, reported when it declares one with it or declares none.
//
// Measured population: 416 sites, every one of them in a Go binary.
// GCC and LLVM reduce a multiply by a small constant themselves,
// with or without Zba, so nothing reaches their encoders in this form.
// See TODO.md.
//
// Where the `li` is wide it is also check_c_compressible's finding,
// which says the same two instructions could be six bytes rather than
// eight -- all 107 such sites carry both. Both stand: C and Zba are
// separate answers to separate questions, and the Zba one makes the C
// one moot by removing the instruction rather than shrinking it.
bool check_const_mul_to_shadd(riscvlint_state *state, const cs_insn *insn,
                              riscvlint_finding *finding);

// `li rc,2^k` followed by an unsigned divide or remainder by it, which
// one RV64I instruction does: `srli rd,rx,k` for `divu`, `srliw` for
// `divuw` -- which divides the low words and sign-extends, exactly what
// srliw's shift does -- and `andi rd,rx,2^k-1` for `remu` and `remuw`,
// the remainder by a power of two being its low bits.
//
// There is no extension gate: all three replacements are RV64I, so the
// finding stands whatever the object's arch string says.
//
// Unsigned only. `div rd,rx,2^k` rounds toward zero and `srai` rounds
// toward minus infinity, which disagree for every negative dividend not
// a multiple of the divisor, so folding a signed divide needs the bias
// added back first and is three instructions rather than one. The
// signed funct3 values are refused in the decoder rather than filtered
// later, so there is one place to look.
//
// Two bounds come from the replacement rather than the shape. andi's
// immediate is twelve bits signed, so a remainder folds only up to a
// mask of 2047 -- k of 11 -- above which the mask would need its own
// `li` and the pair would not shrink. srliw's shift amount is five
// bits, so a `divuw` folds only to k of 31, above which the divisor's
// low word is not a power of two in the first place. Neither bound
// rejects anything in the corpus.
//
// Measured population: 0. Of 1,593,373 `li` and `lui` whose immediate
// alone is a power of two, 618 are followed by an unsigned divide or
// remainder reading that register, and 603 of those read it as the
// dividend, which no shift replaces;
// 13 of the remaining 15 are branch targets and 2 leave the divisor
// live. All three toolchains in the corpus already do this fold, so
// what is left is adjacency across a control-flow merge. The check is
// cheap and needs no extension, so it is kept for the compilers and
// the hand-written code this corpus does not contain. TODO.md entry 29
// has the decoded site and the argument.
bool check_udiv_pow2(riscvlint_state *state, const cs_insn *insn,
                     riscvlint_finding *finding);

// ---- running every check ----
//
// Called once per finding, with `ctx` as given. The finding is valid
// only for the duration of the call -- `title` points into static
// storage but the struct itself is reused -- so a consumer that keeps
// findings copies them.
//
// Where a summary answers "how many of each kind", this answers "which
// instructions, at what address": the form needed to join findings
// against anything else keyed by address, and the join worth making is
// an execution profile. How often a compiler emits a suboptimal
// encoding is a poor proxy for what it costs, and only a profile tells
// one inside a hot loop from a thousand in cold initialization code.
// The driver's --json mode is built on this.
typedef void (*riscvlint_finding_fn)(void *ctx, const riscvlint_finding *f);
// Decode `len` bytes at `vaddr` and run every check over each
// instruction, in the order the checks need: each one judges its
// instruction against the window as it stood *before* it, so the
// window advances only after the checks have run.
//
// The state must already carry this section
// (riscvlint_state_set_section) and its relocations
// (riscvlint_state_set_relocs); both are facts about the container,
// which is the caller's business rather than the scan's.
//
// Returns the number of findings. `*instructions` and `*skipped`, when
// non-NULL, are *incremented* by the instructions linted and by the
// bytes stepped over without linting, so a caller sweeping several
// sections accumulates across them. Skipped bytes are halfwords this
// capstone build could not decode: the scan resynchronizes two bytes at
// a time past one, and a reader cannot otherwise tell a resynchronized
// sweep of a data-laden section from a clean one.
size_t riscvlint_scan(riscvlint_state *state, csh handle,
                      const uint8_t *code, size_t len, uint64_t vaddr,
                      riscvlint_finding_fn on_finding, void *ctx,
                      uint64_t *instructions, uint64_t *skipped);

// ---- constant chains (`-c`) ----
//
// Every constant the code materializes, tallied by value and ranked by
// the instructions it costs. armlint's `-c` with the axis RISC-V
// forces: there, a chain is MOVZ/MOVN plus MOVKs and its length is the
// value's width in halfwords; here it is whatever RISCVMatInt chose,
// and the question "how much does this constant cost" has a different
// answer per value rather than per width.
//
// What a chain is: an instruction that builds a value out of x0 and an
// immediate -- `li`, `lui`, `c.li`, `c.lui` -- followed by however many
// `addi`/`addiw`/`slli` steps read its own result and nothing else.
// That is the shape RISCVMatInt emits and the shape GNU as emits for
// `li`. A branch into the middle ends it, since the instructions after
// the target are then reached without the ones before.
//
// **The steps need not be adjacent**, and getting that wrong is the
// reason this comment is long. One chain is tracked per register, and
// it ends when its value is *consumed* -- the first instruction to read
// the register closes it -- so a later `addi` on the same register
// starts a new chain rather than extending a finished one. A step may
// also write a register other than the one it reads, since the
// allocator puts the finished constant somewhere else whenever the
// partial value is still live; the source chain stays in flight, which
// means instructions shared between a value and a value derived from it
// are counted under each.
//
// What an adjacency rule cost, before that: libxul's `0x0f0f0f0f`
// read as 27 sites where the true figure is 3,972. Here is why, at
// libxul 0x3267b2a -- a 64-bit SWAR popcount whose four mask
// materializations the scheduler batched and then completed out of
// order:
//
//     lui  a1,0x55555        four luis together, so an adjacency rule
//     lui  a2,0x33333        closes each after one instruction, at
//     lui  a3,0xf0f1         0x55555000 and friends, and bins all four
//     lui  a4,0x1010         as untallied one-instruction values
//     srai s0,s6,0x3f        unrelated work in the middle
//     addi s1,a1,1365        a1's chain completes into *s1*
//     addi a2,a2,819         this one completes in place
//
// Checked against an oracle that needs neither: `lui rd,imm20` is one
// word per rd, so counting the encoding directly gives a figure the
// census can be held to. Over libxul and both libllvm22 builds the two
// agree to within 1.3% on each of those four masks.
//
// Composition through a register-register `add` or `or` is followed
// too, which is how RISCVMatInt joins the halves of a 64-bit value.
// Unlike a step there is no ambiguity about what it does -- the sum or
// union of two known constants is a constant whatever else is true --
// so both sources are closed without being counted and their
// instructions are charged to the value they were built for. Where the
// two halves grew from the same root instruction, which is what a
// cross-register step leaves behind, their counts overlap and the
// larger is taken rather than the sum.
//
// That is what makes a 64-bit constant visible as itself: libxul's
// 2,867 `0x5555555555555555` chains used to report as
// `0x5555555500000000`, the shifted half, and the 64-bit popcount is
// the expensive one.
//
// Still not followed: anything else that combines two known values --
// `sub`, `xor`, `and`, a shift by a register. Those appear in
// RISCVMatInt's output rarely or not at all, and every one added is a
// chance to absorb an instruction that was using a constant rather
// than building one.
//
// Two things the report says that a by-value tally alone would not.// Two things the report says that a by-value tally alone would not.
//
// Whether the value is a *constant* or an *address*: in a linked
// object `lui`+`addi` of a symbol's %hi/%lo is indistinguishable from
// arithmetic on a literal, and conflating them makes the report
// useless -- in libxul the split is 5,671 addresses against 29,701
// constants. The caller decides, through riscvlint_mapped_fn, since
// "does this value address something the file maps" is a question
// about the container.
//
// And whether a chain *rebuilds* a value its own function already
// built, which is the difference between a constant that is expensive
// and one that is expensive repeatedly. The caller supplies the
// function identity through riscvlint_anchor_fn, for the same reason.
// Note what this does not claim: a rebuild is not necessarily a miss.
// Telling the two apart needs dominance and liveness, which this does
// not have.

typedef struct riscvlint_cchain riscvlint_cchain;

// True when `value` falls inside something the file maps -- any
// allocated section -- which is what tells an address from a literal.
// A caller with nothing to say returns false and gets everything
// counted as a constant.
typedef bool (*riscvlint_mapped_fn)(void *ctx, uint64_t value);

// The function holding `addr`, as an opaque identity: its start
// address, or 0 where none is known. Two chains agree on a function
// exactly when this agrees, so a caller with no symbols returns 0 and
// no chain is counted as a rebuild.
typedef uint64_t (*riscvlint_anchor_fn)(void *ctx, uint64_t addr);

riscvlint_cchain *riscvlint_cchain_create(void);
void riscvlint_cchain_destroy(riscvlint_cchain *c);
void riscvlint_cchain_set_hooks(riscvlint_cchain *c,
                                riscvlint_mapped_fn mapped, void *mapped_ctx,
                                riscvlint_anchor_fn anchor, void *anchor_ctx);
// Walks `len` bytes at `vaddr`, recognizing every chain. `targets`, when
// non-NULL, is the state whose side-entry map says where a branch lands,
// so a chain is not read across one; a caller without it loses the few
// chains a target splits rather than reporting them as one.
void riscvlint_cchain_scan(riscvlint_cchain *c, csh handle,
                           const riscvlint_state *targets,
                           const uint8_t *code, size_t len, uint64_t vaddr);
void riscvlint_cchain_print(const riscvlint_cchain *c, const char *path,
                            bool samples);
// For the tests: totals, and the figures for one value.
size_t riscvlint_cchain_chains(const riscvlint_cchain *c);
size_t riscvlint_cchain_instructions(const riscvlint_cchain *c);
size_t riscvlint_cchain_values(const riscvlint_cchain *c);
bool riscvlint_cchain_lookup(const riscvlint_cchain *c, int64_t value,
                             size_t *chains, size_t *insns, size_t *rebuilt,
                             bool *address);

// ---- ISA census ----
//
// A by-extension tally of every instruction decoded: armlint's census
// with the axis RISC-V actually has. AArch64 versions its architecture,
// so armlint reads a ladder off Armv8.x; RISC-V names its extensions
// instead, and the ladder here is the RVA profile that made each one
// mandatory -- Zba/Zbb/Zbs and Zfhmin at RVA22U64, V and Zicond and Zcb
// and Zfa and Zawrs at RVA23U64. So the census answers the same
// question, "what was this binary compiled for", by naming the profile
// whose mandatory set covers everything it uses.
//
// The rungs are transcribed from llvm/lib/Target/RISCV/RISCVProfiles.td
// rather than from memory, because the membership is not what anyone
// guesses: Zifencei is mandated by RVA20S64 and by no RVA U-mode
// profile at all, and Zicbop is in RVA22U64 while Zbc, Zacas and Zfh
// are in none of them.
//
// The attribution is capstone's own, read from the feature groups its
// RISC-V module generates out of LLVM's instruction predicates, and
// matched by group NAME rather than by number. The numbers are
// generated content with no assigned values past the first, so they
// move whenever capstone regenerates against a newer LLVM; the names do
// not. This is the second thing riscvlint trusts capstone for (the file
// header says why it does not trust the operand model) and it is sound
// where that is not: a predicate says which extension defines an
// encoding, which is exactly what a census asks.
//
// An instruction can need two extensions at once -- a compressed
// `c.mul` needs Zcb and M, `c.fld` needs C and D -- and it is counted
// under each, so the per-extension counts sum past the instruction
// total. The baseline line does not overlap them: it counts the
// instructions that needed nothing beyond RV64I.
//
// Three groups never raise the profile level. Zihintpause's `pause`,
// Zihintntl's `ntl.*` and Zicbop's `prefetch.*` are HINTs: their
// encodings are a FENCE, an `add x0,...` and an `ori x0,...` that a
// core without the extension executes as written and ignores, so a
// binary full of them still runs on RVA20 hardware. They get their own
// line, exactly as armlint's hint-space PAC and BTI do. Everything no
// RVA profile mandates gets another, since a single `-march=` token
// bolts any of them onto an older target; and vendor extensions get a
// third, because they are not in the standard encoding space at all.
//
// Capstone marks no feature group on the CSR instructions or on
// `fence.i`, and none on the two uncompressed hints, so those four are
// picked out by raw decode -- otherwise `csrr a0,cycle` would be
// reported as base RV64I, which it is not. (The compressed `c.ntl.*`
// carry capstone's RVC-hint group and are left in C, which is baseline
// and cannot mislead the ladder.)
//
// An undecodable halfword may be data in text OR an extension this
// capstone cannot decode, so the skipped count bounds what the census
// could have missed. And the census reports presence, not requirement:
// an extension reached only through a runtime dispatch counts the same
// as one on every path.
//
// Opaque; NULL is accepted everywhere.
typedef struct riscvlint_census riscvlint_census;

riscvlint_census *riscvlint_census_create(void);
void riscvlint_census_destroy(riscvlint_census *census);

// Linear-sweep decode of `len` bytes at `vaddr`, tallying each
// instruction's extensions. An undecodable halfword resynchronises past
// two bytes and is counted as skipped, the same rule the check driver
// uses. Call once per executable section.
void riscvlint_census_scan(riscvlint_census *census, csh handle,
                           const uint8_t *code, size_t len, uint64_t vaddr);

// Print the census: totals, one line per profile rung, the three lines
// that never raise it, and the profile the tallies imply. `path` names
// the object on the first line, or NULL for none. `arch` is the
// object's Tag_RISCV_arch string (NULL when it has none), which is
// reported and cross-checked against what was used. `samples` adds up
// to four addresses per extension, to tell real use from data decoded
// as code.
void riscvlint_census_print(const riscvlint_census *census, const char *path,
                            const char *arch, bool samples);

size_t riscvlint_census_instructions(const riscvlint_census *census);
size_t riscvlint_census_skipped(const riscvlint_census *census);

// Instructions needing nothing beyond RV64I.
size_t riscvlint_census_baseline(const riscvlint_census *census);

// Tally for one extension by the name the census prints ("Zba", "C",
// "V", "XTHeadBa"); 0 for an unknown name or a NULL census. The
// spelling is capstone's feature-group name with its prefix removed, so
// it is capitalized the way LLVM's predicates are.
size_t riscvlint_census_extension_count(const riscvlint_census *census,
                                        const char *name);

// The lowest RVA U-mode profile whose mandatory set covers every
// extension used: "RVA20U64", "RVA22U64" or "RVA23U64". Extensions no
// profile mandates, the hint-space ones and the vendor ones do not
// raise it -- see above -- so this is a floor on what the binary needs
// rather than the whole of it.
const char *riscvlint_census_profile(const riscvlint_census *census);

#endif  // RISCVLINT_H
