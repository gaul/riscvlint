// Unit tests for riscvlint. The decoders and the reach test are where a
// silent bug turns into a wrong finding, so they are tested against
// encodings taken from real binaries rather than only synthetic ones.

#include "riscvlint.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static uint32_t enc_auipc(unsigned rd, uint32_t imm20)
{
    return (imm20 << 12) | (rd << 7) | RV_OP_AUIPC;
}

static uint32_t enc_jalr(unsigned rd, unsigned rs1, int32_t imm12)
{
    return ((uint32_t)(imm12 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) |
           RV_OP_JALR;
}

static void test_decode_auipc(void)
{
    unsigned rd;
    int64_t imm;

    // `auipc ra, 0` at 0x6e3a4 in ripgrep: 0x00000097.
    CHECK(rv_decode_auipc(0x00000097u, &rd, &imm));
    CHECK(rd == 1 && imm == 0);

    // `auipc t0, 0` -> t0 is x5.
    CHECK(rv_decode_auipc(0x00000297u, &rd, &imm));
    CHECK(rd == 5 && imm == 0);

    // The 20 bits are the high half of the addend, so 0x85 means
    // 0x85000 bytes, and the sign lives in bit 19 of the field.
    CHECK(rv_decode_auipc(enc_auipc(1, 0x85), &rd, &imm));
    CHECK(rd == 1 && imm == 0x85000);
    CHECK(rv_decode_auipc(enc_auipc(1, 0xfffff), &rd, &imm));
    CHECK(rd == 1 && imm == -4096);
    CHECK(rv_decode_auipc(enc_auipc(1, 0x80000), &rd, &imm));
    CHECK(imm == -2147483648LL);

    // Not an auipc.
    CHECK(!rv_decode_auipc(0x00000013u, &rd, &imm));   // addi/nop
    CHECK(!rv_decode_auipc(enc_jalr(1, 1, 0), &rd, &imm));
}

static void test_decode_jalr(void)
{
    unsigned rd, rs1;
    int64_t imm;

    // `jalr -1396(ra)` at 0x6e3a8 in ripgrep: 0xa8c080e7.
    CHECK(rv_decode_jalr(0xa8c080e7u, &rd, &rs1, &imm));
    CHECK(rd == 1 && rs1 == 1 && imm == -1396);

    CHECK(rv_decode_jalr(enc_jalr(1, 1, 2047), &rd, &rs1, &imm));
    CHECK(imm == 2047);
    CHECK(rv_decode_jalr(enc_jalr(0, 6, -2048), &rd, &rs1, &imm));
    CHECK(rd == 0 && rs1 == 6 && imm == -2048);

    // funct3 must be zero: 0x67 with funct3 != 0 is not jalr.
    CHECK(!rv_decode_jalr(enc_jalr(1, 1, 0) | (1u << 12), &rd, &rs1, &imm));
    CHECK(!rv_decode_jalr(0x00000097u, &rd, &rs1, &imm));
}

static void test_decode_shift_add(void)
{
    unsigned rd, rs1, rs2, sh;

    // 4-byte forms taken from gh: `slli s0,t2,0x2` / `add s0,s0,t2`.
    CHECK(rv_decode_slli(0x00239413u, 4, &rd, &rs1, &sh));
    CHECK(rd == 8 && rs1 == 7 && sh == 2);          // s0, t2
    CHECK(rv_decode_add(0x00740433u, 4, &rd, &rs1, &rs2));
    CHECK(rd == 8 && rs1 == 8 && rs2 == 7);

    // 2-byte forms, assembled and read back: `c.slli s0,2` is 0x040a,
    // `c.add s0,t2` is 0x941e, `c.slli a5,3` is 0x078e, `c.add a5,a4`
    // is 0x97ba.
    CHECK(rv_decode_slli(0x040au, 2, &rd, &rs1, &sh));
    CHECK(rd == 8 && rs1 == 8 && sh == 2);          // c.slli implies rd == rs1
    CHECK(rv_decode_add(0x941eu, 2, &rd, &rs1, &rs2));
    CHECK(rd == 8 && rs1 == 8 && rs2 == 7);
    CHECK(rv_decode_slli(0x078eu, 2, &rd, &rs1, &sh));
    CHECK(rd == 15 && sh == 3);                     // a5
    CHECK(rv_decode_add(0x97bau, 2, &rd, &rs1, &rs2));
    CHECK(rd == 15 && rs2 == 14);                   // a5, a4

    // srli, both spellings. `slli a4,a2,0x20` is 0x02061713 and the
    // c.srli that follows it is 0x9301; `srli a6,a6,0x20` stays four
    // bytes at 0x02085813 because a6 is x16 and CB-format names only
    // x8-x15.
    CHECK(rv_decode_srli(0x9301u, 2, &rd, &rs1, &sh));
    CHECK(rd == 14 && rs1 == 14 && sh == 32);        // a4
    CHECK(rv_decode_srli(0x9001u, 2, &rd, &rs1, &sh));
    CHECK(rd == 8 && sh == 32);                      // s0
    CHECK(rv_decode_srli(0x02085813u, 4, &rd, &rs1, &sh));
    CHECK(rd == 16 && rs1 == 16 && sh == 32);        // a6
    // c.srai shares c.srli's funct3 and differs in bit 10; it shifts in
    // the sign, which is sext.w rather than zext.w.
    CHECK(!rv_decode_srli(0x9401u, 2, &rd, &rs1, &sh));
    // The 4-byte srai differs in funct6.
    CHECK(!rv_decode_srli(0x02085813u | (0x10u << 26), 4, &rd, &rs1, &sh));
    // slli shares the opcode, differing in funct3.
    CHECK(!rv_decode_srli(0x02061713u, 4, &rd, &rs1, &sh));

    CHECK(rv_insn_len(0x00239413u) == 4);
    CHECK(rv_insn_len(0x040au) == 2);

    // srli shares the opcode and differs only in funct3 (5, not 1); the
    // 64-bit shifts use funct6, so a set bit above shamt is srai.
    CHECK(!rv_decode_slli(0x00239413u | (1u << 14), 4, &rd, &rs1, &sh));
    CHECK(!rv_decode_slli(0x00239413u | (1u << 30), 4, &rd, &rs1, &sh));
    // sub shares add's opcode and funct3, differing in funct7.
    CHECK(!rv_decode_add(0x00740433u | (0x20u << 25), 4, &rd, &rs1, &rs2));
    // c.jalr and c.ebreak share c.add's funct4 with a zero register.
    CHECK(!rv_decode_add(0x9002u, 2, &rd, &rs1, &rs2));       // c.ebreak
    CHECK(!rv_decode_add(0x9402u, 2, &rd, &rs1, &rs2));       // c.jalr s0
    // c.slli with a zero shift or into x0 is a hint, not a shift.
    CHECK(!rv_decode_slli(0x0402u, 2, &rd, &rs1, &sh));
}

static void test_arch_gate(void)
{
    // Rust and C++ objects in the corpus carry this; Go objects carry no
    // attributes section at all.
    const char *rva23 = "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_b1p0_v1p0_"
                        "zba1p0_zbb1p0_zbs1p0_zvl128b1p0";
    unsigned e = riscvlint_parse_arch(rva23);
    CHECK(e & RISCVLINT_EXT_ZBA);
    CHECK(e & RISCVLINT_EXT_ZBB);
    CHECK(e & RISCVLINT_EXT_ZBS);
    CHECK(e & RISCVLINT_EXT_DECLARED);

    unsigned g = riscvlint_parse_arch("rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0");
    CHECK(!(g & RISCVLINT_EXT_ZBA));
    CHECK(g & RISCVLINT_EXT_DECLARED);

    // No attributes at all: nothing is known, and DECLARED stays clear.
    CHECK(riscvlint_parse_arch(NULL) == 0);

    // -m names: extensions, profiles, and a rejection.
    unsigned m = 0;
    CHECK(riscvlint_parse_ext_name("zba", &m) && m == RISCVLINT_EXT_ZBA);
    CHECK(riscvlint_parse_ext_name("zbb", &m) && m == RISCVLINT_EXT_ZBB);
    CHECK(riscvlint_parse_ext_name("zbs", &m) && m == RISCVLINT_EXT_ZBS);
    // rva20 is the baseline: a valid name that mandates none of the
    // extensions gated here, which is how -m rva20 silences them.
    CHECK(riscvlint_parse_ext_name("rva20", &m) && m == 0);
    CHECK(riscvlint_parse_ext_name("rva22", &m) &&
          m == (RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS));
    // The two profiles used to expand alike. Zcb missed RVA22's
    // ratification window and is mandatory in RVA23U64, so it is the
    // first extension gated here that separates them; test_zcb_gate
    // covers the difference from the other side.
    CHECK(riscvlint_parse_ext_name("rva23", &m) &&
          m == (RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                RISCVLINT_EXT_ZCB));
    CHECK(!riscvlint_parse_ext_name("zbq", &m));
    CHECK(!riscvlint_parse_ext_name("", &m));

    riscvlint_state *st = riscvlint_state_create();
    riscvlint_state_set_extensions(st, e);
    CHECK(riscvlint_may_use(st, RISCVLINT_EXT_ZBA));
    riscvlint_state_set_extensions(st, g);
    CHECK(!riscvlint_may_use(st, RISCVLINT_EXT_ZBA));
    riscvlint_state_set_extensions(st, 0);          // the Go case
    CHECK(riscvlint_may_use(st, RISCVLINT_EXT_ZBA));
    riscvlint_state_destroy(st);
}

static void test_jal_reach(void)
{
    CHECK(rv_jal_reaches(0));
    CHECK(rv_jal_reaches(-1396));
    CHECK(rv_jal_reaches(543472));      // a real in-range site
    CHECK(rv_jal_reaches(1048574));     // largest encodable
    CHECK(rv_jal_reaches(-1048576));    // most negative encodable
    CHECK(!rv_jal_reaches(1048576));    // one step past
    CHECK(!rv_jal_reaches(-1048578));
    CHECK(!rv_jal_reaches(3));          // odd offsets have no encoding
}

// Builds a section from words, runs the check at word 0, and reports
// whether it fired (and with what target).
static bool run_check(csh handle, const uint32_t *words, size_t nwords,
                      uint64_t vaddr, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, words, nwords * 4);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return false;
    bool fired = false;
    if (riscvlint_state_set_section(state, handle, buf, nwords * 4, vaddr)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = nwords * 4;
        uint64_t addr = vaddr;
        if (insn && cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            fired = check_call_pair_to_jal(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_check(csh handle)
{
    riscvlint_finding f;

    // The ripgrep site: auipc ra,0 ; jalr ra,-1396(ra) at 0x6e3a4,
    // targeting memcpy@plt at 0x6de30, 1396 bytes back.
    uint32_t call[] = { 0x00000097u, 0xa8c080e7u, 0x00008067u };
    CHECK(run_check(handle, call, 3, 0x6e3a4, &f));
    CHECK(strcmp(f.replacement, "jal ra, 0x6de30") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x6e3a4);

    // A backward call: imm20 0xfffff is -4096 once sign-extended. Read
    // as an unsigned field it computes as 4 GiB away and the site is
    // dropped -- which is what a check built on capstone's operand does,
    // since capstone reports the raw field. Most calls to a PLT stub
    // near the start of .text have this shape.
    uint32_t back[] = { enc_auipc(1, 0xfffff), enc_jalr(1, 1, 8),
                        0x00008067u };
    CHECK(run_check(handle, back, 3, 0x6ed5a, &f));
    CHECK(strcmp(f.replacement, "jal ra, 0x6dd62") == 0);

    // The same site with nothing but the section base changed: at a low
    // address the target would underflow past zero, which is not an
    // address, so it is not a finding.
    CHECK(!run_check(handle, back, 3, 0x8, NULL));

    // The most negative encodable offset, at an address high enough for
    // it to land somewhere real.
    uint32_t edge_neg[] = { enc_auipc(1, 0xfff00), enc_jalr(1, 1, 0),
                            0x00008067u };
    CHECK(run_check(handle, edge_neg, 3, 0x200000, &f));
    uint32_t past_neg[] = { enc_auipc(1, 0xfff00), enc_jalr(1, 1, -4),
                            0x00008067u };
    CHECK(!run_check(handle, past_neg, 3, 0x200000, NULL));

    // Same shape but the target is past jal's reach: 0x200 pages is
    // 2 MiB away.
    uint32_t far[] = { enc_auipc(1, 0x200), enc_jalr(1, 1, 0), 0x00008067u };
    CHECK(!run_check(handle, far, 3, 0x1000, NULL));

    // Exactly one byte past the boundary does not fire, one step inside
    // does. jal reaches [-2^20, 2^20-2].
    uint32_t edge_in[] = { enc_auipc(1, 0xff), enc_jalr(1, 1, 2046),
                           0x00008067u };
    CHECK(run_check(handle, edge_in, 3, 0, &f));       // 0xff000+2046
    uint32_t edge_out[] = { enc_auipc(1, 0x100), enc_jalr(1, 1, 0),
                            0x00008067u };
    CHECK(!run_check(handle, edge_out, 3, 0, NULL));   // exactly 2^20

    // Tail call: jalr writes x0, so folding to `j` would stop writing
    // the auipc's destination. Not reported without liveness.
    uint32_t tail[] = { enc_auipc(6, 0), enc_jalr(0, 6, 16), 0x00008067u };
    CHECK(!run_check(handle, tail, 3, 0x1000, NULL));

    // The jalr does not consume the auipc.
    uint32_t unrelated[] = { enc_auipc(1, 0), enc_jalr(1, 6, 16),
                             0x00008067u };
    CHECK(!run_check(handle, unrelated, 3, 0x1000, NULL));

    // The jalr's destination differs from the auipc's: the rewrite
    // would leave the auipc's register unwritten.
    uint32_t split[] = { enc_auipc(6, 0), enc_jalr(1, 6, 16), 0x00008067u };
    CHECK(!run_check(handle, split, 3, 0x1000, NULL));

    // auipc into x0 computes nothing.
    uint32_t zero[] = { enc_auipc(0, 0), enc_jalr(0, 0, 16), 0x00008067u };
    CHECK(!run_check(handle, zero, 3, 0x1000, NULL));

    // A side entry onto the jalr: `beqz a0, .+8` lands on the second
    // instruction of the pair, which the rewrite would delete. The
    // branch sits first so the pair starts at word 1.
    uint32_t side[] = {
        0x00050463u,          // beqz a0, .+8  (targets word 2)
        0x00000097u,          // auipc ra, 0
        enc_jalr(1, 1, 16),   // jalr ra, 16(ra)   <- branch target
        0x00008067u,
    };
    static uint8_t buf[256];
    memcpy(buf, side, sizeof side);
    riscvlint_state *state = riscvlint_state_create();
    CHECK(riscvlint_state_set_section(state, handle, buf, sizeof side, 0));
    CHECK(riscvlint_is_branch_target(state, 8));
    cs_insn *insn = cs_malloc(handle);
    const uint8_t *p = buf + 4;
    size_t remain = sizeof side - 4;
    uint64_t addr = 4;
    CHECK(cs_disasm_iter(handle, &p, &remain, &addr, insn));
    riscvlint_finding sf;
    memset(&sf, 0, sizeof sf);
    CHECK(!check_call_pair_to_jal(state, insn, &sf));
    cs_free(insn, 1);
    riscvlint_state_destroy(state);

    // A relocated site: the immediates are placeholders, so no range
    // test on them means anything.
    state = riscvlint_state_create();
    memcpy(buf, call, sizeof call);
    CHECK(riscvlint_state_set_section(state, handle, buf, sizeof call, 0));
    uint64_t reloc_at = 0;
    riscvlint_state_set_relocs(state, &reloc_at, 1);
    insn = cs_malloc(handle);
    p = buf; remain = sizeof call; addr = 0;
    CHECK(cs_disasm_iter(handle, &p, &remain, &addr, insn));
    memset(&sf, 0, sizeof sf);
    CHECK(!check_call_pair_to_jal(state, insn, &sf));
    cs_free(insn, 1);
    riscvlint_state_destroy(state);
}

// Runs check_slli_add_to_shadd over a byte sequence, so the compressed
// spellings can be tested alongside the 4-byte ones.
static bool run_shadd(csh handle, const uint8_t *bytes, size_t len,
                      unsigned exts, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, bytes, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return false;
    bool fired = false;
    riscvlint_state_set_extensions(state, exts);
    if (riscvlint_state_set_section(state, handle, buf, len, 0x1000)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = len;
        uint64_t addr = 0x1000;
        if (insn && cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            fired = check_slli_add_to_shadd(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_shadd_check(csh handle)
{
    riscvlint_finding f;
    // c.slli s0,2 ; c.add s0,t2 -- the commonest spelling, four bytes
    // before and after, so the win is one instruction rather than space.
    const uint8_t cc[] = { 0x0a, 0x04, 0x1e, 0x94, 0x82, 0x80 };
    CHECK(run_shadd(handle, cc, sizeof cc, 0, &f));
    CHECK(strcmp(f.replacement, "sh2add s0, s0, t2 (4 -> 4 bytes)") == 0);

    // slli s0,t2,2 ; c.add s0,t2 -- six bytes down to four.
    const uint8_t mixed[] = { 0x13, 0x94, 0x23, 0x00, 0x1e, 0x94, 0x82, 0x80 };
    CHECK(run_shadd(handle, mixed, sizeof mixed, 0, &f));
    CHECK(strcmp(f.replacement, "sh2add s0, t2, t2 (6 -> 4 bytes)") == 0);

    // Declared without Zba: the object says the instruction does not
    // exist on its target, so nothing is reported.
    CHECK(!run_shadd(handle, cc, sizeof cc,
                     RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBB, NULL));
    // Declared with it, and the Go case of nothing declared at all.
    CHECK(run_shadd(handle, cc, sizeof cc,
                    RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBA, NULL));

    // Shift of 4 has no shNadd.
    const uint8_t sh4[] = { 0x12, 0x04, 0x1e, 0x94, 0x82, 0x80 };
    CHECK(!run_shadd(handle, sh4, sizeof sh4, 0, NULL));

    // add rd,rd,rd doubles the shifted value: a wider shift, not a
    // shift-add. c.add s0,s0 is 0x9422.
    const uint8_t dbl[] = { 0x0a, 0x04, 0x22, 0x94, 0x82, 0x80 };
    CHECK(!run_shadd(handle, dbl, sizeof dbl, 0, NULL));

    // The add does not overwrite the shifted register: folding would
    // drop a value that survives, which needs liveness.
    // slli s0,t2,2 ; add a5,s0,t2  (0x007407b3)
    const uint8_t other[] = { 0x13, 0x94, 0x23, 0x00,
                              0xb3, 0x07, 0x74, 0x00, 0x82, 0x80 };
    CHECK(!run_shadd(handle, other, sizeof other, 0, NULL));

    // sub in place of add.
    const uint8_t sub[] = { 0x13, 0x94, 0x23, 0x00,
                            0x33, 0x04, 0x74, 0x40, 0x82, 0x80 };
    CHECK(!run_shadd(handle, sub, sizeof sub, 0, NULL));
}

static bool run_zext(csh handle, const uint8_t *bytes, size_t len,
                     unsigned exts, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, bytes, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return false;
    bool fired = false;
    riscvlint_state_set_extensions(state, exts);
    if (riscvlint_state_set_section(state, handle, buf, len, 0x1000)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = len;
        uint64_t addr = 0x1000;
        if (insn && cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            fired = check_slli_srli_to_zext(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_zext_check(csh handle)
{
    riscvlint_finding f;
    // slli a4,a2,32 ; c.srli a4,32 -- the shape as gh writes it.
    const uint8_t mixed[] = { 0x13, 0x17, 0x06, 0x02, 0x01, 0x93, 0x82, 0x80 };
    CHECK(run_zext(handle, mixed, sizeof mixed, 0, &f));
    CHECK(strcmp(f.replacement, "zext.w a4, a2 (6 -> 4 bytes)") == 0);

    // c.slli s0,32 ; c.srli s0,32 -- four bytes either way.
    const uint8_t cc[] = { 0x02, 0x14, 0x01, 0x90, 0x82, 0x80 };
    CHECK(run_zext(handle, cc, sizeof cc, 0, &f));
    CHECK(strcmp(f.replacement, "zext.w s0, s0 (4 -> 4 bytes)") == 0);

    // c.slli s0,32 ; c.srai s0,32 shifts in the sign: sext.w, not this.
    const uint8_t sra[] = { 0x02, 0x14, 0x01, 0x94, 0x82, 0x80 };
    CHECK(!run_zext(handle, sra, sizeof sra, 0, NULL));

    // Declared without Zba: silent. Declared with it, or not at all: not.
    CHECK(!run_zext(handle, cc, sizeof cc,
                    RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBB, NULL));
    CHECK(run_zext(handle, cc, sizeof cc,
                   RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBA, NULL));

    // A shift of 31 leaves a bit of the upper word, so it is not a
    // zero-extension of the low 32. Bytes taken from the assembler:
    // `slli s0,s0,31` is 0x047e and `srli s0,s0,31` is 0x807d.
    const uint8_t sh31[] = { 0x7e, 0x04, 0x7d, 0x80, 0x82, 0x80 };
    CHECK(!run_zext(handle, sh31, sizeof sh31, 0, NULL));

    // The srli writes elsewhere, leaving the shifted value alive:
    // slli a4,a2,32 ; srli a5,a4,32 (0x020757b3 is srl, so spell the
    // immediate form 0x02075793).
    const uint8_t other[] = { 0x13, 0x17, 0x06, 0x02,
                              0x93, 0x57, 0x07, 0x02, 0x82, 0x80 };
    CHECK(!run_zext(handle, other, sizeof other, 0, NULL));
}

// ---- redundant stack-pointer restore ----

// This check carries state across the section, so unlike run_check it
// has to be driven over every instruction rather than the first one.
// Sequences here mix 2- and 4-byte encodings, so they are built as bytes.
static int run_sp_restore(csh handle, const uint8_t *code, size_t len,
                          uint64_t vaddr, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, code, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return -1;
    int fired = 0;
    if (riscvlint_state_set_section(state, handle, buf, len, vaddr)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = len;
        uint64_t addr = vaddr;
        while (insn && remain >= 2 &&
               cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            if (check_redundant_sp_restore(state, insn, &f)) {
                if (out && !fired) *out = f;
                fired++;
            }
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_decode_addi(void)
{
    unsigned rd, rs1;
    int64_t imm;

    // `addi sp,s0,-48` at 0x6e3d0 in ripgrep: 0xfd040113. The teardown
    // is always this four-byte form -- no compressed spelling writes sp
    // from another register.
    CHECK(rv_decode_addi(0xfd040113u, 4, &rd, &rs1, &imm));
    CHECK(rd == 2 && rs1 == 8 && imm == -48);

    // `addi s0,sp,48` in its four-byte spelling.
    CHECK(rv_decode_addi(0x03010413u, 4, &rd, &rs1, &imm));
    CHECK(rd == 8 && rs1 == 2 && imm == 48);

    // The same instruction as ripgrep actually spells it at 0x6e36c:
    // `c.addi4spn s0,sp,48`, two bytes, 0x1800. Reading only the 4-byte
    // encoding would miss every prologue in that binary.
    CHECK(rv_decode_addi(0x1800u, 2, &rd, &rs1, &imm));
    CHECK(rd == 8 && rs1 == 2 && imm == 48);

    // c.addi4spn's immediate comes out of four non-adjacent fields;
    // `c.addi4spn a5,sp,16` exercises a different one than 48 does.
    CHECK(rv_decode_addi(0x081cu, 2, &rd, &rs1, &imm));
    CHECK(rd == 15 && rs1 == 2 && imm == 16);

    // A zero immediate is the reserved encoding, not an addi of nothing.
    CHECK(!rv_decode_addi(0x0000u, 2, &rd, &rs1, &imm));

    // The other compressed addi spellings are not decoded here, because
    // neither can express a frame-pointer prologue or its restore:
    // `c.addi sp,sp,-16` and `c.addi16sp sp,-16` both write sp from sp.
    CHECK(!rv_decode_addi(0x1141u, 2, &rd, &rs1, &imm));
    CHECK(!rv_decode_addi(0x7139u, 2, &rd, &rs1, &imm));

    // Not an addi at all: funct3 001 is slli, and 0x33 is OP.
    CHECK(!rv_decode_addi(0x00151513u, 4, &rd, &rs1, &imm));
    CHECK(!rv_decode_addi(0x00a58533u, 4, &rd, &rs1, &imm));
}

static void test_sp_restore_check(csh handle)
{
    riscvlint_finding f;

    // The ripgrep shape, cut down: allocate, establish the frame
    // pointer, do something, restore sp from it. Nothing moved sp, so
    // the restore assigns it the value it already holds.
    static const uint8_t plain[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0x13, 0x00, 0x00, 0x00,        // nop
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, plain, sizeof plain, 0x1000, &f) == 1);
    CHECK(f.insn_count == 1 && f.address == 0x1008);
    CHECK(strstr(f.replacement, "delete; sp already holds s0-48") != NULL);

    // A call between the two does not disqualify it, and this is the
    // whole reason the check carries the prologue rather than working
    // region-locally: every frame-pointer function in the corpus has
    // calls between its prologue and its epilogue. What a callee does
    // to sp is not an assumption being made here -- a callee that
    // returned with sp and s0 no longer a fixed distance apart would
    // have invalidated the caller's frame, not just this rewrite.
    static const uint8_t across_call[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0xef, 0x00, 0x00, 0x01,        // jal ra, .+16 (out of section)
        0x13, 0x00, 0x00, 0x00,        // nop
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, across_call, sizeof across_call, 0x1000,
                         NULL) == 1);

    // sp moved in between: the frame is not where the prologue left it,
    // so the restore is doing real work. This is the alloca/VLA case.
    static const uint8_t sp_moved[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0x13, 0x01, 0x01, 0xff,        // addi sp,sp,-16
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, sp_moved, sizeof sp_moved, 0x1000,
                         NULL) == 0);

    // s0 reloaded in between: whatever it holds at the restore is not
    // what the prologue put there.
    static const uint8_t fp_clobbered[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0x03, 0x34, 0x01, 0x00,        // ld s0,0(sp)
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, fp_clobbered, sizeof fp_clobbered, 0x1000,
                         NULL) == 0);

    // The displacements have to be opposites. `addi sp,s0,-32` after
    // `addi s0,sp,48` computes a different address on purpose.
    static const uint8_t mismatched[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0x13, 0x01, 0x04, 0xfe,        // addi sp,s0,-32
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, mismatched, sizeof mismatched, 0x1000,
                         NULL) == 0);

    // No prologue at all: a restore with nothing to match it is not a
    // finding, which is also what keeps a prologue from one function
    // being matched against a restore in the next.
    static const uint8_t orphan[] = {
        0x13, 0x00, 0x00, 0x00,        // nop
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, orphan, sizeof orphan, 0x1000, NULL) == 0);

    // A shared epilogue: something branches to the restore, so it can be
    // reached from code the linear scan has not walked, and that code
    // may have moved sp. 17% of the corpus population has this shape and
    // the check gives all of it up rather than assume.
    static const uint8_t shared[] = {
        0x79, 0x71,                    // c.addi sp,sp,-48
        0x00, 0x18,                    // c.addi4spn s0,sp,48
        0x63, 0x04, 0x05, 0x00,        // beqz a0, .+8   (targets the addi)
        0x13, 0x00, 0x00, 0x00,        // nop
        0x13, 0x01, 0x04, 0xfd,        // addi sp,s0,-48  <- branch target
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_sp_restore(handle, shared, sizeof shared, 0x1000, NULL) == 0);
}

// ---- redundant sign or zero extension ----

static int run_redundant_ext(csh handle, const uint8_t *code, size_t len,
                             uint64_t vaddr, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, code, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return -1;
    int fired = 0;
    if (riscvlint_state_set_section(state, handle, buf, len, vaddr)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = len;
        uint64_t addr = vaddr;
        while (insn && remain >= 2 &&
               cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            if (check_redundant_extension(state, insn, &f)) {
                if (out && !fired) *out = f;
                fired++;
            }
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_result_guarantees(void)
{
    unsigned rd = 99, g;

    // `lw a0,0(a1)` sign-extends from bit 31 and says nothing narrower.
    g = rv_result_guarantees(0x0005a503u, 4, &rd);
    CHECK(rd == 10 && g == RISCVLINT_G_SEXT32);

    // `lbu a0,0(a1)` bounds the value to 0..255, which closes upward
    // through both families -- including sign-extension to 32, since
    // bit 31 of such a value is zero.
    g = rv_result_guarantees(0x0005c503u, 4, &rd);
    CHECK(rd == 10);
    CHECK((g & RISCVLINT_G_ZEXT8) && (g & RISCVLINT_G_ZEXT16) &&
          (g & RISCVLINT_G_ZEXT32) && (g & RISCVLINT_G_SEXT32));
    CHECK(!(g & RISCVLINT_G_SEXT8));   // 200 is not sign-extended from bit 7

    // `lwu a0,0(a1)` is the counter-example the whole model turns on:
    // zero-extended to 32 does NOT imply sign-extended to 32, because
    // 0x80000000 is a legal result.
    g = rv_result_guarantees(0x0005e503u, 4, &rd);
    CHECK((g & RISCVLINT_G_ZEXT32) && !(g & RISCVLINT_G_SEXT32));

    // `andi a0,a1,1` bounds the result by its mask, which is how the
    // check catches sites a producer list keyed on mnemonics misses.
    g = rv_result_guarantees(0x0015f513u, 4, &rd);
    CHECK(rd == 10 && (g & RISCVLINT_G_ZEXT8));

    // A mask too wide for 8 bits stops at 16.
    g = rv_result_guarantees(0x7ff5f513u, 4, &rd);          // andi a0,a1,2047
    CHECK(!(g & RISCVLINT_G_ZEXT8) && (g & RISCVLINT_G_ZEXT16));

    // Every OP-IMM-32 result is sign-extended from bit 31 by definition.
    g = rv_result_guarantees(0x0015051bu, 4, &rd);          // addiw a0,a0,1
    CHECK(g == RISCVLINT_G_SEXT32);

    // c.lbu, two bytes: the same guarantee as its wide spelling.
    g = rv_result_guarantees(0x8188u, 2, &rd);
    CHECK(rd == 10 && (g & RISCVLINT_G_ZEXT8));

    // c.zext.b is itself a producer as well as an extension.
    g = rv_result_guarantees(0x9d61u, 2, &rd);
    CHECK(rd == 10 && (g & RISCVLINT_G_ZEXT8));

    // `ld` and `add` guarantee nothing about the high half.
    CHECK(rv_result_guarantees(0x0005b503u, 4, &rd) == 0); // ld a0,0(a1)
    CHECK(rv_result_guarantees(0x00c58533u, 4, &rd) == 0); // add a0,a1,a2
}

static void test_decode_extension(void)
{
    unsigned rd, rs1, g;

    // sext.w is `addiw rd,rs,0`, not a mnemonic of its own.
    CHECK(rv_decode_extension(0x0005061bu, 4, &rd, &rs1, &g));
    CHECK(rd == 12 && rs1 == 10 && g == RISCVLINT_G_SEXT32);
    // The same opcode with a non-zero immediate is an addition.
    CHECK(!rv_decode_extension(0x0015061bu, 4, &rd, &rs1, &g));

    // zext.w is `add.uw rd,rs,x0`; with a real rs2 it is an addition.
    CHECK(rv_decode_extension(0x0805053bu, 4, &rd, &rs1, &g));
    CHECK(rd == 10 && rs1 == 10 && g == RISCVLINT_G_ZEXT32);
    CHECK(!rv_decode_extension(0x08c5053bu, 4, &rd, &rs1, &g));

    // zext.h, sext.b and sext.h.
    CHECK(rv_decode_extension(0x0805453bu, 4, &rd, &rs1, &g));
    CHECK(g == RISCVLINT_G_ZEXT16);
    CHECK(rv_decode_extension(0x60451513u, 4, &rd, &rs1, &g));
    CHECK(g == RISCVLINT_G_SEXT8);
    CHECK(rv_decode_extension(0x60551513u, 4, &rd, &rs1, &g));
    CHECK(g == RISCVLINT_G_SEXT16);

    // zext.b is `andi rd,rs,255`; any other mask is a real mask.
    CHECK(rv_decode_extension(0x0ff57513u, 4, &rd, &rs1, &g));
    CHECK(rd == 10 && rs1 == 10 && g == RISCVLINT_G_ZEXT8);
    CHECK(!rv_decode_extension(0x0015f513u, 4, &rd, &rs1, &g));

    // The two-byte spellings, which is where most of the corpus's
    // extensions are. `c.addiw a0,0` at 0x2501 is `sext.w a0,a0`, and
    // `c.zext.b a0` at 0x9d61 is the one capstone prints as
    // `andi a0,a0,0xff` -- reading that as the four-byte form is how
    // this check first came out a fifth short.
    CHECK(rv_decode_extension(0x2501u, 2, &rd, &rs1, &g));
    CHECK(rd == 10 && rs1 == 10 && g == RISCVLINT_G_SEXT32);
    CHECK(rv_decode_extension(0x9d61u, 2, &rd, &rs1, &g));
    CHECK(rd == 10 && rs1 == 10 && g == RISCVLINT_G_ZEXT8);
    // c.addiw with a non-zero immediate, and c.not, are not extensions.
    CHECK(!rv_decode_extension(0x2505u, 2, &rd, &rs1, &g));
    CHECK(!rv_decode_extension(0x9d75u, 2, &rd, &rs1, &g));
}

static void test_redundant_ext_check(csh handle)
{
    riscvlint_finding f;

    // The ripgrep site at 0xc55d8, cut down: `andi a0,a1,1` bounds the
    // value to one bit, and the c.zext.b two instructions later cannot
    // change it.
    //
    // The trailing `ret` is load-bearing. riscvlint_word_at reads four
    // bytes, so a two-byte instruction in the last two bytes of a
    // section cannot be read at all and no check fires on it. Real code
    // never ends a section on one of these, but a fixture will.
    static const uint8_t masked[] = {
        0x13, 0xf5, 0x15, 0x00,        // andi a0,a1,1
        0x13, 0x00, 0x00, 0x00,        // nop
        0x61, 0x9d,                    // c.zext.b a0
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_redundant_ext(handle, masked, sizeof masked, 0x1000, &f) == 1);
    CHECK(f.insn_count == 1 && f.address == 0x1008);
    CHECK(strcmp(f.replacement,
                 "delete; a0 is already zext.b (2 bytes)") == 0);

    // Writing elsewhere makes it a copy rather than a deletion, and a
    // four-byte extension becomes a two-byte c.mv.
    static const uint8_t to_mv[] = {
        0x03, 0xa5, 0x05, 0x00,        // lw a0,0(a1)
        0x1b, 0x06, 0x05, 0x00,        // sext.w a2,a0
    };
    CHECK(run_redundant_ext(handle, to_mv, sizeof to_mv, 0x1000, &f) == 1);
    CHECK(strcmp(f.replacement,
                 "mv a2, a0; a0 is already sext.w (4 -> 2 bytes)") == 0);

    // The counter-example: lwu zero-extends, and sext.w of 0x80000000 is
    // not the same value. Not a finding.
    static const uint8_t lwu_sextw[] = {
        0x03, 0xe5, 0x05, 0x00,        // lwu a0,0(a1)
        0x1b, 0x05, 0x05, 0x00,        // sext.w a0,a0
    };
    CHECK(run_redundant_ext(handle, lwu_sextw, sizeof lwu_sextw, 0x1000,
                            NULL) == 0);

    // The producer is overwritten before the extension reads it.
    static const uint8_t clobbered[] = {
        0x03, 0xc5, 0x05, 0x00,        // lbu a0,0(a1)
        0x03, 0xb5, 0x05, 0x00,        // ld a0,0(a1)
        0x61, 0x9d,                    // c.zext.b a0
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_redundant_ext(handle, clobbered, sizeof clobbered, 0x1000,
                            NULL) == 0);

    // A call in between: the table is cleared outright rather than
    // trusting a register model at the place it is known to be thin.
    static const uint8_t across_call[] = {
        0x03, 0xc5, 0x05, 0x00,        // lbu a0,0(a1)
        0xef, 0x00, 0x00, 0x01,        // jal ra, .+16 (out of section)
        0x61, 0x9d,                    // c.zext.b a0
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_redundant_ext(handle, across_call, sizeof across_call, 0x1000,
                            NULL) == 0);

    // A side entry onto the extension: the value reaching it was not
    // necessarily produced by what precedes it in address order.
    static const uint8_t side[] = {
        0x03, 0xc5, 0x05, 0x00,        // lbu a0,0(a1)
        0x63, 0x04, 0x05, 0x00,        // beqz a0, .+8  (targets the zext)
        0x13, 0x00, 0x00, 0x00,        // nop
        0x61, 0x9d,                    // c.zext.b a0   <- branch target
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_redundant_ext(handle, side, sizeof side, 0x1000, NULL) == 0);
}

// ---- Zcb encodability ----

static void test_zcb_form(void)
{
    // Every encoding below came out of `riscv64-linux-gnu-as
    // -march=rv64gc_zba_zbb_zcb` with `.option norvc`, so the wide forms
    // are the assembler's own rather than hand-assembled -- and the
    // compressed answers were checked against both GNU as and clang
    // without norvc.

    // c.lbu carries an unsigned two-bit byte offset.
    CHECK(!strcmp(rv_zcb_form(0x0005c503u, 4), "c.lbu"));   // lbu a0,0(a1)
    CHECK(!strcmp(rv_zcb_form(0x0035c503u, 4), "c.lbu"));   // lbu a0,3(a1)
    CHECK(rv_zcb_form(0x0045c503u, 4) == NULL);             // lbu a0,4(a1)
    CHECK(rv_zcb_form(0xfff5c503u, 4) == NULL);             // lbu a0,-1(a1)

    // Both registers have to be nameable by a three-bit field.
    CHECK(rv_zcb_form(0x00084503u, 4) == NULL);             // lbu a0,0(a6)
    CHECK(rv_zcb_form(0x0005c803u, 4) == NULL);             // lbu a6,0(a1)

    // c.lhu and c.lh share a one-bit field naming the halfword.
    CHECK(!strcmp(rv_zcb_form(0x0025d503u, 4), "c.lhu"));   // lhu a0,2(a1)
    CHECK(rv_zcb_form(0x0045d503u, 4) == NULL);             // lhu a0,4(a1)
    CHECK(!strcmp(rv_zcb_form(0x00259503u, 4), "c.lh"));    // lh a0,2(a1)

    // The stores split their immediate across two fields, which is its
    // own chance to decode the offset wrongly.
    CHECK(!strcmp(rv_zcb_form(0x00a581a3u, 4), "c.sb"));    // sb a0,3(a1)
    CHECK(rv_zcb_form(0x00a58223u, 4) == NULL);             // sb a0,4(a1)
    CHECK(!strcmp(rv_zcb_form(0x00a59123u, 4), "c.sh"));    // sh a0,2(a1)

    // The unary forms write the register they read.
    CHECK(!strcmp(rv_zcb_form(0x0ff57513u, 4), "c.zext.b")); // andi a0,a0,255
    CHECK(rv_zcb_form(0x0ff5f513u, 4) == NULL);              // andi a0,a1,255
    CHECK(!strcmp(rv_zcb_form(0xfff54513u, 4), "c.not"));    // xori a0,a0,-1
    CHECK(rv_zcb_form(0xfff84813u, 4) == NULL);              // xori a6,a6,-1
    CHECK(!strcmp(rv_zcb_form(0x60451513u, 4), "c.sext.b"));
    CHECK(!strcmp(rv_zcb_form(0x60551513u, 4), "c.sext.h"));
    CHECK(!strcmp(rv_zcb_form(0x0805453bu, 4), "c.zext.h"));
    CHECK(!strcmp(rv_zcb_form(0x0805053bu, 4), "c.zext.w"));

    // Zcb has no c.sext.w, so `sext.w a0,a0` is not a finding however it
    // is spelled.
    CHECK(rv_zcb_form(0x0005051bu, 4) == NULL);              // addiw a0,a0,0

    // c.mul is `rd = rd * rs2'`, and multiplication commutes, so either
    // source may be the destination. clang compresses both orders and
    // GNU as only the first; both are encodable and both are reported.
    CHECK(!strcmp(rv_zcb_form(0x02b50533u, 4), "c.mul"));   // mul a0,a0,a1
    CHECK(!strcmp(rv_zcb_form(0x02a58533u, 4), "c.mul"));   // mul a0,a1,a0
    CHECK(rv_zcb_form(0x02c58533u, 4) == NULL);             // mul a0,a1,a2
    CHECK(rv_zcb_form(0x02b80833u, 4) == NULL);             // mul a6,a6,a1

    // Instructions with no Zcb spelling at all, and the two-byte
    // encodings the question is not asked of.
    CHECK(rv_zcb_form(0x00b50533u, 4) == NULL);   // add a0,a0,a1
    CHECK(rv_zcb_form(0x0005b503u, 4) == NULL);   // ld  a0,0(a1)
    CHECK(rv_zcb_form(0x9d61u, 2) == NULL);       // already c.zext.b
}

static void test_zcb_gate(void)
{
    unsigned e;

    // The arch string is where it usually comes from.
    CHECK(riscvlint_parse_arch("rv64i2p1_m2p0_zca1p0_zcb1p0_zcd1p0") &
          RISCVLINT_EXT_ZCB);
    // zcd and zca are not zcb, and neither is a bare rv64gc.
    CHECK(!(riscvlint_parse_arch("rv64i2p1_m2p0_zca1p0_zcd1p0") &
            RISCVLINT_EXT_ZCB));
    CHECK(!(riscvlint_parse_arch("rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0") &
            RISCVLINT_EXT_ZCB));

    // Zcb is the first extension gated here that tells RVA22 and RVA23
    // apart: it missed RVA22's ratification window.
    CHECK(riscvlint_parse_ext_name("zcb", &e) && e == RISCVLINT_EXT_ZCB);
    CHECK(riscvlint_parse_ext_name("rva22", &e) && !(e & RISCVLINT_EXT_ZCB));
    CHECK(riscvlint_parse_ext_name("rva23", &e) && (e & RISCVLINT_EXT_ZCB));
    CHECK(riscvlint_parse_ext_name("rva20", &e) && e == 0);
}

static void test_zcb_check(csh handle)
{
    riscvlint_finding f;

    // A four-byte lbu that c.lbu could spell, in an object that declares
    // Zcb: reported. The ret keeps riscvlint_word_at in bounds.
    static const uint8_t wide[] = {
        0x03, 0xc5, 0x35, 0x00,        // lbu a0,3(a1)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    riscvlint_state *state = riscvlint_state_create();
    CHECK(state != NULL);
    riscvlint_state_set_extensions(state,
                                   RISCVLINT_EXT_ZCB | RISCVLINT_EXT_DECLARED);
    static uint8_t buf[64];
    memcpy(buf, wide, sizeof wide);
    CHECK(riscvlint_state_set_section(state, handle, buf, sizeof wide, 0x1000));
    cs_insn *insn = cs_malloc(handle);
    const uint8_t *p = buf;
    size_t remain = sizeof wide;
    uint64_t addr = 0x1000;
    CHECK(insn && cs_disasm_iter(handle, &p, &remain, &addr, insn));
    memset(&f, 0, sizeof f);
    CHECK(check_zcb_compressible(state, insn, &f));
    CHECK(!strcmp(f.replacement, "c.lbu (4 -> 2 bytes)"));
    CHECK(f.insn_count == 1 && f.address == 0x1000);

    // The same instruction in an object that declares an arch without
    // Zcb: silent. Suggesting an instruction the target does not
    // implement is worse than saying nothing.
    riscvlint_state_set_extensions(state, RISCVLINT_EXT_ZBA |
                                   RISCVLINT_EXT_DECLARED);
    memset(&f, 0, sizeof f);
    CHECK(!check_zcb_compressible(state, insn, &f));

    // And in an object that declares nothing at all -- Go emits no
    // attributes -- the gate stays open, as it does for every other
    // extension here.
    riscvlint_state_set_extensions(state, 0);
    memset(&f, 0, sizeof f);
    CHECK(check_zcb_compressible(state, insn, &f));

    if (insn) cs_free(insn, 1);
    riscvlint_state_destroy(state);
}

int main(void)
{
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RISCVLINT_CS_MODE, &handle) != CS_ERR_OK) {
        printf("FAIL: cs_open\n");
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    test_decode_auipc();
    test_decode_jalr();
    test_jal_reach();
    test_decode_shift_add();
    test_decode_addi();
    test_result_guarantees();
    test_decode_extension();
    test_arch_gate();
    test_zcb_form();
    test_zcb_gate();
    test_check(handle);
    test_shadd_check(handle);
    test_zext_check(handle);
    test_sp_restore_check(handle);
    test_redundant_ext_check(handle);
    test_zcb_check(handle);

    cs_close(&handle);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
