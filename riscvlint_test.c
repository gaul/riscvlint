// Unit tests for riscvlint. The decoders and the reach test are where a
// silent bug turns into a wrong finding, so they are tested against
// encodings taken from real binaries rather than only synthetic ones.

#include "riscvlint.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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
    // Every profile from RVA20 up mandates C, so rva20 is no longer the
    // name that silences everything -- it silences the Zb* families and
    // leaves the compression check on.
    CHECK(riscvlint_parse_ext_name("rva20", &m) && m == RISCVLINT_EXT_C);
    CHECK(riscvlint_parse_ext_name("rva22", &m) &&
          m == (RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                RISCVLINT_EXT_C));
    // The two profiles used to expand alike. Zcb missed RVA22's
    // ratification window and is mandatory in RVA23U64, so it is the
    // first extension gated here that separates them; test_zcb_gate
    // covers the difference from the other side. Zfa is mandatory
    // there too, and is the second.
    CHECK(riscvlint_parse_ext_name("rva23", &m) &&
          m == (RISCVLINT_EXT_ZBA | RISCVLINT_EXT_ZBB | RISCVLINT_EXT_ZBS |
                RISCVLINT_EXT_ZCB | RISCVLINT_EXT_C | RISCVLINT_EXT_ZFA));
    CHECK(riscvlint_parse_ext_name("zfa", &m) && m == RISCVLINT_EXT_ZFA);
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
    CHECK(riscvlint_parse_ext_name("rva20", &e) && e == RISCVLINT_EXT_C);
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

// ---- memory accesses ----

static void test_decode_mem(void)
{
    rv_mem_kind k;
    unsigned data, base;
    int64_t off;

    // Every encoding here is the assembler's own. The decoder was
    // checked exhaustively against `clang -march=rv64gc_zba_zbb_zcb`
    // over 1,668 loads and stores -- every width, both files, offsets
    // in and out of each compressed field's range -- and agrees on all
    // of them; these are the shapes worth pinning in the suite.
    CHECK(rv_decode_mem(0x0005b503u, 4, &k, &data, &base, &off));   // ld a0,0(a1)
    CHECK(k == RV_MEM_LD && data == 10 && base == 11 && off == 0);

    // A store's immediate is split across two fields, which is its own
    // chance to decode the offset wrongly.
    CHECK(rv_decode_mem(0x00a5b423u, 4, &k, &data, &base, &off));   // sd a0,8(a1)
    CHECK(k == RV_MEM_SD && data == 10 && base == 11 && off == 8);
    CHECK(rv_decode_mem(0xfea5bc23u, 4, &k, &data, &base, &off));   // sd a0,-8(a1)
    CHECK(k == RV_MEM_SD && off == -8);

    // The floating-point forms name a register in the other file.
    CHECK(rv_decode_mem(0x00c5a507u, 4, &k, &data, &base, &off));   // flw fa0,12(a1)
    CHECK(k == RV_MEM_FLW && rv_mem_is_fp(k) && data == 10 && base == 11);
    CHECK(off == 12);

    // Quadrant-0 compressed forms, whose offsets are scaled.
    CHECK(rv_decode_mem(0x6188u, 2, &k, &data, &base, &off));       // c.ld a0,0(a1)
    CHECK(k == RV_MEM_LD && data == 10 && base == 11 && off == 0);
    CHECK(rv_decode_mem(0x41c8u, 2, &k, &data, &base, &off));       // c.lw a0,4(a1)
    CHECK(k == RV_MEM_LW && off == 4);

    // Zcb's byte and halfword forms, where the corpus keeps 141,746 of
    // its compressed accesses.
    CHECK(rv_decode_mem(0x81e8u, 2, &k, &data, &base, &off));       // c.lbu a0,3(a1)
    CHECK(k == RV_MEM_LBU && data == 10 && base == 11 && off == 3);
    CHECK(rv_decode_mem(0x85a8u, 2, &k, &data, &base, &off));       // c.lhu a0,2(a1)
    CHECK(k == RV_MEM_LHU && off == 2);
    CHECK(rv_decode_mem(0x85e8u, 2, &k, &data, &base, &off));       // c.lh a0,2(a1)
    CHECK(k == RV_MEM_LH && off == 2);

    // Quadrant 2, whose base is always sp and whose register field is
    // the full five bits. The windowed memory table cannot do without
    // these: a frame slot stored twice is spelled c.sdsp far more often
    // than sd. They are inert for the fold check, which refuses sp as a
    // destination and so can never pair with one.
    CHECK(rv_decode_mem(0x6522u, 2, &k, &data, &base, &off));       // c.ldsp a0,8(sp)
    CHECK(k == RV_MEM_LD && data == 10 && base == 2 && off == 8);
    CHECK(rv_decode_mem(0xe42au, 2, &k, &data, &base, &off));       // c.sdsp a0,8(sp)
    CHECK(k == RV_MEM_SD && data == 10 && base == 2 && off == 8);
    // Its offsets reach further than quadrant 0's and are assembled out
    // of fields in a different order, which is its own chance to be
    // wrong: this one is 504, the largest c.sdsp can express.
    CHECK(rv_decode_mem(0xffaau, 2, &k, &data, &base, &off));       // c.sdsp a0,504(sp)
    CHECK(k == RV_MEM_SD && data == 10 && base == 2 && off == 504);

    // Not memory at all.
    CHECK(!rv_decode_mem(0x00b50533u, 4, &k, &data, &base, &off));  // add a0,a0,a1
}

static void test_mem_encoded_size(void)
{
    // Quadrant 0: both registers in x8-x15, offset scaled by the width.
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 10, 11, 8, true) == 2);
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 10, 11, 4, true) == 4);   // misaligned
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 10, 11, 256, true) == 4); // out of range
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 16, 11, 8, true) == 4);   // a6
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 10, 16, 8, true) == 4);

    // Quadrant 2 reaches further and names any register, which is why a
    // fold onto sp can still come out at two bytes.
    CHECK(rv_mem_encoded_size(RV_MEM_SD, 14, 2, 24, true) == 2);   // c.sdsp
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 16, 2, 504, true) == 2);  // c.ldsp a6
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 16, 2, 512, true) == 4);
    // c.lwsp and c.ldsp cannot name x0; the float file has no such hole.
    CHECK(rv_mem_encoded_size(RV_MEM_LD, 0, 2, 8, true) == 4);
    CHECK(rv_mem_encoded_size(RV_MEM_FLD, 0, 2, 8, true) == 2);

    // The Zcb forms are two bytes only where the target has Zcb.
    CHECK(rv_mem_encoded_size(RV_MEM_LBU, 10, 11, 3, true) == 2);
    CHECK(rv_mem_encoded_size(RV_MEM_LBU, 10, 11, 3, false) == 4);
    CHECK(rv_mem_encoded_size(RV_MEM_LBU, 10, 11, 4, true) == 4);

    // lb, lwu, flw and fsw have no compressed spelling on RV64.
    CHECK(rv_mem_encoded_size(RV_MEM_LB, 10, 11, 0, true) == 4);
    CHECK(rv_mem_encoded_size(RV_MEM_LWU, 10, 11, 0, true) == 4);
    CHECK(rv_mem_encoded_size(RV_MEM_FLW, 10, 11, 0, true) == 4);
}

static void test_decode_base_add(void)
{
    unsigned rd, rs1;
    int64_t imm;

    CHECK(rv_decode_base_add(0x01158793u, 4, &rd, &rs1, &imm));  // addi a5,a1,17
    CHECK(rd == 15 && rs1 == 11 && imm == 17);
    // c.addi adjusts a base in place, which is as much an address
    // computation as forming a new one.
    CHECK(rv_decode_base_add(0x07a1u, 2, &rd, &rs1, &imm));      // c.addi a5,8
    CHECK(rd == 15 && rs1 == 15 && imm == 8);
    // c.mv is an addition of zero.
    CHECK(rv_decode_base_add(0x87bau, 2, &rd, &rs1, &imm));      // c.mv a5,a4
    CHECK(rd == 15 && rs1 == 14 && imm == 0);
    CHECK(rv_decode_base_add(0x1800u, 2, &rd, &rs1, &imm));      // c.addi4spn s0,sp,48
    CHECK(rd == 8 && rs1 == 2 && imm == 48);

    // c.add reads its destination as an operand, so it is not this.
    CHECK(!rv_decode_base_add(0x97bau, 2, &rd, &rs1, &imm));     // c.add a5,a4
    // addiw sign-extends from 32 bits, so its result is not rs + imm.
    CHECK(!rv_decode_base_add(0x0085079bu, 4, &rd, &rs1, &imm)); // addiw a5,a0,8
}

// ---- the windowed memory and constant table ----

// These three read a table the driver fills, so unlike every other
// runner here this one has to call riscvlint_state_observe -- and after
// the checks, which is the order the driver uses and the order the
// answers depend on.
// The window checks, run over a buffer with `exts` declared. Zero is
// the Go case -- no attributes at all -- under which every gate opens.
static int run_window_exts(csh handle, riscvlint_check_fn fn,
                           const uint8_t *code, size_t len, uint64_t vaddr,
                           unsigned exts, riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, code, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return -1;
    riscvlint_state_set_extensions(state, exts);
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
            if (fn(state, insn, &f)) {
                if (out && !fired) *out = f;
                fired++;
            }
            riscvlint_state_observe(state, insn);
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static int run_window(csh handle, riscvlint_check_fn fn, const uint8_t *code,
                      size_t len, uint64_t vaddr, riscvlint_finding *out)
{
    return run_window_exts(handle, fn, code, len, vaddr, 0, out);
}

static void test_window_checks(csh handle)
{
    riscvlint_finding f;

    // The same address loaded twice with only arithmetic between them.
    static const uint8_t reload[] = {
        0x88, 0x65,                    // c.ld a0,8(a1)
        0x05, 0x06,                    // c.addi a2,1
        0x94, 0x65,                    // c.ld a3,8(a1)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_reload, reload, sizeof reload,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1004 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "mv a3, a0") != NULL);

    // A store in between. Proving it lands elsewhere needs more than the
    // encoding gives, so every held value goes.
    static const uint8_t stored[] = {
        0x88, 0x65,                    // c.ld a0,8(a1)
        0x98, 0xe2,                    // c.sd a4,0(a3)
        0x94, 0x65,                    // c.ld a3,8(a1)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_reload, stored, sizeof stored,
                     0x1000, NULL) == 0);

    // A store to a disjoint range through the same base provably misses
    // what the first load read, so the claim stands.
    static const uint8_t disjoint[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x3a, 0xf0,                    // c.sdsp a4,32(sp)
        0xc2, 0x66,                    // c.ldsp a3,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_reload, disjoint, sizeof disjoint,
                     0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "mv a3, a0") != NULL);

    // The same base with the ranges overlapping: 20(sp) lands inside the
    // eight bytes at 16(sp), so it does not miss them.
    static const uint8_t overlap[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x3a, 0xca,                    // c.swsp a4,20(sp)
        0xc2, 0x66,                    // c.ldsp a3,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_reload, overlap, sizeof overlap,
                     0x1000, NULL) == 0);

    // A frame slot stored twice with nothing reading it.
    static const uint8_t deadst[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x3a, 0xe8,                    // c.sdsp a4,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_dead_store, deadst, sizeof deadst,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1000 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "16(sp) is overwritten") != NULL);

    // A load from the same slot is the read that keeps it alive.
    static const uint8_t readback[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0xc2, 0x67,                    // c.ldsp a5,16(sp)
        0x3a, 0xe8,                    // c.sdsp a4,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_dead_store, readback, sizeof readback,
                     0x1000, NULL) == 0);

    // A slot loaded and then written straight back: the store puts back
    // what it read, so it is the store that goes.
    static const uint8_t silent[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silent, sizeof silent,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1004 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "16(sp) already holds a0") != NULL);
    CHECK(strstr(f.replacement, "from the load at 0x1000") != NULL);

    // The record's kind is not the store's and must not have to be:
    // `lwu` says what went into the register, not what is in memory.
    static const uint8_t silentw[] = {
        0x03, 0x65, 0x01, 0x01,        // lwu a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x2a, 0xc8,                    // c.swsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentw, sizeof silentw,
                     0x1000, NULL) == 1);

    // The width does have to match. A four-byte store over an
    // eight-byte record writes bytes the record covers, but proving that
    // is a rule the corpus never needed.
    static const uint8_t silentnarrow[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x2a, 0xc8,                    // c.swsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentnarrow,
                     sizeof silentnarrow, 0x1000, NULL) == 0);

    // A different register is a different value.
    static const uint8_t silentother[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x3a, 0xe8,                    // c.sdsp a4,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentother,
                     sizeof silentother, 0x1000, NULL) == 0);

    // An overlapping store between takes the held value away.
    static const uint8_t silentover[] = {
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x3a, 0xca,                    // c.swsp a4,20(sp)
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentover,
                     sizeof silentover, 0x1000, NULL) == 0);

    // Two stores of the same register with nothing between: this is
    // check_dead_store's finding, which deletes the other one, so this
    // check stands down.
    static const uint8_t silentdead[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentdead,
                     sizeof silentdead, 0x1000, NULL) == 0);
    CHECK(run_window(handle, check_dead_store, silentdead, sizeof silentdead,
                     0x1000, NULL) == 1);

    // The same two stores with a conditional branch between them, which
    // is where the two checks part. `unread` is gone -- the overwrite is
    // not certain -- and `held` is not, because the second store is
    // reached by falling through. 5,622 of the corpus population is this
    // shape.
    static const uint8_t silentbr[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x11, 0xc2,                    // c.beqz a2,0x1006
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_dead_store, silentbr, sizeof silentbr,
                     0x1000, NULL) == 0);
    CHECK(run_window(handle, check_silent_store, silentbr, sizeof silentbr,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1004);
    CHECK(strstr(f.replacement, "from the store at 0x1000") != NULL);

    // A heap address may alias anything and may be a device register, so
    // only frame slots are claimed -- the dead store's restriction, for
    // the dead store's reason.
    static const uint8_t silentheap[] = {
        0x88, 0x65,                    // c.ld a0,8(a1)
        0x05, 0x06,                    // c.addi a2,1
        0x88, 0xe5,                    // c.sd a0,8(a1)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_silent_store, silentheap,
                     sizeof silentheap, 0x1000, NULL) == 0);

    // A constant materialized twice, both four bytes wide.
    static const uint8_t remat[] = {
        0x93, 0x07, 0x20, 0x4d,        // li a5,1234
        0x05, 0x06,                    // c.addi a2,1
        0x13, 0x08, 0x20, 0x4d,        // li a6,1234
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_const_remat, remat, sizeof remat,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1006);
    CHECK(strstr(f.replacement, "mv a6, a5") != NULL);

    // The load overwrites its own base, so the address the second one
    // computes is not the address the first one used. This was a false
    // positive on the first corpus run -- `ld a1,0(a1)` walks a pointer
    // -- and 67 of ripgrep's 151 reload findings were it.
    static const uint8_t walk[] = {
        0x8c, 0x61,                    // c.ld a1,0(a1)
        0x90, 0x61,                    // c.ld a2,0(a1)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_reload, walk, sizeof walk,
                     0x1000, NULL) == 0);

    // A conditional branch between the two stores. "Dead" means the
    // overwrite is certain, and on the taken path it does not happen at
    // all. 32 of ripgrep's 37 first dead-store findings were this.
    static const uint8_t skipped[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x11, 0xe2,                    // c.beqz a2,.+4
        0x3a, 0xe8,                    // c.sdsp a4,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_dead_store, skipped, sizeof skipped,
                     0x1000, NULL) == 0);

    // The same value in a two-byte c.li. Replacing it with c.mv saves
    // nothing and makes an independent instruction depend on another
    // register, so it is not reported.
    static const uint8_t narrow[] = {
        0xbd, 0x47,                    // c.li a5,15
        0x05, 0x06,                    // c.addi a2,1
        0x3d, 0x48,                    // c.li a6,15
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_const_remat, narrow, sizeof narrow,
                     0x1000, NULL) == 0);

    // ---- the bytes a store just wrote, read straight back ----

    // A doubleword read back into another register is a move from the
    // one the store read.
    static const uint8_t fwd[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0xc2, 0x65,                    // c.ldsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, fwd, sizeof fwd,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1004 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "mv a1, a0") != NULL);

    // Read back into the register the store read: the value never left,
    // so the load is redundant by itself and this is not that finding.
    static const uint8_t same[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, same, sizeof same,
                     0x1000, NULL) == 0);

    // Storing x0 makes the rewrite `li a1,0` rather than a move.
    static const uint8_t zeroed[] = {
        0x02, 0xe8,                    // c.sdsp zero,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0xc2, 0x65,                    // c.ldsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, zeroed, sizeof zeroed,
                     0x1000, NULL) == 0);

    // A narrower load of a wider store is a field extraction, not a
    // move, whatever the byte order happens to be.
    static const uint8_t partial[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0xc2, 0x45,                    // c.lwsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, partial, sizeof partial,
                     0x1000, NULL) == 0);

    // A word read back with lw is the sign-extension of what was
    // stored, and `sext.w` is `addiw rd,rs,0` -- no extension needed.
    static const uint8_t sextw[] = {
        0x88, 0xca,                    // c.sw a0,16(a3)
        0x05, 0x06,                    // c.addi a2,1
        0x03, 0xa8, 0x06, 0x01,        // lw a6,16(a3)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, sextw, sizeof sextw,
                     0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "sext.w a6, a0") != NULL);

    // The same shape spelled in two bytes. Every extension form is four,
    // so the rewrite would cost two bytes to save an access -- the trade
    // check_const_remat refuses, and this refuses it too.
    static const uint8_t sextw_c[] = {
        0x2a, 0xc8,                    // c.swsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0xc2, 0x45,                    // c.lwsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, sextw_c, sizeof sextw_c,
                     0x1000, NULL) == 0);

    // A halfword read back with lh is Zbb's `sext.h`, so it is reported
    // where the extension may be used and suppressed where the object
    // declares an arch without it.
    static const uint8_t sexth[] = {
        0x23, 0x98, 0xa6, 0x00,        // sh a0,16(a3)
        0x03, 0x98, 0x06, 0x01,        // lh a6,16(a3)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window_exts(handle, check_store_to_load, sexth, sizeof sexth,
                          0x1000, RISCVLINT_EXT_ZBB |
                          RISCVLINT_EXT_DECLARED, &f) == 1);
    CHECK(strstr(f.replacement, "sext.h a6, a0") != NULL);
    CHECK(run_window_exts(handle, check_store_to_load, sexth, sizeof sexth,
                          0x1000, RISCVLINT_EXT_DECLARED, NULL) == 0);

    // The same disjointness test, asked of a store's held value: a
    // second store elsewhere in the frame cannot have changed the bytes
    // the first one wrote.
    static const uint8_t fwd_disjoint[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x3a, 0xf0,                    // c.sdsp a4,32(sp)
        0xc2, 0x65,                    // c.ldsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, fwd_disjoint,
                     sizeof fwd_disjoint, 0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "mv a1, a0") != NULL);

    static const uint8_t fwd_overlap[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x3a, 0xca,                    // c.swsp a4,20(sp)
        0xc2, 0x65,                    // c.ldsp a1,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, fwd_overlap,
                     sizeof fwd_overlap, 0x1000, NULL) == 0);

    // ---- a load whose destination already holds what it would load ----

    // Stored and read straight back into the register it came from.
    static const uint8_t back[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x42, 0x65,                    // c.ldsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_load, back, sizeof back,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1004 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "a0 still holds 16(sp) from the store") != NULL);

    // The same load twice recomputes the same value at any width.
    static const uint8_t twiceld[] = {
        0x88, 0x6a,                    // c.ld a0,16(a3)
        0x05, 0x06,                    // c.addi a2,1
        0x88, 0x6a,                    // c.ld a0,16(a3)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_load, twiceld, sizeof twiceld,
                     0x1000, NULL) == 1);

    // Stored and read back at half the width. `lw` leaves a0
    // sign-extended from bit 31, which is a0 again only if it already
    // was, and the pair does not say.
    static const uint8_t halfback[] = {
        0x2a, 0xc8,                    // c.swsp a0,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0x42, 0x45,                    // c.lwsp a0,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_load, halfback, sizeof halfback,
                     0x1000, NULL) == 0);

    // lb and lbu are the same width and not the same value.
    static const uint8_t signs[] = {
        0x03, 0xc5, 0x36, 0x00,        // lbu a0,3(a3)
        0x03, 0x85, 0x36, 0x00,        // lb a0,3(a3)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_redundant_load, signs, sizeof signs,
                     0x1000, NULL) == 0);

    // The two checks that rewrite a load into a move both refuse this
    // shape, which is what leaves it to this one.
    CHECK(run_window(handle, check_redundant_reload, twiceld, sizeof twiceld,
                     0x1000, NULL) == 0);
    CHECK(run_window(handle, check_store_to_load, back, sizeof back,
                     0x1000, NULL) == 0);

    // Two loads after one store. The first is this check's; the second
    // is check_redundant_reload's, whose source is the nearer of the
    // two, so this one reports the site once rather than twice.
    static const uint8_t twice[] = {
        0x2a, 0xe8,                    // c.sdsp a0,16(sp)
        0xc2, 0x65,                    // c.ldsp a1,16(sp)
        0x05, 0x06,                    // c.addi a2,1
        0xc2, 0x67,                    // c.ldsp a5,16(sp)
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_store_to_load, twice, sizeof twice,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1002);
    CHECK(run_window(handle, check_redundant_reload, twice, sizeof twice,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1006);

    // ---- a computation a live register already holds ----

    // A frame address computed twice with only arithmetic between them.
    // The second is four bytes because a3 is not a register c.addi4spn
    // can name, and c.mv can name any two.
    static const uint8_t comp[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x05, 0x06,                    // c.addi a2,1
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, comp, sizeof comp,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1006 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "mv a3, a0") != NULL);
    CHECK(strstr(f.replacement, "computed at 0x1000") != NULL);
    CHECK(strstr(f.replacement, "(4 -> 2 bytes)") != NULL);

    // The register the instruction is about to write already holds the
    // value, so it goes away rather than becoming a move -- four bytes
    // rather than two.
    static const uint8_t compdel[] = {
        0x13, 0x17, 0x06, 0x02,        // slli a4,a2,32
        0x93, 0x57, 0x07, 0x02,        // srli a5,a4,32
        0x13, 0x17, 0x06, 0x02,        // slli a4,a2,32
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compdel, sizeof compdel,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1008);
    CHECK(strstr(f.replacement, "delete; a4 already holds this") != NULL);
    CHECK(strstr(f.replacement, "from 0x1000 (4 bytes)") != NULL);

    // A conditional branch over the second does not matter: it is
    // reached by falling through, so everything the record saw ran.
    static const uint8_t compbr[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x19, 0xc2,                    // c.beqz a2,0x100a
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compbr, sizeof compbr,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1006);

    // A vector store through an address the decoder cannot follow takes
    // every claim about a place, and no claim about a register. This is
    // the whole difference between the two tables' lifetimes, and 145 of
    // ripgrep's 646 probe sites.
    static const uint8_t compvec[] = {
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x57, 0x70, 0x81, 0xcd,        // vsetivli zero,2,e64,m1,ta,ma
        0x27, 0xf4, 0x06, 0x02,        // vse64.v v8,(a3)
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compvec, sizeof compvec,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x100c);
    CHECK(strstr(f.replacement, "mv a0, a3") != NULL);

    // Negatives. A match already spelled in two bytes: c.addi4spn can
    // name both destinations, so c.mv would save nothing and trade an
    // independent instruction for a dependent one.
    static const uint8_t compnarrow[] = {
        0x08, 0x08,                    // c.addi4spn a0,sp,16
        0x05, 0x06,                    // c.addi a2,1
        0x0c, 0x08,                    // c.addi4spn a1,sp,16
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compnarrow, sizeof compnarrow,
                     0x1000, NULL) == 0);

    // A def that wrote one of its own sources leaves nothing that can
    // name the value it read, so it is not recorded at all. Without the
    // rule every later `add rd,a0,a1` matches this record.
    static const uint8_t compself[] = {
        0x2e, 0x95,                    // c.add a0,a1
        0x05, 0x06,                    // c.addi a2,1
        0xb3, 0x06, 0xb5, 0x00,        // add a3,a0,a1
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compself, sizeof compself,
                     0x1000, NULL) == 0);

    // sp holds what the ABI says it holds, and this shape --
    // `addi sp,s0,-K` over a frame that never moved -- is
    // check_redundant_sp_restore's finding, which says why.
    static const uint8_t compsp[] = {
        0x13, 0x01, 0x04, 0xf9,        // addi sp,s0,-112
        0x05, 0x06,                    // c.addi a2,1
        0x13, 0x01, 0x04, 0xf9,        // addi sp,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compsp, sizeof compsp,
                     0x1000, NULL) == 0);

    // The source moved, so the second computes a different address.
    static const uint8_t compsrc[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x21, 0x04,                    // c.addi s0,8
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compsrc, sizeof compsrc,
                     0x1000, NULL) == 0);

    // The register holding the earlier result is overwritten, so there
    // is nothing left to move from.
    static const uint8_t compdst[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x01, 0x45,                    // c.li a0,0
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compdst, sizeof compdst,
                     0x1000, NULL) == 0);

    // A different immediate is a different computation.
    static const uint8_t compimm[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x93, 0x06, 0x04, 0xfa,        // addi a3,s0,-96
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compimm, sizeof compimm,
                     0x1000, NULL) == 0);

    // So is a different mnemonic over the same operands: srliw is a
    // 32-bit shift and srli is a 64-bit one.
    static const uint8_t compmn[] = {
        0x9b, 0xd6, 0x77, 0x01,        // srliw a3,a5,23
        0x05, 0x06,                    // c.addi a2,1
        0x13, 0xd6, 0x77, 0x01,        // srli a2,a5,23
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compmn, sizeof compmn,
                     0x1000, NULL) == 0);

    // `mv` is move coalescing, measured at 192 of 73,017 and rejected.
    static const uint8_t compmv[] = {
        0x13, 0x85, 0x05, 0x00,        // mv a0,a1
        0x13, 0x06, 0x16, 0x00,        // addi a2,a2,1
        0x93, 0x86, 0x05, 0x00,        // mv a3,a1
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_comp_remat, compmv, sizeof compmv,
                     0x1000, NULL) == 0);

    // `li` is check_const_remat's, which reports this site and keys on
    // the value rather than on the operands that made it.
    static const uint8_t compli[] = {
        0x13, 0x05, 0x20, 0x4d,        // li a0,1234
        0x13, 0x06, 0x16, 0x00,        // addi a2,a2,1
        0x93, 0x06, 0x20, 0x4d,        // li a3,1234
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_comp_remat, compli, sizeof compli,
                     0x1000, NULL) == 0);
    CHECK(run_window(handle, check_const_remat, compli, sizeof compli,
                     0x1000, NULL) == 1);

    // A call ends the region: it can write any caller-saved register.
    static const uint8_t compcall[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x97, 0x00, 0x00, 0x00,        // auipc ra,0
        0xe7, 0x80, 0xe0, 0x00,        // jalr 14(ra)
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compcall, sizeof compcall,
                     0x1000, NULL) == 0);

    // A side entry on the second: what follows is not reached only from
    // the first.
    static const uint8_t compside[] = {
        0x13, 0x05, 0x04, 0xf9,        // addi a0,s0,-112
        0x09, 0xc2,                    // c.beqz a2,0x1006
        0x93, 0x06, 0x04, 0xf9,        // addi a3,s0,-112
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_comp_remat, compside, sizeof compside,
                     0x1000, NULL) == 0);
}

// ---- rv_decode_jump ----
//
// The CJ and J immediates are scattered fields, and the CB format two
// decoders over got read wrong once in a way that produced plausible
// wrong addresses rather than nothing. So every bit of both is pinned
// against what the assembler emits for a known displacement, rather
// than against a second reading of the manual: each pair below is
// `c.j .+K` or `j .+K` assembled at the address given.
static void test_decode_jump(void)
{
    static const struct { uint32_t w; unsigned size; int64_t off; } t[] = {
        // c.j, one bit of the CJ field at a time.
        { 0xa011u, 2,      4 },   { 0xa021u, 2,      8 },
        { 0xa801u, 2,     16 },   { 0xa005u, 2,     32 },
        { 0xa081u, 2,     64 },   { 0xa041u, 2,    128 },
        { 0xa201u, 2,    256 },   { 0xa401u, 2,    512 },
        { 0xa101u, 2,   1024 },   { 0xaffdu, 2,   2046 },
        { 0xbff5u, 2,     -4 },   { 0xbfe5u, 2,     -8 },
        { 0xbfc5u, 2,    -16 },   { 0xb7c5u, 2,    -32 },
        { 0xb7c1u, 2,    -64 },   { 0xb741u, 2,   -128 },
        { 0xb701u, 2,   -256 },   { 0xb501u, 2,   -512 },
        { 0xb101u, 2,  -1024 },   { 0xb001u, 2,  -2048 },
        // jal, likewise, up to the ends of its range.
        { 0x0040006fu, 4,       4 }, { 0x0080006fu, 4,       8 },
        { 0x0100006fu, 4,      16 }, { 0x0200006fu, 4,      32 },
        { 0x0400006fu, 4,      64 }, { 0x0800006fu, 4,     128 },
        { 0x1000006fu, 4,     256 }, { 0x2000006fu, 4,     512 },
        { 0x4000006fu, 4,    1024 }, { 0x0010006fu, 4,    2048 },
        { 0x0000106fu, 4,    4096 }, { 0x0000206fu, 4,    8192 },
        { 0x0000406fu, 4,   16384 }, { 0x0000806fu, 4,   32768 },
        { 0x0001006fu, 4,   65536 }, { 0x0002006fu, 4,  131072 },
        { 0x0004006fu, 4,  262144 }, { 0x0008006fu, 4,  524288 },
        { 0x7ffff06fu, 4, 1048574 }, { 0x8000006fu, 4, -1048576 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        unsigned rd = 99;
        int64_t off = 0;
        CHECK(rv_decode_jump(t[i].w, t[i].size, &rd, &off));
        CHECK(rd == 0);
        CHECK(off == t[i].off);
    }

    // `jal ra,.+4`: the same encoding with a link register, which is
    // what separates a jump a check may delete from a call it may not.
    unsigned rd = 99;
    int64_t off = 0;
    CHECK(rv_decode_jump(0x004000efu, 4, &rd, &off));
    CHECK(rd == 1 && off == 4);

    // Not a jump: c.jr, a conditional branch, an addi.
    CHECK(!rv_decode_jump(0x8082u, 2, &rd, &off));          // ret
    CHECK(!rv_decode_jump(0xc111u, 2, &rd, &off));          // c.beqz
    CHECK(!rv_decode_jump(0x00d60263u, 4, &rd, &off));      // beq
    CHECK(!rv_decode_jump(0x00160613u, 4, &rd, &off));      // addi
}

// ---- a conditional branch over an unconditional jump, and a
//      transfer to the instruction that follows it ----
//
// Every encoding below is lifted from the corpus at the address named,
// which is also how each was checked against a disassembler.

static void test_branch_over_jump(csh handle)
{
    riscvlint_finding f;

    // firefox-esr 0x271f4: a four-byte branch over a two-byte jump.
    // The inverted branch stays four bytes, so the jump's two are the
    // whole saving.
    static const uint8_t j2[] = {
        0x63, 0x63, 0xc7, 0x00,        // bltu a4,a2,0x271fa
        0x8d, 0xbd,                    // c.j 0x2706a
        0x09, 0xa0,                    // c.j 0x271fc
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, j2, sizeof j2,
                     0x271f4, &f) == 1);
    CHECK(f.address == 0x271f4 && f.insn_count == 2);
    CHECK(strstr(f.replacement, "bgeu a4, a2, 0x2706a") != NULL);
    CHECK(strstr(f.replacement, "(6 -> 4 bytes)") != NULL);

    // firefox-esr 0x3f790: four and four, the largest of the four
    // shapes and 2,468 of the 5,362 sites.
    static const uint8_t j4[] = {
        0x63, 0x64, 0xb5, 0x00,        // bltu a0,a1,0x3f798
        0x6f, 0x00, 0x70, 0x60,        // j 0x4059a
        0x83, 0xb5, 0x8c, 0x03,        // ld a1,56(s9)
    };
    CHECK(run_window(handle, check_branch_over_jump, j4, sizeof j4,
                     0x3f790, &f) == 1);
    CHECK(strstr(f.replacement, "bgeu a0, a1, 0x4059a") != NULL);
    CHECK(strstr(f.replacement, "(8 -> 4 bytes)") != NULL);

    // libmozsqlite3 0x9c1b6: two and two, with the new displacement
    // inside c.bnez's +/-256, so the pair becomes one two-byte branch.
    static const uint8_t c2[] = {
        0x91, 0xc3,                    // c.beqz a5,0x9c1ba
        0xa1, 0xa8,                    // c.j 0x9c210
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, c2, sizeof c2,
                     0x9c1b6, &f) == 1);
    CHECK(strstr(f.replacement, "bnez a5, 0x9c210") != NULL);
    CHECK(strstr(f.replacement, "(4 -> 2 bytes)") != NULL);

    // libgkcodecs 0x202c3e: the same shape with the new displacement at
    // 350, outside that range, so the branch has to grow to four and
    // the rewrite is four bytes for four. It still removes an
    // instruction and a taken branch, so it is reported -- 73 sites.
    static const uint8_t c0[] = {
        0x11, 0xc1,                    // c.beqz a0,0x202c42
        0xb1, 0xaa,                    // c.j 0x202d9c
        0x28, 0x10,                    // addi a0,sp,40
    };
    CHECK(run_window(handle, check_branch_over_jump, c0, sizeof c0,
                     0x202c3e, &f) == 1);
    CHECK(strstr(f.replacement, "bnez a0, 0x202d9c") != NULL);
    CHECK(strstr(f.replacement, "(4 -> 4 bytes)") != NULL);

    // Negatives. Something branches to the jump, which loses its
    // transfer if the jump goes.
    static const uint8_t tgt[] = {
        0x11, 0xc1,                    // c.beqz a0,0x1004
        0xf5, 0xbf,                    // c.j 0xffe
        0x82, 0x80,                    // ret
        0xf5, 0xdd,                    // c.beqz a1,0x1002
    };
    CHECK(run_window(handle, check_branch_over_jump, tgt, sizeof tgt,
                     0x1000, NULL) == 0);

    // The branch does not clear the jump: something else sits between
    // the jump and where the branch lands.
    static const uint8_t gap[] = {
        0x19, 0xc1,                    // c.beqz a0,0x1006
        0xd5, 0xbf,                    // c.j
        0x01, 0x00,                    // nop
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, gap, sizeof gap,
                     0x1000, NULL) == 0);

    // `jal ra,X` rather than `j X`: deleting it would stop writing the
    // link register.
    static const uint8_t link[] = {
        0x19, 0xc1,                    // c.beqz a0,0x1006
        0xef, 0xf0, 0xdf, 0xfe,        // jal ra,0xfec
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, link, sizeof link,
                     0x1000, NULL) == 0);

    // The jump's target is past the branch's +/-4KB, which is the whole
    // reason the pair is written this way: 122,999 of the 128,361 sites
    // in the corpus are this and are the encoding working as designed.
    static const uint8_t far[] = {
        0x19, 0xc1,                    // c.beqz a0,0x1006
        0x6f, 0x10, 0xe0, 0x38,        // j 0x2390
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, far, sizeof far,
                     0x1000, NULL) == 0);

    // The jump goes exactly where the branch goes, so both paths
    // already meet: the pair is dead rather than foldable, and the jump
    // is check_transfer_to_next's.
    static const uint8_t same[] = {
        0x11, 0xc1,                    // c.beqz a0,0x1004
        0x09, 0xa0,                    // c.j 0x1004
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_branch_over_jump, same, sizeof same,
                     0x1000, NULL) == 0);
    CHECK(run_window(handle, check_transfer_to_next, same, sizeof same,
                     0x1000, &f) == 1);
    CHECK(f.address == 0x1002);
}

static void test_transfer_to_next(csh handle)
{
    riscvlint_finding f;

    // ripgrep 0x70c9c, the commonest form: a two-byte c.j to the next
    // instruction, 3,674 of the 3,702 sites.
    static const uint8_t cj[] = {
        0x09, 0xa0,                    // c.j 0x70c9e
        0x83, 0x35, 0x04, 0xfb,        // ld a1,-80(s0)
    };
    CHECK(run_window(handle, check_transfer_to_next, cj, sizeof cj,
                     0x70c9c, &f) == 1);
    CHECK(f.address == 0x70c9c && f.insn_count == 1);
    CHECK(strstr(f.replacement, "delete; the jump") != NULL);
    CHECK(strstr(f.replacement, "(2 bytes)") != NULL);

    // A four-byte jump doing the same. restic has three.
    static const uint8_t j4[] = {
        0x6f, 0x00, 0x40, 0x00,        // j 0x1004
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_transfer_to_next, j4, sizeof j4,
                     0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "(4 bytes)") != NULL);

    // A conditional branch to the next instruction is the same no-op,
    // in both widths.
    static const uint8_t br4[] = {
        0x63, 0x02, 0xd6, 0x00,        // beq a2,a3,0x1004
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_transfer_to_next, br4, sizeof br4,
                     0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "delete; the branch") != NULL);
    static const uint8_t br2[] = {
        0x89, 0xc1,                    // c.beqz a1,0x1002
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_transfer_to_next, br2, sizeof br2,
                     0x1000, NULL) == 1);

    // `jal ra,X` writes the link register, which makes it a PC
    // materialization rather than a no-op. 16 sites in Firefox.
    static const uint8_t link[] = {
        0xef, 0x00, 0x40, 0x00,        // jal ra,0x1004
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_transfer_to_next, link, sizeof link,
                     0x1000, NULL) == 0);

    // A jump anywhere else is a jump.
    static const uint8_t away[] = {
        0x35, 0xa0,                    // c.j 0x102c
        0x82, 0x80,                    // ret
    };
    CHECK(run_window(handle, check_transfer_to_next, away, sizeof away,
                     0x1000, NULL) == 0);
}

// ---- a bit-cast routed through a frame slot ----
//
// Corpus encodings at the addresses named.

static void test_bitcast_through_frame(csh handle)
{
    riscvlint_finding f;

    // liblgpllibs 0xfa84: the commonest direction, a single stored and
    // read back into a general register.
    static const uint8_t xw[] = {
        0x27, 0x20, 0x61, 0x10,        // fsw ft6,256(sp)
        0x83, 0x24, 0x01, 0x10,        // lw s1,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, xw, sizeof xw,
                     0xfa84, &f) == 1);
    CHECK(f.address == 0xfa88 && f.insn_count == 1);
    CHECK(strstr(f.replacement, "fmv.x.w s1, ft6") != NULL);
    CHECK(strstr(f.replacement, "stored at 0xfa84") != NULL);
    CHECK(strstr(f.replacement, "(4 -> 4 bytes)") != NULL);

    // liblgpllibs 0xbfbc: the other direction, off a two-byte store.
    // The store's own width is not the question -- the load's is, since
    // the load is what goes.
    static const uint8_t wx[] = {
        0xb2, 0xc8,                    // c.swsp a2,80(sp)
        0x87, 0x27, 0x01, 0x05,        // flw fa5,80(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, wx, sizeof wx,
                     0xbfbc, &f) == 1);
    CHECK(strstr(f.replacement, "fmv.w.x fa5, a2") != NULL);

    // libxul 0x3d1034a: at the doubleword, with three instructions
    // between that touch neither the base nor the stored register.
    static const uint8_t dx[] = {
        0x23, 0x34, 0xcc, 0x1e,        // sd a2,488(s8)
        0x23, 0x34, 0xac, 0x20,        // sd a0,520(s8)
        0x23, 0x38, 0xbc, 0x20,        // sd a1,528(s8)
        0x17, 0xc5, 0x71, 0xfc,        // auipc a0,0xfc71c
        0x07, 0x37, 0x25, 0x27,        // fld fa5,626(a0)
        0x07, 0x37, 0x8c, 0x1e,        // fld fa4,488(s8)
    };
    CHECK(run_window(handle, check_bitcast_through_frame, dx, sizeof dx,
                     0x3d1034a, &f) == 1);
    CHECK(f.address == 0x3d1035e);
    CHECK(strstr(f.replacement, "fmv.d.x fa4, a2") != NULL);

    // libxul 0x3cee998: armed by a *load* rather than a store, and read
    // back across a conditional branch. The probe this was sized from
    // arms only from stores and does not model either half.
    static const uint8_t xd[] = {
        0x07, 0xb7, 0x0c, 0x00,        // fld fa4,0(s9)
        0x93, 0x15, 0x45, 0x00,        // slli a1,a0,0x4
        0x1a, 0x05,                    // c.slli a0,0x6
        0x0d, 0x8d,                    // c.sub a0,a1
        0xd3, 0x25, 0xf7, 0xa2,        // feq.d a1,fa4,fa5
        0x33, 0x84, 0xac, 0x00,        // add s0,s9,a0
        0xf1, 0xc9,                    // c.beqz a1,+0xd4
        0x03, 0xb6, 0x0c, 0x00,        // ld a2,0(s9)
    };
    CHECK(run_window(handle, check_bitcast_through_frame, xd, sizeof xd,
                     0x3cee998, &f) == 1);
    CHECK(f.address == 0x3cee9ae);
    CHECK(strstr(f.replacement, "fmv.x.d a2, fa4") != NULL);
    CHECK(strstr(f.replacement, "loaded at 0x3cee998") != NULL);

    // Negatives. A two-byte load: none of the four moves has a
    // compressed spelling, so the rewrite would cost two bytes. 869 of
    // the 2,380 sites in the corpus are this, and it is the one place
    // this check declines to pay bytes for a memory access.
    static const uint8_t narrow[] = {
        0x27, 0x20, 0x81, 0x00,        // fsw fs0,0(sp)
        0x82, 0x45,                    // c.lwsp a1,0(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, narrow,
                     sizeof narrow, 0x47298, NULL) == 0);

    // A wider load than the store: it reads bytes the store never wrote.
    static const uint8_t wide[] = {
        0x27, 0x20, 0x61, 0x10,        // fsw ft6,256(sp)
        0x83, 0x34, 0x01, 0x10,        // ld s1,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, wide, sizeof wide,
                     0x1000, NULL) == 0);

    // `lwu` zero-extends where `fmv.x.w` sign-extends.
    static const uint8_t unsgn[] = {
        0x27, 0x20, 0x61, 0x10,        // fsw ft6,256(sp)
        0x83, 0x64, 0x01, 0x10,        // lwu s1,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, unsgn, sizeof unsgn,
                     0x1000, NULL) == 0);

    // The f register is overwritten, so there is nothing left to move
    // from. This is the rule the table could not enforce before it
    // recorded floating-point accesses at all.
    static const uint8_t clobber[] = {
        0x27, 0x20, 0x61, 0x10,        // fsw ft6,256(sp)
        0x53, 0x73, 0x10, 0x00,        // fadd.s ft6,ft0,ft1
        0x83, 0x24, 0x01, 0x10,        // lw s1,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, clobber,
                     sizeof clobber, 0x1000, NULL) == 0);

    // The base is overwritten, so the address is not the one the store
    // used.
    static const uint8_t rebase[] = {
        0x27, 0xa0, 0x64, 0x10,        // fsw ft6,256(s1)
        0x93, 0x84, 0x84, 0x00,        // addi s1,s1,8
        0x03, 0xa5, 0x04, 0x10,        // lw a0,256(s1)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, rebase,
                     sizeof rebase, 0x1000, NULL) == 0);

    // A store through another base may have landed on the slot, and
    // nothing in the encoding says it did not.
    static const uint8_t alias[] = {
        0x27, 0x20, 0x61, 0x10,        // fsw ft6,256(sp)
        0x23, 0xb0, 0xe6, 0x00,        // sd a4,0(a3)
        0x83, 0x24, 0x01, 0x10,        // lw s1,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, alias, sizeof alias,
                     0x1000, NULL) == 0);

    // Both halves in the same file is check_store_to_load's site, and
    // that check still reports it with the table now holding records
    // from both.
    static const uint8_t same[] = {
        0x23, 0x30, 0xc1, 0x10,        // sd a2,256(sp)
        0x03, 0x35, 0x01, 0x10,        // ld a0,256(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_bitcast_through_frame, same, sizeof same,
                     0x1000, NULL) == 0);
    CHECK(run_window(handle, check_store_to_load, same, sizeof same,
                     0x1000, &f) == 1);
    CHECK(strstr(f.replacement, "mv a0, a2") != NULL);

    // The table now holds records from both files, and `data` alone
    // cannot tell f10 from x10. check_silent_store matches on `data`,
    // so it is the one reader that has to be told: without the test it
    // reads this pair as a store of bytes the slot already holds.
    // The record is armed by a load rather than a store, because a
    // store to the slot would make this check_dead_store's site and
    // check_silent_store would stand down before reading `data` at all.
    static const uint8_t files[] = {
        0x07, 0x35, 0x01, 0x01,        // fld fa0,16(sp)
        0x23, 0x38, 0xa1, 0x00,        // sd a0,16(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_silent_store, files, sizeof files,
                     0x1000, NULL) == 0);
}

// ---- a run of zero stores one wider store would do ----
//
// The corpus encodings below are at the addresses named, which is also
// where each was read against a disassembler.

static void test_zero_store_run(csh handle)
{
    riscvlint_finding f;

    // libQt6Core 0xf65ca: GCC zeroing seven bytes of frame one at a
    // time. Covering [-111,-104) takes `sb -111`, `sh -110`, `sw -108`,
    // so 16 of the 28 bytes go -- and it is one finding over seven
    // instructions rather than seven findings or three pair-merges.
    static const uint8_t seven[] = {
        0xa3, 0x08, 0x04, 0xf8,        // sb zero,-111(s0)
        0x23, 0x09, 0x04, 0xf8,        // sb zero,-110(s0)
        0xa3, 0x09, 0x04, 0xf8,        // sb zero,-109(s0)
        0x23, 0x0a, 0x04, 0xf8,        // sb zero,-108(s0)
        0xa3, 0x0a, 0x04, 0xf8,        // sb zero,-107(s0)
        0x23, 0x0b, 0x04, 0xf8,        // sb zero,-106(s0)
        0xa3, 0x0b, 0x04, 0xf8,        // sb zero,-105(s0)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, seven, sizeof seven,
                     0xf65ca, &f) == 1);
    CHECK(f.address == 0xf65ca && f.insn_count == 7);
    CHECK(strstr(f.replacement, "3 instead of 7 stores") != NULL);
    CHECK(strstr(f.replacement, "7 bytes at -111(s0)") != NULL);
    CHECK(strstr(f.replacement, "(28 -> 12 bytes)") != NULL);

    // gh 0x52ff4: two uncompressed `sw zero,K(sp)` in Go's output. Both
    // sides are priced at the best base C encoding, so this reports the
    // two bytes merging saves and not the four that compressing the two
    // stores saves -- those are check_c_compressible's, at both
    // addresses, and the two findings add up to the eight bytes that
    // are really there.
    static const uint8_t gowide[] = {
        0x23, 0x28, 0x01, 0x02,        // sw zero,48(sp)
        0x23, 0x2a, 0x01, 0x02,        // sw zero,52(sp)
        0x13, 0x00, 0x00, 0x00,        // nop
    };
    CHECK(run_window(handle, check_zero_store_run, gowide, sizeof gowide,
                     0x52ff4, &f) == 1);
    CHECK(strstr(f.replacement, "1 instead of 2 stores") != NULL);
    CHECK(strstr(f.replacement, "(4 -> 2 bytes)") != NULL);
    CHECK(run_window(handle, check_c_compressible, gowide, sizeof gowide,
                     0x52ff4, NULL) == 2);

    // libgkcodecs 0x225314: four `c.swsp zero` already compressed, where
    // the middle two merge into one `c.sdsp` and the ends stay. Nothing
    // here is compression's to claim, and the saving is the one
    // instruction at the two bytes it occupies.
    static const uint8_t four[] = {
        0x82, 0xc2,                    // c.swsp zero,68(sp)
        0x82, 0xc4,                    // c.swsp zero,72(sp)
        0x82, 0xc6,                    // c.swsp zero,76(sp)
        0x82, 0xc8,                    // c.swsp zero,80(sp)
        0xa6, 0xce,                    // c.swsp s1,92(sp)
    };
    CHECK(run_window(handle, check_zero_store_run, four, sizeof four,
                     0x225314, &f) == 1);
    CHECK(f.insn_count == 4);
    CHECK(strstr(f.replacement, "3 instead of 4 stores") != NULL);
    CHECK(strstr(f.replacement, "(8 -> 6 bytes)") != NULL);

    // gofmt 0x82198: a run that grows at both ends -- 47, then 48 and
    // 56 upward, then 46 downward -- and mixes widths, which is the
    // shape a single average encoded size cannot price.
    static const uint8_t both[] = {
        0xa3, 0x07, 0x01, 0x02,        // sb zero,47(sp)
        0x02, 0xf8,                    // c.sdsp zero,48(sp)
        0x02, 0xfc,                    // c.sdsp zero,56(sp)
        0x23, 0x07, 0x01, 0x02,        // sb zero,46(sp)
        0x13, 0x00, 0x00, 0x00,        // nop
    };
    CHECK(run_window(handle, check_zero_store_run, both, sizeof both,
                     0x82198, &f) == 1);
    CHECK(f.insn_count == 4);
    CHECK(strstr(f.replacement, "18 bytes at 46(sp)") != NULL);
    CHECK(strstr(f.replacement, "(12 -> 8 bytes)") != NULL);

    // Negatives. A gap ends the run rather than being written through:
    // a wider store would write the bytes between, which nothing asked
    // for. These four are two runs of two, not one run of four.
    static const uint8_t gap[] = {
        0x23, 0x04, 0x01, 0x00,        // sb zero,8(sp)
        0xa3, 0x04, 0x01, 0x00,        // sb zero,9(sp)
        0x23, 0x06, 0x01, 0x00,        // sb zero,12(sp)
        0xa3, 0x06, 0x01, 0x00,        // sb zero,13(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, gap, sizeof gap,
                     0x1000, &f) == 2);
    CHECK(f.address == 0x1000 && f.insn_count == 2);
    CHECK(strstr(f.replacement, "2 bytes at 8(sp)") != NULL);

    // A store of something other than zero ends the run: `sd rD` in
    // place of two `sw rD` would write rD's high half to the second
    // slot, and nothing says a register's halves are the two values
    // that were stored.
    static const uint8_t nonzero[] = {
        0x23, 0x04, 0x01, 0x00,        // sb zero,8(sp)
        0xa3, 0x04, 0xa1, 0x00,        // sb a0,9(sp)
        0x23, 0x05, 0x01, 0x00,        // sb zero,10(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, nonzero, sizeof nonzero,
                     0x1000, NULL) == 0);

    // A base whose alignment the encoding does not give. 23,973 sites
    // and 232,960 bytes run through one, four times the frame
    // population, and a byte-at-a-time store may be the deliberate
    // choice there rather than the missed one.
    static const uint8_t heap[] = {
        0x23, 0x84, 0x05, 0x00,        // sb zero,8(a1)
        0xa3, 0x84, 0x05, 0x00,        // sb zero,9(a1)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, heap, sizeof heap,
                     0x1000, NULL) == 0);

    // Already the cheapest cover: four `sd zero` over 32 bytes merge
    // into nothing at all. Pricing the survivors as compressible made
    // this look like a saving of eight, which is the compression
    // check's figure for the same four instructions.
    static const uint8_t optimal[] = {
        0x23, 0x30, 0x01, 0x00,        // sd zero,0(sp)
        0x23, 0x34, 0x01, 0x00,        // sd zero,8(sp)
        0x23, 0x38, 0x01, 0x00,        // sd zero,16(sp)
        0x23, 0x3c, 0x01, 0x00,        // sd zero,24(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, optimal, sizeof optimal,
                     0x1000, NULL) == 0);

    // `fsw ft0` names f0 with the same field x0 uses, and f0 is a value
    // rather than a zero. Without the test these two would merge into
    // one `sd zero,8(sp)`, which is why the pair is chosen to abut.
    static const uint8_t fp[] = {
        0x27, 0x24, 0x01, 0x00,        // fsw ft0,8(sp)
        0x27, 0x26, 0x01, 0x00,        // fsw ft0,12(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_window(handle, check_zero_store_run, fp, sizeof fp,
                     0x1000, NULL) == 0);

    // A side entry inside the run: a path arriving there would reach the
    // merged store having skipped the bytes before it, and the merged
    // store writes them all.
    static const uint8_t side[] = {
        0x23, 0x04, 0x01, 0x00,        // sb zero,8(sp)
        0xa3, 0x04, 0x01, 0x00,        // sb zero,9(sp)
        0x67, 0x80, 0x00, 0x00,        // ret
        0xe3, 0x0c, 0x05, 0xfe,        // beqz a0,0x1004
    };
    CHECK(run_window(handle, check_zero_store_run, side, sizeof side,
                     0x1000, NULL) == 0);
}

// ---- conditions and branches ----

static void test_decode_condition(void)
{
    unsigned rd, a, b;
    rv_cond_kind k;

    // Encodings from `riscv64-linux-gnu-as -march=rv64gc`.
    CHECK(rv_decode_condition(0x00b527b3u, 4, &rd, &a, &b, &k)); // slt a5,a0,a1
    CHECK(rd == 15 && a == 10 && b == 11 && k == RV_COND_SLT);
    CHECK(rv_decode_condition(0x00b537b3u, 4, &rd, &a, &b, &k)); // sltu
    CHECK(k == RV_COND_SLTU);
    CHECK(rv_decode_condition(0x00b547b3u, 4, &rd, &a, &b, &k)); // xor
    CHECK(k == RV_COND_EQ);
    CHECK(rv_decode_condition(0x40b507b3u, 4, &rd, &a, &b, &k)); // sub
    CHECK(k == RV_COND_EQ);

    // seqz is `sltiu rd,rs,1` and snez is `sltu rd,x0,rs`. Both are
    // aliases rather than mnemonics, and snez has to be picked out
    // before the general sltu rule, which would otherwise claim it and
    // fold to `bltu zero,a0` -- correct, but not what the source said.
    CHECK(rv_decode_condition(0x00153793u, 4, &rd, &a, &b, &k)); // seqz a5,a0
    CHECK(rd == 15 && a == 10 && b == 0 && k == RV_COND_SEQZ);
    CHECK(rv_decode_condition(0x00a037b3u, 4, &rd, &a, &b, &k)); // snez a5,a0
    CHECK(rd == 15 && a == 10 && b == 0 && k == RV_COND_SNEZ);

    // `sltiu rd,rs,2` is a comparison against a constant no branch can
    // make; only the value 1 is seqz.
    CHECK(!rv_decode_condition(0x00253793u, 4, &rd, &a, &b, &k));
    // `and` says nothing a branch can say on its own.
    CHECK(!rv_decode_condition(0x00b577b3u, 4, &rd, &a, &b, &k));
    // A condition written into x0 is discarded, not a condition.
    CHECK(!rv_decode_condition(0x00b53033u, 4, &rd, &a, &b, &k));
}

static void test_decode_cond_branch(void)
{
    unsigned rs1, rs2, f3;
    int64_t off;

    // Four-byte B-type, forward and backward.
    CHECK(rv_decode_cond_branch(0x02078063u, 4, &rs1, &rs2, &f3, &off));
    CHECK(f3 == 0 && rs1 == 15 && rs2 == 0 && off == 32);      // beqz a5,+32
    CHECK(rv_decode_cond_branch(0x00b54c63u, 4, &rs1, &rs2, &f3, &off));
    CHECK(f3 == 4 && rs1 == 10 && rs2 == 11 && off == 24);     // blt a0,a1,+24

    // The two-byte CB forms. `c13d` is `beqz a0,+102` at 0x286fe8 in
    // libQt6Core, and it is the encoding that caught the bug: CB packs
    // imm[8|4:3] in bits 12:10 and imm[7:6|2:1|5] in bits 6:2, and
    // reading those two fields swapped decodes most short branches to a
    // plausible wrong address rather than to nothing.
    CHECK(rv_decode_cond_branch(0xc13du, 2, &rs1, &rs2, &f3, &off));
    CHECK(f3 == 0 && rs1 == 10 && rs2 == 0 && off == 102);
    CHECK(rv_decode_cond_branch(0xc789u, 2, &rs1, &rs2, &f3, &off));
    CHECK(f3 == 0 && rs1 == 15 && rs2 == 0 && off == 10);      // c.beqz a5,+10
    CHECK(rv_decode_cond_branch(0xe781u, 2, &rs1, &rs2, &f3, &off));
    CHECK(f3 == 1 && rs1 == 15 && rs2 == 0 && off == 8);       // c.bnez a5,+8

    CHECK(!rv_decode_cond_branch(0x00008067u, 4, &rs1, &rs2, &f3, &off));

    // Only beqz and bnez have a compressed spelling, and only for a
    // register in x8-x15 with a displacement inside the nine-bit field.
    CHECK(rv_branch_encoded_size(0, 10, 0, 8) == 2);
    CHECK(rv_branch_encoded_size(1, 10, 0, -256) == 2);
    CHECK(rv_branch_encoded_size(1, 10, 0, 256) == 4);
    CHECK(rv_branch_encoded_size(0, 16, 0, 8) == 4);           // a6
    CHECK(rv_branch_encoded_size(0, 10, 11, 8) == 4);          // two registers
    CHECK(rv_branch_encoded_size(4, 10, 0, 8) == 4);           // blt
}

// ---- base C encodability ----

static void test_c_form(void)
{
    char f[24];
    // Encodings from `riscv64-linux-gnu-as -march=rv64gc` with
    // `.option norvc`. The rules behind them were checked against that
    // assembler over a matrix of 2,922 instructions assembled twice,
    // with RVC and without, comparing this decoder's answer to the
    // assembler's choice.

    // The addi family, which is four different compressed forms picked
    // apart by which registers appear and what the immediate is.
    CHECK(rv_c_form(0x00878793u, 4, f, sizeof f) && !strcmp(f, "c.addi"));
    CHECK(rv_c_form(0x00800793u, 4, f, sizeof f) && !strcmp(f, "c.li"));
    CHECK(rv_c_form(0x01010793u, 4, f, sizeof f) && !strcmp(f, "c.addi4spn"));
    CHECK(rv_c_form(0xfe010113u, 4, f, sizeof f) && !strcmp(f, "c.addi16sp"));
    // An addi of zero is a move, and c.mv takes it -- c.addi is the form
    // that cannot hold zero.
    CHECK(rv_c_form(0x00070793u, 4, f, sizeof f) && !strcmp(f, "c.mv"));
    // Out of the six-bit field, and a destination whose result is
    // discarded.
    CHECK(!rv_c_form(0x02078793u, 4, f, sizeof f));   // addi a5,a5,32
    CHECK(!rv_c_form(0x00878013u, 4, f, sizeof f));   // addi zero,a5,8

    // c.lui carries imm[17:12], so the twenty-bit field has to be a
    // sign-extension of its own low six bits, and neither zero nor sp.
    CHECK(rv_c_form(0x000047b7u, 4, f, sizeof f) && !strcmp(f, "c.lui"));
    CHECK(!rv_c_form(0x000207b7u, 4, f, sizeof f));   // lui a5,32
    CHECK(!rv_c_form(0x000007b7u, 4, f, sizeof f));   // lui a5,0
    CHECK(!rv_c_form(0x00004137u, 4, f, sizeof f));   // lui sp,4

    // The shifts and andi name x8-x15 only, except c.slli which reaches
    // the whole file.
    CHECK(rv_c_form(0x00479793u, 4, f, sizeof f) && !strcmp(f, "c.slli"));
    CHECK(rv_c_form(0x00455513u, 4, f, sizeof f) && !strcmp(f, "c.srli"));
    CHECK(rv_c_form(0x40455513u, 4, f, sizeof f) && !strcmp(f, "c.srai"));
    CHECK(rv_c_form(0x00857513u, 4, f, sizeof f) && !strcmp(f, "c.andi"));
    CHECK(!rv_c_form(0x00455813u, 4, f, sizeof f));   // srli a6,a0,4 -- rd!=rs1
    CHECK(!rv_c_form(0x02057513u, 4, f, sizeof f));   // andi a0,a0,32

    // The two-register forms put the destination in one source slot.
    // The commutative ones reach either, because the assembler swaps
    // them; subtraction reaches only the first.
    CHECK(rv_c_form(0x40b50533u, 4, f, sizeof f) && !strcmp(f, "c.sub"));
    CHECK(rv_c_form(0x00b54533u, 4, f, sizeof f) && !strcmp(f, "c.xor"));
    CHECK(rv_c_form(0x00a5c533u, 4, f, sizeof f) && !strcmp(f, "c.xor"));
    CHECK(rv_c_form(0x00f587bbu, 4, f, sizeof f) && !strcmp(f, "c.addw"));
    CHECK(!rv_c_form(0x40a587bbu, 4, f, sizeof f));   // subw a5,a1,a0
    CHECK(rv_c_form(0x00b787b3u, 4, f, sizeof f) && !strcmp(f, "c.add"));
    CHECK(rv_c_form(0x00b007b3u, 4, f, sizeof f) && !strcmp(f, "c.mv"));

    // c.jr and c.jalr, which GNU as reaches from `jr a5` and not from
    // `jalr zero, 0(a5)` -- the same instruction, and the fourth
    // spelling-sensitive gap the corpus has turned up in it.
    CHECK(rv_c_form(0x00078067u, 4, f, sizeof f) && !strcmp(f, "c.jr"));
    CHECK(rv_c_form(0x000780e7u, 4, f, sizeof f) && !strcmp(f, "c.jalr"));
    CHECK(!rv_c_form(0x00478067u, 4, f, sizeof f));   // a displacement
    CHECK(rv_c_form(0x00008067u, 4, f, sizeof f) && !strcmp(f, "c.jr"));

    // A four-byte nop is alignment padding or dead code, and this check
    // has nothing useful to say about either.
    CHECK(!rv_c_form(0x00000013u, 4, f, sizeof f));

    CHECK(rv_c_form(0x00100073u, 4, f, sizeof f) && !strcmp(f, "c.ebreak"));
    CHECK(!rv_c_form(0x00000073u, 4, f, sizeof f));   // ecall

    // The memory and branch families come from the models the fold and
    // compare checks already use, so this only pins the delegation.
    CHECK(rv_c_form(0x0085b503u, 4, f, sizeof f) && !strcmp(f, "c.ld"));
    CHECK(rv_c_form(0x00813503u, 4, f, sizeof f) && !strcmp(f, "c.ldsp"));
    CHECK(!rv_c_form(0x0045b503u, 4, f, sizeof f));   // ld a0,4(a1)

    CHECK(!rv_c_form(0x6588u, 2, f, sizeof f));       // already two bytes
}

// ---- the exhaustive decoder sweep (RISCVLINT_SWEEP=1) ----
//
// riscvlint's checks decode raw encodings; capstone decodes the same
// bytes from LLVM's tables. Where the two disagree one of them is
// wrong, and on the properties below it is riscvlint that would be
// wrong in a way that costs a user something -- check_dead_def deletes
// an instruction on rv_pure_def's word, so a `pure def` that is not
// pure is a deleted side effect.
//
// Unlike armlint there is no liveness classifier to sweep:
// riscvlint_liveness reads cs_regs_access directly, with two
// documented corrections. What is riscvlint's own, and so what this
// checks, is the raw decoding:
//
//   1. rv_insn_len must agree with capstone about how long an
//      instruction is. A skew here desynchronizes every scan.
//   2. rv_pure_def's claim is that the instruction's only effect is
//      writing rd. Capstone must report no *other* register written,
//      no memory operand, and no control transfer. Capstone reporting
//      no write at all is its own under-reporting -- counted, not
//      failed -- because riscvlint corrects for that elsewhere.
//   3. rv_decode_mem says an instruction accesses memory. Capstone
//      must agree there is a memory operand.
//
// Off by default: the four-byte half is 2^30 decodes. The compressed
// half is 2^16 and runs unconditionally, because it is where the
// implicit operands are -- c.jalr writes ra, c.addi4spn reads sp --
// and it costs milliseconds.

typedef struct {
    // 64-bit, because the exclusive end of the four-byte space is 2^32,
    // which a uint32_t holds as 0: the last worker then gets an empty
    // range and a sixteenth of the space goes unread while the sweep
    // reports a pass. tools/tblgen_audit.py caught that in the sibling
    // probe before it was noticed here.
    uint64_t lo, hi;            // the words this worker takes
    unsigned size;              // 2 or 4
    uint64_t decoded;
    uint64_t len_bad, pure_bad, mem_bad;
    uint64_t pure_claimed, pure_nowrite;
    uint32_t first_len, first_pure, first_mem;
} sweep_job;

// riscvlint.c's own mapping, which is static there. A capstone
// register id that is not a general one answers 32, which no rd can be.
static unsigned sweep_gpr(unsigned r)
{
    if (r >= RISCV_REG_X0 && r <= RISCV_REG_X31)
        return (unsigned)(r - RISCV_REG_X0);
    return 32;
}

static bool sweep_group(const cs_insn *in, unsigned g)
{
    if (!in->detail) return false;
    for (uint8_t i = 0; i < in->detail->groups_count; i++)
        if (in->detail->groups[i] == g) return true;
    return false;
}

static bool sweep_has_mem(const cs_insn *in)
{
    if (!in->detail) return false;
    const cs_riscv *rv = &in->detail->riscv;
    for (uint8_t i = 0; i < rv->op_count; i++)
        if (rv->operands[i].type == RISCV_OP_MEM) return true;
    return false;
}

static void sweep_one(csh handle, cs_insn *insn, sweep_job *j, uint32_t w)
{
    uint8_t bytes[4];
    memcpy(bytes, &w, 4);
    const uint8_t *p = bytes;
    size_t remain = j->size;
    uint64_t addr = 0x1000;
    if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) return;
    j->decoded++;

    // 1. The length.
    if (rv_insn_len(w) != insn->size) {
        if (!j->len_bad++) j->first_len = w;
    }
    if (insn->size != j->size) return;   // capstone read a different width

    // 2. The purity claim.
    unsigned rd;
    if (rv_pure_def(w, j->size, &rd)) {
        j->pure_claimed++;
        cs_regs rr, rw;
        uint8_t nr = 0, nw = 0;
        bool bad = false;
        if (cs_regs_access(handle, insn, rr, &nr, rw, &nw) == CS_ERR_OK) {
            unsigned others = 0;
            for (uint8_t i = 0; i < nw; i++)
                if (sweep_gpr(rw[i]) != rd) others++;
            if (others) bad = true;
            if (!nw) j->pure_nowrite++;
        }
        // A pure definition cannot transfer control or touch memory.
        if (sweep_group(insn, RISCV_GRP_JUMP) ||
            sweep_group(insn, RISCV_GRP_CALL) ||
            sweep_group(insn, RISCV_GRP_RET) ||
            sweep_group(insn, RISCV_GRP_BRANCH_RELATIVE) ||
            sweep_has_mem(insn))
            bad = true;
        if (bad && !j->pure_bad++) j->first_pure = w;
    }

    // 3. The memory claim.
    rv_mem_kind kind;
    unsigned data, base;
    int64_t off;
    if (rv_decode_mem(w, j->size, &kind, &data, &base, &off) &&
        kind != RV_MEM_NONE && !sweep_has_mem(insn)) {
        if (!j->mem_bad++) j->first_mem = w;
    }
}

static void sweep_run(sweep_job *j)
{
    csh handle;
    if (cs_open(CS_ARCH_RISCV, RISCVLINT_CS_MODE, &handle) != CS_ERR_OK)
        return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);
    if (insn) {
        for (uint64_t w = j->lo; w < j->hi; w++) {
            // The low two bits say the length: both set is four bytes.
            if (j->size == 4 && (w & 3u) != 3u) continue;
            if (j->size == 2 && (w & 3u) == 3u) continue;
            sweep_one(handle, insn, j, (uint32_t)w);
        }
        cs_free(insn, 1);
    }
    cs_close(&handle);
}

static void *sweep_thread(void *arg)
{
    sweep_run(arg);
    return NULL;
}

static void sweep_report(const char *what, sweep_job *jobs, unsigned n)
{
    sweep_job t;
    memset(&t, 0, sizeof t);
    for (unsigned i = 0; i < n; i++) {
        t.decoded += jobs[i].decoded;
        t.pure_claimed += jobs[i].pure_claimed;
        t.pure_nowrite += jobs[i].pure_nowrite;
        if (jobs[i].len_bad && !t.len_bad) t.first_len = jobs[i].first_len;
        if (jobs[i].pure_bad && !t.pure_bad) t.first_pure = jobs[i].first_pure;
        if (jobs[i].mem_bad && !t.mem_bad) t.first_mem = jobs[i].first_mem;
        t.len_bad += jobs[i].len_bad;
        t.pure_bad += jobs[i].pure_bad;
        t.mem_bad += jobs[i].mem_bad;
    }
    printf("sweep %s: %" PRIu64 " decoded, %" PRIu64 " pure defs"
           " (%" PRIu64 " with no capstone write)\n", what, t.decoded,
           t.pure_claimed, t.pure_nowrite);
    if (t.len_bad)
        printf("  FAIL %" PRIu64 " length disagreements, first 0x%08x\n",
               t.len_bad, t.first_len);
    if (t.pure_bad)
        printf("  FAIL %" PRIu64 " impure 'pure defs', first 0x%08x\n",
               t.pure_bad, t.first_pure);
    if (t.mem_bad)
        printf("  FAIL %" PRIu64 " memory claims capstone denies,"
               " first 0x%08x\n", t.mem_bad, t.first_mem);
    CHECK(t.len_bad == 0);
    CHECK(t.pure_bad == 0);
    CHECK(t.mem_bad == 0);
}

static void sweep_space(const char *what, unsigned size, uint64_t end,
                        unsigned nthreads)
{
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 64) nthreads = 64;
    sweep_job *jobs = calloc(nthreads, sizeof *jobs);
    pthread_t *tids = calloc(nthreads, sizeof *tids);
    if (!jobs || !tids) { free(jobs); free(tids); CHECK(false); return; }
    uint64_t span = end / nthreads;
    for (unsigned i = 0; i < nthreads; i++) {
        jobs[i].size = size;
        jobs[i].lo = i * span;
        jobs[i].hi = i + 1 == nthreads ? end : (i + 1) * span;
    }
    unsigned started = 0;
    for (unsigned i = 0; i < nthreads; i++)
        if (pthread_create(&tids[i], NULL, sweep_thread, &jobs[i]) == 0)
            started++;
        else
            break;
    // A thread that would not start is run here rather than skipped,
    // so a sweep never reports a clean pass over a range it never read.
    for (unsigned i = started; i < nthreads; i++) sweep_run(&jobs[i]);
    for (unsigned i = 0; i < started; i++) pthread_join(tids[i], NULL);
    sweep_report(what, jobs, nthreads);
    free(jobs);
    free(tids);
}

static void test_sweep(void)
{
    // The compressed space always: 2^16 words, and the quadrant with
    // the implicit sp and ra operands is exactly where a hand decode
    // goes wrong.
    sweep_space("compressed (2^16)", 2, 0x10000, 1);

    const char *on = getenv("RISCVLINT_SWEEP");
    if (!on || !*on || !strcmp(on, "0")) {
        printf("sweep four-byte: skipped (set RISCVLINT_SWEEP=1)\n");
        return;
    }
    unsigned nthreads = 1;
    const char *t = getenv("RISCVLINT_SWEEP_THREADS");
    if (t) {
        long v = strtol(t, NULL, 10);
        if (v > 0) nthreads = (unsigned)v;
    }
    sweep_space("four-byte (2^32)", 4, 0x100000000ull, nthreads);
}

// Constant chains. The encodings are clang's for rv64gc; the buffer
// holds one four-byte chain, one compressed three-step chain, two
// single-instruction materializations, and the four-byte chain again
// so the rebuild path has something to find.
static const uint8_t cchain_code[] = {
    0x37, 0xb5, 0xaa, 0xaa,        // lui a0,0xaaaab
    0x1b, 0x05, 0xb5, 0xaa,        // addiw a0,a0,-1365   -> 0xffffffffaaaaaaab
    0x95, 0x45,                    // c.li a1,5           -> 5, one instruction
    0x05, 0x66,                    // c.lui a2,0x1
    0x41, 0x06,                    // c.addi a2,a2,16
    0x12, 0x06,                    // c.slli a2,a2,4      -> 0x10100
    0x81, 0x46,                    // c.li a3,0           -> 0, one instruction
    0x82, 0x80,                    // c.ret
    0x37, 0xb7, 0xaa, 0xaa,        // lui a4,0xaaaab
    0x1b, 0x07, 0xb7, 0xaa,        // addiw a4,a4,-1365   -> the same value
    0x82, 0x80,                    // c.ret
};

#define CC_MAGIC ((int64_t)0xffffffffaaaaaaabull)   // the divide-by-3 magic

// Hooks. `one_function` puts every chain in the same function, so the
// second build of a value is a rebuild; `per_address` gives each its
// own, so none is.
static uint64_t cc_one_function(void *ctx, uint64_t addr)
{
    (void)ctx; (void)addr;
    return 0x1000;
}

static uint64_t cc_per_address(void *ctx, uint64_t addr)
{
    (void)ctx;
    return addr;
}

static uint64_t cc_no_function(void *ctx, uint64_t addr)
{
    (void)ctx; (void)addr;
    return 0;
}

static bool cc_mapped_magic(void *ctx, uint64_t value)
{
    (void)ctx;
    return value == (uint64_t)CC_MAGIC;
}

static bool cc_mapped_long(void *ctx, uint64_t value)
{
    (void)ctx;
    return value == 0x10100;        // reached by a three-step chain
}

static void test_cchain(csh handle)
{
    size_t chains, insns, rebuilt;
    bool address;

    // No hooks: the totals and the by-value figures stand on their own.
    riscvlint_cchain *c = riscvlint_cchain_create();
    CHECK(c != NULL);
    if (!c) return;
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    // Five materializations: two of them one instruction, three chains.
    CHECK(riscvlint_cchain_chains(c) == 5);
    CHECK(riscvlint_cchain_instructions(c) == 9);
    CHECK(riscvlint_cchain_values(c) == 2);     // only the chains are tallied
    CHECK(riscvlint_cchain_lookup(c, CC_MAGIC, &chains, &insns, &rebuilt,
                                  &address));
    CHECK(chains == 2 && insns == 4 && rebuilt == 0 && !address);
    CHECK(riscvlint_cchain_lookup(c, 0x10100, &chains, &insns, NULL, NULL));
    CHECK(chains == 1 && insns == 3);
    // The single-instruction values are counted in the totals and kept
    // out of the tally, which is what stops a report about expensive
    // constants being a list of `li rd,0`.
    CHECK(!riscvlint_cchain_lookup(c, 5, NULL, NULL, NULL, NULL));
    CHECK(!riscvlint_cchain_lookup(c, 0, NULL, NULL, NULL, NULL));
    riscvlint_cchain_destroy(c);

    // One function: the second build of the magic is a rebuild.
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_set_hooks(c, NULL, NULL, cc_one_function, NULL);
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    CHECK(riscvlint_cchain_lookup(c, CC_MAGIC, &chains, NULL, &rebuilt, NULL));
    CHECK(chains == 2 && rebuilt == 1);
    riscvlint_cchain_destroy(c);

    // A function each: the same two builds, no rebuild. The figure is
    // about repetition inside one function, not about the binary.
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_set_hooks(c, NULL, NULL, cc_per_address, NULL);
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    CHECK(riscvlint_cchain_lookup(c, CC_MAGIC, NULL, NULL, &rebuilt, NULL));
    CHECK(rebuilt == 0);
    riscvlint_cchain_destroy(c);

    // No function at all -- a stripped C++ binary -- is not a function
    // every chain shares: nothing may be called a rebuild.
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_set_hooks(c, NULL, NULL, cc_no_function, NULL);
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    CHECK(riscvlint_cchain_lookup(c, CC_MAGIC, NULL, NULL, &rebuilt, NULL));
    CHECK(rebuilt == 0);
    riscvlint_cchain_destroy(c);

    // The address label, and the rule that only a two-instruction chain
    // can carry it: `lui` sets bits 31:12 and the `addi` the low twelve,
    // so the %hi/%lo idiom is exactly two instructions and a longer
    // chain is arithmetic however the value lands.
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_set_hooks(c, cc_mapped_magic, NULL, NULL, NULL);
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    CHECK(riscvlint_cchain_lookup(c, CC_MAGIC, NULL, NULL, NULL, &address));
    CHECK(address);
    riscvlint_cchain_destroy(c);

    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_set_hooks(c, cc_mapped_long, NULL, NULL, NULL);
    riscvlint_cchain_scan(c, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    CHECK(riscvlint_cchain_lookup(c, 0x10100, NULL, NULL, NULL, &address));
    CHECK(!address);
    riscvlint_cchain_destroy(c);

    // Non-adjacent steps and a cross-register completion, which is what
    // the per-register tracking exists for. These are libxul's own bytes
    // at 0x3267b2a: two mask materializations whose `lui`s the scheduler
    // batched, with unrelated work between, and the first completing
    // into a register other than the one it was built in.
    static const uint8_t split[] = {
        0xb7, 0x55, 0x55, 0x55,        // lui a1,0x55555
        0x37, 0x36, 0x33, 0x33,        // lui a2,0x33333
        0x13, 0x54, 0xfb, 0x43,        // srai s0,s6,0x3f   (unrelated)
        0x93, 0x84, 0x55, 0x55,        // addi s1,a1,1365 -> 0x55555555
        0x13, 0x06, 0x36, 0x33,        // addi a2,a2,819  -> 0x33333333
    };
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_scan(c, handle, NULL, split, sizeof split, 0x1000);
    // Both masks are found at two instructions each, which an adjacency
    // rule reports as neither: it would close `lui a1` against `lui a2`
    // and bin both at one instruction.
    CHECK(riscvlint_cchain_lookup(c, 0x55555555, &chains, &insns, NULL, NULL));
    CHECK(chains == 1 && insns == 2);
    CHECK(riscvlint_cchain_lookup(c, 0x33333333, &chains, &insns, NULL, NULL));
    CHECK(chains == 1 && insns == 2);
    // The cross-register step left a1 in flight rather than consuming
    // it, because an `addi` reading a built constant may be using it as
    // a base rather than completing it. Nothing finished a1, so it
    // closes as a one-instruction value and is not tallied.
    CHECK(!riscvlint_cchain_lookup(c, 0x55555000, NULL, NULL, NULL, NULL));
    // Three materializations: the two masks and a1's leftover. The
    // `lui a1` is counted under both its own and s1's chain, which is
    // the price of not guessing which of the two the step was.
    CHECK(riscvlint_cchain_chains(c) == 3);
    CHECK(riscvlint_cchain_instructions(c) == 5);
    CHECK(riscvlint_cchain_values(c) == 2);
    riscvlint_cchain_destroy(c);

    // Composition through a register-register `add`, which is how
    // RISCVMatInt joins the halves of a 64-bit value. Without it the
    // chain stops at the shifted high half and a 64-bit constant is
    // reported as something that was never built.
    static const uint8_t comp[] = {
        0xb7, 0x55, 0x55, 0x55,        // lui a1,0x55555
        0x93, 0x84, 0x55, 0x55,        // addi s1,a1,1365 -> 0x55555555
        0x13, 0x99, 0x04, 0x02,        // slli s2,s1,0x20 -> 0x5555555500000000
        0xb3, 0x09, 0x99, 0x00,        // add s3,s2,s1    -> 0x5555555555555555
    };
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_scan(c, handle, NULL, comp, sizeof comp, 0x1000);
    CHECK(riscvlint_cchain_lookup(c, (int64_t)0x5555555555555555ull, &chains,
                                  &insns, NULL, NULL));
    // Four instructions, not five: s1 and s2 grew from the same `lui`,
    // so their counts overlap and adding them would charge it twice.
    CHECK(chains == 1 && insns == 4);
    // The halves are consumed by the composition and not counted on
    // their own, so neither appears.
    CHECK(!riscvlint_cchain_lookup(c, 0x55555555, NULL, NULL, NULL, NULL));
    CHECK(!riscvlint_cchain_lookup(c, (int64_t)0x5555555500000000ull, NULL,
                                   NULL, NULL, NULL));
    riscvlint_cchain_destroy(c);

    // `or` composes too, and two halves with *different* roots add
    // their counts rather than taking the larger.
    static const uint8_t comp_or[] = {
        0x93, 0x04, 0x10, 0x00,        // addi s1,zero,1   -> 1, one insn
        0x37, 0x39, 0x33, 0x33,        // lui s2,0x33333
        0x13, 0x09, 0x39, 0x33,        // addi s2,s2,819   -> 0x33333333, two
        0x33, 0x6a, 0x99, 0x00,        // or s4,s2,s1      -> 0x33333333 | 1
    };
    c = riscvlint_cchain_create();
    if (!c) { CHECK(false); return; }
    riscvlint_cchain_scan(c, handle, NULL, comp_or, sizeof comp_or, 0x1000);
    CHECK(riscvlint_cchain_lookup(c, 0x33333333, &chains, &insns, NULL, NULL));
    CHECK(chains == 1 && insns == 4);   // 1 + 2 + the `or` itself
    riscvlint_cchain_destroy(c);

    // Everything tolerates NULL, as the census does.
    riscvlint_cchain_destroy(NULL);
    riscvlint_cchain_set_hooks(NULL, NULL, NULL, NULL, NULL);
    riscvlint_cchain_scan(NULL, handle, NULL, cchain_code, sizeof cchain_code,
                          0x1000);
    riscvlint_cchain_print(NULL, "none", false);
    CHECK(riscvlint_cchain_chains(NULL) == 0);
    CHECK(!riscvlint_cchain_lookup(NULL, 0, NULL, NULL, NULL, NULL));
}

// An address computed for one indexed load, which Zilx does in one
// instruction. The encodings are clang's for rv64gc.
static void test_indexed_load(csh handle)
{
    riscvlint_finding f;
    const unsigned zilx = RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZILX;

    // The commonest shape: the load overwrites the address register, so
    // the computed address dies by construction and no walk is needed.
    static const uint8_t self[] = {
        0x33, 0x85, 0xc5, 0x00,     // add a0,a1,a2
        0x08, 0x61,                 // c.ld a0,0(a0)
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, self, sizeof self,
                          0x1000, zilx, &f) == 1);
    CHECK(f.address == 0x1000 && f.insn_count == 2);
    CHECK(strstr(f.replacement, "lxd a0, (a1), a2") != NULL);
    CHECK(strstr(f.replacement, "(6 -> 4 bytes)") != NULL);

    // A byte load, which Zilx spells with the scaled form because its
    // scale factor is 1. The address register is written again after,
    // so the walk proves it dead.
    static const uint8_t bytes[] = {
        0xb3, 0x86, 0xc5, 0x00,     // add a3,a1,a2
        0x03, 0xc7, 0x06, 0x00,     // lbu a4,0(a3)
        0x81, 0x46,                 // c.li a3,0
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, bytes, sizeof bytes,
                          0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxsbu a4, (a1), a2") != NULL);

    // The gate, which is this check's own: Zilx has to be positively
    // present. An object declaring an arch without it is silent, and so
    // is one declaring nothing at all -- where every other gated check
    // would fire, since Zilx is in no profile and no shipping core and
    // the permissive reading would suggest an instruction nobody can
    // execute.
    CHECK(run_window_exts(handle, check_indexed_load, self, sizeof self,
                          0x1000, RISCVLINT_EXT_DECLARED, NULL) == 0);
    CHECK(run_window_exts(handle, check_indexed_load, self, sizeof self,
                          0x1000, 0, NULL) == 0);
    unsigned m;
    CHECK(riscvlint_parse_ext_name("zilx", &m) && m == RISCVLINT_EXT_ZILX);
    CHECK(!(riscvlint_parse_ext_name("rva23", &m) &&
            (m & RISCVLINT_EXT_ZILX)));

    // Zilx has no indexed store, so a store through the computed base
    // is not a finding however much it looks like one.
    static const uint8_t store[] = {
        0xb3, 0x86, 0xc5, 0x00,     // add a3,a1,a2
        0x98, 0xe2,                 // c.sd a4,0(a3)
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, store, sizeof store,
                          0x1000, zilx, NULL) == 0);

    // Nor an indexed floating-point load.
    static const uint8_t fp[] = {
        0xb3, 0x86, 0xc5, 0x00,     // add a3,a1,a2
        0x88, 0x22,                 // c.fld fa0,0(a3)
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, fp, sizeof fp,
                          0x1000, zilx, NULL) == 0);

    // A non-zero offset needs the base+index form *and* a displacement,
    // which Zilx does not have.
    static const uint8_t off[] = {
        0xb3, 0x86, 0xc5, 0x00,     // add a3,a1,a2
        0x98, 0x66,                 // c.ld a4,8(a3)
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, off, sizeof off,
                          0x1000, zilx, NULL) == 0);

    // And the address register read again afterwards: the fold stops
    // writing it, so the walk has to prove it dead and here it is not.
    static const uint8_t live[] = {
        0xb3, 0x86, 0xc5, 0x00,     // add a3,a1,a2
        0x98, 0x62,                 // c.ld a4,0(a3)
        0xb6, 0x87,                 // c.mv a5,a3
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_indexed_load, live, sizeof live,
                          0x1000, zilx, NULL) == 0);
}

// Counts findings by title over the whole registry. The scaled fold's
// suppression of the unscaled one cannot be seen through
// run_window_exts: the two fire at different instructions and reach
// each other through the state, so the scan is the only harness that
// watches both at once.
typedef struct {
    const char *a, *b;
    int na, nb;
} title_tally;

static void tally_titles(void *ctx, const riscvlint_finding *f)
{
    title_tally *t = ctx;
    if (t->a && strcmp(f->title, t->a) == 0) t->na++;
    if (t->b && strcmp(f->title, t->b) == 0) t->nb++;
}

static void scan_titles(csh handle, const uint8_t *code, size_t len,
                        uint64_t vaddr, unsigned exts, title_tally *t)
{
    static uint8_t buf[256];
    memcpy(buf, code, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) { failures++; return; }
    riscvlint_state_set_extensions(state, exts);
    if (riscvlint_state_set_section(state, handle, buf, len, vaddr))
        riscvlint_scan(state, handle, buf, len, vaddr, tally_titles, t,
                       NULL, NULL);
    riscvlint_state_destroy(state);
}

// An address scaled for one indexed load. Every buffer here is clang's
// own assembly of the shape, since hand-encoding three instructions and
// a shift amount is how a test comes to agree with a wrong check.
static void test_scaled_indexed_load(csh handle)
{
    riscvlint_finding f;
    const unsigned zilx = RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZILX;

    // The commonest shape: the add overwrites the shifted index and the
    // load overwrites the address, so both writes the fold removes die
    // by construction and no walk is needed.
    static const uint8_t self[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x83, 0xb6, 0x06, 0x00,     // ld   a3, 0(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, self,
                          sizeof self, 0x1000, zilx, &f) == 1);
    CHECK(f.address == 0x1000 && f.insn_count == 3);
    CHECK(strstr(f.replacement, "lxsd a3, (s6), a5") != NULL);
    CHECK(strstr(f.replacement, "(12 -> 4 bytes)") != NULL);

    // All three compressed, which is the cheapest the base ISA can
    // spell this and still twice the size of the fold. c.slli implies
    // rd == rs1, so here the index register is the shifted register and
    // the suggestion names it unshifted.
    static const uint8_t packed[] = {
        0x8e, 0x06,                 // c.slli a3, 3
        0xda, 0x96,                 // c.add  a3, s6
        0x94, 0x62,                 // c.ld   a3, 0(a3)
        0x82, 0x80,                 // c.jr   ra
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, packed,
                          sizeof packed, 0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxsd a3, (s6), a3") != NULL);
    CHECK(strstr(f.replacement, "(6 -> 4 bytes)") != NULL);

    // The scale is log2 of the access size and nothing else, so a shift
    // the load's width does not match is a different computation. This
    // is the condition the whole population rests on: without it the
    // triple reads 78% higher on libLLVM.
    static const uint8_t mismatch[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x83, 0xa6, 0x06, 0x00,     // lw   a3, 0(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, mismatch,
                          sizeof mismatch, 0x1000, zilx, NULL) == 0);

    // A halfword, where the address register is not the loaded one and
    // the walk has to prove it dead.
    static const uint8_t half[] = {
        0x93, 0x96, 0x17, 0x00,     // slli a3, a5, 1
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x03, 0xd7, 0x06, 0x00,     // lhu  a4, 0(a3)
        0x93, 0x06, 0x00, 0x00,     // li   a3, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, half,
                          sizeof half, 0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxshu a4, (s6), a5") != NULL);

    // Byte loads scale by 1, so their shift amount is zero, there is no
    // `slli` to fold, and a byte load behind one is a shift of
    // something else. That site is the unscaled check's.
    static const uint8_t byte[] = {
        0x93, 0x96, 0x17, 0x00,     // slli a3, a5, 1
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x03, 0xc7, 0x06, 0x00,     // lbu  a4, 0(a3)
        0x93, 0x06, 0x00, 0x00,     // li   a3, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, byte,
                          sizeof byte, 0x1000, zilx, NULL) == 0);

    // The gate is check_indexed_load's: Zilx positively present, not
    // merely un-denied, so an object declaring nothing at all is silent
    // where every other gated check would fire.
    CHECK(run_window_exts(handle, check_scaled_indexed_load, self,
                          sizeof self, 0x1000, RISCVLINT_EXT_DECLARED,
                          NULL) == 0);
    CHECK(run_window_exts(handle, check_scaled_indexed_load, self,
                          sizeof self, 0x1000, 0, NULL) == 0);

    // Zilx has no indexed store and no indexed floating-point load.
    static const uint8_t store[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x23, 0xb0, 0xe6, 0x00,     // sd   a4, 0(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, store,
                          sizeof store, 0x1000, zilx, NULL) == 0);
    static const uint8_t fp[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x07, 0xb5, 0x06, 0x00,     // fld  fa0, 0(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, fp, sizeof fp,
                          0x1000, zilx, NULL) == 0);

    // base + (index << N) and nothing else: there is no displacement to
    // carry the 8 with.
    static const uint8_t off[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0x66, 0x01,     // add  a3, a3, s6
        0x83, 0xb6, 0x86, 0x00,     // ld   a3, 8(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, off, sizeof off,
                          0x1000, zilx, NULL) == 0);

    // `add a3,a3,a3` doubles the shifted value, which is a wider shift
    // and not this rewrite -- and leaves no operand to call the base.
    static const uint8_t twice[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0xb3, 0x86, 0xd6, 0x00,     // add  a3, a3, a3
        0x83, 0xb6, 0x06, 0x00,     // ld   a3, 0(a3)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, twice,
                          sizeof twice, 0x1000, zilx, NULL) == 0);

    // Two writes disappear, so either one still being read declines the
    // fold. These two buffers differ in one register and isolate the
    // proofs: the shifted index read afterwards, then the address.
    static const uint8_t live_index[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0x33, 0x87, 0x66, 0x01,     // add  a4, a3, s6
        0x03, 0x38, 0x07, 0x00,     // ld   a6, 0(a4)
        0x13, 0x85, 0x06, 0x00,     // mv   a0, a3
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, live_index,
                          sizeof live_index, 0x1000, zilx, NULL) == 0);
    static const uint8_t live_addr[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0x33, 0x87, 0x66, 0x01,     // add  a4, a3, s6
        0x03, 0x38, 0x07, 0x00,     // ld   a6, 0(a4)
        0x13, 0x05, 0x07, 0x00,     // mv   a0, a4
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, live_addr,
                          sizeof live_addr, 0x1000, zilx, NULL) == 0);

    // The same three registers with both killed afterwards, which is
    // the walk answering rather than the encoding.
    static const uint8_t walked[] = {
        0x93, 0x96, 0x37, 0x00,     // slli a3, a5, 3
        0x33, 0x87, 0x66, 0x01,     // add  a4, a3, s6
        0x03, 0x38, 0x07, 0x00,     // ld   a6, 0(a4)
        0x93, 0x06, 0x00, 0x00,     // li   a3, 0
        0x13, 0x07, 0x00, 0x00,     // li   a4, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_scaled_indexed_load, walked,
                          sizeof walked, 0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxsd a6, (s6), a5") != NULL);

    // One site is one rewrite. The `add` in the middle is also the
    // unscaled check's match, so a scaled finding has to replace that
    // one rather than stand beside it -- otherwise the pair would be
    // counted twice and counted as the worse fold.
    const char *sc = "address scaled for one indexed load";
    const char *un = "address computed for one indexed load";
    title_tally t = { sc, un, 0, 0 };
    scan_titles(handle, self, sizeof self, 0x1000, zilx, &t);
    CHECK(t.na == 1 && t.nb == 0);

    // And the suppression is precise rather than blanket: where the
    // scaled fold declines, the unscaled one still has its own finding.
    title_tally t2 = { sc, un, 0, 0 };
    scan_titles(handle, mismatch, sizeof mismatch, 0x1000, zilx, &t2);
    CHECK(t2.na == 0 && t2.nb == 1);
}

// An address scaled from a zero-extended index. Same provenance as the
// buffers above: clang assembled every one of them.
static void test_zext_indexed_load(csh handle)
{
    riscvlint_finding f;
    const unsigned zilx = RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZILX;

    // One register throughout, which is what the compiler emits and
    // what needs no liveness walk: the srli overwrites the slli, the
    // add overwrites the srli, the load overwrites the add.
    static const uint8_t self[] = {
        0x13, 0x17, 0x07, 0x02,     // slli a4, a4, 32
        0x13, 0x57, 0xd7, 0x01,     // srli a4, a4, 29
        0x33, 0x07, 0xe5, 0x00,     // add  a4, a0, a4
        0x03, 0x37, 0x07, 0x00,     // ld   a4, 0(a4)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, self,
                          sizeof self, 0x1000, zilx, &f) == 1);
    CHECK(f.address == 0x1000 && f.insn_count == 4);
    CHECK(strstr(f.replacement, "lxsuwd a4, (a0), a4") != NULL);
    CHECK(strstr(f.replacement, "(16 -> 4 bytes)") != NULL);

    // All four compressed, which is as cheap as the base ISA can spell
    // base + (zext32(index) << 3) and still ten bytes against four.
    static const uint8_t packed[] = {
        0x02, 0x17,                 // c.slli a4, 32
        0x75, 0x83,                 // c.srli a4, 29
        0x2a, 0x97,                 // c.add  a4, a0
        0x18, 0x63,                 // c.ld   a4, 0(a4)
        0x82, 0x80,                 // c.jr   ra
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, packed,
                          sizeof packed, 0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "(8 -> 4 bytes)") != NULL);

    // A byte load's scale is 1, so its shift is zero and the pair is
    // `zext.w` itself -- which the Zba check also claims, under a
    // different extension and as a different rewrite.
    static const uint8_t byte[] = {
        0x13, 0x97, 0x06, 0x02,     // slli a4, a3, 32
        0x13, 0x57, 0x07, 0x02,     // srli a4, a4, 32
        0x33, 0x07, 0xe5, 0x00,     // add  a4, a0, a4
        0x83, 0x47, 0x07, 0x00,     // lbu  a5, 0(a4)
        0x13, 0x07, 0x00, 0x00,     // li   a4, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, byte, sizeof byte,
                          0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxsuwbu a5, (a0), a3") != NULL);

    // `srli 28` scales by 16, a stride through 16-byte structures that
    // no load width names. This is the shape that dominates what
    // reaches the test -- 10,133 sites in debian-libllvm22 -- so it is
    // the one rejection that decides the population.
    static const uint8_t stride[] = {
        0x13, 0x97, 0x06, 0x02,     // slli a4, a3, 32
        0x13, 0x57, 0xc7, 0x01,     // srli a4, a4, 28
        0x33, 0x07, 0xe5, 0x00,     // add  a4, a0, a4
        0x83, 0x37, 0x07, 0x00,     // ld   a5, 0(a4)
        0x13, 0x07, 0x00, 0x00,     // li   a4, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, stride,
                          sizeof stride, 0x1000, zilx, NULL) == 0);

    // `srai` shifts the sign back in, so the index is sign-extended and
    // this addressing mode is the wrong one.
    static const uint8_t arith[] = {
        0x13, 0x97, 0x06, 0x02,     // slli a4, a3, 32
        0x13, 0x57, 0xd7, 0x41,     // srai a4, a4, 29
        0x33, 0x07, 0xe5, 0x00,     // add  a4, a0, a4
        0x83, 0x37, 0x07, 0x00,     // ld   a5, 0(a4)
        0x13, 0x07, 0x00, 0x00,     // li   a4, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, arith,
                          sizeof arith, 0x1000, zilx, NULL) == 0);

    // The srli writing a register the slli did not, which is about a
    // third of libxul's population and the case that needs all three
    // liveness proofs at once.
    static const uint8_t split[] = {
        0x13, 0x97, 0x06, 0x02,     // slli a4, a3, 32
        0x93, 0x57, 0xd7, 0x01,     // srli a5, a4, 29
        0x33, 0x08, 0xf5, 0x00,     // add  a6, a0, a5
        0x83, 0x38, 0x08, 0x00,     // ld   a7, 0(a6)
        0x13, 0x07, 0x00, 0x00,     // li   a4, 0
        0x93, 0x07, 0x00, 0x00,     // li   a5, 0
        0x13, 0x08, 0x00, 0x00,     // li   a6, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, split,
                          sizeof split, 0x1000, zilx, &f) == 1);
    CHECK(strstr(f.replacement, "lxsuwd a7, (a0), a3") != NULL);

    // The same quad with the widened index read afterwards. That is the
    // proof the scaled shape never has to make, so it gets its own
    // buffer: the other two registers still die.
    static const uint8_t live_wide[] = {
        0x13, 0x97, 0x06, 0x02,     // slli a4, a3, 32
        0x93, 0x57, 0xd7, 0x01,     // srli a5, a4, 29
        0x33, 0x08, 0xf5, 0x00,     // add  a6, a0, a5
        0x83, 0x38, 0x08, 0x00,     // ld   a7, 0(a6)
        0x13, 0x05, 0x07, 0x00,     // mv   a0, a4
        0x93, 0x07, 0x00, 0x00,     // li   a5, 0
        0x13, 0x08, 0x00, 0x00,     // li   a6, 0
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, live_wide,
                          sizeof live_wide, 0x1000, zilx, NULL) == 0);

    // Still loads only, and still integer loads only.
    static const uint8_t store[] = {
        0x13, 0x17, 0x07, 0x02,     // slli a4, a4, 32
        0x13, 0x57, 0xd7, 0x01,     // srli a4, a4, 29
        0x33, 0x07, 0xe5, 0x00,     // add  a4, a0, a4
        0x23, 0x30, 0xf7, 0x00,     // sd   a5, 0(a4)
        0x67, 0x80, 0x00, 0x00,     // ret
    };
    CHECK(run_window_exts(handle, check_zext_indexed_load, store,
                          sizeof store, 0x1000, zilx, NULL) == 0);

    // The same gate as the other two: positively present, not merely
    // un-denied.
    CHECK(run_window_exts(handle, check_zext_indexed_load, self, sizeof self,
                          0x1000, RISCVLINT_EXT_DECLARED, NULL) == 0);
    CHECK(run_window_exts(handle, check_zext_indexed_load, self, sizeof self,
                          0x1000, 0, NULL) == 0);

    // And the same claim on the `add`: four instructions folding to one
    // is not an unscaled finding beside two surviving shifts.
    const char *zx = "address scaled from a zero-extended index";
    const char *un = "address computed for one indexed load";
    title_tally t = { zx, un, 0, 0 };
    scan_titles(handle, self, sizeof self, 0x1000, zilx, &t);
    CHECK(t.na == 1 && t.nb == 0);

    // Where the width test declines, the unscaled finding stands.
    title_tally t2 = { zx, un, 0, 0 };
    scan_titles(handle, stride, sizeof stride, 0x1000, zilx, &t2);
    CHECK(t2.na == 0 && t2.nb == 1);
}

// A bit count spelled out longhand. The buffer is clang's own output
// for a 32-bit SWAR popcount of a0 into a5 -- masks hoisted, stages
// computed in place, the final shift an `srliw` -- with `li a0,0` after
// it so the source register is provably dead and the rewrite is
// equivalent.
static void test_swar_popcount(csh handle)
{
    riscvlint_finding f;
    static const uint8_t pc32[] = {
        0xb7, 0x55, 0x55, 0x55,     // lui a1,0x55555
        0x93, 0x85, 0x55, 0x55,     // addi a1,a1,1365   -> 0x55555555
        0x37, 0x36, 0x33, 0x33,     // lui a2,0x33333
        0x13, 0x06, 0x36, 0x33,     // addi a2,a2,819    -> 0x33333333
        0xb7, 0x16, 0x0f, 0x0f,     // lui a3,0xf0f1
        0x93, 0x86, 0xf6, 0xf0,     // addi a3,a3,-241   -> 0x0f0f0f0f
        0x37, 0x07, 0x01, 0x01,     // lui a4,0x1010
        0x13, 0x07, 0x17, 0x10,     // addi a4,a4,257    -> 0x01010101
        0x13, 0x58, 0x15, 0x00,     // srli a6,a0,0x1
        0x33, 0x78, 0xb8, 0x00,     // and a6,a6,a1
        0x33, 0x05, 0x05, 0x41,     // sub a0,a0,a6      stage 1, in place
        0x33, 0x78, 0xc5, 0x00,     // and a6,a0,a2
        0x09, 0x81,                 // c.srli a0,a0,0x2
        0x71, 0x8d,                 // c.and a0,a0,a2
        0x42, 0x95,                 // c.add a0,a0,a6    stage 2
        0x13, 0x58, 0x45, 0x00,     // srli a6,a0,0x4
        0x42, 0x95,                 // c.add a0,a0,a6
        0x75, 0x8d,                 // c.and a0,a0,a3    stage 3
        0x33, 0x05, 0xe5, 0x02,     // mul a0,a0,a4
        0x9b, 0x57, 0x85, 0x01,     // srliw a5,a0,0x18  the finding
        0x01, 0x45,                 // c.li a0,0         a0 dies here
        0x82, 0x80,                 // c.ret
    };
    CHECK(run_window_exts(handle, check_swar_popcount, pc32, sizeof pc32,
                          0x1000, RISCVLINT_EXT_DECLARED |
                          RISCVLINT_EXT_ZBB, &f) == 1);
    // Reported at the opening shift, not the closing one: that is where
    // the sequence a reader has to look at begins.
    CHECK(f.address == 0x1020);
    CHECK(strstr(f.replacement, "cpopw a5, a0") != NULL);
    // Twelve instructions, five of them two bytes: 38 bytes for what
    // `cpopw` does in four. The mask materializations are not counted,
    // and neither is stage one counted twice where the two halves of
    // the middle stage both descend from it.
    CHECK(strstr(f.replacement, "(12 instructions, 38 -> 4 bytes") != NULL);

    // The gate. An object declaring an arch without Zbb says the
    // instruction is unavailable.
    CHECK(run_window_exts(handle, check_swar_popcount, pc32, sizeof pc32,
                          0x1000, RISCVLINT_EXT_DECLARED, NULL) == 0);

    // The source register has to be dead, because the sequence computed
    // in place and `cpopw a5,a0` would leave a0 holding what it held.
    // Replacing the `li a0,0` with a use of a0 takes the finding away;
    // on the corpus this is what 74% of the sequences fail.
    static uint8_t live[sizeof pc32];
    memcpy(live, pc32, sizeof pc32);
    live[sizeof pc32 - 4] = 0x2a;   // c.mv a4,a0 in place of c.li a0,0
    live[sizeof pc32 - 3] = 0x87;
    CHECK(run_window_exts(handle, check_swar_popcount, live, sizeof live,
                          0x1000, RISCVLINT_EXT_DECLARED |
                          RISCVLINT_EXT_ZBB, NULL) == 0);

    // A wrong final shift is a different computation: the 32-bit form
    // ends at 24 and nothing else matches.
    static uint8_t shift[sizeof pc32];
    memcpy(shift, pc32, sizeof pc32);
    shift[sizeof pc32 - 6] = 0x55;  // srliw a5,a0,0x10
    CHECK(run_window_exts(handle, check_swar_popcount, shift, sizeof shift,
                          0x1000, RISCVLINT_EXT_DECLARED |
                          RISCVLINT_EXT_ZBB, NULL) == 0);

    // And a wrong mask: 0x55555554 is not 0x55555555, so the sequence
    // computes something else and nothing is reported.
    static uint8_t mask[sizeof pc32];
    memcpy(mask, pc32, sizeof pc32);
    mask[4] = 0x13;                 // addi a1,a1,1364
    mask[5] = 0x85;
    mask[6] = 0x45;
    mask[7] = 0x55;
    CHECK(run_window_exts(handle, check_swar_popcount, mask, sizeof mask,
                          0x1000, RISCVLINT_EXT_DECLARED |
                          RISCVLINT_EXT_ZBB, NULL) == 0);
}

// Zfa's fli table, against LLVM's RISCVLoadFPImm::getLoadFPImm. The
// entry numbers are the ones LLVM's own table yields, so a wrong
// transcription shows up here rather than as a suggestion the assembler
// rejects.
static void test_fli_table(void)
{
    // binary64.
    CHECK(rv_fli_entry(0x3ff0000000000000ull, 8) == 16);   // 1.0
    CHECK(rv_fli_entry(0xbff0000000000000ull, 8) == 0);    // -1.0
    CHECK(rv_fli_entry(0x3fe0000000000000ull, 8) == 12);   // 0.5
    CHECK(rv_fli_entry(0x3fe8000000000000ull, 8) == 14);   // 0.75
    CHECK(rv_fli_entry(0x4000000000000000ull, 8) == 20);   // 2.0
    CHECK(rv_fli_entry(0x40f0000000000000ull, 8) == 29);   // 65536.0
    CHECK(rv_fli_entry(0x3ef0000000000000ull, 8) == 2);    // 2^-16
    CHECK(rv_fli_entry(0x7ff0000000000000ull, 8) == 30);   // inf
    CHECK(rv_fli_entry(0x7ff8000000000000ull, 8) == 31);   // canonical NaN
    CHECK(rv_fli_entry(0x0010000000000000ull, 8) == 1);    // DBL_MIN
    // Everything the table does not hold. Zero is not an entry (x0
    // through fmv.d.x is how that one is built), the only negative
    // entry is -1.0, and a mantissa needing more than two bits is out
    // whether or not the value looks round.
    CHECK(rv_fli_entry(0x0000000000000000ull, 8) == -1);   // 0.0
    CHECK(rv_fli_entry(0x8000000000000000ull, 8) == -1);   // -0.0
    CHECK(rv_fli_entry(0xbfe0000000000000ull, 8) == -1);   // -0.5
    CHECK(rv_fli_entry(0x40091eb851eb851full, 8) == -1);   // 3.14
    CHECK(rv_fli_entry(0x3fb999999999999aull, 8) == -1);   // 0.1
    CHECK(rv_fli_entry(0xfff8000000000000ull, 8) == -1);   // -NaN
    CHECK(rv_fli_entry(0x7ff8000000000001ull, 8) == -1);   // NaN, payload
    CHECK(rv_fli_entry(0xfff0000000000000ull, 8) == -1);   // -inf
    CHECK(rv_fli_entry(0x0000000000000001ull, 8) == -1);   // subnormal
    // 2^-127 is representable as a double and not as a normal float, so
    // the exponent range test is what rejects it rather than the
    // mantissa one.
    CHECK(rv_fli_entry(0x3800000000000000ull, 8) == -1);

    // binary32.
    CHECK(rv_fli_entry(0x3f800000ull, 4) == 16);           // 1.0f
    CHECK(rv_fli_entry(0xbf800000ull, 4) == 0);            // -1.0f
    CHECK(rv_fli_entry(0x00800000ull, 4) == 1);            // FLT_MIN
    CHECK(rv_fli_entry(0x7f800000ull, 4) == 30);           // inf
    CHECK(rv_fli_entry(0x7fc00000ull, 4) == 31);           // NaN
    CHECK(rv_fli_entry(0x4048f5c3ull, 4) == -1);           // 3.14f
    CHECK(rv_fli_entry(0x00000000ull, 4) == -1);           // 0.0f
    CHECK(rv_fli_entry(0x1ff800000ull, 4) == -1);          // not 32 bits
    CHECK(rv_fli_entry(0x3f800000ull, 2) == -1);           // no such width

    // The spelling, which is LLVM's printer: three by name and the rest
    // by value, integral ones with one fraction digit.
    char buf[32];
    CHECK(strcmp(rv_fli_spell(16, buf, sizeof buf), "1.0") == 0);
    CHECK(strcmp(rv_fli_spell(0, buf, sizeof buf), "-1.0") == 0);
    CHECK(strcmp(rv_fli_spell(12, buf, sizeof buf), "0.5") == 0);
    CHECK(strcmp(rv_fli_spell(14, buf, sizeof buf), "0.75") == 0);
    CHECK(strcmp(rv_fli_spell(20, buf, sizeof buf), "2.0") == 0);
    CHECK(strcmp(rv_fli_spell(1, buf, sizeof buf), "min") == 0);
    CHECK(strcmp(rv_fli_spell(30, buf, sizeof buf), "inf") == 0);
    CHECK(strcmp(rv_fli_spell(31, buf, sizeof buf), "nan") == 0);
    CHECK(strcmp(rv_fli_spell(2, buf, sizeof buf),
                 "1.52587890625e-05") == 0);
    // Every entry round-trips: the value its spelling names is the
    // value whose bits map back to it. Entries 1, 30 and 31 are spelled
    // by name and have no value to parse, so they sit out.
    for (int e = 0; e < 32; e++) {
        if (e == 1 || e == 30 || e == 31) continue;
        rv_fli_spell(e, buf, sizeof buf);
        double d = strtod(buf, NULL);
        uint64_t bits;
        memcpy(&bits, &d, sizeof bits);
        CHECK(rv_fli_entry(bits, 8) == e);
    }
}

// A pool of one value at one address, standing in for the image.
typedef struct {
    uint64_t addr;
    uint64_t bits;
    unsigned width;
} fake_pool;

static bool fake_read(void *ctx, uint64_t vaddr, void *out, size_t n)
{
    const fake_pool *p = ctx;
    if (vaddr != p->addr || n != p->width) return false;
    uint8_t b[8];
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(p->bits >> (8 * i));
    memcpy(out, b, n);
    return true;
}

// run_window_exts with an image installed. A NULL pool is the "caller
// offered none" case, where the check must stand down rather than guess.
static int run_fli(csh handle, const uint8_t *code, size_t len,
                   uint64_t vaddr, unsigned exts, fake_pool *pool,
                   riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, code, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return -1;
    riscvlint_state_set_extensions(state, exts);
    if (pool) riscvlint_state_set_image(state, fake_read, pool);
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
            if (check_fp_pool_to_fli(state, insn, &f)) {
                if (out && !fired) *out = f;
                fired++;
            }
            riscvlint_state_observe(state, insn);
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

// A floating-point constant fli would have built. The encodings are
// clang's for rv64gc; the code sits at 0x1000, so `auipc rd,0` plus an
// offset of 256 resolves to 0x1100, which is where the fake pool is.
static void test_fp_pool_to_fli(csh handle)
{
    riscvlint_finding f;
    // The commonest shape in libxul: a double pool load of 1.0, with
    // the address register overwritten straight after.
    static const uint8_t dbl[] = {
        0x17, 0x05, 0x00, 0x00,        // auipc a0,0
        0x07, 0x35, 0x05, 0x10,        // fld fa0,256(a0)
        0x05, 0x45,                    // c.li a0,1
        0x82, 0x80,                    // c.ret
    };
    fake_pool one = { 0x1100, 0x3ff0000000000000ull, 8 };
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, &one, &f) == 1);
    CHECK(f.address == 0x1000 && f.insn_count == 2);
    CHECK(strstr(f.replacement, "fli.d fa0, 1.0") != NULL);
    CHECK(strstr(f.replacement, "8 -> 4 bytes") != NULL);
    CHECK(strstr(f.replacement, "pool 0x1100") != NULL);

    // The four other values libxul's pool holds most of.
    static const struct { uint64_t bits; const char *text; } values[] = {
        { 0x7ff8000000000000ull, "fli.d fa0, nan" },
        { 0x3fe0000000000000ull, "fli.d fa0, 0.5" },
        { 0x7ff0000000000000ull, "fli.d fa0, inf" },
        { 0xbff0000000000000ull, "fli.d fa0, -1.0" },
        { 0x0010000000000000ull, "fli.d fa0, min" },
    };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        fake_pool p = { 0x1100, values[i].bits, 8 };
        CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, &p, &f) == 1);
        CHECK(strstr(f.replacement, values[i].text) != NULL);
    }

    // A value no entry holds is the common case and not a finding.
    static const uint64_t absent[] = {
        0x40091eb851eb851full,         // 3.14
        0x0000000000000000ull,         // 0.0
        0xbfe0000000000000ull,         // -0.5
    };
    for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++) {
        fake_pool p = { 0x1100, absent[i], 8 };
        CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, &p, NULL) == 0);
    }

    // The single, which is `flw` and `fli.s`.
    static const uint8_t sgl[] = {
        0x97, 0x05, 0x00, 0x00,        // auipc a1,0
        0x87, 0xa5, 0x05, 0x10,        // flw fa1,256(a1)
        0x85, 0x45,                    // c.li a1,1
        0x82, 0x80,                    // c.ret
    };
    fake_pool onef = { 0x1100, 0x3f800000ull, 4 };
    CHECK(run_fli(handle, sgl, sizeof sgl, 0x1000, 0, &onef, &f) == 1);
    CHECK(strstr(f.replacement, "fli.s fa1, 1.0") != NULL);

    // The rewrite stops writing the address register, so a site that
    // reads it afterwards is not one. This is what the liveness proof
    // is for, and on libxul it is what 475 of 3,441 sites fail.
    static const uint8_t live[] = {
        0x97, 0x06, 0x00, 0x00,        // auipc a3,0
        0x87, 0xb6, 0x06, 0x10,        // fld fa3,256(a3)
        0x36, 0xe0,                    // c.sdsp a3,0(sp)
        0x82, 0x80,                    // c.ret
    };
    fake_pool lp = { 0x1100, 0x3ff0000000000000ull, 8 };
    CHECK(run_fli(handle, live, sizeof live, 0x1000, 0, &lp, NULL) == 0);

    // No image: the caller offered nothing to resolve against, so the
    // check loses a finding rather than inventing one.
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, NULL, NULL) == 0);

    // The pool address must resolve. A reader that declines -- which is
    // what the driver's does for a writable section -- is the same
    // answer as having none.
    fake_pool elsewhere = { 0x2200, 0x3ff0000000000000ull, 8 };
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, &elsewhere, NULL) == 0);

    // The gate. An object that declares an arch without Zfa positively
    // says the instruction is unavailable; one that declares an arch
    // with it, or declares nothing at all, leaves the check on.
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000,
                  RISCVLINT_EXT_DECLARED, &one, NULL) == 0);
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000,
                  RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZFA, &one,
                  NULL) == 1);
    CHECK(run_fli(handle, dbl, sizeof dbl, 0x1000, 0, &one, NULL) == 1);
}

// The ISA census. The encodings are the fixture's, assembled by clang
// for rv64gc plus the extensions named, so what capstone's feature
// groups say about them is being checked against what an assembler
// required to emit them.
static bool run_cmul(csh handle, const uint8_t *bytes, size_t len,
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
            fired = check_const_mul_to_shadd(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_const_mul_to_shadd(csh handle)
{
    riscvlint_finding f;

    // c.li a5,3 ; mul a5,a4,a5 -- the commonest spelling, and the one
    // that needs no liveness query: the multiply overwrites the
    // constant it reads.
    static const uint8_t self[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_cmul(handle, self, sizeof self, 0, &f));
    CHECK(strcmp(f.replacement, "sh1add a5, a4, a4 (6 -> 4 bytes)") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x1000);
    CHECK(strcmp(f.title, "li + mul foldable to shNadd") == 0);

    // A wide `li` for the 5: eight bytes down to four.
    static const uint8_t wide[] = {
        0x93, 0x07, 0x50, 0x00,        // li a5,5
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_cmul(handle, wide, sizeof wide, 0, &f));
    CHECK(strcmp(f.replacement, "sh2add a5, a4, a4 (8 -> 4 bytes)") == 0);

    // Nine is the third factor, and the one Go's compiler emits most.
    static const uint8_t nine[] = {
        0xa5, 0x47,                    // c.li a5,9
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_cmul(handle, nine, sizeof nine, 0, &f));
    CHECK(strcmp(f.replacement, "sh3add a5, a4, a4 (6 -> 4 bytes)") == 0);

    // Both halves compressed: Zcb's `c.mul`, where the rewrite buys an
    // instruction and no space. The corpus has none -- no object that
    // multiplies by a small constant also uses Zcb -- but the shape is
    // the one a target with both extensions would present.
    static const uint8_t compressed[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xd9, 0x9f,                    // c.mul a5,a4
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_cmul(handle, compressed, sizeof compressed, 0, &f));
    CHECK(strcmp(f.replacement, "sh1add a5, a4, a4 (4 -> 4 bytes)") == 0);

    // Seven needs two shifts and a subtract: no shNadd, so nothing to
    // say.
    static const uint8_t seven[] = {
        0x9d, 0x47,                    // c.li a5,7
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, seven, sizeof seven, 0, NULL));

    // Four is a shift, which is the rewrite a compiler already made.
    static const uint8_t four[] = {
        0x91, 0x47,                    // c.li a5,4
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, four, sizeof four, 0, NULL));

    // mulw sign-extends its 32-bit product; sh1add does not, so this
    // pair is not two instructions for one.
    static const uint8_t wordop[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xbb, 0x07, 0xf7, 0x02,        // mulw a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, wordop, sizeof wordop, 0, NULL));

    // mulh returns the other half of the product.
    static const uint8_t high[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xb3, 0x17, 0xf7, 0x02,        // mulh a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, high, sizeof high, 0, NULL));

    // The multiply reads the constant twice: that is nine, a constant of
    // its own, not three times something.
    static const uint8_t square[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xb3, 0x87, 0xf7, 0x02,        // mul a5,a5,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, square, sizeof square, 0, NULL));

    // A multiply that does not read the constant at all: the `li` is for
    // something later and the two are adjacent by accident.
    static const uint8_t unrelated[] = {
        0x8d, 0x47,                    // c.li a5,3
        0x33, 0x87, 0xc6, 0x02,        // mul a4,a3,a2
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, unrelated, sizeof unrelated, 0, NULL));

    // x0 as the multiplicand makes the product zero.
    static const uint8_t zeroarg[] = {
        0x8d, 0x47,                    // c.li a5,3
        0x33, 0x07, 0xf0, 0x02,        // mul a4,zero,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, zeroarg, sizeof zeroarg, 0, NULL));

    // The multiply writes elsewhere and the constant is read after it:
    // the rewrite would drop a value something still wants.
    static const uint8_t live[] = {
        0x8d, 0x47,                    // c.li a5,3
        0x33, 0x87, 0xf6, 0x02,        // mul a4,a3,a5
        0x3e, 0x85,                    // c.mv a0,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, live, sizeof live, 0, NULL));

    // The same shape with the constant overwritten instead of read, so
    // the walk proves it dead and the fold stands.
    static const uint8_t walked[] = {
        0x8d, 0x47,                    // c.li a5,3
        0x33, 0x87, 0xf6, 0x02,        // mul a4,a3,a5
        0x85, 0x47,                    // c.li a5,1
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_cmul(handle, walked, sizeof walked, 0, &f));
    CHECK(strcmp(f.replacement, "sh1add a4, a3, a3 (6 -> 4 bytes)") == 0);

    // A branch into the multiply: arriving that way, the register it
    // reads need not hold a 3.
    static const uint8_t target[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xb3, 0x07, 0xf7, 0x02,        // mul a5,a4,a5
        0x75, 0xff,                    // c.bnez a4,-4
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_cmul(handle, target, sizeof target, 0, NULL));

    // Declared without Zba: the instruction does not exist on that
    // target. Declared with it, and the Go case of declaring nothing,
    // both report.
    CHECK(!run_cmul(handle, self, sizeof self,
                    RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBB, NULL));
    CHECK(run_cmul(handle, self, sizeof self,
                   RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBA, NULL));
}

static bool run_udiv(csh handle, const uint8_t *bytes, size_t len,
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
            fired = check_udiv_pow2(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_udiv_pow2(csh handle)
{
    riscvlint_finding f;

    // c.li a5,8 ; divu a5,a4,a5 -- the quotient is the dividend shifted
    // down three, with no bias and no case distinction.
    static const uint8_t divd[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, divd, sizeof divd, 0, &f));
    CHECK(strcmp(f.replacement, "srli a5, a4, 3 (6 -> 4 bytes)") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x1000);
    CHECK(strcmp(f.title,
                 "unsigned divide or remainder by a power of two") == 0);

    // A wide `li` for 64: eight bytes down to four.
    static const uint8_t wide[] = {
        0x93, 0x07, 0x00, 0x04,        // li a5,64
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_udiv(handle, wide, sizeof wide, 0, &f));
    CHECK(strcmp(f.replacement, "srli a5, a4, 6 (8 -> 4 bytes)") == 0);

    // divuw divides the low words and sign-extends: srliw, not srli.
    static const uint8_t divw[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xbb, 0x57, 0xf7, 0x02,        // divuw a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, divw, sizeof divw, 0, &f));
    CHECK(strcmp(f.replacement, "srliw a5, a4, 3 (6 -> 4 bytes)") == 0);

    // The remainder is the low three bits, which is a mask of 7. The
    // `w` form masks to the same value.
    static const uint8_t remd[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x77, 0xf7, 0x02,        // remu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, remd, sizeof remd, 0, &f));
    CHECK(strcmp(f.replacement, "andi a5, a4, 7 (6 -> 4 bytes)") == 0);

    static const uint8_t remw[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xbb, 0x77, 0xf7, 0x02,        // remuw a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, remw, sizeof remw, 0, &f));
    CHECK(strcmp(f.replacement, "andi a5, a4, 7 (6 -> 4 bytes)") == 0);

    // c.lui a5,1 is 4096: a shift of twelve, which srli holds.
    static const uint8_t big[] = {
        0x85, 0x67,                    // c.lui a5,1
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, big, sizeof big, 0, &f));
    CHECK(strcmp(f.replacement, "srli a5, a4, 12 (6 -> 4 bytes)") == 0);

    // The same divisor for a remainder needs a mask of 4095, which does
    // not fit andi's twelve signed bits, so the pair would not shrink.
    static const uint8_t bigrem[] = {
        0x85, 0x67,                    // c.lui a5,1
        0xb3, 0x77, 0xf7, 0x02,        // remu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, bigrem, sizeof bigrem, 0, NULL));

    // The signed forms round toward zero where a shift rounds down, so
    // neither folds to one instruction.
    static const uint8_t signd[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x47, 0xf7, 0x02,        // div a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, signd, sizeof signd, 0, NULL));

    static const uint8_t signr[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x67, 0xf7, 0x02,        // rem a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, signr, sizeof signr, 0, NULL));

    // mulhu shares the funct7 and is not a divide.
    static const uint8_t high[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x37, 0xf7, 0x02,        // mulhu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, high, sizeof high, 0, NULL));

    // Three is not a power of two.
    static const uint8_t three[] = {
        0x8d, 0x47,                    // c.li a5,3
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, three, sizeof three, 0, NULL));

    // One is a move and the remainder by it is zero; zero is a divide
    // by zero, which on riscv64 returns all ones rather than trapping.
    // Neither is a shift, and neither reaches the shift-amount loop.
    static const uint8_t one[] = {
        0x85, 0x47,                    // c.li a5,1
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, one, sizeof one, 0, NULL));

    static const uint8_t zero[] = {
        0x81, 0x47,                    // c.li a5,0
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, zero, sizeof zero, 0, NULL));

    // The constant as the dividend rather than the divisor: division
    // does not commute, so this is 8/a4 and not a shift.
    static const uint8_t swapped[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0xd7, 0xe7, 0x02,        // divu a5,a5,a4
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, swapped, sizeof swapped, 0, NULL));

    // Both operands the constant: that is 1, a constant of its own.
    static const uint8_t both[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0xd7, 0xf7, 0x02,        // divu a5,a5,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, both, sizeof both, 0, NULL));

    // x0 as the dividend makes the quotient zero.
    static const uint8_t zeronum[] = {
        0xa1, 0x47,                    // c.li a5,8
        0x33, 0x57, 0xf0, 0x02,        // divu a4,zero,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, zeronum, sizeof zeronum, 0, NULL));

    // The divide writes elsewhere and the divisor is read after it.
    static const uint8_t live[] = {
        0xa1, 0x47,                    // c.li a5,8
        0x33, 0xd7, 0xf6, 0x02,        // divu a4,a3,a5
        0x3e, 0x85,                    // c.mv a0,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, live, sizeof live, 0, NULL));

    // The same shape with the divisor overwritten, so the walk proves
    // it dead.
    static const uint8_t walked[] = {
        0xa1, 0x47,                    // c.li a5,8
        0x33, 0xd7, 0xf6, 0x02,        // divu a4,a3,a5
        0x85, 0x47,                    // c.li a5,1
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_udiv(handle, walked, sizeof walked, 0, &f));
    CHECK(strcmp(f.replacement, "srli a4, a3, 3 (6 -> 4 bytes)") == 0);

    // A branch into the divide: the divisor need not be 8 on that path.
    static const uint8_t target[] = {
        0xa1, 0x47,                    // c.li a5,8
        0xb3, 0x57, 0xf7, 0x02,        // divu a5,a4,a5
        0x75, 0xff,                    // c.bnez a4,-4
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_udiv(handle, target, sizeof target, 0, NULL));

    // No extension gate: srli, srliw and andi are RV64I, so an object
    // declaring a bare rv64gc still gets the finding, and one declaring
    // Zbb and nothing else gets it too.
    CHECK(run_udiv(handle, divd, sizeof divd, RISCVLINT_EXT_DECLARED, &f));
    CHECK(run_udiv(handle, divd, sizeof divd,
                   RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBB, NULL));
}

static bool run_zibi(csh handle, const uint8_t *bytes, size_t len,
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
            fired = check_const_eq_branch(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_const_eq_branch(csh handle)
{
    riscvlint_finding f;
    const unsigned Z = RISCVLINT_EXT_ZIBI;

    // c.li a5,17 then beq against it, with both successors
    // redefining a5 -- the only way the walk proves deadness, since it
    // declines at a `ret` rather than guess an ABI.
    static const uint8_t eq[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_zibi(handle, eq, sizeof eq, Z, &f));
    CHECK(strcmp(f.replacement,
                 "beqi a4, 17, 0x100a (6 -> 4 bytes)") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x1000);
    CHECK(strcmp(f.title,
                 "constant loaded for one equality branch") == 0);

    // bne gives bnei.
    static const uint8_t ne[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x14, 0xf7, 0x00,     // bne a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_zibi(handle, ne, sizeof ne, Z, &f));
    CHECK(strcmp(f.replacement,
                 "bnei a4, 17, 0x100a (6 -> 4 bytes)") == 0);

    // beq commutes, so the constant may be the first operand; the
    // rewrite names the other one either way.
    static const uint8_t swap[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x84, 0xe7, 0x00,     // beq a5,a4,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_zibi(handle, swap, sizeof swap, Z, &f));
    CHECK(strcmp(f.replacement,
                 "beqi a4, 17, 0x100a (6 -> 4 bytes)") == 0);

    // -1 is in imm5_zibi's range though it is not a five-bit unsigned
    // value: the encoding spends the otherwise unused zero on it.
    static const uint8_t negone[] = {
        0xfd, 0x57,                 // c.li a5,-1 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_zibi(handle, negone, sizeof negone, Z, &f));
    CHECK(strcmp(f.replacement,
                 "beqi a4, -1, 0x100a (6 -> 4 bytes)") == 0);

    // A wide `li` for 31, the top of the range: eight bytes to four.
    static const uint8_t wide[] = {
        0x93, 0x07, 0xf0, 0x01,     // li a5,31 (4)
        0x63, 0x06, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x93, 0x07, 0x10, 0x00,     // li a5,1 (4)
        0x67, 0x80, 0x00, 0x00,     // ret (4)
        0x93, 0x07, 0x20, 0x00,     // li a5,2 (4)
        0x67, 0x80, 0x00, 0x00,     // ret (4)
    };
    CHECK(run_zibi(handle, wide, sizeof wide, Z, &f));
    CHECK(strcmp(f.replacement,
                 "beqi a4, 31, 0x1010 (8 -> 4 bytes)") == 0);

    // 32 is one past the top.
    static const uint8_t big[] = {
        0x93, 0x07, 0x00, 0x02,     // li a5,32 (4)
        0x63, 0x06, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x93, 0x07, 0x10, 0x00,     // li a5,1 (4)
        0x67, 0x80, 0x00, 0x00,     // ret (4)
        0x93, 0x07, 0x20, 0x00,     // li a5,2 (4)
        0x67, 0x80, 0x00, 0x00,     // ret (4)
    };
    CHECK(!run_zibi(handle, big, sizeof big, Z, NULL));

    // -2 is outside it on the other side -- only -1 is there.
    static const uint8_t negtwo[] = {
        0xf9, 0x57,                 // c.li a5,-2 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, negtwo, sizeof negtwo, Z, NULL));

    // Zero is outside it too, and for a reason: `beqz` already
    // compares against x0, which is why Zibi has -1 instead.
    static const uint8_t zero[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, zero, sizeof zero, Z, NULL));

    // Equality only. Zibi's condition predicate is
    // isIntEqualitySetCC, so an ordered comparison has no form.
    static const uint8_t lt[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x44, 0xf7, 0x00,     // blt a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, lt, sizeof lt, Z, NULL));

    // The branch naming the constant in both operands is a condition
    // that reads nothing else.
    static const uint8_t both[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x84, 0xf7, 0x00,     // beq a5,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, both, sizeof both, Z, NULL));

    // ...and in neither, which makes the two adjacent by accident.
    static const uint8_t unrel[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x04, 0xd7, 0x00,     // beq a4,a3,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, unrel, sizeof unrel, Z, NULL));

    // `beq x0,a5`, which the assembler writes as c.beqz: zero against
    // a constant is settled before run time.
    static const uint8_t zeroop[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x99, 0xc3,                 // beq zero,a5,.L (2)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, zeroop, sizeof zeroop, Z, NULL));

    // The constant read again on the fall-through path.
    static const uint8_t live[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x3e, 0x85,                 // mv a0,a5 (2)
        0x82, 0x80,                 // ret (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, live, sizeof live, Z, NULL));

    // ...and the case a fall-through-only proof would miss: dead where
    // a linear scan walks, live where the branch goes. This is the
    // reason the proof is made twice.
    static const uint8_t livetk[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0x82, 0x80,                 // ret (2)
        0x3e, 0x85,                 // mv a0,a5 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, livetk, sizeof livetk, Z, NULL));

    // A branch into the branch: arriving that way, the register
    // compared against need not hold 17.
    static const uint8_t target[] = {
        0xc5, 0x47,                 // c.li a5,17 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0x85, 0x47,                 // c.li a5,1 (2)
        0xed, 0xfe,                 // bnez a3,.T (2)
        0x89, 0x47,                 // c.li a5,2 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_zibi(handle, target, sizeof target, Z, NULL));
    // The gate is positive presence, not un-denial: unlike every
    // riscvlint_may_use check, an object declaring nothing at all is
    // still not told about an instruction no target has. The three Zilx
    // checks read the set the same way.
    CHECK(!run_zibi(handle, eq, sizeof eq, 0, NULL));
    CHECK(!run_zibi(handle, eq, sizeof eq, RISCVLINT_EXT_DECLARED, NULL));
    CHECK(!run_zibi(handle, eq, sizeof eq,
                    RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBA, NULL));
    CHECK(run_zibi(handle, eq, sizeof eq, RISCVLINT_EXT_DECLARED | Z, NULL));
}

static bool run_ord(csh handle, const uint8_t *bytes, size_t len,
                    riscvlint_finding *out)
{
    static uint8_t buf[256];
    memcpy(buf, bytes, len);
    riscvlint_state *state = riscvlint_state_create();
    if (!state) return false;
    bool fired = false;
    if (riscvlint_state_set_section(state, handle, buf, len, 0x1000)) {
        cs_insn *insn = cs_malloc(handle);
        const uint8_t *p = buf;
        size_t remain = len;
        uint64_t addr = 0x1000;
        if (insn && cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            riscvlint_finding f;
            memset(&f, 0, sizeof f);
            fired = check_const_ord_branch(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_const_ord_branch(csh handle)
{
    riscvlint_finding f;

    // `rx <u 1` is `rx == 0`: beqz, and a4 is one of x8-x15 with a
    // displacement CB format holds, so the branch compresses too and the
    // pair goes from six bytes to two.
    // c.li a5,1 ; bltu a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ltu1[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x64, 0xf7, 0x00,     // bltu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, ltu1, sizeof ltu1, &f));
    CHECK(strcmp(f.replacement,
                 "beqz a4, 0x100a (6 -> 2 bytes)") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x1000);
    CHECK(strcmp(f.title,
                 "constant loaded for a branch against zero") == 0);

    // `rx >=u 1` is `rx != 0`.
    // c.li a5,1 ; bgeu a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t geu1[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x74, 0xf7, 0x00,     // bgeu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, geu1, sizeof geu1, &f));
    CHECK(strcmp(f.replacement,
                 "bnez a4, 0x100a (6 -> 2 bytes)") == 0);

    // `rx < 1` is `rx <= 0`, which is `bge x0,rx` -- the comparison
    // flips and the operands swap. No compressed form, so four bytes.
    // c.li a5,1 ; blt a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t lt1[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x44, 0xf7, 0x00,     // blt a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, lt1, sizeof lt1, &f));
    CHECK(strcmp(f.replacement,
                 "blez a4, 0x100a (6 -> 4 bytes)") == 0);

    // `rx >= 1` is `rx > 0`.
    // c.li a5,1 ; bge a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ge1[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x54, 0xf7, 0x00,     // bge a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, ge1, sizeof ge1, &f));
    CHECK(strcmp(f.replacement,
                 "bgtz a4, 0x100a (6 -> 4 bytes)") == 0);

    // Against 0 the signed forms are a plain substitution of x0.
    // c.li a5,0 ; blt a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t lt0[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0x44, 0xf7, 0x00,     // blt a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, lt0, sizeof lt0, &f));
    CHECK(strcmp(f.replacement,
                 "bltz a4, 0x100a (6 -> 4 bytes)") == 0);

    // c.li a5,0 ; bge a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ge0[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0x54, 0xf7, 0x00,     // bge a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, ge0, sizeof ge0, &f));
    CHECK(strcmp(f.replacement,
                 "bgez a4, 0x100a (6 -> 4 bytes)") == 0);

    // With the constant first, `0 <u rx` is `rx != 0`: unsigned
    // comparison against zero collapses to equality either way round.
    // c.li a5,0 ; bltu a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ltu0r[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0xe4, 0xe7, 0x00,     // bltu a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, ltu0r, sizeof ltu0r, &f));
    CHECK(strcmp(f.replacement,
                 "bnez a4, 0x100a (6 -> 2 bytes)") == 0);

    // and `0 >=u rx` is `rx == 0`.
    // c.li a5,0 ; bgeu a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t geu0r[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0xf4, 0xe7, 0x00,     // bgeu a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, geu0r, sizeof geu0r, &f));
    CHECK(strcmp(f.replacement,
                 "beqz a4, 0x100a (6 -> 2 bytes)") == 0);

    // The signed pair with the constant first keeps its comparison and
    // leaves the register in rs2, which is what bgtz and blez are.
    // c.li a5,0 ; blt a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t lt0r[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0xc4, 0xe7, 0x00,     // blt a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, lt0r, sizeof lt0r, &f));
    CHECK(strcmp(f.replacement,
                 "bgtz a4, 0x100a (6 -> 4 bytes)") == 0);

    // c.li a5,0 ; bge a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ge0r[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0xd4, 0xe7, 0x00,     // bge a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, ge0r, sizeof ge0r, &f));
    CHECK(strcmp(f.replacement,
                 "blez a4, 0x100a (6 -> 4 bytes)") == 0);

    // The same fold on t1, which CB format cannot name: the beqz stays
    // four bytes and only the `li` is saved.
    // c.li a5,1 ; bltu t1,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t farreg[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x64, 0xf3, 0x00,     // bltu t1,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(run_ord(handle, farreg, sizeof farreg, &f));
    CHECK(strcmp(f.replacement,
                 "beqz t1, 0x100a (6 -> 4 bytes)") == 0);

    // `1 >=u rx` is `rx <=u 1`, a two-value test with no zero form.
    // This is the shape the corpus actually has most of.
    // c.li a5,1 ; bgeu a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t geu1r[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0xf4, 0xe7, 0x00,     // bgeu a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, geu1r, sizeof geu1r, NULL));

    // `1 <u rx` is `rx >u 1`, likewise.
    // The signed pair with K of 1 and the constant first is the same
    // story: `1 < rx` and `1 >= rx` compare against one, not zero.
    // Between them these four are 39,523 of the corpus's 39,596
    // formless shapes, so they are the rejection that matters.
    // c.li a5,1 ; blt a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t lt1r[] = {
        0x85, 0x47,                 // c.li a5,1
        0x63, 0xc4, 0xe7, 0x00,     // blt a5,a4,.L
        0xa5, 0x47,                 // c.li a5,9
        0x82, 0x80,                 // ret
        0xa1, 0x47,                 // c.li a5,8
        0x82, 0x80,                 // ret
    };
    CHECK(!run_ord(handle, lt1r, sizeof lt1r, NULL));

    // c.li a5,1 ; bge a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ge1r[] = {
        0x85, 0x47,                 // c.li a5,1
        0x63, 0xd4, 0xe7, 0x00,     // bge a5,a4,.L
        0xa5, 0x47,                 // c.li a5,9
        0x82, 0x80,                 // ret
        0xa1, 0x47,                 // c.li a5,8
        0x82, 0x80,                 // ret
    };
    CHECK(!run_ord(handle, ge1r, sizeof ge1r, NULL));
    // c.li a5,1 ; bltu a5,a4,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ltu1r[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0xe4, 0xe7, 0x00,     // bltu a5,a4,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, ltu1r, sizeof ltu1r, NULL));

    // `rx <u 0` is never taken, and that is a dead-branch finding
    // rather than this one.
    // c.li a5,0 ; bltu a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t ltu0[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0x64, 0xf7, 0x00,     // bltu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, ltu0, sizeof ltu0, NULL));

    // `rx >=u 0` is always taken, likewise.
    // c.li a5,0 ; bgeu a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t geu0[] = {
        0x81, 0x47,                 // c.li a5,0 (2)
        0x63, 0x74, 0xf7, 0x00,     // bgeu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, geu0, sizeof geu0, NULL));

    // Two is not 0 or 1, and nothing in the base ISA compares against
    // it without a register.
    // c.li a5,2 ; blt a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t two[] = {
        0x89, 0x47,                 // c.li a5,2 (2)
        0x63, 0x44, 0xf7, 0x00,     // blt a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, two, sizeof two, NULL));

    // Equality against a constant is check_const_eq_branch's, and needs
    // Zibi to say anything at all.
    // c.li a5,1 ; beq a4,a5,.L ; c.li a5,9 ; ret ; c.li a5,8 ; ret
    static const uint8_t eqk[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x04, 0xf7, 0x00,     // beq a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, eqk, sizeof eqk, NULL));

    // The constant read again on the fall-through path.
    // c.li a5,1 ; bltu a4,a5,.L ; mv a0,a5 ; ret ; c.li a5,8 ; ret
    static const uint8_t liveft[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x64, 0xf7, 0x00,     // bltu a4,a5,.L (4)
        0x3e, 0x85,                 // mv a0,a5 (2)
        0x82, 0x80,                 // ret (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, liveft, sizeof liveft, NULL));

    // ...and on the taken path, which a fall-through-only proof would
    // miss.
    // c.li a5,1 ; bltu a4,a5,.L ; c.li a5,9 ; ret ; mv a0,a5 ; ret
    static const uint8_t livetk[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x64, 0xf7, 0x00,     // bltu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0x82, 0x80,                 // ret (2)
        0x3e, 0x85,                 // mv a0,a5 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, livetk, sizeof livetk, NULL));

    // A branch into the branch.
    // c.li a5,1 ; bltu a4,a5,.L ; c.li a5,9 ; bnez a3,.T ; c.li a5,8 ; ret
    static const uint8_t target[] = {
        0x85, 0x47,                 // c.li a5,1 (2)
        0x63, 0x64, 0xf7, 0x00,     // bltu a4,a5,.L (4)
        0xa5, 0x47,                 // c.li a5,9 (2)
        0xed, 0xfe,                 // bnez a3,.T (2)
        0xa1, 0x47,                 // c.li a5,8 (2)
        0x82, 0x80,                 // ret (2)
    };
    CHECK(!run_ord(handle, target, sizeof target, NULL));
}

static bool run_zexth(csh handle, const uint8_t *bytes, size_t len,
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
            fired = check_slli_srli_to_zexth(state, insn, &f);
            if (fired && out) *out = f;
        }
        if (insn) cs_free(insn, 1);
    }
    riscvlint_state_destroy(state);
    return fired;
}

static void test_slli_srli_to_zexth(csh handle)
{
    riscvlint_finding f;

    // slli a5,a4,48 ; c.srli a5,48 -- the spelling all 9,522 corpus
    // sites use, where the srli overwrites what the slli wrote and the
    // intermediate is dead by construction.
    static const uint8_t over[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0xc1, 0x93,                    // c.srli a5,48
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_zexth(handle, over, sizeof over, 0, &f));
    CHECK(strcmp(f.replacement, "zext.h a5, a4 (6 -> 4 bytes)") == 0);
    CHECK(f.insn_count == 2 && f.address == 0x1000);
    CHECK(strcmp(f.title, "slli + srli foldable to zext.h") == 0);

    // Both wide: eight bytes down to four.
    static const uint8_t wide[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0x93, 0xd7, 0x07, 0x03,        // srli a5,a5,48
        0x67, 0x80, 0x00, 0x00,        // ret
    };
    CHECK(run_zexth(handle, wide, sizeof wide, 0, &f));
    CHECK(strcmp(f.replacement, "zext.h a5, a4 (8 -> 4 bytes)") == 0);

    // The srli writing elsewhere, with the shifted value overwritten
    // afterwards so the walk proves it dead. This is the arm the
    // zext.w sibling does not have, and 43 of libgkcodecs's 151 shapes
    // are this -- none of the Go ones.
    static const uint8_t split[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0x93, 0xd6, 0x07, 0x03,        // srli a3,a5,48
        0x85, 0x47,                    // c.li a5,1
        0x82, 0x80,                    // c.ret
    };
    CHECK(run_zexth(handle, split, sizeof split, 0, &f));
    CHECK(strcmp(f.replacement, "zext.h a3, a4 (8 -> 4 bytes)") == 0);

    // The same shape with the shifted value read afterwards instead.
    static const uint8_t live[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0x93, 0xd6, 0x07, 0x03,        // srli a3,a5,48
        0x3e, 0x85,                    // c.mv a0,a5
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_zexth(handle, live, sizeof live, 0, NULL));

    // srai shifts the sign in: that is sext.h, a different rewrite,
    // and rv_decode_srli refuses it.
    static const uint8_t arith[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0xc1, 0x97,                    // c.srai a5,48
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_zexth(handle, arith, sizeof arith, 0, NULL));

    // 32 and 32 is zext.w, which is check_slli_srli_to_zext's and needs
    // Zba rather than Zbb.
    static const uint8_t w32[] = {
        0x93, 0x17, 0x07, 0x02,        // slli a5,a4,32
        0x81, 0x93,                    // c.srli a5,32
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_zexth(handle, w32, sizeof w32, 0, NULL));

    // Shifting left 48 and right 32 keeps sixteen bits and moves them,
    // which is no single instruction at all.
    static const uint8_t mixed[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0x81, 0x93,                    // c.srli a5,32
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_zexth(handle, mixed, sizeof mixed, 0, NULL));

    // An srli that reads something the slli did not write: two
    // instructions that happen to be adjacent.
    static const uint8_t other[] = {
        0x93, 0x17, 0x07, 0x03,        // slli a5,a4,48
        0x93, 0x56, 0x06, 0x03,        // srli a3,a2,48
        0x82, 0x80,                    // c.ret
    };
    CHECK(!run_zexth(handle, other, sizeof other, 0, NULL));

    // Gated on Zbb, permissively: an object declaring an arch string
    // without it is told nothing, one declaring it is, and Go declaring
    // nothing at all is -- which is where the whole population is.
    CHECK(!run_zexth(handle, over, sizeof over,
                     RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBA, NULL));
    CHECK(run_zexth(handle, over, sizeof over,
                    RISCVLINT_EXT_DECLARED | RISCVLINT_EXT_ZBB, NULL));
    CHECK(run_zexth(handle, over, sizeof over, 0, NULL));
}

static void test_census(csh handle)
{
    static const uint8_t code[] = {
        0x11, 0x65,                    // c.lui a0,4          C
        0x97, 0x05, 0x00, 0x00,        // auipc a1,0          baseline
        0x13, 0x16, 0x45, 0x01,        // slli a2,a0,20       baseline
        0x9d, 0x46,                    // c.li a3,7           C
        0x2e, 0x95,                    // c.add a0,a1         C
        0x18, 0x61,                    // c.ld a4,0(a0)       C
        0x3a, 0xe4,                    // c.sdsp a4,8(sp)     C
        0xb3, 0x07, 0xb5, 0x02,        // mul a5,a0,a1        M
        0x33, 0x58, 0xb5, 0x02,        // divu a6,a0,a1       M
        0xaf, 0x28, 0x05, 0x10,        // lr.w a7,(a0)        A
        0xaf, 0x32, 0x65, 0x00,        // amoadd.d t0,t1,(a0) A
        0x53, 0xf5, 0xc5, 0x00,        // fadd.s fa0,fa1,fa2  F
        0xd3, 0x76, 0xf7, 0x02,        // fadd.d fa3,fa4,fa5  D
        0xf3, 0x23, 0x00, 0xc0,        // csrr t2,cycle       Zicsr
        0x0f, 0x10, 0x00, 0x00,        // fence.i             Zifencei
        0x33, 0x4e, 0xb5, 0x20,        // sh2add t3,a0,a1     Zba
        0xb3, 0x7e, 0xb5, 0x40,        // andn t4,a0,a1       Zbb
        0x13, 0x1f, 0x25, 0x60,        // cpop t5,a0          Zbb
        0x93, 0x1f, 0x35, 0x28,        // bseti t6,a0,3       Zbs
        0x33, 0xd5, 0xc5, 0x0e,        // czero.eqz a0,a1,a2  Zicond
        0x53, 0x05, 0x18, 0xf0,        // fli.s fa0,1.0       Zfa
        0x71, 0x9d,                    // c.zext.w a0         Zcb + Zba
        0x0f, 0x00, 0x00, 0x01,        // pause               Zihintpause
        0x33, 0x00, 0x50, 0x00,        // ntl.all             Zihintntl
        0x82, 0x80,                    // c.ret               C
    };

    riscvlint_census *census = riscvlint_census_create();
    CHECK(census != NULL);
    if (!census) return;
    riscvlint_census_scan(census, handle, code, sizeof code, 0x1000);

    CHECK(riscvlint_census_instructions(census) == 25);
    CHECK(riscvlint_census_skipped(census) == 0);
    // Only the auipc and the slli need nothing beyond RV64I: the
    // assembler compressed everything else it could.
    CHECK(riscvlint_census_baseline(census) == 2);

    CHECK(riscvlint_census_extension_count(census, "C") == 6);
    CHECK(riscvlint_census_extension_count(census, "M") == 2);
    CHECK(riscvlint_census_extension_count(census, "A") == 2);
    CHECK(riscvlint_census_extension_count(census, "F") == 1);
    CHECK(riscvlint_census_extension_count(census, "D") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zbb") == 2);
    CHECK(riscvlint_census_extension_count(census, "Zbs") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zicond") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zfa") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zcb") == 1);
    CHECK(riscvlint_census_extension_count(census, "") == 0);
    CHECK(riscvlint_census_extension_count(census, "Zbc") == 0);

    // `c.zext.w` needs Zcb for the encoding and Zba for the instruction,
    // and is counted under both -- so the per-extension counts sum past
    // the instruction total, by exactly the one instruction that does.
    CHECK(riscvlint_census_extension_count(census, "Zba") == 2);

    // Capstone marks no feature group on either of these; the raw-decode
    // path is the only thing that keeps them out of the baseline.
    CHECK(riscvlint_census_extension_count(census, "Zicsr") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zifencei") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zihintpause") == 1);
    CHECK(riscvlint_census_extension_count(census, "Zihintntl") == 1);

    CHECK(strcmp(riscvlint_census_profile(census), "RVA23U64") == 0);
    riscvlint_census_destroy(census);

    // Zba alone is an RVA22 target; the same code with Zba taken out is
    // an RVA20 one. Neither the hints nor Zifencei move it, which is the
    // whole reason they are kept off the rungs: `pause` is a FENCE and
    // `ntl.all` an `add x0,x0,x5` on a core that has neither extension,
    // and Zifencei is mandated by no RVA U-mode profile at all.
    static const uint8_t rva22[] = {
        0x33, 0x4e, 0xb5, 0x20,        // sh2add t3,a0,a1     Zba
        0x0f, 0x00, 0x00, 0x01,        // pause               Zihintpause
        0x0f, 0x10, 0x00, 0x00,        // fence.i             Zifencei
    };
    census = riscvlint_census_create();
    CHECK(census != NULL);
    if (!census) return;
    riscvlint_census_scan(census, handle, rva22, sizeof rva22, 0x1000);
    CHECK(strcmp(riscvlint_census_profile(census), "RVA22U64") == 0);
    riscvlint_census_scan(census, handle, rva22 + 4, sizeof rva22 - 4, 0x2000);
    CHECK(riscvlint_census_extension_count(census, "Zihintpause") == 2);
    CHECK(strcmp(riscvlint_census_profile(census), "RVA22U64") == 0);
    riscvlint_census_destroy(census);

    census = riscvlint_census_create();
    CHECK(census != NULL);
    if (!census) return;
    riscvlint_census_scan(census, handle, rva22 + 4, sizeof rva22 - 4, 0x1000);
    CHECK(strcmp(riscvlint_census_profile(census), "RVA20U64") == 0);
    riscvlint_census_destroy(census);

    // An undecodable halfword is resynchronised past and counted, so the
    // skipped total bounds what the census could have missed. 0x9c00 is
    // a hole in the compressed quadrant 0 that not even Zcb fills; the
    // all-zero halfword would not do, since capstone reads it as the
    // defined `unimp` and counts it as an instruction.
    static const uint8_t bad[] = {
        0x00, 0x9c,                    // reserved
        0x33, 0x4e, 0xb5, 0x20,        // sh2add t3,a0,a1
    };
    census = riscvlint_census_create();
    CHECK(census != NULL);
    if (!census) return;
    riscvlint_census_scan(census, handle, bad, sizeof bad, 0x1000);
    CHECK(riscvlint_census_skipped(census) == 1);
    CHECK(riscvlint_census_instructions(census) == 1);
    CHECK(riscvlint_census_extension_count(census, "Zba") == 1);
    riscvlint_census_destroy(census);

    // NULL is accepted everywhere, which is what lets a caller that
    // could not allocate one carry on without a branch at every site.
    riscvlint_census_scan(NULL, handle, code, sizeof code, 0x1000);
    riscvlint_census_print(NULL, "x", NULL, true);
    CHECK(riscvlint_census_instructions(NULL) == 0);
    CHECK(riscvlint_census_skipped(NULL) == 0);
    CHECK(riscvlint_census_baseline(NULL) == 0);
    CHECK(riscvlint_census_extension_count(NULL, "C") == 0);
    CHECK(strcmp(riscvlint_census_profile(NULL), "RVA20U64") == 0);
    riscvlint_census_destroy(NULL);
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
    test_decode_mem();
    test_mem_encoded_size();
    test_decode_base_add();
    test_decode_condition();
    test_decode_cond_branch();
    test_c_form();
    test_zcb_form();
    test_zcb_gate();
    test_check(handle);
    test_shadd_check(handle);
    test_zext_check(handle);
    test_sp_restore_check(handle);
    test_redundant_ext_check(handle);
    test_zcb_check(handle);
    test_window_checks(handle);
    test_decode_jump();
    test_branch_over_jump(handle);
    test_transfer_to_next(handle);
    test_zero_store_run(handle);
    test_bitcast_through_frame(handle);
    test_cchain(handle);
    test_swar_popcount(handle);
    test_indexed_load(handle);
    test_scaled_indexed_load(handle);
    test_zext_indexed_load(handle);
    test_sweep();
    test_fli_table();
    test_fp_pool_to_fli(handle);
    test_const_mul_to_shadd(handle);
    test_udiv_pow2(handle);
    test_const_eq_branch(handle);
    test_const_ord_branch(handle);
    test_slli_srli_to_zexth(handle);
    test_census(handle);

    cs_close(&handle);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
