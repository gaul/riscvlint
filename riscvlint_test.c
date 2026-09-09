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
    test_check(handle);

    cs_close(&handle);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
