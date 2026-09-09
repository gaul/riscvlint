// Integration fixture for check_call_pair_to_jal.
//
// Immediates are written as raw numbers rather than symbol references on
// purpose. A symbolic call emits R_RISCV_CALL_PLT and leaves both
// immediates as zero placeholders, which the check skips -- so a fixture
// written the natural way would test nothing.
//
// Two constraints on what can be written here. A .o has its section at
// address 0, so a net backward displacement underflows past zero and is
// not a finding; the sign-extension path is covered in riscvlint_test.c
// at a realistic address instead. And `jalr rd, 0(rd)` assembles to the
// two-byte c.jalr, which this check does not claim, so every jalr below
// carries a non-zero offset.

    .text
    .globl  _start
    .p2align 1
_start:
    // Positives:
    // 1) Canonical forward call, 16 bytes ahead.
    auipc   ra, 0
    jalr    ra, 16(ra)

    // 2) Negative offset on the jalr, positive overall: one page
    //    forward less 2048 bytes.
    auipc   ra, 1
    jalr    ra, -2048(ra)

    // 3) At the top of jal's reach: 0xff pages + 2046 is 1,046,526,
    //    inside the +1,048,574 ceiling.
    auipc   ra, 0xff
    jalr    ra, 2046(ra)

    // 4) A link register other than ra folds the same way, as long as
    //    the jalr writes back the register the auipc wrote.
    auipc   t0, 0
    jalr    t0, 32(t0)

    // Negatives:
    // N1) Just past 2^20 forward: one step beyond what jal encodes.
    auipc   ra, 0x100
    jalr    ra, 4(ra)

    // N2) Far call, the shape that dominates a large binary.
    auipc   ra, 0x4000
    jalr    ra, 4(ra)

    // N3) Tail call. Collapsing to `j` would stop writing t1, which is
    //     only safe if t1 is dead -- a liveness question this check
    //     does not ask.
    auipc   t1, 0
    jalr    zero, 16(t1)

    // N4) The jalr does not consume the auipc's result.
    auipc   ra, 0
    jalr    ra, 16(t1)

    // N5) The jalr writes a different register than the auipc, so the
    //     rewrite would leave the auipc's destination unwritten.
    auipc   t1, 0
    jalr    ra, 16(t1)

    // N6) auipc into x0 computes nothing.
    auipc   zero, 0
    jalr    zero, 16(zero)

    // N7) Side entry: the branch lands on the jalr, which the rewrite
    //     deletes. The pair is otherwise a textbook positive.
    beqz    a0, .Lside
    auipc   ra, 0
.Lside:
    jalr    ra, 16(ra)

    // N8) Not adjacent: an instruction sits between the two halves.
    auipc   ra, 0
    addi    a0, a0, 1
    jalr    ra, 16(ra)

    ret
