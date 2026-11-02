// Integration fixture for the -f fusion report: one block per pair a
// fusing core issues as one operation, and per kind of near miss.
// Blocks are fenced with ebreak, which no pair includes and no split
// walk passes, so each block is counted on its own. A rename needs the
// first destination proven dead, so those blocks redefine it before
// anything reads it.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // spacemit-x100, fused as written.
    and     a0, a1, a2          // logic + logic
    or      a0, a0, a3
    ebreak
    xor     a0, a1, a2          // logic + logic imm
    andi    a0, a0, 15
    ebreak
    xori    a0, a1, 1           // logic imm + logic
    and     a0, a0, a2
    ebreak
    mul     a0, a1, a2          // mul + add
    add     a0, a0, a3
    ebreak
    mulw    a0, a1, a2          // mulw + addw
    addw    a0, a0, a3
    ebreak
    add     t0, a1, a2          // add + load
    ld      a3, 0(t0)
    ebreak
    add     t0, a1, a2          // add + store
    sw      a3, 0(t0)
    ebreak
    slli    a0, a1, 3           // slli + srai, a field extract
    srai    a0, a0, 3
    ebreak

    // Greedy: the or is taken by the and, so the xor stands alone.
    and     a0, a1, a2
    or      a0, a0, a3
    xor     a0, a0, a4
    ebreak

    // Not fused: a displaced access, an add that overwrites a source,
    // a right shift shorter than the left, and mixed widths.
    add     t0, a1, a2
    ld      a3, 8(t0)
    ebreak
    add     a1, a1, a2
    ld      a3, 0(a1)
    ebreak
    slli    a0, a1, 5
    srli    a0, a0, 3
    ebreak
    mul     a0, a1, a2
    addw    a0, a0, a3
    ebreak

    // Swap: the second reads the first's result as its second operand.
    and     a0, a1, a2
    or      a0, a3, a0
    ebreak
    mul     a0, a1, a2
    add     a0, a3, a0
    ebreak

    // Rename: t1 is dead after the or, so it could have been a4.
    and     t1, a1, a2
    or      a4, t1, a3
    li      t1, 0
    ebreak
    // Not a rename: t1 is read afterwards.
    and     t1, a1, a2
    or      a4, t1, a3
    mv      a5, t1
    ebreak

    // Split: the addi touches neither half, so the xori could sink.
    xori    a0, a1, 1
    addi    a5, a6, 1
    and     a0, a0, a2
    ebreak
    // Split: the addi writes the xori's source, but the and can rise.
    xori    a0, a1, 1
    addi    a1, a1, 1
    and     a0, a0, a2
    ebreak
    // Not split: the addi reads the xori's result.
    xori    a0, a1, 1
    addi    a5, a0, 1
    and     a0, a0, a2
    ebreak
    // Not split: something branches between the two.
    xori    a0, a1, 1
    beqz    a7, 1f
    addi    a5, a6, 1
1:  and     a0, a0, a2
    ebreak
    // Not split: the load writes the add's source, and a load cannot
    // rise past another access.
    add     t0, a1, a2
    ld      a1, 8(sp)
    ld      a3, 0(t0)
    ebreak

    // Split at the limit: seven instructions between, reported; eight,
    // not.
    xori    a0, a1, 1
    addi    t0, t1, 1
    addi    t0, t1, 2
    addi    t0, t1, 3
    addi    t0, t1, 4
    addi    t0, t1, 5
    addi    t0, t1, 6
    addi    t0, t1, 7
    and     a0, a0, a2
    ebreak
    xori    a0, a1, 1
    addi    t0, t1, 1
    addi    t0, t1, 2
    addi    t0, t1, 3
    addi    t0, t1, 4
    addi    t0, t1, 5
    addi    t0, t1, 6
    addi    t0, t1, 7
    addi    t0, t1, 8
    and     a0, a0, a2
    ebreak

    // sifive-p450 and family.
    lui     a0, 0x12345         // lui + addi
    addi    a0, a0, 0x678
    ebreak
    auipc   a0, 0               // auipc + addi
    addi    a0, a0, 16
    ebreak
    lui     t1, 0x12345         // rename: lui + addiw
    addiw   a0, t1, 0x678
    li      t1, 0
    ebreak
    lui     a0, 0x12345         // split: lui + addi
    addi    a5, a6, 1
    addi    a0, a0, 0x678
    ebreak

    // xiangshan-nanhu and -kunminghu; the first is a field extract to
    // the x100 as well, the second is not (32 > 30).
    slli    a0, a1, 32          // zext.w
    srli    a0, a0, 32
    ebreak
    slli    a0, a1, 32          // shifted zext.w
    srli    a0, a0, 30
    ebreak
    slli    a0, a1, 48          // zext.h
    srli    a0, a0, 48
    ebreak

    // The compressed spellings fuse the same.
    .option rvc
    c.slli  a0, 32
    c.srli  a0, 32
    ebreak
    c.and   a0, a1
    c.or    a0, a2
    ebreak
    bnez    a1, 2f              // branch + c.mv
    c.mv    a0, a2
2:  ebreak
    ret
