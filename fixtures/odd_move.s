// Integration fixture for check_odd_move: a move spelled other than
// `mv`, or a zeroing other than `li rd,0` that reads a register. The
// K3's X100 eliminates `addi rd,rs,0` and c.mv at rename and runs the
// other moves as one-cycle operations, and a zeroing that reads a
// register waits for it.

    .text
    .globl  _start
    .p2align 1
_start:
    .option push
    .option norvc

    // 1) Reported: moves, as SpiderMonkey copies sp and V8 shifts by
    //    zero.
    or      a2, sp, zero
    ori     a0, a1, 0
    slli    t1, a1, 0
    xor     a3, zero, a4
    sub     a5, a1, zero

    // 2) Reported: zeroings that wait for the register they read.
    xor     a0, a0, a0
    sub     a1, a2, a2
    andi    a3, a4, 0
    sltu    a5, a6, zero

    // 3) Not reported: the canonical spellings, a zeroing from x0 alone,
    //    and a move onto its own source, which is check_no_effect's.
    mv      a0, a1
    li      a0, 0
    lui     a0, 0
    ori     a0, a0, 0
    .option pop

    // 4) Reported: the compressed zeroings, which stay two bytes as c.li.
    c.sub   a0, a0
    c.xor   a1, a1
    ret
