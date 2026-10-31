// Integration fixture for check_long_li: a constant built on one
// register in more instructions than the plain RV64I recurrence needs
// for the value the chain ends up holding. The stores exist so that the
// chains have a reader; without them the dead-definition check has its
// own things to say about the last instruction of each.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) V8's fixed-length 48-bit load: six instructions for a value
    //    that lui + addiw + slli + addi builds in four. The jalr is what
    //    the sequence is for in the corpus.
    lui     t6, 0x156
    addi    t6, t6, 866
    slli    t6, t6, 11
    ori     t6, t6, 0x3f0
    slli    t6, t6, 6
    ori     t6, t6, 0
    jalr    t6

    // 2) Three where two do: 0x1005 is lui 1 + addiw 5.
    li      a0, 1
    slli    a0, a0, 12
    addi    a0, a0, 5
    sd      a0, 0(sp)

    // 3) Optimal chains are not reported.
    lui     a1, 1
    addiw   a1, a1, 5
    sd      a1, 8(sp)
    li      a2, 2
    slli    a2, a2, 35
    sd      a2, 16(sp)

    // 4) Something branches to the addi, so the chain ends at the lui
    //    and one instruction is never too many.
    lui     a3, 1
1:  addi    a3, a3, 5
    slli    a3, a3, 1
    sd      a3, 24(sp)
    beqz    a0, 1b

    // 5) The compressed spelling of 2): six bytes where c.lui + c.addiw
    //    is four, the replacement being priced at the chain's own
    //    encoding class.
    .option rvc
    li      a4, 1
    slli    a4, a4, 12
    addi    a4, a4, 5
    sd      a4, 32(sp)
    ret
