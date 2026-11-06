// Integration fixture for check_cross_jump: a label reached only by
// unconditional jumps, each preceded by the same instructions, which
// can hold those instructions once. The instruction before each label
// is a `ret` or a `j`, so nothing falls into it.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) Two jumps to L1, each after `li a0,1`: one copy of the tail.
    li      a0, 1
    j       .L1
    li      a0, 1
    j       .L1
    li      a1, 0
    ret
.L1:
    li      a2, 0
    ret

    // 2) A two-instruction tail shared by three jumps.
    xor     a0, a0, a1
    add     a0, a0, a2
    j       .L2
    xor     a0, a0, a1
    add     a0, a0, a2
    j       .L2
    xor     a0, a0, a1
    add     a0, a0, a2
    j       .L2
    li      a1, 0
    ret
.L2:
    li      a2, 0
    ret

    // 3) Not reported: the tails differ.
    li      a0, 1
    j       .L3
    li      a0, 2
    j       .L3
    li      a1, 0
    ret
.L3:
    li      a2, 0
    ret

    // 4) Not reported: a conditional branch also reaches the label.
    li      a0, 1
    j       .L4
    li      a0, 1
    j       .L4
    beqz    a3, .L4
    ret
.L4:
    li      a2, 0
    ret

    // 5) Not reported: the instruction before the label falls through.
    li      a0, 1
    j       .L5
    li      a0, 1
    j       .L5
    li      a1, 0
.L5:
    li      a2, 0
    ret

    // 6) A branch into the second tail below its top: the tail stops
    //    above that instruction, one instruction rather than two.
    xor     a0, a0, a1
    add     a0, a0, a2
    j       .L6
    xor     a0, a0, a1
.L6b:
    add     a0, a0, a2
    j       .L6
    bnez    a0, .L6b
    ret
.L6:
    li      a2, 0
    ret
