// Integration fixture for check_fixed_branch: a conditional branch
// whose operands fix its outcome. LLVM leaves these when copy
// propagation makes the two registers of a comparison one.

    .text
    .globl  _start
    .p2align 1
_start:
    // 1) Reported, never taken: they can go.
    mv      s10, s11
    bne     s11, s11, 1f
    bltu    a0, zero, 1f

    // 2) Reported, always taken: `j`, which compresses within c.j's
    //    reach.
    beq     a0, a0, 1f
    bgeu    a1, zero, 1f
    bge     a2, a2, 1f
1:
    // 3) Not reported: each compares with something else.
    bne     a0, a1, 2f
    bgez    a0, 2f
    bltu    zero, a0, 2f
2:  ret
