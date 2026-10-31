// Integration fixture for check_zero_eq_branch: zero loaded into a
// register only to be compared for equality, where beqz and bnez
// compare against x0 without it. Each branch lands on, and falls
// through to, a redefinition of the zero, which proves it dead on both
// successors.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // TurboFan's spelling: the zero, then beq against it.
    li      a7, 0
    beq     a6, a7, 1f
    li      a7, 9
1:  li      a7, 8

    // The zero first, and bne.
    li      t0, 0
    bne     t0, a0, 2f
    li      t0, 9
2:  li      t0, 8

    // Not reported: an ordered comparison, which is the branch-against-
    // zero check's.
    li      a7, 0
    blt     a6, a7, 3f
    li      a7, 9
3:  li      a7, 8

    // Not reported: the zero read again where the branch lands.
    li      a7, 0
    beq     a6, a7, 4f
    li      a7, 9
4:  mv      a0, a7

    // Compressed: a4 is one of x8-x15 and the target is near, so the
    // beqz compresses as well, and six bytes become two.
    .option rvc
    li      a5, 0
    beq     a4, a5, 5f
    li      a5, 9
5:  li      a5, 8
    ret
