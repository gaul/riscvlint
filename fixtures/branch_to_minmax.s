// Integration fixture for check_branch_to_minmax: an ordered branch over
// a move between the two registers it compared, which Zbb's max and min
// do in one instruction. Assembled with -march=rv64gc_zbb (see the
// .flags sidecar) so the object declares Zbb. Each block stores its
// result, so nothing reads as dead.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Maglev's argument-count clamp: a5 becomes at least 2, and t2,
    // which already holds 2, is what max compares against.
    li      t2, 2
    blt     t2, a5, 1f
    li      a5, 2
1:  sd      a5, 0(sp)

    // A move between the compared registers, a0 kept when the lesser:
    // min.
    blt     a0, a1, 2f
    mv      a0, a1
2:  sd      a0, 8(sp)

    // Unsigned, a2 kept when the greater: maxu.
    bgeu    a2, a3, 3f
    mv      a2, a3
3:  sd      a2, 16(sp)

    // x0 compared and `li a4,0` the move: clamped at zero.
    bge     a4, zero, 4f
    li      a4, 0
4:  sd      a4, 24(sp)

    // Not reported: the move copies a register the branch did not
    // compare.
    blt     a0, a1, 5f
    mv      a0, a2
5:  sd      a0, 32(sp)

    // Not reported: equality chooses nothing.
    li      t2, 2
    beq     t2, a5, 6f
    li      a5, 2
6:  sd      a5, 40(sp)
    ret
