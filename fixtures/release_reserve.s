// Integration fixture for check_release_reserve: `addi sp,sp,+a`
// directly followed by `addi sp,sp,-b`, which is one addi by the
// difference or nothing at all when the two cancel. The last two blocks
// are the seam with the push run and the release run, each of which
// keeps the half of the pair it holds.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Baseline popping one value and pushing the next: the pair cancels.
    ld      a2, 0(sp)
    addi    sp, sp, 8
    addi    sp, sp, -8
    sd      s1, 0(sp)
    ret

    // Unequal: one addi by the difference.
    addi    sp, sp, 16
    addi    sp, sp, -8
    sd      a0, 0(sp)
    ret

    // Not reported: the reservation is a side entry.
    addi    sp, sp, 8
1:  addi    sp, sp, -8
    sd      a0, 0(sp)
    bnez    a0, 1b
    ret

    // Not reported: an instruction between the two.
    addi    sp, sp, 8
    ld      a0, 0(sp)
    addi    sp, sp, -8
    ret

    // The reservation begins a push run, which takes it; the pair
    // stands down.
    addi    sp, sp, 8
    addi    sp, sp, -8
    sd      a0, 0(sp)
    addi    sp, sp, -8
    sd      a1, 0(sp)
    ret

    // The release ends a release run, which takes it; the pair stands
    // down.
    addi    sp, sp, 8
    ld      a0, 0(sp)
    addi    sp, sp, 8
    addi    sp, sp, -8
    ret

    // Compressed: c.addi sp,8 + c.addi sp,-8 cancel in four bytes.
    .option rvc
    addi    sp, sp, 8
    addi    sp, sp, -8
    ret
