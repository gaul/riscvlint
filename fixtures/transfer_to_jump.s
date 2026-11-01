// Integration fixture for check_transfer_to_jump: a transfer whose
// target is an unconditional jump, retargeted to where that jump goes.
// Nothing is removed, so every finding is four bytes for four or two
// for two; what goes is a taken jump on every path through the
// transfer.
//
// The far jumps' offsets are explicit, as in jump_pair_to_j.s, and the
// distances that decide reach are arranged with .space.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) A branch to a jump.
    bltu    a0, a1, 1f
    ret
1:  j       near

    // 2) Two jumps in a row. The branch skips both, and the first jump
    //    is itself a transfer to a jump.
    bltu    a0, a1, 2f
    ret
2:  j       3f
    ret
3:  j       near

    // 3) A call through a jump, which writes the same link either way.
    jal     ra, 4f
    ret
4:  j       near

    // 4) A compressed branch whose new target is still inside c.beqz's
    //    +/-256: two bytes for two.
    beqz    a0, 5f
    ret
5:  j       near2

    // 5) A chain that leads back to the instruction after the branch,
    //    which then does nothing at all.
    beqz    a0, 6f
7:  ret
6:  j       7b

    // Negatives:
    // N1) A branch over one jump, which check_branch_over_jump folds.
    //     The jump goes rather than being gone around.
    beqz    a0, 8f
    j       near2
8:  j       near

    // N2) A compressed branch whose new target is past c.beqz's +/-256.
    //     It would have to widen to four bytes to save a jump.
    beqz    a0, 9f
    ret
9:  j       near

    // N3) A new target past the branch's +/-4KB.
    bltu    a0, a1, 10f
    ret
10: j       faraway

    // N4) A jump to itself is a loop, not a step on the way anywhere.
    bltu    a0, a1, 11f
    ret
11: j       11b

    .option norvc
    // 6) V8's far jump, landing on a write of t6: skipping the auipc
    //    changes nothing anyone reads.
    beqz    a0, 12f
    ret
12: auipc   t6, 0
    jalr    zero, 12(t6)
    nop
    li      t6, 0
    ret

    // N5) The same far jump landing on a read of t6, which skipping the
    //     auipc would change.
    beqz    a0, 13f
    ret
13: auipc   t6, 0
    jalr    zero, 12(t6)
    nop
    add     a0, t6, a1
    ret
    .option rvc

near2:
    ret
    .space 300
near:
    ret
    .space 4096
faraway:
    ret
