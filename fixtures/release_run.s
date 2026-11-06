// Integration fixture for check_release_run: values popped one at a
// time, the push run read backwards, where one adjustment by the total
// at the last release and the same loads at new offsets would do. Each
// block ends with a `ret`, which ends a run.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // A Wasm epilogue: the frame freed, the saved pair restored, their
    // slots freed. One addi of 32, with the loads at 24 and 16.
    addi    sp, sp, 16
    ld      ra, 8(sp)
    ld      s0, 0(sp)
    addi    sp, sp, 16
    ret

    // Ion pops s0 and ra one at a time. The run begins at the first
    // release, after the load it pairs with.
    ld      s0, 0(sp)
    addi    sp, sp, 8
    ld      ra, 0(sp)
    addi    sp, sp, 8
    ret

    // Three releases, and a load after the last that is not in the run.
    addi    sp, sp, 8
    ld      a0, 0(sp)
    addi    sp, sp, 8
    ld      a2, 0(sp)
    addi    sp, sp, 16
    ld      ra, 0(sp)
    ret

    // Not reported: a reservation ends the run.
    addi    sp, sp, 8
    ld      a0, 0(sp)
    addi    sp, sp, -8
    ld      a2, 0(sp)
    addi    sp, sp, 8
    ret

    // Not reported: sp read between two releases.
    addi    sp, sp, 8
    ld      a0, 0(sp)
    mv      t0, sp
    addi    sp, sp, 8
    ret

    // Not reported: a load into sp ends the run.
    addi    sp, sp, 8
    ld      sp, 0(sp)
    addi    sp, sp, 8
    ret

    // Not reported: a branch back to the second release.
    addi    sp, sp, 8
    ld      a0, 0(sp)
1:  addi    sp, sp, 8
    ld      a2, 0(sp)
    bnez    a2, 1b
    ret

    // Not reported: a load at 2040 moved up by 8 leaves its offset field.
    addi    sp, sp, 8
    ld      a0, 2040(sp)
    addi    sp, sp, 8
    ret

    // Compressed: c.addi16sp 16 around a c.ldsp becomes one c.addi16sp
    // 32 with the load at 16, two bytes saved.
    .option rvc
    addi    sp, sp, 16
    ld      ra, 0(sp)
    addi    sp, sp, 16
    ret
