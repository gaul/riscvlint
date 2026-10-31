// Integration fixture for check_push_run: values pushed one at a time,
// as V8's Maglev and baseline tiers push them, where one stack
// adjustment and the same stores at new offsets would do. Each block
// ends with an instruction that reads sp, which ends a run.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Maglev's prologue: three pushes, then the rest of the frame. One
    // addi of -40, with the stores at 32, 24 and 16.
    sd      s0, 0(sp)
    mv      s0, sp
    addi    sp, sp, -8
    sd      s7, 0(sp)
    addi    sp, sp, -8
    sd      a1, 0(sp)
    addi    sp, sp, -8
    sd      a0, 0(sp)
    addi    sp, sp, -16
    addi    t2, sp, -304

    // Baseline loads each value just before pushing it, through s0.
    ld      s3, -120(s0)
    addi    sp, sp, -8
    sd      s3, 0(sp)
    ld      s3, -112(s0)
    addi    sp, sp, -8
    sd      s3, 0(sp)
    ld      s3, -104(s0)
    addi    sp, sp, -8
    sd      s3, 0(sp)
    mv      t0, sp

    // Not reported: sp read between two pushes.
    addi    sp, sp, -8
    sd      a0, 0(sp)
    mv      a1, sp
    addi    sp, sp, -8
    sd      a1, 0(sp)
    mv      t0, sp

    // Not reported: a push of sp itself, whose value the fold changes.
    addi    sp, sp, -8
    sd      sp, 0(sp)
    addi    sp, sp, -8
    sd      a0, 0(sp)
    mv      t0, sp

    // Not reported: a branch back to the second push.
    addi    sp, sp, -8
    sd      a0, 0(sp)
1:  addi    sp, sp, -8
    sd      a1, 0(sp)
    bnez    a2, 1b

    // Compressed: c.addi16sp -64 and -16 around two c.sdsp become one
    // c.addi16sp -80, which saves two bytes rather than four.
    .option rvc
    addi    sp, sp, -64
    sd      a0, 0(sp)
    addi    sp, sp, -16
    sd      a1, 0(sp)
    ret
