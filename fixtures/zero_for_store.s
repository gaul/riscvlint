// Integration fixture for check_zero_for_store: a register loaded with
// zero only to be stored, where each store could store x0 and the li
// go. The shapes are V8's baseline and Maglev ones; each block ends by
// redefining the register, which is what proves it dead.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Baseline: one store of the zero.
    li      a0, 0
    sd      a0, -128(s0)
    li      a0, 15

    // Three stores of the same zero, one after an unrelated addi.
    li      a5, 0
    sd      a5, 15(s1)
    sd      a5, 23(s1)
    addi    a6, a4, 40
    sd      a5, 31(s1)
    li      a5, 1

    // A word store works the same way.
    li      t3, 0
    sw      t3, -32(s0)
    li      t3, 2

    // Not reported: the zero read again after the store.
    li      a0, 0
    sd      a0, 8(sp)
    mv      a1, a0
    li      a0, 3

    // Not reported: a branch back to the second store, which a0 then
    // reaches holding something else.
    li      a0, 0
    sd      a0, 8(sp)
1:  sd      a0, 16(sp)
    li      a0, 1
    bnez    a2, 1b

    // Not reported: a store through the zero rather than of it.
    li      a0, 0
    sd      a1, 0(a0)
    li      a0, 4

    // Compressed: c.sdsp names x0, c.sd does not, so the first pair is
    // one c.sdsp zero and the second would grow to a four-byte sd zero.
    .option rvc
    li      a5, 0
    sd      a5, 8(sp)
    li      a5, 1
    li      a5, 0
    sd      a5, 8(a0)
    li      a5, 1
    ret
