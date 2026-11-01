// Integration fixture for check_const_for_imm: a constant loaded only
// for operations whose immediate forms would take it. Each block ends
// by storing what it computed and redefining the constant's register,
// which is what proves the constant dead.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Maglev's overflow-checked add of 1, without the deopt branch.
    li      a3, 1
    add     t2, a2, a3
    addw    a4, a2, a3
    sd      t2, 0(sp)
    sd      a4, 8(sp)
    li      a3, 5

    // Subtraction adds the negation, and a shift takes the low bits.
    li      a1, 5
    sub     a0, a0, a1
    sll     a2, a2, a1
    sd      a0, 16(sp)
    sd      a2, 24(sp)
    li      a1, 0

    // An and that overwrites the constant's register: dead at once.
    li      a3, 7
    and     a3, a2, a3
    sd      a3, 32(sp)

    // Not reported: k - rx has no immediate form.
    li      a1, 5
    sub     a0, a1, a0
    sd      a0, 40(sp)
    li      a1, 0

    // Not reported: the constant is stored as well.
    li      a3, 1
    add     t2, a2, a3
    sd      a3, 48(sp)
    sd      t2, 56(sp)
    li      a3, 0

    // Compressed: c.add becomes c.addi.
    .option rvc
    li      a5, 3
    add     a0, a0, a5
    sd      a0, 64(sp)
    li      a5, 0
    ret
