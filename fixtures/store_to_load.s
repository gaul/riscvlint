// Integration fixture for check_store_to_load: the bytes a store just
// wrote, read straight back.
//
// The rewrite deletes nothing -- the store stays and the load becomes a
// register operation -- so unlike the folds around it there is no
// liveness question here. Every question it asks looks backward, and
// each negative below takes away one of the answers.
//
// Built for a target that declares Zba and Zbb, because two of the
// seven forms are spelled with them.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) A doubleword read straight back is a move.
    sd      a0, 8(sp)
    addi    a2, a2, 1
    ld      a1, 8(sp)

    // The four narrower forms below load into a6, which no compressed
    // form can name together with a base in x8-x15. Every extension
    // form is four bytes -- each writes a register it does not read,
    // which no compressed spelling expresses -- so a four-byte load is
    // what makes the rewrite free rather than two bytes dearer. N11
    // covers the other case.

    // 2) A word read back with lw is the sign-extension of what was
    //    stored. `sext.w` is `addiw rd,rs,0` and needs no extension.
    sw      a0, 16(a3)
    addi    a2, a2, 1
    lw      a6, 16(a3)

    // 3) The same word read back with lwu is Zba's `zext.w`.
    sw      a0, 24(a3)
    addi    a2, a2, 1
    lwu     a6, 24(a3)

    // 4) A halfword through lh is Zbb's `sext.h`.
    sh      a0, 32(a3)
    addi    a2, a2, 1
    lh      a6, 32(a3)

    // 5) A byte through lbu is `andi rd,rs,255`, which needs nothing.
    sb      a0, 40(a3)
    addi    a2, a2, 1
    lbu     a6, 40(a3)

    // 6) The base does not have to be the frame. Nothing here claims a
    //    slot went unread -- only that nothing wrote it in between --
    //    and a store that cannot be shown to miss the slot ends the
    //    window anyway.
    sd      a0, 48(a3)
    addi    a2, a2, 1
    ld      a1, 48(a3)

    // 7) A second store to a disjoint slot through the same base
    //    cannot have changed the bytes the first one wrote.
    sd      a0, 144(sp)
    sd      a4, 152(sp)
    ld      a1, 144(sp)

    // Negatives:
    // N1) The load writes the register the store read, so the value
    //     never left and the load is redundant by itself. That is
    //     check_redundant_load's finding, which the expected output
    //     shows here, and not one this check makes.
    sd      a0, 56(sp)
    addi    a2, a2, 1
    ld      a0, 56(sp)

    // N2) Storing x0 makes the rewrite `li a1,0` rather than a move --
    //     better than this one, and also not this one.
    sd      zero, 64(sp)
    addi    a2, a2, 1
    ld      a1, 64(sp)

    // N3) A store through another base may have landed on the slot.
    sd      a0, 72(sp)
    sd      a4, 0(a3)
    ld      a1, 72(sp)

    // N3b) Through the same base with the ranges overlapping, which is
    //      the half of the disjointness test that says no.
    sd      a0, 160(sp)
    sw      a4, 164(sp)
    ld      a1, 160(sp)

    // N4) The register the store read is overwritten, so there is
    //     nothing left to move from.
    sd      a0, 80(sp)
    li      a0, 3
    ld      a1, 80(sp)

    // N5) The base is overwritten, so the address the load computes is
    //     not the address the store used.
    sd      a0, 88(a4)
    addi    a4, a4, 8
    ld      a1, 88(a4)

    // N6) A narrower load of a wider store is a field extraction rather
    //     than a move, whatever the byte order happens to be.
    sd      a0, 96(sp)
    addi    a2, a2, 1
    lw      a1, 96(sp)

    // N7) A call can write the frame and can change anything.
    sd      a0, 104(sp)
    call    other
    ld      a1, 104(sp)

    // N8) Floating point is refused on both sides: the window drops a
    //     held value when its register is written, and its write scan
    //     cannot see the f registers at all.
    fsd     fa0, 112(sp)
    addi    a2, a2, 1
    fld     fa1, 112(sp)

    // N9) A side entry between the two: what follows is not reached
    //     only from here.
    sd      a0, 120(sp)
    beqz    a2, .Lside
.Lside:
    ld      a1, 120(sp)

    // N11) The assembler spelled this load in two bytes, and every
    //      extension form is four. Spending two bytes to save an access
    //      is the trade check_const_remat refuses, so this one does too.
    sw      a0, 136(sp)
    addi    a2, a2, 1
    lw      a1, 136(sp)

    // N10) The first load is this check's. The second is
    //      check_redundant_reload's, whose source is the nearer of the
    //      two, so this one stands down rather than reporting the same
    //      site twice.
    sd      a0, 128(sp)
    ld      a1, 128(sp)
    addi    a2, a2, 1
    ld      a5, 128(sp)

    ret

other:
    ret
