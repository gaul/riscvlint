// Integration fixture for check_redundant_load: a load whose
// destination already holds what it would load.
//
// This is the case check_redundant_reload and check_store_to_load both
// refuse -- they rewrite a load into a move, and there is no move to
// make when the value never left the register. The instruction goes
// instead, which makes it the one window check whose finding is always
// worth its own encoding in bytes.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) Stored and read straight back into the register it came from.
    //    A doubleword is the whole register, so the load restores what
    //    is already there.
    sd      a0, 8(sp)
    addi    a2, a2, 1
    ld      a0, 8(sp)

    // 2) The same load twice. The second recomputes the first's value
    //    from bytes nothing has touched.
    ld      a0, 16(a3)
    addi    a2, a2, 1
    ld      a0, 16(a3)

    // 3) Narrower is exact for load-then-load whatever the width, since
    //    both loads extend the same bytes the same way.
    lbu     a0, 24(a3)
    addi    a2, a2, 1
    lbu     a0, 24(a3)

    // 4) A store to a disjoint slot through the same base cannot have
    //    changed what the first load read.
    lw      a0, 32(a3)
    sw      a4, 40(a3)
    lw      a0, 32(a3)

    // Negatives:
    // N1) Stored and read back at half the width. `lw` leaves a0
    //     sign-extended from bit 31, which is a0 again only if it
    //     already was, and nothing in the pair says whether it was.
    sw      a0, 48(sp)
    addi    a2, a2, 1
    lw      a0, 48(sp)

    // N2) lb and lbu are the same width and not the same value.
    lb      a0, 3(a3)
    addi    a2, a2, 1
    lbu     a0, 3(a3)

    // N3) The register is overwritten in between, so the load is doing
    //     work after all. The `mv` is then a dead definition, which is
    //     a different check's finding and is why one appears below.
    ld      a0, 56(a3)
    mv      a0, a1
    ld      a0, 56(a3)

    // N4) A store that lands on the bytes. The value in a0 is stale
    //     even though the address is the same.
    ld      a0, 64(a3)
    sw      a4, 64(a3)
    ld      a0, 64(a3)

    // N5) The base is overwritten, so the second load reads somewhere
    //     else entirely.
    ld      a0, 72(a4)
    addi    a4, a4, 8
    ld      a0, 72(a4)

    // N6) A call can write the frame and can change anything.
    ld      a0, 80(sp)
    call    other
    ld      a0, 80(sp)

    // N7) A side entry between the two: what follows is not reached
    //     only from here.
    ld      a0, 88(sp)
    beqz    a2, .Lside
.Lside:
    ld      a0, 88(sp)

    // N8) Floating point is refused: the window drops a held value when
    //     the register holding it is written, and its write scan cannot
    //     see the f registers at all.
    fld     fa0, 96(sp)
    addi    a2, a2, 1
    fld     fa0, 96(sp)

    ret

other:
    ret
