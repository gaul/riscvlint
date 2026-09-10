// Integration fixture for check_silent_store: a store of bytes the slot
// already holds.
//
// The dead store read from the other end. check_dead_store deletes the
// first of two stores and needs the overwrite to be certain; this
// deletes the second and does not, because putting back what is already
// there is a no-op on every path that reaches it. The two flags the
// window keeps say exactly that, and the cases below are mostly about
// which of them survives what.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) A slot loaded and written straight back. The store puts back
    //    what it just read.
    ld      a0, 8(sp)
    addi    a2, a2, 1
    sd      a0, 8(sp)

    // 2) Stored, tested, and stored again from the path that falls
    //    through. The branch is what keeps check_dead_store out: on the
    //    taken path the second store never happens, so the first is not
    //    dead. Deleting the second is sound either way. 5,622 of the
    //    corpus population is this shape and all but 169 of it is Go.
    sd      a0, 16(sp)
    beqz    a2, .Lskip
    sd      a0, 16(sp)
.Lskip:

    // 3) The record's kind is not the store's, and this is the one
    //    window check where that must not matter. `lwu` says what went
    //    into the register; the bytes in the slot do not record how
    //    they were read.
    lwu     a0, 24(sp)
    addi    a2, a2, 1
    sw      a0, 24(sp)

    // 4) A store to a disjoint slot through the same base cannot have
    //    changed what the load read, so the value is still held.
    ld      a0, 32(sp)
    sd      a4, 48(sp)
    sd      a0, 32(sp)

    // 5) Zero is a value like any other here. The checks that rewrite a
    //    load refuse x0 because their rewrite becomes `li rd,0` rather
    //    than a move; this one deletes, so there is nothing to refuse.
    sd      zero, 56(sp)
    beqz    a2, .Lskip2
    sd      zero, 56(sp)
.Lskip2:

    // 6) A load through another base between the two stores. It may be
    //    the read that keeps the first store alive, so `unread` goes and
    //    check_dead_store declines; it cannot have changed the slot, so
    //    the value is still held and this one does not. That is the
    //    third way the two flags part, worth 28 sites of the corpus.
    sd      a0, 60(sp)
    ld      a1, 0(a3)
    sd      a0, 60(sp)

    // Negatives:
    // N1) Two stores with nothing between them: check_dead_store's
    //     finding, which deletes the other one of the pair for the same
    //     saving. One rewrite per site, so this check stands down.
    sd      a0, 64(sp)
    addi    a2, a2, 1
    sd      a0, 64(sp)

    // N2) A different register is a different value.
    ld      a0, 72(sp)
    addi    a2, a2, 1
    sd      a4, 72(sp)

    // N3) Half the width. The low four bytes of a0 are in fact the low
    //     four bytes of the slot, but the corpus never needed the rule
    //     and an untested rule is worth less than the sites it adds.
    ld      a0, 80(sp)
    addi    a2, a2, 1
    sw      a0, 80(sp)

    // N4) A store that lands on the bytes in between. What a0 holds is
    //     no longer what is in the slot.
    ld      a0, 88(sp)
    sw      a4, 88(sp)
    sd      a0, 88(sp)

    // N5) The register is overwritten, so the store writes something
    //     else.
    ld      a0, 96(sp)
    mv      a0, a1
    sd      a0, 96(sp)

    // N6) The base is overwritten, so the store lands somewhere else.
    ld      a0, 104(a4)
    addi    a4, a4, 8
    sd      a0, 104(a4)

    // N7) A call can write the frame.
    ld      a0, 112(sp)
    call    other
    sd      a0, 112(sp)

    // N8) A side entry between the two: the store is reached from
    //     somewhere the load is not.
    ld      a0, 120(sp)
    beqz    a2, .Lside
.Lside:
    sd      a0, 120(sp)

    // N9) A heap address may alias anything and may be a device
    //     register that has to be written whatever it holds. Frame
    //     slots only, which is the dead store's restriction for the
    //     dead store's reason; it costs 319 of the 7,330 sites.
    ld      a0, 8(a1)
    addi    a2, a2, 1
    sd      a0, 8(a1)

    // N11) A load into x0 puts nothing anywhere, so a record it armed
    //      says only that x0 holds what is at the address, which is not
    //      true. Storing x0 over a slot an earlier *store* of x0 armed
    //      is a finding -- positive 5 -- and this is not. The corpus has
    //      no site either way; the rule is here because the two cases
    //      look identical in the record.
    ld      zero, 136(sp)
    addi    a2, a2, 1
    sd      zero, 136(sp)

    // N10) Floating point is refused on both sides: the window's write
    //      scan cannot see the f registers, so an f-register claim
    //      would never be taken away.
    fld     fa0, 128(sp)
    addi    a2, a2, 1
    fsd     fa0, 128(sp)

    ret

other:
    ret
