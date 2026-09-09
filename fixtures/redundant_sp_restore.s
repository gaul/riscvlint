// Integration fixture for check_redundant_sp_restore.
//
// The prologue is spelled the way clang spells it -- `addi s0,sp,K`,
// which the assembler compresses to c.addi4spn whenever K fits its
// scaled field and s0 is in range. The first sequence relies on that;
// the last one forces the four-byte spelling with an offset c.addi4spn
// cannot express, so both decoder paths are exercised end to end.
//
// Two findings here come from other checks and are not noise to be
// suppressed. The `call other` in sequence 2 is a foldable call pair,
// and sequence 4's prologue is a dead definition because the reload two
// instructions later overwrites s0 before anything reads it.
//
// What this fixture cannot show is the composition the corpus has: once
// the restore is deleted, a prologue whose only reader it was becomes a
// dead definition too, and the existing check reports it. Here the
// prologue is still read by the restore at the time the checks run, so
// only one of the two findings exists at a time.

    .text
    .globl  _start
    .p2align 1
_start:

// 1) The ordinary shape. Nothing between the two touches sp, so the
//    restore assigns sp the value it already holds.
    addi    sp, sp, -48
    sd      ra, 40(sp)
    addi    s0, sp, 48
    nop
    addi    sp, s0, -48
    ld      ra, 40(sp)
    addi    sp, sp, 48
    ret

// 2) With a call in the middle, which is what makes this check need the
//    prologue carried forward rather than a region-local window: every
//    frame-pointer function in the corpus has calls between the two.
    addi    sp, sp, -32
    addi    s0, sp, 32
    call    other
    addi    sp, s0, -32
    addi    sp, sp, 32
    ret

// 3) Negative: sp moves in between, so the frame is not where the
//    prologue left it and the restore is doing real work. This is the
//    alloca and VLA case.
    addi    sp, sp, -32
    addi    s0, sp, 32
    addi    sp, sp, -16
    addi    sp, s0, -32
    ret

// 4) Negative: s0 is reloaded before the restore reads it.
    addi    sp, sp, -32
    addi    s0, sp, 32
    ld      s0, 0(sp)
    addi    sp, s0, -32
    ret

// 5) Negative: the displacements are not opposites, so the restore
//    computes a different address on purpose.
    addi    sp, sp, -32
    addi    s0, sp, 32
    addi    sp, s0, -16
    ret

// 6) Negative: a shared epilogue. Something branches to the restore, so
//    it can be reached from code the linear scan has not walked yet,
//    and that code may have moved sp.
    addi    sp, sp, -32
    addi    s0, sp, 32
    beqz    a0, .Lshared
    nop
.Lshared:
    addi    sp, s0, -32
    ret

// 7) A prologue whose offset c.addi4spn cannot encode -- its field is a
//    multiple of four below 1024 -- so the setup stays four bytes and
//    the four-byte decode path is what has to match it.
    addi    sp, sp, -2048
    addi    s0, sp, 2044
    nop
    addi    sp, s0, -2044
    ret

other:
    ret
