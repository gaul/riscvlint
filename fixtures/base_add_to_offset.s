// Integration fixture for check_base_add_to_offset.
//
// Assembled with Zcb (see the .flags sidecar) so that the byte and
// halfword compressed accesses are available: capstone decodes them
// whenever the C extension is on, and the corpus contains 141,746 of
// them, so they belong in the end-to-end coverage.
//
// Every sequence that needs the producer's register dead afterwards
// kills it explicitly with `li`. Those kills are themselves dead
// definitions with nothing after them, so check_dead_def reports some of
// them; that is correct and an artefact of a synthetic sequence.
//
// Two negatives are written in deliberately awkward spellings. A store
// to sp normally assembles to c.sdsp, which is a quadrant-2 form
// rv_decode_mem does not claim at all -- so a natural-looking prologue
// would be rejected before the sp test it is meant to exercise ever ran.
// The unaligned offset forces the four-byte spelling instead.
//
// That omission is about the access being *read*. Sizing the access the
// fold would *write* is a different question, and rv_mem_encoded_size
// does model the quadrant-2 forms -- see sequence 3, where the folded
// store lands on sp and c.sdsp spells it in two bytes.

    .text
    .globl  _start
    .p2align 1
_start:
    // Positives:
    // 1) The load overwrites its own base, so the addi's value is dead
    //    by construction and no liveness query is needed. This is about
    //    two thirds of the corpus population -- 67% of the C++ findings,
    //    72% of the Rust ones, 68% of the Go ones -- so the liveness
    //    walk still earns the remaining third.
    addi    a5, a1, 17
    lb      a5, 0(a5)

    // 2) Both halves compressed, and the folded offset still fits
    //    c.sd's field: four bytes down to two.
    addi    a5, a5, 8
    sd      a4, 0(a5)
    li      a5, 0

    // 3) c.addi4spn, folding onto sp. A quadrant-0 form's three-bit
    //    register field cannot name sp, but c.sdsp can: the store keeps
    //    its two bytes and the addi's two go. Reporting this as 4 -> 4
    //    on the strength of the quadrant-0 rule alone would understate
    //    it, which is why the size model carries quadrant 2.
    addi    a5, sp, 16
    sd      a4, 8(a5)
    li      a5, 0

    // 4) A move is an addition of zero.
    mv      a5, a4
    ld      a3, 8(a5)
    li      a5, 0

    // 5) Zcb, with the folded offset still inside its two-bit field.
    addi    a5, a0, 1
    lbu     a4, 2(a5)
    li      a5, 0

    // 6) A floating-point access folds the same way. Its data register
    //    is in the other file, so it can never alias the base.
    addi    a5, a0, 8
    flw     fa0, 12(a5)
    li      a5, 0

    // 7) The register is killed on both sides of a branch, which is the
    //    case a linear scan cannot decide.
    addi    a5, a0, 24
    ld      a4, 0(a5)
    beqz    a4, .Lboth
    li      a5, 1
    ret
.Lboth:
    li      a5, 2
    ret

    // Negatives:
    // N1) The store's source is the addi's destination, so that register
    //     is read for the data as well as the base.
    addi    a5, a0, 8
    sd      a5, 0(a5)
    li      a5, 0

    // N2) 2047 + 8 does not fit the 12-bit immediate.
    addi    a5, a0, 2047
    ld      a4, 8(a5)
    li      a5, 0

    // N3) sp as the destination. Written as a four-byte store with an
    //     unaligned offset so the site is rejected for that reason
    //     rather than because c.sdsp is a form the decoder skips.
    addi    sp, a0, 16
    sd      ra, 7(sp)

    // N4) A second access reads the computed address.
    addi    a5, a0, 8
    ld      a4, 0(a5)
    ld      a3, 8(a5)

    // N5) A branch lands on the access, which the rewrite changes the
    //     meaning of, having deleted the addi before it.
    beqz    a0, .Lside
    addi    a5, a0, 8
.Lside:
    ld      a4, 0(a5)
    li      a5, 0

    // N6) Not adjacent.
    addi    a5, a0, 8
    nop
    ld      a4, 0(a5)
    li      a5, 0

    // N7) addiw sign-extends from 32 bits, so its result is not
    //     a0 + 8 in general and there is nothing to fold.
    addiw   a5, a0, 8
    ld      a4, 0(a5)
    li      a5, 0

    // N8) A return leaves which registers are observable an ABI
    //     question, so the walk answers UNKNOWN -- and UNKNOWN is not a
    //     finding.
    addi    a5, a0, 8
    ld      a4, 0(a5)
    ret
