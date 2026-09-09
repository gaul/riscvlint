// Integration fixture for check_cond_to_branch.
//
// RISC-V has no condition flags, so the shape armlint spells `cmp #0`
// is here a comparison materialized into a register and then tested
// with beqz or bnez. Folding it deletes the comparison, which is only
// legal if the condition register is dead on *both* successors -- so
// every positive here kills it on both sides and every negative leaves
// it live on one.
//
// The kills are themselves dead definitions with nothing after them, so
// check_dead_def reports several; that is correct and an artefact of a
// synthetic sequence.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) sltu + bnez is the commonest of these in the corpus by a wide
    //    margin. The folded branch is a four-byte B-type either way.
    sltu    a5, a0, a1
    bnez    a5, .P1
    li      a5, 0
    ret
.P1:
    li      a5, 1
    ret

    // 2) The same producer with the opposite test folds to the opposite
    //    branch: not-less-than unsigned is bgeu.
    sltu    a5, a0, a1
    beqz    a5, .P2
    li      a5, 0
    ret
.P2:
    li      a5, 2
    ret

    // 3) slt is the signed pair of it.
    slt     a5, a0, a1
    bnez    a5, .P3
    li      a5, 0
    ret
.P3:
    li      a5, 3
    ret

    // 4) xor is zero exactly when the two are equal, so beqz on it is
    //    beq. sub says the same thing and folds the same way.
    xor     a5, a0, a1
    beqz    a5, .P4
    li      a5, 0
    ret
.P4:
    li      a5, 4
    ret

    // 5) seqz is `sltiu rd,rs,1`, an immediate form that folds anyway
    //    because the comparison it makes is against zero. The result is
    //    a branch on the source, which c.bnez spells in two bytes.
    seqz    a4, a0
    beqz    a4, .P5
    li      a4, 0
    ret
.P5:
    li      a4, 5
    ret

    // 6) snez is `sltu rd,x0,rs`, and has to be picked out before the
    //    general sltu rule would claim it.
    snez    a4, a0
    bnez    a4, .P6
    li      a4, 0
    ret
.P6:
    li      a4, 6
    ret

    // Negatives:
    // N1) The condition is read after the branch on the fall-through
    //     path, so the comparison cannot go.
    sltu    a5, a0, a1
    bnez    a5, .N1
    mv      a0, a5
    ret
.N1:
    li      a5, 0
    ret

    // N2) Read on the taken path instead, which is the case a linear
    //     scan cannot see and the whole reason this needs a walk.
    sltu    a5, a0, a1
    bnez    a5, .N2
    li      a5, 0
    ret
.N2:
    mv      a0, a5
    ret

    // N3) The branch tests a different register.
    sltu    a5, a0, a1
    bnez    a4, .N3
    li      a5, 0
    ret
.N3:
    li      a5, 0
    ret

    // N4) `and` says nothing about an ordering or an equality that a
    //     branch can make on its own.
    and     a5, a0, a1
    beqz    a5, .N4
    li      a5, 0
    ret
.N4:
    li      a5, 0
    ret

    // N5) A side entry on the branch: something can arrive there with
    //     the condition register set by code that is not this
    //     comparison, and the rewrite deletes the comparison.
    sltu    a5, a0, a1
    beqz    a0, .N5
.N5:
    bnez    a5, .N5b
    li      a5, 0
    ret
.N5b:
    li      a5, 0
    ret
