// Integration fixture for check_branch_over_jump and
// check_transfer_to_next, which are one shape read two ways: a relative
// transfer that goes where control would have gone anyway.
//
// `beqz a0,L` + `j X` + `L:` is `bnez a0,X` with the jump gone. The
// shape is 128,361 sites in the corpus and almost all of it is the
// standard way to spell a conditional branch out of range -- the branch
// reaches +/-4KB and the jump reaches +/-1MB -- so the whole question
// is whether the jump's target is one the branch could have reached on
// its own. 5,362 are, and the ones below stand in for the four
// encodings that produces.
//
// Every distance here is arranged with .space, because that is the only
// part of the shape that decides anything.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives for the fold:
    // 1) A four-byte branch over a four-byte jump. Two registers means
    //    the branch cannot compress, and a target past c.j's +/-2KB
    //    means the jump cannot either. The inverted branch is four
    //    bytes, so the jump's four are the saving.
    bltu    a0, a1, 1f
    j       mid
1:  ret

    // 2) A four-byte branch over a two-byte jump: the saving is two.
    bltu    a0, a1, 2f
    j       near
2:  ret

    // 3) Both halves two bytes, with the new target inside c.bnez's
    //    +/-256, so the pair becomes one two-byte branch.
    beqz    a0, 3f
    j       near2
3:  ret

    // 4) The same shape with the new target outside that range, so the
    //    branch has to grow to four and the rewrite is four bytes for
    //    four. It still removes an instruction and a taken branch, so
    //    it is reported and the finding says so. 73 sites.
    beqz    a0, 14f
    j       near
14: ret

    // Negatives for the fold:
    // N1) The jump's target is past the branch's +/-4KB. This is what
    //     the shape is for, and 122,999 of the 128,361 sites.
    beqz    a0, 4f
    j       faraway
4:  ret

    // N2) Something branches to the jump, which loses its transfer if
    //     the jump goes.
    beqz    a0, 5f
.Lentry:
    j       near
5:  ret
    beqz    a1, .Lentry

    // N3) The branch does not clear the jump: something else sits
    //     between the jump and where the branch lands.
    beqz    a0, 6f
    j       near
    nop
6:  ret

    // N4) `jal ra,X` rather than `j X`. Deleting it would stop writing
    //     the link register, which is a liveness question this does not
    //     ask.
    beqz    a0, 7f
    jal     ra, near
7:  ret

    // N5) The jump goes exactly where the branch goes, so both paths
    //     already meet. The pair is dead rather than foldable, and the
    //     jump is the other check's finding below.
    beqz    a0, 8f
    j       8f
8:  ret

    // Positives for the delete: a transfer to the instruction that
    // follows it, in each of the four spellings it takes.
    j       9f
9:  ret
    beqz    a1, 10f
10: ret
    .option norvc
    j       11f
11: ret
    beq     a2, a3, 12f
12: ret

    // N6) `jal ra,X` again: it writes the link register, which makes it
    //     a PC materialization rather than a no-op. 16 sites in
    //     Firefox, and none anywhere else.
    jal     ra, 13f
13: ret
    .option rvc

    // N7) A jump anywhere else is a jump.
    j       near

near2:
    ret

    .space 200
near:
    ret
    .space 2400
mid:
    ret
    .space 4096
faraway:
    ret
