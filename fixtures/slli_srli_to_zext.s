// Integration fixture for check_slli_srli_to_zext.
//
// Assembled with -march=rv64gc_zba (see the .flags sidecar) so the object
// declares Zba; the gate itself is covered by the slli_add_no_zba and
// slli_add_forced_zba pair.

    .text
    .globl  _start
    .p2align 1
_start:
    // Positives:
    // 1) As Go writes it. The slli cannot compress because its rd and
    //    rs1 differ; the srli can, because a4 is inside x8-x15.
    slli    a4, a2, 32
    srli    a4, a4, 32

    // 2) Both halves compressed: four bytes either way, so the win is
    //    one instruction and one dependency rather than space.
    slli    s0, s0, 32
    srli    s0, s0, 32

    // 3) a6 is x16, which CB-format cannot name, so the srli stays four
    //    bytes while c.slli takes the register happily.
    slli    a6, a6, 32
    srli    a6, a6, 32

    // Negatives:
    // N1) A shift of 31 leaves a bit of the upper word in place.
    slli    s0, s0, 31
    srli    s0, s0, 31

    // N2) srai shifts in the sign: that is sext.w, a different rewrite,
    //     and one the base ISA already spells as addiw rd,rs,0.
    slli    s0, s0, 32
    srai    s0, s0, 32

    // N3) The srli writes elsewhere, so the shifted value survives.
    slli    a4, a2, 32
    srli    a5, a4, 32

    // N4) The srli reads a different register, so the pair is unrelated.
    slli    a4, a2, 32
    srli    a4, a5, 32

    // N5) Side entry: the branch lands on the srli, which the rewrite
    //     deletes.
    beqz    a0, .Lside
    slli    a4, a2, 32
.Lside:
    srli    a4, a4, 32

    // N6) Not adjacent.
    slli    a4, a2, 32
    addi    a0, a0, 1
    srli    a4, a4, 32

    ret
