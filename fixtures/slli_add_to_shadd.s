// Integration fixture for check_slli_add_to_shadd.
//
// Assembled with -march=rv64gc_zba (see the .flags sidecar) so the object
// declares Zba in Tag_RISCV_arch. The companion fixture
// slli_add_no_zba.s is the same shape without it, and must report
// nothing.

    .text
    .globl  _start
    .p2align 1
_start:
    // Positives:
    // 1) Canonical, both halves in their 4-byte spelling: 8 bytes down
    //    to 4. slli's rd differs from its rs1, so it cannot compress.
    slli    s0, t2, 2
    add     s0, s0, t2

    // 2) Both halves compressed, which is the commonest form in real
    //    code: 4 bytes either way, so the win is one instruction and one
    //    dependency rather than space.
    slli    s0, s0, 2
    add     s0, s0, t2

    // 3) A shift of 1, with the add's operands the other way round --
    //    add commutes, so this is still sh1add.
    slli    s0, t2, 1
    add     s0, t2, s0

    // 4) A shift of 3, mixed spellings: 6 bytes down to 4.
    slli    s0, t2, 3
    add     s0, s0, t2

    // Negatives:
    // N1) A shift of 4 has no shNadd.
    slli    s0, t2, 4
    add     s0, s0, t2

    // N2) add rd,rd,rd doubles the shifted value; that is a wider shift,
    //     not a shift-add.
    slli    s0, s0, 2
    add     s0, s0, s0

    // N3) The add writes elsewhere, so the shifted value survives and
    //     folding would drop it. Needs liveness; not claimed here.
    slli    s0, t2, 2
    add     a5, s0, t2

    // N4) sub shares add's opcode and funct3.
    slli    s0, t2, 2
    sub     s0, s0, t2

    // N5) Side entry: the branch lands on the add, which the rewrite
    //     deletes.
    beqz    a0, .Lside
    slli    s0, t2, 2
.Lside:
    add     s0, s0, t2

    // N6) Not adjacent.
    slli    s0, t2, 2
    addi    a0, a0, 1
    add     s0, s0, t2

    ret
