// Integration fixture for check_comp_remat: a computation whose result
// is still live in a register, which is `mv rd,rprev` -- or a deletion
// where the register it is about to write already holds it.
//
// This is check_const_remat's question widened from `li` to everything
// that writes one register as a function of registers, and the table it
// reads carries the rule the constant table does not need: a record
// dies when a *source* is written, not only when its own register is.
// Most of the sequences below are that rule being asked in one form or
// another.
//
// Two populations were sized separately and are one check: the frame
// address (`addi rd,sp,K` or `addi rd,s0,-K`), which is most of it, and
// ordinary arithmetic. Nothing in the check tells them apart.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) A frame address computed twice with only arithmetic between.
    //    a3 is not a register c.addi4spn can name, so the duplicate is
    //    four bytes; c.mv names any two non-zero registers, so the
    //    rewrite is two.
    addi    a0, s0, -0x70
    addi    a2, a2, 1
    addi    a3, s0, -0x70

    // 2) The register the instruction is about to write already holds
    //    the value, so it goes away rather than becoming a move -- four
    //    bytes rather than two.
    slli    a4, a2, 32
    srli    a5, a4, 32
    slli    a4, a2, 32

    // 3) Ordinary arithmetic, which is the other population. Both
    //    halves are four bytes and neither operand moves.
    srliw   a3, a5, 23
    addi    a2, a2, 1
    srliw   a2, a5, 23

    // 4) A conditional branch over the second does not matter: the
    //    second is reached by falling through, so everything the record
    //    saw ran. If it could also be reached by the branch it would be
    //    a side entry, which N8 is.
    addi    a0, s0, -0x60
    beqz    a2, .Lover
    addi    a3, s0, -0x60
.Lover:

    // 5) A vector store through an address the decoder cannot follow
    //    takes every claim about a place and no claim about a register.
    //    This is the whole difference between the memory window's
    //    lifetime and the computation table's, and it is 145 of
    //    ripgrep's 646 sites.
    addi    a3, s0, -0x50
    vsetivli zero, 2, e64, m1, ta, ma
    vse64.v v8, (a3)
    addi    a0, s0, -0x50

    // 6) So does a store to a place we can name. A computation is a
    //    claim about a register, and no store can reach one.
    addi    a0, s0, -0x40
    sd      a4, 0(a1)
    addi    a3, s0, -0x40

    // Negatives:
    // N1) A match already spelled in two bytes: c.addi4spn can name both
    //     destinations, so c.mv would save nothing and would trade an
    //     instruction that depends on nothing for one that depends on
    //     another register. 9,622 of the 39,274 sites in the corpus.
    addi    a0, sp, 16
    addi    a2, a2, 1
    addi    a1, sp, 16

    // N2) A def that wrote one of its own sources leaves nothing that
    //     can name the value it read, so it is not recorded at all.
    //     Without the rule every later `add rd,a0,a1` matches it. This
    //     was a false positive in the probe before it was a rule here.
    add     a0, a0, a1
    addi    a2, a2, 1
    add     a3, a0, a1

    // N3) sp holds what the ABI says it holds, and this shape --
    //     `addi sp,s0,-K` over a frame that never moved -- is
    //     check_redundant_sp_restore's finding, which says why. 27 of
    //     ripgrep's 646 probe sites write one of the three, and 26 of
    //     those are already reported as that restore.
    addi    sp, s0, -0x70
    addi    a2, a2, 1
    addi    sp, s0, -0x70

    // N4) The source moved, so the second computes a different address.
    addi    a0, s0, -0x30
    addi    s0, s0, 8
    addi    a3, s0, -0x30

    // N5) The register holding the earlier result is overwritten, so
    //     there is nothing left to move from.
    addi    a0, s0, -0x28
    li      a0, 0
    addi    a3, s0, -0x28

    // N6) A different immediate is a different computation, and a
    //     different mnemonic over the same operands is too: srliw is a
    //     32-bit shift and srli is a 64-bit one.
    addi    a0, s0, -0x20
    addi    a3, s0, -0x18
    srliw   a3, a5, 21
    srli    a2, a5, 21

    // N7) A call can write any caller-saved register.
    addi    a0, s0, -0x10
    call    other
    addi    a3, s0, -0x10

    // N8) A side entry on the second: what follows is not reached only
    //     from the first.
    addi    a0, s0, -0x8
    beqz    a2, .Lside
.Lside:
    addi    a3, s0, -0x8

    // N9) `mv` is move coalescing, measured at 192 of 73,017 and
    //     rejected, and `li` is check_const_remat's, which keys on the
    //     value rather than on the operands that made it. Both are
    //     refused here; the `li` pair is reported by that check.
    .option norvc
    mv      a0, a1
    addi    a2, a2, 1
    mv      a3, a1
    li      a0, 1234
    addi    a2, a2, 1
    li      a3, 1234
    .option rvc

    // N10) The f registers are the other register file, which this
    //      table does not follow, and `fmv.x.d` writes a general
    //      register from one of them.
    fmv.x.d a0, fa0
    addi    a2, a2, 1
    fmv.x.d a3, fa0

    ret

other:
    ret
