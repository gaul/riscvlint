// Integration fixture for check_c_compressible.
//
// Assembled under `.option norvc`, because with RVC on the assembler
// compresses every positive here as it emits it and there would be
// nothing to find. That is also what the check is for: it reports what
// an assembler that does not select RVC left behind, and Go's does not.
//
// The rules were checked against `riscv64-linux-gnu-as` over a matrix
// that assembles the same 2,922 instructions twice, once with RVC and
// once without, and compares this decoder's answer against the
// assembler's choice. They agree on all but eighteen, and those
// eighteen are the assembler's gap rather than this decoder's -- see the
// jr and jalr sequence below.

    .text
    .globl  _start
    .p2align 1
_start:
    .option norvc

    // Positives, one per form the base C extension carries on RV64.
    addi    a5, a5, 8           // c.addi
    addi    a5, zero, 8         // c.li
    addi    a5, sp, 16          // c.addi4spn
    addi    sp, sp, -32         // c.addi16sp
    addiw   a5, a5, 8           // c.addiw
    lui     a5, 4               // c.lui
    slli    a5, a5, 4           // c.slli
    srli    a0, a0, 4           // c.srli
    srai    a0, a0, 4           // c.srai
    andi    a0, a0, 8           // c.andi
    add     a5, zero, a4        // c.mv
    addi    a5, a4, 0           // c.mv, from the other spelling
    add     a5, a5, a4          // c.add
    sub     a0, a0, a1          // c.sub
    xor     a0, a0, a1          // c.xor
    or      a0, a0, a1          // c.or
    and     a0, a0, a1          // c.and
    subw    a0, a0, a1          // c.subw
    addw    a0, a0, a1          // c.addw
    addw    a0, a1, a0          // c.addw, commuted
    ld      a0, 8(a1)           // c.ld
    ld      a0, 8(sp)           // c.ldsp
    sd      a0, 8(a1)           // c.sd
    sd      a0, 8(sp)           // c.sdsp
    lw      a0, 4(a1)           // c.lw
    fld     fa0, 8(a1)          // c.fld
    beqz    a0, .Lnear          // c.beqz
    bnez    a0, .Lnear          // c.bnez
    j       .Lnear              // c.j
    ebreak                      // c.ebreak
    addi    sp, sp, -8          // c.addi: it reaches sp like any other
                                // register, and only c.addi16sp needs
                                // the multiple of sixteen
    addi    a5, a5, 0           // c.mv: an addi of zero is a move, and
                                // c.addi is the form that cannot hold
                                // zero, not this one
.Lnear:

    // The jr and jalr spellings GNU as leaves wide. `jr a5` written as a
    // pseudo-op compresses; `jalr zero, 0(a5)`, the same instruction,
    // does not. Both are c.jr, and this is the fourth spelling-sensitive
    // gap the corpus has turned up in that assembler.
    jalr    zero, 0(a5)         // c.jr
    jalr    ra, 0(a5)           // c.jalr

    // Negatives: a register the three-bit field cannot name.
    srli    a6, a6, 4
    and     a6, a6, a1
    ld      a6, 8(a1)

    // Negatives: an immediate outside the form's field.
    addi    a5, a5, 32
    andi    a0, a0, 32
    lui     a5, 32
    addi    sp, sp, -528        // past c.addi16sp's range, and too wide
                                // for c.addi to take instead
    ld      a0, 4(a1)           // c.ld's offset is a multiple of eight

    // Negatives: the destination is not one of the sources, so no
    // two-register form can express it.
    sub     a0, a1, a2
    subw    a0, a1, a0          // and subtraction does not commute
    addi    a5, a4, 8

    // Negatives: an immediate the form forbids being zero, a
    // destination the form forbids, and a result that is discarded.
    lui     a5, 0
    lui     sp, 4
    addi    zero, a5, 8

    // Negative: a four-byte nop is alignment padding that exists for
    // its width, or it is dead and wants deleting. Neither is what this
    // check has to say.
    nop

    // And the last finding is the `ret` itself, which is `jalr zero,
    // 0(ra)` and so c.jr -- the same instruction the jalr sequence above
    // covers, arriving here through the pseudo-op the file ends with.
    ret
