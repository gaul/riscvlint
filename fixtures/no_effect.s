// Integration fixture for check_no_effect: instructions that change
// nothing and are not `nop`. The first block is every four-byte form the
// check knows, the second the things that look like one and are not,
// the third the compressed spellings, written as raw halfwords because
// an assembler will not spell a hint for you.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Reported.
    addi    a0, a0, 0          // mv a0,a0
    addi    sp, sp, 0          // MultiPush/MultiPop with nothing to push
    ori     t6, t6, 0          // the tail of V8's fixed address load
    xori    a1, a1, 0
    andi    a2, a2, -1
    slli    a3, a3, 0
    srai    a4, a4, 0
    add     a5, a5, zero
    sub     a6, a6, zero
    or      a7, a7, a7
    lui     zero, 0x54321      // V8's stop code, the word after ebreak
    auipc   zero, 0            // V8's constant pool guard; Zicfilp's lpad,
                               // reported because rv64gc lacks Zicfilp
    fsgnj.d fa0, fa0, fa0      // fmv.d fa0,fa0

    // Not reported: the canonical nop, a W form (it sign-extends), the
    // two assigned hint families, and operations that do something.
    nop
    addiw   a0, a0, 0
    ori     zero, a0, 0        // prefetch.i 0(a0)
    add     zero, zero, t0     // ntl.all
    addi    a0, a0, 1
    add     a0, a0, a1

    // Compressed: c.mv a0,a0; c.addi a1,0; c.andi a0,-1; c.li zero,5;
    // c.slli a0,0 are reported; c.nop and c.add zero,t0 (ntl.all) are
    // not.
    .2byte  0x852a
    .2byte  0x0581
    .2byte  0x997d
    .2byte  0x4015
    .2byte  0x0502
    .2byte  0x0001
    .2byte  0x9016
    ret
