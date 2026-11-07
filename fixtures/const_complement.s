// Integration fixture for check_const_complement: a constant built only
// for and, or and xor whose complement li builds in fewer instructions,
// which andn, orn and xnor then take -- and the reverse.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) SpiderMonkey's nursery check: the GC chunk mask, 0x7ffffff00000,
    //    takes three instructions however it is built, and its
    //    complement two, a rotated lui; the and overwrites the mask.
    lui     t4, 0x8000
    addiw   t4, t4, -1
    slli    t4, t4, 20
    and     t4, t4, a2
    ld      t4, 0(t4)
    sd      t4, 0(sp)

    // 2) The reverse: the mask built for andn is its complement built for
    //    and.
    lui     t5, 0x8000
    addiw   t5, t5, -1
    slli    t5, t5, 20
    andn    a0, a1, t5
    sd      a0, 8(sp)
    li      t5, 0

    // 3) or becomes orn.
    lui     t6, 0x8000
    addiw   t6, t6, -1
    slli    t6, t6, 20
    or      a3, a3, t6
    sd      a3, 16(sp)
    li      t6, 0

    // 4) Two xors of one mask become two xnors.
    lui     t3, 0x8000
    addiw   t3, t3, -1
    slli    t3, t3, 20
    xor     a4, a4, t3
    xor     a5, a5, t3
    sd      a4, 24(sp)
    sd      a5, 32(sp)
    li      t3, 0

    // 5) Not reported: the mask is stored after the and, so it is live.
    lui     t2, 0x8000
    addiw   t2, t2, -1
    slli    t2, t2, 20
    and     a6, a6, t2
    sd      t2, 40(sp)

    // 6) Not reported: the and is a c.and, two bytes, and andn has no
    //    compressed form, so the site would grow.
    .option rvc
    lui     s1, 0x8000
    addiw   s1, s1, -1
    slli    s1, s1, 20
    and     a0, a0, s1
    sd      a0, 48(sp)
    li      s1, 0
    ret
