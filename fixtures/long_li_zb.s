// Integration fixture for check_long_li under Zba, Zbb and Zbs: chains
// spelled the way RV64I needs them, for values the extensions build in
// fewer instructions, and chains already spelled the extensions' way.
// The stores exist so that the chains have a reader.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) A single bit: li + slli is bseti.
    li      a0, 1
    slli    a0, a0, 40
    sd      a0, 0(sp)

    // 2) 0x810d9695, a uint32 that is not an int32: lui + addiw of its
    //    sign extension, then zext.w.
    lui     a1, 129
    addiw   a1, a1, 217
    slli    a1, a1, 12
    addi    a1, a1, 1685
    sd      a1, 8(sp)

    // 3) 0x19f228913, five times an int32: sh2add.
    lui     a2, 415
    addiw   a2, a2, 553
    slli    a2, a2, 12
    addi    a2, a2, -1773
    sd      a2, 16(sp)

    // 4) 0x154955f7f: slli.uw clears the bits lui's sign extension set.
    lui     a3, 170
    addiw   a3, a3, 1195
    slli    a3, a3, 13
    addi    a3, a3, -129
    sd      a3, 24(sp)

    // 5) 0xbffffffffd956be9, seven instructions in RV64I: lui + addiw of
    //    the low half, and bclri for the one zero above it.
    li      a4, -1
    slli    a4, a4, 37
    addi    a4, a4, -1
    slli    a4, a4, 13
    addi    a4, a4, -1705
    slli    a4, a4, 12
    addi    a4, a4, -1047
    sd      a4, 32(sp)

    // 6) 0xffe7ffffffffffff: li -4 rotated, which LLVM's planner finds;
    //    two zeros, so not bclri.
    li      a5, -3
    slli    a5, a5, 51
    addi    a5, a5, -1
    sd      a5, 40(sp)

    // 7) 0xffff8000000fffff, the complement of SpiderMonkey's GC chunk
    //    mask: lui rotated, which LLVM's planner does not try.
    li      a6, -1
    slli    a6, a6, 37
    srli    a6, a6, 17
    not     a6, a6
    sd      a6, 48(sp)

    // 8) Already the extensions' spellings, and not reported: the rotated
    //    lui, and bseti starting a chain that addi finishes.
    lui     a7, 0xf8000
    rori    a7, a7, 44
    sd      a7, 56(sp)
    bseti   t0, zero, 40
    addi    t0, t0, 5
    sd      t0, 64(sp)
    ret
