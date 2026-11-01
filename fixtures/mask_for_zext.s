// Integration fixture for check_mask_for_zext: a mask of the low bits
// built in two instructions or more and then only anded with, which
// zext.h, zext.w or a shift pair does alone. Assembled with
// -march=rv64gc_zba_zbb (see the .flags sidecar) so the object declares
// both extensions. Each block stores what it computed and then
// redefines the mask's register, which proves the mask dead.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Maglev's 0xffff, ahead of a halfword store.
    lui     t2, 0x10
    addiw   t2, t2, -1
    and     a0, t1, t2
    sh      a0, 15(a1)
    li      t2, 0

    // 0xffffffff in three instructions: zext.w.
    li      t2, 1
    slli    t2, t2, 32
    addi    t2, t2, -1
    and     a2, a2, t2
    sd      a2, 0(sp)
    li      t2, 0

    // Twenty bits: no extension does it, the shift pair does.
    lui     t2, 0x100
    addiw   t2, t2, -1
    and     a3, a4, t2
    sd      a3, 8(sp)
    li      t2, 0

    // Not reported: 0xfffe is not a mask.
    lui     t2, 0x10
    addiw   t2, t2, -2
    and     a0, t1, t2
    sd      a0, 16(sp)
    li      t2, 0

    // Not reported: the mask is stored as well.
    lui     t2, 0x10
    addiw   t2, t2, -1
    and     a0, t1, t2
    sd      t2, 24(sp)
    sd      a0, 32(sp)
    ret
