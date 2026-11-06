// Integration fixture for check_scratch_call_to_jal: `auipc rx,X` +
// `jalr ra,Y(rx)`, the call pair with a scratch register carrying the
// address, folded to `jal ra,target` where the target is inside jal's
// reach and rx is dead both at the callee and at the return address.
// It is check_call_pair_to_jal's shape with the one difference that
// decides every site below: that pair's jalr overwrites the auipc's
// register, and this one's leaves it holding the address.
//
// Every target is an explicit displacement from the auipc, so nothing
// is relocated, and `.option norvc` keeps each instruction four bytes.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) Folds: t4 is written first at the return (li t4,0) and at the
    //    callee (li t4,1).
    auipc   t4, 0
    jalr    ra, 16(t4)
    li      t4, 0
    ret
    li      t4, 1
    ret

    // 2) Does not fold: the callee reads t4 before writing it.
    auipc   t4, 0
    jalr    ra, 16(t4)
    li      t4, 0
    ret
    add     a0, t4, a1
    ret

    // 3) Does not fold: the code after the return reads t4.
    auipc   t4, 0
    jalr    ra, 16(t4)
    add     a0, t4, a1
    ret
    li      t4, 1
    ret

    // 4) Does not fold: `ret` at the return before any write to t4,
    //    which the walk cannot see past.
    auipc   t4, 0
    jalr    ra, 12(t4)
    ret
    li      t4, 1
    ret

    // 5) Something branches to the jalr, which the fold would delete.
    auipc   t4, 0
1:  jalr    ra, 16(t4)
    li      t4, 0
    beqz    a0, 1b
    li      t4, 1
    ret

    // 6) A megabyte ahead is past jal's reach.
    auipc   t4, 0x100
    jalr    ra, 0(t4)
    li      t4, 0
    ret

    // 7) The call pair's own spelling, which is that check's finding
    //    and not this one's.
    auipc   ra, 0
    jalr    ra, 12(ra)
    li      t4, 0
    ret
