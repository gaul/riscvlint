// Integration fixture for check_jump_pair_to_j: `auipc rd,X` + `jr Y(rd)`
// folded to `j target`. It is check_call_pair_to_jal's shape with x0 for
// the link register, and the difference decides every site below: the
// call pair folds exactly, because `jal rd` writes what the jalr wrote,
// while `j` leaves rd holding whatever it held before the pair, so the
// fold is sound only where the target writes rd before reading it.
//
// Every target is reached by an explicit displacement from the auipc,
// so no relocation is involved, and `.option norvc` keeps each
// instruction four bytes so that those displacements are what they say.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // 1) Folds: control lands on `li t6,0`, which redefines t6.
    auipc   t6, 0
    jalr    zero, 8(t6)
    li      t6, 0
    ret

    // 2) Does not fold: the target reads t6 before anything writes it.
    auipc   t6, 0
    jalr    zero, 8(t6)
    add     a0, t6, a1
    ret

    // 3) The call spelling. It writes ra, which is a different question
    //    and a different check (and not that check's shape either, whose
    //    jalr has to write the auipc's own register).
    auipc   t6, 0
    jalr    ra, 8(t6)
    li      t6, 0
    ret

    // 4) Something branches to the jr, which the fold would delete.
    auipc   t6, 0
1:  jalr    zero, 8(t6)
    li      t6, 0
    beqz    a0, 1b

    // 5) A megabyte ahead is one byte past j's reach; the check stops
    //    there, before asking where the target is.
    auipc   t6, 0x100
    jalr    zero, 0(t6)
    ret

    // 6) A backward pair, into the first site's `li t6,0`: the auipc
    //    sits at 76 and the li at 8.
    auipc   t6, 0
    jalr    zero, -68(t6)
    ret
