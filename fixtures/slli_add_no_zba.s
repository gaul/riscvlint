// Gate fixture for check_slli_add_to_shadd.
//
// The same shape as slli_add_to_shadd.s, but with no .flags sidecar, so
// the assembler records a plain rv64gc arch string. The object states
// that its target has no Zba, and a check that suggested sh2add anyway
// would be proposing an instruction that does not assemble. Expected
// output: nothing.

    .text
    .globl  _start
    .p2align 1
_start:
    slli    s0, t2, 2
    add     s0, s0, t2

    slli    s0, s0, 2
    add     s0, s0, t2

    ret
