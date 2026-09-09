// Override fixture for check_slli_add_to_shadd.
//
// Assembled without a .flags sidecar, so the object declares a plain
// rv64gc arch and the check would normally stay quiet -- see
// slli_add_no_zba.s, which is this same shape and reports nothing. The
// .args sidecar passes -m zba, which overrides the declaration and asks
// the question the flag exists for: what would rebuilding with Zba buy?

    .text
    .globl  _start
    .p2align 1
_start:
    slli    s0, t2, 2
    add     s0, s0, t2

    slli    s0, s0, 3
    add     s0, s0, t2

    ret
