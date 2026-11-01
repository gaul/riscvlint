// Integration fixture for check_slli_srli_to_andi: an equal shift pair
// keeping eleven bits or fewer, which one andi keeps. The first block is
// V8's DecodeField of a field at bit 0. Each block stores what it
// computed, so no other check calls the shifts dead.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // Baseline's OsrUrgencyBits: three bits, andi 7.
    slli    s4, s4, 61
    srli    s4, s4, 61
    sd      s4, 0(sp)

    // 53 keeps eleven bits, the widest andi mask.
    slli    a0, a0, 53
    srli    a0, a0, 53
    sd      a0, 8(sp)

    // Not reported: 52 keeps twelve, which andi's immediate cannot hold.
    slli    a0, a0, 52
    srli    a0, a0, 52
    sd      a0, 16(sp)

    // The srli writing elsewhere, the shifted value dead after it.
    slli    a5, a4, 57
    srli    a3, a5, 57
    li      a5, 1
    sd      a3, 24(sp)
    sd      a5, 32(sp)

    // Not reported: unequal amounts move the field rather than mask it.
    slli    a0, a0, 61
    srli    a0, a0, 60
    sd      a0, 40(sp)

    // Compressed: c.slli and c.srli on a5 become one c.andi.
    .option rvc
    slli    a5, a5, 61
    srli    a5, a5, 61
    sd      a5, 48(sp)
    ret
