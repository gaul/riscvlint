// Integration fixture for check_t0_call: a call through t0, `jalr
// ra,lo(t0)` or `c.jalr t0`. ra and t0 are the two link registers, and a
// jalr naming both, different ones, tells the return-address stack to
// pop and then push, which costs the caller its own return prediction.
// The call is reported when the instruction that wrote t0 is an
// ordinary one, which leaves a code pointer there rather than a return
// address.

    .text
    .globl  _start
    .p2align 1
_start:

    // 1) Reported: Go's closure call before 1.27, the code pointer
    //    loaded from the closure into t0 and called through it.
    .option push
    .option norvc
    ld      s10, 72(a1)
    ld      t0, 0(s10)
    ld      a1, 8(a0)
    jalr    ra, 0(t0)
    .option pop

    // 2) Reported: the same in two bytes, as Firefox's XPCOM invoke stub
    //    spells it -- `jalr t0` assembles to `c.jalr t0`.
    ld      t0, 0(s2)
    jalr    t0

    // 3) Reported: the writer seen through a conditional branch, whose
    //    fall-through still carries t0.
    ld      t0, 8(s2)
    beqz    a0, 1f
    jalr    ra, 16(t0)
1:

    // 4) Not reported: through t1, which only pushes.
    ld      t1, 0(s2)
    jalr    t1

    // 5) Not reported: `jalr t0, 0(ra)` is a coroutine's yield, which
    //    pops on purpose; `jalr t0, 0(t0)` links t0 and only pushes.
    ld      t0, 0(s2)
    jalr    t0, 0(ra)
    ld      t0, 0(s2)
    jalr    t0, 0(t0)

    // 6) Not reported: t0 copies ra, so it may hold a return address.
    mv      t0, ra
    jalr    ra, 0(t0)

    // 7) Not reported: t0 is whatever the call before left in it.
    ld      t0, 0(s2)
    call    _start
    jalr    ra, 0(t0)

    // 8) Not reported: something branches to the call, and t0 may come
    //    from that path.
    ld      t0, 0(s2)
2:  jalr    ra, 0(t0)
    bnez    a0, 2b
    ret
