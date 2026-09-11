// Integration fixture for check_bitcast_through_frame: a value moved
// between the two register files by storing it to a slot and loading it
// back, where one `fmv` does it in a single instruction and no memory.
//
// This is the one check here whose value is not bytes. None of the four
// moves has a compressed spelling, so the rewrite breaks even against a
// four-byte load and would cost two against a two-byte one -- and it is
// refused there, which is N1 below and 869 of the 2,380 sites the probe
// finds.
//
// It is also the reason the windowed table records floating-point
// accesses at all. Every other reader of that table skips a record
// whose register is in the other file, because an f register and an x
// register with the same number are two registers.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) A single stored and read back into a general register.
    //    `fmv.x.w` sign-extends the 32 bits it moves and so does `lw`.
    .option norvc
    fsw     ft6, 256(sp)
    lw      s1, 256(sp)
    .option rvc

    // 2) The other direction, off a two-byte store. The store's own
    //    width is not the question -- the load's is, since the load is
    //    what goes.
    sw      a2, 80(sp)
    flw     fa5, 80(sp)

    // 3) At the doubleword, with three instructions between that touch
    //    neither the base nor the stored register.
    sd      a2, 488(s8)
    sd      a0, 520(s8)
    sd      a1, 528(s8)
    fld     fa4, 488(s8)

    // 4) Armed by a *load* rather than a store, and read back across a
    //    conditional branch. The load is reached by falling through, so
    //    everything the record saw ran. The probe this was sized from
    //    arms only from stores and models neither half.
    fld     fa4, 0(s9)
    slli    a1, a0, 4
    feq.d   a1, fa4, fa5
    beqz    a1, .Lover
    ld      a2, 0(s9)
.Lover:

    // Negatives:
    // N1) A two-byte load. The move is four bytes whatever happens, so
    //     this would grow the code by two to save a memory access, and
    //     this check will not pay bytes for one.
    fsw     fs0, 0(sp)
    lw      a1, 0(sp)

    // N2) A wider load than the store: it reads bytes the store never
    //     wrote.
    .option norvc
    fsw     ft6, 264(sp)
    ld      s1, 264(sp)

    // N3) `lwu` zero-extends where `fmv.x.w` sign-extends.
    fsw     ft6, 272(sp)
    lwu     s1, 272(sp)

    // N4) The f register is overwritten, so there is nothing left to
    //     move from. This is the rule the table could not enforce
    //     before it recorded floating-point accesses at all.
    fsw     ft6, 280(sp)
    fadd.s  ft6, ft0, ft1
    lw      s1, 280(sp)

    // N5) The base is overwritten, so the address is not the one the
    //     store used.
    fsw     ft6, 256(s1)
    addi    s1, s1, 8
    lw      a0, 256(s1)

    // N6) A store through another base may have landed on the slot, and
    //     nothing in the encoding says it did not.
    fsw     ft6, 288(sp)
    sd      a4, 0(a3)
    lw      s1, 288(sp)

    // N7) Both halves in the same file is check_store_to_load's site,
    //     which still reports it with the table holding records from
    //     both.
    sd      a2, 296(sp)
    ld      a0, 296(sp)
    .option rvc

    ret
