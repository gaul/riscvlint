// Integration fixture for the three checks that read the windowed
// memory and constant table: check_redundant_reload, check_dead_store
// and check_const_remat.
//
// None of these can be decided from a pair -- the distances cluster at
// 4-15 instructions in the corpus -- so every sequence here puts
// something between the two halves. What that something is, is the
// whole test: an instruction that cannot have changed the location
// leaves the finding standing, and one that might takes it away.
//
// riscvlint_state_observe owns the table and the driver calls it after
// the checks, so each sequence is judged against the table as it stood
// before the instruction under the cursor.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) The same address loaded twice with only arithmetic in between.
    //    The second load is a move from wherever the first put it.
    ld      a0, 8(a1)
    addi    a2, a2, 1
    ld      a3, 8(a1)

    // 2) A frame slot stored twice with nothing reading it. The first
    //    store is dead. c.sdsp is how this is spelled in real code,
    //    which is why the decoder claims quadrant 2.
    sd      a0, 16(sp)
    addi    a2, a2, 1
    sd      a4, 16(sp)

    // 3) A constant materialized twice. Both are four bytes, so the mv
    //    that replaces the second saves two.
    li      a5, 1234
    addi    a2, a2, 1
    li      a6, 1234

    // 4) A load from a disjoint slot through the same base cannot have
    //    read what the store put at 32(sp), so the store is still dead.
    sd      a0, 32(sp)
    ld      a7, 48(sp)
    sd      a4, 32(sp)

    // Negatives:
    // N1) A store between two loads. Proving it lands elsewhere needs
    //     more than the encoding gives, so the held value is dropped.
    ld      a0, 24(a1)
    sd      a4, 0(a3)
    ld      a3, 24(a1)

    // N2) The base is overwritten, so the address the second load
    //     computes is not the address the first one used.
    ld      a0, 40(a1)
    addi    a1, a1, 8
    ld      a3, 40(a1)

    // N3) The register holding the value is overwritten, so there is
    //     nothing left to move from.
    ld      a0, 56(a1)
    li      a0, 0
    ld      a3, 56(a1)

    // N4) lb and lbu are the same width and not the same value.
    lb      a0, 3(a1)
    addi    a2, a2, 1
    lbu     a3, 3(a1)

    // N5) A load from the slot is the read that keeps the store alive.
    sd      a0, 64(sp)
    ld      a7, 64(sp)
    sd      a4, 64(sp)

    // N6) A load through another base may alias the slot, and nothing
    //     in the encoding says it does not.
    sd      a0, 72(sp)
    ld      a7, 0(a1)
    sd      a4, 72(sp)

    // N7) A call can read the frame and can change anything.
    sd      a0, 80(sp)
    call    other
    sd      a4, 80(sp)

    // N8) c.li is already two bytes, so rewriting it as c.mv saves
    //     nothing and trades an independent instruction for a dependent
    //     one. 97% of the raw re-materialization population is this.
    li      a5, 7
    addi    a2, a2, 1
    li      a6, 7

    // N9) A different constant is not a re-materialization.
    li      a5, 4321
    addi    a2, a2, 1
    li      a6, 4322

    // N10) A side entry between the two halves: what follows is not
    //      reached only from here.
    ld      a0, 88(a1)
    beqz    a2, .Lside
.Lside:
    ld      a3, 88(a1)

    // The three below were false positives the first time this was run
    // over the corpus, each caught by reading the disassembly around a
    // finding rather than by any test.

    // N11) The load overwrites its own base, so the address the second
    //      one computes is not the address the first one used --
    //      `ld a1,0(a1)` walks a pointer. 67 of ripgrep's 151 first
    //      reload findings were this.
    ld      a1, 0(a1)
    ld      a2, 0(a1)

    // N12) A conditional branch between the two stores. "Dead" means
    //      the overwrite is certain, and on the taken path it does not
    //      happen at all. 32 of ripgrep's 37 first dead-store findings
    //      were this.
    sd      a0, 96(sp)
    beqz    a2, .Lskip
    sd      a4, 96(sp)
.Lskip:

    // N13) A vector load through an address taken from the frame. It
    //      reads the slot, and rv_decode_mem cannot say where a vector
    //      access lands, so the whole window goes rather than the claim
    //      being kept in ignorance.
    sd      a0, 104(sp)
    addi    a3, sp, 104
    vsetivli zero, 2, e64, m1, ta, ma
    vle64.v v8, (a3)
    sd      a4, 104(sp)

    ret

other:
    ret
