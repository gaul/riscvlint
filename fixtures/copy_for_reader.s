// Integration fixture for check_copy_for_reader: `mv rd,rs` whose one
// reader could name rs instead, with rd gone after that reader. The
// copy goes and the reader is rewritten.

    .option norvc
    .text
    .globl  _start
    .p2align 1
_start:

    // The Wasm GC shape: a copy, a store of it, the copy's register
    // written again. The store names t0.
    mv      a1, t0
    sd      a1, 0(sp)
    li      a1, 0
    ret

    // A reader that writes rd itself: nothing after it has to be asked.
    mv      a0, a1
    addi    a0, a0, 5
    ret

    // An instruction between the copy and the reader that touches
    // neither register.
    mv      a1, t0
    li      a2, 0
    sd      a1, 0(sp)
    li      a1, 0
    ret

    // Not reported: rd is read twice.
    mv      a1, t0
    sd      a1, 0(sp)
    sd      a1, 8(sp)
    li      a1, 0
    ret

    // Not reported: rs is written before the reader.
    mv      a1, t0
    li      t0, 0
    sd      a1, 0(sp)
    li      a1, 0
    ret

    // Not reported: the reader is a side entry.
    mv      a1, t0
1:  sd      a1, 0(sp)
    li      a1, 0
    bnez    a0, 1b
    ret

    // Not reported: rd's fate after the reader is unknown, since `ret`
    // may expose it.
    mv      a1, t0
    sd      a1, 0(sp)
    ret

    // Compressed: c.sdsp names t0 in its five-bit field and stays two
    // bytes; c.sd's three-bit field cannot, so that reader takes four
    // bytes and the two-byte copy saves nothing.
    .option rvc
    mv      a1, t0
    sd      a1, 0(sp)
    li      a1, 0
    ret

    mv      a1, t0
    sd      a1, 0(a0)
    li      a1, 0
    ret
