// Integration fixture for check_zcb_compressible.
//
// Assembled for rv64gc_zba_zbb -- without Zcb -- on purpose. With Zcb
// enabled the assembler compresses every positive here as it emits it,
// and the fixture would contain nothing to find. The .args sidecar then
// passes -m zcb, so the check sees a target that has the extension over
// code assembled for one that does not. That is also the shape of the
// question the finding answers on a real baseline build.
//
// Zba and Zbb are on because sext.b, sext.h, zext.h and zext.w are their
// instructions; without them the assembler expands each pseudo-op into a
// shift pair and there is no wide encoding to compress. -m zcb replaces
// the declared set rather than adding to it, so the Zba checks stay
// quiet over the same code.
//
// The extension sequences run one after another on a0, so a value that
// one of them narrows is still narrow when the next reads it, and
// check_redundant_extension reports several of them too. Two findings on
// one instruction is not a duplicate: one says the instruction does
// nothing, the other says its encoding is two bytes too wide, and they
// are independently true.

    .text
    .globl  _start
    .p2align 1
_start:

    // The memory forms. c.lbu and c.sb carry an unsigned two-bit byte
    // offset; c.lhu, c.lh and c.sh carry a one-bit halfword offset.
    lbu     a0, 0(a1)
    lbu     a0, 3(a1)
    lhu     a0, 2(a1)
    lh      a0, 2(a1)
    sb      a0, 3(a1)
    sh      a0, 2(a1)

    // Negatives: one past each offset field, and a negative offset,
    // which the compressed forms cannot express at all.
    lbu     a0, 4(a1)
    lhu     a0, 4(a1)
    sb      a0, 4(a1)
    lbu     a0, -1(a1)

    // Negatives: a register a three-bit field cannot name, on either
    // side of the access.
    lbu     a0, 0(a6)
    lbu     a6, 0(a1)

    // The unary forms, which all write the register they read.
    andi    a0, a0, 255
    xori    a0, a0, -1
    sext.b  a0, a0
    sext.h  a0, a0
    zext.h  a0, a0
    zext.w  a0, a0

    // Negatives: a different destination, and a register out of range.
    andi    a0, a1, 255
    xori    a6, a6, -1

    // c.mul is rd = rd * rs2', and multiplication commutes, so either
    // source may be the destination. clang compresses both orders;
    // GNU as compresses only the first and leaves 303 of the second in
    // libQt6Core alone.
    mul     a0, a0, a1
    mul     a0, a1, a0

    // Negatives: neither source is the destination, and a destination
    // out of range.
    mul     a0, a1, a2
    mul     a6, a6, a1

    // Zcb has no c.sext.w, so this one has no compressed spelling
    // however the corpus writes it.
    sext.w  a0, a0

    ret
