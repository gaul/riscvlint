// Integration fixture for check_redundant_extension.
//
// Assembled with Zcb, because that is where most of these instructions
// really are: the assembler picks `c.zext.b` over the four-byte
// `andi rd,rd,255` whenever the register is in x8-x15, and capstone
// prints both with the wide mnemonic. Reading such a site as the
// four-byte form is what made this check come out a fifth short the
// first time it was measured, so both spellings are covered here.
//
// The registers are chosen deliberately. a0-a5 are in x8-x15 and get the
// compressed spelling; a6 and a7 are not, and force the four-byte one.

    .text
    .globl  _start
    .p2align 1
_start:

// 1) lbu already zero-extends, so the mask is dead. In x8-x15 this is
//    c.zext.b, two bytes.
    lbu     a0, 0(a1)
    andi    a0, a0, 255
    ret

// 2) The same shape forced four bytes wide by a register c.zext.b
//    cannot name.
    lbu     a6, 0(a1)
    andi    a6, a6, 255
    ret

// 3) lw sign-extends from bit 31, so sext.w after it is dead.
    lw      a0, 0(a1)
    sext.w  a0, a0
    ret

// 4) Writing elsewhere makes it a copy rather than a deletion.
    lw      a0, 0(a1)
    sext.w  a2, a0
    ret

// 5) The guarantee comes from a mask rather than a load: `andi a0,a1,1`
//    bounds the value to one bit, which no zero-extension can change.
//    A producer list keyed on load mnemonics misses this.
    andi    a0, a1, 1
    nop
    andi    a0, a0, 255
    ret

// 6) Negative, and the case the whole model turns on: lwu zero-extends
//    to 32 bits, which does not imply sign-extension to 32 bits --
//    sext.w of 0x80000000 is a different value.
    lwu     a0, 0(a1)
    sext.w  a0, a0
    ret

// 7) Negative: the producer is overwritten before the extension reads
//    it, and ld says nothing about the high half.
    lbu     a0, 0(a1)
    ld      a0, 0(a1)
    andi    a0, a0, 255
    ret

// 8) Negative: a call in between clears what is known, rather than
//    trusting a register model at the place it is known to be thin.
    lbu     a0, 0(a1)
    call    other
    andi    a0, a0, 255
    ret

// 9) Negative: a side entry onto the extension. The value reaching it
//    was not necessarily produced by what precedes it in address order.
    lbu     a0, 0(a1)
    beqz    a1, .Lside
    nop
.Lside:
    andi    a0, a0, 255
    ret

// 10) sext.h after lb: a value sign-extended from bit 7 is already
//     sign-extended from bit 15, which is the closure the guarantee
//     model applies when it records rather than when it tests.
    lb      a0, 0(a1)
    sext.h  a0, a0
    ret

other:
    ret
