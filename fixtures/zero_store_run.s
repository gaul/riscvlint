// Integration fixture for check_zero_store_run: consecutive stores of
// x0 to abutting frame slots, where fewer naturally aligned stores
// would cover the same bytes.
//
// GCC zeroes a frame buffer one byte at a time and the opportunity is
// the whole run rather than a set of adjacent pairs -- read as pairs
// the corpus is 50,755 sites and read as runs it is 30,321, because a
// run of seven `sb` is one finding worth 16 bytes and not three
// pair-merges worth four each.
//
// Both sides of the byte figure are priced at the best encoding the
// base C extension offers rather than at the bytes the binary carries,
// which is what keeps this check off check_c_compressible's ground.
// Positive 2 is the case that separates them.

    .text
    .globl  _start
    .p2align 1
_start:

    // Positives:
    // 1) The libQt6Core shape: seven bytes of frame zeroed one at a
    //    time. Covering [-111,-104) with aligned stores takes three --
    //    `sb -111`, `sh -110`, `sw -108` -- so 16 of the 28 bytes go.
    sb      zero, -111(s0)
    sb      zero, -110(s0)
    sb      zero, -109(s0)
    sb      zero, -108(s0)
    sb      zero, -107(s0)
    sb      zero, -106(s0)
    sb      zero, -105(s0)
    nop

    // 2) Go's shape: two `sw zero,K(sp)` the assembler left wide. The
    //    finding is two bytes, not four: the other two are
    //    check_c_compressible's, at both addresses, and the two
    //    findings add up to the eight bytes that are really there.
    .option norvc
    sw      zero, 48(sp)
    sw      zero, 52(sp)
    .option rvc
    nop

    // 3) A run that grows at both ends and mixes widths -- 47, then 48
    //    and 56 upward, then 46 downward. One average encoded size
    //    cannot price this; each store is priced on its own.
    sb      zero, 47(sp)
    sd      zero, 48(sp)
    sd      zero, 56(sp)
    sb      zero, 46(sp)
    nop

    // 4) Four stores already compressed, where the middle two merge
    //    into one `c.sdsp` and the ends stay. Nothing here is
    //    compression's to claim and the saving is the one instruction.
    sw      zero, 68(sp)
    sw      zero, 72(sp)
    sw      zero, 76(sp)
    sw      zero, 80(sp)
    nop

    // Negatives:
    // N1) A gap ends the run rather than being written through: a wider
    //     store would write the bytes between, which nothing asked for.
    //     These four are two runs of two.
    sb      zero, 8(s0)
    sb      zero, 9(s0)
    sb      zero, 12(s0)
    sb      zero, 13(s0)
    nop

    // N2) A store of something other than zero ends it. `sd rD` in
    //     place of two `sw rD` would write rD's high half to the second
    //     slot, and nothing says a register's halves are the two values
    //     that were stored.
    sb      zero, 16(s0)
    sb      a0, 17(s0)
    sb      zero, 18(s0)
    nop

    // N3) A base whose alignment the encoding does not give. 23,973
    //     sites run through one -- four times the frame population --
    //     and there a byte-at-a-time store may be the deliberate choice
    //     rather than the missed one.
    sb      zero, 8(a1)
    sb      zero, 9(a1)
    nop

    // N4) Already the cheapest cover: four `sd zero` over 32 bytes
    //     merge into nothing at all. Pricing the survivors as
    //     compressible while pricing these at what they occupy made
    //     this look like a saving of eight, which is the compression
    //     check's figure for the same four instructions.
    .option norvc
    sd      zero, 0(sp)
    sd      zero, 8(sp)
    sd      zero, 16(sp)
    sd      zero, 24(sp)
    .option rvc
    nop

    // N5) `fsw ft0` names f0 with the same field x0 uses, and f0 is a
    //     value rather than a zero. The two abut, so without the test
    //     they would merge.
    fsw     ft0, 24(s0)
    fsw     ft0, 28(s0)
    nop

    // N6) A side entry inside the run: a path arriving there would
    //     reach the merged store having skipped the bytes before it,
    //     and the merged store writes them all.
    sb      zero, 32(s0)
.Lside:
    sb      zero, 33(s0)
    ret
    beqz    a0, .Lside

    // N7) One store is not a run.
    sb      zero, 40(s0)

    ret
