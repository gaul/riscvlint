// A floating-point constant built in an integer register and moved
// across with fmv, which Zfa's `fli` would have built in one
// instruction. This is how V8's TurboFan builds them, in t3; the cases
// here use a different argument register each, so that the write
// proving each one dead is not itself a dead write.
	.option norelax
	.text
	.globl _start
_start:
// TurboFan's 1.0. The slli is compressed, so the chain is six bytes.
// a0 is overwritten straight after, which proves the rewrite may stop
// writing it.
	li	a0, 1023
	slli	a0, a0, 52
	fmv.d.x	ft6, a0
	li	a0, 1

// A single built by lui alone and moved with fmv.w.x.
	lui	a1, 0x3f800
	fmv.w.x	ft0, a1
	li	a1, 1

// The canonical NaN, which fli spells by name. li 4095 assembles as lui
// and addi, so this chain is three instructions.
	li	a2, 4095
	slli	a2, a2, 51
	fmv.d.x	ft1, a2
	li	a2, 1

// 1024.0, which no entry holds. Not a finding.
	li	a3, 1033
	slli	a3, a3, 52
	fmv.d.x	ft2, a3
	li	a3, 1

// 1.0 again, but a4 is read after the move, so the liveness proof
// refuses it.
	li	a4, 1023
	slli	a4, a4, 52
	fmv.d.x	ft3, a4
	sd	a4, 0(sp)

// 1.0 once more, but a branch lands inside the chain, so the value the
// move sees depends on the path. Not a finding.
	beqz	a0, .Lmid
	li	a5, 1023
.Lmid:
	slli	a5, a5, 52
	fmv.d.x	ft4, a5
	li	a5, 1

	ret
