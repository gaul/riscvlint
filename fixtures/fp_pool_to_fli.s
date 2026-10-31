// A floating-point constant loaded from a pool that Zfa's `fli` would
// have built in one instruction. The fixture is linked rather than left
// relocatable (see fp_pool_to_fli.link): the check has to resolve the
// pool address into a section, and in a .o every section sits at 0.
	.option norelax
	.text
	.globl _start
_start:
// 1.0 is the value libxul's pool holds most of -- 909 of its 3,459
// encodable loads. a0 is overwritten straight after, which is what
// proves the rewrite may stop writing it.
.Lone:
	auipc	a0, %pcrel_hi(one)
	fld	fa0, %pcrel_lo(.Lone)(a0)
	li	a0, 1

// The single, which folds to `fli.s`.
.Lonef:
	auipc	a1, %pcrel_hi(onef)
	flw	fa1, %pcrel_lo(.Lonef)(a1)
	li	a1, 1

// Entry 31 is spelled by name rather than by value, as LLVM's printer
// spells it.
.Lnan:
	auipc	a2, %pcrel_hi(quiet_nan)
	fld	fa2, %pcrel_lo(.Lnan)(a2)
	li	a2, 1

// A value no entry holds. The pool is where it belongs and this is not
// a finding.
.Lpi:
	auipc	a3, %pcrel_hi(pi)
	fld	fa3, %pcrel_lo(.Lpi)(a3)
	li	a3, 1

// 1.0 again, but the address register is read afterwards: the rewrite
// would stop writing it, so the liveness proof refuses this one. On
// libxul this is what 475 of 3,441 sites look like.
.Llive:
	auipc	a4, %pcrel_hi(one)
	fld	fa4, %pcrel_lo(.Llive)(a4)
	sd	a4, 0(sp)

	ret

// The pool itself: allocated and not writable, which is the condition
// the rewrite rests on. A constant the program could overwrite is not
// a constant.
	.section .rodata,"a",@progbits
	.balign	8
one:	.dword	0x3ff0000000000000
quiet_nan:
	.dword	0x7ff8000000000000
pi:	.dword	0x40091eb851eb851f
onef:	.word	0x3f800000
