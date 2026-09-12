	# The census reads what the instructions need rather than what the
	# object says it was built for, so this fixture pins the two apart:
	# the arch string at the bottom stops at Zba, and the text uses Zbb,
	# Zbs, Zcb, Zicond and Zfa as well. Everything past Zba should come
	# back reported as used but not declared.
	.text
	.global census
census:
	# Base RV64I, four bytes each.
	lui	a0, 4
	auipc	a1, 0
	slli	a2, a0, 20
	# The same kind of work in two bytes: the C extension.
	c.li	a3, 7
	c.add	a0, a1
	c.ld	a4, 0(a0)
	c.sdsp	a4, 8(sp)
	# M, A, F and D, the rest of what rv64gc mandates.
	mul	a5, a0, a1
	divu	a6, a0, a1
	lr.w	a7, (a0)
	amoadd.d	t0, t1, (a0)
	fadd.s	fa0, fa1, fa2
	fadd.d	fa3, fa4, fa5
	# Zicsr and Zifencei: capstone marks no feature group on either, so
	# these two are what the raw-decode path exists for. Zifencei is in
	# no RVA U-mode profile -- only in RVA20S64 -- so it belongs under
	# "outside the RVA profiles" and must not raise the level.
	csrr	t2, 0xc00
	fence.i
	# RVA22U64: the bitmanip trio.
	sh2add	t3, a0, a1
	andn	t4, a0, a1
	cpop	t5, a0
	bseti	t6, a0, 3
	# RVA23U64. The last is two bytes and needs Zcb and Zba both, so it
	# is counted under each and the totals do not add up to the
	# instruction count -- which is the point of counting that way.
	czero.eqz	a0, a1, a2
	fli.s	fa0, 1.0
	c.zext.w	a0
	# Hint space: `pause` is a FENCE and `ntl.all` an `add x0,x0,x5`, so
	# a core with neither extension executes both and ignores them. They
	# must not raise the level either.
	pause
	ntl.all
	ret

	# Last, because the directive also narrows what the assembler will
	# accept from here on: with it at the top, half the instructions
	# above stop assembling. Pinning the string rather than letting
	# -march write it keeps the expected output off the assembler's
	# extension version numbering as well.
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zba1p0"
