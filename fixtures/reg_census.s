	# The register census: which registers the code names, and which
	# four-byte instructions a compressed form would have held but for a
	# register outside x8-x15. .option norvc keeps the assembler from
	# compressing what it could, so the census sees the wide spellings
	# a toolchain without C, or a relocation, leaves behind.
	.text
	.global regs
regs:
	.option push
	.option norvc
	ld	a0, 8(a1)		# c.ld would hold it; left wide here
	ld	t0, 8(a1)		# kept wide by t0, the data
	ld	a0, 8(s2)		# by s2, the base
	ld	s2, 8(s3)		# by both
	ld	a0, 256(a1)		# by the offset, which no register fixes
	sd	zero, 0(a0)		# by x0, which no three-bit field names
	sd	a0, -8(s0)		# below the frame pointer
	beqz	t0, 1f			# by t0
	and	t0, t0, t1		# by t0 and t1
	addi	t0, sp, 16		# by t0: c.addi4spn
	srli	t0, t0, 3		# by t0
	lbu	t0, 1(a0)		# by t0, under Zcb
	andi	t0, t0, 255		# by t0, under Zcb: c.zext.b
	mul	t0, t0, a0		# by t0, under Zcb: c.mul
	fld	ft0, 8(a0)		# by ft0
	jal	1f			# ra written without being shown
	.option pop
1:
	c.ld	a0, 0(a1)
	c.add	a0, a1
	c.sdsp	ra, 8(sp)
	ret
