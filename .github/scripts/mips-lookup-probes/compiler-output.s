	.abicalls
	.section	.mdebug.abi32,"",@progbits
	.nan	legacy
	.module	fp=xx
	.module	nooddspreg
	.text
	.file	"-"
	.globl	combine                         # -- Begin function combine
	.p2align	2
	.type	combine,@function
	.set	nomicromips
	.set	nomips16
	.ent	combine
combine:                                # @combine
	.frame	$sp,0,$ra
	.mask 	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.set	noat
# %bb.0:                                # %entry
	lui	$2, %hi(_gp_disp)
	addiu	$2, $2, %lo(_gp_disp)
	blez	$5, $BB0_8
	addu	$2, $2, $25
# %bb.1:
	lw	$3, %got($JTI0_0)($2)
	b	$BB0_4
	nop
$BB0_2:                                 # %sw.bb2
                                        #   in Loop: Header=BB0_4 Depth=1
	ori	$7, $1, 255
	sltu	$8, $6, $7
	movn	$7, $6, $8
	andi	$1, $1, 255
	sltu	$6, $6, $1
	movn	$7, $1, $6
	move	$6, $7
$BB0_3:                                 # %sw.epilog
                                        #   in Loop: Header=BB0_4 Depth=1
	addiu	$5, $5, -1
	beqz	$5, $BB0_8
	addiu	$4, $4, 4
$BB0_4:                                 # %for.body
                                        # =>This Inner Loop Header: Depth=1
	lw	$1, 0($4)
	andi	$7, $1, 3
	sll	$7, $7, 2
	addu	$7, $7, $3
	lw	$7, %lo($JTI0_0)($7)
	addu	$7, $2, $7
	jr	$7
	nop
$BB0_5:                                 # %sw.bb
                                        #   in Loop: Header=BB0_4 Depth=1
	xor	$1, $1, $6
	sll	$6, $1, 1
	b	$BB0_3
	addu	$6, $6, $1
$BB0_6:                                 # %sw.default
                                        #   in Loop: Header=BB0_4 Depth=1
	sll	$7, $6, 5
	addu	$6, $7, $6
	b	$BB0_3
	addu	$6, $1, $6
$BB0_7:                                 # %sw.bb1
                                        #   in Loop: Header=BB0_4 Depth=1
	rotr	$1, $1, 25
	b	$BB0_3
	addu	$6, $1, $6
$BB0_8:                                 # %for.cond.cleanup
	jr	$ra
	move	$2, $6
	.set	at
	.set	macro
	.set	reorder
	.end	combine
$func_end0:
	.size	combine, $func_end0-combine
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
$JTI0_0:
	.gpword	$BB0_5
	.gpword	$BB0_7
	.gpword	$BB0_2
	.gpword	$BB0_6
                                        # -- End function
	.text
	.globl	blend                           # -- Begin function blend
	.p2align	2
	.type	blend,@function
	.set	nomicromips
	.set	nomips16
	.ent	blend
blend:                                  # @blend
	.frame	$sp,0,$ra
	.mask 	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.set	noat
# %bb.0:                                # %entry
	beqz	$6, $BB1_3
	nop
# %bb.1:                                # %for.body.lr.ph
	addu	$2, $5, $6
	addiu	$1, $zero, 256
	subu	$3, $1, $7
$BB1_2:                                 # %for.body
                                        # =>This Inner Loop Header: Depth=1
	lbu	$1, 0($4)
	mul	$1, $7, $1
	lbu	$6, 0($5)
	mul	$6, $3, $6
	addu	$1, $6, $1
	srl	$1, $1, 8
	sb	$1, 0($5)
	addiu	$5, $5, 1
	bne	$5, $2, $BB1_2
	addiu	$4, $4, 1
$BB1_3:                                 # %for.cond.cleanup
	jr	$ra
	nop
	.set	at
	.set	macro
	.set	reorder
	.end	blend
$func_end1:
	.size	blend, $func_end1-blend
                                        # -- End function
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.text
