/* Generated from contract.c with Clang 23.1.2 for stable code across native SDK compiler versions. */
	.def	"@feat.00";
	.scl	3;
	.type	0;
	.endef
	.globl	"@feat.00"
"@feat.00" = 0
	.file	"contract.c"
	.def	QUALIFIED_SHIM;
	.scl	2;
	.type	32;
	.endef
	.text
	.globl	QUALIFIED_SHIM          // -- Begin function QUALIFIED_SHIM
	.p2align	2
QUALIFIED_SHIM:                 // @QUALIFIED_SHIM
// %bb.0:
	hint	#27
	stp	x19, x20, [sp, #-32]!           // 16-byte Folded Spill
	str	x30, [sp, #16]                  // 8-byte Spill
	mov	x19, x1
	mov	x20, x0
	bl	neverd_cookie
	ldr	x30, [sp, #16]                  // 8-byte Reload
	mov	x0, x20
	mov	x1, x19
	ldp	x19, x20, [sp], #32             // 16-byte Folded Reload
	hint	#31
	b	neverd_driver_entry
                                        // -- End function
	.section	.debug$S,"dr"
	.p2align	2, 0x0
	.word	4                               // Debug section magic
	.word	241
	.word	.Ltmp1-.Ltmp0                   // Subsection size
.Ltmp0:
	.hword	.Ltmp3-.Ltmp2                   // Record length
.Ltmp2:
	.hword	4353                            // Record kind: S_OBJNAME
	.word	0                               // Signature
	.byte	0                               // Object name
	.p2align	2, 0x0
.Ltmp3:
	.hword	.Ltmp5-.Ltmp4                   // Record length
.Ltmp4:
	.hword	4412                            // Record kind: S_COMPILE3
	.word	16384                           // Flags and language
	.hword	246                             // CPUType
	.hword	0                               // Frontend version
	.hword	0
	.hword	0
	.hword	0
	.hword	23012                           // Backend version
	.hword	0
	.hword	0
	.hword	0
	.byte	0                               // Null-terminated compiler version string
	.p2align	2, 0x0
.Ltmp5:
.Ltmp1:
	.p2align	2, 0x0
	.addrsig
