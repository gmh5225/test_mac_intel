
.text
.p2align 2
.macro dispatch name, width
.globl \name
\name:
.cfi_startproc
 cmp w0, #3
 b.hi 9f
 adr x10, 8f
 .if \width == 4
 adr x11, 3f
 ldrsw x9, [x10, w0, uxtw #2]
 add x9, x11, x9
 .else
 adr x11, 1f
 .if \width == 1
 ldrb w9, [x10, w0, uxtw]
 .else
 ldrh w9, [x10, w0, uxtw #1]
 .endif
 add x9, x11, x9, lsl #2
 .endif
 br x9
1: add x0, x1, #11
 ret
2: add x0, x1, #29
 ret
3: add x0, x1, #43
 ret
9: sub x0, x1, #5
 ret
 .if \width == 1
 .data_region
 .long 0xd503237f
 .end_data_region
 .data_region jt8
8: .byte (3b-1b)/4, 0, (2b-1b)/4, 0
 .elseif \width == 2
 .data_region jt16
8: .short (3b-1b)/4, 0, (2b-1b)/4, 0
 .else
 .data_region jt32
8: .long 0, 1b-3b, 2b-3b, 1b-3b
 .endif
 .end_data_region
.cfi_endproc
.endm
dispatch _leaf_sum, 1
dispatch _leaf_difference, 2
dispatch _leaf_wide, 4
.subsections_via_symbols
