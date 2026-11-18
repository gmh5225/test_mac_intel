
.text
.p2align 2
.globl _leaf_sum
_leaf_sum:
.cfi_startproc
  ldr w8, Lbias
  b Lresume
.data_region
Lbias:
  .long 0xd503237f
.end_data_region
.data_region jt8
  .byte 1,2
.end_data_region
.data_region jt16
  .short 3
.end_data_region
.data_region jt32
  .long 4
.end_data_region
Lresume:
  add x0, x0, x1
  add x0, x0, x8
  ret
.cfi_endproc
.text
.p2align 2
.globl _leaf_difference
_leaf_difference:
.cfi_startproc
  sub x0,x0,x1
  ret
.cfi_endproc
.subsections_via_symbols
