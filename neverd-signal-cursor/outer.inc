.text
.p2align 2
.globl _call_outer
_call_outer:
.cfi_startproc
  pacibsp
  stp x29,x30,[sp,#-16]!
.cfi_def_cfa_offset 16
.cfi_offset x29,-16
.cfi_offset x30,-8
  mov x29,sp
.cfi_def_cfa x29,16
  adr x2,Louter_return
  mov w5,#8
Lchoose_outer_sp:
  mov x3,x2
  mov x4,sp
  pacib x3,x4
  cmp x2,x3
  b.ne Lcall_inner
  subs w5,w5,#1
  b.eq Lno_outer_signature
  sub sp,sp,#16
  b Lchoose_outer_sp
Lno_outer_signature:
  brk #0
Lcall_inner:
  bl _invoke_stages
Louter_return:
  mov sp,x29
  ldp x29,x30,[sp],#16
  retab
.cfi_endproc
.globl _outer_return_address
_outer_return_address:
  adr x0,Louter_return
  ret
