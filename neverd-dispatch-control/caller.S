
.text
.p2align 2
.globl _invoke_stages
_invoke_stages:
.cfi_startproc
  pacibsp
  stp x29, x30, [sp,#-16]!
.cfi_def_cfa_offset 16
.cfi_offset x29,-16
.cfi_offset x30,-8
  mov x29, sp
.cfi_def_cfa x29, 16
  str x19, [sp,#-16]!
.cfi_offset x19,-32
  mov x19,#0x5a19
  adr x2, Lreturn_site
  mov w5, #8
Lselect_sp:
  mov x3, x2
  mov x4, sp
  pacib x3, x4
  cmp x2, x3
  b.ne Lcall
  subs w5, w5, #1
  b.eq Lno_signature
  sub sp, sp, #16
  b Lselect_sp
Lno_signature:
  brk #0
Lcall:
  adrp x7, _stage_entry_sp@PAGE
  add x7, x7, _stage_entry_sp@PAGEOFF
  mov x4, sp
  stlr x4, [x7]
  adrp x7, _incoming_x19@PAGE
  add x7, x7, _incoming_x19@PAGEOFF
  stlr x19, [x7]
  mov x16, x0
  mov x0, x1
  blraaz x16
Lreturn_site:
  ldur x19, [x29,#-16]
.cfi_restore x19
  mov sp, x29
  ldp x29,x30,[sp],#16
  retab
.cfi_endproc

.globl _return_address
_return_address:
  adr x0, Lreturn_site
  ret

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
