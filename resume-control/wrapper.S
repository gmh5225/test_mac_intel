
.text
.globl _invoke_resume
.p2align 2
_invoke_resume:
.cfi_startproc
  pacibsp
  stp x29,x30,[sp,#-128]!
.cfi_def_cfa_offset 128
.cfi_offset x29,-128
.cfi_offset x30,-120
  mov x29,sp
  stp x19,x20,[sp,#16]
  str x21,[sp,#32]
  stp d8,d9,[sp,#48]
  stp d10,d11,[sp,#64]
  stp d12,d13,[sp,#80]
  stp d14,d15,[sp,#96]
  mov x16,x0
  mov x0,x1
  mov x20,x3
  mov x21,sp
  mov x19,#0x5319
  ldp q0,q1,[x2]
  ldp q2,q3,[x2,#32]
  ldp q4,q5,[x2,#64]
  ldp q6,q7,[x2,#96]
  ldp q8,q9,[x2,#128]
  ldp q10,q11,[x2,#160]
  ldp q12,q13,[x2,#192]
  ldp q14,q15,[x2,#224]
  ldp q16,q17,[x2,#256]
  ldp q18,q19,[x2,#288]
  ldp q20,q21,[x2,#320]
  ldp q22,q23,[x2,#352]
  ldp q24,q25,[x2,#384]
  ldp q26,q27,[x2,#416]
  ldp q28,q29,[x2,#448]
  ldp q30,q31,[x2,#480]
  blraaz x16
Lresume_return:
  cmp sp,x21
  b.ne Lbad_resume
  cmp x29,x21
  b.ne Lbad_resume
  mov x11,#0x5319
  cmp x19,x11
  b.ne Lbad_resume
  adr x11,Lresume_return
  cmp x30,x11
  b.ne Lbad_resume
  stp q0,q1,[x20]
  stp q2,q3,[x20,#32]
  stp q4,q5,[x20,#64]
  stp q6,q7,[x20,#96]
  stp q8,q9,[x20,#128]
  stp q10,q11,[x20,#160]
  stp q12,q13,[x20,#192]
  stp q14,q15,[x20,#224]
  stp q16,q17,[x20,#256]
  stp q18,q19,[x20,#288]
  stp q20,q21,[x20,#320]
  stp q22,q23,[x20,#352]
  stp q24,q25,[x20,#384]
  stp q26,q27,[x20,#416]
  stp q28,q29,[x20,#448]
  stp q30,q31,[x20,#480]
  mrs x9,fpcr
  mrs x10,fpsr
  add x11,x20,#512
  stp w9,w10,[x11]
  b Lfinish_resume
Lbad_resume:
  mov x0,#0
Lfinish_resume:
  ldp d8,d9,[sp,#48]
  ldp d10,d11,[sp,#64]
  ldp d12,d13,[sp,#80]
  ldp d14,d15,[sp,#96]
  ldp x19,x20,[sp,#16]
  ldr x21,[sp,#32]
  ldp x29,x30,[sp],#128
  retab
.cfi_endproc
