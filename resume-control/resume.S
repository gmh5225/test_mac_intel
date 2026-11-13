
.text
.globl _resume_frame
.p2align 2
_resume_frame:
.cfi_startproc
.cfi_escape 0x2e, 0
  pacibsp
  stp x19, x30, [sp, #-112]!
.cfi_def_cfa_offset 112
.cfi_offset x19, -112
.cfi_offset x30, -104
  stp q8, q9, [sp, #16]
  stp q10, q11, [sp, #48]
  stp d12, d13, [sp, #80]
  stp d14, d15, [sp, #96]
  mov x19, #0
  movi v8.16b, #0x28
  movi v9.16b, #0x29
  movi v10.16b, #0x2a
  movi v11.16b, #0x2b
  movi v12.16b, #0x2c
  movi v13.16b, #0x2d
  movi v14.16b, #0x2e
  movi v15.16b, #0x2f
#ifdef NEVERD_RESUME_PUBLISHED
  mov w9, #2
#else
  mov w9, #1
#endif
  stlr w9, [x0]
1:ldar w10, [x0]
  cbnz w10, 1b
  ldp q8, q9, [sp, #16]
  ldp q10, q11, [sp, #48]
  ldp d12, d13, [sp, #80]
  ldp d14, d15, [sp, #96]
  ldp x19, x30, [sp], #112
.cfi_restore x19
.cfi_restore x30
.cfi_def_cfa_offset 0
  mov w0,#0
  retab
.cfi_endproc
.subsections_via_symbols
