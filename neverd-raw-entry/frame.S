
.text
.p2align 2
.globl _stages
_stages:
.cfi_startproc
#ifdef NEVERD_TEST_EXPLICIT_RA
.cfi_b_key_frame
#endif
.cfi_escape 0x2e, 0
.macro stage n
  mov w2, #\n
  stlr w2, [x0]
  add x3, x0, #4
1:ldar w4, [x3]
  cmp w4, w2
  b.ne 1b
.endm
  cbz x0, Lstages_return
  stage 1
  pacibsp
#ifdef NEVERD_TEST_EXPLICIT_RA
.cfi_negate_ra_state
#endif
  stage 2
  sub sp, sp, #16
.cfi_def_cfa_offset 16
  stp x19, x30, [sp]
.cfi_offset 19, -16
.cfi_offset 30, -8
  mov x19, xzr
  stage 3
  ldp x19, x30, [sp]
.cfi_restore 19
.cfi_restore 30
  add sp, sp, #16
.cfi_def_cfa_offset 0
  stage 4
  autibsp
#ifdef NEVERD_TEST_EXPLICIT_RA
.cfi_negate_ra_state
#endif
  stage 5
Lstages_return:
  ret
.cfi_endproc
.subsections_via_symbols
