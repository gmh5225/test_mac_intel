//===- start.S - Stack-free controlled EL1 entry and exception probe ----===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//

#include "CptaGuest.def"

.section .text.start,"ax"
.global _start
_start:
  ldr x0, =GuestBSSStart
  ldr x1, =GuestBSSEnd
ClearBSS:
  cmp x0, x1
  b.hs BSSReady
  str xzr, [x0], #CPA_MACHINE_WORD_BYTES
  b ClearBSS
BSSReady:
  ldr x0, =GuestStackEnd
  mov sp, x0
  adrp x0, GuestVectors
  add x0, x0, :lo12:GuestVectors
  msr VBAR_EL1, x0
  isb
  mov x11, xzr
  bl guestMain
  b UnexpectedException

.global probeStack
probeStack:
  mov x9, sp
  mov x10, xzr
  adr x11, ProbeResume
  cbz x1, ProbeGeneral
  mov sp, x0
  ldr x2, [sp]
  b ProbeResume
ProbeGeneral:
  ldr x2, [x0]
ProbeResume:
  mov sp, x9
  mov x0, x10
  mov x11, xzr
  ret

.global copyVector
copyVector:
  ldr q17, [x0, x2]
  str q17, [x1, x2]
  ret

.balign (1 << CPA_GUEST_VECTOR_ALIGNMENT)
GuestVectors:
  .rept CPA_GUEST_VECTOR_COUNT
  b GuestException
  .space CPA_GUEST_VECTOR_SLOT_BYTES - CPA_INSTRUCTION_BYTES
  .endr
GuestException:
  cbz x11, UnexpectedException
  adr x12, ProbeResume
  cmp x11, x12
  b.ne UnexpectedException
  mrs x10, ESR_EL1
  lsr x12, x10, #CPA_ESR_EC_SHIFT
  cmp x12, #CPA_SP_ALIGNMENT_EC
  b.ne UnexpectedException
  msr ELR_EL1, x11
  eret
UnexpectedException:
  mov x0, #CPA_SEMIHOST_WRITE0
  adr x1, UnexpectedText
  hlt #CPA_SEMIHOST_IMMEDIATE
  mov x0, #CPA_SEMIHOST_EXIT_EXTENDED
  adr x1, UnexpectedExit
  hlt #CPA_SEMIHOST_IMMEDIATE
  b .
UnexpectedText:
  .asciz CPA_UNEXPECTED_TEXT
.balign CPA_MACHINE_WORD_BYTES
UnexpectedExit:
  .quad CPA_SEMIHOST_APPLICATION_EXIT, 1

.section .bss,"aw",%nobits
.balign CPA_SP_ALIGNMENT
GuestStack:
  .space CPA_GUEST_STACK_BYTES
GuestStackEnd:
