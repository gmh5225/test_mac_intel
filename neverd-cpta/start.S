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

#if defined(CPA_GENERATED_PAUTH_FAULTS)
// A fault skips the generated function's epilogue. Save the complete AAPCS64
// callee-saved bank here and restore it at the wrapper's own resume address.
.global probeGeneratedPAuth
probeGeneratedPAuth:
  stp x29, x30, [sp, #-CPA_FAULT_FRAME_BYTES]!
  stp x19, x20, [sp, #CPA_FAULT_X19_OFFSET]
  stp x21, x22, [sp, #CPA_FAULT_X21_OFFSET]
  stp x23, x24, [sp, #CPA_FAULT_X23_OFFSET]
  stp x25, x26, [sp, #CPA_FAULT_X25_OFFSET]
  stp x27, x28, [sp, #CPA_FAULT_X27_OFFSET]
  stp d8, d9, [sp, #CPA_FAULT_D8_OFFSET]
  stp d10, d11, [sp, #CPA_FAULT_D10_OFFSET]
  stp d12, d13, [sp, #CPA_FAULT_D12_OFFSET]
  stp d14, d15, [sp, #CPA_FAULT_D14_OFFSET]
  ldr x12, =GeneratedPAuthFaultState
  adr x13, GeneratedPAuthFaultResume
  mov x14, sp
  stp x13, x14, [x12, #CPA_FAULT_RESUME_OFFSET]
  str x2, [x12, #CPA_FAULT_REPORT_OFFSET]
  mov x16, x0
  mov x0, x1
  blr x16
  ldr x12, =GeneratedPAuthFaultState
  ldr x13, [x12, #CPA_FAULT_REPORT_OFFSET]
  stp x0, x1, [x13, #CPA_FAULT_LOW_OFFSET]
  mov x14, #CPA_FAULT_COMPLETED
  str x14, [x13, #CPA_FAULT_COMPLETED_OFFSET]
GeneratedPAuthFaultResume:
  ldr x12, =GeneratedPAuthFaultState
  str xzr, [x12, #CPA_FAULT_REPORT_OFFSET]
  ldp x19, x20, [sp, #CPA_FAULT_X19_OFFSET]
  ldp x21, x22, [sp, #CPA_FAULT_X21_OFFSET]
  ldp x23, x24, [sp, #CPA_FAULT_X23_OFFSET]
  ldp x25, x26, [sp, #CPA_FAULT_X25_OFFSET]
  ldp x27, x28, [sp, #CPA_FAULT_X27_OFFSET]
  ldp d8, d9, [sp, #CPA_FAULT_D8_OFFSET]
  ldp d10, d11, [sp, #CPA_FAULT_D10_OFFSET]
  ldp d12, d13, [sp, #CPA_FAULT_D12_OFFSET]
  ldp d14, d15, [sp, #CPA_FAULT_D14_OFFSET]
  ldp x29, x30, [sp], #CPA_FAULT_FRAME_BYTES
  ret
#endif

.global copyVector
copyVector:
  ldr q17, [x0, x2]
  str q17, [x1, x2]
  ret

#if defined(CPA_GENERATED_EL0_MEMORY)
.global runGeneratedAtEL0
runGeneratedAtEL0:
  stp x29, x30, [sp, #-CPA_SP_ALIGNMENT]!
  ldr x9, =GuestEL0StackEnd
  msr SP_EL0, x9
  mov x9, #CPA_SPSR_EL0T_MASKED
  msr SPSR_EL1, x9
  adr x9, GeneratedEL0Entry
  msr ELR_EL1, x9
  eret
GeneratedEL0Entry:
  bl CPA_GENERATED_ENTRY
GeneratedEL0Return:
  svc #CPA_SVC_IMMEDIATE
GeneratedEL0AfterSVC:
  b UnexpectedException
GeneratedEL1Resume:
  ldp x29, x30, [sp], #CPA_SP_ALIGNMENT
  ret
#endif

.balign (1 << CPA_GUEST_VECTOR_ALIGNMENT)
GuestVectors:
  .rept CPA_GUEST_VECTOR_COUNT
  b GuestException
  .space CPA_GUEST_VECTOR_SLOT_BYTES - CPA_INSTRUCTION_BYTES
  .endr
GuestException:
#if defined(CPA_GENERATED_PAUTH_FAULTS)
  CPA_FAULT_CLEAR_PAN
  ldr x12, =GeneratedPAuthFaultState
  ldr x13, [x12, #CPA_FAULT_REPORT_OFFSET]
  cbnz x13, GeneratedPAuthFaultException
#endif
#if defined(CPA_GENERATED_EL0_MEMORY)
  mrs x12, ESR_EL1
  lsr x13, x12, #CPA_ESR_EC_SHIFT
  cmp x13, #CPA_SVC64_EC
  b.eq GeneratedEL0Exception
#endif
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
#if defined(CPA_GENERATED_PAUTH_FAULTS)
GeneratedPAuthFaultException:
  // Remain stack-free until the wrapper's controlled SP is restored. In
  // particular X9 belongs to the independent probeStack alignment control.
  mrs x14, ESR_EL1
  str x14, [x13, #CPA_FAULT_ESR_OFFSET]
  mrs x14, SPSR_EL1
  and x14, x14, #CPA_SPSR_MODE_MASK
  str x14, [x13, #CPA_FAULT_ORIGIN_OFFSET]
  cbz x14, GeneratedPAuthFaultEL0
  cmp x14, #CPA_FAULT_EL1H
  b.ne UnexpectedException
  mov x15, sp
  str x15, [x13, #CPA_FAULT_SP_OFFSET]
  ldr x15, [x12, #CPA_FAULT_HOST_SP_OFFSET]
  mov sp, x15
  b GeneratedPAuthFaultReturn
GeneratedPAuthFaultEL0:
  mrs x15, SP_EL0
  str x15, [x13, #CPA_FAULT_SP_OFFSET]
  ldr x15, [x12, #CPA_FAULT_HOST_SP_OFFSET]
  msr SP_EL0, x15
GeneratedPAuthFaultReturn:
  mrs x14, ELR_EL1
  ldr w15, [x14]
  str x15, [x13, #CPA_FAULT_WORD_OFFSET]
  mov x15, #CPA_FAULT_COMPLETED
  str x15, [x13, #CPA_FAULT_FAULTED_OFFSET]
  ldr x14, [x12, #CPA_FAULT_RESUME_OFFSET]
  msr ELR_EL1, x14
  eret
#endif
#if defined(CPA_GENERATED_EL0_MEMORY)
GeneratedEL0Exception:
  and x12, x12, #CPA_SVC_ISS_MASK
  cmp x12, #CPA_SVC_IMMEDIATE
  b.ne UnexpectedException
  mrs x12, ELR_EL1
  adr x13, GeneratedEL0AfterSVC
  cmp x12, x13
  b.ne UnexpectedException
  mrs x1, SPSR_EL1
  and x1, x1, #CPA_SPSR_MODE_MASK
  cmp x1, #CPA_EL0_ORIGIN
  b.ne UnexpectedException
  mov x12, #CPA_SPSR_EL1H_MASKED
  msr SPSR_EL1, x12
  adr x12, GeneratedEL1Resume
  msr ELR_EL1, x12
  eret
#endif
UnexpectedException:
  mrs x0, ESR_EL1
  mrs x1, ELR_EL1
  mrs x2, FAR_EL1
  mov x3, sp
  mrs x14, SCTLR_EL1
  mov x15, #CPA_MEMORY_SCTLR_SET
  bic x14, x14, x15
  msr SCTLR_EL1, x14
  isb
  ldr x13, =GuestStackEnd
  mov sp, x13
  bl reportUnexpected
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

#if defined(CPA_GENERATED_PAUTH_FAULTS)
.balign CPA_MACHINE_WORD_BYTES
GeneratedPAuthFaultState:
  .space CPA_FAULT_STATE_BYTES
#endif

#if defined(CPA_GENERATED_EL0_MEMORY)
.balign CPA_SP_ALIGNMENT
GuestEL0Stack:
  .space CPA_GUEST_STACK_BYTES
GuestEL0StackEnd:
#endif
