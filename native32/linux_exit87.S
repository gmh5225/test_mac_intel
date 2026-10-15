.syntax unified
.text
.global _start
.type _start, %function
#if defined(__thumb__)
.thumb
.thumb_func
#else
.arm
#endif
_start:
  mov r0, #87
  mov r7, #1
  svc #0
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
