.text
.globl _start
.p2align 4, 0x90
_start:
  xorl %ebp, %ebp
  andl $-16, %esp
  calll _main
  ud2
