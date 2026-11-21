.text
.p2align 2
.globl capture_and_call
capture_and_call:
    mov x8, x0
    mov x9, x3
    mov x0, x1
    mov x1, x2
    stp x0, x1, [x9]
    mov x10, sp
    stp x10, x30, [x9, #16]
    br x8
