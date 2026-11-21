.text
.p2align 2
.globl observe_entry
observe_entry:
    ldp x9, x10, [x0]
    mov x8, x0
    add x9, x9, x1
    eor x0, x9, x10
    stp x0, x1, [x8]
    ret
