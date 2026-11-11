#ifdef __APPLE__
#define S1(x) _##x
#else
#define S1(x) x
#endif
.text
.globl S1(probe_fx)
S1(probe_fx):
    pushq %rbp
    movq %rsp, %rbp
    subq $512, %rsp
    fxsave64 (%rsp)
    fninit
    testl %esi, %esi
    jz 2f
1:
    fldl (%rdx)
    addq $8, %rdx
    decl %esi
    jnz 1b
2:
    callq *%rcx
    fxsave64 (%rdi)
    fxrstor64 (%rsp)
    leave
    retq

.globl S1(fxch0)
S1(fxch0):
    .byte 0xd9, 0xc8
    retq
.globl S1(fxch1)
S1(fxch1):
    .byte 0xd9, 0xc9
    retq
.globl S1(fxch2)
S1(fxch2):
    .byte 0xd9, 0xca
    retq
.globl S1(fxch3)
S1(fxch3):
    .byte 0xd9, 0xcb
    retq
.globl S1(fxch4)
S1(fxch4):
    .byte 0xd9, 0xcc
    retq
.globl S1(fxch5)
S1(fxch5):
    .byte 0xd9, 0xcd
    retq
.globl S1(fxch6)
S1(fxch6):
    .byte 0xd9, 0xce
    retq
.globl S1(fxch7)
S1(fxch7):
    .byte 0xd9, 0xcf
    retq
.globl S1(fstp0)
S1(fstp0):
    .byte 0xdd, 0xd8
    retq
.globl S1(fstp1)
S1(fstp1):
    .byte 0xdd, 0xd9
    retq
.globl S1(fstp2)
S1(fstp2):
    .byte 0xdd, 0xda
    retq
.globl S1(fstp3)
S1(fstp3):
    .byte 0xdd, 0xdb
    retq
.globl S1(fstp4)
S1(fstp4):
    .byte 0xdd, 0xdc
    retq
.globl S1(fstp5)
S1(fstp5):
    .byte 0xdd, 0xdd
    retq
.globl S1(fstp6)
S1(fstp6):
    .byte 0xdd, 0xde
    retq
.globl S1(fstp7)
S1(fstp7):
    .byte 0xdd, 0xdf
    retq
.globl S1(ddx0)
S1(ddx0):
    .byte 0xdd, 0xc8
    retq
.globl S1(ddx1)
S1(ddx1):
    .byte 0xdd, 0xc9
    retq
.globl S1(ddx2)
S1(ddx2):
    .byte 0xdd, 0xca
    retq
.globl S1(ddx3)
S1(ddx3):
    .byte 0xdd, 0xcb
    retq
.globl S1(ddx4)
S1(ddx4):
    .byte 0xdd, 0xcc
    retq
.globl S1(ddx5)
S1(ddx5):
    .byte 0xdd, 0xcd
    retq
.globl S1(ddx6)
S1(ddx6):
    .byte 0xdd, 0xce
    retq
.globl S1(ddx7)
S1(ddx7):
    .byte 0xdd, 0xcf
    retq
.globl S1(dfx0)
S1(dfx0):
    .byte 0xdf, 0xc8
    retq
.globl S1(dfx1)
S1(dfx1):
    .byte 0xdf, 0xc9
    retq
.globl S1(dfx2)
S1(dfx2):
    .byte 0xdf, 0xca
    retq
.globl S1(dfx3)
S1(dfx3):
    .byte 0xdf, 0xcb
    retq
.globl S1(dfx4)
S1(dfx4):
    .byte 0xdf, 0xcc
    retq
.globl S1(dfx5)
S1(dfx5):
    .byte 0xdf, 0xcd
    retq
.globl S1(dfx6)
S1(dfx6):
    .byte 0xdf, 0xce
    retq
.globl S1(dfx7)
S1(dfx7):
    .byte 0xdf, 0xcf
    retq
.globl S1(dfd00)
S1(dfd00):
    .byte 0xdf, 0xd0
    retq
.globl S1(dfd01)
S1(dfd01):
    .byte 0xdf, 0xd1
    retq
.globl S1(dfd02)
S1(dfd02):
    .byte 0xdf, 0xd2
    retq
.globl S1(dfd03)
S1(dfd03):
    .byte 0xdf, 0xd3
    retq
.globl S1(dfd04)
S1(dfd04):
    .byte 0xdf, 0xd4
    retq
.globl S1(dfd05)
S1(dfd05):
    .byte 0xdf, 0xd5
    retq
.globl S1(dfd06)
S1(dfd06):
    .byte 0xdf, 0xd6
    retq
.globl S1(dfd07)
S1(dfd07):
    .byte 0xdf, 0xd7
    retq
.globl S1(dfd80)
S1(dfd80):
    .byte 0xdf, 0xd8
    retq
.globl S1(dfd81)
S1(dfd81):
    .byte 0xdf, 0xd9
    retq
.globl S1(dfd82)
S1(dfd82):
    .byte 0xdf, 0xda
    retq
.globl S1(dfd83)
S1(dfd83):
    .byte 0xdf, 0xdb
    retq
.globl S1(dfd84)
S1(dfd84):
    .byte 0xdf, 0xdc
    retq
.globl S1(dfd85)
S1(dfd85):
    .byte 0xdf, 0xdd
    retq
.globl S1(dfd86)
S1(dfd86):
    .byte 0xdf, 0xde
    retq
.globl S1(dfd87)
S1(dfd87):
    .byte 0xdf, 0xdf
    retq
#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
