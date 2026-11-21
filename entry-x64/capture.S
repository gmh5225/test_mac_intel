.text
.intel_syntax noprefix
.globl capture_and_forward
capture_and_forward:
    mov rax, qword ptr [rsp+40]
    mov r10, qword ptr [rsp+48]
    mov qword ptr [r10], rcx
    mov qword ptr [r10+8], rdx
    mov qword ptr [r10+16], r8
    mov qword ptr [r10+24], r9
    mov qword ptr [r10+32], rsp
    mov r11, qword ptr [rsp]
    mov qword ptr [r10+40], r11
    jmp rax
