.text
.intel_syntax noprefix
.globl forward_4
.seh_proc forward_4
forward_4:
    sub rsp, 40
    .seh_stackalloc 40
    .seh_endprologue
    call read_cpu_leaf
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    call consume_four
    add rsp, 40
    ret
.seh_endproc
.globl read_cpu_leaf
.seh_proc read_cpu_leaf
read_cpu_leaf:
    push rbx
    .seh_pushreg rbx
    .seh_endprologue
    xor eax, eax
    cpuid
    pop rbx
    ret
.seh_endproc
