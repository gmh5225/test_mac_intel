.text
.p2align 4
.globl not_2
not_2:
movq %rcx, %rax
notq %rax
notq %rax
ret
.p2align 4
.globl not_2_narrow
not_2_narrow:
movq %rcx, %rax
notq %rax
movl %eax,%eax
notq %rax
ret
.p2align 4
.globl not_3
not_3:
movq %rcx, %rax
notq %rax
notq %rax
notq %rax
ret
.p2align 4
.globl not_3_narrow
not_3_narrow:
movq %rcx, %rax
notq %rax
movl %eax,%eax
notq %rax
notq %rax
ret
.p2align 4
.globl not_4
not_4:
movq %rcx, %rax
notq %rax
notq %rax
notq %rax
notq %rax
ret
.p2align 4
.globl not_4_narrow
not_4_narrow:
movq %rcx, %rax
notq %rax
movl %eax,%eax
notq %rax
notq %rax
notq %rax
ret
.p2align 4
.globl neg_2
neg_2:
movq %rcx, %rax
negq %rax
negq %rax
ret
.p2align 4
.globl neg_2_narrow
neg_2_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
ret
.p2align 4
.globl neg_3
neg_3:
movq %rcx, %rax
negq %rax
negq %rax
negq %rax
ret
.p2align 4
.globl neg_3_narrow
neg_3_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
negq %rax
ret
.p2align 4
.globl neg_4
neg_4:
movq %rcx, %rax
negq %rax
negq %rax
negq %rax
negq %rax
ret
.p2align 4
.globl neg_4_narrow
neg_4_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
negq %rax
negq %rax
ret
.p2align 4
.globl not_then_neg
not_then_neg:
movq %rcx, %rax
notq %rax
negq %rax
ret
.p2align 4
.globl neg_then_not
neg_then_not:
movq %rcx, %rax
negq %rax
notq %rax
ret
.p2align 4
.globl neg_2_flags
neg_2_flags:
movq %rcx, %rax
negq %rax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
.p2align 4
.globl neg_2_flags_narrow
neg_2_flags_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
.p2align 4
.globl neg_3_flags
neg_3_flags:
movq %rcx, %rax
negq %rax
negq %rax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
.p2align 4
.globl neg_3_flags_narrow
neg_3_flags_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
.p2align 4
.globl neg_4_flags
neg_4_flags:
movq %rcx, %rax
negq %rax
negq %rax
negq %rax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
.p2align 4
.globl neg_4_flags_narrow
neg_4_flags_narrow:
movq %rcx, %rax
negq %rax
movl %eax,%eax
negq %rax
negq %rax
negq %rax
pushfq
popq %rdx
andl $0x801,%edx
xorq %rdx,%rax
ret
