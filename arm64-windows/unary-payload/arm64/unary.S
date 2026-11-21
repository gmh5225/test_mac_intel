.text
.p2align 4
.globl not_2
not_2:
mvn x0,x0
mvn x0,x0
ret
.p2align 4
.globl not_2_narrow
not_2_narrow:
mvn x0,x0
mov w0,w0
mvn x0,x0
ret
.p2align 4
.globl not_3
not_3:
mvn x0,x0
mvn x0,x0
mvn x0,x0
ret
.p2align 4
.globl not_3_narrow
not_3_narrow:
mvn x0,x0
mov w0,w0
mvn x0,x0
mvn x0,x0
ret
.p2align 4
.globl not_4
not_4:
mvn x0,x0
mvn x0,x0
mvn x0,x0
mvn x0,x0
ret
.p2align 4
.globl not_4_narrow
not_4_narrow:
mvn x0,x0
mov w0,w0
mvn x0,x0
mvn x0,x0
mvn x0,x0
ret
.p2align 4
.globl neg_2
neg_2:
neg x0,x0
neg x0,x0
ret
.p2align 4
.globl neg_2_narrow
neg_2_narrow:
neg x0,x0
mov w0,w0
neg x0,x0
ret
.p2align 4
.globl neg_3
neg_3:
neg x0,x0
neg x0,x0
neg x0,x0
ret
.p2align 4
.globl neg_3_narrow
neg_3_narrow:
neg x0,x0
mov w0,w0
neg x0,x0
neg x0,x0
ret
.p2align 4
.globl neg_4
neg_4:
neg x0,x0
neg x0,x0
neg x0,x0
neg x0,x0
ret
.p2align 4
.globl neg_4_narrow
neg_4_narrow:
neg x0,x0
mov w0,w0
neg x0,x0
neg x0,x0
neg x0,x0
ret
.p2align 4
.globl not_then_neg
not_then_neg:
mvn x0,x0
neg x0,x0
ret
.p2align 4
.globl neg_then_not
neg_then_not:
neg x0,x0
mvn x0,x0
ret
