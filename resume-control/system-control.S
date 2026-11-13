.text
.globl _caller
_caller:
 pacibsp
 stp x29,x30,[sp,#-32]!
 mov x29,sp
 str d8,[sp,#16]
 bl Lcallee
Lresumed:
 umov x9,v8.d[0]
 cmp x9,#0x331
 mov x10,#0x3311
 cmp x9,x10
 b.ne Lbad
 umov x9,v8.d[1]
 mov x10,#0x7722
 cmp x9,x10
 b.eq Ldone
Lbad:
 mov x0,#4
Ldone:
 ldr d8,[sp,#16]
 ldp x29,x30,[sp],#32
 retab
Lcallee:
 pacibsp
 sub sp,sp,#16
 adrp x9,_captured_lr@PAGE
 str x30,[x9,_captured_lr@PAGEOFF]
 brk #1
 mov x0,#9
 add sp,sp,#16
 retab
.globl _control_pc
_control_pc:
 adr x0,Lresumed
 ret
.globl _captured_lr
.zerofill __DATA,__bss,_captured_lr,8,3
