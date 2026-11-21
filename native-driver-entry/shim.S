.text
.p2align 2
.globl original_shim
original_shim:
    .incbin "init-shim.bin"
.org original_shim + 0x38
    b neverd_cookie
.org original_shim + 0x70
    b neverd_driver_entry

.globl neverd_cookie
neverd_cookie:
    mov x0, xzr
    mov x1, xzr
    ret

.globl neverd_driver_entry
neverd_driver_entry:
    adrp x8, observed
    add x8, x8, :lo12:observed
    stp x0, x1, [x8]
    adrp x8, desired_status
    ldr w0, [x8, :lo12:desired_status]
    ret
