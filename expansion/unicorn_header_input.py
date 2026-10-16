"""Authenticate pinned checkout bytes before bounded native-host corrections."""


def authenticate(original: bytes, committed: bytes) -> None:
    if original not in (committed, committed.replace(b"\n", b"\r\n")):
        raise ValueError("Unicorn header differs from the pinned Git input")


def corrected_header(original: bytes, committed: bytes) -> bytes:
    authenticate(original, committed)
    old = b"#if defined(_WIN64)\n"
    new = b"#if defined(_WIN64) && !defined(__aarch64__)\n"
    if committed.count(old) != 1:
        raise ValueError("unexpected Windows setjmp guard")
    return committed.replace(old, new)


def corrected_handler(original: bytes, committed: bytes) -> bytes:
    authenticate(original, committed)
    old = b"#ifdef _WIN64\n    ptr = closure;"
    if committed.count(old) != 1:
        raise ValueError("unexpected Windows exception closure")
    new = b"""#if defined(__aarch64__)
    /* Windows ARM64: x0 retains PEXCEPTION_POINTERS, x1 receives uc and
     * x16 is the volatile intra-procedure branch register. This leaf tail
     * call preserves sp and lr. See Microsoft's ARM64 ABI conventions. */
    const uint32_t tramp[] = {
        0x58000081, /* ldr x1, [pc + 16] */
        0x580000b0, /* ldr x16, [pc + 20] */
        0xd61f0200, /* br x16 */
        0xd503201f  /* nop: align the two pointer literals */
    };
    memcpy(closure, tramp, sizeof(tramp));
    memcpy(closure + 16, &uc, sizeof(uc));
    memcpy(closure + 24, &handler, sizeof(handler));
    FlushInstructionCache(GetCurrentProcess(), closure, 32);
#elif defined(_WIN64)
    ptr = closure;"""
    return committed.replace(old, new)


def corrected_masks(original: bytes, committed: bytes) -> bytes:
    authenticate(original, committed)
    for shift in (b"s0", b"s1"):
        old = b"0xffffUL << " + shift
        if committed.count(old) != 1:
            raise ValueError("unexpected ARM64 immediate mask")
        committed = committed.replace(old, b"0xffffULL << " + shift)
    return committed
