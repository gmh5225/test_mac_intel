"""Authenticate checkout line endings before changing the host ABI guard."""


def corrected_header(original: bytes, committed: bytes) -> bytes:
    if original not in (committed, committed.replace(b"\n", b"\r\n")):
        raise ValueError("Unicorn header differs from the pinned Git input")
    old = b"#if defined(_WIN64)\n"
    new = b"#if defined(_WIN64) && !defined(__aarch64__)\n"
    if committed.count(old) != 1:
        raise ValueError("unexpected Windows setjmp guard")
    return committed.replace(old, new)
