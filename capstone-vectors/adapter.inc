extern "C" size_t X86_disasmOneText(csh, const uint8_t *, size_t, uint64_t,
                                    cs_insn *) __attribute__((weak));
static inline bool single_text(csh h, const uint8_t **p, size_t *size, uint64_t *ip, cs_insn *insn) {
    const size_t n = X86_disasmOneText(h, *p, *size, *ip, insn);
    if (!n) return false;
    *p += n;
    *size -= n;
    *ip += n;
    return true;
}
