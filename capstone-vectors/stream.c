#include "arch/Mips/MipsInstPrinter.c"

static unsigned callback_count;
static int observe(char *dst, size_t size, const char *format, va_list args)
{
    ++callback_count;
    return vsnprintf(dst, size, format, args);
}

int main(void)
{
    uint64_t matches = 0;
    unsigned callbacks = 0;
    cs_struct handle = { 0 };
    MCInst inst = { 0 };
    inst.csh = &handle;
    cs_vsnprintf_t saved = cs_vsnprintf;
    for (unsigned custom = 0; custom < 2; ++custom) {
        cs_vsnprintf = custom ? observe : saved;
        for (unsigned syntax = 0; syntax < 4; ++syntax) {
            handle.syntax = (syntax & 1 ? CS_OPT_SYNTAX_NOREGNAME : 0)
                          | (syntax & 2 ? CS_OPT_SYNTAX_NO_DOLLAR : 0);
            for (unsigned reg = 1; reg < MIPS_REG_ENDING; ++reg) {
                const char *name = Mips_LLVM_getRegisterName(reg, syntax & 1);
                if (!name) return 3;
                for (unsigned flags = 0; flags < 16; ++flags) {
                    const size_t offsets[] = {0, 1, 7, 32, SSTREAM_BUF_LEN - 8,
                        SSTREAM_BUF_LEN - 7, SSTREAM_BUF_LEN - 6, SSTREAM_BUF_LEN - 5,
                        SSTREAM_BUF_LEN - 4, SSTREAM_BUF_LEN - 3, SSTREAM_BUF_LEN - 2,
                        SSTREAM_BUF_LEN - 1, SSTREAM_BUF_LEN, SIZE_MAX};
                    for (unsigned i = 0; i < ARR_SIZE(offsets); ++i) {
                        SStream expected, actual;
                        memset(&expected, 0xa5, sizeof expected);
                        expected.is_closed = !!(flags & 1);
                        expected.markup_stream = !!(flags & 2);
                        expected.prefixed_by_markup = !!(flags & 4);
                        expected.unsigned_num = !!(flags & 8);
                        expected.index = offsets[i];
                        if (expected.index < SSTREAM_BUF_LEN) expected.buffer[expected.index] = 0;
                        memcpy(&actual, &expected, sizeof actual);
                        callback_count = 0;
                        if (!(syntax & 2)) SStream_concat1(&expected, '$');
                        (SStream_concat0)(&expected, name);
                        const unsigned reference_calls = callback_count;
                        callback_count = 0;
                        printRegName(&inst, &actual, reg);
                        if (memcmp(&expected, &actual, sizeof actual) || callback_count != reference_calls) {
                            fprintf(stderr, "reg %u syntax %u state %u offset %zu custom %u\n",
                                    reg, syntax, flags, offsets[i], custom);
                            return 5;
                        }
                        ++matches;
                        callbacks += callback_count;
                    }
                }
            }
        }
    }
    cs_vsnprintf = saved;
    printf("%llu %u\n", (unsigned long long)matches, callbacks);
    return 0;
}
