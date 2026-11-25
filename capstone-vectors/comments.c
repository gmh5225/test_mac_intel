#include "arch/Mips/MipsInstPrinter.c"

static void reference(MCInst *MI, SStream *out)
{
    SStream_replc(out, '#', 0);
#ifndef CAPSTONE_MIPS_FINAL_OUTPUT_TRIM
    SStream_trimls(out);
#endif
    if (MI->csh->syntax & CS_OPT_SYNTAX_NO_DOLLAR) {
#ifdef CAPSTONE_MIPS_FINAL_OUTPUT_TRIM
        SStream_trimls(out);
#endif
        char *dollar = strchr(out->buffer, '$');
        if (dollar)
            memmove(dollar, dollar + 1, strlen(dollar + 1) + 1);
    }
}

int main(void)
{
    cs_struct handle = {0};
    MCInst inst = {0};
    inst.csh = &handle;
    unsigned count = 0;
    for (unsigned end = 0; end < SSTREAM_BUF_LEN; ++end) {
        for (unsigned mark = 0; mark <= SSTREAM_BUF_LEN; ++mark) {
            for (unsigned mode = 0; mode < 4; ++mode) {
                SStream x, expected;
                memset(&x, 0, sizeof(x));
                memset(x.buffer, 'r', sizeof(x.buffer));
                x.buffer[0] = mode & 1 ? '\t' : '$';
                x.buffer[1] = ' ';
                x.buffer[(end + 25) % SSTREAM_BUF_LEN] = '$';
                if (mark != SSTREAM_BUF_LEN) x.buffer[mark] = '#';
                x.buffer[end] = 0;
                x.buffer[SSTREAM_BUF_LEN - 1] = 0;
                x.index = mode == 0 ? 0 : mode == 1 ? end : mode == 2 ? sizeof(x.buffer) - 1 : end + 1;
                x.is_closed = (end & 1) != 0;
                x.markup_stream = (end & 2) != 0;
                x.prefixed_by_markup = (mark & 1) != 0;
                x.unsigned_num = (mark & 2) != 0;
                memcpy(&expected, &x, sizeof(x));
                handle.syntax = (mode & 1 ? CS_OPT_SYNTAX_NOREGNAME : 0) |
                                (mode & 2 ? CS_OPT_SYNTAX_NO_DOLLAR : 0);
                reference(&inst, &expected);
                patch_cs_printer(&inst, &x);
                if (memcmp(&x, &expected, sizeof(x))) return 1;
                ++count;
            }
        }
    }
    /* The original replacement leaves the last byte alone even if it is '#'. */
    SStream x = {0};
    memset(x.buffer, 'a', sizeof(x.buffer));
    x.buffer[sizeof(x.buffer) - 1] = '#';
    x.index = sizeof(x.buffer) - 1;
    handle.syntax = 0;
    patch_cs_printer(&inst, &x);
    if (x.buffer[sizeof(x.buffer) - 1] != '#') return 2;
    printf("%u\n", count + 1);
}
