#include <stdlib.h>
#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
typedef void Writer(const uint8_t *, cs_insn *, uint16_t *, uint8_t,
                    const struct X86SimpleOutput *, const struct X86SimpleRegister *);
extern Writer __real_X86_writeImmediateOutput, measure_digits, measure_details;
static Writer *selected;
static void detected(const uint8_t *code, cs_insn *insn, uint16_t *length, uint8_t rex,
                     const struct X86SimpleOutput *row, const struct X86SimpleRegister *reg) { _Exit(73); }
void measure_select_scalar(int i) {
    Writer *const variants[] = {__real_X86_writeImmediateOutput, measure_digits, measure_details, detected};
    if ((unsigned)i >= 4) abort();
    selected=variants[i];
}
void __wrap_X86_writeImmediateOutput(const uint8_t *code, cs_insn *insn, uint16_t *length, uint8_t rex,
                                     const struct X86SimpleOutput *row, const struct X86SimpleRegister *reg) {
    selected(code,insn,length,rex,row,reg);
}
