#include "cs_priv.h"
#include <stdint.h>

uint64_t benchmark_layout[8];

void benchmark_capture(csh value, cs_insn *insn, const uint8_t *input, const void *stack)
{
    const cs_struct *handle = (const cs_struct *)(uintptr_t)value;
    benchmark_layout[0] = (uintptr_t)handle;
    benchmark_layout[1] = (uintptr_t)handle->x86_insn_lut;
    benchmark_layout[2] = (uintptr_t)handle->x86_insn_reg_lut;
    benchmark_layout[3] = (uintptr_t)handle->printer_info;
    benchmark_layout[4] = (uintptr_t)insn;
    benchmark_layout[5] = (uintptr_t)insn->detail;
    benchmark_layout[6] = (uintptr_t)input;
    benchmark_layout[7] = (uintptr_t)stack;
}
