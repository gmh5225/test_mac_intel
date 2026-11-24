#include "cs_priv.h"
#include <stdio.h>
#include <stdlib.h>

typedef CS_PRESERVE_MOST bool Read(cs_struct *, const uint8_t *, size_t,
                                   cs_insn *, uint16_t *, bool);
extern Read original_a, original_b, late_a, late_b, measured_probe;
static Read *selected;
unsigned long long reader_entries, admission_checks, group_ff, register_hits;
static void report(void)
{
    fprintf(stderr, "%llu %llu %llu %llu\n", reader_entries, admission_checks,
            group_ff, register_hits);
}
void choose_reader(unsigned i)
{
    static Read *const functions[] = { original_a, original_b, late_a, late_b, measured_probe };
    if (i >= sizeof(functions)/sizeof(functions[0])) abort();
    selected = functions[i];
    if (i == 4) atexit(report);
}
CS_PRESERVE_MOST bool __wrap_X86_decodeRegisterFallback32(cs_struct *handle,
    const uint8_t *code, size_t size, cs_insn *insn, uint16_t *length, bool batch)
{
    return selected(handle, code, size, insn, length, batch);
}
