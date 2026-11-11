#include "cs_priv.h"
#include "arch/X86/X86Mapping.h"
#include <stdlib.h>
void dense_X86_get_insn_id(cs_struct *, cs_insn *, unsigned int);
static void (*selected)(cs_struct *, cs_insn *, unsigned int);
void choose_mapping(void) {
    const char *variant = getenv("CAPSTONE_MAPPING_VARIANT");
    selected = variant && variant[0] == 'n' ? dense_X86_get_insn_id : X86_get_insn_id;
}
void bind_mapping(csh h) {
    cs_struct *handle = (cs_struct *)(uintptr_t)h;
    if (handle->insn_id != X86_get_insn_id || !selected) abort();
    handle->insn_id = selected;
}
