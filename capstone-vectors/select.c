#include "cs_priv.h"
#include "arch/X86/X86Mapping.h"
#include <stdlib.h>

cs_err __real_cs_open(cs_arch, cs_mode, csh *);

cs_err __wrap_cs_open(cs_arch arch, cs_mode mode, csh *out)
{
    cs_err err = __real_cs_open(arch, mode, out);
    if (err != CS_ERR_OK || arch != CS_ARCH_X86)
        return err;
    cs_struct *handle = (cs_struct *)(uintptr_t)*out;
    if (handle->reg_access != X86_reg_access_short)
        abort();
    const char *choice = getenv("CS_BENCH_CALLBACK");
    if (!choice || !choice[0] || choice[1])
        abort();
    switch (choice[0]) {
    case '0':
    case '2':
        handle->reg_access = X86_reg_access;
        break;
    case '1':
    case '3':
        break;
    default:
        abort();
    }
    return CS_ERR_OK;
}
