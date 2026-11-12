#include "cs_priv.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static csh spare;
static uint32_t *original, *original_regs;
static unsigned policy;
static void *forward(size_t bytes) { return malloc(bytes); }
static cs_err open_with_policy(cs_mode mode, bool shared, csh *handle)
{
    cs_malloc_t saved = cs_mem_malloc;
    if (!shared) cs_mem_malloc = forward;
    cs_err err = cs_open(CS_ARCH_X86, mode, handle);
    cs_mem_malloc = saved;
    if (err == CS_ERR_OK && ((cs_struct *)(uintptr_t)*handle)->x86_shared_lookups != shared)
        abort();
    return err;
}
cs_err storage_open(cs_mode mode, csh *handle)
{
    const char *v=getenv("LOOKUP_POLICY");
    if (!v || v[0]<'0' || v[0]>'3' || v[1]) abort();
    policy=(unsigned)(v[0]-'0');
    return open_with_policy(mode,policy>=2,handle);
}
void storage_bind(csh handle, cs_mode mode, cs_insn *insn, uintptr_t *addresses)
{
    cs_struct *h=(cs_struct *)(uintptr_t)handle;
    if (open_with_policy(mode,policy<2,&spare)!=CS_ERR_OK) abort();
    cs_struct *other=(cs_struct *)(uintptr_t)spare;
    size_t bytes=((size_t)h->x86_insn_lut_max+1)*sizeof(uint32_t);
    original=h->x86_insn_lut; original_regs=h->x86_insn_reg_lut;
    if(h->x86_insn_lut_max!=other->x86_insn_lut_max ||
       memcmp(original,other->x86_insn_lut,bytes) ||
       memcmp(original_regs,other->x86_insn_reg_lut,bytes)) abort();
    if((policy>=2)!=(bool)(policy&1)){
        h->x86_insn_lut=other->x86_insn_lut;
        h->x86_insn_reg_lut=other->x86_insn_reg_lut;
    }
    addresses[0]=(uintptr_t)h->x86_insn_lut&65535;
    addresses[1]=(uintptr_t)h->x86_insn_reg_lut&65535;
    addresses[2]=(uintptr_t)h&65535;
    addresses[3]=(uintptr_t)insn&65535;
    addresses[4]=(uintptr_t)insn->detail&65535;
}
void storage_restore(csh handle)
{
    cs_struct *h=(cs_struct *)(uintptr_t)handle;
    h->x86_insn_lut=original; h->x86_insn_reg_lut=original_regs;
    if(cs_close(&spare)!=CS_ERR_OK) abort();
}
