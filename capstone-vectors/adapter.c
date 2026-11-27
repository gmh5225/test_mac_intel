#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
typedef bool (*iterator)(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
#ifdef REQUEST_NATIVE
iterator const requested_native = X86_disasmIterText;
#endif
bool measure_fixed_iterator(csh h,const uint8_t **p,size_t *n,uint64_t *ip,cs_insn *i) {
    return cs_disasm_iter(h,p,n,ip,i);
}
#ifdef TEST_MAIN
int main(void) {
    csh h; if (cs_open(CS_ARCH_X86, CS_MODE_32, &h)) return 1;
    const uint8_t code[]={0x89,0xd8}; const uint8_t *p=code; size_t n=sizeof(code);
    uint64_t addr=0; cs_insn *i=cs_malloc(h);
    int result=!i || !measure_fixed_iterator(h,&p,&n,&addr,i) || i->size!=2;
    cs_free(i,1);cs_close(&h);return result;
}

#endif
