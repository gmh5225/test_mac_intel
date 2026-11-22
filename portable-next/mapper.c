#include "arch/X86/X86Mapping.h"
#include <stdio.h>
#include <string.h>
#define GET_INSTRINFO_ENUM
#include "arch/X86/X86GenInstrInfo.inc"
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
int main(void) {
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 6;
#endif
    cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
    unsigned count=0;
    for(unsigned m=0;m<3;++m) {
        csh h; if(cs_open(CS_ARCH_X86,modes[m],&h)||cs_option(h,CS_OPT_DETAIL,CS_OPT_ON))return 2;
        cs_struct *s=(cs_struct *)(uintptr_t)h;
        uint32_t *cache=s->x86_insn_lut;
        if(!cache)return 3;
        for(unsigned use=0;use<2;++use) {
            s->x86_insn_lut=use?cache:NULL;
            for(unsigned fill=0;fill<2;++fill) for(unsigned id=0;id<=X86_INSTRUCTION_LIST_END;++id) {
                cs_insn out={0};cs_detail d;
                memset(&d,fill?0x5a:0,sizeof d);
                d.x86.addr_size=fill?2:8;
                out.id=~(unsigned)0;out.detail=&d;X86_get_insn_id(s,&out,id);out.detail=NULL;
                if(fwrite(&out,1,sizeof out,stdout)!=sizeof out||fwrite(&d,1,sizeof d,stdout)!=sizeof d)return 4;
                ++count;
            }
        }
        s->x86_insn_lut=cache;
        if(cs_close(&h))return 5;
    }
    fprintf(stderr,"%u mapped records of %zu bytes\n",count,sizeof(cs_detail)+sizeof(cs_insn));
}
