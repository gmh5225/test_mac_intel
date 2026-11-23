#include "MCInst.h"
#include "arch/X86/X86Mapping.h"
#include <stdint.h>
#include <stdio.h>
#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "arch/X86/X86GenInstrInfo_reduce.inc"
#else
#include "arch/X86/X86GenInstrInfo.inc"
#endif

int main(void) {
    const cs_mode modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
    const unsigned char settings[][4] = {
        {0xf2,0,0,0}, {0xf3,0,0,0}, {0,0x3e,0,0},
        {0xf2,0x3e,0,0}, {0xf3,0x3e,0,0}, {0xf2,0x64,0,0},
        {0xf3,0x3e,0xf3,1}, {0xf2,0x3e,0xf2,0}, {0,0,0,0},
    };
    unsigned long long records = 0;
    for (unsigned m=0;m<3;m++) {
        csh h;
        if (cs_open(CS_ARCH_X86,modes[m],&h)) return 2;
        cs_struct *handle=(cs_struct *)(uintptr_t)h;
        uint32_t *lookup=handle->x86_insn_lut;
        if (!lookup) return 3;
        cs_insn insn={0}; cs_detail detail={0}; insn.detail=&detail;
        MCInst mi={0}; mi.csh=handle; mi.flat_insn=&insn;
        for (unsigned cached=0;cached<2;cached++) {
            handle->x86_insn_lut=cached?lookup:NULL;
            for (unsigned on=0;on<2;on++) {
                if(cs_option(h,CS_OPT_DETAIL,on?CS_OPT_ON:CS_OPT_OFF)) return 4;
                for (unsigned id=0;id<=X86_INSTRUCTION_LIST_END+2;id++)
                    for(unsigned k=0;k<sizeof(settings)/sizeof(settings[0]);k++) {
                        const unsigned char *p=settings[k];
                        mi.Opcode=id;
                        mi.x86_prefix[0]=p[0];mi.x86_prefix[1]=p[1];
                        mi.x86_prefix[2]=0x66;mi.x86_prefix[3]=0x67;
                        mi.xAcquireRelease=p[2];mi.x86Lock=p[3];
                        detail.regs_read_count=1;detail.regs_write_count=2;
                        detail.regs_read[1]=detail.regs_write[2]=0xa55a;
                        memset(detail.x86.prefix,0x5a,sizeof(detail.x86.prefix));
                        SStream ss={0}; ss.buffer[0]='x';ss.index=1;
                        X86_printPrefixes(&mi,&ss);
                        if(ss.index>=40 || detail.regs_read_count>2 || detail.regs_write_count>3) return 5;
                        unsigned char record[56]={0};
                        memcpy(record,ss.buffer,40);record[40]=(unsigned char)ss.index;
                        memcpy(record+41,mi.x86_prefix,4);memcpy(record+45,detail.x86.prefix,4);
                        record[49]=detail.regs_read_count;record[50]=detail.regs_write_count;
                        memcpy(record+51,detail.regs_read+1,2);memcpy(record+53,detail.regs_write+2,2);
                        if(fwrite(record,1,sizeof(record),stdout)!=sizeof(record))return 6;
                        records++;
                    }
            }
        }
        handle->x86_insn_lut=lookup;
        if(cs_close(&h))return 7;
    }
    fprintf(stderr,"%llu prefix records of 56 bytes\n",records);
}
