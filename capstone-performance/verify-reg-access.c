#include <capstone/capstone.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

struct api {
    __typeof__(&cs_regs_access) access;
    csh handle;
};
static int load_api(struct api *a, const char *file)
{
    void *m = dlopen(file, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!m) return 1;
    __typeof__(&cs_open) openfn = dlsym(m, "cs_open");
    __typeof__(&cs_option) optfn = dlsym(m, "cs_option");
    a->access = dlsym(m, "cs_regs_access");
    return !openfn || !optfn || !a->access ||
           openfn(CS_ARCH_X86, CS_MODE_64, &a->handle) != CS_ERR_OK ||
           optfn(a->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK;
}
static uint32_t state = 0xb754d139;
static uint32_t pick(void) {
    state ^= state << 13; state ^= state >> 17; state ^= state << 5;
    return state;
}
static unsigned reg(void) {
    const unsigned choices[] = {0, 1, 2, 3, 4, 5, 8, 9, 17, 64, 65, 512, 65535, 65536, 65537};
    return choices[pick() % (sizeof(choices) / sizeof(*choices))];
}
int main(int argc, char **argv)
{
    struct api a[2];
    if (argc!=3 || load_api(a,argv[1]) || load_api(a+1,argv[2]) || a[0].access==a[1].access) return 1;
    for (unsigned n=0;n<750000;n++) {
        cs_detail d={0}; cs_insn in={0};
        in.id=1;in.detail=&d;
        d.regs_read_count=pick()%(1+sizeof(d.regs_read)/sizeof(*d.regs_read));
        d.regs_write_count=pick()%(1+sizeof(d.regs_write)/sizeof(*d.regs_write));
        for (unsigned i=0;i<d.regs_read_count;i++) d.regs_read[i]=reg();
        for (unsigned i=0;i<d.regs_write_count;i++) d.regs_write[i]=reg();
        d.x86.op_count=pick()%(1+sizeof(d.x86.operands)/sizeof(*d.x86.operands));
        for(unsigned i=0;i<d.x86.op_count;i++) {
            cs_x86_op *o=&d.x86.operands[i];
            switch(pick()%4) {
            case 0: case 1: o->type=X86_OP_REG;o->reg=(x86_reg)reg();o->access=pick()%4;break;
            case 2: o->type=X86_OP_MEM;o->mem.segment=(x86_reg)reg();o->mem.base=(x86_reg)reg();o->mem.index=(x86_reg)reg();break;
            default:o->type=X86_OP_IMM;break;
            }
        }
        if (n%3) {
            d.regs_read_count=0;
            d.regs_write_count=n%3==2 ? pick()%3 : 0;
            d.x86.op_count=2;
            cs_x86_op *first=&d.x86.operands[0],*second=&d.x86.operands[1];
            first->type=X86_OP_REG;first->access=CS_AC_WRITE;first->reg=(x86_reg)reg();
            switch(pick()%3) {
            case 0:second->type=X86_OP_REG;second->access=CS_AC_READ;second->reg=(x86_reg)reg();break;
            case 1:second->type=X86_OP_IMM;break;
            case 2:second->type=X86_OP_MEM;second->mem.segment=(pick()&1)?X86_REG_INVALID:(x86_reg)reg();second->mem.base=(x86_reg)reg();second->mem.index=(pick()&1)?X86_REG_INVALID:(x86_reg)reg();break;
            }
        }
        uint16_t dest[2][128];
        unsigned offsets[]={0,1,2,7,32,64},wo=offsets[n%6];
        uint8_t counts[2][2];memset(counts,0x6b,sizeof(counts));memset(dest,0xa5,sizeof(dest));
        for(unsigned i=0;i<2;i++) {
            if (a[i].access(a[i].handle,&in,dest[i],&counts[i][0],dest[i]+wo,&counts[i][1])) return 2;
        }
        if (memcmp(dest[0],dest[1],sizeof(dest[0])) || memcmp(counts[0],counts[1],sizeof(counts[0]))) {
            fprintf(stderr,"case %u, offset %u\n",n,wo);return 3;
        }
    }
    puts("750000 overlapping and disjoint register lists matched, including untouched output tails");return 0;
}
