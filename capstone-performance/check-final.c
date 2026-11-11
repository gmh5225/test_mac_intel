#include "utils.h"
#include "arch/X86/X86Mapping.h"
#include "arch/X86/X86InstPrinterCommon.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef x86_reg (*GetRegister)(cs_struct *,unsigned,enum cs_ac_type *);
typedef bool (*GetPair)(unsigned,x86_reg *,enum cs_ac_type *,x86_reg *,enum cs_ac_type *);
typedef const uint8_t *(*GetAccess)(cs_struct *,unsigned,uint64_t *);

static void original(MCInst *mi, GetRegister single, GetPair pair, GetAccess get_access)
{
    cs_x86 *x=&mi->flat_insn->detail->x86;
    enum cs_ac_type ac,ac2;
    x86_reg r=single(mi->csh,mi->Opcode,&ac),r2;
    if (r) {
        memmove(x->operands+1,x->operands,(sizeof(x->operands)-sizeof(x->operands[0])));
        memset(x->operands,0,sizeof(x->operands[0]));
        x->operands[0].type=X86_OP_REG;x->operands[0].reg=r;
        x->operands[0].size=mi->csh->regsize_map[r];x->operands[0].access=ac;
        ++x->op_count;
    } else if(pair(mi->Opcode,&r,&ac,&r2,&ac2)) {
        x->operands[0].type=X86_OP_REG;x->operands[0].reg=r;
        x->operands[0].size=mi->csh->regsize_map[r];x->operands[0].access=ac;
        x->operands[1].type=X86_OP_REG;x->operands[1].reg=r2;
        x->operands[1].size=mi->csh->regsize_map[r2];x->operands[1].access=ac2;x->op_count=2;
    }
    uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE]={0};
    const uint8_t *raw=get_access(mi->csh,mi->Opcode,&x->eflags);
    if(raw) for(unsigned i=0;i<sizeof(access) && raw[i];i++) access[i]=raw[i]==CS_AC_IGNORE?0:raw[i];
    for(unsigned i=0;i<x->op_count && i<sizeof(access);i++) x->operands[i].access=access[i];
    if(!mi->op1_size && r) mi->op1_size=mi->csh->regsize_map[r];
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!lib)return 3;
    GetRegister get_single=(GetRegister)dlsym(lib,"X86_insn_reg_intel_h");
    GetPair get_pair=(GetPair)dlsym(lib,"X86_insn_reg_intel2");
    GetAccess get_access=(GetAccess)dlsym(lib,"X86_get_op_access");
    if(!get_single||!get_pair||!get_access)return 4;
    csh handle; if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK)return 5;
    cs_struct h=*(cs_struct *)handle;
    cs_detail outputs[2]; cs_insn insn[2]={{0}}; MCInst mi[2]={{0}};
    for(unsigned i=0;i<2;i++){insn[i].detail=&outputs[i];mi[i].flat_insn=&insn[i];mi[i].csh=&h;}
    unsigned checks=0;
    for(unsigned cached=0;cached<3;cached++){
        if(cached==1)h.x86_insn_lut=NULL;
        if(cached==2)h.x86_insn_reg_lut=NULL;
        for(unsigned id=0;id<=UINT16_MAX;id++)for(unsigned pattern=0;pattern<3;pattern++){
            unsigned n=pattern?((id+pattern)%8):0;
            memset(outputs,(int)((id+pattern*83)&255),sizeof(outputs));
            for(unsigned i=0;i<2;i++){
                mi[i].Opcode=id;mi[i].op1_size=pattern==2?4:0;
                outputs[i].x86.op_count=(uint8_t)n;
            }
            original(&mi[0],get_single,get_pair,get_access);
            X86_finalize_intel_operands(&mi[1]);
            if(mi[0].op1_size!=mi[1].op1_size || memcmp(&outputs[0],&outputs[1],sizeof(outputs[0]))){
                fprintf(stderr,"id=%u pattern=%u cached=%u\n",id,pattern,cached);return 6;
            }
            checks++;
        }
    }
    printf("Compared %u full detail states and first-operand sizes against original library selectors\n",checks);
    cs_close(&handle);dlclose(lib);return 0;
}
