#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const x86_insn ids[] = { X86_INS_KMOVB, X86_INS_KMOVW, X86_INS_KMOVD, X86_INS_KMOVQ };
    const unsigned payload[] = { 0x79, 0x78, 0xf9, 0xf8 };
    const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
    unsigned cases = 0, incorrect_access = 0;
    for (unsigned m = 0; m < 3; ++m) {
        csh handle;
        if (cs_open(CS_ARCH_X86, modes[m], &handle) || cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
            return 3;
        for (unsigned att = 0; att < 2; ++att) {
            cs_err err=cs_option(handle, CS_OPT_SYNTAX, att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
            if (att && err == CS_ERR_X86_ATT) continue;
            if (err) return 4;
            for (unsigned k=0; k<4; ++k)
            for (unsigned short_vex=0; short_vex<=(k<2); ++short_vex)
            for (unsigned mod=0; mod<3; ++mod)
            for (unsigned mask=0; mask<8; ++mask)
            for (unsigned store=0; store<2; ++store) {
                uint8_t code[12], *p=code;
                if (short_vex) { *p++=0xc5; *p++=0x80|payload[k]; }
                else { *p++=0xc4; *p++=0xe1; *p++=payload[k]; }
                *p++=0x90+store; *p++=(uint8_t)((mod<<6)|(mask<<3)|3);
                const unsigned disp=mod==0?0:mod==1?1:m==0?2:4;
                memset(p, 0x9f, disp); p+=disp;
                cs_insn *insn=NULL;
                if (cs_disasm(handle,code,p-code,0x1000,1,&insn)!=1) return 5;
                const cs_x86 *x=&insn->detail->x86;
                const cs_x86_op *mem=&x->operands[(att!=0)==(store!=0)], *reg=&x->operands[(att!=0)!=(store!=0)];
                if (insn->id!=ids[k] || insn->size!=p-code || x->op_count!=2 || mem->type!=X86_OP_MEM || mem->size!=(1u<<k) || reg->type!=X86_OP_REG || reg->reg!=(x86_reg)(X86_REG_K0+mask) || reg->access!=(store?CS_AC_READ:CS_AC_WRITE)) {
                    fprintf(stderr,"shape %u %u %u %u %s %s\n",m,att,k,store,insn->mnemonic,insn->op_str);return 6;
                }
                if (mem->access!=(store?CS_AC_WRITE:CS_AC_READ)) {
                    ++incorrect_access;
                    if (incorrect_access<=4)printf("%s %s: memory access %u expected %u\n",insn->mnemonic,insn->op_str,mem->access,store?CS_AC_WRITE:CS_AC_READ);
                }
                ++cases; cs_free(insn,1);
            }
        }
        cs_close(&handle);
    }
    printf("%u encodings and syntax cases, %u incorrect memory accesses\n",cases,incorrect_access);
    return incorrect_access!=0;
}
