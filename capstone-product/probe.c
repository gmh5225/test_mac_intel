/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

struct move_form {
    uint8_t head[5], size, memory_size;
    x86_insn id;
    bool store, wide_only;
};

static const struct move_form forms[] = {
{ { 0x0f, 0x6e }, 2, 4, X86_INS_MOVD, false, false },
{ { 0x0f, 0x7e }, 2, 4, X86_INS_MOVD, true, false },
{ { 0x0f, 0x6f }, 2, 8, X86_INS_MOVQ, false, false },
{ { 0x0f, 0x7f }, 2, 8, X86_INS_MOVQ, true, false },
{ { 0x48, 0x0f, 0x6e }, 3, 8, X86_INS_MOVQ, false, true },
{ { 0x48, 0x0f, 0x7e }, 3, 8, X86_INS_MOVQ, true, true },
{ { 0x66, 0x0f, 0x6e }, 3, 4, X86_INS_MOVD, false, false },
{ { 0x66, 0x0f, 0x7e }, 3, 4, X86_INS_MOVD, true, false },
{ { 0x66, 0x48, 0x0f, 0x6e }, 4, 8, X86_INS_MOVQ, false, true },
{ { 0x66, 0x48, 0x0f, 0x7e }, 4, 8, X86_INS_MOVQ, true, true },
{ { 0xf3, 0x0f, 0x7e }, 3, 8, X86_INS_MOVQ, false, false },
{ { 0x66, 0x0f, 0xd6 }, 3, 8, X86_INS_MOVQ, true, false },
{ { 0xc5, 0xf9, 0x6e }, 3, 4, X86_INS_VMOVD, false, false },
{ { 0xc5, 0xf9, 0x7e }, 3, 4, X86_INS_VMOVD, true, false },
{ { 0xc5, 0xfa, 0x7e }, 3, 8, X86_INS_VMOVQ, false, false },
{ { 0xc5, 0xf9, 0xd6 }, 3, 8, X86_INS_VMOVQ, true, false },
{ { 0xc4, 0xe1, 0x79, 0x6e }, 4, 4, X86_INS_VMOVD, false, false },
{ { 0xc4, 0xe1, 0x79, 0x7e }, 4, 4, X86_INS_VMOVD, true, false },
{ { 0xc4, 0xe1, 0xf9, 0x6e }, 4, 8, X86_INS_VMOVQ, false, true },
{ { 0xc4, 0xe1, 0xf9, 0x7e }, 4, 8, X86_INS_VMOVQ, true, true },
{ { 0xc4, 0xe1, 0x7a, 0x7e }, 4, 8, X86_INS_VMOVQ, false, false },
{ { 0xc4, 0xe1, 0x79, 0xd6 }, 4, 8, X86_INS_VMOVQ, true, false },
{ { 0x62, 0xf1, 0x7d, 0x08, 0x6e }, 5, 4, X86_INS_VMOVD, false, false },
{ { 0x62, 0xf1, 0x7d, 0x08, 0x7e }, 5, 4, X86_INS_VMOVD, true, false },
{ { 0x62, 0xf1, 0xfd, 0x08, 0x6e }, 5, 8, X86_INS_VMOVQ, false, true },
{ { 0x62, 0xf1, 0xfd, 0x08, 0x7e }, 5, 8, X86_INS_VMOVQ, true, true },
{ { 0x62, 0xf1, 0xfe, 0x08, 0x7e }, 5, 8, X86_INS_VMOVQ, false, false },
{ { 0x62, 0xf1, 0xfd, 0x08, 0xd6 }, 5, 8, X86_INS_VMOVQ, true, false },
};

int main(void)
{
    const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
    unsigned cases=0, bad_access=0, bad_shape=0;
    for(unsigned m=0; m<3; ++m) {
        csh h;
        if(cs_open(CS_ARCH_X86,modes[m],&h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 3;
        for(unsigned att=0; att<2; ++att) {
            cs_err err=cs_option(h,CS_OPT_SYNTAX,att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
            if(att && err==CS_ERR_X86_ATT) continue;
            if(err) return 4;
            for(unsigned i=0;i<sizeof(forms)/sizeof(forms[0]);++i) {
                const struct move_form *f=&forms[i];
                if(m!=2 && f->wide_only)continue;
                if(m==0 && f->head[0]==0x66)continue;
                unsigned errors=0, shape=0, rejected=0;
                for(unsigned mod=0;mod<3;++mod) {
                    for(unsigned reg=0;reg<8;++reg) {
                        uint8_t bytes[12];
                        memcpy(bytes,f->head,f->size);
                        bytes[f->size]=(uint8_t)((mod<<6)|(reg<<3)|3);
                        unsigned n=f->size+1, disp=mod==0?0:mod==1?1:m==0?2:4;
                        memset(bytes+n,0x39,disp);n+=disp;
                        cs_insn *insn=NULL;
                        if(cs_disasm(h,bytes,n,0x1000,1,&insn)!=1) { ++rejected; ++cases; continue; }
                        const cs_x86 *x=&insn->detail->x86;
                        const unsigned mi=(att!=0)==f->store;
                        const cs_x86_op *mem=&x->operands[mi], *other=&x->operands[1-mi];
                        if(insn->size!=n || insn->id!=f->id || x->op_count!=2 || mem->type!=X86_OP_MEM || mem->size!=f->memory_size || other->type!=X86_OP_REG) {
                            if(!shape)fprintf(stderr,"shape %u bits %u att %u: %s %s id %u width %u count %u\n",i,16u<<m,att,insn->mnemonic,insn->op_str,insn->id,mem->size,x->op_count);
                            ++shape;
                        }
                        if(mem->access!=(f->store?CS_AC_WRITE:CS_AC_READ) || other->access!=(f->store?CS_AC_READ:CS_AC_WRITE))++errors;
                        ++cases;cs_free(insn,1);
                    }
                }
                if(errors)fprintf(stderr,"form %u bits %u att %u: %u access mismatches\n",i,16u<<m,att,errors);
                if(rejected)fprintf(stderr,"decode %u bits %u att %u: %u rejected\n",i,16u<<m,att,rejected);
                bad_access+=errors;bad_shape+=shape+rejected;
            }
        }
        cs_close(&h);
    }
    printf("%u encodings and syntax cases, %u incorrect memory accesses, %u incorrect shapes\n",cases,bad_access,bad_shape);
    return bad_access || bad_shape;
}
