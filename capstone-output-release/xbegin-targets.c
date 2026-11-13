#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const unsigned modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_64|CS_MODE_X86_INTEL, CS_MODE_64|CS_MODE_X86_AMD};
    const unsigned syntaxes[] = {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT, CS_OPT_SYNTAX_MASM};
    const uint32_t values[] = {0,1,9,10,0x7fff,0x8000,0xffff,0x12348000,0x80000000,0xffffffff};
    const uint64_t pcs[]={0, 0xfffd, 0x123450000, UINT64_MAX-2};
    unsigned checked=0, errors=0;
    for(size_t m=0; m<sizeof(modes)/sizeof(modes[0]);++m) {
        csh h;
        if(cs_open(CS_ARCH_X86,(cs_mode)modes[m],&h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 2;
        cs_insn *i=cs_malloc(h);
        if(!i) return 2;
        bool wide=(modes[m]&CS_MODE_64)!=0;
        for(size_t sy=0; sy<3; ++sy) {
            if(cs_option(h,CS_OPT_SYNTAX,syntaxes[sy])) continue;
            for(unsigned prefixes=0; prefixes<(wide?16u:4u); ++prefixes) {
                uint8_t bytes[10];
                unsigned offset=0;
                if(prefixes&1)bytes[offset++]=0x66;
                if(prefixes&2)bytes[offset++]=0x67;
                if(prefixes&4)bytes[offset++]=0x40|((prefixes&8)?8:0);
                bytes[offset++]=0xc7;bytes[offset++]=0xf8;
                bool rel16=((modes[m]==CS_MODE_16) != ((prefixes&1)!=0)) && (prefixes&12)!=12;
                unsigned width=rel16?2:4;
                for(size_t v=0;v<sizeof(values)/sizeof(values[0]);++v) {
                    for(unsigned n=0;n<width;++n) bytes[offset+n]=(uint8_t)(values[v]>>(8*n));
                    int64_t delta=rel16?(int16_t)values[v]:(int32_t)values[v];
                    for(size_t a=0; a<4; ++a) {
                        const uint8_t *cur=bytes;
                        size_t n=offset+width;
                        uint64_t pc=pcs[a];
                        uint64_t target=(pc+n+(uint64_t)delta)&(wide?UINT64_MAX:UINT32_MAX);
                        bool ok=cs_disasm_iter(h,&cur,&n,&pc,i);
                        cs_x86 *x=&i->detail->x86;
                        bool mismatch=!ok||n||cur!=bytes+offset+width||i->id!=X86_INS_XBEGIN||x->op_count!=1||x->operands[0].type!=X86_OP_IMM||(uint64_t)x->operands[0].imm!=target||x->encoding.imm_offset!=offset||x->encoding.imm_size!=width;
                        if(mismatch && errors<12) fprintf(stderr,"mode=%u syntax=%u prefixes=%x bits=%08x at=%" PRIx64 " expected=%" PRIx64 " got=%" PRIx64 " text='%s' len=%u width=%u\n",modes[m],syntaxes[sy],prefixes,values[v],pcs[a],target,(uint64_t)x->operands[0].imm,i->op_str,i->size,x->encoding.imm_size);
                        errors+=mismatch; ++checked;
                    }
                }
            }
        }
        cs_free(i,1);cs_close(&h);
    }
    printf("XBEGIN public record cases=%u failures=%u\n",checked,errors);
    return errors!=0;
}
