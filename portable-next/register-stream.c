#include "arch/RISCV/RISCVInstPrinter.c"

int main(void)
{
    uint64_t matches=0;
    for (unsigned numeric=0;numeric<2;++numeric) {
        ArchRegNames=numeric!=0;
        for (unsigned bank=0;bank<4;++bank) for(unsigned i=0;i<32;++i) {
            const unsigned first[]={RISCV_X0,RISCV_F0_F,RISCV_F0_D,RISCV_V0};
            const unsigned reg=first[bank]+i;
            const char *name=getRegisterName(reg,numeric?RISCV_NoRegAltName:RISCV_ABIRegAltName);
            if (!name || !name[0]) return 2;
            if (bank==0 && strlen(name)<2) return 4;
            for(unsigned flags=0;flags<16;++flags) for(unsigned n=0;n<SSTREAM_BUF_LEN+3;++n) {
                SStream ref,now;
                memset(&ref,0xa5,sizeof(ref));
                ref.is_closed=(flags&1)!=0;ref.markup_stream=(flags&2)!=0;
                ref.prefixed_by_markup=(flags&4)!=0;ref.unsigned_num=(flags&8)!=0;
                ref.index=n==SSTREAM_BUF_LEN+2?SIZE_MAX:n;
                if(ref.index<SSTREAM_BUF_LEN)ref.buffer[ref.index]='\0';
                now=ref;
                (SStream_concat0)(markup_OS(&ref,Markup_Register),name);
                printRegName(&now,reg);
                if(memcmp(&ref,&now,sizeof(now))!=0){
                    fprintf(stderr,"reg=%u flags=%u cursor=%u numeric=%u\n",reg,flags,n,numeric);return 3;
                }
                ++matches;
            }
        }
    }
    printf("%llu\n",(unsigned long long)matches);
    return 0;
}
