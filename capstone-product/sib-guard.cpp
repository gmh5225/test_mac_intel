#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool observed_sib(csh,const uint8_t *,size_t,cs_insn *,uint16_t *);
int main() {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *area = static_cast<uint8_t *>(mmap(nullptr,page*2,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANON,-1,0));
    if (area==MAP_FAILED || mprotect(area+page,page,PROT_NONE)) return 1;
    uint64_t tried=0, accepted_index=0, accepted_without=0;
    const std::array<std::array<uint8_t,2>,18> forms{{
        {0,0x8d},{0,0x89},{0,0x8b},{0,0x8a},{0,0x88},{0,0x01},{0,0x03},
        {0,0x85},{0,0xff},{0,0x83},{0,0x81},{0,0x80},{0x64,0x8d},{0x2e,0x8d},
        {0x0f,0xb7},{0x0f,0xbe},{0,0xc7},{0,0xc6}
    }};
    for (unsigned detail : {0,1}) {
        csh fast=0,ordinary=0;cs_opt_mnem neutral{X86_INS_UD2,"ud2"};
        if (cs_open(CS_ARCH_X86,CS_MODE_32,&fast) || cs_open(CS_ARCH_X86,CS_MODE_32,&ordinary) ||
            cs_option(ordinary,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&neutral)))return 2;
        if (detail && (cs_option(fast,CS_OPT_DETAIL,CS_OPT_ON) ||
                       cs_option(ordinary,CS_OPT_DETAIL,CS_OPT_ON)))return 2;
        for (auto form:forms) for(unsigned sib=0;sib<256;++sib)
        for(unsigned mod=0;mod<3;++mod) for(unsigned reg=0;reg<8;++reg) {
            unsigned off=form[0]!=0;
            std::array<uint8_t,12> bytes{};bytes[0]=form[0];bytes[off]=form[1];
            bytes[off+1]=static_cast<uint8_t>(mod<<6|reg<<3|4);
            bytes[off+2]=static_cast<uint8_t>(sib);
            const unsigned disp=mod==2 || (!mod && (sib&7)==5) ? 4 : mod;
            const unsigned imm=form[1]==0x81||form[1]==0xc7?4:
                form[1]==0x83||form[1]==0x80||form[1]==0xc6?1:0;
            const unsigned total=off+3+disp+imm;
            for (unsigned i=off+3;i<total;++i) bytes[i]=static_cast<uint8_t>(sib*13+reg+i*57);
            for (unsigned n=0;n<=total;++n) {
                uint8_t *p=area+page-n;std::memcpy(p,bytes.data(),n);
                cs_insn actual,reference;cs_detail act,ref;
                std::memset(&actual,0xa5,sizeof(actual));std::memset(&act,0xa5,sizeof(act));
                std::memcpy(&reference,&actual,sizeof(actual));std::memcpy(&ref,&act,sizeof(act));
                actual.detail=detail?&act:nullptr;reference.detail=detail?&ref:nullptr;
                actual.address=reference.address=0x31415926;uint16_t written=0xeeff;
                ++tried;
                if (!observed_sib(fast,p,n,&actual,&written)) {
                    actual.detail=reference.detail;
                    if (written!=0xeeff || std::memcmp(&actual,&reference,sizeof(actual)) ||
                        std::memcmp(&act,&ref,sizeof(act))) return 3;
                    continue;
                }
                const uint8_t *cursor=p;size_t left=n;uint64_t ip=reference.address;
                if (!cs_disasm_iter(ordinary,&cursor,&left,&ip,&reference) ||
                    written!=total || written!=reference.size || written!=actual.size ||
                    cursor!=p+written || left!=n-written || ip!=reference.address+written ||
                    actual.id!=reference.id || std::memcmp(actual.bytes,reference.bytes,sizeof(actual.bytes)) ||
                    std::memcmp(actual.mnemonic,reference.mnemonic,sizeof(actual.mnemonic)) ||
                    std::memcmp(actual.op_str,reference.op_str,sizeof(actual.op_str)) ||
                    (detail && std::memcmp(&act,&ref,offsetof(cs_detail,x86)+sizeof(cs_x86)))) {
                    std::fprintf(stderr,"i386 SIB mismatch opcode=%02x %02x mod=%u reg=%u sib=%02x n=%u\n",form[0],form[1],mod,reg,sib,n);
                    return 4;
                }
                ((sib&0x38)==0x20 ? accepted_without : accepted_index)++;
            }
        }
        cs_close(&ordinary);cs_close(&fast);
    }
    munmap(area,page*2);
    std::printf("%llu %llu %llu\n",(unsigned long long)tried,(unsigned long long)accepted_index,(unsigned long long)accepted_without);
}
