#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    auto *block = static_cast<uint8_t *>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (block == MAP_FAILED || mprotect(block + page, page, PROT_NONE)) return 1;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) || cs_option(handle,CS_OPT_TEXT,CS_OPT_OFF)) return 2;
    uint8_t bytes[16]={0x62,0xf1,0x7d,8,0x6f,0,5,0x80,0xfd,0xac,0x66,0x37,0x91,0xc8,7,0x90};
    uint64_t total=0,good=0,checksum=0;
    auto probe=[&](size_t n) {
        uint8_t *p=block+page-n;
        std::memcpy(p,bytes,n);
        uint32_t base[]={0x8a7799ab,0x98bbaacc},test[]={0x8a7799ab,0x98bbaacc};
        auto want=X86_scanBatch(handle,p,n,UINT64_MAX-8,base,1);
        auto have=X86_scanNativeBatch(handle,p,n,UINT64_MAX-8,test,1);
        if (want.bytes!=have.bytes || want.count!=have.count || std::memcmp(base,test,sizeof(base))) {
            for(size_t k=0;k<n;++k)std::fprintf(stderr,"%02x",p[k]);
            std::fprintf(stderr," length=%zu ordinary=%08x/%zu native=%08x/%zu\n",n,base[0],want.bytes,test[0],have.bytes);
            std::exit(3);
        }
        ++total;good+=want.count;checksum=checksum*131+test[0]+have.bytes;
    };
    const uint8_t opcodes[]={0x5a,0x6f,0x7f};
    const uint8_t operands[]={0x04,0x44,0x85,0xff};
    for (uint8_t op:opcodes) {
        bytes[4]=op;
        for (unsigned map=0;map<4;++map) {
            for (unsigned p1=0;p1<256;++p1) for(unsigned p2=0;p2<256;++p2) {
                bytes[1]=uint8_t(((p1^p2)&0xf0)|map);bytes[2]=uint8_t(p1);bytes[3]=uint8_t(p2);
                for(uint8_t mr:operands) {
                    bytes[5]=mr;bytes[6]=uint8_t(p1*19+p2);
                    probe(5+(p1+p2+mr)%7);probe(15);
                }
            }
        }
    }
    for (uint8_t op:opcodes) {
        bytes[4]=op;
        for(unsigned ext=0;ext<16;++ext) for(unsigned w=0;w<2;++w) for(unsigned ll=0;ll<3;++ll) {
            bytes[1]=uint8_t((ext<<4)|(op==0x5a ? 2 : 1));
            for (unsigned pp=1;pp<=3;++pp) {
                if (op==0x5a && pp!=1) continue;
                bytes[2]=uint8_t((w<<7)|0x7c|pp);
                const uint8_t masks[]={8,9,0x8f};
                for(uint8_t mask:masks) {
                    bytes[3]=uint8_t((ll<<5)|mask);
                    for(unsigned mr=0;mr<256;++mr) {
                        bytes[5]=uint8_t(mr);
                        const bool sib=mr<192 && (mr&7)==4;
                        for(unsigned addr=0;addr<(sib?256u:1u);++addr) {
                            bytes[6]=uint8_t(addr);
                            const unsigned mod=mr>>6;
                            const unsigned disp=mod==1 ? 1 : mod==2 || (!mod && (sib ? (addr&7)==5 : (mr&7)==5)) ? 4 : 0;
                            const size_t length=6+sib+disp;
                            probe(length-1);probe(length);
                        }
                    }
                }
            }
        }
    }
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",total,good,checksum);
    cs_close(&handle);
    return munmap(block,2*page)!=0;
}
