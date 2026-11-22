#include "arch/X86/X86ScanAdapter.h"
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
int main() {
    csh h=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h)||cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 1;
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    auto mem=(uint8_t*)mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(mem==MAP_FAILED||mprotect(mem+page,page,PROT_NONE))return 2;
    uint8_t bytes[16]={0xc5,0,0,0,0,0x7f,0x80,0x1f,0xff,0x10,0x70,0xfd,0xc5,0xf8,0x77,0};
    uint64_t records=0,accepted=0;
    auto test=[&](unsigned n,size_t cap) {
        uint32_t a[4]={0x7c420a5d,2,3,4},b[4];std::memcpy(b,a,sizeof(a));
        auto p=mem+page-n;std::memcpy(p,bytes,n);
        auto base=X86_scanBatch(h,p,n,UINT64_MAX-7,a,cap);
        auto cand=X86_scanBatch64(h,p,n,UINT64_MAX-7,b,cap);
        if(base.count!=cand.count||base.bytes!=cand.bytes||std::memcmp(a,b,sizeof(a))){std::fprintf(stderr,"%02x %02x %02x %02x %02x n=%u cap=%zu\n",bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],n,cap);std::exit(3);}
        ++records;accepted+=base.count;
    };
    for(unsigned p=0;p<256;++p) {
        bytes[1]=p;
        for(unsigned op=0;op<256;++op) {
            bytes[2]=op;
            for(unsigned m=0;m<256;++m) {
                bytes[3]=m;bytes[4]=(m^op^p)&255;
                test(4,1);test(11,3);
                if(p>=0xc0 && ((m&7)==4 || m>=0xc0)) {
                    for(unsigned n=1;n<11;++n)test(n,3);
                }
            }
        }
    }
    for(unsigned prefix=0;prefix<=16;++prefix) {
        unsigned lead=prefix!=0;
        if(lead)bytes[0]=uint8_t(0x3f+prefix);
        for(unsigned op=0;op<256;++op)for(unsigned mr=0;mr<256;++mr) {
            bytes[lead]=uint8_t(op);bytes[lead+1]=uint8_t(mr);
            for(unsigned sib: {0u,5u,0x25u,0xffu}) {
                bytes[lead+2]=uint8_t(sib);
                test(15,1);test((op+mr+prefix)&15,3);
            }
        }
    }
    std::printf("%llu guarded batches, %llu accepted records\n",(unsigned long long)records,(unsigned long long)accepted);
    munmap(mem,page*2);return cs_close(&h);
}
