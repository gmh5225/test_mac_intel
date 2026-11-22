#include "arch/X86/X86ScanAdapter.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

extern "C" uint32_t projected_word(const uint8_t*,size_t);
int main() {
    csh scan=0, full=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&scan)||cs_open(CS_ARCH_X86,CS_MODE_64,&full)||
       cs_option(scan,CS_OPT_TEXT,CS_OPT_OFF)||cs_option(full,CS_OPT_DETAIL,CS_OPT_ON))return 1;
    cs_opt_mnem marker{X86_INS_UD2,"ud2"};
    if(cs_option(full,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&marker)))return 2;
    cs_insn *record=cs_malloc(full);if(!record)return 3;
#ifdef _WIN32
    SYSTEM_INFO si; GetSystemInfo(&si);
    const size_t page = si.dwPageSize;
    auto memory = static_cast<uint8_t *>(VirtualAlloc(nullptr,2*page,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    DWORD old;
    if (!memory || !VirtualProtect(memory+page,page,PAGE_NOACCESS,&old)) return 2;
#else
    const size_t page = sysconf(_SC_PAGESIZE);
    auto memory = static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if (memory == MAP_FAILED || mprotect(memory+page,page,PROT_NONE)) return 2;
#endif
    uint8_t bytes[15]={0x62,0,0,0,0,0,0x0a,0xab,0x37,0xff,0x80,0xc7,0,0x98,0x23};
    uint64_t total=0, claimed=0;
    for(unsigned map=1;map<=3;++map)for(unsigned key=0;key<8;++key)
    for(unsigned op=0;op<256;++op)for(unsigned fields=0;fields<256;++fields)
    for(unsigned variant=0;variant<4;++variant){
        bytes[1]=uint8_t(((fields&15)<<4)|map);
        bytes[2]=uint8_t(((key>>2)<<7)|(key&3)|4|(((fields>>4)&15)<<3));
        bytes[3]=uint8_t((variant<<5)|0x10|((fields&16)>>1));
        if(fields>=128 && (fields&1))bytes[3]|=uint8_t(0x80|(fields&7));
        bytes[4]=uint8_t(op);bytes[5]=uint8_t(0xc0|(fields&63));
        for(unsigned j=0;j<2;++j){
            const unsigned n=j==0?15:((op+key+variant+fields)%7);
            auto p=memory+page-n;std::memcpy(p,bytes,n);
            const auto word=n?projected_word(p,n):0;uint32_t a=0x19378456,b=a;
            const auto x=X86_scanBatch(scan,p,n,0x401000,&a,1);
            const auto y=X86_scanNativeBatch(scan,p,n,0x401000,&b,1);
            bool equal=x.count==y.count&&x.bytes==y.bytes&&a==b;
            if(word){
                const uint8_t* position=p;size_t remaining=n;uint64_t ip=0x401000;
                bool ok=cs_disasm_iter(full,&position,&remaining,&ip,record);
                equal=equal&&ok&&x.count==1&&a==word&&word==((record->id<<8)|record->size);
                ++claimed;
            }
            if(!equal){
                std::fprintf(stderr,"Rounded EVEX mismatch map=%u key=%u mr=%02x bytes=",map,key,bytes[5]);
                for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",p[i]);
                std::fprintf(stderr," full=%s/%u:%u before=%x after=%x direct=%x\n",record->mnemonic,record->id,record->size,a,b,word);
                return 5;
            }
            ++total;
        }
    }
    if (!claimed) return 6;
    std::printf("%llu %llu\n",(unsigned long long)total,(unsigned long long)claimed);
    cs_free(record,1);cs_close(&full);cs_close(&scan);
#ifdef _WIN32
    VirtualFree(memory,0,MEM_RELEASE);
#else
    munmap(memory,page*2);
#endif

}
