#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef CHECK_ADAPTER
static uint32_t custom(void *calls, const uint8_t *code, size_t size) {
    ++*static_cast<uint64_t *>(calls);
    return size && code[0] == 0xcc ? (uint32_t(X86_INS_NOP) << 8) | 1 : 0;
}
#endif
int main() {
#ifdef _WIN32
    SYSTEM_INFO si; GetSystemInfo(&si);
    const size_t page = si.dwPageSize;
    auto mem = static_cast<uint8_t *>(VirtualAlloc(nullptr,2*page,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    DWORD old;
    if (!mem || !VirtualProtect(mem+page,page,PAGE_NOACCESS,&old)) return 2;
#else
    const size_t page = sysconf(_SC_PAGESIZE);
    auto mem = static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if (mem == MAP_FAILED || mprotect(mem+page,page,PROT_NONE)) return 2;
#endif
    uint8_t bytes[16] = {0x80,0x90,0x25,0,0,0x7f,0x80,0x1f,0xff,0x10,0x70,0xfd,0xc5,0xf8,0x77,0};
    csh handles[2]{};
    uint64_t records=0, accepted=0, calls[2]{}, digest=14695981039346656037ull;
    auto compare=[&](unsigned n, size_t cap) {
        auto p=mem+page-n; std::memcpy(p,bytes,n);
        uint32_t a[4]={0x12345678,2,3,4}, b[4]; std::memcpy(b,a,sizeof(a));
        auto ref=X86_scanBatch(handles[0],p,n,UINT64_MAX-7,a,cap);
        auto cur=X86_scanNativeBatch(handles[1],p,n,UINT64_MAX-7,b,cap);
        if (ref.bytes!=cur.bytes || ref.count!=cur.count || std::memcmp(a,b,sizeof(a)) ||
            cs_errno(handles[0])!=cs_errno(handles[1]) || calls[0]!=calls[1]) {
            std::fprintf(stderr,"opcode %02x %02x %02x %02x extent %u capacity %zu\n",bytes[0],bytes[1],bytes[2],bytes[3],n,cap); std::exit(3);
        }
        ++records; accepted+=ref.count;
        digest=(digest^(ref.bytes+ref.count))*1099511628211ull;
        for (size_t i=0;i<ref.count;++i)digest=(digest^a[i])*1099511628211ull;
    };
    for (auto mode : {CS_MODE_16, CS_MODE_32, CS_MODE_64}) {
        for (auto &h:handles)if (cs_open(CS_ARCH_X86,mode,&h)||cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 4;
        for (unsigned op=0;op<256;++op)for(unsigned mr=0;mr<256;++mr) {
            bytes[0]=op;bytes[1]=mr;
            if (mode==CS_MODE_32) {
                for (unsigned base=0;base<8;++base) {
                    bytes[2]=uint8_t((mr^op)&0xf8)|base;
                    for (unsigned n=0;n<=15;++n)compare(n,1);
                }
            }else{compare(15,4);compare((op+mr)&15,1);}
        }
        if (mode==CS_MODE_32) {
            bytes[0]=0xc5;
            for(unsigned flags=0;flags<256;++flags)for(unsigned op=0;op<256;++op) {
                bytes[1]=flags;bytes[2]=op;
                for(unsigned j=0;j<16;++j) {
                    bytes[3]=uint8_t(17*j);compare(j,1);compare(15,4);
                }
            }
#ifdef CHECK_ADAPTER
            for(unsigned i=0;i<2;++i)if(!X86_setScanAdapter(handles[i],mode,custom,&calls[i]))return 5;
            for(unsigned op=0;op<256;++op){bytes[0]=op;compare(15,2);}
            if(!calls[0])return 6;
#endif
        }
        for (unsigned option=0;option<8;++option) {
            for(auto h:handles) {
                cs_option(h,CS_OPT_DETAIL,option&1?CS_OPT_ON:CS_OPT_OFF);
                cs_option(h,CS_OPT_TEXT,option&2?CS_OPT_ON:CS_OPT_OFF);
                cs_option(h,CS_OPT_SKIPDATA,option&4?CS_OPT_ON:CS_OPT_OFF);
            }
            for (unsigned op=0;op<256;++op){bytes[0]=op;compare(op&15,op%5);}
        }
        for(auto &h:handles)if(cs_close(&h))return 7;
    }
    std::printf("%llu %llu %016llx\n",(unsigned long long)records,(unsigned long long)accepted,(unsigned long long)digest);
#ifdef _WIN32
    VirtualFree(mem,0,MEM_RELEASE);
#else
    munmap(mem,2*page);
#endif
}
