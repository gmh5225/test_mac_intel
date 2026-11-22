#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
extern "C" uint32_t projected_word(const uint8_t*,size_t);
int main() {
    csh scan=0,full=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&scan)||cs_open(CS_ARCH_X86,CS_MODE_64,&full)||cs_option(scan,CS_OPT_TEXT,CS_OPT_OFF)||cs_option(full,CS_OPT_DETAIL,CS_OPT_ON)) return 1;
    cs_opt_mnem name{X86_INS_UD2,"ud2"};
    if(cs_option(full,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&name))) return 2;
    cs_insn *insn=cs_malloc(full);if(!insn)return 3;
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
    uint8_t bytes[16]={0,0,0,0,0,0,0x88,0x25,0,0,0x80,0x7f,0xff,0xa0,0xcc,0};
    uint64_t total=0,hits=0;
    for(unsigned size_prefix=0;size_prefix<2;++size_prefix)for(unsigned rex=0;rex<=16;++rex){
        unsigned prefix=0;
        if(size_prefix)bytes[prefix++]=0x66;
        if(rex)bytes[prefix++]=uint8_t(0x3f+rex);
        bytes[prefix++]=0x0f;
        for(unsigned op=0;op<256;++op)for(unsigned mr=0;mr<256;++mr){
            bytes[prefix]=uint8_t(op);bytes[prefix+1]=uint8_t(mr);
            for(unsigned variant=0;variant<2;++variant){
                bytes[prefix+2]=uint8_t((op&0xf8)|(variant?5:((op+mr)&7)));
                for(unsigned j=0;j<3;++j){
                    const unsigned n=j==0?15:j==1?((op+mr+rex)&15):prefix+2+variant;
                    auto p=memory+page-n;std::memcpy(p,bytes,n);
                    const auto word=n?projected_word(p,n):0;
                    uint32_t a=0x12345678,b=a;
                    const auto x=X86_scanBatch(scan,p,n,0x401000,&a,1);
                    const auto y=X86_scanNativeBatch(scan,p,n,0x401000,&b,1);
                    bool same=x.count==y.count&&x.bytes==y.bytes&&a==b;
                    if(word){
                        auto next=static_cast<const uint8_t*>(p);size_t left=n;uint64_t ip=0x401000;
                        same=same&&x.count==1&&cs_disasm_iter(full,&next,&left,&ip,insn)&&word==a&&word==((insn->id<<8)|insn->size);
                        ++hits;
                    }
                    if(!same){
                        for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",bytes[i]);
                        std::fprintf(stderr," extent=%u plan=%x scan=%x candidate=%x full=%s/%u\n",n,word,a,b,insn->mnemonic,insn->size);
                        return 5;
                    }
                    ++total;
                }
            }
        }
    }
    cs_free(insn,1);cs_close(&scan);cs_close(&full);
#ifdef _WIN32
    VirtualFree(memory,0,MEM_RELEASE);
#else
    munmap(memory,page*2);
#endif
    std::printf("%llu %llu\n",(unsigned long long)total,(unsigned long long)hits);
}
