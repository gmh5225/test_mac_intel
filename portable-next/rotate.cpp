#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <cstring>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#include "forms.inc"

int main() {
#ifdef _WIN32
    SYSTEM_INFO info; GetSystemInfo(&info);
    size_t page=info.dwPageSize;
    auto *mem=static_cast<uint8_t *>(VirtualAlloc(nullptr,2*page,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    DWORD old_protect;
    if (!mem || !VirtualProtect(mem+page,page,PAGE_NOACCESS,&old_protect)) return 1;
#else
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    auto *mem = static_cast<uint8_t *>(mmap(nullptr, page*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON,-1,0));
    if (mem==MAP_FAILED || mprotect(mem+page,page,PROT_NONE))return 1;
#endif
    uint64_t n=0, good=0, hash=0, rotate=0, prior_aliases=0;
    for (cs_mode mode : {CS_MODE_32,CS_MODE_64}) {
        csh scan{}, full{};
        if (cs_open(CS_ARCH_X86,mode,&scan)||cs_open(CS_ARCH_X86,mode,&full)||
            cs_option(scan,CS_OPT_TEXT,CS_OPT_OFF))return 2;
        cs_opt_mnem name{X86_INS_UD2,"unrelated-ud2"};
        if(cs_option(full,CS_OPT_MNEMONIC,(uintptr_t)&name))return 3;
        auto *si=cs_malloc(scan),*fi=cs_malloc(full);if(!si||!fi)return 4;
        uint8_t input[15]={0xc4,0xe3,0x7b,0xf0,0xc8,0x63,0x80,0x11,0xff,0x40,9,0x67,0xc0,0x20,0x90};
        auto probe=[&](unsigned size,bool strict) {
            auto *bytes=mem+page-size;std::memcpy(bytes,input,size);
            const uint8_t *sp=bytes,*fp=bytes;uint64_t ip=UINT64_MAX-5,other=ip;size_t sl=size,fl=size;
            bool a=cs_disasm_iter(scan,&sp,&sl,&ip,si);
            bool b=cs_disasm_iter(full,&fp,&fl,&other,fi);
            uint32_t words[]={0x12345678u,0x87654321u};
            auto r=X86_scanNativeBatch(scan,bytes,size,UINT64_MAX-5,words,1);
            bool mismatch=a!=b || (a && (si->id!=fi->id||sp!=fp||sl!=fl||ip!=other||si->size!=fi->size));
            uint32_t expect=a?(si->id<<8)|unsigned(si->size):0x12345678u;
            if ((strict && mismatch)||r.count!=unsigned(a)||r.bytes!=size_t(sp-bytes)||
                words[0]!=expect||words[1]!=0x87654321u||(a && r.bytes!=si->size)) {
                std::fprintf(stderr,"%u-bit %02x %02x %02x %02x %02x len %u scan %u full %u batch %u\n",
                  mode==CS_MODE_64?64:32,input[0],input[1],input[2],input[3],input[4],size,a?si->id:0,b?fi->id:0,words[0]);std::exit(5);
            }
            ++n;good+=a;prior_aliases+=mismatch;rotate+=b && fi->id==X86_INS_RORX;
            hash=hash*UINT64_C(1099511628211)+expect+(b?((uint64_t(fi->id)<<12)|fi->size):0);
        };
        // Every changed table cell, prefix extension, encoded source and ModR/M,
        // including the no-base SIB form at an inaccessible page boundary.
        for(auto const &form:forms)for(unsigned reg=0;reg<8;++reg)for(unsigned v=0;v<16;++v)
          for(unsigned mr=0;mr<256;++mr)for(unsigned sib: {0x24u,0x25u}) {
            input[1]=uint8_t(reg*32+form[0]);input[2]=uint8_t(((form[1]&8)<<4)|(v<<3)|(form[1]&7));
            input[3]=uint8_t(form[2]);input[4]=uint8_t(mr);input[5]=uint8_t(sib);
            for(unsigned size=0;size<=15;++size)probe(size,mode==CS_MODE_64||reg>=6);
        }
        // Include the other opcodes and prefixes for the generic VEX scanner.
        for(unsigned m : {1u,2u,3u})for(unsigned k=0;k<16;++k)for(unsigned op=0;op<256;++op)
          for(unsigned mr:{0x00u,0x04u,0x45u,0x8du,0xc7u,0xffu})for(unsigned enc:{0x00u,0x60u,0xe0u})
          for(unsigned v : {0u,7u,15u}) {
            input[1]=uint8_t(enc|m);input[2]=uint8_t(((k&8)<<4)|(v<<3)|(k&7));input[3]=uint8_t(op);
            input[4]=uint8_t(mr);input[5]=0x25;
            for(unsigned size:{4u,5u,6u,9u,15u})probe(size,false);
        }
        cs_free(si,1);cs_free(fi,1);cs_close(&scan);cs_close(&full);
    }
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",n,good,hash,rotate,prior_aliases);
#ifdef _WIN32
    return !VirtualFree(mem,0,MEM_RELEASE);
#else
    return munmap(mem,page*2)!=0;
#endif
}
