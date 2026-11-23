#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *pages = static_cast<uint8_t *>(mmap(nullptr, 2*page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
    if (pages == MAP_FAILED || mprotect(pages+page, page, PROT_NONE)) return 1;
    const unsigned opcodes[] = {0x01,0x03,0x09,0x2b,0x39,0x3b,0x85,0x88,0x89,0x8a,0x8b,0x8d,0xff,0xc6,0xc7,0x80,0x81,0x83,0x63,0xfb6,0xfb7,0xfbe,0xfbf};
    const unsigned sibs[] = {0x24,0x20,0x25,0x44,0x8c,0xcd,0x50,0xf5};
    uint64_t tested=0, accepted=0;
    for (cs_mode mode : {CS_MODE_32, CS_MODE_64}) for (bool detail : {false,true}) {
        csh h[2]{}; cs_opt_mnem neutral{X86_INS_UD2,"ud2"};
        for (auto &handle:h) if (cs_open(CS_ARCH_X86,mode,&handle) ||
            (detail && cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON))) return 2;
        if (cs_option(h[1],CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&neutral))) return 2;
        for (unsigned prefix : {0U,0x40U,0x49U,0x4eU,0x64U,0x2eU}) {
          if (mode==CS_MODE_32 && prefix>=0x40 && prefix<=0x4f) continue;
          for (unsigned op:opcodes) for (unsigned mod=0;mod<3;++mod)
          for (unsigned group=0;group<8;++group) for (unsigned rm=0;rm<8;++rm)
          for (unsigned si=0;si<(rm==4?8U:1U);++si) {
            std::array<uint8_t,15> bytes{}; unsigned off=0;
            if (prefix) bytes[off++]=static_cast<uint8_t>(prefix);
            if (op>0xff) bytes[off++]=0x0f;
            bytes[off++]=static_cast<uint8_t>(op);
            bytes[off++]=static_cast<uint8_t>((mod<<6)|(group<<3)|rm);
            if (rm==4) bytes[off++]=static_cast<uint8_t>(sibs[si]);
            unsigned displacement=(mod==2 || (!mod && (rm==5 || (rm==4 && (sibs[si]&7)==5))))?4:mod;
            unsigned imm=(op==0xc7 || op==0x81)?4:(op==0x80 || op==0x83 || op==0xc6);
            unsigned total=off+displacement+imm;
            for (unsigned i=off;i<total;++i) bytes[i]=static_cast<uint8_t>(0x83+group*31+si*17+i*23);
            for (unsigned n: {0U,total-1,total}) {
              uint8_t *ptr=pages+page-n; std::memcpy(ptr,bytes.data(),n);
              cs_insn insn[2]; cs_detail dt[2]; std::memset(insn,0xa5,sizeof(insn));std::memset(dt,0xa5,sizeof(dt));
              const uint8_t *cursor[2]={ptr,ptr}; size_t left[2]={n,n}; uint64_t ip[2]={0x31415926,0x31415926}; bool res[2]{};
              for(unsigned k=0;k!=2;++k) {
                insn[k].detail=detail?&dt[k]:nullptr;
                res[k]=k?cs_disasm_iter(h[k],&cursor[k],&left[k],&ip[k],&insn[k]):
                         X86_disasmIterText(h[k],&cursor[k],&left[k],&ip[k],&insn[k]);
                if(insn[k].detail!=(detail?&dt[k]:nullptr))return 3;
                insn[k].detail=nullptr;
              }
              ++tested;accepted+=res[0];
              if(res[0]!=res[1] || cursor[0]!=cursor[1] || left[0]!=left[1] || ip[0]!=ip[1] ||
                 cs_errno(h[0])!=cs_errno(h[1]) || std::memcmp(&insn[0],&insn[1],sizeof(cs_insn)) ||
                 std::memcmp(&dt[0],&dt[1],sizeof(cs_detail))) {
                std::fprintf(stderr,"mode=%u detail=%d prefix=%x op=%x mod=%u group=%u rm=%u sib=%x n=%u ok=%u/%u\n",mode,detail,prefix,op,mod,group,rm,sibs[si],n,res[0],res[1]);return 4;
              }
            }
          }
        }
        cs_close(&h[0]);cs_close(&h[1]);
    }
    munmap(pages,2*page);
    std::printf("%llu %llu\n",(unsigned long long)tested,(unsigned long long)accepted);
}
