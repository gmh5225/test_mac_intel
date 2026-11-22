#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

static uint64_t calls[7][17]{};
static std::map<std::string,uint64_t> formats;
extern "C" void measure_number(unsigned kind,uint64_t value) {
    unsigned n=0;
    for (uint64_t x=value;x;x>>=4) ++n;
    ++calls[kind][n];
}
extern "C" void measure_format(const char *s) { ++formats[s]; }

static void hash(uint64_t &h,const void *p,size_t size) {
    const uint8_t *v=static_cast<const uint8_t *>(p);
    for(size_t i=0;i<size;++i) h=(h^v[i])*UINT64_C(1099511628211);
}
int main(int argc,char **argv) {
    if(argc!=5) return 1;
    const auto bits=std::atoi(argv[1]);bool selected=std::atoi(argv[2])!=0;
    std::ifstream input(argv[3],std::ios::binary);if(!input)return 2;
    std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(input),{});
    uint64_t ip=std::strtoull(argv[4],nullptr,0);
    cs_arch arch=CS_ARCH_X86;cs_mode cm=bits==32?CS_MODE_32:CS_MODE_64;size_t align=1;
    switch(bits) {
    case 101:arch=CS_ARCH_ARM;cm=CS_MODE_ARM;align=4;break;
    case 102:arch=CS_ARCH_AARCH64;cm=CS_MODE_LITTLE_ENDIAN;align=4;break;
    case 103:arch=CS_ARCH_MIPS;cm=CS_MODE_MIPS64;align=4;break;
    case 104:arch=CS_ARCH_PPC;cm=CS_MODE_64;align=4;break;
    case 105:arch=CS_ARCH_RISCV;cm=cs_mode(CS_MODE_RISCV64|CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_A);align=2;break;
    }
    csh handle;
    if(cs_open(arch,cm,&handle)||cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON))return 3;
    cs_insn insn{};cs_detail detail{};insn.detail=&detail;
    const auto next=selected?(bits==32?X86_disasmIter32:X86_disasmIterText):cs_disasm_iter;
    size_t left=bytes.size(),valid=0,rejected=0;const uint8_t *ptr=bytes.data();
    uint64_t digest=UINT64_C(14695981039346656037);
    while(left) {
        if(next(handle,&ptr,&left,&ip,&insn)) {
            if(insn.detail!=&detail || !insn.size)return 4;
            ++valid;insn.detail=nullptr;hash(digest,&insn,sizeof insn);hash(digest,&detail,sizeof detail);insn.detail=&detail;
        } else {
            ++rejected;size_t step=std::min(align,left);ptr+=step;left-=step;ip+=step;
        }
    }
    std::printf("records %zu %zu %016llx\n",valid,rejected,(unsigned long long)digest);
    for(unsigned i=0;i<7;++i){
        std::printf("hist %u",i);for(auto v:calls[i])std::printf(" %llu",(unsigned long long)v);std::puts("");
    }
    for(const auto &[fmt,n]:formats) std::printf("fmt %llu %s\n",(unsigned long long)n,fmt.c_str());
    return cs_close(&handle)!=CS_ERR_OK;
}
