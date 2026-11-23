#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

static uintptr_t zero;
static bool first;
static std::ofstream trace;
static std::map<std::string, unsigned long long> owners;
extern "C" void trace_vector_write(char *dst, unsigned bank, unsigned n, unsigned sep,const char *owner) {
    const char *base=std::strrchr(owner,'/');++owners[base?base+1:owner];
    uintptr_t at=reinterpret_cast<uintptr_t>(dst);
    if(at<zero || at-zero+(sep?8:6)>sizeof(cs_insn::op_str) || bank>=3 || n>=32 || sep>1) std::abort();
    const uint8_t item[]={uint8_t(at-zero),uint8_t(bank),uint8_t(n),uint8_t(sep+2*first)};
    trace.write(reinterpret_cast<const char *>(item),sizeof(item));
    first=false;
}
int main(int argc,char **argv) {
    if(argc!=5)return 1;
    cs_mode mode=argv[1][0]=='3'?CS_MODE_32:CS_MODE_64;
    std::ifstream file(argv[2],std::ios::binary),spans(argv[3]);
    trace.open(argv[4],std::ios::binary);
    if(!file||!spans||!trace)return 2;
    const std::vector<uint8_t> text{std::istreambuf_iterator<char>(file),{}};
    csh h; if(cs_open(CS_ARCH_X86,mode,&h))return 3;
    cs_insn *rec=cs_malloc(h); if(!rec)return 4;
    zero=reinterpret_cast<uintptr_t>(rec->op_str);
    size_t off,n,valid=0,rejected=0,touched=0;
    uint64_t ip;
    while(spans>>off>>n>>ip) {
        if(off>text.size()||n>text.size()-off)return 5;
        const uint8_t *cursor=text.data()+off;
        while(n){
            first=true;
            const uint8_t *p=cursor;auto left=n;auto address=ip;
            if(X86_disasmIterText(h,&p,&left,&address,rec)){
                if(!rec->size||p!=cursor+rec->size||n-left!=rec->size)return 6;
                touched+=!first; ++valid; cursor=p;n=left;ip=address;
            } else {
                if(!first || p!=cursor || left!=n || address!=ip)return 7;
                ++cursor;--n;++ip;++rejected;
            }
        }
    }
    const auto bytes=trace.tellp();trace.close();if(!trace)return 8;
    cs_free(rec,1);cs_close(&h);
    std::printf("%zu %zu %zu %llu\n",valid,rejected,touched,static_cast<unsigned long long>(bytes)/4);
    for(const auto &owner:owners)std::printf("%s %llu\n",owner.first.c_str(),owner.second);
}
