#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" { uint64_t path_counts[8]{}; }
static uint64_t mix(uint64_t x, const void *data, size_t size) {
    auto p=static_cast<const uint8_t*>(data);
    for (size_t i=0;i<size;++i) x=(x^p[i])*UINT64_C(1099511628211);
    return x;
}
int main(int argc,char **argv) {
    if(argc!=5) return 1;
    int bits=std::atoi(argv[1]),mode=std::atoi(argv[4]);
    std::ifstream file(argv[2],std::ios::binary),spans(argv[3]);
    if(!file||!spans) return 2;
    std::vector<uint8_t> data{std::istreambuf_iterator<char>(file),{}};
    csh h[2];cs_insn *rec[2];cs_detail *det[2];
    for(unsigned i=0;i<2;++i){
        if(cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,h+i)||cs_option(h[i],CS_OPT_DETAIL,mode==2?CS_OPT_ON:CS_OPT_OFF))return 3;
        rec[i]=cs_malloc(h[i]);if(!rec[i])return 4;det[i]=rec[i]->detail;
    }
    uint64_t sums[2][8]{},groups[3][3]{},hash[2]{},disagree[3]{},seen=0,accepted=0,off,len,addr;
    while(spans>>off>>len>>addr){
        if(off>data.size()||len>data.size()-off)return 5;
        size_t left[2]={size_t(len),size_t(len)};uint64_t ip[2]={addr,addr};const uint8_t *p[2]={data.data()+off,data.data()+off};
        while(left[0]){
            bool ok[2];unsigned which[2];++seen;
            for(unsigned i=0;i<2;++i){
                auto x=rec[i];std::memset(x,0,sizeof(*x));x->detail=det[i];if(det[i])std::memset(det[i],0,sizeof(*det[i]));
                std::memset(path_counts,0,sizeof(path_counts));
                ok[i]=i?X86_disasmIterText(h[i],&p[i],&left[i],&ip[i],x):cs_disasm_iter(h[i],&p[i],&left[i],&ip[i],x);
                if(path_counts[1]>1)return 6;
                which[i]=ok[i]?1+(path_counts[1]!=0):0;
                for(unsigned k=0;k<8;++k)sums[i][k]+=path_counts[k];
                if(ok[i]){
                    hash[i]=mix(hash[i],&x->id,sizeof(x->id));hash[i]=mix(hash[i],&x->address,sizeof(x->address));hash[i]=mix(hash[i],&x->size,sizeof(x->size));hash[i]=mix(hash[i],x->bytes,x->size);
                    hash[i]=mix(hash[i],x->mnemonic,std::strlen(x->mnemonic)+1);hash[i]=mix(hash[i],x->op_str,std::strlen(x->op_str)+1);
                    if(det[i]) hash[i]=mix(hash[i],det[i],sizeof(*det[i]));
                }else{++p[i];--left[i];++ip[i];}
            }
            if(ok[0]!=ok[1]||left[0]!=left[1]||ip[0]!=ip[1]||p[0]!=p[1])return 7;
            ++groups[which[0]][which[1]];if(!ok[0])continue;++accepted;
            auto a=rec[0],b=rec[1];disagree[0]+=(a->id!=b->id||a->size!=b->size||a->address!=b->address||std::memcmp(a->bytes,b->bytes,a->size)!=0);
            disagree[1]+=(std::strcmp(a->mnemonic,b->mnemonic)||std::strcmp(a->op_str,b->op_str));
            if(det[0])disagree[2]+=std::memcmp(det[0],det[1],sizeof(*det[0]))!=0;
        }
    }
    if(!spans.eof())return 8;
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64,seen,accepted,hash[0],hash[1]);
    for(auto n:disagree)std::printf(" %" PRIu64,n);
    for(auto &row:sums)for(auto v:row)std::printf(" %" PRIu64,v);
    for(auto &row:groups)for(auto v:row)std::printf(" %" PRIu64,v);
    std::puts("");for(unsigned i=0;i<2;++i){cs_free(rec[i],1);cs_close(h+i);}return 0;
}
