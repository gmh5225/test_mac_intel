#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <tuple>
#include <vector>

extern "C" unsigned path_events[7];
using Counts=std::array<uint64_t,8>;
struct Buckets {
    Counts counts{};
    std::string example;
};
static std::string shape(const cs_x86 &x) {
    std::string s;
    for(unsigned i=0;i<x.op_count;++i) {
        const cs_x86_op &op=x.operands[i];
        if(i) s+=",";
        if(op.type==X86_OP_REG) s+="r";
        else if(op.type==X86_OP_IMM) s+="i";
        else if(op.type==X86_OP_MEM) {
            s+="m";
            s+=op.mem.base==X86_REG_RIP?"rip":op.mem.base==X86_REG_INVALID?"abs":"base";
            if(op.mem.index!=X86_REG_INVALID) s+="+idx";
            if(op.mem.segment!=X86_REG_INVALID) s+="+seg";
            if(x.encoding.disp_size) s+="d"+std::to_string(x.encoding.disp_size);
        } else s+="?";
        s+=std::to_string(op.size);
    }
    return s.empty()?"none":s;
}
int main(int argc,char **argv) {
    if(argc!=5) return 1;
    const unsigned bits=std::stoul(argv[1]);const auto mode=bits==32?CS_MODE_32:CS_MODE_64;
    std::ifstream input(argv[2],std::ios::binary);std::ofstream output(argv[4]);
    if(!input||!output) return 2;
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    csh canonical{},actual{};
    if(cs_open(CS_ARCH_X86,mode,&actual)||cs_open(CS_ARCH_X86,mode,&canonical)) return 3;
    cs_opt_mnem m{X86_INS_UD2,"ud2"};if(cs_option(canonical,CS_OPT_MNEMONIC,(size_t)&m)) return 4;
    for(unsigned detail:{0,1}) for(unsigned fixed:{0,1}) {
        for(auto h:{actual,canonical}) if(cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)) return 5;
        const auto next=fixed?(bits==64?X86_disasmIterText:X86_disasmIter32):cs_disasm_iter;
        std::map<std::tuple<bool,std::string,std::string>,Buckets> histogram;
        std::ifstream intervals(argv[3]);size_t start,len,valid=0,invalid=0;uint64_t ip;
        if(!intervals)return 6;
        while(intervals>>start>>len>>ip) {
            if(start>bytes.size()||len>bytes.size()-start)return 7;
            const uint8_t *p=bytes.data()+start;
            while(len) {
                cs_detail da{},db{};cs_insn a{},b{};a.detail=detail?&da:nullptr;b.detail=detail?&db:nullptr;
                auto pa=p,pb=p;auto na=len,nb=len;auto ia=ip,ib=ip;
                const bool ref=cs_disasm_iter(canonical,&pa,&na,&ia,&a);
                std::fill(path_events,path_events+7,0u);
                const bool ok=next(actual,&pb,&nb,&ib,&b);
                if(a.detail!=(detail?&da:nullptr)||b.detail!=(detail?&db:nullptr))return 8;
                b.detail=a.detail;
                if(ok!=ref||pa!=pb||na!=nb||ia!=ib||std::memcmp(&a,&b,sizeof(a))||std::memcmp(&da,&db,sizeof(da))||path_events[0]>1) {
                    std::fprintf(stderr,"%u-bit fixed=%u detail=%u ip=%llx %s %s\n",bits,fixed,detail,(unsigned long long)ip,a.mnemonic,a.op_str);
                    return 9;
                }
                auto &bucket=histogram[{path_events[0]!=0,ok?a.mnemonic:"(invalid)",detail&&ok?shape(da.x86):"-"}];
                ++bucket.counts[0];
                for(unsigned i=0;i<7;++i)bucket.counts[i+1]+=path_events[i];
                if(bucket.example.empty()) for(size_t i=0;i<(ok?a.size:1);++i) {
                    char hex[3];std::snprintf(hex,sizeof(hex),"%02x",p[i]);bucket.example+=hex;
                }
                if(ok){++valid;p=pa;len=na;ip=ia;} else {++invalid;++p;--len;++ip;}
            }
        }
        std::printf("%u %u %zu %zu\n",fixed,detail,valid,invalid);
        for(const auto &[k,b]:histogram) {
            const auto &[full,name,kind]=k;
            output<<fixed<<'\t'<<detail<<'\t'<<full<<'\t'<<name<<'\t'<<kind<<'\t'<<b.example;
            for(auto n:b.counts)output<<'\t'<<n;
            output<<'\n';
        }
    }
    cs_close(&canonical);cs_close(&actual);
}
