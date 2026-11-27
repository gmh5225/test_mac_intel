#define main old_benchmark_main
#include "compare.cpp"
#undef main
#include <array>
#include <map>
#include <tuple>
int main(int argc,char **argv){
    if(argc!=7)return 2;
    std::ifstream f(argv[3],std::ios::binary),ranges(argv[4]);std::vector<uint8_t> data{std::istreambuf_iterator<char>(f),{}};
    check(!data.empty()&&ranges.good(),"corpus");unsigned platform=std::atoi(argv[5]),route=std::atoi(argv[6]);bool att=route==2||route==3||route==6||route==7;bool public_api=route>=4;
    Api refs(argv[1]),tested(argv[2]);
    Session left(refs,CS_ARCH_X86,platform==64?CS_MODE_64:CS_MODE_32),right(tested,CS_ARCH_X86,platform==64?CS_MODE_64:CS_MODE_32);
    for(auto *s:{&left,&right}){
        s->set(CS_OPT_DETAIL,(route&1)?CS_OPT_ON:CS_OPT_OFF);s->set(CS_OPT_SYNTAX,att?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL);
    }
    uint64_t ok=0,invalid=0,fixed=0,bytes=0,hash=0;
            auto base_next=public_api?refs.sym<decltype(refs.next)>("cs_disasm_iter"):refs.next;
            auto trial_next=public_api?tested.sym<decltype(tested.next)>("cs_disasm_iter"):tested.next;
    size_t offset,len;uint64_t ip;
    while(ranges>>offset>>len>>ip){
        check(offset<=data.size()&&len<=data.size()-offset&&len,"range");const uint8_t *p=data.data()+offset;bytes+=len;
        while(len){
            auto original=p;auto other=p;auto n=len;auto pc=ip;
            cs_insn a,b;cs_detail x,y;
            std::memset(&a,0x5a,sizeof a);a.illegal=a.is_alias=a.usesAliasDetails=false;std::memcpy(&b,&a,sizeof a);
            std::memset(&x,0x5a,sizeof x);std::memcpy(&y,&x,sizeof y);a.detail=&x;b.detail=&y;
            bool decoded=base_next(left.h,&p,&len,&ip,&a),next=trial_next(right.h,&other,&n,&pc,&b);
            check(decoded==next && p==other && n==len && pc==ip && refs.error(left.h)==tested.error(right.h),"cursor");
            check(a.detail==&x&&b.detail==&y,"owner");a.detail=b.detail=nullptr;if(std::memcmp(&a,&b,sizeof a)||std::memcmp(&x,&y,sizeof x)){
                std::fprintf(stderr,"pc %llx route %u bytes",(unsigned long long)a.address,route);
                for(unsigned i=0;i< std::min<size_t>(15,data.data()+data.size()-original);++i)std::fprintf(stderr," %02x",original[i]);
                std::fprintf(stderr," old %u [%s] [%s] new %u [%s] [%s]",a.id,a.mnemonic,a.op_str,b.id,b.mnemonic,b.op_str);
                for(size_t i=0;i<sizeof(a);++i)if(((unsigned char*)&a)[i]!=((unsigned char*)&b)[i]){std::fprintf(stderr," first insn diff %zu",i);break;}
                for(size_t i=0;i<sizeof(x);++i)if(((unsigned char*)&x)[i]!=((unsigned char*)&y)[i]){std::fprintf(stderr," first detail diff %zu",i);break;}
                std::fputc(10,stderr);return 10;
            }
            check(!std::memcmp(&x,&y,sizeof x),"complete detail");
            if(decoded) {
                const unsigned op = a.bytes[0];
                fixed += platform==32 && a.size==3 && op==0xc5 && (a.bytes[1] & 0xfb)==0xf8 && a.bytes[2]==0x77;
            }
            if(decoded){++ok;hash=hash*131+a.address+a.id+a.size;}
            else{++invalid;++p;--len;++ip;}
        }
    }
    if(!ranges.eof())return 3;
    std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",ok,invalid,bytes,hash,fixed);
    return 0;
}
