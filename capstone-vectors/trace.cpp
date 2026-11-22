#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <tuple>
#include <vector>
extern "C" bool observedOutput32(csh, const uint8_t*, size_t, cs_insn*, uint16_t*);
extern "C" bool observedOutput64(csh, const uint8_t*, size_t, cs_insn*, uint16_t*);
int main(int argc,char **argv) {
    if (argc != 4) return 1;
    const unsigned bits=std::atoi(argv[1]);
    std::ifstream in(argv[2],std::ios::binary), spans(argv[3]);
    if(!in || !spans) return 2;
    const std::vector<uint8_t> data{std::istreambuf_iterator<char>(in), {}};
    const auto writer=bits==64 ? observedOutput64 : observedOutput32;
    const auto mode=bits==64 ? CS_MODE_64 : CS_MODE_32;
    csh normal=0, fast=0;
    if(cs_open(CS_ARCH_X86,mode,&normal)||cs_open(CS_ARCH_X86,mode,&fast)||cs_option(normal,CS_OPT_DETAIL,CS_OPT_ON)||cs_option(fast,CS_OPT_DETAIL,CS_OPT_ON))return 3;
    cs_opt_mnem custom{X86_INS_UD2,"ud2"};
    if(cs_option(normal,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&custom))) return 3;
    cs_insn *ref=cs_malloc(normal);
    if(!ref)return 3;
    using Key=std::tuple<unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned>;
    std::map<Key,uint64_t> counts;
    unsigned mismatches=0;
    size_t start,n;uint64_t ip;
    while(spans>>start>>n>>ip){
        if(start>data.size()||n>data.size()-start)return 4;
        const uint8_t *p=data.data()+start;
        while(n) {
            auto next=p;auto left=n;auto address=ip;
            ref->is_alias=false;ref->usesAliasDetails=false;ref->illegal=false;
            const bool valid=cs_disasm_iter(normal,&next,&left,&address,ref);
            cs_detail detail{};cs_insn text{},built{};
            text.address=built.address=ip;built.detail=&detail;
            uint16_t size_text=0,size_detail=0;
            const bool text_hit=writer(fast,p,n,&text,&size_text);
            const bool detail_hit=writer(fast,p,n,&built,&size_detail);
            auto equal=[&](const cs_insn &out,unsigned size) {
                return valid && size==ref->size && out.id==ref->id && out.size==size && !std::strcmp(out.mnemonic,ref->mnemonic) && !std::strcmp(out.op_str,ref->op_str);
            };
            if((text_hit&&!equal(text,size_text))||(detail_hit&&!equal(built,size_detail))){
                if(++mismatches<=10) {
                    std::fprintf(stderr,"mismatch @%llx ",(unsigned long long)ip);
                    for(size_t i=0;i<(n<15?n:15);++i)std::fprintf(stderr,"%02x",p[i]);
                    std::fprintf(stderr," expected %d %u %s %s found %u %s %s\n",valid,ref->size,ref->mnemonic,ref->op_str,size_text,text.mnemonic,text.op_str);
                }
            }
            const unsigned len=valid ? ref->size : 1;
            if(!len || len>n || (valid&&(next!=p+len||left!=n-len)))return 5;
            const auto &x=ref->detail->x86;
            unsigned operands=0,flags=0;
            if(valid){
                for(unsigned i=0;i<x.op_count;++i)operands=operands*8+unsigned(x.operands[i].type);
                flags=(x.encoding.disp_size!=0) | ((x.encoding.imm_size!=0)<<1);
                if(x.encoding.modrm_offset){
                    const auto mr=p[x.encoding.modrm_offset];
                    flags|=(mr<0xc0 ? ((mr&7)==4?2u:1u) : 3u)<<2;
                }
            }
            const unsigned status=valid?(1+text_hit+2*detail_hit):0;
            unsigned primary=p[0],opcode=primary,map=0;
            unsigned pos=0;
            while(pos+1<len && (p[pos]==0x66||p[pos]==0xf2||p[pos]==0xf3||p[pos]==0x67||(bits==64&&(p[pos]&0xf0)==0x40)))++pos;
            opcode=p[pos];
            if(opcode==0x0f && pos+1<len){map=1;opcode=p[++pos];if((opcode==0x38||opcode==0x3a)&&pos+1<len){map=opcode==0x38?2:3;opcode=p[++pos];}}
            else if(opcode==0x62&&pos+5<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=p[pos+1]&15;opcode=p[pos+4];}
            else if(opcode==0xc4&&pos+3<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=p[pos+1]&31;opcode=p[pos+3];}
            else if(opcode==0xc5&&pos+2<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=1;opcode=p[pos+2];}
            ++counts[{status,primary,map,opcode,valid?ref->id:0,operands,flags,len,valid?x.op_count:0}];
            ip+=len;p+=len;n-=len;
        }
    }
    for(const auto &[k,total]:counts){
        const auto [status,primary,map,op,id,operands,flags,len,nops]=k;
        std::printf("%u %u %u %u %u %u %u %u %u %llu\n",status,primary,map,op,id,operands,flags,len,nops,(unsigned long long)total);
    }
    std::fprintf(stderr,"%u writer output mismatches\n",mismatches);
    cs_free(ref,1);cs_close(&normal);cs_close(&fast);return mismatches?7:0;
}
