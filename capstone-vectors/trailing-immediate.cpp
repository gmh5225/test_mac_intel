#define main unused_comparison_main
#include "compare.cpp"
#undef main
#include <sstream>

static std::string spelling(uint64_t value, bool masm)
{
    char buffer[32];
    std::snprintf(buffer,sizeof buffer,"%" PRIx64,value);
    if (!masm) return std::string("0x")+buffer;
    return std::string(buffer[0]>='a'?"0":"")+buffer+"h";
}
static std::string isolate(std::string& text, bool att)
{
    size_t first=0,end=0;
    if (!att) {
        first=text.find('[');end=text.find(']',first);
        check(first!=text.npos&&end!=text.npos,"Intel memory spelling");++first;
    } else {
        for (;;) {
            first=text.find_first_not_of(' ',first);end=text.find(',',first);
            if (end==text.npos) end=text.size();
            if (first<end && text[first]!='$' && text[first]!='%')break;
            check(end<text.size(),"AT&T memory spelling");first=end+1;
        }
    }
    auto number=text.substr(first,end-first);text.replace(first,end-first,"[address]");return number;
}
int main(int argc,char **argv)
{
    if(argc!=2)return 1;
    Api api(argv[1]);
    uint64_t cases=0,wrong=0,changed=0,hash=0;
    const unsigned modes[]={0,CS_MODE_16,CS_MODE_32,CS_MODE_64,CS_MODE_16|CS_MODE_32,CS_MODE_64|CS_MODE_32,CS_MODE_16|CS_MODE_64,CS_MODE_16|CS_MODE_32|CS_MODE_64};
    for(unsigned m:modes)for(unsigned vendor:{0u,unsigned(CS_MODE_X86_AMD),unsigned(CS_MODE_X86_INTEL)}) {
        const unsigned bits=m&CS_MODE_16?16:m&CS_MODE_32?32:64;
        Session h(api,CS_ARCH_X86,cs_mode(m|vendor));
        for(auto syntax:{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT,CS_OPT_SYNTAX_MASM}) {
            h.set(CS_OPT_SYNTAX,syntax);
            for(bool detail:{false,true})for(bool unsign:{false,true}) {
                h.set(CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF);h.set(CS_OPT_UNSIGNED,unsign?CS_OPT_ON:CS_OPT_OFF);
                for(int override:{0,1})for(unsigned prefix:{0u,0x66u,0x48u})for(unsigned opc:{0x80,0x83,0xc6,0xc7,0xf6,0xf7,0x69,0x6b})for(unsigned imm:{0x7fu,0x80u,0xffu}) {
                    if(prefix==0x48 && bits!=64)continue;
                    unsigned width=override?(bits==32?16:32):bits;
                    std::vector<uint8_t> bytes;
                    if(override)bytes.push_back(0x67);
                    if(prefix)bytes.push_back(prefix);
                    bytes.push_back(opc);
                    if(bits==64){bytes.push_back(4);bytes.push_back(0x25);}
                    else bytes.push_back(width==16?6:5);
                    bytes.push_back(0x34);bytes.push_back(0x12);
                    if(width!=16){bytes.push_back(0);bytes.push_back(0);}
                    auto high=bytes.size()-1;
                    bytes.insert(bytes.end(),{uint8_t(imm),0xff,0xff,0xff});
                    std::string operands[2];cs_x86 parts[2]{};
                    for(unsigned neg=0;neg<2;++neg) {
                        if(neg)bytes[high]|=0x80;
                        Result got(h,bytes.data(),bytes.size(),0x1000,1);
                        check(got.n==1,"decode memory/immediate");
                        auto &insn=*got.a;operands[neg]=insn.op_str;
                        auto num=isolate(operands[neg],syntax==CS_OPT_SYNTAX_ATT);
                        uint64_t address=0x1234;
                        if(neg)address=width==16?0x9234:width==32?0x80001234:UINT64_C(0xffffffff80001234);
                        if(num!=spelling(address,syntax==CS_OPT_SYNTAX_MASM))++wrong;
                        if(detail) {
                            parts[neg]=insn.detail->x86;auto &x=parts[neg];
                            const int64_t raw=neg?(width==16?INT64_C(-28108):INT64_C(-2147478988)):0x1234;
                            check(x.addr_size==width/8&&x.disp==raw,"decoded address width/displacement");
                            x.disp=0;unsigned found=0,immediates=0;
                            for(unsigned i=0;i<x.op_count;++i) {
                                auto &op=x.operands[i];
                                if(op.type==X86_OP_MEM){check(op.mem.disp==raw,"signed operand displacement");op.mem.disp=0;++found;}
                                if(op.type==X86_OP_IMM)++immediates;
                            }
                            check(found==1&&immediates==1,"explicit operands");
                        }
                    }
                    ++cases;
                    if(operands[0]!=operands[1]||std::memcmp(&parts[0],&parts[1],sizeof(parts[0])))++changed;
                    for(const auto &s:operands){for(unsigned char c:s)hash=hash*131+c;hash=hash*131;}
                }
            }
        }
    }
    std::printf("{\"cases\":%" PRIu64 ",\"wrong_address\":%" PRIu64 ",\"changed_operands\":%" PRIu64 ",\"suffix_hash\":%" PRIu64 "}\n",cases,wrong,changed,hash);
}
