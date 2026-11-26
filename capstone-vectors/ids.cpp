#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
extern "C" bool X86_disasmIterText(csh,const uint8_t**,size_t*,uint64_t*,cs_insn*);
static unsigned integer_family(const uint8_t *p,size_t n) {
    while(n && (*p==0x26||*p==0x2e||*p==0x36||*p==0x3e||*p==0x64||*p==0x65||*p==0x67)){++p;--n;}
    if(n<7||p[0]!=0x62||(p[1]&15)!=3||(p[2]&7)!=5)return 0;
    bool wide=(p[2]&128)!=0;
    switch(p[4]){
        case 0x1e:return wide?X86_INS_VPCMPUQ:X86_INS_VPCMPUD;
        case 0x1f:return wide?X86_INS_VPCMPQ:X86_INS_VPCMPD;
        case 0x3e:return wide?X86_INS_VPCMPUW:X86_INS_VPCMPUB;
        case 0x3f:return wide?X86_INS_VPCMPW:X86_INS_VPCMPB;
        default:return 0;
    }
}
static bool floating_compare(const uint8_t *p,size_t n) {
    while(n && (*p==0x26||*p==0x2e||*p==0x36||*p==0x3e||*p==0x64||*p==0x65||*p==0x67)){++p;--n;}
    return (n>=5&&p[0]==0xc5&&p[2]==0xc2)||(n>=6&&p[0]==0xc4&&(p[1]&31)==1&&p[3]==0xc2)||
           (n>=7&&p[0]==0x62&&(p[1]&15)==1&&p[4]==0xc2);
}
int main(int argc,char **argv) {
    if(argc!=4)return 1;
    int bits=std::stoi(argv[1]);
    auto mode=bits==64?CS_MODE_64:CS_MODE_32;
    std::ifstream raw(argv[2],std::ios::binary),ranges(argv[3]);
    std::vector<uint8_t> data{std::istreambuf_iterator<char>(raw),{}};
    std::array<csh,3> handles{};cs_insn *slots[3]{};csh canonical{};
    if(cs_open(CS_ARCH_X86,mode,&canonical)||cs_option(canonical,CS_OPT_DETAIL,CS_OPT_ON))return 2;
    for(unsigned m=0;m<3;++m) {
        if(cs_open(CS_ARCH_X86,mode,&handles[m])||cs_option(handles[m],CS_OPT_TEXT,m?CS_OPT_ON:CS_OPT_OFF)||
            cs_option(handles[m],CS_OPT_DETAIL,m==2?CS_OPT_ON:CS_OPT_OFF)||!(slots[m]=cs_malloc(handles[m])))return 3;
    }
    uint64_t count[3]{},offset,bytes,ip,accepted=0,rejected=0;int64_t delta[3]{};
    while(ranges>>offset>>bytes>>ip) {
        if(offset>data.size()||bytes>data.size()-offset)return 4;
        const auto *at=data.data()+offset;
        while(bytes) {
            cs_insn *item=nullptr;bool ok=cs_disasm(canonical,at,bytes,ip,1,&item)==1;
            unsigned length=ok?item->size:1,id=ok?item->id:0;
            if(ok)++accepted;else ++rejected;
            for(unsigned m=0;m<3;++m) {
                const uint8_t *cur=at;size_t left=bytes;uint64_t addr=ip;
                auto next=m?X86_disasmIterText:cs_disasm_iter;
                bool valid=next(handles[m],&cur,&left,&addr,slots[m]);
                if(valid!=ok||(ok&&(slots[m]->size!=length||cur!=at+length)))return 5;
                if(ok && !m && floating_compare(at,length)) {
                    unsigned scan=slots[0]->id;
                    if(scan!=X86_INS_VCMP&&scan!=X86_INS_VCMPSS&&scan!=X86_INS_VCMPSD&&scan!=X86_INS_VCMPPS&&scan!=X86_INS_VCMPPD)return 8;
                    if(id!=scan && id!=scan+1+(at[length-1]&31))return 9;
                    id=scan;
                }
                if(ok && slots[m]->id!=id) {
                    unsigned old=slots[m]->id;
                    bool integer=old==X86_INS_VPCMP && integer_family(at,length)==id;
                    bool floating=floating_compare(at,length) && old==id+1+(at[length-1]&31);
                    if(!(floating && m!=0) && !(integer && m==0)){std::fprintf(stderr,"Unexpected ID delta at %llx old=%u bulk=%u\n",(unsigned long long)ip,old,id);return 6;}
                    ++count[m];delta[m]+=int64_t(id)-old;
                }
            }
            cs_free(item,ok);at+=length;ip+=length;bytes-=length;
        }
    }
    if(!ranges.eof())return 7;
    std::printf("%llu %llu",(unsigned long long)accepted,(unsigned long long)rejected);
    for(unsigned m=0;m<3;++m){std::printf(" %llu %lld",(unsigned long long)count[m],(long long)delta[m]);cs_free(slots[m],1);cs_close(&handles[m]);}
    std::puts("");cs_close(&canonical);
}
