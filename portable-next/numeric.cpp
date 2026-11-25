#include <capstone/capstone.h>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <map>
#include <string>
#include <vector>

struct Api {
    void *lib;
    decltype(&cs_open) open;
    decltype(&cs_close) close;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) next;
    decltype(&cs_regs_access) access;
    decltype(&cs_reg_name) name;
    explicit Api(const char *file):lib(dlopen(file,RTLD_NOW|RTLD_LOCAL)),
        open((decltype(open))dlsym(lib,"cs_open")),close((decltype(close))dlsym(lib,"cs_close")),
        option((decltype(option))dlsym(lib,"cs_option")),next((decltype(next))dlsym(lib,"cs_disasm_iter")),
        access((decltype(access))dlsym(lib,"cs_regs_access")),name((decltype(name))dlsym(lib,"cs_reg_name")) {}
};
static std::map<std::string,std::string> spelling;
static std::string numeric(std::string text) {
    // An ABI range s0-sN crosses from x9 to x18. Numeric ranges split there.
    const size_t pos=text.find("s0-s");
    if (pos!=text.npos) {
        const size_t end=text.find_first_not_of("0123456789",pos+4);
        const unsigned last=std::stoul(text.substr(pos+4,end-(pos+4)));
        if(last>=2) text.replace(pos,end-pos,"s0-s1, s2"+(last==2?std::string():"-s"+std::to_string(last)));
    }
    std::string out;
    for(size_t i=0;i<text.size();) {
        if(!std::isalnum((unsigned char)text[i])&&text[i]!='_'){out+=text[i++];continue;}
        size_t j=i+1;
        while(j<text.size()&&(std::isalnum((unsigned char)text[j])||text[j]=='_'))++j;
        auto token=text.substr(i,j-i);
        auto name=spelling.find(token);out+=name==spelling.end()?token:name->second;i=j;
    }
    return out;
}
static uint64_t records, changed, rejected, queries, list, integer;
static bool pair(Api &a,Api &b,csh h,csh k,const uint8_t *p,size_t size,uint64_t address,size_t &used) {
    const uint8_t *xcur=p,*ycur=p;size_t nx=size,ny=size;uint64_t ix=address,iy=address;
    cs_insn x,y;cs_detail dx,dy;
    memset(&x,0xa5,sizeof x);x.is_alias=false;x.illegal=false;y=x;
    memset(&dx,0xa5,sizeof dx);dy=dx;x.detail=&dx;y.detail=&dy;
    bool vx=a.next(h,&xcur,&nx,&ix,&x),vy=b.next(k,&ycur,&ny,&iy,&y);
    if(vx!=vy||nx!=ny||ix!=iy||xcur!=ycur||memcmp(&dx,&dy,sizeof dx))return false;
    x.detail=y.detail=nullptr;
    if(!vx){used=size>=2?2:1;++rejected;return !memcmp(&x,&y,sizeof x);}
    ++records;used=size-nx;
    std::string expected=numeric(x.op_str);
    if(expected!=x.op_str)++changed;
    if(expected!=y.op_str){fprintf(stderr,"ip=%llx %s [%s] wanted [%s] got [%s]\n",(unsigned long long)address,x.mnemonic,x.op_str,expected.c_str(),y.op_str);return false;}
    // Different register spelling is the only permitted public record difference.
    std::memset(x.op_str,0,sizeof x.op_str);std::memcpy(x.op_str,expected.data(),expected.size());
    if(memcmp(&x,&y,sizeof x)){fprintf(stderr,"insn=%s ptr=%llu\n",x.mnemonic,(unsigned long long)address);return false;}
    x.detail=&dx;y.detail=&dy;cs_regs rx{},wx{},ry{},wy{};uint8_t nrx=0,nwx=0,nry=0,nwy=0;
    auto ax=a.access(h,&x,rx,&nrx,wx,&nwx),ay=b.access(k,&y,ry,&nry,wy,&nwy);
    if(ax!=ay||nrx!=nry||nwx!=nwy||memcmp(rx,ry,sizeof rx)||memcmp(wx,wy,sizeof wx))return false;
    ++queries;return true;
}
int main(int argc,char **argv){
    if(argc!=4)return 1;Api a(argv[1]),b(argv[2]);if(!a.lib||!b.lib)return 2;
    const char *gpr[]={"zero","ra","sp","gp","tp","t0","t1","t2","s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"};
    const char *fpr[]={"ft0","ft1","ft2","ft3","ft4","ft5","ft6","ft7","fs0","fs1","fa0","fa1","fa2","fa3","fa4","fa5","fa6","fa7","fs2","fs3","fs4","fs5","fs6","fs7","fs8","fs9","fs10","fs11","ft8","ft9","ft10","ft11"};
    for(int i=0;i<32;++i){spelling[gpr[i]]="x"+std::to_string(i);spelling[fpr[i]]="f"+std::to_string(i);}
    std::ifstream input(argv[3],std::ios::binary);std::vector<uint8_t> elf((std::istreambuf_iterator<char>(input)),{});if(elf.empty())return 3;
    for(auto base:{CS_MODE_RISCV32,CS_MODE_RISCV64})for(bool zcmp:{false,true})
    for(auto syntax:{CS_OPT_SYNTAX_ALIAS,CS_OPT_SYNTAX_REAL,CS_OPT_SYNTAX_UNCOMPRESSED_REAL}){
        auto mode=cs_mode(unsigned(base)|(zcmp?CS_MODE_RISCV_ZCMP_ZCMT_ZCE:unsigned(CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_V)));csh h,k;
        if(a.open(CS_ARCH_RISCV,mode,&h)||b.open(CS_ARCH_RISCV,mode,&k))return 4;
        if(a.option(h,CS_OPT_SYNTAX,syntax)||b.option(k,CS_OPT_SYNTAX,unsigned(syntax)|CS_OPT_SYNTAX_NOREGNAME)||
           a.option(h,CS_OPT_DETAIL,CS_OPT_ON)||b.option(k,CS_OPT_DETAIL,CS_OPT_ON))return 5;
        for(unsigned i=0;i<32;++i)if(std::string(a.name(h,RISCV_REG_X0+i))!=gpr[i]||b.name(k,RISCV_REG_X0+i)!=spelling[gpr[i]])return 6;
        if(zcmp) {
            for(unsigned op:{0xb8u,0xbau,0xbcu,0xbeu})for(unsigned regs=4;regs<16;++regs)for(unsigned adj=0;adj<4;++adj){
                uint8_t bytes[]={uint8_t((regs<<4)|(adj<<2)|2),uint8_t(op)};size_t used;auto before=records;
                if(!pair(a,b,h,k,bytes,2,0,used)||records==before||used!=2)return 7;++list;
            }
        }else{
            for(unsigned rd=0;rd<32;++rd)for(unsigned rs=0;rs<32;++rs){
                auto word=0x33u|(rd<<7)|(rs<<15)|(((rs+rd)%32)<<20);uint8_t bytes[]={uint8_t(word),uint8_t(word>>8),uint8_t(word>>16),uint8_t(word>>24)};size_t used;auto before=records;
                if(!pair(a,b,h,k,bytes,4,0,used)||records==before||used!=4)return 8;++integer;
            }
            if(base==CS_MODE_RISCV64)for(size_t i=0;i<elf.size();){size_t used;if(!pair(a,b,h,k,elf.data()+i,elf.size()-i,0x100000+i,used)||!used)return 9;i+=used;}
        }
        a.close(&h);b.close(&k);
    }
    printf("{\"records\":%llu,\"changed\":%llu,\"rejected\":%llu,\"register_queries\":%llu,\"zcmp\":%llu,\"integer\":%llu}\n",(unsigned long long)records,(unsigned long long)changed,(unsigned long long)rejected,(unsigned long long)queries,(unsigned long long)list,(unsigned long long)integer);
    return 0;
}
