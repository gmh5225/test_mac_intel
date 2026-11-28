#include <capstone/capstone.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstddef>
#include <cstdint>
static void hash(uint64_t& h,const void *p,size_t n) {
    const uint8_t *q=static_cast<const uint8_t*>(p);
    while(n--)h=(h^*q++)*1099511628211ULL;
}
int main(int argc,char**argv){
    if(argc!=6)return 1;
    bool fixed=std::atoi(argv[1]);unsigned opt=std::atoi(argv[2]);
    bool diet=cs_support(CS_SUPPORT_DIET);
    std::ifstream input(argv[3],std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    uint64_t address=std::strtoull(argv[4],nullptr,10);
    uint64_t h=14695981039346656037ULL,hdet=h,hregs=h;
    csh handle;if(cs_open(CS_ARCH_ALPHA,CS_MODE_LITTLE_ENDIAN,&handle))return 2;
    if(cs_option(handle,CS_OPT_DETAIL,opt==2?CS_OPT_ON|CS_OPT_DETAIL_REAL:opt==3?CS_OPT_ON|CS_OPT_DETAIL_ALIAS:opt?CS_OPT_ON:CS_OPT_OFF))return 3;
    if(opt==4&&cs_option(handle,CS_OPT_TEXT,CS_OPT_OFF))return 3;
    unsigned bad=0,good=0,branches=0,changed=0,zeros=0;
    for(size_t n=0;n<bytes.size();){
        cs_insn insn{};cs_detail det{};insn.detail=opt?&det:nullptr;
        const auto* p=&bytes[n];size_t left=bytes.size()-n;uint64_t pc=address+n;
        const uint64_t next=pc+4;bool ok=cs_disasm_iter(handle,&p,&left,&pc,&insn);
        hash(h,&ok,sizeof(ok));hash(h,&pc,sizeof(pc));
        if(!ok){n+=4;++bad;continue;}
        if(p!=bytes.data()+n+4||pc!=next||insn.size!=4)return 4;
        uint32_t word=0;for(unsigned i=0;i<4;++i)word|=uint32_t(bytes[n+i])<<(8*i);
        n+=4;++good;hash(h,&insn,offsetof(cs_insn,detail));if(!opt)continue;
        unsigned op=word>>26,ra=ALPHA_REG_R0+((word>>21)&31),rb=ALPHA_REG_R0+((word>>16)&31);
        bool direct=op==0x30||op==0x34,jump=op==0x1a;
        cs_regs rd,wr;uint8_t nr=0,nw=0;
        if(!diet&&cs_regs_access(handle,&insn,rd,&nr,wr,&nw))return 5;
        if(!direct&&!jump){
            hash(hdet,&det,offsetof(cs_detail,alpha)+sizeof(cs_alpha));
            if(!diet){
                hash(hregs,&nr,1);hash(hregs,rd,nr*sizeof(rd[0]));
                unsigned out=0;
                for(unsigned i=0;i<nw;++i){
                    if(wr[i]==ALPHA_REG_R31||wr[i]==ALPHA_REG_F31){++zeros;if(fixed)return 6;}
                    else wr[out++]=wr[i];
                }
                hash(hregs,&out,sizeof(out));hash(hregs,wr,out*sizeof(wr[0]));
            }
            continue;
        }
        ++branches;
        const unsigned ids[]={ALPHA_INS_JMP,ALPHA_INS_JSR,ALPHA_INS_RET,ALPHA_INS_JSR_COROUTINE};
        unsigned id=jump?ids[(word>>14)&3]:op==0x30?ALPHA_INS_BR:ALPHA_INS_BSR;
        int64_t disp=word&0x1fffff;if(disp&0x100000)disp-=0x200000;
        auto& a=det.alpha;const auto& o=a.operands[jump?2:1];
        bool valid=insn.id==id&&a.op_count==(jump?3:2)&&a.operands[0].type==ALPHA_OP_REG&&a.operands[0].reg==ra&&
           a.operands[0].access==(diet?CS_AC_INVALID:CS_AC_WRITE)&&o.type==ALPHA_OP_IMM&&
           o.access==(diet?CS_AC_INVALID:CS_AC_READ)&&o.imm==(jump?int64_t(word&0x3fff):int64_t(next+disp*4))&&
           (!jump||(a.operands[1].type==ALPHA_OP_REG&&a.operands[1].reg==rb&&a.operands[1].access==(diet?CS_AC_INVALID:CS_AC_READ)))&&
           det.regs_read_count==0&&det.regs_write_count==0&&
           (diet||(nr==jump&&(!nr||rd[0]==rb)&&nw==(ra!=ALPHA_REG_R31)&&(!nw||wr[0]==ra)));
        if(opt==4)valid=insn.id==id && a.op_count==0 && !det.regs_read_count && !det.regs_write_count && !nr && !nw;
        if(!valid){++changed;if(fixed){std::fprintf(stderr,"Bad %s %s at %#llx word %#x options %u\n",insn.mnemonic,insn.op_str,(unsigned long long)insn.address,word,opt);return 7;}}
        hash(hdet,&det.groups_count,sizeof(det.groups_count));hash(hdet,det.groups,sizeof(det.groups));
    }
    cs_close(&handle);std::printf("%u %u %u %llu %llu %llu %u %u\n",good,bad,branches,(unsigned long long)h,(unsigned long long)hdet,(unsigned long long)hregs,changed,zeros);
}
