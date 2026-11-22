#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
extern "C" bool observed_move(const uint8_t *,size_t,cs_insn *,uint16_t *);
int main(){
    csh h=0;cs_opt_mnem names{X86_INS_UD2,"ud2"};
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h)||cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)||cs_option(h,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&names)))return 1;
    const auto page=static_cast<size_t>(sysconf(_SC_PAGESIZE));auto *area=static_cast<uint8_t *>(mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if(area==MAP_FAILED||mprotect(area+page,page,PROT_NONE))return 2;
    uint64_t tried=0,accepted=0,indexed=0;
    for(unsigned sib=0;sib<256;++sib)for(unsigned ext=0;ext<16;++ext)
    for(unsigned mod=0;mod<3;++mod)for(unsigned dir=0;dir<2;++dir)
    for(unsigned variant=0;variant<4;++variant){
        const unsigned which=sib+ext+variant, opcode=variant==3 ? (dir?0x28:0x29) : (dir?0x6f:0x7f);
        std::array<uint8_t,11> bytes{{0x62,static_cast<uint8_t>(ext<<4|1),
            static_cast<uint8_t>(0x7c|(variant==3?0:variant+1)|((sib&1)<<7)),
            static_cast<uint8_t>(8|(which%3)<<5),static_cast<uint8_t>(opcode),
            static_cast<uint8_t>(mod<<6|((ext+sib)&7)<<3|4),static_cast<uint8_t>(sib),
            static_cast<uint8_t>(which*37),0xfa,0x80,0xff}};
        const unsigned size=7+(mod==2||(!mod&&(sib&7)==5)?4:mod);
        for(unsigned length=0;length<=size;++length){
            uint8_t *p=area+page-length;std::memcpy(p,bytes.data(),length);
            cs_insn actual,reference;cs_detail act,ref;
            std::memset(&actual,0xa5,sizeof(actual));std::memset(&act,0xa5,sizeof(act));
            reference=actual;ref=act;actual.detail=&act;reference.detail=&ref;
            actual.address=reference.address=0x31415926;uint16_t out=0xeeff;
            ++tried;
            if(!observed_move(p,length,&actual,&out)){
                actual.detail=&ref;
                if(out!=0xeeff||std::memcmp(&actual,&reference,sizeof(actual))||std::memcmp(&act,&ref,sizeof(act)))return 3;
                continue;
            }
            ++accepted;const uint8_t *cursor=p;size_t left=length;uint64_t ip=reference.address;
            if(!cs_disasm_iter(h,&cursor,&left,&ip,&reference)||left!=0||cursor!=p+out||out!=actual.size||out!=reference.size||actual.id!=reference.id||
               std::memcmp(actual.bytes,reference.bytes,sizeof(actual.bytes))||
               std::memcmp(actual.mnemonic,reference.mnemonic,sizeof(actual.mnemonic))||
               std::memcmp(actual.op_str,reference.op_str,sizeof(actual.op_str))||
               std::memcmp(&act,&ref,offsetof(cs_detail,x86)+sizeof(cs_x86))){std::fprintf(stderr,"EVEX mismatch sib=%x ext=%x mod=%u length=%u\n",sib,ext,mod,length);return 4;}
            indexed+=act.x86.sib_index!=X86_REG_INVALID;
        }
    }
    std::printf("%llu %llu %llu\n",(unsigned long long)tried,(unsigned long long)accepted,(unsigned long long)indexed);
    cs_close(&h);munmap(area,page*2);return accepted?0:5;
}
