#include <capstone/capstone.h>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool X86_disasmIter32(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" bool X86_disasmIterText(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" unsigned long long bare_opcode_hits[256];

int main(int argc,char **) {
    const bool candidate=argc==2;
    const size_t page=size_t(sysconf(_SC_PAGESIZE));
    auto *mem=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if(mem==MAP_FAILED || mprotect(mem+page,page,PROT_NONE)) return 1;
    unsigned long long checks=0,hits[2]={};
    for(unsigned wide : {0,1}) for(unsigned profile=0;profile<7;++profile) {
        const auto mode=wide?CS_MODE_64:CS_MODE_32;
        bool detail=profile!=0;
        csh reference=0,reader=0;
        if(cs_open(CS_ARCH_X86,mode,&reference)||cs_open(CS_ARCH_X86,mode,&reader)) return 2;
        cs_opt_mnem m{X86_INS_UD2,"ud2"};
        if(cs_option(reference,CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&m))) return 3;
        for(csh h : {reference,reader}) {
            if(detail && cs_option(h,CS_OPT_DETAIL,profile==2?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_ON)) return 4;
            if(profile==3 && cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT)) return 5;
            if(profile==4 && cs_option(h,CS_OPT_UNSIGNED,CS_OPT_ON)) return 6;
            if(profile==5) {
                cs_opt_mnem custom{X86_INS_SHRD,"shift_test"};
                if(cs_option(h,CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&custom))) return 7;
            }
            if(profile==6 && cs_option(h,CS_OPT_TEXT,CS_OPT_OFF)) return 8;
        }
        auto next=wide?X86_disasmIterText:X86_disasmIter32;
        auto check=[&](const std::array<uint8_t,9> &code,unsigned length) {
            uint8_t *input=mem+page-length;
            std::memcpy(input,code.data(),length);
            const uint8_t *a=input,*b=input;size_t na=length,nb=length;
            uint64_t ia=0xfffffffeu,ib=ia;
            cs_detail da,db;cs_insn ra,rb;
            std::memset(&da,0xa5,sizeof(da));std::memcpy(&db,&da,sizeof(db));
            std::memset(&ra,0xa5,sizeof(ra));ra.illegal=false;ra.is_alias=false;ra.usesAliasDetails=false;ra.alias_id=0;
            std::memcpy(&rb,&ra,sizeof(ra));ra.detail=detail?&da:nullptr;rb.detail=detail?&db:nullptr;
            const unsigned long long before=bare_opcode_hits[0xa4]+bare_opcode_hits[0xac];
            const bool got=next(reader,&a,&na,&ia,&ra);
            const unsigned long long delta=bare_opcode_hits[0xa4]+bare_opcode_hits[0xac]-before;
            const bool expected=cs_disasm_iter(reference,&b,&nb,&ib,&rb);
            bool valid=ra.detail==(detail?&da:nullptr)&&rb.detail==(detail?&db:nullptr);
            ra.detail=rb.detail;
            const bool eligible=!wide && profile<=2 && length>=4 && code[0]==0x0f &&
                                (code[1]==0xa4||code[1]==0xac) && code[2]>=0xc0;
            if(!valid||got!=expected||a!=b||na!=nb||ia!=ib||delta!=unsigned(candidate&&eligible)||
                std::memcmp(&ra,&rb,sizeof(ra))||std::memcmp(&da,&db,sizeof(da))) {
                std::fprintf(stderr,"wide=%u profile=%u n=%u code=%02x %02x %02x %02x ok=%u/%u hits=%llu eligible=%u id=%u/%u\n",
                             wide,profile,length,code[0],code[1],code[2],code[3],got,expected,delta,eligible,ra.id,rb.id);
                return false;
            }
            ++checks;hits[wide]+=delta;return true;
        };
        for(unsigned op : {0xa4,0xac}) for(unsigned mr=0;mr<256;++mr) {
            std::array<uint8_t,9> code={0x0f,uint8_t(op),uint8_t(mr),0x85,0xfe,0xff,0xff,0xff,0x73};
            for(unsigned n=0;n<=9;++n)if(!check(code,n))return 10;
            if(mr>=0xc0)for(unsigned imm=0;imm<256;++imm) {
                code[3]=uint8_t(imm);
                if(!check(code,4))return 11;
            }
            for(unsigned prefix : {0x66,0x67,0xf0,0xf2,0xf3,0x40,0x48}) {
                std::array<uint8_t,9> pref={uint8_t(prefix),0x0f,uint8_t(op),uint8_t(mr),0x80,0xff,0xff,0xff,0xdc};
                for(unsigned n : {2,3,4,5,9})if(!check(pref,n))return 12;
            }
        }
        for(unsigned op=0;op<256;++op) {
            std::array<uint8_t,9> near={0x0f,uint8_t(op),0xd1,0x97,0x77,0x77,0x77,0x77,0x77};
            for(unsigned n=0;n<=9;++n)if(!check(near,n))return 13;
        }
        cs_close(&reader);cs_close(&reference);
    }
    munmap(mem,2*page);
    if(bool(hits[0])!=candidate||hits[1])return 14;
    std::printf("%llu %llu %llu\n",checks,hits[0],hits[1]);
}
