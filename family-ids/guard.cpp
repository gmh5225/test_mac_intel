#define main original_compare_main
#include "compare.cpp"
#undef main

int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Api left(argv[1]),right(argv[2]);
    uint64_t total=0,decoded=0;
    const size_t page=sysconf(_SC_PAGESIZE);
    auto *buffer=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
    check(buffer!=MAP_FAILED&&!mprotect(buffer+page,page,PROT_NONE),"guard");
    for (cs_mode mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64,
         static_cast<cs_mode>(CS_MODE_32|CS_MODE_X86_AMD),static_cast<cs_mode>(CS_MODE_64|CS_MODE_X86_INTEL)}) {
        Session a(left,CS_ARCH_X86,mode),b(right,CS_ARCH_X86,mode);
        for(Session *s:{&a,&b})s->set(CS_OPT_TEXT,CS_OPT_OFF);
        std::mt19937 rng(0xa36317);
        for(unsigned map=0;map<14;++map)for(unsigned opcode=0;opcode<256;++opcode) {
            for(unsigned form=0;form<32;++form) {
                uint8_t bytes[15];for(uint8_t &ch:bytes)ch=uint8_t(rng());
                unsigned start=0;
                switch(map) {
                    case 0:break;
                    case 1:bytes[start++]=0x40+(form&15);break;
                    case 2:bytes[start++]=0x0f;break;
                    case 3:bytes[start++]=0x66;break;
                    case 4:bytes[start++]=0xf2;bytes[start++]=0x0f;break;
                    case 5:bytes[start++]=0xf3;bytes[start++]=0x0f;break;
                    case 6:bytes[start++]=0x66;bytes[start++]=0x40+(form&15);bytes[start++]=0x0f;break;
                    case 7:bytes[start++]=0xc5;bytes[start++]=uint8_t(rng());break;
                    case 8:bytes[start++]=0xc4;bytes[start++]=(rng()&0xe0)|(1+form%3);bytes[start++]=uint8_t(rng());break;
                    case 9:bytes[start++]=0x62;bytes[start++]=(rng()&0xf0)|(1+form%6);bytes[start++]=uint8_t(rng()|4);bytes[start++]=uint8_t(rng());break;
                    case 10:bytes[start++]=0xf0;break;
                    case 11:bytes[start++]=0x67;break;
                    case 12:bytes[start++]=0x3e;bytes[start++]=0x66;break;
                    case 13:bytes[start++]=0xd5;bytes[start++]=uint8_t(rng());break;
                }
                bytes[start]=uint8_t(opcode);
                bytes[start+1]=uint8_t(((form&3)<<6)|(form&0x1c)|(rng()&7));
                for(unsigned n : {0u,start+1,start+2,3u+(form%13),15u}) {
                    if(!n && (form||opcode))continue;
                    auto edge=buffer+page-n;
                    std::memcpy(edge,bytes,n);
                    const uint8_t *p[2]={edge,edge};size_t sizes[2]={n,n};uint64_t ip[2]={UINT64_MAX-form,UINT64_MAX-form};
                    cs_insn records[2];cs_detail details[2];bool ok[2];
                    for(unsigned i=0;i<2;++i) {
                        auto &s=i?b:a;
                        auto &v=records[i];std::memset(&v,(0x67+form)&0xff,sizeof(v));
                        std::memset(details+i,0xa5,sizeof(cs_detail));v.detail=form&1?details+i:nullptr;
                        v.is_alias=v.usesAliasDetails=v.illegal=(form&2)!=0;
                        ok[i]=s.api.next(s.h,p+i,sizes+i,ip+i,&v);
                        check(v.detail==((form&1)?details+i:nullptr),"reused detail");
                        v.detail=nullptr;
                    }
                    if(ok[0]!=ok[1]||p[0]!=p[1]||sizes[0]!=sizes[1]||ip[0]!=ip[1]||left.error(a.h)!=right.error(b.h)||
                        std::memcmp(records,records+1,sizeof(cs_insn))||std::memcmp(details,details+1,sizeof(cs_detail))) {
                        std::fprintf(stderr,"record mismatch mode %u map %u op %x form %u size %u ids %u/%u\n",
                                     unsigned(mode),map,opcode,form,n,records[0].id,records[1].id);return 1;
                    }
                    ++total;decoded+=ok[0];
                }
            }
        }
    }
    std::printf("%llu %llu\n",(unsigned long long)total,(unsigned long long)decoded);
    return munmap(buffer,2*page)!=0;
}
