#define main original_compare_main
#include "trial-compare.cpp"
#undef main

int main(int argc, char **argv) {
    if(argc!=3)return 2;
    Api ref(argv[1]),next(argv[2]);
    size_t pg=sysconf(_SC_PAGESIZE);
    auto *p=static_cast<uint8_t *>(mmap(nullptr,2*pg,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
    check(p!=MAP_FAILED&&!mprotect(p+pg,pg,PROT_NONE),"guard");
    uint64_t trials=0,accepted=0;
    for (auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
        Session a(ref,CS_ARCH_X86,mode),b(next,CS_ARCH_X86,mode);
        for (unsigned config=0;config<8;++config) {
            for(auto *s:{&a,&b}) {
                s->set(CS_OPT_DETAIL,config&1?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_UNSIGNED,config&2?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_TEXT,config&4?CS_OPT_OFF:CS_OPT_ON);
            }
            for (unsigned op=0;op<256;++op) {
                for(unsigned v=0;v<256;++v) {
                    uint8_t bytes[15]={uint8_t(op),uint8_t(v)};unsigned len=sizeof bytes;
                    uint32_t mix=0x9e3779b9U^(v+(op<<8));
                    for(unsigned n=2;n<len;++n){mix=mix*1664525U+1013904223U;bytes[n]=mix>>24;}
                    for(unsigned avail=0;avail<=len;++avail){
                        if(avail!=1 && avail!=2 && avail!=len && ((op+v+avail)&31))continue;
                        const uint8_t *pos=p+pg-avail;std::memcpy(p+pg-avail,bytes,avail);
                        const uint8_t *in[2]={pos,pos};size_t sz[2]={avail,avail};uint64_t ip[2]={0xfffffffffffffffeULL,0xfffffffffffffffeULL};
                        cs_insn entries[2];cs_detail dt[2];bool ok[2];
                        for(unsigned i=0;i<2;++i){auto &s=i?b:a;auto &z=entries[i];std::memset(&z,0xa5,sizeof(z));std::memset(&dt[i],0xa5,sizeof(dt[i]));
                            z.detail=config&1?dt+i:nullptr;z.illegal=z.is_alias=z.usesAliasDetails=false;
                            ok[i]=s.api.next(s.h,in+i,sz+i,ip+i,&z);check(z.detail==((config&1)?dt+i:nullptr),"record owner");z.detail=nullptr;}
                        if(ok[0]!=ok[1]||in[0]!=in[1]||sz[0]!=sz[1]||ip[0]!=ip[1]||ref.error(a.h)!=next.error(b.h)||std::memcmp(entries,entries+1,sizeof(cs_insn))||std::memcmp(dt,dt+1,sizeof(cs_detail))){
                            std::fprintf(stderr,"mismatch mode=%u options=%u first=%x second=%x avail=%u text=(%s %s)/(%s %s)\n",mode,config,op,v,avail,entries[0].mnemonic,entries[0].op_str,entries[1].mnemonic,entries[1].op_str);
                            const auto *l=reinterpret_cast<const uint8_t *>(dt),*r=reinterpret_cast<const uint8_t *>(dt+1);
                            for(size_t k=0;k<sizeof(cs_detail);++k)if(l[k]!=r[k])std::fprintf(stderr," detail[%zu]=%02x/%02x\n",k,l[k],r[k]);
                            return 1;
                        }++trials;accepted+=ok[0];
                    }
                }
            }
        }
    }
    std::printf("%llu %llu\n",(unsigned long long)trials,(unsigned long long)accepted);return munmap(p,2*pg)!=0;
}
