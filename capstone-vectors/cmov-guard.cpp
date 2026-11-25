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
            for (unsigned pre=0;pre<21;++pre)for(unsigned op=0x3f;op<=0x50;++op) {
                for(unsigned v=0;v<256;++v) {
                    uint8_t bytes[10]={},len=0;
                    if(pre>=1 && pre<=16)bytes[len++]=uint8_t(0x3f+pre);
                    else if(pre==17)bytes[len++]=0x66;
                    else if(pre==18)bytes[len++]=0xf3;
                    else if(pre==19)bytes[len++]=0xf0;
                    else if(pre==20){bytes[len++]=0x66;bytes[len++]=0x48;}
                    bytes[len++]=0x0f;bytes[len++]=op;bytes[len++]=v;bytes[len++]=uint8_t(v*163);bytes[len++]=uint8_t(v*57);bytes[len++]=v;
                    for(unsigned avail=0;avail<=len;++avail){
                        if((v&15) && avail!=len && avail!=len-3)continue;
                        const uint8_t *pos=p+pg-avail;std::memcpy(p+pg-avail,bytes,avail);
                        const uint8_t *in[2]={pos,pos};size_t sz[2]={avail,avail};uint64_t ip[2]={0xfffffffffffffffeULL,0xfffffffffffffffeULL};
                        cs_insn entries[2];cs_detail dt[2];bool ok[2];
                        for(unsigned i=0;i<2;++i){auto &s=i?b:a;auto &z=entries[i];std::memset(&z,0xa5,sizeof(z));std::memset(&dt[i],0xa5,sizeof(dt[i]));
                            z.detail=config&1?dt+i:nullptr;z.illegal=z.is_alias=z.usesAliasDetails=false;
                            ok[i]=s.api.next(s.h,in+i,sz+i,ip+i,&z);check(z.detail==((config&1)?dt+i:nullptr),"record owner");z.detail=nullptr;}
                        if(ok[0]!=ok[1]||in[0]!=in[1]||sz[0]!=sz[1]||ip[0]!=ip[1]||ref.error(a.h)!=next.error(b.h)||std::memcmp(entries,entries+1,sizeof(cs_insn))||std::memcmp(dt,dt+1,sizeof(cs_detail))){
                            std::fprintf(stderr,"mismatch mode=%u options=%u prefix=%u op=%x imm=%x avail=%u text=(%s %s)/(%s %s)\n",mode,config,pre,op,v,avail,entries[0].mnemonic,entries[0].op_str,entries[1].mnemonic,entries[1].op_str);
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
