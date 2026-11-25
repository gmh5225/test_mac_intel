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
        cs_opt_mnem neutral{X86_INS_UD2,"ud2"};a.set(CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&neutral));
        for (unsigned config=0;config<8;++config) {
            for(auto *s:{&a,&b}) {
                s->set(CS_OPT_DETAIL,config&1?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_UNSIGNED,config&2?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_TEXT,config&4?CS_OPT_OFF:CS_OPT_ON);
            }
            for (unsigned pre:{0,0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}) {
                for(unsigned op:{0x80,0x81,0xf6,0xf7,0xfe,0xff})
                for(unsigned mr=0;mr<256;++mr)for(unsigned v=0;v<((mr&7)==4?256u:1u);++v) {
                    const unsigned ext=(mr>>3)&7;
                    const bool selected=(op==0x80&&ext==7)||(op==0xf6&&ext==0)||(op==0xff&&(ext==2||ext==4));
                    if (!selected && v>1 && v!=0x24 && v!=255)continue;
                    if (mode!=CS_MODE_64 && v>1 && v!=0x24 && v!=255)continue;
                    uint8_t bytes[12]={};unsigned len=0;
                    if(pre)bytes[len++]=pre;
                    bytes[len++]=op;bytes[len++]=mr;if((mr&7)==4)bytes[len++]=v;
                    for(unsigned i=0;i<5;++i)bytes[len++]=uint8_t(73*(i+1)+mr+v);
                    for(unsigned avail=0;avail<=len;++avail){
                        if(!selected && avail!=len)continue;
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
