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
            for(unsigned ext=0;ext<16;++ext) for(unsigned vv=0;vv<32;++vv)
            for(unsigned ll=0;ll<4;++ll) for(unsigned mr=0;mr<256;++mr)
            for(unsigned op:{0xb4u,0xb5u}) {
                if((mode!=CS_MODE_64 || config>1) && (vv!=0 && vv!=31 || ext!=0 && ext!=15))continue;
                const unsigned salt=(ll+vv+mr+ext)&255, mod=mr>>6, rm=mr&7;
                const unsigned pre=(ext<<4)|2, v=vv;
                for(unsigned invalid:{0u,1u,2u,3u,4u,5u,6u,7u}) {
                    if(invalid && (vv!=0 || ext!=15 || mr%17))continue;
                    uint8_t bytes[]={0x62,uint8_t(pre),uint8_t(0x85|((~vv&15)<<3)),uint8_t((ll<<5)|((~vv&16)>>1)),uint8_t(op),uint8_t(mr),uint8_t(salt),uint8_t(0x80+salt),0xb4,0xc9,0x91};
                    switch(invalid) {
                    case 1:bytes[1]^=4;break;case 2:bytes[2]^=4;break;case 3:bytes[2]^=0x80;break;
                    case 4:bytes[2]^=1;break;case 5:bytes[3]^=0x80;break;case 6:bytes[3]^=0x10;break;case 7:bytes[3]|=7;break;
                    }
                    unsigned len=6;
                    if(mod!=3){
                        if(rm==4)++len;
                        len+=mod==2||(!mod&&(rm==5||rm==4&&(bytes[6]&7)==5))?4:mod;
                    }
                    for(unsigned avail=0;avail<=len;++avail){
                        if((vv!=0 || ext!=15) && avail!=len)continue;
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
